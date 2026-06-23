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

# File transfer settings.
MAX_TRANSFER_BYTES = 0xFFFFFFFF              # file size fits in 32-bit (two 16-bit header packets)
MAX_FILENAME_BYTES = 0xFFFF                  # filename length must fit in one 16-bit identifier
READY_TIMEOUT_SECONDS = 5.0
FILE_PACKET_DELAY_SECONDS = 0.0               # raise this if hostb starts dropping packets

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
    if file_size > MAX_TRANSFER_BYTES:
        print(f"Transfer failed: file too large ({file_size} bytes, max {MAX_TRANSFER_BYTES}).")
        return

    filename = os.path.basename(source_path)
    filename_bytes = filename.encode("utf-8")
    filename_length = len(filename_bytes)
    if filename_length == 0 or filename_length > MAX_FILENAME_BYTES:
        print(f"Transfer failed: invalid filename '{filename}' ({filename_length} bytes)")
        return

    num_filename_packets = (filename_length + 1) // 2
    num_data_packets = (file_size + 1) // 2
    print(f"File: {source_path}")
    print(f"  Name:     '{filename}' ({filename_length} bytes, {num_filename_packets} packets)")
    print(f"  Contents: {file_size} bytes ({num_data_packets} packets)")

    # Open the ICMP recv socket first so we don't miss the ready-ack that
    # may arrive before we return from sending the command.
    try:
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        send_socket = open_raw_send_socket()
    except PermissionError:
        ctx.error_message = "permission denied (raw sockets require sudo)"
        handle_error(ctx)

    try:
        request_identifier = encrypt_identifier(CMD_TRANSFER_FILE)
        try:
            send_icmp_identifier(
                send_socket, ctx.source_ip, ctx.destination_ip, request_identifier, 1
            )
        except OSError as exc:
            ctx.error_message = f"failed to send transfer request: {exc}"
            ctx.error_code = 2
            handle_error(ctx)
        print(f"Sent transfer request (cmd={CMD_TRANSFER_FILE}). Waiting for ready ack...")

        deadline = time.time() + READY_TIMEOUT_SECONDS
        ready = False
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            recv_socket.settimeout(remaining)
            try:
                packet, _ = recv_socket.recvfrom(65535)
            except socket.timeout:
                break

            if len(packet) < 28:
                continue
            ip_header_length = (packet[0] & 0x0F) * 4
            if len(packet) < ip_header_length + 8:
                continue
            if socket.inet_ntoa(packet[12:16]) != ctx.destination_ip:
                continue

            icmp_header = packet[ip_header_length:ip_header_length + 8]
            icmp_type, _code, _chk, identifier, _seq = struct.unpack("!BBHHH", icmp_header)
            if icmp_type != 8:
                continue
            if decrypt_identifier(identifier) == ACK_READY:
                ready = True
                break

        if not ready:
            print("Transfer failed: no ready ack from hostb.")
            return

        print("hostb is ready. Sending file...")

        # Header: seq=1 file_size high16, seq=2 file_size low16, seq=3 filename length.
        try:
            send_icmp_identifier(
                send_socket, ctx.source_ip, ctx.destination_ip,
                encrypt_identifier((file_size >> 16) & 0xFFFF), 1,
            )
            if FILE_PACKET_DELAY_SECONDS > 0:
                time.sleep(FILE_PACKET_DELAY_SECONDS)
            send_icmp_identifier(
                send_socket, ctx.source_ip, ctx.destination_ip,
                encrypt_identifier(file_size & 0xFFFF), 2,
            )
            if FILE_PACKET_DELAY_SECONDS > 0:
                time.sleep(FILE_PACKET_DELAY_SECONDS)
            send_icmp_identifier(
                send_socket, ctx.source_ip, ctx.destination_ip,
                encrypt_identifier(filename_length), 3,
            )
            if FILE_PACKET_DELAY_SECONDS > 0:
                time.sleep(FILE_PACKET_DELAY_SECONDS)
        except OSError as exc:
            ctx.error_message = f"failed to send header packet: {exc}"
            ctx.error_code = 2
            handle_error(ctx)

        # Body: filename bytes followed by file data bytes, two bytes per
        # packet. Logical sequence increments forever; wire sequence wraps
        # at 16 bits. Receiver appends body packets in arrival order, so
        # this works as long as the network preserves order (LAN does).
        body_stream = filename_bytes + file_bytes
        body_total = (len(body_stream) + 1) // 2
        log_interval = max(1000, body_total // 100)
        logical_seq = 4
        for i in range(0, len(body_stream), 2):
            high = body_stream[i]
            low = body_stream[i + 1] if i + 1 < len(body_stream) else 0
            chunk_value = (high << 8) | low
            try:
                send_icmp_identifier(
                    send_socket, ctx.source_ip, ctx.destination_ip,
                    encrypt_identifier(chunk_value), logical_seq & 0xFFFF,
                )
            except OSError as exc:
                ctx.error_message = (
                    f"failed to send body packet (logical seq {logical_seq}): {exc}"
                )
                ctx.error_code = 2
                handle_error(ctx)

            body_index = logical_seq - 3
            if body_index % log_interval == 0:
                pct = (body_index * 100) // body_total
                print(f"  ... sent {body_index}/{body_total} body packets ({pct}%)")

            logical_seq += 1
            if FILE_PACKET_DELAY_SECONDS > 0:
                time.sleep(FILE_PACKET_DELAY_SECONDS)

        total_packets = 3 + body_total
        print(
            f"Transfer complete: sent {total_packets} ICMP packets "
            f"({filename_length} byte name + {file_size} byte file)."
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
