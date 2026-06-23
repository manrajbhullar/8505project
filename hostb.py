"""hostb: knock-then-command listener for the remote administration tool.

Usage:
    sudo python3 hostb.py
"""

import argparse
import os
import signal
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass, field


KNOCK_PORTS = (7000, 8000, 9000)
KNOCK_TIMEOUT_SECONDS = 5.0
ACK_SOURCE_PORT = 9000
ACK_DESTINATION_PORT = 54321
TTL = 64
PRE_SHARED_KEY = 0xA5C3
CMD_DISCONNECT = 1
CMD_TRANSFER_FILE = 2
ACK_READY = 0xFFFE

RECEIVED_FILE_PREFIX = "received_"
RECEIVED_FALLBACK_NAME = "received_file"
FILE_TRANSFER_TIMEOUT_SECONDS = 10.0

# How long to block in recvfrom() before re-checking stop_requested.
RECV_POLL_TIMEOUT_SECONDS = 0.2

# TCP flag bits.
TCP_SYN_FLAG = 0x02
TCP_ACK_FLAG = 0x10
TCP_SYN_ACK_MASK = TCP_SYN_FLAG | TCP_ACK_FLAG   # mask used to require "SYN, no ACK"

ICMP_ECHO_REQUEST_TYPE = 8

# Mimic Linux `ping`: 8-byte timestamp slot (zeroed) + 48 bytes of the
# 0x10..0x3F filler pattern. hosta ignores this payload — it only reads
# the identifier and sequence header fields.
PING_PAYLOAD = b"\x00" * 8 + bytes(range(0x10, 0x40))


@dataclass
class HostbArgs:
    pass


@dataclass
class Context:
    args: HostbArgs | None = None
    error_message: str | None = None
    error_code: int = 1
    connected_to: str | None = None
    connected: bool = False
    stop_requested: threading.Event = field(default_factory=threading.Event)


@dataclass
class KnockProgress:
    knocks_received: int
    sequence_started_at: float


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


def build_tcp_ack_header(source_ip, destination_ip):
    def with_checksum(checksum):
        return struct.pack(
            "!HHLLBBHHH",
            ACK_SOURCE_PORT,
            ACK_DESTINATION_PORT,
            0,                        # sequence number
            1,                        # ack number
            0x50,                     # data offset 5 (20 bytes), reserved 0
            0x10,                     # flags: ACK only
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


def parse_ip_packet(packet):
    """Return (ip_header_length, source_ip) or None if malformed."""
    if len(packet) < 20:
        return None
    ip_header_length = (packet[0] & 0x0F) * 4
    if len(packet) < ip_header_length:
        return None
    source_ip = socket.inet_ntoa(packet[12:16])
    return ip_header_length, source_ip


def parse_tcp_header(packet, ip_header_length):
    """Return (src_port, dst_port, flags) or None if too short."""
    if len(packet) < ip_header_length + 20:
        return None
    src_port, dst_port, _seq, _ack, _offset, flags, _w, _c, _u = struct.unpack(
        "!HHLLBBHHH", packet[ip_header_length:ip_header_length + 20]
    )
    return src_port, dst_port, flags


def parse_icmp_header(packet, ip_header_length):
    """Return (type, code, identifier, sequence) or None if too short."""
    if len(packet) < ip_header_length + 8:
        return None
    icmp_type, code, _checksum, identifier, sequence = struct.unpack(
        "!BBHHH", packet[ip_header_length:ip_header_length + 8]
    )
    return icmp_type, code, identifier, sequence


class KnockTracker:
    """Tracks per-source-IP progress through the knock sequence.

    Call `process(source_ip, destination_port)` for each SYN-only packet
    received. Returns the authenticated source_ip when the full sequence
    completes for that source, otherwise None.
    """
    def __init__(self):
        self.in_progress: dict[str, KnockProgress] = {}

    def process(self, source_ip: str, destination_port: int) -> str | None:
        now = time.time()
        progress = self.in_progress.get(source_ip)

        if progress and now - progress.sequence_started_at > KNOCK_TIMEOUT_SECONDS:
            progress = None
            self.in_progress.pop(source_ip, None)

        next_knock_index = progress.knocks_received if progress else 0
        already_accepted_ports = KNOCK_PORTS[:next_knock_index]

        # Loopback can deliver the same SYN twice; ignore the echo.
        if progress and destination_port in already_accepted_ports:
            return None

        expected_port = KNOCK_PORTS[next_knock_index]
        if destination_port != expected_port:
            self.in_progress.pop(source_ip, None)
            return None

        knocks_received = next_knock_index + 1
        print(f"[{knocks_received}/{len(KNOCK_PORTS)}] {source_ip} -> :{destination_port}")

        if knocks_received == len(KNOCK_PORTS):
            self.in_progress.pop(source_ip, None)
            print(f"[AUTH] {source_ip}")
            return source_ip

        sequence_started_at = progress.sequence_started_at if progress else now
        self.in_progress[source_ip] = KnockProgress(
            knocks_received=knocks_received,
            sequence_started_at=sequence_started_at,
        )
        return None


# ---------------------------------------------------------------------------
# FSM state functions
# ---------------------------------------------------------------------------

def handle_error(ctx: Context):
    sys.stderr.write(f"\nError: {ctx.error_message}\n")
    sys.stderr.write(f"Exit Code: {ctx.error_code}\n")
    sys.exit(ctx.error_code)


def parse_arguments(ctx: Context, argv: list[str] | None = None):
    parser = argparse.ArgumentParser(
        prog="hostb",
        description="Knock-then-command listener for the remote administration tool.",
    )

    try:
        parser.parse_args(argv)
    except SystemExit as exc:
        sys.exit(1 if exc.code else 0)

    ctx.args = HostbArgs()


def handle_arguments(ctx: Context):
    signal.signal(signal.SIGINT, lambda *_: ctx.stop_requested.set())
    signal.signal(signal.SIGTERM, lambda *_: ctx.stop_requested.set())


def wait_for_session(ctx: Context):
    try:
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except PermissionError:
        ctx.error_message = "permission denied (raw sockets require sudo)"
        handle_error(ctx)
    recv_socket.settimeout(RECV_POLL_TIMEOUT_SECONDS)

    tracker = KnockTracker()
    print("[KNOCK] listening; Ctrl+C to stop")

    try:
        while not ctx.stop_requested.is_set():
            try:
                packet, _ = recv_socket.recvfrom(65535)
            except socket.timeout:
                continue

            parsed = parse_ip_packet(packet)
            if parsed is None:
                continue
            ip_header_length, source_ip = parsed

            tcp = parse_tcp_header(packet, ip_header_length)
            if tcp is None:
                continue
            _src_port, dst_port, flags = tcp

            if (flags & TCP_SYN_ACK_MASK) != TCP_SYN_FLAG:
                continue
            if dst_port not in KNOCK_PORTS:
                continue

            authenticated = tracker.process(source_ip, dst_port)
            if authenticated is not None:
                ctx.connected_to = authenticated
                return
    finally:
        recv_socket.close()


def establish_session(ctx: Context):
    if not ctx.connected_to:
        return

    source_ip = detect_source_ip(ctx.connected_to)
    try:
        raw_socket = open_raw_send_socket()
    except PermissionError:
        ctx.error_message = "permission denied (raw sockets require sudo)"
        handle_error(ctx)

    try:
        tcp_header = build_tcp_ack_header(source_ip, ctx.connected_to)
        ip_header = build_ip_header(source_ip, ctx.connected_to, 20 + len(tcp_header))
        try:
            raw_socket.sendto(
                ip_header + tcp_header,
                (ctx.connected_to, ACK_DESTINATION_PORT),
            )
        except OSError as exc:
            ctx.error_message = f"failed to send ack: {exc}"
            ctx.error_code = 2
            handle_error(ctx)
    finally:
        raw_socket.close()

    print(f"[ACK] sent to {ctx.connected_to}")
    ctx.connected = True
    print(f"[CONNECTED] {ctx.connected_to}")


def listen_for_command(ctx: Context) -> int | None:
    if not ctx.connected:
        return None

    try:
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        ctx.error_message = "permission denied (raw sockets require sudo)"
        handle_error(ctx)
    recv_socket.settimeout(RECV_POLL_TIMEOUT_SECONDS)

    print(f"[CMD] waiting for commands from {ctx.connected_to}")

    try:
        while not ctx.stop_requested.is_set():
            try:
                packet, _ = recv_socket.recvfrom(65535)
            except socket.timeout:
                continue

            parsed = parse_ip_packet(packet)
            if parsed is None:
                continue
            ip_header_length, source_ip = parsed
            if source_ip != ctx.connected_to:
                continue

            icmp = parse_icmp_header(packet, ip_header_length)
            if icmp is None:
                continue
            icmp_type, _code, identifier, sequence = icmp
            if icmp_type != ICMP_ECHO_REQUEST_TYPE:
                continue

            command_code = decrypt_identifier(identifier)
            print(
                f"[CMD] from {source_ip} "
                f"id={identifier:#06x} -> cmd={command_code} seq={sequence}"
            )
            return command_code
    finally:
        recv_socket.close()

    return None


def receive_file(ctx: Context):
    if not ctx.connected_to:
        return

    # Open the recv socket before sending the ready-ack so the first file
    # packets land in our kernel buffer even if we haven't called
    # recvfrom() yet.
    try:
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        ctx.error_message = "permission denied (raw sockets require sudo)"
        handle_error(ctx)
    recv_socket.settimeout(RECV_POLL_TIMEOUT_SECONDS)

    source_ip = detect_source_ip(ctx.connected_to)
    try:
        send_socket = open_raw_send_socket()
    except PermissionError:
        recv_socket.close()
        ctx.error_message = "permission denied (raw sockets require sudo)"
        handle_error(ctx)

    try:
        icmp_packet = build_icmp_echo_request(encrypt_identifier(ACK_READY), 1)
        ip_header = build_ip_header(
            source_ip, ctx.connected_to,
            20 + len(icmp_packet), socket.IPPROTO_ICMP,
        )
        try:
            send_socket.sendto(ip_header + icmp_packet, (ctx.connected_to, 0))
        except OSError as exc:
            recv_socket.close()
            ctx.error_message = f"failed to send ready ack: {exc}"
            ctx.error_code = 2
            handle_error(ctx)
    finally:
        send_socket.close()

    print(f"[ACK_READY] sent to {ctx.connected_to}")

    filename_length: int | None = None
    file_size: int | None = None
    packets: dict[int, int] = {}
    expected_total: int | None = None
    deadline = time.time() + FILE_TRANSFER_TIMEOUT_SECONDS

    try:
        while not ctx.stop_requested.is_set():
            if time.time() >= deadline:
                break
            try:
                packet, _ = recv_socket.recvfrom(65535)
            except socket.timeout:
                continue

            parsed = parse_ip_packet(packet)
            if parsed is None:
                continue
            ip_header_length, src_ip = parsed
            if src_ip != ctx.connected_to:
                continue

            icmp = parse_icmp_header(packet, ip_header_length)
            if icmp is None:
                continue
            icmp_type, _code, identifier, sequence = icmp
            if icmp_type != ICMP_ECHO_REQUEST_TYPE:
                continue

            value = decrypt_identifier(identifier)
            packets[sequence] = value

            if sequence == 1:
                filename_length = value
                print(f"[FILE] filename length: {value} bytes")
            elif sequence == 2:
                file_size = value
                print(f"[FILE] file size: {value} bytes")
            else:
                print(f"[FILE] seq={sequence} ({len(packets)} packets total)")

            if filename_length is not None and file_size is not None:
                num_filename_packets = (filename_length + 1) // 2
                num_data_packets = (file_size + 1) // 2
                expected_total = 2 + num_filename_packets + num_data_packets
                if len(packets) >= expected_total:
                    break
    finally:
        recv_socket.close()

    if expected_total is None or len(packets) < expected_total:
        print(f"[FILE] transfer incomplete: got {len(packets)} packets")
        return

    def collect_chunks(start_seq: int, count: int, byte_length: int, label: str) -> bytes | None:
        out = bytearray()
        for i in range(count):
            seq = start_seq + i
            if seq not in packets:
                print(f"[FILE] missing {label} packet seq={seq}; aborting write")
                return None
            value = packets[seq]
            out.append((value >> 8) & 0xFF)
            out.append(value & 0xFF)
        return bytes(out[:byte_length])

    num_filename_packets = (filename_length + 1) // 2
    num_data_packets = (file_size + 1) // 2

    filename_bytes = collect_chunks(3, num_filename_packets, filename_length, "filename")
    if filename_bytes is None:
        return
    file_bytes = collect_chunks(
        3 + num_filename_packets, num_data_packets, file_size, "data"
    )
    if file_bytes is None:
        return

    try:
        decoded_name = filename_bytes.decode("utf-8")
    except UnicodeDecodeError:
        decoded_name = ""
    safe_name = os.path.basename(decoded_name.replace("\\", "/"))
    if not safe_name or safe_name in (".", "..") or "\x00" in safe_name:
        safe_name = RECEIVED_FALLBACK_NAME
    output_path = RECEIVED_FILE_PREFIX + safe_name

    try:
        with open(output_path, "wb") as f:
            f.write(file_bytes)
    except OSError as exc:
        ctx.error_message = f"failed to write {output_path}: {exc}"
        ctx.error_code = 2
        handle_error(ctx)

    print(f"[FILE] reproduced {output_path} ({len(file_bytes)} bytes)")


if __name__ == "__main__":
    print("--------------- HOSTB ---------------")
    ctx = Context()
    parse_arguments(ctx)
    handle_arguments(ctx)

    while not ctx.stop_requested.is_set():
        print("\nWaiting for session...")
        wait_for_session(ctx)
        if ctx.connected_to is None:
            break
        print("\nEstablishing session...")
        establish_session(ctx)

        while ctx.connected and not ctx.stop_requested.is_set():
            print("\nListening for commands...")
            command_code = listen_for_command(ctx)
            if command_code is None:
                break
            if command_code == CMD_DISCONNECT:
                print(f"[DISCONNECTED] {ctx.connected_to}")
                ctx.connected = False
                ctx.connected_to = None
                break
            elif command_code == CMD_TRANSFER_FILE:
                print("\nReceiving file...")
                receive_file(ctx)
            else:
                print(f"Ignoring unknown command code {command_code}.")

    print("\nShutting down.")
