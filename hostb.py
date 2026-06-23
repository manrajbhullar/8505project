"""hostb: knock-then-command listener for the remote administration tool.

Usage:
    sudo python3 hostb.py -i <interface>
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

from scapy.all import AsyncSniffer, ICMP, IP, TCP


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
INACTIVITY_TIMEOUT_SECONDS = 5.0
RECV_BUFFER_BYTES = 256 * 1024 * 1024         # request a 256 MB kernel recv buffer for file phase
SO_RCVBUFFORCE = 33                           # Linux: bypass net.core.rmem_max (needs root)

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


@dataclass
class Context:
    args: HostbArgs | None = None
    error_message: str | None = None
    error_code: int = 1
    iface: str | None = None
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
    def __init__(self, expected_source):
        self.expected_source = expected_source
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
        command_code = decrypt_identifier(encrypted)
        print(
            f"[CMD] from {self.expected_source} "
            f"id={encrypted:#06x} -> cmd={command_code} seq={sequence}"
        )
        self.command_code = command_code
        self.command_received.set()


class FileReceiveWatcher:
    """State for an in-progress file receive. Driven from the raw-socket
    loop in receive_file via feed(value, wire_seq); single-threaded, so
    no locking needed."""

    def __init__(self):
        self.file_size_hi: int | None = None
        self.file_size_lo: int | None = None
        self.filename_length: int | None = None
        self.expected_body: int | None = None
        self.body_packets: list[int] = []      # decrypted values in arrival order
        self.complete = False

    @property
    def file_size(self):
        if self.file_size_hi is None or self.file_size_lo is None:
            return None
        return (self.file_size_hi << 16) | self.file_size_lo

    def feed(self, value: int, wire_seq: int) -> None:
        if self.complete:
            return

        # Headers occupy wire seq 1, 2, 3. Each is only treated as a
        # header the first time it's seen, so the rollover-wrapped
        # versions for big files fall through into body.
        if wire_seq == 1 and self.file_size_hi is None:
            self.file_size_hi = value
            print(f"[FILE] file size high16: {value:#06x}")
        elif wire_seq == 2 and self.file_size_lo is None:
            self.file_size_lo = value
            print(f"[FILE] file size: {self.file_size} bytes")
        elif wire_seq == 3 and self.filename_length is None:
            self.filename_length = value
            print(f"[FILE] filename length: {value} bytes")
        else:
            # Body packet in arrival order. LAN delivery is in-order,
            # so position in body_packets implies logical sequence.
            self.body_packets.append(value)
            count = len(self.body_packets)
            if self.expected_body is not None:
                log_interval = max(1000, self.expected_body // 100)
                if count % log_interval == 0:
                    pct = (count * 100) // self.expected_body
                    print(f"[FILE] received {count}/{self.expected_body} body packets ({pct}%)")

        if (self.expected_body is None
            and self.file_size is not None
            and self.filename_length is not None):
            num_filename_packets = (self.filename_length + 1) // 2
            num_data_packets = (self.file_size + 1) // 2
            self.expected_body = num_filename_packets + num_data_packets
            print(
                f"[FILE] expecting {num_filename_packets} filename + "
                f"{num_data_packets} data = {self.expected_body} body packets"
            )

        if (self.expected_body is not None
            and len(self.body_packets) >= self.expected_body):
            self.complete = True


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
    parser.add_argument("-i", "--iface", dest="iface", required=False,
                        metavar="<interface>",
                        help="network interface to sniff on (default: scapy default)")

    try:
        parsed = parser.parse_args(argv)
    except SystemExit as exc:
        sys.exit(1 if exc.code else 0)

    ctx.args = HostbArgs(iface=parsed.iface)


def handle_arguments(ctx: Context):
    ctx.iface = ctx.args.iface
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

    watcher = CommandWatcher(expected_source=ctx.connected_to)
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

    # For the file phase we use a raw ICMP socket instead of scapy:
    # scapy's per-packet Python parsing tops out around 3-5 kpps, which
    # makes hostb fall behind on multi-megabyte transfers and the kernel
    # silently drops packets. Reading SOCK_RAW and decoding only the 8
    # bytes we need lifts the ceiling well into hosta-bound territory.
    try:
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        ctx.error_message = "permission denied (raw sockets require sudo)"
        handle_error(ctx)

    # Bump kernel recv buffer to absorb the whole transfer burst. SO_RCVBUFFORCE
    # bypasses net.core.rmem_max (root only); fall back to SO_RCVBUF if it fails.
    for opt in (SO_RCVBUFFORCE, socket.SO_RCVBUF):
        try:
            recv_socket.setsockopt(socket.SOL_SOCKET, opt, RECV_BUFFER_BYTES)
            break
        except OSError:
            continue
    actual_rcvbuf = recv_socket.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
    print(f"[FILE] kernel recv buffer: {actual_rcvbuf // (1024 * 1024)} MB")

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

    watcher = FileReceiveWatcher()
    src = socket.inet_aton(ctx.connected_to)
    expected_src_int = (src[0] << 24) | (src[1] << 16) | (src[2] << 8) | src[3]

    # Pre-allocated recv buffer + settimeout outside the loop avoids per-packet
    # allocation and the syscall to update the timeout. recvfrom_into writes
    # into the existing bytearray rather than producing a new bytes object.
    buf = bytearray(65535)
    recv_socket.settimeout(INACTIVITY_TIMEOUT_SECONDS)
    feed = watcher.feed                                 # local-name caches for speed
    decrypt = decrypt_identifier

    try:
        while not ctx.stop_requested.is_set() and not watcher.complete:
            try:
                nbytes, _ = recv_socket.recvfrom_into(buf, 65535)
            except socket.timeout:
                break

            if nbytes < 28:
                continue
            ihl = (buf[0] & 0x0F) * 4
            if nbytes < ihl + 8:
                continue
            if buf[ihl] != 8:                           # ICMP type: echo request
                continue
            src_int = (buf[12] << 24) | (buf[13] << 16) | (buf[14] << 8) | buf[15]
            if src_int != expected_src_int:
                continue

            identifier = (buf[ihl + 4] << 8) | buf[ihl + 5]
            wire_seq = (buf[ihl + 6] << 8) | buf[ihl + 7]
            feed(decrypt(identifier), wire_seq)
    finally:
        recv_socket.close()

    if not watcher.complete:
        got = len(watcher.body_packets)
        expected = watcher.expected_body if watcher.expected_body is not None else "?"
        print(f"[FILE] transfer incomplete: got {got}/{expected} body packets")
        return

    def pack_values(values, byte_length):
        out = bytearray()
        for v in values:
            out.append((v >> 8) & 0xFF)
            out.append(v & 0xFF)
        return bytes(out[:byte_length])

    num_filename_packets = (watcher.filename_length + 1) // 2

    filename_bytes = pack_values(
        watcher.body_packets[:num_filename_packets], watcher.filename_length
    )
    file_bytes = pack_values(
        watcher.body_packets[num_filename_packets:], watcher.file_size
    )

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
            else:
                print(f"Ignoring unknown command code {command_code}.")

    print("\nShutting down.")
