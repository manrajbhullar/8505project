"""hostb: knock-then-command listener for the remote administration tool.
Usage:
    sudo python3 hostb.py -i <interface>
"""

import argparse
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


def build_ip_header(source_ip, destination_ip, total_length):
    def with_checksum(checksum):
        return struct.pack(
            "!BBHHHBBH4s4s",
            0x45,                     # version 4, header length 5 (20 bytes)
            0,                        # type of service
            total_length,
            0,                        # identification
            0,                        # flags + fragment offset
            TTL,
            socket.IPPROTO_TCP,
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
    def __init__(self, expected_source, on_disconnect):
        self.expected_source = expected_source
        self.on_disconnect = on_disconnect

    def __call__(self, packet):
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

        if command_code == CMD_DISCONNECT:
            print("[DISCONNECT] received")
            self.on_disconnect()
        else:
            print(f"[CMD] unknown command code {command_code}")


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


def listen_for_command(ctx: Context):
    if not ctx.connected:
        return

    done = threading.Event()
    watcher = CommandWatcher(expected_source=ctx.connected_to, on_disconnect=done.set)
    sniffer = AsyncSniffer(iface=ctx.iface, filter=BPF_COMMAND, prn=watcher, store=False)
    sniffer.start()
    print(f"[CMD] waiting for commands from {ctx.connected_to}")

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

    if done.is_set():
        print(f"[DISCONNECTED] {ctx.connected_to}")
    ctx.connected = False
    ctx.connected_to = None


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
        print("\nListening for commands...")
        listen_for_command(ctx)

    print("\nShutting down.")
