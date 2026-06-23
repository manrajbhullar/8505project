#!/usr/bin/env python3
"""hostb: knock-then-command listener for the remote administration tool.

Phase 1 (DISCONNECTED): sniff for the 3-port SYN knock from any source.
On success, send a raw-socket ack back and transition to phase 2.

Phase 2 (CONNECTED): sniff ICMP echo requests from the connected hosta.
Decrypt the identifier field to get a command code; sequence field gives
packet order. On CMD_DISCONNECT, return to phase 1.

Usage:
    sudo python3 hostb.py --iface <interface>
"""

import argparse
import signal
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

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
            socket.IPPROTO_TCP,
            checksum_value,
            socket.inet_aton(source_ip),
            socket.inet_aton(destination_ip),
        )
    correct_checksum = compute_checksum(header_with_checksum(0))
    return header_with_checksum(correct_checksum)


def build_tcp_ack_header(source_ip: str, destination_ip: str) -> bytes:
    def header_with_checksum(checksum_value: int) -> bytes:
        return struct.pack(
            "!HHLLBBHHH",
            ACK_SOURCE_PORT,
            ACK_DESTINATION_PORT,
            0,                        # sequence number
            1,                        # ack number
            0x50,                     # data offset 5 (20 bytes), reserved 0
            0x10,                     # flags: ACK only
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


def send_connection_ack(hosta_ip: str) -> None:
    source_ip = detect_source_ip(hosta_ip)
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
        tcp_header = build_tcp_ack_header(source_ip, hosta_ip)
        ip_header = build_ip_header(source_ip, hosta_ip, 20 + len(tcp_header))
        raw_socket.sendto(ip_header + tcp_header, (hosta_ip, ACK_DESTINATION_PORT))
    finally:
        raw_socket.close()


def decrypt_identifier(ciphertext: int) -> int:
    return (ciphertext ^ PRE_SHARED_KEY) & 0xFFFF


@dataclass
class KnockProgress:
    knocks_received: int
    sequence_started_at: float


class KnockWatcher:
    def __init__(self, on_authenticated: Callable[[str], None]) -> None:
        self.in_progress: dict[str, KnockProgress] = {}
        self.lock = threading.Lock()
        self.on_authenticated = on_authenticated

    def __call__(self, packet: Any) -> None:
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
    def __init__(self, expected_source: str, on_disconnect: Callable[[], None]) -> None:
        self.expected_source = expected_source
        self.on_disconnect = on_disconnect

    def __call__(self, packet: Any) -> None:
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


def wait_for_knock(iface: Optional[str], stop_requested: threading.Event) -> Optional[str]:
    result: dict[str, Optional[str]] = {"hosta_ip": None}
    done = threading.Event()

    def on_authenticated(hosta_ip: str) -> None:
        result["hosta_ip"] = hosta_ip
        done.set()

    watcher = KnockWatcher(on_authenticated)
    sniffer = AsyncSniffer(iface=iface, filter=BPF_KNOCK, prn=watcher, store=False)
    sniffer.start()
    print(f"[KNOCK] listening on {iface or 'default'}; Ctrl+C to stop")

    try:
        while sniffer.running and not done.is_set() and not stop_requested.is_set():
            time.sleep(0.1)
    finally:
        if sniffer.running:
            sniffer.stop(join=True)

    return result["hosta_ip"]


def wait_for_commands(
    iface: Optional[str], hosta_ip: str, stop_requested: threading.Event
) -> None:
    done = threading.Event()
    watcher = CommandWatcher(expected_source=hosta_ip, on_disconnect=done.set)
    sniffer = AsyncSniffer(iface=iface, filter=BPF_COMMAND, prn=watcher, store=False)
    sniffer.start()
    print(f"[CMD] waiting for commands from {hosta_ip}")

    try:
        while sniffer.running and not done.is_set() and not stop_requested.is_set():
            time.sleep(0.1)
    finally:
        if sniffer.running:
            sniffer.stop(join=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", help="interface to sniff on")
    args = parser.parse_args()

    stop_requested = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop_requested.set())
    signal.signal(signal.SIGTERM, lambda *_: stop_requested.set())

    while not stop_requested.is_set():
        hosta_ip = wait_for_knock(args.iface, stop_requested)
        if hosta_ip is None:
            break

        try:
            send_connection_ack(hosta_ip)
            print(f"[ACK] sent to {hosta_ip}")
        except OSError as exc:
            print(f"[ACK] failed: {exc}")
            continue

        print(f"[CONNECTED] {hosta_ip}")
        wait_for_commands(args.iface, hosta_ip, stop_requested)
        print(f"[DISCONNECTED] {hosta_ip}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
