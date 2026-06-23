#!/usr/bin/env python3
"""hostb: listen for the port-knock sequence, then ack hosta.

All knocks from a given source IP must arrive within KNOCK_TIMEOUT_SECONDS.
When the full sequence completes, send a raw-socket ack back to hosta so
the control center knows the connection is established.

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
from typing import Any, Callable

from scapy.all import AsyncSniffer, IP, TCP

KNOCK_PORTS = (7000, 8000, 9000)
KNOCK_TIMEOUT_SECONDS = 5.0
ACK_SOURCE_PORT = 9000
ACK_DESTINATION_PORT = 54321
TTL = 64

BPF_FILTER = (
    "tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn and ("
    + " or ".join(f"dst port {p}" for p in KNOCK_PORTS)
    + ")"
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", help="interface to sniff on")
    args = parser.parse_args()

    def on_authenticated(hosta_ip: str) -> None:
        try:
            send_connection_ack(hosta_ip)
            print(f"[ACK] sent to {hosta_ip}")
        except OSError as exc:
            print(f"[ACK] failed: {exc}")

    watcher = KnockWatcher(on_authenticated)
    stop_requested = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop_requested.set())
    signal.signal(signal.SIGTERM, lambda *_: stop_requested.set())

    sniffer = AsyncSniffer(
        iface=args.iface, filter=BPF_FILTER, prn=watcher, store=False
    )
    sniffer.start()
    print(f"listening on {args.iface or 'default'}; Ctrl+C to stop")

    try:
        while sniffer.running and not stop_requested.is_set():
            time.sleep(0.1)
    finally:
        if sniffer.running:
            sniffer.stop(join=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
