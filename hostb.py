#!/usr/bin/env python3
"""Victim: listen for the port-knock sequence.

All knocks from a given source IP must arrive within KNOCK_TIMEOUT_SECONDS.

Usage:
    sudo python3 victim.py --iface <interface>
"""

import argparse
import signal
import threading
import time
from dataclasses import dataclass
from typing import Any

from scapy.all import AsyncSniffer, IP, TCP

KNOCK_PORTS = (7000, 8000, 9000)
KNOCK_TIMEOUT_SECONDS = 5.0

BPF_FILTER = (
    "tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn and ("
    + " or ".join(f"dst port {p}" for p in KNOCK_PORTS)
    + ")"
)


@dataclass
class KnockProgress:
    knocks_received: int
    sequence_started_at: float


class KnockWatcher:
    def __init__(self) -> None:
        self.in_progress: dict[str, KnockProgress] = {}
        self.lock = threading.Lock()

    def __call__(self, packet: Any) -> None:
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return

        source_ip = packet[IP].src
        destination_port = int(packet[TCP].dport)
        now = time.time()

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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", help="interface to sniff on")
    args = parser.parse_args()

    watcher = KnockWatcher()
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
