#!/usr/bin/env python3
"""hostb: ICMP-only knock-then-command listener.

Phase 1 (DISCONNECTED): sniff incoming ICMP echo requests; the decrypted
identifier must match KNOCK_IDS in order. On success, send an ICMP echo
reply tagged with encrypted(ACK_MAGIC) and transition to phase 2.

Phase 2 (CONNECTED): sniff ICMP echo requests from the connected hosta,
decrypt the identifier as a command code, dispatch. CMD_DISCONNECT
returns to phase 1.

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

from scapy.all import AsyncSniffer, ICMP, IP

KNOCK_IDS = (7000, 8000, 9000)
KNOCK_TIMEOUT_SECONDS = 5.0
ACK_MAGIC = 0xACAC
PRE_SHARED_KEY = 0xA5C3
CMD_DISCONNECT = 1
TTL = 64
ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8

PING_PAYLOAD = b"\x00" * 8 + bytes(range(0x10, 0x40))

BPF_ICMP_ECHO = "icmp[icmptype] = icmp-echo"


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
            socket.IPPROTO_ICMP,
            checksum_value,
            socket.inet_aton(source_ip),
            socket.inet_aton(destination_ip),
        )
    correct_checksum = compute_checksum(header_with_checksum(0))
    return header_with_checksum(correct_checksum)


def encrypt_identifier(plaintext: int) -> int:
    return (plaintext ^ PRE_SHARED_KEY) & 0xFFFF


def decrypt_identifier(ciphertext: int) -> int:
    return (ciphertext ^ PRE_SHARED_KEY) & 0xFFFF


def build_icmp_echo_reply(identifier_encrypted: int, sequence: int) -> bytes:
    def packet_with_checksum(checksum_value: int) -> bytes:
        header = struct.pack(
            "!BBHHH",
            ICMP_ECHO_REPLY,
            0,                         # code
            checksum_value,
            identifier_encrypted,
            sequence,
        )
        return header + PING_PAYLOAD
    correct_checksum = compute_checksum(packet_with_checksum(0))
    return packet_with_checksum(correct_checksum)


def send_connection_ack(hosta_ip: str) -> None:
    source_ip = detect_source_ip(hosta_ip)
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
        identifier = encrypt_identifier(ACK_MAGIC)
        icmp_packet = build_icmp_echo_reply(identifier, 0)
        ip_header = build_ip_header(source_ip, hosta_ip, 20 + len(icmp_packet))
        raw_socket.sendto(ip_header + icmp_packet, (hosta_ip, 0))
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
        if not (packet.haslayer(IP) and packet.haslayer(ICMP)):
            return
        if int(packet[ICMP].type) != ICMP_ECHO_REQUEST:
            return

        source_ip = packet[IP].src
        encrypted = int(packet[ICMP].id) & 0xFFFF
        knock_value = decrypt_identifier(encrypted)
        now = time.time()
        sequence_complete = False

        with self.lock:
            progress = self.in_progress.get(source_ip)

            if progress and now - progress.sequence_started_at > KNOCK_TIMEOUT_SECONDS:
                progress = None
                self.in_progress.pop(source_ip, None)

            next_knock_index = progress.knocks_received if progress else 0
            expected_id = KNOCK_IDS[next_knock_index]

            if knock_value != expected_id:
                self.in_progress.pop(source_ip, None)
                return

            knocks_received = next_knock_index + 1
            print(f"[{knocks_received}/{len(KNOCK_IDS)}] {source_ip} knock={knock_value}")

            sequence_complete = knocks_received == len(KNOCK_IDS)
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
        if int(packet[ICMP].type) != ICMP_ECHO_REQUEST:
            return

        encrypted = int(packet[ICMP].id) & 0xFFFF
        sequence = int(packet[ICMP].seq) & 0xFFFF
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
    sniffer = AsyncSniffer(iface=iface, filter=BPF_ICMP_ECHO, prn=watcher, store=False)
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
    sniffer = AsyncSniffer(iface=iface, filter=BPF_ICMP_ECHO, prn=watcher, store=False)
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
