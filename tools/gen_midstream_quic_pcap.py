#!/usr/bin/env python3
"""Synthesize a pcap of mid-stream QUIC: UDP/443 with 1-RTT short headers only.

No handshake, so Iris's quic probe answers Unsure and never concludes -- which means L7OnDisc is
never dispatched, MaybeQuic's veto never fires, and the heuristic runs to its own verdict. This is
exactly the population MaybeQuic exists to catch, and no committed trace contains it.

Satisfies MaybeQuic's gates: >= MAYBE_QUIC_REQUIRED_MATCHES (11) short-header packets within a
12-packet window, >= MAYBE_QUIC_MIN_DISTINCT_LOW5 (5) distinct low-5-bit values in the first byte,
and datagrams above MIN_1RTT_DATAGRAM_LEN (21).
"""
import struct
import sys

N_PKTS = 20
PAYLOAD_LEN = 40  # comfortably above MIN_1RTT_DATAGRAM_LEN


def ip_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def make_frame(i: int) -> bytes:
    # Short header: top two bits 01 (form=0, fixed=1). Vary the low five bits, which header
    # protection randomizes per packet and which MaybeQuic's entropy check counts.
    first = 0x40 | (i % 32)
    payload = bytes([first]) + bytes((i * 7 + j) & 0xFF for j in range(PAYLOAD_LEN - 1))

    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", 50000, 443, udp_len, 0) + payload

    total_len = 20 + udp_len
    ip_no_ck = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, i, 0, 64, 17, 0,
        bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]),
    )
    ck = ip_checksum(ip_no_ck)
    ip = ip_no_ck[:10] + struct.pack("!H", ck) + ip_no_ck[12:]

    eth = bytes([0x02, 0, 0, 0, 0, 2]) + bytes([0x02, 0, 0, 0, 0, 1]) + struct.pack("!H", 0x0800)
    return eth + ip + udp


def main(path: str) -> None:
    with open(path, "wb") as fh:
        # pcap global header: magic, v2.4, no tz/sigfigs, snaplen, LINKTYPE_ETHERNET
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i in range(N_PKTS):
            frame = make_frame(i)
            ts_sec = 1_700_000_000 + i // 100
            ts_usec = (i % 100) * 1000
            fh.write(struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame)))
            fh.write(frame)
    print(f"wrote {N_PKTS} mid-stream QUIC packets to {path}")


if __name__ == "__main__":
    main(sys.argv[1])
