#!/usr/bin/env python3
"""Synthesize a pcap of one SSH connection: TCP handshake, banners, NEWKEYS, then a data tail.

No committed trace has SSH, and Iris rejects TCP connections that do not start with a bare SYN, so
this builds the full three-way handshake before the banners.

Two different bars have to be cleared, which is why the NEWKEYS exchange is here:

  * The `ssh` *filter* matches as soon as the probe sees "SSH-" in the first four payload bytes,
    i.e. on the banner alone.
  * An `SshHandshake` *datatype* only exists once the parser returns `HeadersDone`, which it does
    only after both sides have sent SSH_MSG_NEWKEYS (see core/src/protocols/stream/ssh/parser.rs).

So a callback that takes `ssh: &SshHandshake` needs the NEWKEYS packets; one that does not would
fire on the banner. The NEWKEYS packets below are minimal but well-formed per RFC 4253: a 16-byte
binary packet carrying the single payload byte 21, padded so the total is a multiple of 8.
"""
import struct
import sys

CLIENT_IP = bytes([10, 0, 0, 1])
SERVER_IP = bytes([10, 0, 0, 2])
CLIENT_PORT = 51000
SERVER_PORT = 22
BANNER = b"SSH-2.0-OpenSSH_9.0p1\r\n"

SSH_MSG_NEWKEYS = 21


def ssh_binary_packet(payload: bytes) -> bytes:
    """One unencrypted SSH binary packet (RFC 4253 s6).

    Layout is uint32 packet_length, byte padding_length, payload, padding -- where packet_length
    covers everything after itself. Padding is at least 4 bytes and the whole packet must be a
    multiple of 8, so pad up to that.
    """
    # 4 (length) + 1 (padding_length) + payload + padding, rounded up to a multiple of 8 with at
    # least 4 bytes of padding.
    unpadded = 4 + 1 + len(payload)
    padding_len = 8 - (unpadded % 8)
    while padding_len < 4:
        padding_len += 8
    packet_len = 1 + len(payload) + padding_len
    return struct.pack("!IB", packet_len, padding_len) + payload + b"\x00" * padding_len


NEWKEYS = ssh_binary_packet(bytes([SSH_MSG_NEWKEYS]))
TAIL_PKTS = 24  # enough for pkts.total() to pass the offload threshold
TAIL_LEN = 200


def ip_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def frame(src_ip, dst_ip, sport, dport, seq, ack, flags, payload, ip_id):
    # data offset 5 (20-byte header), no options
    tcp = struct.pack(
        "!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0
    ) + payload

    total_len = 20 + len(tcp)
    ip_no_ck = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, ip_id, 0x4000, 64, 6, 0, src_ip, dst_ip,
    )
    ck = ip_checksum(ip_no_ck)
    ip = ip_no_ck[:10] + struct.pack("!H", ck) + ip_no_ck[12:]

    if src_ip == CLIENT_IP:
        eth = bytes([0x02, 0, 0, 0, 0, 2]) + bytes([0x02, 0, 0, 0, 0, 1])
    else:
        eth = bytes([0x02, 0, 0, 0, 0, 1]) + bytes([0x02, 0, 0, 0, 0, 2])
    return eth + struct.pack("!H", 0x0800) + ip + tcp


FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def main(path):
    pkts = []
    ip_id = 0

    def add(src, dst, sport, dport, seq, ack, flags, payload=b""):
        nonlocal ip_id
        ip_id += 1
        pkts.append(frame(src, dst, sport, dport, seq, ack, flags, payload, ip_id))

    c_seq, s_seq = 1000, 5000

    # Three-way handshake. Iris requires the connection to open with a bare SYN.
    add(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, c_seq, 0, SYN)
    c_seq += 1
    add(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, s_seq, c_seq, SYN | ACK)
    s_seq += 1
    add(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, c_seq, s_seq, ACK)

    # Banner exchange -- this is what the ssh probe matches on.
    add(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, c_seq, s_seq, PSH | ACK, BANNER)
    c_seq += len(BANNER)
    add(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, s_seq, c_seq, PSH | ACK, BANNER)
    s_seq += len(BANNER)

    # NEWKEYS from both sides. This is what makes the parser emit a session, and so what makes an
    # `SshHandshake` datatype available to a callback.
    add(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, c_seq, s_seq, PSH | ACK, NEWKEYS)
    c_seq += len(NEWKEYS)
    add(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, s_seq, c_seq, PSH | ACK, NEWKEYS)
    s_seq += len(NEWKEYS)

    # Opaque tail, standing in for the encrypted body of the session.
    for i in range(TAIL_PKTS):
        payload = bytes((i * 13 + j) & 0xFF for j in range(TAIL_LEN))
        if i % 2 == 0:
            add(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, c_seq, s_seq, PSH | ACK, payload)
            c_seq += len(payload)
        else:
            add(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, s_seq, c_seq, PSH | ACK, payload)
            s_seq += len(payload)

    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, f in enumerate(pkts):
            fh.write(struct.pack("<IIII", 1_700_000_000, i * 1000, len(f), len(f)))
            fh.write(f)
    print(f"wrote {len(pkts)} packets (1 SSH connection) to {path}")


if __name__ == "__main__":
    main(sys.argv[1])
