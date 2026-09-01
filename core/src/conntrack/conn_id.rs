//! Bidirectional connection identifiers.
//!
//! Provides endpoint-specific (distinguishes originator and responder) and generic identifiers for bi-directional connections.
//! Iris defines a "connection" by five tuple (source/destination addresses, ports, and transport protocol).

use crate::conntrack::L4Context;

use crate::protocols::packet::tcp::TCP_PROTOCOL;
use crate::protocols::packet::udp::UDP_PROTOCOL;
use std::cmp;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddr::V4, SocketAddr::V6};

use serde::Serialize;

/// Connection 5-tuple.
///
/// The sender of the first observed packet in the connection becomes the originator `orig`, and the
/// recipient becomes the responder `resp`.
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Serialize)]
pub struct FiveTuple {
    /// The originator connection endpoint.
    pub orig: SocketAddr,
    /// The responder connection endpoint.
    pub resp: SocketAddr,
    /// The layer-4 protocol.
    pub proto: usize,
}

impl FiveTuple {
    /// Creates a new 5-tuple from `ctxt`.
    pub fn from_ctxt(ctxt: &L4Context) -> Self {
        FiveTuple {
            orig: ctxt.src,
            resp: ctxt.dst,
            proto: ctxt.proto,
        }
    }

    /// Converts a 5-tuple to a non-directional connection identifier.
    pub fn conn_id(&self) -> ConnId {
        ConnId::new(self.orig, self.resp, self.proto)
    }

    /// Non-bucketed u64 hash of the canonicalized five-tuple.
    ///
    /// Paired downstream with `first_seen_ts` to form
    /// the composite connection key; `conn_hash` alone is NOT unique.
    pub fn conn_hash(&self) -> u64 {
        const FNV_OFFSET: u64 = 0xcbf29ce484222325;
        const FNV_PRIME: u64 = 0x100000001b3;

        #[inline]
        fn mix(mut h: u64, v: u64) -> u64 {
            for byte in v.to_le_bytes() {
                h ^= byte as u64;
                h = h.wrapping_mul(FNV_PRIME);
            }
            h
        }

        #[inline]
        fn hash_sockaddr(sa: SocketAddr) -> u64 {
            let ip: u64 = match sa {
                V4(a) => a.ip().to_bits() as u64,
                V6(a) => {
                    let n = a.ip().to_bits();
                    (n as u64) ^ ((n >> 64) as u64)
                }
            };
            (ip << 16) ^ (sa.port() as u64)
        }

        let (hi, lo) = (cmp::max(self.orig, self.resp), cmp::min(self.orig, self.resp));
        let mut h = FNV_OFFSET;
        h = mix(h, hash_sockaddr(hi));
        h = mix(h, hash_sockaddr(lo));
        h = mix(h, self.proto as u64);
        h
    }

    /// Utility for returning a string representation of the dst. subnet
    /// /24 for IPv4, /64 for IPv6; no mask for broadcast
    pub fn dst_subnet_str(&self) -> String {
        if let V4(_) = self.orig {
            if let V4(dst) = self.resp {
                if dst.ip().is_broadcast() || dst.ip().is_multicast() {
                    return dst.ip().to_string();
                } else {
                    let mask = !0u32 << (32 - 24); // Convert to a /24
                    return Ipv4Addr::from(dst.ip().to_bits() & mask).to_string();
                }
            }
        } else if let V6(_) = self.orig {
            if let V6(dst) = self.resp {
                let mask = !0u128 << (128 - 64); // Convert to a /64
                return Ipv6Addr::from(dst.ip().to_bits() & mask).to_string();
            }
        }
        String::new()
    }

    /// Utility for returning a string representation of the dst. IP
    pub fn dst_ip_str(&self) -> String {
        if let V4(dst) = self.resp {
            return dst.ip().to_string();
        }
        if let V6(dst) = self.resp {
            return dst.ip().to_string();
        }
        String::new()
    }

    pub fn src_ip_str(&self) -> String {
        if let V4(src) = self.orig {
            return src.ip().to_string();
        } else if let V6(src) = self.orig {
            return src.ip().to_string();
        }
        String::new()
    }

    /// Utility for returning a string representation of the transport
    /// protocol and source/destination ports
    pub fn transp_proto_str(&self) -> String {
        let src_port = self.orig.port();
        let dst_port = self.resp.port();
        let proto = match self.proto {
            UDP_PROTOCOL => "udp",
            TCP_PROTOCOL => "tcp",
            _ => "none",
        };
        format!(
            "{{ \"proto\": \"{}\", \"src\": \"{}\", \"dst\": \"{}\" }}",
            proto, src_port, dst_port
        )
    }
}

impl fmt::Display for FiveTuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> ", self.orig)?;
        write!(f, "{}", self.resp)?;
        write!(f, " protocol {}", self.proto)?;
        Ok(())
    }
}

/// A generic connection identifier.
///
/// Identifies a connection independent of the source and destination socket address order. Does not
/// distinguish between the originator and responder of the connection.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct ConnId(SocketAddr, SocketAddr, usize);

impl ConnId {
    /// Returns the connection ID of a packet with `src` and `dst` IP/port pairs.
    pub(super) fn new(src: SocketAddr, dst: SocketAddr, protocol: usize) -> Self {
        ConnId(cmp::max(src, dst), cmp::min(src, dst), protocol)
    }
}

impl fmt::Display for ConnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} <> ", self.0)?;
        write!(f, "{}", self.1)?;
        write!(f, " protocol {}", self.2)?;
        Ok(())
    }
}
