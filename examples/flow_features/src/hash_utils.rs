use std::net::IpAddr;

const HASH_SALT: u64 = 0x9e3779b97f4a7c15;
pub const HASH_BUCKETS: u64 = 100_000;

pub fn hash_ip(ip: IpAddr) -> u64 {
    match ip {
        IpAddr::V4(v4) => hash_u32(u32::from(v4)),
        IpAddr::V6(v6) => hash_u128(u128::from(v6)),
    }
}

#[inline]
fn hash_u32(n: u32) -> u64 {
    (n as u64 ^ HASH_SALT).wrapping_mul(HASH_SALT)
}

#[inline]
fn hash_u128(n: u128) -> u64 {
    let lo = n as u64;
    let hi = (n >> 64) as u64;
    (lo ^ hi ^ HASH_SALT).wrapping_mul(HASH_SALT)
}

pub fn hash_str(s: &str) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME:  u64 = 0x100000001b3;

    let mut h = FNV_OFFSET;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }

    h % HASH_BUCKETS
}