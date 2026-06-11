//! Raw-pattern flow drops for Intel ICE NICs.
//!
//! Ports the TLS Application-Data and QUIC short-header drops from
//! intel_nic_study/software_forwarder.c. ICE expects raw-pattern rules whose
//! `pattern` buffer is the ASCII hex encoding of the spec/mask bytes, with
//! length doubled accordingly. Unlike the mlx5 dyn_hardware_assist path, ICE
//! does not need a table-0 -> table-1 jump — rules go on group 0 directly.

use std::ffi::CStr;
use std::mem;
use std::ptr;

use anyhow::{bail, Result};

use crate::dpdk;
use crate::dpdk::{
    rte_flow, rte_flow_action, rte_flow_action_queue, rte_flow_attr, rte_flow_create,
    rte_flow_error, rte_flow_item, rte_flow_item_raw,
};
use crate::port::PortId;

/// What the raw-pattern rule does with a matching packet.
///
/// `Drop` is the production action (hardware drop). `Steer` redirects matches
/// to a dedicated RX queue instead, so a sink core can poll and count them —
/// used to measure how many packets the rule matches without relying on
/// hardware flow counters (which the ICE PMD does not support for raw/parser
/// FDIR rules; see ice_fdir_create_filter).
#[derive(Clone, Copy, Debug)]
pub enum RawAction {
    Drop,
    Steer(u16),
}

const TLS_APPDATA_TYPE: u8 = 0x17;
const TLS_VERSION_MAJOR: u8 = 0x03;

/// Linux-with-timestamps layout. ICE FDIR allows only one FV profile per
/// ptype-group, so we pin doff=8 (matches software_forwarder.c).
const TCP_DOFF_PINNED: u8 = 8;

/// ETH(14) + IPv4(60 worst-case) + TCP(60 worst-case) + 2-byte TLS prefix.
const MAX_TEMPLATE_BYTES: usize = 136;
/// Hex buffer size matching software_forwarder.c (`MAX_TEMPLATE_BYTES * 2 +
/// 1`). The ICE PMD reads `length` bytes but walks past the end on some
/// patterns, so we mirror C's fixed-size NUL-padded buffer.
const MAX_TEMPLATE_HEX: usize = MAX_TEMPLATE_BYTES * 2 + 1;

fn bytes_to_hex(bytes: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    // Allocate a fixed-size, zero-padded buffer like the C reference.
    let mut out = vec![0u8; MAX_TEMPLATE_HEX];
    for (i, &b) in bytes.iter().enumerate() {
        out[2 * i] = HEX[(b >> 4) as usize];
        out[2 * i + 1] = HEX[(b & 0x0f) as usize];
    }
    out
}

fn fill_ipv4_l4_prefix(spec: &mut [u8], mask: &mut [u8], ihl: u8, l4_proto: u8) {
    spec[12] = 0x08;
    spec[13] = 0x00;
    mask[12] = 0xff;
    mask[13] = 0xff;

    let ip_off = 14;
    spec[ip_off] = 0x40 | ihl;
    mask[ip_off] = 0xff;
    spec[ip_off + 9] = l4_proto;
    mask[ip_off + 9] = 0xff;
}

fn fill_ipv6_l4_prefix(spec: &mut [u8], mask: &mut [u8], l4_proto: u8) {
    spec[12] = 0x86;
    spec[13] = 0xdd;
    mask[12] = 0xff;
    mask[13] = 0xff;

    let ip_off = 14;
    spec[ip_off] = 0x60;
    mask[ip_off] = 0xf0;
    spec[ip_off + 6] = l4_proto;
    mask[ip_off + 6] = 0xff;
}

fn create_raw_drop(
    port_id: PortId,
    spec: &[u8],
    mask: &[u8],
    priority: u32,
    label: &str,
    action: RawAction,
) -> Result<*mut rte_flow> {
    assert_eq!(spec.len(), mask.len());
    let total = spec.len();

    // ICE convention: raw pattern is ASCII hex; length is the hex string length.
    // Both Vec<u8>s must outlive the rte_flow_create call.
    let spec_hex = bytes_to_hex(spec);
    let mask_hex = bytes_to_hex(mask);

    let mut raw_spec: rte_flow_item_raw = unsafe { mem::zeroed() };
    raw_spec.length = (total * 2) as u16;
    raw_spec.pattern = spec_hex.as_ptr();

    let mut raw_mask: rte_flow_item_raw = unsafe { mem::zeroed() };
    raw_mask.length = (total * 2) as u16;
    raw_mask.pattern = mask_hex.as_ptr();

    let pattern: [rte_flow_item; 2] = [
        rte_flow_item {
            type_: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_RAW,
            spec: &raw_spec as *const _ as *const _,
            mask: &raw_mask as *const _ as *const _,
            last: ptr::null(),
        },
        rte_flow_item {
            type_: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_END,
            spec: ptr::null(),
            mask: ptr::null(),
            last: ptr::null(),
        },
    ];

    // Terminal action: either hardware drop, or steer to a sink queue for
    // software counting. queue_conf must outlive the rte_flow_create call.
    let queue_conf = match action {
        RawAction::Steer(qid) => rte_flow_action_queue { index: qid },
        RawAction::Drop => rte_flow_action_queue { index: 0 },
    };
    let terminal = match action {
        RawAction::Drop => rte_flow_action {
            type_: dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_DROP,
            conf: ptr::null(),
        },
        RawAction::Steer(_) => rte_flow_action {
            type_: dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_QUEUE,
            conf: &queue_conf as *const _ as *const _,
        },
    };
    let actions: [rte_flow_action; 2] = [
        terminal,
        rte_flow_action {
            type_: dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_END,
            conf: ptr::null(),
        },
    ];

    let mut attr: rte_flow_attr = unsafe { mem::zeroed() };
    attr.set_ingress(1);
    attr.priority = priority;
    attr.group = 0;

    let mut error: rte_flow_error = unsafe { mem::zeroed() };
    let validate_ret = unsafe {
        dpdk::rte_flow_validate(
            port_id.raw(),
            &attr,
            pattern.as_ptr(),
            actions.as_ptr(),
            &mut error,
        )
    };
    if validate_ret < 0 {
        let msg = unsafe {
            if error.message.is_null() {
                "(none)".to_string()
            } else {
                CStr::from_ptr(error.message).to_string_lossy().into_owned()
            }
        };
        bail!(
            "rte_flow_validate failed for {} on port {} (type={}, cause={:?}): {}",
            label,
            port_id.raw(),
            error.type_,
            error.cause,
            msg
        );
    }

    let mut error: rte_flow_error = unsafe { mem::zeroed() };
    let flow = unsafe {
        rte_flow_create(
            port_id.raw(),
            &attr,
            pattern.as_ptr(),
            actions.as_ptr(),
            &mut error,
        )
    };
    if flow.is_null() {
        let msg = unsafe {
            if error.message.is_null() {
                "(none)".to_string()
            } else {
                CStr::from_ptr(error.message).to_string_lossy().into_owned()
            }
        };
        bail!(
            "rte_flow_create failed for {} on port {} (type={}, cause={:?}): {}",
            label,
            port_id.raw(),
            error.type_,
            error.cause,
            msg
        );
    }
    log::debug!(
        "Installed raw drop flow {} on port {} (prio={}, total={} B)",
        label,
        port_id.raw(),
        priority,
        total
    );
    Ok(flow)
}

fn install_tls_appdata_drop_variant(
    port_id: PortId,
    ip_ver: u8,
    ihl: u8,
    action: RawAction,
) -> Result<*mut rte_flow> {
    let ip_off = 14usize;
    let ip_hlen = if ip_ver == 4 { ihl as usize * 4 } else { 40 };
    let tcp_off = ip_off + ip_hlen;
    let tls_off = tcp_off + TCP_DOFF_PINNED as usize * 4;
    let total = tls_off + 2;

    let mut spec = vec![0u8; total];
    let mut mask = vec![0u8; total];

    match ip_ver {
        4 => fill_ipv4_l4_prefix(&mut spec, &mut mask, ihl, 0x06),
        6 => fill_ipv6_l4_prefix(&mut spec, &mut mask, 0x06),
        _ => bail!("unsupported ip_ver {}", ip_ver),
    }

    // TCP data-offset byte at TCP[12], upper nibble.
    spec[tcp_off + 12] = TCP_DOFF_PINNED << 4;
    mask[tcp_off + 12] = 0xf0;

    spec[tls_off] = TLS_APPDATA_TYPE;
    spec[tls_off + 1] = TLS_VERSION_MAJOR;
    mask[tls_off] = 0xff;
    mask[tls_off + 1] = 0xff;

    let label = format!(
        "tls-appdata v{} ihl={} doff={} {:?}",
        ip_ver, ihl, TCP_DOFF_PINNED, action
    );
    create_raw_drop(port_id, &spec, &mask, 0, &label, action)
}

fn install_quic_short_drop_variant(
    port_id: PortId,
    ip_ver: u8,
    ihl: u8,
    action: RawAction,
) -> Result<*mut rte_flow> {
    let ip_off = 14usize;
    let ip_hlen = if ip_ver == 4 { ihl as usize * 4 } else { 40 };
    let udp_off = ip_off + ip_hlen;
    let quic_off = udp_off + 8;
    let total = quic_off + 5;

    let mut spec = vec![0u8; total];
    let mut mask = vec![0u8; total];

    match ip_ver {
        4 => fill_ipv4_l4_prefix(&mut spec, &mut mask, ihl, 0x11),
        6 => fill_ipv6_l4_prefix(&mut spec, &mut mask, 0x11),
        _ => bail!("unsupported ip_ver {}", ip_ver),
    }

    // QUIC byte 0: form=0, fixed=1, masked at runtime. Bytes 1..=4 stay zero
    // in spec and mask — they're the parser anchor only (see C reference).
    spec[quic_off] = 0x40;
    mask[quic_off] = 0xc0;

    let label = format!("quic-short v{} ihl={} (b0-only) {:?}", ip_ver, ihl, action);
    create_raw_drop(port_id, &spec, &mask, 0, &label, action)
}

/// Installs the TLS Application-Data raw rules (type 0x17, version-major 0x03)
/// over TCP with `data offset = 8`, for IPv4 (IHL=5) and IPv6. `action` selects
/// hardware drop or steer-to-queue. Failure on a single variant is logged and
/// skipped.
pub fn install_tls_appdata_drop(port_id: PortId, action: RawAction) -> Result<Vec<*mut rte_flow>> {
    let mut flows = Vec::new();
    for &(ip_ver, ihl) in &[(4u8, 5u8), (6u8, 0u8)] {
        match install_tls_appdata_drop_variant(port_id, ip_ver, ihl, action) {
            Ok(f) => flows.push(f),
            Err(e) => log::warn!("tls-appdata v{} ihl={} skipped: {:?}", ip_ver, ihl, e),
        }
    }
    log::info!(
        "Installed {} TLS-AppData raw flows on port {} ({:?})",
        flows.len(),
        port_id.raw(),
        action
    );
    Ok(flows)
}

/// Installs the QUIC short-header raw rules (form=0, fixed=1) on UDP using the
/// 5-byte parser-anchor template, for IPv4 (IHL=5) and IPv6. `action` selects
/// hardware drop or steer-to-queue.
pub fn install_quic_short_drop(port_id: PortId, action: RawAction) -> Result<Vec<*mut rte_flow>> {
    let mut flows = Vec::new();
    for &(ip_ver, ihl) in &[(4u8, 5u8), (6u8, 0u8)] {
        match install_quic_short_drop_variant(port_id, ip_ver, ihl, action) {
            Ok(f) => flows.push(f),
            Err(e) => log::warn!("quic-short v{} ihl={} skipped: {:?}", ip_ver, ihl, e),
        }
    }
    log::info!(
        "Installed {} QUIC short-header raw flows on port {} ({:?})",
        flows.len(),
        port_id.raw(),
        action
    );
    Ok(flows)
}
