use std::ffi::CStr;
use std::mem;
use std::ptr;
use std::net::{IpAddr};

use anyhow::{bail, Result};
use crate::FiveTuple;
use crate::port::PortId;
use crate::protocols::packet::tcp::TCP_PROTOCOL;
use crate::protocols::packet::udp::UDP_PROTOCOL;

use crate::dpdk;
use crate::dpdk::{rte_flow, rte_flow_item, rte_flow_attr, rte_flow_error, rte_flow_create,
    rte_flow_destroy, rte_flow_action, rte_flow_item_ipv4, rte_flow_item_ipv6,
    rte_flow_item_tcp, rte_flow_item_udp, rte_flow_action_queue};

const BASE_GROUP: u32 = 2;
const LAST_GROUP: u32 = 2;
const NUM_GROUPS: u32 = LAST_GROUP - BASE_GROUP + 1; // 13
const L4_LSB_MASK: u16 = 0x000F;

const TCP: u8 = 6;
const UDP: u8 = 17;

/// Returns a table in [2..=14] using dest port low nibble for TCP/UDP.
/// Non-TCP/UDP fall back to BASE_GROUP.
/// CURRENTLY UNUSED FOR TESTING !
fn find_table(tuple: &FiveTuple) -> u32 {
    let nibble_u32 = match tuple.proto as u8 {
        TCP | UDP => u32::from(tuple.resp.port() & L4_LSB_MASK),
        _ => 0,
    };
    BASE_GROUP + (nibble_u32 % NUM_GROUPS)
}

fn ingress_attr(group: u32, priority: u32) -> rte_flow_attr {
    let mut attr: rte_flow_attr = unsafe { mem::zeroed() };
    attr.set_ingress(1);
    attr.group = group;
    attr.priority = priority;
    attr
}

struct PatternStorage {
    ipv4_spec: rte_flow_item_ipv4,
    ipv4_mask: rte_flow_item_ipv4,
    ipv6_spec: rte_flow_item_ipv6,
    ipv6_mask: rte_flow_item_ipv6,
    tcp_spec:  rte_flow_item_tcp,
    tcp_mask:  rte_flow_item_tcp,
    udp_spec:  rte_flow_item_udp,
    udp_mask:  rte_flow_item_udp,
}

impl PatternStorage {
    fn zeroed() -> Self {
        unsafe {
            Self {
                ipv4_spec: mem::zeroed(),
                ipv4_mask: mem::zeroed(),
                ipv6_spec: mem::zeroed(),
                ipv6_mask: mem::zeroed(),
                tcp_spec:  mem::zeroed(),
                tcp_mask:  mem::zeroed(),
                udp_spec:  mem::zeroed(),
                udp_mask:  mem::zeroed(),
            }
        }
    }
}

/// Builds a pattern buffer [ETH + IP + L4 + END] from a FiveTuple.
/// Returns the filled pattern array and takes ownership of storage to keep it alive.
fn build_pattern<'a>(
    tuple:   &FiveTuple,
    storage: &'a mut PatternStorage,
) -> Result<[rte_flow_item; 5]> {
    let (src_ip, dst_ip) = (tuple.orig.ip(), tuple.resp.ip());
    let (src_port, dst_port) = (tuple.orig.port(), tuple.resp.port());

    // Pattern buffer structure is ETH + [IP] + [L4] + END
    let mut pattern: [rte_flow_item; 5] = unsafe { mem::zeroed() };
    let mut i = 0;

    // ETH
    pattern[i] = rte_flow_item {
        type_: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_ETH,
        spec: ptr::null(),
        mask: ptr::null(),
        last: ptr::null(),
    };
    i += 1;

    // Check IP version
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            storage.ipv4_spec.hdr.src_addr = u32::from_ne_bytes(src.octets());
            storage.ipv4_spec.hdr.dst_addr = u32::from_ne_bytes(dst.octets());
            storage.ipv4_spec.hdr.next_proto_id = tuple.proto as u8;

            storage.ipv4_mask.hdr.src_addr = u32::MAX;
            storage.ipv4_mask.hdr.dst_addr = u32::MAX;
            storage.ipv4_mask.hdr.next_proto_id = 0xFF;

            pattern[i] = rte_flow_item {
                type_: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_IPV4,
                spec: &storage.ipv4_spec as *const _ as *const _,
                mask: &storage.ipv4_mask as *const _ as *const _,
                last: ptr::null(),
            };
            i += 1;
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            storage.ipv6_spec.hdr.src_addr = dpdk::rte_ipv6_addr { a: src.octets() };
            storage.ipv6_spec.hdr.dst_addr = dpdk::rte_ipv6_addr { a: dst.octets() };
            storage.ipv6_spec.hdr.proto = tuple.proto as u8;

            storage.ipv6_mask.hdr.src_addr = dpdk::rte_ipv6_addr { a: [0xFF; 16] };
            storage.ipv6_mask.hdr.dst_addr = dpdk::rte_ipv6_addr { a: [0xFF; 16] };
            storage.ipv6_mask.hdr.proto = 0xFF;

            pattern[i] = rte_flow_item {
                type_: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_IPV6,
                spec: &storage.ipv6_spec as *const _ as *const _,
                mask: &storage.ipv6_mask as *const _ as *const _,
                last: ptr::null(),
            };
            i += 1;
        }
        _ => bail!("Mismatched IP versions"),
    }

    // Check TCP vs UDP
    match tuple.proto {
        TCP_PROTOCOL => {
            storage.tcp_spec.hdr.src_port = src_port.to_be();
            storage.tcp_spec.hdr.dst_port = dst_port.to_be();

            storage.tcp_mask.hdr.src_port = 0xFFFF;
            storage.tcp_mask.hdr.dst_port = 0xFFFF;

            pattern[i] = rte_flow_item {
                type_: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_TCP,
                spec: &storage.tcp_spec as *const _ as *const _,
                mask: &storage.tcp_mask as *const _ as *const _,
                last: ptr::null(),
            };
            i += 1;
        }
        UDP_PROTOCOL => {
            storage.udp_spec.hdr.src_port = src_port.to_be();
            storage.udp_spec.hdr.dst_port = dst_port.to_be();

            storage.udp_mask.hdr.src_port = 0xFFFF;
            storage.udp_mask.hdr.dst_port = 0xFFFF;

            pattern[i] = rte_flow_item {
                type_: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_UDP,
                spec: &storage.udp_spec as *const _ as *const _,
                mask: &storage.udp_mask as *const _ as *const _,
                last: ptr::null(),
            };
            i += 1;
        }
        _ => bail!("Unsupported protocol {}", tuple.proto),
    }

    // END
    pattern[i] = rte_flow_item {
        type_: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_END,
        spec: ptr::null(),
        mask: ptr::null(),
        last: ptr::null(),
    };

    Ok(pattern)
}

/// Installs a flow rule (forward + reverse) on each port with the given actions.
fn install(
    port_ids: &[PortId],
    tuple:    &FiveTuple,
    attr:     &rte_flow_attr,
    actions:  &[rte_flow_action],
) -> Result<Vec<*mut rte_flow>> {
    let mut flows = Vec::with_capacity(port_ids.len() * 2);

    let mut storage = PatternStorage::zeroed();
    let pattern = build_pattern(tuple, &mut storage)?;

    // Create flow rule using pattern
    for port_id in port_ids.iter() {
        let mut error: rte_flow_error = unsafe { mem::zeroed() };

        let start = unsafe { dpdk::rte_rdtsc() };
        let flow = unsafe {
            rte_flow_create(
                port_id.raw(),
                attr,
                pattern.as_ptr(),
                actions.as_ptr(),
                &mut error,
            )
        };

        // Latency Calculation
        //let duration = unsafe { dpdk::rte_rdtsc() } - start;
        //println!("Latency (cycles): {}", duration);

        if flow.is_null() {
            let msg = unsafe {
                CStr::from_ptr(error.message)
                    .to_string_lossy()
                    .into_owned()
            };
            anyhow::bail!(
                "Failed to install flow on port {}: {}",
                port_id.raw(),
                msg
            );
        }

        flows.push(flow);
    }

    // -------- REVERSE FLOW (resp -> orig) --------
    let rev = FiveTuple {
        orig: tuple.resp,
        resp: tuple.orig,
        proto: tuple.proto,
    };

    let mut rev_storage = PatternStorage::zeroed();
    let rev_pattern = build_pattern(&rev, &mut rev_storage)?;

    for port_id in port_ids.iter() {
        let mut error_rev: rte_flow_error = unsafe { mem::zeroed() };
        let start = unsafe { dpdk::rte_rdtsc() };
        let flow_rev = unsafe {
            rte_flow_create(
                port_id.raw(),
                attr,
                rev_pattern.as_ptr(),
                actions.as_ptr(),
                &mut error_rev,
            )
        };

        // Latency Calculation
        //let duration = unsafe { dpdk::rte_rdtsc() } - start;
        //println!("[REV] Latency (cycles): {}", duration);

        if flow_rev.is_null() {
            let msg = unsafe {
                CStr::from_ptr(error_rev.message)
                    .to_string_lossy()
                    .into_owned()
            };

            anyhow::bail!(
                "Failed to install flow on port {}: {}",
                port_id.raw(),
                msg
            );
        }

        flows.push(flow_rev);
    }

    Ok(flows)
}

pub fn install_drop_flow(
    port_ids: Vec<PortId>,
    tuple:    &FiveTuple,
) -> Result<Vec<*mut rte_flow>> {
    let actions = [
        rte_flow_action {
            type_: dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_DROP,
            conf: ptr::null(),
        },
        rte_flow_action {
            type_: dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_END,
            conf: ptr::null(),
        },
    ];

    install(&port_ids, tuple, &ingress_attr(1, 0), &actions)
}

pub fn install_split_flow(
    port_ids: Vec<PortId>,
    tuple:    &FiveTuple,
    queue_id: u16,
) -> Result<Vec<*mut rte_flow>> {
    let conf = rte_flow_action_queue { index: queue_id };
    let actions = [
        rte_flow_action {
            type_: dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_QUEUE,
            conf:  &conf as *const _ as *const _,
        },
        rte_flow_action {
            type_: dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_END,
            conf:  ptr::null(),
        },
    ];

    install(&port_ids, tuple, &ingress_attr(1, 0), &actions)
}

/// Uninstall flow rules previously installed
pub fn uninstall_flow(port_ids: Vec<PortId>, flows: Vec<*mut rte_flow>) -> Result<()> {
    if (port_ids.len() * 2) != flows.len() { // Must double length of port_ids to account for forward/rev flows
        bail!(
            "Mismatched lengths: {} ports but {} flows",
            port_ids.len(),
            flows.len()
        );
    }

    for (port_id, flow) in port_ids.iter().zip(flows.iter()) {
        if flow.is_null() {
            println!("No flow to uninstall on port {}", port_id.raw());
            continue;
        }

        let mut error: rte_flow_error = unsafe { mem::zeroed() };
        let start = unsafe { dpdk::rte_rdtsc() };
        let ret = unsafe { rte_flow_destroy(port_id.raw(), *flow, &mut error) };

        // Latency Calculation
        //let duration = unsafe { dpdk::rte_rdtsc() } - start;
        //println!("Uninstall latency (cycles): {}", duration);

        if ret != 0 {
            let msg = unsafe {
                CStr::from_ptr(error.message).to_string_lossy().into_owned()
            };
            bail!(
                "Failed to uninstall flow on port {}: {}",
                port_id.raw(),
                msg
            );
        }
    }

    Ok(())
}