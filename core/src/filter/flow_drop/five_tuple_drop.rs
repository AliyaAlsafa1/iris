use std::ffi::CStr;
use std::mem;
use std::net::IpAddr;
use std::ptr;

use crate::port::PortId;
use crate::protocols::packet::tcp::TCP_PROTOCOL;
use crate::protocols::packet::udp::UDP_PROTOCOL;
use crate::FiveTuple;
use anyhow::{bail, Result};

use crate::dpdk;
use crate::dpdk::{
    rte_flow, rte_flow_action, rte_flow_attr, rte_flow_create, rte_flow_destroy, rte_flow_error,
    rte_flow_item, rte_flow_item_ipv4, rte_flow_item_ipv6, rte_flow_item_tcp, rte_flow_item_udp,
};

const BASE_GROUP: u32 = 2;
const LAST_GROUP: u32 = 2;
const NUM_GROUPS: u32 = LAST_GROUP - BASE_GROUP + 1; // 13
const L4_LSB_MASK: u16 = 0x000F;

const TCP: u8 = 6;
const UDP: u8 = 17;

/// Returns a table in [2..=14] using dest port low nibble for TCP/UDP.
/// Non-TCP/UDP fall back to BASE_GROUP.
/// CURRENTLY UNUSED FOR TESTING ! Kept (with the consts above) as scaffolding for
/// spreading drop rules across groups; `NUM_GROUPS` is 1 until LAST_GROUP moves.
#[allow(dead_code)]
#[allow(clippy::modulo_one)]
fn find_table(tuple: &FiveTuple) -> u32 {
    let nibble_u32 = match tuple.proto as u8 {
        TCP | UDP => u32::from(tuple.resp.port() & L4_LSB_MASK),
        _ => 0,
    };
    BASE_GROUP + (nibble_u32 % NUM_GROUPS)
}

// Take in vector of PortIds, FiveTuple to block, and returns a vector of flow pointers
//
// `unused_assignments` is allowed because the reverse-direction block below writes into
// the same *_spec structs that `pattern` already holds raw pointers to. rte_flow_create
// reads them through those pointers, which rustc cannot see.
#[allow(unused_assignments)]
pub fn install_drop_flow(port_ids: Vec<PortId>, tuple: &FiveTuple) -> Result<Vec<*mut rte_flow>> {
    let mut flows = Vec::with_capacity(port_ids.len());

    // Set ingress attribute
    let mut attr: rte_flow_attr = unsafe { mem::zeroed() };
    attr.set_ingress(1);

    // Set group and priority
    attr.group = 1;
    attr.priority = 0;

    // Recommended to declare headers and masks here so they're not dropped prematurely
    let mut ipv4_spec: rte_flow_item_ipv4 = unsafe { mem::zeroed() };
    let mut ipv4_mask: rte_flow_item_ipv4 = unsafe { mem::zeroed() };
    let mut ipv6_spec: rte_flow_item_ipv6 = unsafe { mem::zeroed() };
    let mut ipv6_mask: rte_flow_item_ipv6 = unsafe { mem::zeroed() };
    let mut tcp_spec: rte_flow_item_tcp = unsafe { mem::zeroed() };
    let mut tcp_mask: rte_flow_item_tcp = unsafe { mem::zeroed() };
    let mut udp_spec: rte_flow_item_udp = unsafe { mem::zeroed() };
    let mut udp_mask: rte_flow_item_udp = unsafe { mem::zeroed() };

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
            ipv4_spec.hdr.src_addr = u32::from_ne_bytes(src.octets());
            ipv4_spec.hdr.dst_addr = u32::from_ne_bytes(dst.octets());
            ipv4_spec.hdr.next_proto_id = tuple.proto as u8;

            ipv4_mask.hdr.src_addr = u32::MAX;
            ipv4_mask.hdr.dst_addr = u32::MAX;
            ipv4_mask.hdr.next_proto_id = 0xFF;

            pattern[i] = rte_flow_item {
                type_: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_IPV4,
                spec: &ipv4_spec as *const _ as *const _,
                mask: &ipv4_mask as *const _ as *const _,
                last: ptr::null(),
            };
            i += 1;
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            ipv6_spec.hdr.src_addr = dpdk::rte_ipv6_addr { a: src.octets() };
            ipv6_spec.hdr.dst_addr = dpdk::rte_ipv6_addr { a: dst.octets() };
            ipv6_spec.hdr.proto = tuple.proto as u8;

            ipv6_mask.hdr.src_addr = dpdk::rte_ipv6_addr { a: [0xFF; 16] };
            ipv6_mask.hdr.dst_addr = dpdk::rte_ipv6_addr { a: [0xFF; 16] };
            ipv6_mask.hdr.proto = 0xFF;

            pattern[i] = rte_flow_item {
                type_: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_IPV6,
                spec: &ipv6_spec as *const _ as *const _,
                mask: &ipv6_mask as *const _ as *const _,
                last: ptr::null(),
            };
            i += 1;
        }
        _ => bail!("Mismatched IP versions"),
    }

    // Check TCP vs UDP
    match tuple.proto {
        TCP_PROTOCOL => {
            tcp_spec.hdr.src_port = src_port.to_be();
            tcp_spec.hdr.dst_port = dst_port.to_be();

            tcp_mask.hdr.src_port = 0xFFFF;
            tcp_mask.hdr.dst_port = 0xFFFF;

            pattern[i] = rte_flow_item {
                type_: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_TCP,
                spec: &tcp_spec as *const _ as *const _,
                mask: &tcp_mask as *const _ as *const _,
                last: ptr::null(),
            };
            i += 1;
        }
        UDP_PROTOCOL => {
            udp_spec.hdr.src_port = src_port.to_be();
            udp_spec.hdr.dst_port = dst_port.to_be();

            udp_mask.hdr.src_port = 0xFFFF;
            udp_mask.hdr.dst_port = 0xFFFF;

            pattern[i] = rte_flow_item {
                type_: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_UDP,
                spec: &udp_spec as *const _ as *const _,
                mask: &udp_mask as *const _ as *const _,
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

    // Actions
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

    // Create flow rule using pattern
    for port_id in port_ids.iter() {
        let mut error: rte_flow_error = unsafe { mem::zeroed() };

        //let start = unsafe { dpdk::rte_rdtsc() };
        let flow = unsafe {
            rte_flow_create(
                port_id.raw(),
                &attr,
                pattern.as_ptr(),
                actions.as_ptr(),
                &mut error,
            )
        };

        // Latency Calculation
        //let duration = unsafe { dpdk::rte_rdtsc() } - start;
        //println!("Latency (cycles): {}", duration);

        if flow.is_null() {
            let msg = unsafe { CStr::from_ptr(error.message).to_string_lossy().into_owned() };
            anyhow::bail!("Failed to install flow on port {}: {}", port_id.raw(), msg);
        }

        flows.push(flow);
    }

    // -------- REVERSE FLOW (resp -> orig) --------
    // No new FiveTuple is needed: the specs `pattern` points at are swapped in place below.
    attr.group = 1;

    // Swap addresses/ports in the SAME specs, then call create again
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            ipv4_spec.hdr.src_addr = u32::from_ne_bytes(dst.octets()); // swap
            ipv4_spec.hdr.dst_addr = u32::from_ne_bytes(src.octets());
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            ipv6_spec.hdr.src_addr = dpdk::rte_ipv6_addr { a: dst.octets() };
            ipv6_spec.hdr.dst_addr = dpdk::rte_ipv6_addr { a: src.octets() };
        }
        _ => bail!("Mismatched IP versions"),
    }

    match tuple.proto {
        TCP_PROTOCOL => {
            tcp_spec.hdr.src_port = dst_port.to_be(); // swap
            tcp_spec.hdr.dst_port = src_port.to_be();
        }
        UDP_PROTOCOL => {
            udp_spec.hdr.src_port = dst_port.to_be(); // swap
            udp_spec.hdr.dst_port = src_port.to_be();
        }
        _ => unreachable!(),
    }

    for port_id in port_ids.iter() {
        let mut error_rev: rte_flow_error = unsafe { mem::zeroed() };
        //let start = unsafe { dpdk::rte_rdtsc() };
        let flow_rev = unsafe {
            rte_flow_create(
                port_id.raw(),
                &attr,
                pattern.as_ptr(),
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

            anyhow::bail!("Failed to install flow on port {}: {}", port_id.raw(), msg);
        }

        flows.push(flow_rev);
    }

    Ok(flows)
}

/// Uninstall DROP flow rules previously installed with `install_drop_flow`
pub fn uninstall_drop_flow(port_ids: Vec<PortId>, flows: Vec<*mut rte_flow>) -> Result<()> {
    if (port_ids.len() * 2) != flows.len() {
        // Must double length of port_ids to account for forward/rev flows
        bail!(
            "Mismatched lengths: {} ports but {} flows",
            port_ids.len(),
            flows.len()
        );
    }

    for (port_id, flow) in port_ids.iter().zip(flows.iter()) {
        if flow.is_null() {
            println!("No DROP flow to uninstall on port {}", port_id.raw());
            continue;
        }

        let mut error: rte_flow_error = unsafe { mem::zeroed() };
        //let start = unsafe { dpdk::rte_rdtsc() };
        let ret = unsafe { rte_flow_destroy(port_id.raw(), *flow, &mut error) };

        // Latency Calculation
        //let duration = unsafe { dpdk::rte_rdtsc() } - start;
        //println!("Uninstall latency (cycles): {}", duration);

        if ret != 0 {
            let msg = unsafe { CStr::from_ptr(error.message).to_string_lossy().into_owned() };
            bail!(
                "Failed to uninstall DROP flow on port {}: {}",
                port_id.raw(),
                msg
            );
        }
    }

    Ok(())
}
