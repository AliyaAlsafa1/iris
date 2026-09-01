use std::ffi::CStr;
use std::mem;
use std::ptr;
use std::net::{IpAddr};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{bail, Result};
use crate::FiveTuple;
use crate::port::PortId;
use crate::protocols::packet::tcp::TCP_PROTOCOL;
use crate::protocols::packet::udp::UDP_PROTOCOL;

use crate::dpdk;
use crate::dpdk::{rte_flow, rte_flow_item, rte_flow_attr, rte_flow_error, rte_flow_create,
    rte_flow_destroy, rte_flow_query_count, rte_flow_action, rte_flow_item_ipv4, rte_flow_item_ipv6,
    rte_flow_item_tcp, rte_flow_item_udp, rte_flow_action_queue, rte_flow_action_count,
    rte_flow_action_handle, rte_flow_action_handle_create, rte_flow_action_handle_destroy,
    rte_flow_action_handle_query, rte_flow_indir_action_conf};

const BASE_GROUP: u32 = 2;
const LAST_GROUP: u32 = 2;
const NUM_GROUPS: u32 = LAST_GROUP - BASE_GROUP + 1; // 13
const L4_LSB_MASK: u16 = 0x000F;

const TCP: u8 = 6;
const UDP: u8 = 17;

/// Aggregate hits/bytes read from each rule's indirect counter at uninstall
/// time (on eviction and at teardown). Incremented in `uninstall_flow`, read
/// by the binary at shutdown to report totals instead of printing per rule.
pub static DISCARDED_PACKETS: AtomicU64 = AtomicU64::new(0);
pub static DISCARDED_BYTES:   AtomicU64 = AtomicU64::new(0);

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

/// Create an indirect (shared) COUNT action handle for a port.
fn create_count_handle(port_id: u16) -> Result<*mut rte_flow_action_handle> {
    let mut conf: rte_flow_indir_action_conf = unsafe { mem::zeroed() };
    conf.set_ingress(1);

    let count_conf = rte_flow_action_count { id: 0 };
    let count_action = rte_flow_action {
        type_: dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_COUNT,
        conf: &count_conf as *const _ as *const _,
    };

    let mut error: rte_flow_error = unsafe { mem::zeroed() };
    let handle = unsafe {
        rte_flow_action_handle_create(port_id, &conf, &count_action, &mut error)
    };

    if handle.is_null() {
        let msg = unsafe {
            CStr::from_ptr(error.message).to_string_lossy().into_owned()
        };
        bail!("rte_flow_action_handle_create failed on port {}: {}", port_id, msg);
    }

    Ok(handle)
}

/// Installs a flow rule (forward + reverse) on each port.
fn install<F>(
    port_ids: &[PortId],
    tuple:    &FiveTuple,
    attr:     &rte_flow_attr,
    make_actions: F,
) -> Result<(Vec<*mut rte_flow>, Vec<*mut rte_flow_action_handle>)>
where
    F: Fn(*mut rte_flow_action_handle) -> Vec<rte_flow_action>,
{
    let mut flows = Vec::with_capacity(port_ids.len() * 2);
    let mut handles = Vec::with_capacity(port_ids.len() * 2);

    let mut storage = PatternStorage::zeroed();
    let pattern = build_pattern(tuple, &mut storage)?;

    // Create flow rule using pattern
    for port_id in port_ids.iter() {
        let handle = create_count_handle(port_id.raw())?;
        let actions = make_actions(handle);

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
            // Clean up the handle we just created since the rule failed.
            let mut derr: rte_flow_error = unsafe { mem::zeroed() };
            unsafe { rte_flow_action_handle_destroy(port_id.raw(), handle, &mut derr) };
            anyhow::bail!(
                "Failed to install flow on port {}: {}",
                port_id.raw(),
                msg
            );
        }

        flows.push(flow);
        handles.push(handle);
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
        let handle = create_count_handle(port_id.raw())?;
        let actions = make_actions(handle);

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
            let mut derr: rte_flow_error = unsafe { mem::zeroed() };
            unsafe { rte_flow_action_handle_destroy(port_id.raw(), handle, &mut derr) };
            anyhow::bail!(
                "Failed to install flow on port {}: {}",
                port_id.raw(),
                msg
            );
        }

        flows.push(flow_rev);
        handles.push(handle);
    }

    Ok((flows, handles))
}

pub fn install_drop_flow(
    port_ids: Vec<PortId>,
    tuple:    &FiveTuple,
) -> Result<(Vec<*mut rte_flow>, Vec<*mut rte_flow_action_handle>)> {
    install(&port_ids, tuple, &ingress_attr(1, 0), |handle| {
        vec![
            rte_flow_action {
                type_: dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_INDIRECT,
                conf: handle as *const _,
            },
            rte_flow_action {
                type_: dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_DROP,
                conf: ptr::null(),
            },
            rte_flow_action {
                type_: dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_END,
                conf: ptr::null(),
            },
        ]
    })
}

pub fn install_split_flow(
    port_ids: Vec<PortId>,
    tuple:    &FiveTuple,
    queue_id: u16,
) -> Result<(Vec<*mut rte_flow>, Vec<*mut rte_flow_action_handle>)> {
    // queue conf must outlive the actions array; box it so the pointer
    // stays valid for each per-flow actions vec.
    let queue_conf = Box::new(rte_flow_action_queue { index: queue_id });
    let queue_ptr = &*queue_conf as *const rte_flow_action_queue;

    let result = install(&port_ids, tuple, &ingress_attr(1, 0), |handle| {
        vec![
            rte_flow_action {
                type_: dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_INDIRECT,
                conf: handle as *const _,
            },
            rte_flow_action {
                type_: dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_QUEUE,
                conf:  queue_ptr as *const _,
            },
            rte_flow_action {
                type_: dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_END,
                conf:  ptr::null(),
            },
        ]
    });

    // queue_conf is dropped here, after all rte_flow_create calls have
    // copied the pattern/actions into the PMD.
    drop(queue_conf);
    result
}

/// Uninstall flow rules previously installed, querying their indirect
/// counters first. `flows` and `handles` are parallel vectors of equal length.
/// The queried hits/bytes are accumulated into the global DISCARDED_PACKETS /
/// DISCARDED_BYTES counters rather than printed per rule.
pub fn uninstall_flow(
    port_ids: Vec<PortId>,
    flows: Vec<*mut rte_flow>,
    handles: Vec<*mut rte_flow_action_handle>,
) -> Result<()> {
    if (port_ids.len() * 2) != flows.len() { // Must double length of port_ids to account for forward/rev flows
        bail!(
            "Mismatched lengths: {} ports but {} flows",
            port_ids.len(),
            flows.len()
        );
    }
    if flows.len() != handles.len() {
        bail!(
            "Mismatched lengths: {} flows but {} handles",
            flows.len(),
            handles.len()
        );
    }

    // forward flows occupy [0..ports.len()), reverse flows [ports.len()..2*ports.len())
    let n = port_ids.len();
    for (idx, flow) in flows.iter().enumerate() {
        let port_id = &port_ids[idx % n];
        let handle = handles[idx];

        if flow.is_null() {
            continue;
        }

        if !handle.is_null() {
            match query_flow_stats(port_id.raw(), handle) {
                Ok((hits, bytes)) => {
                    DISCARDED_PACKETS.fetch_add(hits, Ordering::Relaxed);
                    DISCARDED_BYTES.fetch_add(bytes, Ordering::Relaxed);
                }
                Err(e) => eprintln!(
                    "Port {} flow stats unavailable: {}",
                    port_id.raw(), e
                ),
            }
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

        // Destroy the indirect counter handle after the rule referencing it
        // is gone.
        if !handle.is_null() {
            let mut derr: rte_flow_error = unsafe { mem::zeroed() };
            let dret = unsafe {
                rte_flow_action_handle_destroy(port_id.raw(), handle, &mut derr)
            };
            if dret != 0 {
                let msg = unsafe {
                    CStr::from_ptr(derr.message).to_string_lossy().into_owned()
                };
                eprintln!(
                    "Failed to destroy count handle on port {}: {}",
                    port_id.raw(), msg
                );
            }
        }
    }

    Ok(())
}

/// Query the indirect counters of a still-installed rule set and accumulate
/// the hits/bytes into DISCARDED_PACKETS / DISCARDED_BYTES, WITHOUT destroying
/// the rules or their handles. Use this at shutdown to tally flows that are
/// still resident (never evicted). `flows` and `handles` are the parallel
/// vectors returned by install_drop_flow / install_split_flow; `flows` is only
/// used for its length/null checks, no rte_flow_destroy is called.
pub fn query_resident_flow(
    port_ids: &[PortId],
    flows: &[*mut rte_flow],
    handles: &[*mut rte_flow_action_handle],
) -> Result<()> {
    if (port_ids.len() * 2) != flows.len() {
        bail!(
            "Mismatched lengths: {} ports but {} flows",
            port_ids.len(),
            flows.len()
        );
    }
    if flows.len() != handles.len() {
        bail!(
            "Mismatched lengths: {} flows but {} handles",
            flows.len(),
            handles.len()
        );
    }

    let n = port_ids.len();
    for (idx, flow) in flows.iter().enumerate() {
        let port_id = &port_ids[idx % n];
        let handle = handles[idx];

        if flow.is_null() || handle.is_null() {
            continue;
        }

        match query_flow_stats(port_id.raw(), handle) {
            Ok((hits, bytes)) => {
                DISCARDED_PACKETS.fetch_add(hits, Ordering::Relaxed);
                DISCARDED_BYTES.fetch_add(bytes, Ordering::Relaxed);
            }
            Err(e) => eprintln!(
                "Port {} resident flow stats unavailable: {}",
                port_id.raw(), e
            ),
        }
    }

    Ok(())
}

fn query_flow_stats(
    port_id: u16,
    handle: *mut rte_flow_action_handle,
) -> Result<(u64, u64)> {
    let mut count_data: rte_flow_query_count = unsafe { mem::zeroed() };

    let mut error: rte_flow_error = unsafe { mem::zeroed() };

    let ret = unsafe {
        rte_flow_action_handle_query(
            port_id,
            handle,
            &mut count_data as *mut _ as *mut _,
            &mut error,
        )
    };

    if ret != 0 {
        let msg = unsafe {
            CStr::from_ptr(error.message).to_string_lossy().into_owned()
        };
        bail!("rte_flow_action_handle_query failed on port {}: {}", port_id, msg);
    }

    let hits  = if count_data.hits_set()  != 0 { count_data.hits  } else { 0 };
    let bytes = if count_data.bytes_set() != 0 { count_data.bytes } else { 0 };

    Ok((hits, bytes))
}