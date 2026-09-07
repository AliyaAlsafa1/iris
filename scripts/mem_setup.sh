#!/usr/bin/env bash
# Enable the kernel interfaces the memory evaluation reads. Root, machine-wide, reversible.
#
#   scripts/mem_setup.sh          # enable, and report what changed
#   scripts/mem_setup.sh --check  # report only, change nothing
#   scripts/mem_setup.sh --undo   # put back what this script changed
#
# Three things are needed, none of them enabled by default on this host:
#
#   msr module        PCM reads MSRs directly; also the prerequisite for a future DDIO way sweep.
#   resctrl mounted   Intel RDT's cache/bandwidth monitoring (CMT, MBM) and allocation (CAT, MBA)
#                     are exposed only through this filesystem.
#   perf_event_paranoid  Reading uncore PMUs (IMC, IIO) system-wide needs -1, or root. The eval
#                     already runs under sudo, but tools/mem_sample.py is meant to be runnable
#                     without it.
#
# Every change is printed with its previous value so it can be reasoned about, and --undo restores
# exactly what this script altered — it will not unload msr or unmount resctrl if they were already
# in place when it ran, since something else on the box may depend on them.
set -euo pipefail

STATE_FILE="/run/iris-mem-setup.state"
MODE="${1:-enable}"

case "${MODE}" in
  enable|--enable) MODE=enable ;;
  --check|check)   MODE=check ;;
  --undo|undo)     MODE=undo ;;
  *) echo "usage: $0 [--check|--undo]" >&2; exit 2 ;;
esac

need_root() {
  if [[ ${EUID} -ne 0 ]]; then
    echo "error: --${MODE} needs root; re-run with sudo" >&2
    exit 1
  fi
}

# --- current state -----------------------------------------------------------------------------

msr_loaded()      { [[ -e /dev/cpu/0/msr ]]; }
resctrl_mounted() { mount | grep -q " on /sys/fs/resctrl "; }
paranoid()        { cat /proc/sys/kernel/perf_event_paranoid; }

report() {
  echo "=== memory-evaluation prerequisites ==="
  printf '  %-22s %s\n' "msr module:" \
    "$(msr_loaded && echo 'loaded (/dev/cpu/0/msr present)' || echo 'NOT loaded')"
  printf '  %-22s %s\n' "resctrl:" \
    "$(resctrl_mounted && echo 'mounted at /sys/fs/resctrl' || echo 'NOT mounted')"
  printf '  %-22s %s\n' "perf_event_paranoid:" \
    "$(paranoid)  (need -1 for system-wide uncore reads as non-root)"

  # These are properties of the CPU, not something this script can change. Report them so a
  # missing capability is diagnosed here rather than as a confusing empty counter later.
  echo "--- CPU capabilities (informational) ---"
  for flag in cat_l3 mba cqm_occup_llc cqm_mbm_total cqm_mbm_local; do
    if grep -qm1 "\b${flag}\b" /proc/cpuinfo; then
      printf '  %-22s present\n' "${flag}:"
    else
      printf '  %-22s MISSING\n' "${flag}:"
    fi
  done
  if resctrl_mounted; then
    printf '  %-22s %s\n' "L3 monitoring:" \
      "$([[ -d /sys/fs/resctrl/info/L3_MON ]] && echo present || echo MISSING)"
    if [[ -r /sys/fs/resctrl/info/L3/cbm_mask ]]; then
      printf '  %-22s cbm_mask=%s num_closids=%s\n' "CAT:" \
        "$(cat /sys/fs/resctrl/info/L3/cbm_mask)" \
        "$(cat /sys/fs/resctrl/info/L3/num_closids 2>/dev/null || echo '?')"
    fi
  fi
  echo "--- uncore PMUs (informational) ---"
  printf '  %-22s %s\n' "uncore_imc units:" \
    "$(ls -d /sys/bus/event_source/devices/uncore_imc_* 2>/dev/null | wc -l)"
  printf '  %-22s %s\n' "uncore_iio units:" \
    "$(ls -d /sys/bus/event_source/devices/uncore_iio_[0-9]* 2>/dev/null | wc -l)"
}

# --- enable ------------------------------------------------------------------------------------

do_enable() {
  need_root
  local changed=()

  if msr_loaded; then
    echo "msr: already loaded, leaving alone"
  else
    modprobe msr
    echo "msr: loaded"
    changed+=("msr")
  fi

  if resctrl_mounted; then
    echo "resctrl: already mounted, leaving alone"
  else
    mkdir -p /sys/fs/resctrl
    # `mba_MBps` would let MBA be expressed in MB/s rather than percent, but it needs the
    # per-core MBM counters to be trustworthy; stay with the default percentage semantics.
    mount -t resctrl resctrl /sys/fs/resctrl
    echo "resctrl: mounted at /sys/fs/resctrl"
    changed+=("resctrl")
  fi

  local prev
  prev="$(paranoid)"
  if [[ "${prev}" == "-1" ]]; then
    echo "perf_event_paranoid: already -1, leaving alone"
  else
    sysctl -q -w kernel.perf_event_paranoid=-1
    echo "perf_event_paranoid: ${prev} -> -1"
    changed+=("paranoid=${prev}")
  fi

  printf '%s\n' "${changed[@]:-}" > "${STATE_FILE}"
  echo
  if [[ ${#changed[@]} -eq 0 ]]; then
    echo "nothing needed changing."
  else
    echo "changed: ${changed[*]}"
    echo "undo with: sudo $0 --undo"
  fi
  echo
  report
}

# --- undo --------------------------------------------------------------------------------------

do_undo() {
  need_root
  if [[ ! -f "${STATE_FILE}" ]]; then
    echo "no ${STATE_FILE}: this script has not enabled anything since boot, so there is" >&2
    echo "nothing it is safe to undo. Leaving the system alone." >&2
    exit 1
  fi

  # Undo in reverse order of enabling, and only what this script actually changed.
  while read -r item; do
    [[ -z "${item}" ]] && continue
    case "${item}" in
      paranoid=*)
        sysctl -q -w "kernel.perf_event_paranoid=${item#paranoid=}"
        echo "perf_event_paranoid: restored to ${item#paranoid=}"
        ;;
      resctrl)
        # Monitoring groups are directories under the mount; remove ours so the unmount is clean.
        for g in /sys/fs/resctrl/mon_groups/iris_*; do
          [[ -d "${g}" ]] && rmdir "${g}" && echo "removed monitoring group ${g}"
        done
        umount /sys/fs/resctrl && echo "resctrl: unmounted"
        ;;
      msr)
        rmmod msr && echo "msr: unloaded"
        ;;
    esac
  done < <(tac "${STATE_FILE}")

  rm -f "${STATE_FILE}"
}

case "${MODE}" in
  check)  report ;;
  enable) do_enable ;;
  undo)   do_undo ;;
esac
