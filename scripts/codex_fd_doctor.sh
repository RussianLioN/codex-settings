#!/bin/zsh
set -u
set -o pipefail

DEFAULT_WAVE_SIZE=6
MAX_WAVE_SIZE=19
MAX_NATIVE_SESSION_THREADS=19
HIGH_FD_LIMIT=4096
MIN_FD_HEADROOM=64
BASE_REQUIRED_PROCESS_HEADROOM=128
PROCESS_HEADROOM_PER_WAVE=20

usage() {
  cat <<'EOF'
Usage: codex_fd_doctor.sh [--wave-size N]
       codex_fd_doctor.sh --wave-size N --skill-id ID --skill-file PATH --manifest PATH

Inspect the effective file-descriptor budget, the node_repl launcher, and
Codex-related process pressure before starting a subagent wave.
EOF
}

wave_size=$DEFAULT_WAVE_SIZE
skill_id=""
skill_file=""
manifest=""
while (( $# > 0 )); do
  case "$1" in
    --wave-size)
      [[ $# -ge 2 ]] || { print -u2 -- "--wave-size requires a value"; exit 2; }
      wave_size=$2
      shift 2
      ;;
    --skill-id)
      [[ $# -ge 2 ]] || { print -u2 -- "--skill-id requires a value"; exit 2; }
      skill_id=$2
      shift 2
      ;;
    --skill-file)
      [[ $# -ge 2 ]] || { print -u2 -- "--skill-file requires a value"; exit 2; }
      skill_file=$2
      shift 2
      ;;
    --manifest)
      [[ $# -ge 2 ]] || { print -u2 -- "--manifest requires a value"; exit 2; }
      manifest=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      print -u2 -- "unknown argument: $1"
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! "$wave_size" =~ ^[1-9][0-9]*$ ]] || (( wave_size > MAX_WAVE_SIZE )); then
  print -u2 -- "wave size must be an integer in 1..${MAX_WAVE_SIZE}"
  exit 2
fi

# Mandatory resource checks cannot be bypassed by a temporary hook override.

lock_path=${CODEX_FD_DOCTOR_LOCK_PATH:-${TMPDIR:-/tmp}/codex-fd-doctor-${UID}.lock}
release_lock() {
  [[ -n ${lock_owned:-} ]] || return 0
  rm -f -- "$lock_path/owner.pid"
  rmdir "$lock_path" 2>/dev/null || true
}

if ! mkdir -m 700 "$lock_path" 2>/dev/null; then
  print -- "status=BLOCK"
  print -- "wave_size=$wave_size"
  print -- "requested_wave_size=$wave_size"
  print -- "admission_result_scope=requested_wave"
  print -- "larger_wave_admission=not_evaluated"
  print -- "allowed_wave_size=0"
  print -- "capacity_decision=BLOCK"
  print -- "admission_scope=session"
  print -- "default_wave_size=$DEFAULT_WAVE_SIZE"
  print -- "reasons=fd_doctor_already_running"
  exit 2
fi
lock_owned=1
if ! print -r -- "$$" > "$lock_path/owner.pid"; then
  release_lock
  print -- "status=BLOCK"
  print -- "wave_size=$wave_size"
  print -- "requested_wave_size=$wave_size"
  print -- "admission_result_scope=requested_wave"
  print -- "larger_wave_admission=not_evaluated"
  print -- "allowed_wave_size=0"
  print -- "capacity_decision=BLOCK"
  print -- "admission_scope=session"
  print -- "default_wave_size=$DEFAULT_WAVE_SIZE"
  print -- "reasons=fd_doctor_lock_unavailable"
  exit 2
fi
trap release_lock EXIT
trap 'exit 130' HUP INT TERM

soft_limit=${CODEX_FD_DOCTOR_SOFT_LIMIT:-$(ulimit -Sn)}
hard_limit=${CODEX_FD_DOCTOR_HARD_LIMIT:-$(ulimit -Hn)}
launchd_fd_soft_limit=${CODEX_FD_DOCTOR_LAUNCHD_FD_SOFT_LIMIT:-${CODEX_FD_DOCTOR_LAUNCHD_SOFT_LIMIT:-$(launchctl limit maxfiles 2>/dev/null | awk 'NR == 1 { print $2 }')}}
user_process_ulimit=${CODEX_FD_DOCTOR_USER_PROCESS_SOFT_LIMIT:-${CODEX_FD_DOCTOR_USER_PROCESS_LIMIT:-$(ulimit -Su)}}
launchd_maxproc_soft_limit=${CODEX_FD_DOCTOR_LAUNCHD_MAXPROC_SOFT_LIMIT:-${CODEX_FD_DOCTOR_LAUNCHD_PROCESS_LIMIT:-$(launchctl limit maxproc 2>/dev/null | awk 'NR == 1 { print $2 }')}}
kern_maxprocperuid=${CODEX_FD_DOCTOR_KERN_MAXPROCPERUID:-$(sysctl -n kern.maxprocperuid 2>/dev/null)}

read_mcp_command() {
  local config=${CODEX_HOME:-$HOME/.codex}/config.toml
  [[ -f "$config" ]] || return 1
  awk '
    /^[[:space:]]*\[mcp_servers\.node_repl\][[:space:]]*(#.*)?$/ { active = 1; next }
    active && /^[[:space:]]*\[/ { exit }
    active && /^[[:space:]]*command[[:space:]]*=/ {
      sub(/^[[:space:]]*command[[:space:]]*=[[:space:]]*"/, "")
      sub(/"[[:space:]]*$/, "")
      print
      exit
    }
  ' "$config"
}

read_agent_thread_cap() {
  local config=${CODEX_HOME:-$HOME/.codex}/config.toml
  [[ -f "$config" ]] || return 1
  awk '
    /^[[:space:]]*\[agents\][[:space:]]*(#.*)?$/ { active = 1; next }
    active && /^[[:space:]]*\[/ { exit }
    active && /^[[:space:]]*max_concurrent_threads_per_session[[:space:]]*=/ {
      sub(/^[[:space:]]*max_concurrent_threads_per_session[[:space:]]*=[[:space:]]*/, "")
      sub(/[[:space:]]*#.*/, "")
      sub(/[[:space:]]*$/, "")
      print
      exit
    }
  ' "$config"
}

effective_process_limit() {
  local minimum=""
  local candidate
  for candidate in "$@"; do
    [[ "$candidate" =~ ^[1-9][0-9]*$ ]] || continue
    if [[ -z "$minimum" || $candidate -lt $minimum ]]; then
      minimum=$candidate
    fi
  done
  [[ -n "$minimum" ]] || return 1
  print -- "$minimum"
}

output_value() {
  local output=$1
  local key=$2
  print -r -- "$output" | awk -F= -v key="$key" '$1 == key { print substr($0, length(key) + 2); exit }'
}

mcp_command=${CODEX_FD_DOCTOR_MCP_COMMAND:-$(read_mcp_command 2>/dev/null || true)}
agent_thread_cap=${CODEX_FD_DOCTOR_AGENT_THREAD_CAP:-$(read_agent_thread_cap 2>/dev/null || true)}
[[ -n "$agent_thread_cap" ]] || agent_thread_cap=not_configured
script_dir=${0:A:h}
process_inventory=${CODEX_FD_DOCTOR_PROCESS_INVENTORY:-$script_dir/codex_process_inventory.py}
inventory_status=unavailable
codex_pid=none
codex_processes=unknown
node_repl_processes=unknown
node_repl_attached_processes=unknown
node_repl_orphan_candidate_processes=unknown
node_repl_confirmed_orphan_processes=unknown
node_repl_external_processes=unknown
node_repl_unknown_processes=unknown
orphan_node_repl_processes=unknown
stale_node_repl_processes=unknown
user_process_count=unknown
max_expected_node_repl_processes=unknown
test_mode=${CODEX_FD_DOCTOR_TEST_MODE:-0}

if [[ "$test_mode" == 1 \
   && -n ${CODEX_FD_DOCTOR_CODEX_PROCESS_COUNT:-} \
   && -n ${CODEX_FD_DOCTOR_NODE_REPL_PROCESS_COUNT:-} \
   && -n ${CODEX_FD_DOCTOR_ORPHAN_NODE_REPL_COUNT:-} \
   && -n ${CODEX_FD_DOCTOR_STALE_NODE_REPL_COUNT:-} \
   && -n ${CODEX_FD_DOCTOR_USER_PROCESS_COUNT:-} ]]; then
  inventory_status=overridden
  codex_pid=${CODEX_FD_DOCTOR_CODEX_PID:-none}
  codex_processes=$CODEX_FD_DOCTOR_CODEX_PROCESS_COUNT
  node_repl_processes=$CODEX_FD_DOCTOR_NODE_REPL_PROCESS_COUNT
  node_repl_attached_processes=${CODEX_FD_DOCTOR_ATTACHED_NODE_REPL_COUNT:-$node_repl_processes}
  node_repl_orphan_candidate_processes=$CODEX_FD_DOCTOR_ORPHAN_NODE_REPL_COUNT
  node_repl_confirmed_orphan_processes=${CODEX_FD_DOCTOR_CONFIRMED_ORPHAN_NODE_REPL_COUNT:-0}
  node_repl_external_processes=${CODEX_FD_DOCTOR_EXTERNAL_NODE_REPL_COUNT:-0}
  node_repl_unknown_processes=${CODEX_FD_DOCTOR_UNKNOWN_NODE_REPL_COUNT:-0}
  orphan_node_repl_processes=$CODEX_FD_DOCTOR_ORPHAN_NODE_REPL_COUNT
  stale_node_repl_processes=$CODEX_FD_DOCTOR_STALE_NODE_REPL_COUNT
  user_process_count=$CODEX_FD_DOCTOR_USER_PROCESS_COUNT
elif [[ -f "$process_inventory" ]]; then
  inventory_args=(--format shell)
  if [[ "$test_mode" == 1 && -n ${CODEX_FD_DOCTOR_PROCESS_SNAPSHOT:-} ]]; then
    inventory_args+=(--snapshot-json "$CODEX_FD_DOCTOR_PROCESS_SNAPSHOT")
  fi
  if [[ "$test_mode" == 1 && -n ${CODEX_FD_DOCTOR_CALLER_PID:-} ]]; then
    inventory_args+=(--caller-pid "$CODEX_FD_DOCTOR_CALLER_PID")
  fi
  if [[ "$test_mode" == 1 && -n ${CODEX_FD_DOCTOR_NOW_EPOCH:-} ]]; then
    inventory_args+=(--now-epoch "$CODEX_FD_DOCTOR_NOW_EPOCH")
  fi
  inventory_output=$(python3 "$process_inventory" "${inventory_args[@]}" 2>/dev/null)
  inventory_exit=$?
  inventory_protocol=$(output_value "$inventory_output" inventory_protocol_version)
  inventory_status=$(output_value "$inventory_output" inventory_status)
  if (( inventory_exit == 0 )) && [[ "$inventory_protocol" == 1 && "$inventory_status" == ok ]]; then
    codex_pid=$(output_value "$inventory_output" inventory_current_codex_pid)
    codex_processes=$(output_value "$inventory_output" inventory_codex_roots)
    node_repl_processes=$(output_value "$inventory_output" inventory_node_repl_total)
    node_repl_attached_processes=$(output_value "$inventory_output" inventory_node_repl_attached)
    node_repl_orphan_candidate_processes=$(output_value "$inventory_output" inventory_node_repl_orphan_candidate)
    node_repl_confirmed_orphan_processes=$(output_value "$inventory_output" inventory_node_repl_confirmed_orphan)
    node_repl_external_processes=$(output_value "$inventory_output" inventory_node_repl_external)
    stale_node_repl_processes=$(output_value "$inventory_output" inventory_node_repl_stale_path)
    node_repl_unknown_processes=$(output_value "$inventory_output" inventory_node_repl_unknown)
    user_process_count=$(output_value "$inventory_output" inventory_user_process_count)
    orphan_node_repl_processes=$(( node_repl_orphan_candidate_processes + node_repl_confirmed_orphan_processes ))
  else
    inventory_status=unavailable
  fi
fi

if [[ -n ${CODEX_FD_DOCTOR_CODEX_FD_COUNT:-} ]]; then
  codex_fd_count=$CODEX_FD_DOCTOR_CODEX_FD_COUNT
elif [[ "$codex_pid" =~ ^[1-9][0-9]*$ ]]; then
  codex_fd_count=$(lsof -p "$codex_pid" 2>/dev/null | awk 'NR > 1 { count++ } END { print count + 0 }')
else
  codex_fd_count=0
fi

required_process_headroom=$(( BASE_REQUIRED_PROCESS_HEADROOM + PROCESS_HEADROOM_PER_WAVE * wave_size ))
if process_limit=$(effective_process_limit "$user_process_ulimit" "$launchd_maxproc_soft_limit" "$kern_maxprocperuid" 2>/dev/null); then
  user_process_soft_limit=$process_limit
else
  process_limit=unknown
  user_process_soft_limit=unknown
fi
if [[ "$process_limit" =~ ^[0-9]+$ && "$user_process_count" =~ ^[0-9]+$ ]]; then
  process_headroom=$(( process_limit - user_process_count ))
else
  process_headroom=unknown
fi
doctor_status=OK
reasons=()
allowed_wave_size=$wave_size
capacity_decision=ALLOW
wide_wave_manifest_trusted=0

block() {
  doctor_status=BLOCK
  reasons+=("$1")
}

warn() {
  [[ "$doctor_status" == BLOCK ]] || doctor_status=WARN
  reasons+=("$1")
}

if [[ "$inventory_status" == unavailable ]]; then
  block "process_inventory_unavailable"
fi

if [[ -z "$mcp_command" || ! -x "$mcp_command" ]]; then
  block "node_repl_command_unresolvable"
fi

if [[ "$soft_limit" =~ ^[0-9]+$ ]]; then
  fd_headroom=$(( soft_limit - codex_fd_count ))
  if (( codex_fd_count > 0 && fd_headroom < MIN_FD_HEADROOM )); then
    block "fd_headroom_below_${MIN_FD_HEADROOM}"
  fi
  if (( wave_size > DEFAULT_WAVE_SIZE && soft_limit < HIGH_FD_LIMIT )); then
    block "wide_wave_requires_soft_limit_${HIGH_FD_LIMIT}"
  elif (( soft_limit < 1024 )); then
    warn "soft_limit_below_1024"
  fi
elif [[ "$soft_limit" == unlimited ]]; then
  fd_headroom=unlimited
else
  fd_headroom=unknown
  if (( wave_size > DEFAULT_WAVE_SIZE )); then
    block "wide_wave_requires_soft_limit_${HIGH_FD_LIMIT}"
  fi
fi

if [[ "$process_headroom" =~ ^-?[0-9]+$ ]]; then
  if (( process_headroom < required_process_headroom )); then
    block "process_headroom_below_${required_process_headroom}"
  fi
else
  block "process_budget_unavailable"
fi

if [[ "$node_repl_orphan_candidate_processes" =~ ^[0-9]+$ ]] && (( node_repl_orphan_candidate_processes > 0 )); then
  warn "orphan_candidate_node_repl_processes"
fi

if [[ "$node_repl_confirmed_orphan_processes" =~ ^[0-9]+$ ]] && (( node_repl_confirmed_orphan_processes > 0 )); then
  block "confirmed_orphan_node_repl_processes"
fi

if [[ "$stale_node_repl_processes" =~ ^[0-9]+$ ]] && (( stale_node_repl_processes > 0 )); then
  warn "stale_node_repl_executable_paths"
fi

if [[ "$node_repl_unknown_processes" =~ ^[0-9]+$ ]] && (( node_repl_unknown_processes > 0 )); then
  warn "unknown_node_repl_ownership"
fi

if (( wave_size > DEFAULT_WAVE_SIZE )) || [[ -n "$skill_id" || -n "$skill_file" || -n "$manifest" ]]; then
  if [[ -z "$skill_id" || -z "$skill_file" || -z "$manifest" ]]; then
    block "wide_wave_requires_trust_manifest"
  else
    script_dir=${0:A:h}
    manifest_validator=$script_dir/validate_wide_wave_manifest.py
    trusted_registry=${CODEX_HOME:-$HOME/.codex}/config/trusted-wide-wave-skills.json
    if [[ "$test_mode" == 1 ]]; then
      manifest_validator=${CODEX_FD_DOCTOR_MANIFEST_VALIDATOR:-$manifest_validator}
      trusted_registry=${CODEX_FD_DOCTOR_TRUSTED_REGISTRY:-$trusted_registry}
    fi
    if [[ ! -f "$trusted_registry" && -f "$script_dir/../config/trusted-wide-wave-skills.json" ]]; then
      trusted_registry="$script_dir/../config/trusted-wide-wave-skills.json"
    fi
    if [[ ! -x "$manifest_validator" && ! -f "$manifest_validator" ]]; then
      block "wide_wave_manifest_validator_missing"
    else
      validator_output=$(python3 "$manifest_validator" --manifest "$manifest" --skill-id "$skill_id" --skill-file "$skill_file" --trusted-registry "$trusted_registry" --expected-wave-size "$wave_size" 2>&1)
      validator_status=$?
      if (( validator_status != 0 )); then
        block "wide_wave_manifest_untrusted"
        validator_reasons=$(print -- "$validator_output" | awk -F= '/^reasons=/ { print $2; exit }')
        if [[ -n "$validator_reasons" && "$validator_reasons" != "none" ]]; then
          reasons+=("$validator_reasons")
        fi
      else
        wide_wave_manifest_trusted=1
      fi
    fi
  fi
fi

# Native admission belongs to this session. Inspect current resources only;
# never consult capacity stores, calibration, leases, or other sessions' quotas.
if [[ "$skill_id" == consilium ]] && (( wave_size > DEFAULT_WAVE_SIZE && wave_size != 19 )); then
  block "strict_consilium_requires_19"
fi
if (( wave_size <= DEFAULT_WAVE_SIZE || wide_wave_manifest_trusted == 1 )); then
  resource_snapshot=""
  if [[ "$test_mode" == 1 ]]; then
    resource_snapshot=${CODEX_FD_DOCTOR_CAPACITY_OBSERVER_SNAPSHOT:-}
  fi
  if [[ "$test_mode" != 1 || -n "$resource_snapshot" || "$wave_size" -gt "$DEFAULT_WAVE_SIZE" ]]; then
  resource_output=$(python3 - "${0:A:h}" "$resource_snapshot" <<'PY_RESOURCE'
import json
import sys
import time
from pathlib import Path
sys.path.insert(0, sys.argv[1])
try:
    import codex_capacity_observer as observer
    raw = (observer.json_loads_strict(Path(sys.argv[2]).read_text(encoding="utf-8"))
           if sys.argv[2] else observer.collect_snapshot(
               deadline=time.monotonic() + observer.OBSERVE_TIMEOUT_SECONDS))
    snapshot = observer.normalize_snapshot(raw)
    if snapshot.get("_missing"):
        raise observer.ObservationError("measurement_unavailable:" + ",".join(snapshot["_missing"]))
    # Zero costs evaluate actual reserves, without a speculative per-agent cost.
    costs = dict.fromkeys(observer.MIN_COSTS["normal"], 0.0)
    red, yellow = [], []
    status = observer.classify_raw_status(
        snapshot, costs, {"swapout_bytes_per_minute": None}, red, yellow)
    decision = {"GREEN": "ALLOW", "YELLOW": "WARN", "RED": "BLOCK"}[status]
    print(decision + "|" + ",".join(red + yellow))
except Exception:
    print("BLOCK|resource_measurement_unavailable")
PY_RESOURCE
  )
  resource_decision=${resource_output%%|*}
  resource_reasons=${resource_output#*|}
  if [[ -n "$resource_reasons" ]]; then
    reasons+=("$resource_reasons")
  fi
  case "$resource_decision" in
    ALLOW) ;;
    WARN) warn "resource_warning_requires_fallback" ;;
    *) block "resource_preflight_blocked" ;;
  esac
  fi
fi

if [[ "$doctor_status" == BLOCK ]]; then
  allowed_wave_size=0
  capacity_decision=BLOCK
elif [[ "$doctor_status" == WARN && "$capacity_decision" == ALLOW ]]; then
  capacity_decision=WARN
  if (( wave_size > DEFAULT_WAVE_SIZE )); then
    allowed_wave_size=$DEFAULT_WAVE_SIZE
  fi
fi

reason_text=none
if (( ${#reasons[@]} > 0 )); then
  reason_text=$(IFS=,; print -- "${reasons[*]}")
fi

print -- "status=$doctor_status"
print -- "wave_size=$wave_size"
print -- "requested_wave_size=$wave_size"
print -- "admission_result_scope=requested_wave"
print -- "larger_wave_admission=not_evaluated"
print -- "allowed_wave_size=$allowed_wave_size"
print -- "capacity_decision=$capacity_decision"
print -- "admission_scope=session"
print -- "swapout_bytes_per_minute=unknown"
print -- "default_wave_size=$DEFAULT_WAVE_SIZE"
print -- "agent_thread_cap=$agent_thread_cap"
print -- "max_agent_threads=$MAX_NATIVE_SESSION_THREADS"
print -- "soft_limit=$soft_limit"
print -- "hard_limit=$hard_limit"
print -- "launchd_fd_soft_limit=${launchd_fd_soft_limit:-unknown}"
print -- "codex_pid=${codex_pid:-none}"
print -- "codex_fd_count=$codex_fd_count"
print -- "fd_headroom=$fd_headroom"
print -- "user_process_soft_limit=$user_process_soft_limit"
print -- "launchd_process_limit=${launchd_maxproc_soft_limit:-unknown}"
print -- "kern_maxprocperuid=${kern_maxprocperuid:-unknown}"
print -- "process_limit=$process_limit"
print -- "user_process_count=$user_process_count"
print -- "process_headroom=$process_headroom"
print -- "required_process_headroom=$required_process_headroom"
print -- "process_inventory_status=$inventory_status"
print -- "codex_processes=$codex_processes"
print -- "node_repl_processes=$node_repl_processes"
print -- "max_expected_node_repl_processes=$max_expected_node_repl_processes"
print -- "node_repl_attached_processes=$node_repl_attached_processes"
print -- "node_repl_orphan_candidate_processes=$node_repl_orphan_candidate_processes"
print -- "node_repl_confirmed_orphan_processes=$node_repl_confirmed_orphan_processes"
print -- "node_repl_external_processes=$node_repl_external_processes"
print -- "node_repl_unknown_processes=$node_repl_unknown_processes"
print -- "orphan_node_repl_processes=$orphan_node_repl_processes"
print -- "stale_node_repl_processes=$stale_node_repl_processes"
print -- "mcp_command=${mcp_command:-missing}"
print -- "reasons=$reason_text"

case "$doctor_status" in
  OK) exit 0 ;;
  WARN) exit 1 ;;
  BLOCK) exit 2 ;;
esac
