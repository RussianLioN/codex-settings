#!/bin/zsh
set -u
set -o pipefail

DEFAULT_WAVE_SIZE=6
MAX_WAVE_SIZE=20
MAX_NATIVE_SESSION_THREADS=20
HIGH_FD_LIMIT=4096
MIN_FD_HEADROOM=64

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

soft_limit=${CODEX_FD_DOCTOR_SOFT_LIMIT:-$(ulimit -Sn)}
hard_limit=${CODEX_FD_DOCTOR_HARD_LIMIT:-$(ulimit -Hn)}
launchd_fd_soft_limit=${CODEX_FD_DOCTOR_LAUNCHD_FD_SOFT_LIMIT:-${CODEX_FD_DOCTOR_LAUNCHD_SOFT_LIMIT:-$(launchctl limit maxfiles 2>/dev/null | awk 'NR == 1 { print $2 }')}}
user_process_ulimit=${CODEX_FD_DOCTOR_USER_PROCESS_SOFT_LIMIT:-$(ulimit -Su)}
launchd_maxproc_soft_limit=${CODEX_FD_DOCTOR_LAUNCHD_MAXPROC_SOFT_LIMIT:-$(launchctl limit maxproc 2>/dev/null | awk 'NR == 1 { print $2 }')}

find_codex_ancestor() {
  local pid=$PPID
  local comm command parent
  while [[ "$pid" =~ ^[0-9]+$ ]] && (( pid > 1 )); do
    comm=$(ps -p "$pid" -o comm= 2>/dev/null | awk '{ print $1 }')
    command=$(ps -p "$pid" -o command= 2>/dev/null)
    if [[ "$comm" == "codex" || "$command" == *"/codex "* || "$command" == "codex"* ]]; then
      print -- "$pid"
      return 0
    fi
    parent=$(ps -p "$pid" -o ppid= 2>/dev/null | tr -d ' ')
    [[ -n "$parent" && "$parent" != "$pid" ]] || break
    pid=$parent
  done
  return 1
}

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

count_user_processes() {
  local uid
  uid=$(id -u)
  ps -axo uid= 2>/dev/null | awk -v uid="$uid" '$1 == uid { count++ } END { print count + 0 }'
}

effective_process_limit() {
  local first=$1
  local second=$2
  local minimum=""
  for candidate in "$first" "$second"; do
    if [[ "$candidate" =~ ^[0-9]+$ ]]; then
      if [[ -z "$minimum" || $candidate -lt $minimum ]]; then
        minimum=$candidate
      fi
    fi
  done
  print -- "${minimum:-unknown}"
}

inspect_node_repl_health() {
  local pid parent command executable
  local orphan_count=0
  local stale_count=0
  while IFS= read -r pid; do
    [[ -n "$pid" ]] || continue
    parent=$(ps -p "$pid" -o ppid= 2>/dev/null | tr -d ' ')
    if [[ ! "$parent" =~ ^[0-9]+$ ]] || (( parent <= 1 )) || ! ps -p "$parent" >/dev/null 2>&1; then
      (( orphan_count++ ))
    fi
    command=$(ps -p "$pid" -o command= 2>/dev/null)
    executable=${command%% *}
    if [[ "$executable" == /* && ! -x "$executable" ]]; then
      (( stale_count++ ))
    fi
  done < <(pgrep -f '/node_repl([[:space:]]|$)' 2>/dev/null)
  print -- "$orphan_count $stale_count"
}

codex_pid=$(find_codex_ancestor 2>/dev/null || true)
if [[ -n ${CODEX_FD_DOCTOR_CODEX_FD_COUNT:-} ]]; then
  codex_fd_count=$CODEX_FD_DOCTOR_CODEX_FD_COUNT
elif [[ -n "$codex_pid" ]]; then
  codex_fd_count=$(lsof -p "$codex_pid" 2>/dev/null | awk 'NR > 1 { count++ } END { print count + 0 }')
else
  codex_fd_count=0
fi

mcp_command=${CODEX_FD_DOCTOR_MCP_COMMAND:-$(read_mcp_command 2>/dev/null || true)}
agent_thread_cap=${CODEX_FD_DOCTOR_AGENT_THREAD_CAP:-$(read_agent_thread_cap 2>/dev/null || true)}
codex_processes=${CODEX_FD_DOCTOR_CODEX_PROCESS_COUNT:-$(pgrep -x codex 2>/dev/null | wc -l | tr -d ' ')}
node_repl_processes=${CODEX_FD_DOCTOR_NODE_REPL_PROCESS_COUNT:-$(pgrep -f '/node_repl([[:space:]]|$)' 2>/dev/null | wc -l | tr -d ' ')}
user_process_count=${CODEX_FD_DOCTOR_USER_PROCESS_COUNT:-$(count_user_processes)}
user_process_soft_limit=$(effective_process_limit "$user_process_ulimit" "$launchd_maxproc_soft_limit")
required_process_headroom=$(( wave_size * 4 ))
if (( required_process_headroom < 64 )); then
  required_process_headroom=64
fi
if [[ "$user_process_soft_limit" =~ ^[0-9]+$ && "$user_process_count" =~ ^[0-9]+$ ]]; then
  process_headroom=$(( user_process_soft_limit - user_process_count ))
else
  process_headroom=unknown
fi
if [[ -n ${CODEX_FD_DOCTOR_ORPHAN_NODE_REPL_COUNT:-} && -n ${CODEX_FD_DOCTOR_STALE_NODE_REPL_COUNT:-} ]]; then
  orphan_node_repl_processes=$CODEX_FD_DOCTOR_ORPHAN_NODE_REPL_COUNT
  stale_node_repl_processes=$CODEX_FD_DOCTOR_STALE_NODE_REPL_COUNT
else
  node_repl_health=$(inspect_node_repl_health)
  orphan_node_repl_processes=${CODEX_FD_DOCTOR_ORPHAN_NODE_REPL_COUNT:-${node_repl_health%% *}}
  stale_node_repl_processes=${CODEX_FD_DOCTOR_STALE_NODE_REPL_COUNT:-${node_repl_health##* }}
fi

doctor_status=OK
reasons=()

block() {
  doctor_status=BLOCK
  reasons+=("$1")
}

warn() {
  [[ "$doctor_status" == BLOCK ]] || doctor_status=WARN
  reasons+=("$1")
}

if [[ -z "$mcp_command" || ! -x "$mcp_command" ]]; then
  block "node_repl_command_unresolvable"
fi

if [[ ! "$agent_thread_cap" =~ ^[1-9][0-9]*$ ]] || (( agent_thread_cap != MAX_NATIVE_SESSION_THREADS )); then
  block "agents_max_concurrent_threads_not_${MAX_NATIVE_SESSION_THREADS}"
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
elif (( wave_size > DEFAULT_WAVE_SIZE )); then
  block "process_limit_unknown_for_wide_wave"
else
  warn "process_limit_unknown"
fi

if (( orphan_node_repl_processes > 0 )); then
  warn "orphan_node_repl_processes"
fi

if (( stale_node_repl_processes > 0 )); then
  warn "stale_node_repl_executable_paths"
fi

if (( wave_size > DEFAULT_WAVE_SIZE )); then
  if [[ -z "$skill_id" || -z "$skill_file" || -z "$manifest" ]]; then
    block "wide_wave_requires_trust_manifest"
  else
    script_dir=${0:A:h}
    manifest_validator=${CODEX_FD_DOCTOR_MANIFEST_VALIDATOR:-$script_dir/validate_wide_wave_manifest.py}
    trusted_registry=${CODEX_FD_DOCTOR_TRUSTED_REGISTRY:-${CODEX_HOME:-$HOME/.codex}/config/trusted-wide-wave-skills.json}
    if [[ ! -f "$trusted_registry" && -f "$script_dir/../config/trusted-wide-wave-skills.json" ]]; then
      trusted_registry="$script_dir/../config/trusted-wide-wave-skills.json"
    fi
    if [[ ! -x "$manifest_validator" && ! -f "$manifest_validator" ]]; then
      block "wide_wave_manifest_validator_missing"
    else
      validator_output=$(python3 "$manifest_validator" --manifest "$manifest" --skill-id "$skill_id" --skill-file "$skill_file" --trusted-registry "$trusted_registry" 2>&1)
      validator_status=$?
      if (( validator_status != 0 )); then
        block "wide_wave_manifest_untrusted"
        validator_reasons=$(print -- "$validator_output" | awk -F= '/^reasons=/ { print $2; exit }')
        if [[ -n "$validator_reasons" && "$validator_reasons" != "none" ]]; then
          reasons+=("$validator_reasons")
        fi
      fi
    fi
  fi
fi

if (( wave_size > DEFAULT_WAVE_SIZE )) && [[ "$doctor_status" == WARN ]]; then
  block "wide_wave_cannot_start_with_warnings"
fi

reason_text=none
if (( ${#reasons[@]} > 0 )); then
  reason_text=$(IFS=,; print -- "${reasons[*]}")
fi

print -- "status=$doctor_status"
print -- "wave_size=$wave_size"
print -- "default_wave_size=$DEFAULT_WAVE_SIZE"
print -- "agent_thread_cap=${agent_thread_cap:-missing}"
print -- "max_agent_threads=$MAX_NATIVE_SESSION_THREADS"
print -- "soft_limit=$soft_limit"
print -- "hard_limit=$hard_limit"
print -- "launchd_fd_soft_limit=${launchd_fd_soft_limit:-unknown}"
print -- "codex_pid=${codex_pid:-none}"
print -- "codex_fd_count=$codex_fd_count"
print -- "fd_headroom=$fd_headroom"
print -- "user_process_soft_limit=$user_process_soft_limit"
print -- "user_process_count=$user_process_count"
print -- "process_headroom=$process_headroom"
print -- "required_process_headroom=$required_process_headroom"
print -- "codex_processes=$codex_processes"
print -- "node_repl_processes=$node_repl_processes"
print -- "orphan_node_repl_processes=$orphan_node_repl_processes"
print -- "stale_node_repl_processes=$stale_node_repl_processes"
print -- "mcp_command=${mcp_command:-missing}"
print -- "reasons=$reason_text"

case "$doctor_status" in
  OK) exit 0 ;;
  WARN) exit 1 ;;
  BLOCK) exit 2 ;;
esac
