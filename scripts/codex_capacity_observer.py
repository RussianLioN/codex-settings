#!/usr/bin/env python3
"""Observe and calibrate shared Codex capacity without changing live processes."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import math
import os
import re
import resource
import shlex
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable


PROTOCOL_VERSION = 1
DEFAULT_CAPACITY = 6
MAX_CAPACITY = 20
OBSERVATION_LIMIT = 100
MIN_SUCCESSFUL_OBSERVATIONS = 30
YELLOW_RECOVERY_SECONDS = 60.0
RED_RECOVERY_SNAPSHOTS = 3
RED_RECOVERY_INTERVAL_SECONDS = 10.0
RECOVERY_GAP_RESET_SECONDS = 120.0
CLEAN_CYCLES_PER_STEP = 10
CAPACITY_STEPS = [8, 12, 16, 20]
SWAPOUT_RED_BYTES_PER_MINUTE = 256 * 1024 * 1024
SWAPOUT_YELLOW_BYTES_PER_MINUTE = 64 * 1024 * 1024
MEMORY_PRESSURE_WARN_FREE_PERCENT = 15.0
MEMORY_PRESSURE_CRITICAL_FREE_PERCENT = 10.0
STATE_DIR_MODE = 0o700
STATE_FILE_MODE = 0o600
OBSERVE_TIMEOUT_SECONDS = 0.5

MANDATORY_MEASUREMENTS = (
    "total_ram_bytes",
    "available_memory_bytes",
    "memory_pressure",
    "swapouts_total_bytes",
    "cpu_idle_percent",
    "user_process_limit",
    "user_process_count",
    "root_fd_soft_limit",
    "root_fd_used",
    "system_fd_max",
    "system_fd_used",
    "disk_free_bytes",
    "disk_total_bytes",
    "heavy_lanes_in_use",
    "active_slots",
)

MIN_COSTS: dict[str, dict[str, float]] = {
    "light": {
        "memory_bytes": 192 * 1024 * 1024,
        "processes": 6.0,
        "root_fds": 24.0,
        "system_fds": 128.0,
    },
    "normal": {
        "memory_bytes": 384 * 1024 * 1024,
        "processes": 8.0,
        "root_fds": 32.0,
        "system_fds": 192.0,
    },
    "browser": {
        "memory_bytes": 2 * 1024 * 1024 * 1024,
        "processes": 32.0,
        "root_fds": 96.0,
        "system_fds": 768.0,
        "heavy_lanes": 1.0,
    },
}

CALIBRATION_SETTLE_SECONDS = 2.0
CALIBRATION_MAX_SECONDS = 900.0
CALIBRATION_MAX_GAP_SECONDS = 120.0
CALIBRATION_MIN_PEAK_SECONDS = 1.0
CALIBRATION_MEMORY_DRIFT_BYTES = 256 * 1024 * 1024
CALIBRATION_PROCESS_DRIFT = 4.0
CALIBRATION_ROOT_FD_DRIFT = 8.0
CALIBRATION_SYSTEM_FD_DRIFT = 128.0
CALIBRATION_DOMAIN = "codex-capacity-calibration-v1"
CALIBRATION_TEST_MODE_ENV = "CODEX_CAPACITY_CALIBRATION_TEST_MODE"
VALID_CAPACITIES = {DEFAULT_CAPACITY, *CAPACITY_STEPS}


class ObservationError(Exception):
    pass


class StoreSecurityError(ObservationError):
    pass


def default_state_dir(home: Path | None = None) -> Path:
    root = Path(home or Path.home()).expanduser()
    return root / ".local" / "state" / "codex-capacity-v1"


def observe(
    *,
    snapshot: dict[str, Any] | None = None,
    state_dir: Path | None = None,
    now_epoch: float | None = None,
    workload_class: str = "normal",
    expected_cost: dict[str, float] | None = None,
    active_slots: float | int | None = None,
    managed_root_identities: list[tuple[int, str]] | None = None,
    caller_pid: int | None = None,
) -> dict[str, Any]:
    now = float(time.time() if now_epoch is None else now_epoch)
    if workload_class == "light" and os.getenv(CALIBRATION_TEST_MODE_ENV) != "1":
        workload_class = "normal"
    deadline = time.monotonic() + OBSERVE_TIMEOUT_SECONDS
    observed_state_dir = Path(state_dir or default_state_dir())
    try:
        if snapshot is not None:
            raw_snapshot = snapshot
        elif managed_root_identities is None and caller_pid is None:
            raw_snapshot = collect_snapshot(state_dir=observed_state_dir, deadline=deadline)
        else:
            raw_snapshot = collect_snapshot(
                state_dir=observed_state_dir,
                deadline=deadline,
                managed_root_identities=managed_root_identities,
                caller_pid=caller_pid,
            )
        if active_slots is not None:
            raw_snapshot = dict(raw_snapshot)
            raw_snapshot["active_slots"] = active_slots
        current_snapshot = normalize_snapshot(raw_snapshot)
        evaluated_cost = expected_cost
        if evaluated_cost is None:
            try:
                profile_deadline = None
                if deadline is not None:
                    profile_deadline = min(deadline, time.monotonic() + 0.02)
                profile = calibration_status(state_dir=observed_state_dir, deadline=profile_deadline)["classes"].get(workload_class)
                if profile and int(profile.get("accepted_count") or 0) >= MIN_SUCCESSFUL_OBSERVATIONS:
                    evaluated_cost = normalize_cost(profile.get("cost_estimate") or {}, workload_class)
            except Exception:
                evaluated_cost = None
        store = ObserverStore(observed_state_dir)
        result = store.update(
            lambda state: evaluate_snapshot(
                current_snapshot,
                state=state,
                now_epoch=now,
                workload_class=workload_class,
                expected_cost=evaluated_cost,
            ),
            deadline=deadline,
        )
        return apply_calibration_to_output(
            result,
            current_snapshot,
            state_dir=observed_state_dir,
            now_epoch=now,
            workload_class=workload_class,
            deadline=deadline,
        )
    except Exception as exc:  # Library API is intentionally fail-closed.
        return fail_closed_output(str(exc))


def fail_closed_output(reason: str) -> dict[str, Any]:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "status": "RED",
        "reasons": [reason],
        "effective_capacity": DEFAULT_CAPACITY,
        "admission_capacity": 0,
        "max_wave_size": 0,
        "max_capacity": MAX_CAPACITY,
        "successful_observations": 0,
        "clean_cycles": 0,
        "capacity_mode": "fail_closed",
        "measurements": {},
        "reserves": {},
    }


def normalize_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(snapshot, dict):
        raise ObservationError("snapshot_not_object")
    normalized = dict(snapshot)
    for key in MANDATORY_MEASUREMENTS:
        if key not in normalized:
            normalized.setdefault("_missing", []).append(key)
            continue
        if key == "memory_pressure":
            pressure = str(normalized[key]).lower()
            if pressure == "warning":
                pressure = "warn"
            if pressure not in {"normal", "warn", "critical"}:
                raise ObservationError("invalid_memory_pressure")
            normalized[key] = pressure
        else:
            normalized[key] = finite_number(key, normalized[key])
    for key in ("codex_root_count", "external_codex_roots"):
        if key in normalized:
            number = finite_number(key, normalized[key])
            if number < 0:
                raise ObservationError(f"invalid_measurement:{key}")
            normalized[key] = number
    return normalized


def finite_number(key: str, value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ObservationError(f"invalid_measurement:{key}") from exc
    if not math.isfinite(number):
        raise ObservationError(f"invalid_measurement:{key}")
    if key in MANDATORY_MEASUREMENTS and number < 0:
        raise ObservationError(f"invalid_measurement:{key}")
    return number

def reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid_json_constant:{value}")


def json_loads_strict(text: str) -> Any:
    return json.loads(text, parse_constant=reject_json_constant)


def json_dumps_strict(value: Any, **kwargs: Any) -> str:
    return json.dumps(value, allow_nan=False, **kwargs)


def finite_state_number(path: str, value: Any, *, nonnegative: bool = True) -> float:
    if isinstance(value, bool):
        raise ObservationError(f"state_invalid_type:{path}")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ObservationError(f"state_invalid_type:{path}") from exc
    if not math.isfinite(number):
        raise ObservationError(f"state_invalid_number:{path}")
    if nonnegative and number < 0:
        raise ObservationError(f"state_negative_number:{path}")
    return number


def state_int(path: str, value: Any, *, minimum: int = 0, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ObservationError(f"state_invalid_type:{path}")
    if value < minimum or (maximum is not None and value > maximum):
        raise ObservationError(f"state_invalid_number:{path}")
    return value


def state_optional_time(path: str, value: Any) -> float | None:
    if value is None:
        return None
    return finite_state_number(path, value, nonnegative=True)


def validate_state(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ObservationError("database_error:state_not_object")
    allowed = set(default_state())
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise ObservationError(f"state_unknown_keys:{','.join(unknown)}")
    state = default_state()
    state.update(payload)
    state_int("protocol_version", state["protocol_version"], minimum=PROTOCOL_VERSION, maximum=PROTOCOL_VERSION)
    if state["last_status"] not in {"GREEN", "YELLOW", "RED"}:
        raise ObservationError("state_invalid_status:last_status")
    state["last_observed_at"] = state_optional_time("last_observed_at", state["last_observed_at"])
    state["successful_observations"] = state_int("successful_observations", state["successful_observations"], maximum=10_000_000)
    state["clean_cycles"] = state_int("clean_cycles", state["clean_cycles"], maximum=10_000_000)
    state["effective_capacity"] = state_int("effective_capacity", state["effective_capacity"], minimum=0, maximum=MAX_CAPACITY)
    state["proven_capacity"] = state_int("proven_capacity", state["proven_capacity"], minimum=0, maximum=MAX_CAPACITY)
    state["recovery"] = validate_recovery(state["recovery"])
    state["last_snapshot"] = validate_optional_snapshot("last_snapshot", state["last_snapshot"])
    state["observations"] = validate_observations(state["observations"])
    state["cost_samples"] = validate_cost_mapping("cost_samples", state["cost_samples"], values_are_lists=True)
    state["cost_estimates"] = validate_cost_mapping("cost_estimates", state["cost_estimates"], values_are_lists=False)
    state["cost_updated_at"] = validate_cost_updated_at(state["cost_updated_at"])
    return state


def validate_recovery(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ObservationError("state_invalid_type:recovery")
    allowed = {"from_status", "started_at", "normal_count", "last_normal_at"}
    if set(value) - allowed:
        raise ObservationError("state_unknown_keys:recovery")
    recovery = empty_recovery()
    recovery.update(value)
    if recovery["from_status"] not in {None, "GREEN", "YELLOW", "RED"}:
        raise ObservationError("state_invalid_status:recovery.from_status")
    recovery["started_at"] = state_optional_time("recovery.started_at", recovery["started_at"])
    recovery["last_normal_at"] = state_optional_time("recovery.last_normal_at", recovery["last_normal_at"])
    recovery["normal_count"] = state_int("recovery.normal_count", recovery["normal_count"], maximum=RED_RECOVERY_SNAPSHOTS)
    return recovery


def validate_optional_snapshot(path: str, value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ObservationError(f"state_invalid_type:{path}")
    allowed = set(MANDATORY_MEASUREMENTS) | {
        "root_fd_state",
        "codex_root_count",
        "external_codex_roots",
        "memory_free_percent",
        "swapout_bytes_per_minute",
    }
    if set(value) - allowed:
        raise ObservationError(f"state_unknown_keys:{path}")
    validated: dict[str, Any] = {}
    for key, item in value.items():
        item_path = f"{path}.{key}"
        if key in {"root_fd_state"}:
            if item not in {"measured", "partial", "unavailable", "no_codex_root"}:
                raise ObservationError(f"state_invalid_value:{item_path}")
            validated[key] = item
        elif key == "memory_pressure":
            if item not in {"normal", "warn", "critical"}:
                raise ObservationError(f"state_invalid_value:{item_path}")
            validated[key] = item
        elif key == "swapout_bytes_per_minute" and item is None:
            validated[key] = None
        else:
            validated[key] = finite_state_number(item_path, item, nonnegative=True)
    return validated


def validate_observations(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > OBSERVATION_LIMIT:
        raise ObservationError("state_invalid_type:observations")
    observations: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ObservationError(f"state_invalid_type:observations.{index}")
        allowed = set(MANDATORY_MEASUREMENTS) | {
            "root_fd_state",
            "codex_root_count",
            "external_codex_roots",
            "memory_free_percent",
            "swapout_bytes_per_minute",
            "observed_at",
            "status",
        }
        if set(item) - allowed:
            raise ObservationError(f"state_unknown_keys:observations.{index}")
        validated = validate_optional_snapshot(f"observations.{index}", {key: val for key, val in item.items() if key not in {"observed_at", "status"}}) or {}
        if "observed_at" not in item or "status" not in item:
            raise ObservationError(f"state_missing_keys:observations.{index}")
        validated["observed_at"] = finite_state_number(f"observations.{index}.observed_at", item["observed_at"], nonnegative=True)
        if item["status"] not in {"GREEN", "YELLOW", "RED"}:
            raise ObservationError(f"state_invalid_status:observations.{index}.status")
        validated["status"] = item["status"]
        observations.append(validated)
    return observations


def validate_cost_mapping(path: str, value: Any, *, values_are_lists: bool) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ObservationError(f"state_invalid_type:{path}")
    validated: dict[str, Any] = {}
    for workload_class, item in value.items():
        if workload_class not in MIN_COSTS:
            raise ObservationError(f"state_unknown_keys:{path}.{workload_class}")
        if values_are_lists:
            if not isinstance(item, list) or len(item) > OBSERVATION_LIMIT:
                raise ObservationError(f"state_invalid_type:{path}.{workload_class}")
            validated[workload_class] = [validate_cost_record(f"{path}.{workload_class}.{index}", record) for index, record in enumerate(item)]
        else:
            validated[workload_class] = validate_cost_record(f"{path}.{workload_class}", item)
    return validated


def validate_cost_record(path: str, value: Any) -> dict[str, float]:
    if not isinstance(value, dict):
        raise ObservationError(f"state_invalid_type:{path}")
    allowed = {"memory_bytes", "processes", "root_fds", "system_fds", "heavy_lanes"}
    if set(value) - allowed:
        raise ObservationError(f"state_unknown_keys:{path}")
    return {key: finite_state_number(f"{path}.{key}", item, nonnegative=True) for key, item in value.items()}


def validate_cost_updated_at(value: Any) -> dict[str, float]:
    if not isinstance(value, dict):
        raise ObservationError("state_invalid_type:cost_updated_at")
    validated: dict[str, float] = {}
    for workload_class, item in value.items():
        if workload_class not in MIN_COSTS:
            raise ObservationError(f"state_unknown_keys:cost_updated_at.{workload_class}")
        validated[workload_class] = finite_state_number(f"cost_updated_at.{workload_class}", item, nonnegative=True)
    return validated


def evaluate_snapshot(
    snapshot: dict[str, Any],
    *,
    state: dict[str, Any] | None,
    now_epoch: float,
    workload_class: str,
    expected_cost: dict[str, float] | None,
) -> dict[str, Any]:
    old_state = default_state()
    if state:
        old_state.update(state)

    reasons: list[str] = []
    warning_reasons: list[str] = []
    missing = [str(item) for item in snapshot.get("_missing", [])]
    for key in missing:
        reasons.append(f"measurement_unavailable:{key}")

    costs = normalize_cost(expected_cost or current_cost(old_state, workload_class), workload_class)
    deltas = resource_deltas(snapshot, old_state.get("last_snapshot"), now_epoch, old_state.get("last_observed_at"))
    if missing:
        raw_status = "RED"
    else:
        raw_status = classify_raw_status(snapshot, costs, deltas, reasons, warning_reasons)

    status, hysteresis_reasons, new_recovery = apply_hysteresis(
        raw_status,
        previous_status=str(old_state.get("last_status", "GREEN")),
        previous_recovery=dict(old_state.get("recovery") or {}),
        previous_observed_at=old_state.get("last_observed_at"),
        now_epoch=now_epoch,
    )
    reasons.extend(hysteresis_reasons)
    if status == "YELLOW":
        reasons.extend(warning_reasons)
    elif status == "GREEN":
        reasons = []
    if status == "RED" and warning_reasons:
        reasons.extend(reason for reason in warning_reasons if reason not in reasons)

    observations = list(old_state.get("observations") or [])
    previous_successful_count = int(old_state.get("successful_observations", 0))
    successful_count = previous_successful_count
    cost_samples = dict(old_state.get("cost_samples") or {})
    cost_estimates = dict(old_state.get("cost_estimates") or {})
    cost_updated_at = dict(old_state.get("cost_updated_at") or {})
    previous_calibrated = len(list(cost_samples.get(workload_class, []))) >= MIN_SUCCESSFUL_OBSERVATIONS

    if not missing:
        successful_count += 1
        observations.append(observation_record(snapshot, now_epoch, status))
        observations = observations[-OBSERVATION_LIMIT:]
        sample = snapshot.get("workload_delta") if os.getenv("CODEX_CAPACITY_OBSERVER_TEST_MODE") == "1" else None
        if isinstance(sample, dict):
            class_samples = list(cost_samples.get(workload_class, []))
            class_samples.append(normalize_delta_sample(sample))
            class_samples = class_samples[-OBSERVATION_LIMIT:]
            cost_samples[workload_class] = class_samples
            if len(class_samples) >= MIN_SUCCESSFUL_OBSERVATIONS:
                prior_cost = cost_estimates.get(workload_class)
                estimated = estimate_cost(
                    workload_class,
                    class_samples,
                    prior_cost=prior_cost,
                    now_epoch=now_epoch,
                    prior_updated_epoch=float(cost_updated_at.get(workload_class, now_epoch)),
                )
                cost_estimates[workload_class] = estimated
                cost_updated_at[workload_class] = now_epoch

    calibrated = len(list(cost_samples.get(workload_class, []))) >= MIN_SUCCESSFUL_OBSERVATIONS

    clean_cycles = int(old_state.get("clean_cycles", 0))
    effective_capacity = int(old_state.get("effective_capacity", DEFAULT_CAPACITY))
    proven_capacity = int(old_state.get("proven_capacity", DEFAULT_CAPACITY))
    step_projection: dict[str, Any] | None = None
    if status == "GREEN" and calibrated:
        if not previous_calibrated:
            clean_cycles = 0
        else:
            clean_cycles += 1
        if clean_cycles >= CLEAN_CYCLES_PER_STEP:
            next_capacity = next_capacity_step(effective_capacity)
            if next_capacity > effective_capacity:
                step_projection = capacity_projection(snapshot, costs, next_capacity)
                if step_projection["ok"]:
                    effective_capacity = next_capacity
                    proven_capacity = effective_capacity
                    clean_cycles = 0
                else:
                    clean_cycles = 0
            else:
                clean_cycles = 0
    else:
        clean_cycles = 0
        if status in {"RED", "YELLOW"}:
            effective_capacity = min(proven_capacity, effective_capacity)
            if effective_capacity > DEFAULT_CAPACITY:
                effective_capacity = previous_capacity_step(effective_capacity)
            effective_capacity = max(DEFAULT_CAPACITY, min(effective_capacity, proven_capacity))
        else:
            effective_capacity = DEFAULT_CAPACITY

    if not calibrated:
        effective_capacity = DEFAULT_CAPACITY
        proven_capacity = DEFAULT_CAPACITY

    last_snapshot = sanitized_snapshot(snapshot)
    if deltas.get("swapout_bytes_per_minute") is not None:
        last_snapshot["swapout_bytes_per_minute"] = deltas["swapout_bytes_per_minute"]

    admission = admission_protocol(status, effective_capacity)
    new_state = {
        "protocol_version": PROTOCOL_VERSION,
        "last_observed_at": now_epoch,
        "last_status": status,
        "last_snapshot": last_snapshot,
        "recovery": new_recovery,
        "observations": observations,
        "successful_observations": successful_count,
        "clean_cycles": clean_cycles,
        "effective_capacity": effective_capacity,
        "proven_capacity": proven_capacity,
        "cost_samples": cost_samples,
        "cost_estimates": cost_estimates,
        "cost_updated_at": cost_updated_at,
    }
    output = {
        "protocol_version": PROTOCOL_VERSION,
        "status": status,
        "reasons": sorted(set(reasons)),
        "effective_capacity": effective_capacity,
        "admission_capacity": admission["admission_capacity"],
        "max_wave_size": admission["max_wave_size"],
        "max_capacity": MAX_CAPACITY,
        "successful_observations": successful_count,
        "clean_cycles": clean_cycles,
        "workload_class": workload_class,
        "capacity_mode": "dynamic" if calibrated else "fixed_until_calibrated",
        "measurements": measurement_summary(snapshot, deltas),
        "reserves": reserve_summary(snapshot, costs, target_capacity=effective_capacity),
    }
    if step_projection is not None:
        output["capacity_step_projection"] = step_projection
    return {"state": new_state, "output": output}


def classify_raw_status(
    snapshot: dict[str, Any],
    costs: dict[str, float],
    deltas: dict[str, float | None],
    red_reasons: list[str],
    yellow_reasons: list[str],
) -> str:
    root_fd_state = str(snapshot.get("root_fd_state", "measured"))
    if root_fd_state in {"partial", "unavailable"}:
        red_reasons.append("root_fd_measurement_unavailable")

    pressure = str(snapshot["memory_pressure"]).lower()
    if pressure in {"critical", "red"}:
        red_reasons.append("memory_pressure_critical")
    elif pressure in {"warn", "yellow"}:
        yellow_reasons.append("memory_pressure_warning")

    projection = resource_projection(snapshot, costs, additional_slots=1)
    red_reasons.extend(projection["red_reasons"])
    yellow_reasons.extend(projection["yellow_reasons"])

    swapout_rate = deltas.get("swapout_bytes_per_minute")
    previous_swapout_rate = deltas.get("previous_swapout_bytes_per_minute")
    if swapout_rate is not None and previous_swapout_rate is not None:
        if swapout_rate > SWAPOUT_RED_BYTES_PER_MINUTE and previous_swapout_rate > SWAPOUT_RED_BYTES_PER_MINUTE:
            red_reasons.append("swapout_growth_critical")
        elif swapout_rate > SWAPOUT_YELLOW_BYTES_PER_MINUTE:
            yellow_reasons.append("swapout_growth_warning")
    elif swapout_rate is not None and swapout_rate > SWAPOUT_YELLOW_BYTES_PER_MINUTE:
        yellow_reasons.append("swapout_growth_warning")

    if snapshot["cpu_idle_percent"] < 15.0:
        yellow_reasons.append("cpu_idle_warning")
    if costs.get("heavy_lanes", 0.0) > 0 and snapshot["heavy_lanes_in_use"] > 0:
        yellow_reasons.append("heavy_lane_unavailable")

    if red_reasons:
        return "RED"
    if yellow_reasons:
        return "YELLOW"
    return "GREEN"


def resource_projection(snapshot: dict[str, Any], costs: dict[str, float], *, additional_slots: int) -> dict[str, Any]:
    slots = max(0, int(additional_slots))
    total_ram = snapshot["total_ram_bytes"]
    memory_cost = costs["memory_bytes"] * slots
    process_cost = costs["processes"] * slots
    root_fd_cost = costs["root_fds"] * slots
    system_fd_cost = costs["system_fds"] * slots
    red_reasons: list[str] = []
    yellow_reasons: list[str] = []

    projected_memory = snapshot["available_memory_bytes"] - memory_cost
    red_memory_reserve = max(1.5 * 1024 * 1024 * 1024, 0.10 * total_ram)
    yellow_memory_reserve = max(2.5 * 1024 * 1024 * 1024, 0.15 * total_ram)
    if projected_memory < red_memory_reserve:
        red_reasons.append("memory_reserve_critical")
    elif projected_memory < yellow_memory_reserve:
        yellow_reasons.append("memory_reserve_warning")

    process_free = snapshot["user_process_limit"] - snapshot["user_process_count"] - process_cost
    process_reserve = max(256.0, 0.20 * snapshot["user_process_limit"])
    if process_free < process_reserve:
        red_reasons.append("process_reserve_critical")

    root_fd_free = snapshot["root_fd_soft_limit"] - snapshot["root_fd_used"] - root_fd_cost
    root_fd_reserve = max(512.0, 0.25 * snapshot["root_fd_soft_limit"])
    if root_fd_free < root_fd_reserve:
        red_reasons.append("root_fd_reserve_critical")

    system_fd_free = snapshot["system_fd_max"] - snapshot["system_fd_used"] - system_fd_cost
    system_fd_reserve = max(8192.0, 0.20 * snapshot["system_fd_max"])
    if system_fd_free < system_fd_reserve:
        red_reasons.append("system_fd_reserve_critical")

    disk_free = snapshot["disk_free_bytes"]
    disk_total = snapshot["disk_total_bytes"]
    if disk_free < max(20 * 1024 * 1024 * 1024, 0.05 * disk_total):
        red_reasons.append("disk_reserve_critical")
    elif disk_free < max(50 * 1024 * 1024 * 1024, 0.10 * disk_total):
        yellow_reasons.append("disk_reserve_warning")

    return {
        "additional_slots": slots,
        "red_reasons": red_reasons,
        "yellow_reasons": yellow_reasons,
        "projected_memory_bytes": projected_memory,
        "processes_after_launch": process_free,
        "root_fds_after_launch": root_fd_free,
        "system_fds_after_launch": system_fd_free,
    }


def capacity_projection(snapshot: dict[str, Any], costs: dict[str, float], target_capacity: int) -> dict[str, Any]:
    active_slots = int(snapshot.get("active_slots", 0))
    additional_slots = max(0, int(target_capacity) - active_slots)
    projection = resource_projection(snapshot, costs, additional_slots=additional_slots)
    blocking = projection["red_reasons"] + projection["yellow_reasons"]
    return {
        "target_capacity": int(target_capacity),
        "active_slots": active_slots,
        "additional_slots": additional_slots,
        "ok": not blocking,
        "reasons": sorted(set(blocking)),
    }


def admission_protocol(status: str, effective_capacity: int) -> dict[str, int]:
    if status == "RED":
        return {"admission_capacity": 0, "max_wave_size": 0}
    if status == "YELLOW":
        return {"admission_capacity": min(DEFAULT_CAPACITY, int(effective_capacity)), "max_wave_size": 2}
    return {"admission_capacity": int(effective_capacity), "max_wave_size": int(effective_capacity)}


def apply_hysteresis(
    raw_status: str,
    *,
    previous_status: str,
    previous_recovery: dict[str, Any],
    previous_observed_at: float | None,
    now_epoch: float,
) -> tuple[str, list[str], dict[str, Any]]:
    recovery = dict(previous_recovery)
    if previous_observed_at is not None and now_epoch - float(previous_observed_at) > RECOVERY_GAP_RESET_SECONDS:
        recovery = empty_recovery()
    if raw_status != "GREEN":
        recovery = {"from_status": raw_status, "started_at": None, "normal_count": 0, "last_normal_at": None}
        return raw_status, [], recovery

    if previous_status == "RED" or recovery.get("from_status") == "RED":
        last_normal = recovery.get("last_normal_at")
        normal_count = int(recovery.get("normal_count") or 0)
        if last_normal is None or now_epoch - float(last_normal) >= RED_RECOVERY_INTERVAL_SECONDS:
            normal_count += 1
            last_normal = now_epoch
        recovery = {
            "from_status": "RED",
            "started_at": recovery.get("started_at") or now_epoch,
            "normal_count": normal_count,
            "last_normal_at": last_normal,
        }
        if normal_count < RED_RECOVERY_SNAPSHOTS:
            return "RED", ["hysteresis_red"], recovery
        return "GREEN", [], empty_recovery()

    if previous_status == "YELLOW" or recovery.get("from_status") == "YELLOW":
        started = recovery.get("started_at") or now_epoch
        recovery = {"from_status": "YELLOW", "started_at": started, "normal_count": 0, "last_normal_at": now_epoch}
        if now_epoch - float(started) < YELLOW_RECOVERY_SECONDS:
            return "YELLOW", ["hysteresis_yellow"], recovery
        return "GREEN", [], empty_recovery()

    return "GREEN", [], empty_recovery()


def empty_recovery() -> dict[str, Any]:
    return {"from_status": None, "started_at": None, "normal_count": 0, "last_normal_at": None}


def estimate_cost(
    workload_class: str,
    samples: list[dict[str, float]],
    *,
    prior_cost: dict[str, float] | None = None,
    now_epoch: float,
    prior_updated_epoch: float,
) -> dict[str, float]:
    minimum = MIN_COSTS[workload_class]
    normalized_samples = [normalize_delta_sample(sample) for sample in samples][-OBSERVATION_LIMIT:]
    candidate: dict[str, float] = {}
    for key, minimum_value in minimum.items():
        values = [float(sample.get(key, 0.0)) for sample in normalized_samples]
        if values:
            raw_value = max(float(minimum_value), 1.5 * percentile(values, 95), 1.2 * max(values))
        else:
            raw_value = float(minimum_value)
        old_value = float((prior_cost or {}).get(key, raw_value))
        if raw_value >= old_value:
            candidate[key] = raw_value
        else:
            elapsed_days = max(0.0, now_epoch - prior_updated_epoch) / 86400.0
            max_drop_fraction = min(1.0, 0.10 * elapsed_days)
            candidate[key] = max(raw_value, old_value * (1.0 - max_drop_fraction))
    return candidate


def percentile(values: list[float], percentile_value: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * percentile_value / 100.0
    lower = math.floor(rank)
    upper = math.ceil(rank)
    if lower == upper:
        return ordered[int(rank)]
    fraction = rank - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


def current_cost(state: dict[str, Any], workload_class: str) -> dict[str, float]:
    estimates = state.get("cost_estimates") or {}
    existing = estimates.get(workload_class)
    if isinstance(existing, dict):
        return normalize_cost(existing, workload_class)
    return dict(MIN_COSTS[workload_class])


def normalize_cost(cost: dict[str, float], workload_class: str) -> dict[str, float]:
    minimum = MIN_COSTS[workload_class]
    normalized = dict(minimum)
    for key, value in cost.items():
        normalized[key] = max(float(value), float(minimum.get(key, 0.0)))
    return normalized


def normalize_delta_sample(sample: dict[str, Any]) -> dict[str, float]:
    keys = ("memory_bytes", "processes", "root_fds", "system_fds", "heavy_lanes")
    return {key: float(sample.get(key, 0.0)) for key in keys}


def calibration_token(label: str, value: Any) -> str:
    text = f"{CALIBRATION_DOMAIN}:{label}:{value}"
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:24]


def root_token_from_snapshot(snapshot: dict[str, Any]) -> str:
    identity = snapshot.get("current_codex_root_identity")
    if isinstance(identity, (list, tuple)) and len(identity) == 2:
        return calibration_token("root", f"{identity[0]}:{identity[1]}")
    pid = snapshot.get("current_codex_root_pid")
    marker = snapshot.get("current_codex_root_start_marker")
    if pid not in (None, "") and marker not in (None, ""):
        return calibration_token("root", f"{pid}:{marker}")
    return ""


def calibration_snapshot_record(snapshot: dict[str, Any], now_epoch: float) -> dict[str, Any]:
    status = str(snapshot.get("_calibration_status") or "").upper()
    if status not in {"GREEN", "YELLOW", "RED"}:
        status = "RED"
    record: dict[str, Any] = {"observed_at": float(now_epoch), "status": status}
    for key in (
        "total_ram_bytes",
        "available_memory_bytes",
        "memory_pressure",
        "swapouts_total_bytes",
        "cpu_idle_percent",
        "user_process_count",
        "user_process_limit",
        "root_fd_used",
        "current_root_fd_used",
        "root_fd_soft_limit",
        "system_fd_used",
        "system_fd_max",
        "disk_free_bytes",
        "disk_total_bytes",
        "active_slots",
        "external_codex_roots",
        "codex_root_count",
        "heavy_lanes_in_use",
    ):
        if key == "current_root_fd_used" and key not in snapshot and os.getenv(CALIBRATION_TEST_MODE_ENV) == "1":
            record[key] = finite_number("root_fd_used", snapshot.get("root_fd_used"))
            continue
        if key not in snapshot:
            raise ObservationError(f"calibration_missing:{key}")
        if key == "memory_pressure":
            pressure = str(snapshot[key]).lower()
            if pressure == "warning":
                pressure = "warn"
            if pressure not in {"normal", "warn", "critical"}:
                raise ObservationError("invalid_memory_pressure")
            record[key] = pressure
        else:
            record[key] = finite_number(key, snapshot[key])
    record["root_fd_state"] = str(snapshot.get("root_fd_state") or "measured")
    record["root_token"] = root_token_from_snapshot(snapshot)
    if not record["root_token"]:
        raise ObservationError("calibration_missing:root_token")
    return record


def validate_calibration_snapshot_record(path: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ObservationError(f"calibration_invalid_snapshot:{path}")
    allowed = {
        "observed_at", "status", "total_ram_bytes", "available_memory_bytes", "memory_pressure",
        "swapouts_total_bytes", "cpu_idle_percent", "user_process_count", "user_process_limit",
        "root_fd_used", "current_root_fd_used", "root_fd_soft_limit", "system_fd_used", "system_fd_max",
        "disk_free_bytes", "disk_total_bytes", "active_slots", "external_codex_roots", "codex_root_count",
        "heavy_lanes_in_use", "root_fd_state", "root_token",
    }
    if set(value) - allowed:
        raise ObservationError(f"calibration_unknown_snapshot_keys:{path}")
    missing = allowed - set(value)
    if missing:
        raise ObservationError(f"calibration_missing_snapshot_keys:{path}")
    record: dict[str, Any] = {}
    if value["status"] not in {"GREEN", "YELLOW", "RED"}:
        raise ObservationError(f"calibration_invalid_snapshot_status:{path}")
    if value["memory_pressure"] not in {"normal", "warn", "critical"}:
        raise ObservationError(f"calibration_invalid_snapshot_memory_pressure:{path}")
    if value["root_fd_state"] not in {"measured", "partial", "unavailable", "no_codex_root"}:
        raise ObservationError(f"calibration_invalid_snapshot_root_fd_state:{path}")
    root_value = str(value.get("root_token") or "")
    if not re.fullmatch(r"[a-f0-9]{24}", root_value):
        raise ObservationError(f"calibration_invalid_snapshot_root_token:{path}")
    for key, item in value.items():
        if key in {"status", "memory_pressure", "root_fd_state", "root_token"}:
            record[key] = str(item)
        else:
            record[key] = finite_state_number(f"{path}.{key}", item, nonnegative=True)
    return record


def default_calibration_class(workload_class: str) -> dict[str, Any]:
    return {
        "samples": [],
        "accepted_count": 0,
        "rejected_count": 0,
        "last_rejection_code": None,
        "saturated_clean_cycles": 0,
        "effective_capacity": DEFAULT_CAPACITY,
        "proven_capacity": DEFAULT_CAPACITY,
        "cost_estimate": dict(MIN_COSTS[workload_class]),
        "cost_updated_at": None,
    }


def default_calibration_state() -> dict[str, Any]:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "active": None,
        "classes": {name: default_calibration_class(name) for name in MIN_COSTS},
    }


def validate_calibration_state(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ObservationError("calibration_state_not_object")
    if int(payload.get("protocol_version", PROTOCOL_VERSION)) != PROTOCOL_VERSION:
        raise ObservationError("calibration_state_bad_version")
    state = default_calibration_state()
    classes = payload.get("classes") or {}
    if not isinstance(classes, dict):
        raise ObservationError("calibration_classes_not_object")
    for workload_class in MIN_COSTS:
        profile = default_calibration_class(workload_class)
        existing = classes.get(workload_class) or {}
        if not isinstance(existing, dict):
            raise ObservationError(f"calibration_class_not_object:{workload_class}")
        for key in profile:
            if key in existing:
                profile[key] = existing[key]
        profile["samples"] = [normalize_delta_sample(sample) for sample in list(profile.get("samples") or [])[-OBSERVATION_LIMIT:]]
        profile["accepted_count"] = state_int(f"calibration.{workload_class}.accepted_count", profile["accepted_count"], maximum=10_000_000)
        profile["rejected_count"] = state_int(f"calibration.{workload_class}.rejected_count", profile["rejected_count"], maximum=10_000_000)
        profile["saturated_clean_cycles"] = state_int(f"calibration.{workload_class}.saturated_clean_cycles", profile["saturated_clean_cycles"], maximum=10_000_000)
        profile["effective_capacity"] = state_int(f"calibration.{workload_class}.effective_capacity", profile["effective_capacity"], minimum=0, maximum=MAX_CAPACITY)
        profile["proven_capacity"] = state_int(f"calibration.{workload_class}.proven_capacity", profile["proven_capacity"], minimum=0, maximum=MAX_CAPACITY)
        if profile["effective_capacity"] not in VALID_CAPACITIES or profile["proven_capacity"] not in VALID_CAPACITIES:
            raise ObservationError(f"calibration_invalid_capacity:{workload_class}")
        if profile["accepted_count"] < MIN_SUCCESSFUL_OBSERVATIONS:
            if profile["effective_capacity"] != DEFAULT_CAPACITY or profile["proven_capacity"] != DEFAULT_CAPACITY or profile["saturated_clean_cycles"] != 0:
                raise ObservationError(f"calibration_invalid_prethreshold_state:{workload_class}")
        profile["cost_estimate"] = normalize_cost(profile.get("cost_estimate") or {}, workload_class)
        profile["cost_updated_at"] = state_optional_time(f"calibration.{workload_class}.cost_updated_at", profile.get("cost_updated_at"))
        last_code = profile.get("last_rejection_code")
        profile["last_rejection_code"] = str(last_code) if last_code not in (None, "") else None
        state["classes"][workload_class] = profile
    active = payload.get("active")
    if active is not None:
        if not isinstance(active, dict):
            raise ObservationError("calibration_active_not_object")
        allowed = {
            "phase", "workload_class", "session_token", "turn_token", "request_token", "agent_token", "armed_at",
            "started_at", "stopped_at", "settle_after", "last_observed_at", "baseline", "peak_start", "peak_stop", "settle",
        }
        active_state = {key: active[key] for key in active if key in allowed}
        if active_state.get("phase") not in {"ARMED", "MEASURING", "SETTLING"}:
            raise ObservationError("calibration_invalid_phase")
        if active_state.get("workload_class") not in MIN_COSTS:
            raise ObservationError("calibration_invalid_workload_class")
        for key in ("session_token", "turn_token", "request_token", "armed_at", "last_observed_at", "baseline"):
            if active_state.get(key) in (None, ""):
                raise ObservationError(f"calibration_missing_active:{key}")
        if active_state.get("phase") in {"MEASURING", "SETTLING"} and active_state.get("agent_token") in (None, ""):
            raise ObservationError("calibration_missing_active:agent_token")
        for key in ("armed_at", "started_at", "stopped_at", "settle_after", "last_observed_at"):
            if key in active_state:
                active_state[key] = state_optional_time(f"calibration.active.{key}", active_state[key])
        active_state["baseline"] = validate_calibration_snapshot_record("calibration.active.baseline", active_state["baseline"])
        if active_state.get("peak_start") is not None:
            active_state["peak_start"] = validate_calibration_snapshot_record("calibration.active.peak_start", active_state["peak_start"])
        if active_state.get("peak_stop") is not None:
            active_state["peak_stop"] = validate_calibration_snapshot_record("calibration.active.peak_stop", active_state["peak_stop"])
        if active_state.get("settle") is not None:
            active_state["settle"] = validate_calibration_snapshot_record("calibration.active.settle", active_state["settle"])
        state["active"] = active_state
    return state


class CalibrationStore:
    def __init__(self, state_dir: Path) -> None:
        self.state_dir = Path(state_dir).expanduser()
        self.state_path = self.state_dir / "calibration_state.json"
        self.lock_path = self.state_dir / "calibration.lock"
        self.expected_parent = self.state_dir.parent

    def update(
        self,
        callback: Callable[[dict[str, Any]], dict[str, Any]],
        *,
        deadline: float | None = None,
    ) -> dict[str, Any]:
        check_deadline(deadline)
        self._prepare_state_dir()
        with self._locked(deadline=deadline):
            state = self._load_unlocked()
            result = callback(state)
            self._save_unlocked(result["state"])
            return result["output"]

    def load(self, *, deadline: float | None = None) -> dict[str, Any]:
        check_deadline(deadline)
        self._prepare_state_dir()
        with self._locked(deadline=deadline):
            check_deadline(deadline)
            return self._load_unlocked()

    def _prepare_state_dir(self) -> None:
        self._validate_parent_chain()
        if not self.state_dir.exists() and not self.state_dir.is_symlink():
            try:
                self.state_dir.mkdir(parents=True, mode=STATE_DIR_MODE)
            except FileExistsError:
                pass
        self._validate_dir(self.state_dir)
        self._ensure_file(self.lock_path)
        if self.state_path.exists() or self.state_path.is_symlink():
            self._validate_regular_file(self.state_path)

    def _validate_parent_chain(self) -> None:
        candidates = [self.state_dir]
        candidates.extend(self.state_dir.parents)
        home = Path.home().expanduser()
        stop_after: Path | None = None
        try:
            self.state_dir.relative_to(home)
            stop_after = home.parent
        except ValueError:
            stop_after = self.state_dir.parent.parent
        for parent in candidates:
            if parent == stop_after:
                break
            if not parent.exists() and not parent.is_symlink():
                continue
            try:
                stat_result = parent.lstat()
            except OSError as exc:
                raise StoreSecurityError(f"state_parent_error:{exc}") from exc
            if os.path.islink(parent):
                raise StoreSecurityError("state_parent_symlink")

    def _locked(self, *, deadline: float | None):
        class LockContext:
            def __init__(inner_self, outer: CalibrationStore, deadline_value: float | None) -> None:
                inner_self.outer = outer
                inner_self.deadline_value = deadline_value
                inner_self.handle = None

            def __enter__(inner_self):
                inner_self.outer._validate_regular_file(inner_self.outer.lock_path)
                inner_self.handle = inner_self.outer.lock_path.open("r+", encoding="utf-8")
                try:
                    while True:
                        check_deadline(inner_self.deadline_value)
                        try:
                            fcntl.flock(inner_self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                            return inner_self.handle
                        except BlockingIOError:
                            time.sleep(min(0.01, max(0.001, remaining_seconds(inner_self.deadline_value))))
                except Exception:
                    inner_self.handle.close()
                    inner_self.handle = None
                    raise

            def __exit__(inner_self, exc_type, exc, tb) -> None:
                assert inner_self.handle is not None
                try:
                    fcntl.flock(inner_self.handle.fileno(), fcntl.LOCK_UN)
                finally:
                    inner_self.handle.close()

        return LockContext(self, deadline)

    def _ensure_file(self, path: Path) -> None:
        if path.exists() or path.is_symlink():
            self._validate_regular_file(path)
            return
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, STATE_FILE_MODE)
        except FileExistsError:
            self._validate_regular_file(path)
            return
        os.close(descriptor)
        self._validate_regular_file(path)

    def _validate_dir(self, path: Path) -> None:
        try:
            stat_result = path.lstat()
        except OSError as exc:
            raise StoreSecurityError(f"state_dir_error:{exc}") from exc
        if not os.path.isdir(path) or os.path.islink(path):
            raise StoreSecurityError("state_dir_unexpected_type")
        if stat_result.st_uid != os.getuid():
            raise StoreSecurityError("state_dir_foreign_owner")
        if stat_result.st_mode & 0o077:
            os.chmod(path, STATE_DIR_MODE)

    def _validate_regular_file(self, path: Path) -> None:
        try:
            stat_result = path.lstat()
        except OSError as exc:
            raise StoreSecurityError(f"state_file_error:{exc}") from exc
        if os.path.islink(path):
            raise StoreSecurityError("state_file_symlink")
        if not os.path.isfile(path):
            raise StoreSecurityError("state_file_unexpected_type")
        if stat_result.st_uid != os.getuid():
            raise StoreSecurityError("state_file_foreign_owner")
        if stat_result.st_nlink != 1:
            raise StoreSecurityError("state_file_hardlink")
        if stat_result.st_mode & 0o177:
            os.chmod(path, STATE_FILE_MODE)

    def _load_unlocked(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return default_calibration_state()
        self._validate_regular_file(self.state_path)
        try:
            payload = json_loads_strict(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ObservationError(f"calibration_database_error:{exc}") from exc
        return validate_calibration_state(payload)

    def _save_unlocked(self, state: dict[str, Any]) -> None:
        self._validate_dir(self.state_dir)
        if self.state_path.exists() or self.state_path.is_symlink():
            self._validate_regular_file(self.state_path)
        tmp_path = self.state_dir / f".calibration_state.{os.getpid()}.{time.time_ns()}.tmp"
        payload = json_dumps_strict(state, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        descriptor = os.open(tmp_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, STATE_FILE_MODE)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.write("\n")
            self._validate_regular_file(tmp_path)
            os.replace(tmp_path, self.state_path)
            self._validate_regular_file(self.state_path)
        finally:
            if tmp_path.exists() and not tmp_path.is_symlink():
                try:
                    stat_result = tmp_path.lstat()
                    if stat_result.st_uid == os.getuid() and stat_result.st_nlink == 1:
                        tmp_path.unlink()
                except OSError:
                    pass


def calibration_status(*, state_dir: Path | None = None, deadline: float | None = None) -> dict[str, Any]:
    state = CalibrationStore(Path(state_dir or default_state_dir())).load(deadline=deadline)
    return safe_calibration_status(state)


def safe_calibration_status(state: dict[str, Any]) -> dict[str, Any]:
    active = state.get("active") if isinstance(state.get("active"), dict) else None
    classes: dict[str, Any] = {}
    for workload_class, profile in (state.get("classes") or {}).items():
        if workload_class not in MIN_COSTS:
            continue
        classes[workload_class] = {
            "accepted_count": int(profile.get("accepted_count") or 0),
            "rejected_count": int(profile.get("rejected_count") or 0),
            "last_rejection_code": profile.get("last_rejection_code"),
            "saturated_clean_cycles": int(profile.get("saturated_clean_cycles") or 0),
            "effective_capacity": int(profile.get("effective_capacity") or DEFAULT_CAPACITY),
            "proven_capacity": int(profile.get("proven_capacity") or DEFAULT_CAPACITY),
            "cost_estimate": normalize_cost(profile.get("cost_estimate") or {}, workload_class),
        }
    return {
        "protocol_version": PROTOCOL_VERSION,
        "phase": str(active.get("phase")) if active else "IDLE",
        "workload_class": str(active.get("workload_class")) if active else None,
        "classes": classes,
    }


def calibration_hook_event(
    event: str,
    *,
    state_dir: Path | None = None,
    snapshot: dict[str, Any] | None = None,
    now_epoch: float | None = None,
    workload_class: str = "normal",
    session_id: str = "",
    turn_id: str = "",
    request_id: str = "",
    agent_id: str = "",
    deadline: float | None = None,
) -> dict[str, Any]:
    now = float(time.time() if now_epoch is None else now_epoch)
    event_deadline = deadline if deadline is not None else time.monotonic() + OBSERVE_TIMEOUT_SECONDS
    selected_class = workload_class if workload_class in MIN_COSTS else "normal"
    if selected_class == "light" and os.getenv(CALIBRATION_TEST_MODE_ENV) != "1":
        selected_class = "normal"
    tokens = {
        "session_token": calibration_token("session", session_id) if session_id else "",
        "turn_token": calibration_token("turn", turn_id) if turn_id else "",
        "request_token": calibration_token("request", request_id) if request_id else "",
        "agent_token": calibration_token("agent", agent_id) if agent_id else "",
    }

    def update(state: dict[str, Any]) -> dict[str, Any]:
        new_state = validate_calibration_state(state)
        apply_calibration_event(
            new_state,
            event,
            snapshot=snapshot,
            now_epoch=now,
            workload_class=selected_class,
            tokens=tokens,
        )
        return {"state": new_state, "output": safe_calibration_status(new_state) | {"event": event}}

    return CalibrationStore(Path(state_dir or default_state_dir())).update(update, deadline=event_deadline)


def apply_calibration_event(
    state: dict[str, Any],
    event: str,
    *,
    snapshot: dict[str, Any] | None,
    now_epoch: float,
    workload_class: str,
    tokens: dict[str, str],
) -> None:
    active = state.get("active") if isinstance(state.get("active"), dict) else None
    if active:
        expiry = calibration_expiry_code(active, now_epoch)
    else:
        expiry = ""
    if active and expiry:
        reject_active_calibration(state, expiry)
        active = None
    if event in {"spawn_failed", "stop", "session_end"}:
        require_turn = event in {"spawn_failed", "stop"}
        if active and active.get("phase") in {"ARMED", "MEASURING"} and token_matches(active, tokens, require_agent=False, require_turn=require_turn):
            reject_active_calibration(state, event)
        return
    if event == "pretool_lease":
        if active is not None or snapshot is None:
            return
        try:
            record = calibration_snapshot_record(snapshot, now_epoch)
        except ObservationError:
            return
        state["active"] = {
            "phase": "ARMED",
            "workload_class": workload_class,
            "session_token": tokens.get("session_token", ""),
            "turn_token": tokens.get("turn_token", ""),
            "request_token": tokens.get("request_token", ""),
            "agent_token": "",
            "armed_at": now_epoch,
            "started_at": None,
            "stopped_at": None,
            "settle_after": None,
            "last_observed_at": now_epoch,
            "baseline": record,
            "peak_start": None,
            "peak_stop": None,
            "settle": None,
        }
        return
    if active is None:
        return
    if event == "subagent_start":
        if snapshot is None or not token_matches(active, tokens, require_agent=False, require_turn=True):
            return
        try:
            record = calibration_snapshot_record(snapshot, now_epoch)
        except ObservationError:
            return
        active["phase"] = "MEASURING"
        active["agent_token"] = tokens.get("agent_token", "")
        active["started_at"] = now_epoch
        active["last_observed_at"] = now_epoch
        active["peak_start"] = record
        return
    if event == "subagent_stop_before_release":
        if snapshot is None or not token_matches(active, tokens, require_agent=True, require_turn=False):
            return
        try:
            record = calibration_snapshot_record(snapshot, now_epoch)
        except ObservationError:
            return
        active["phase"] = "SETTLING"
        active["stopped_at"] = now_epoch
        active["settle_after"] = now_epoch + CALIBRATION_SETTLE_SECONDS
        active["last_observed_at"] = now_epoch
        active["peak_stop"] = record
        return
    if event == "settle_snapshot":
        if snapshot is None or active.get("phase") != "SETTLING":
            return
        if now_epoch < float(active.get("settle_after") or 0.0):
            return
        try:
            active["settle"] = calibration_snapshot_record(snapshot, now_epoch)
        except ObservationError:
            reject_active_calibration(state, "invalid_settle_snapshot")
            return
        accept_or_reject_calibration(state, now_epoch)


def calibration_expiry_code(active: dict[str, Any], now_epoch: float) -> str:
    armed_at = float(active.get("armed_at") or now_epoch)
    last_observed = float(active.get("last_observed_at") or armed_at)
    if now_epoch - armed_at > CALIBRATION_MAX_SECONDS:
        return "expired"
    if now_epoch - last_observed > CALIBRATION_MAX_GAP_SECONDS:
        return "sleep_gap"
    return ""


def token_matches(active: dict[str, Any], tokens: dict[str, str], *, require_agent: bool, require_turn: bool) -> bool:
    keys = ["session_token"]
    if require_turn:
        keys.append("turn_token")
    if require_agent:
        keys.append("agent_token")
    for key in keys:
        if active.get(key) in (None, "") or tokens.get(key) in (None, "") or active.get(key) != tokens.get(key):
            return False
    return True


def reject_active_calibration(state: dict[str, Any], code: str) -> None:
    active = state.get("active") if isinstance(state.get("active"), dict) else None
    workload_class = str((active or {}).get("workload_class") or "normal")
    profile = state["classes"].setdefault(workload_class, default_calibration_class(workload_class))
    profile["rejected_count"] = int(profile.get("rejected_count") or 0) + 1
    profile["last_rejection_code"] = code
    profile["saturated_clean_cycles"] = 0
    if code.startswith("resource_") and int(profile.get("effective_capacity") or DEFAULT_CAPACITY) > DEFAULT_CAPACITY:
        profile["effective_capacity"] = previous_capacity_step(int(profile.get("effective_capacity") or DEFAULT_CAPACITY))
    state["active"] = None


def accept_or_reject_calibration(state: dict[str, Any], now_epoch: float) -> None:
    active = state.get("active") if isinstance(state.get("active"), dict) else None
    if not active:
        return
    code = calibration_rejection_code(active)
    if code:
        reject_active_calibration(state, code)
        return
    workload_class = str(active.get("workload_class") or "normal")
    profile = state["classes"].setdefault(workload_class, default_calibration_class(workload_class))
    samples = list(profile.get("samples") or [])
    samples.append(calibration_delta(active))
    profile["samples"] = samples[-OBSERVATION_LIMIT:]
    previous_accepted = int(profile.get("accepted_count") or 0)
    profile["accepted_count"] = previous_accepted + 1
    profile["last_rejection_code"] = None
    profile["cost_estimate"] = estimate_cost(
        workload_class,
        profile["samples"],
        prior_cost=profile.get("cost_estimate"),
        now_epoch=now_epoch,
        prior_updated_epoch=float(profile.get("cost_updated_at") or now_epoch),
    )
    profile["cost_updated_at"] = now_epoch
    effective = int(profile.get("effective_capacity") or DEFAULT_CAPACITY)
    if previous_accepted >= MIN_SUCCESSFUL_OBSERVATIONS:
        peak_slots = int(float(active["peak_stop"]["active_slots"]))
        if peak_slots >= effective:
            profile["saturated_clean_cycles"] = int(profile.get("saturated_clean_cycles") or 0) + 1
        else:
            profile["saturated_clean_cycles"] = 0
        if int(profile.get("saturated_clean_cycles") or 0) >= CLEAN_CYCLES_PER_STEP:
            next_step = next_capacity_step(effective)
            projection = capacity_projection(active["settle"], normalize_cost(profile["cost_estimate"], workload_class), next_step)
            if next_step > effective and projection["ok"]:
                profile["effective_capacity"] = next_step
                profile["proven_capacity"] = next_step
            profile["saturated_clean_cycles"] = 0
    else:
        profile["effective_capacity"] = DEFAULT_CAPACITY
        profile["proven_capacity"] = DEFAULT_CAPACITY
        profile["saturated_clean_cycles"] = 0
    state["active"] = None


def calibration_rejection_code(active: dict[str, Any]) -> str:
    names = ("baseline", "peak_start", "peak_stop", "settle")
    if any(not isinstance(active.get(name), dict) for name in names):
        return "missing_snapshot"
    baseline = active["baseline"]
    peak_start = active["peak_start"]
    peak_stop = active["peak_stop"]
    settle = active["settle"]
    snapshots = (baseline, peak_start, peak_stop, settle)
    if any(item.get("status") != "GREEN" for item in snapshots):
        return "resource_not_green"
    if any(item.get("root_fd_state") != "measured" for item in snapshots):
        return "root_fd_unmeasured"
    if float(active.get("stopped_at") or 0.0) - float(active.get("started_at") or 0.0) < CALIBRATION_MIN_PEAK_SECONDS:
        return "task_too_short"
    if float(active.get("stopped_at") or 0.0) - float(active.get("armed_at") or 0.0) > CALIBRATION_MAX_SECONDS:
        return "expired"
    observed = [float(item["observed_at"]) for item in snapshots]
    if any(right - left > CALIBRATION_MAX_GAP_SECONDS for left, right in zip(observed, observed[1:])):
        return "sleep_gap"
    baseline_slots = float(baseline["active_slots"])
    if float(peak_start["active_slots"]) != baseline_slots + 1 or float(peak_stop["active_slots"]) != baseline_slots + 1:
        return "active_slots_changed"
    if float(settle["active_slots"]) != baseline_slots:
        return "active_slots_changed"
    for key, code in (
        ("external_codex_roots", "external_roots_changed"),
        ("codex_root_count", "codex_roots_changed"),
        ("root_token", "root_token_changed"),
    ):
        if any(item.get(key) != baseline.get(key) for item in snapshots[1:]):
            return code
    if float(settle["swapouts_total_bytes"]) > float(baseline["swapouts_total_bytes"]):
        return "swap_growth"
    memory_drift = max(float(CALIBRATION_MEMORY_DRIFT_BYTES), 0.02 * float(baseline["total_ram_bytes"]))
    system_drift = max(float(CALIBRATION_SYSTEM_FD_DRIFT), 0.0025 * float(baseline["system_fd_max"]))
    if float(baseline["available_memory_bytes"]) - float(settle["available_memory_bytes"]) > memory_drift:
        return "settle_memory_drift"
    if float(settle["user_process_count"]) - float(baseline["user_process_count"]) > CALIBRATION_PROCESS_DRIFT:
        return "settle_process_drift"
    if float(settle["current_root_fd_used"]) - float(baseline["current_root_fd_used"]) > CALIBRATION_ROOT_FD_DRIFT:
        return "settle_root_fd_drift"
    if float(settle["system_fd_used"]) - float(baseline["system_fd_used"]) > system_drift:
        return "settle_system_fd_drift"
    return ""


def calibration_delta(active: dict[str, Any]) -> dict[str, float]:
    baseline = active["baseline"]
    peak_start = active["peak_start"]
    peak_stop = active["peak_stop"]
    settle = active["settle"]
    peak_available = min(float(peak_start["available_memory_bytes"]), float(peak_stop["available_memory_bytes"]))
    stable_available = max(float(baseline["available_memory_bytes"]), float(settle["available_memory_bytes"]))
    return normalize_delta_sample(
        {
            "memory_bytes": max(0.0, stable_available - peak_available),
            "processes": max(0.0, max(float(peak_start["user_process_count"]), float(peak_stop["user_process_count"])) - min(float(baseline["user_process_count"]), float(settle["user_process_count"]))),
            "root_fds": max(0.0, max(float(peak_start["current_root_fd_used"]), float(peak_stop["current_root_fd_used"])) - min(float(baseline["current_root_fd_used"]), float(settle["current_root_fd_used"]))),
            "system_fds": max(0.0, max(float(peak_start["system_fd_used"]), float(peak_stop["system_fd_used"])) - min(float(baseline["system_fd_used"]), float(settle["system_fd_used"]))),
            "heavy_lanes": max(0.0, max(float(peak_start["heavy_lanes_in_use"]), float(peak_stop["heavy_lanes_in_use"])) - min(float(baseline["heavy_lanes_in_use"]), float(settle["heavy_lanes_in_use"]))),
        }
    )


def apply_calibration_to_output(
    output: dict[str, Any],
    snapshot: dict[str, Any],
    *,
    state_dir: Path,
    now_epoch: float,
    workload_class: str,
    deadline: float | None = None,
) -> dict[str, Any]:
    if os.getenv("CODEX_CAPACITY_OBSERVER_TEST_MODE") == "1" and isinstance(snapshot.get("workload_delta"), dict):
        return output
    patched = dict(output)
    selected_class = workload_class if workload_class in MIN_COSTS else "normal"
    try:
        snapshot_for_settle = dict(snapshot)
        snapshot_for_settle["_calibration_status"] = str(output.get("status") or "RED")
        settle = calibration_hook_event(
            "settle_snapshot",
            state_dir=state_dir,
            snapshot=snapshot_for_settle,
            now_epoch=now_epoch,
            workload_class=selected_class,
            deadline=deadline,
        )
        profile = settle["classes"][selected_class]
    except Exception:
        status = str(patched.get("status") or "RED")
        patched["effective_capacity"] = DEFAULT_CAPACITY
        patched["admission_capacity"] = 0 if status == "RED" else DEFAULT_CAPACITY if status == "GREEN" else min(DEFAULT_CAPACITY, int(patched.get("admission_capacity") or DEFAULT_CAPACITY))
        patched["max_wave_size"] = 0 if status == "RED" else DEFAULT_CAPACITY if status == "GREEN" else min(2, int(patched.get("max_wave_size") or 2))
        patched["capacity_mode"] = "calibration_unavailable_fixed6"
        patched["accepted_calibrations"] = 0
        patched["calibration_error"] = "calibration_state_unavailable"
        return patched
    accepted = int(profile.get("accepted_count") or 0)
    effective = int(profile.get("effective_capacity") or DEFAULT_CAPACITY)
    if accepted < MIN_SUCCESSFUL_OBSERVATIONS:
        effective = DEFAULT_CAPACITY
    status = str(patched.get("status") or "RED")
    admission = admission_protocol(status, effective)
    patched["workload_class"] = selected_class
    patched["accepted_calibrations"] = accepted
    patched["rejected_calibrations"] = int(profile.get("rejected_count") or 0)
    patched["last_calibration_rejection"] = profile.get("last_rejection_code")
    patched["clean_cycles"] = int(profile.get("saturated_clean_cycles") or 0)
    patched["capacity_mode"] = "dynamic" if accepted >= MIN_SUCCESSFUL_OBSERVATIONS else "fixed_until_calibrated"
    patched["calibration_phase"] = settle.get("phase") or "IDLE"
    patched["effective_capacity"] = effective
    patched["admission_capacity"] = admission["admission_capacity"]
    patched["max_wave_size"] = admission["max_wave_size"]
    return patched


def resource_deltas(
    snapshot: dict[str, Any],
    previous_snapshot: dict[str, Any] | None,
    now_epoch: float,
    previous_epoch: float | None,
) -> dict[str, float | None]:
    swapout_rate = None
    previous_swapout_rate = None
    if previous_snapshot and previous_epoch is not None:
        elapsed = max(0.001, now_epoch - float(previous_epoch))
        swapout_delta = max(0.0, float(snapshot["swapouts_total_bytes"]) - float(previous_snapshot.get("swapouts_total_bytes", 0.0)))
        swapout_rate = swapout_delta * 60.0 / elapsed
        previous_swapout_rate = previous_snapshot.get("swapout_bytes_per_minute")
    return {"swapout_bytes_per_minute": swapout_rate, "previous_swapout_bytes_per_minute": previous_swapout_rate}


def observation_record(snapshot: dict[str, Any], now_epoch: float, status: str) -> dict[str, Any]:
    record = measurement_summary(snapshot, {})
    record["observed_at"] = now_epoch
    record["status"] = status
    return record


def sanitized_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    allowed = set(MANDATORY_MEASUREMENTS) | {"root_fd_state", "codex_root_count", "external_codex_roots", "memory_free_percent"}
    return {key: snapshot[key] for key in allowed if key in snapshot}


def measurement_summary(snapshot: dict[str, Any], deltas: dict[str, float | None]) -> dict[str, Any]:
    summary = {key: snapshot.get(key) for key in MANDATORY_MEASUREMENTS}
    summary["swapout_bytes_per_minute"] = deltas.get("swapout_bytes_per_minute")
    if "root_fd_state" in snapshot:
        summary["root_fd_state"] = snapshot["root_fd_state"]
    if "codex_root_count" in snapshot:
        summary["codex_root_count"] = snapshot["codex_root_count"]
    if "external_codex_roots" in snapshot:
        summary["external_codex_roots"] = snapshot["external_codex_roots"]
    if "memory_free_percent" in snapshot:
        summary["memory_free_percent"] = snapshot["memory_free_percent"]
    return summary


def reserve_summary(snapshot: dict[str, Any], costs: dict[str, float], *, target_capacity: int) -> dict[str, Any]:
    if snapshot.get("_missing"):
        return {}
    projection = capacity_projection(snapshot, costs, target_capacity)
    one_slot = resource_projection(snapshot, costs, additional_slots=1)
    return {
        "single_slot": one_slot,
        "target_capacity_projection": projection,
        "required_red_memory_bytes": max(1.5 * 1024 * 1024 * 1024, 0.10 * snapshot["total_ram_bytes"]),
        "required_yellow_memory_bytes": max(2.5 * 1024 * 1024 * 1024, 0.15 * snapshot["total_ram_bytes"]),
        "required_process_reserve": max(256.0, 0.20 * snapshot["user_process_limit"]),
        "required_root_fd_reserve": max(512.0, 0.25 * snapshot["root_fd_soft_limit"]),
        "required_system_fd_reserve": max(8192.0, 0.20 * snapshot["system_fd_max"]),
    }


def next_capacity_step(current: int) -> int:
    for step in CAPACITY_STEPS:
        if step > current:
            return step
    return min(MAX_CAPACITY, current)


def previous_capacity_step(current: int) -> int:
    candidates = [DEFAULT_CAPACITY] + [step for step in CAPACITY_STEPS if step < current]
    return max(candidates)


def default_state() -> dict[str, Any]:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "last_observed_at": None,
        "last_status": "GREEN",
        "last_snapshot": None,
        "recovery": empty_recovery(),
        "observations": [],
        "successful_observations": 0,
        "clean_cycles": 0,
        "effective_capacity": DEFAULT_CAPACITY,
        "proven_capacity": DEFAULT_CAPACITY,
        "cost_samples": {},
        "cost_estimates": {},
        "cost_updated_at": {},
    }


class ObserverStore:
    def __init__(self, state_dir: Path) -> None:
        self.state_dir = Path(state_dir).expanduser()
        self.state_path = self.state_dir / "observer_state.json"
        self.lock_path = self.state_dir / "observer.lock"
        self.expected_parent = self.state_dir.parent

    def update(
        self,
        callback: Callable[[dict[str, Any]], dict[str, Any]],
        *,
        deadline: float | None = None,
    ) -> dict[str, Any]:
        check_deadline(deadline)
        self._prepare_state_dir()
        check_deadline(deadline)
        with self._locked(deadline=deadline):
            check_deadline(deadline)
            state = self._load_unlocked()
            check_deadline(deadline)
            result = callback(state)
            check_deadline(deadline)
            self._save_unlocked(result["state"])
            check_deadline(deadline)
            return result["output"]

    def load(self) -> dict[str, Any]:
        self._prepare_state_dir()
        with self._locked(deadline=None):
            return self._load_unlocked()

    def save(self, state: dict[str, Any]) -> None:
        self._prepare_state_dir()
        with self._locked(deadline=None):
            self._save_unlocked(state)

    def _prepare_state_dir(self) -> None:
        self._validate_parent_chain()
        if not self.state_dir.exists() and not self.state_dir.is_symlink():
            try:
                self.state_dir.mkdir(parents=True, mode=STATE_DIR_MODE)
            except FileExistsError:
                pass
        self._validate_dir(self.state_dir)
        self._ensure_file(self.lock_path)
        if self.state_path.exists() or self.state_path.is_symlink():
            self._validate_regular_file(self.state_path)

    def _validate_parent_chain(self) -> None:
        candidates = [self.state_dir]
        candidates.extend(self.state_dir.parents)
        home = Path.home().expanduser()
        stop_after: Path | None = None
        try:
            self.state_dir.relative_to(home)
            stop_after = home.parent
        except ValueError:
            stop_after = self.state_dir.parent.parent
        for parent in candidates:
            if parent == stop_after:
                break
            if not parent.exists() and not parent.is_symlink():
                continue
            try:
                stat_result = parent.lstat()
            except OSError as exc:
                raise StoreSecurityError(f"state_parent_error:{exc}") from exc
            if os.path.islink(parent):
                raise StoreSecurityError("state_parent_symlink")

    def _locked(self, *, deadline: float | None):
        class LockContext:
            def __init__(inner_self, outer: ObserverStore, deadline_value: float | None) -> None:
                inner_self.outer = outer
                inner_self.deadline_value = deadline_value
                inner_self.handle = None

            def __enter__(inner_self):
                inner_self.outer._validate_regular_file(inner_self.outer.lock_path)
                inner_self.handle = inner_self.outer.lock_path.open("r+", encoding="utf-8")
                try:
                    while True:
                        check_deadline(inner_self.deadline_value)
                        try:
                            fcntl.flock(inner_self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                            return inner_self.handle
                        except BlockingIOError:
                            time.sleep(min(0.01, max(0.001, remaining_seconds(inner_self.deadline_value))))
                except Exception:
                    inner_self.handle.close()
                    inner_self.handle = None
                    raise

            def __exit__(inner_self, exc_type, exc, tb) -> None:
                assert inner_self.handle is not None
                try:
                    fcntl.flock(inner_self.handle.fileno(), fcntl.LOCK_UN)
                finally:
                    inner_self.handle.close()

        return LockContext(self, deadline)

    def _load_unlocked(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return default_state()
        self._validate_regular_file(self.state_path)
        try:
            payload = json_loads_strict(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ObservationError(f"database_error:{exc}") from exc
        return validate_state(payload)

    def _save_unlocked(self, state: dict[str, Any]) -> None:
        self._validate_dir(self.state_dir)
        if self.state_path.exists() or self.state_path.is_symlink():
            self._validate_regular_file(self.state_path)
        tmp_path = self.state_dir / f".observer_state.{os.getpid()}.{time.time_ns()}.tmp"
        payload = json_dumps_strict(state, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        descriptor = os.open(tmp_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, STATE_FILE_MODE)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.write("\n")
            self._validate_regular_file(tmp_path)
            os.replace(tmp_path, self.state_path)
            self._validate_regular_file(self.state_path)
        finally:
            if tmp_path.exists() and not tmp_path.is_symlink():
                try:
                    stat_result = tmp_path.lstat()
                    if stat_result.st_uid == os.getuid() and stat_result.st_nlink == 1:
                        tmp_path.unlink()
                except OSError:
                    pass

    def _ensure_file(self, path: Path) -> None:
        if path.exists() or path.is_symlink():
            self._validate_regular_file(path)
            return
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, STATE_FILE_MODE)
        except FileExistsError:
            self._validate_regular_file(path)
            return
        os.close(descriptor)
        self._validate_regular_file(path)

    def _validate_dir(self, path: Path) -> None:
        try:
            stat_result = path.lstat()
        except OSError as exc:
            raise StoreSecurityError(f"state_dir_error:{exc}") from exc
        if not os.path.isdir(path) or os.path.islink(path):
            raise StoreSecurityError("state_dir_unexpected_type")
        if stat_result.st_uid != os.getuid():
            raise StoreSecurityError("state_dir_foreign_owner")
        if stat_result.st_mode & 0o077:
            os.chmod(path, STATE_DIR_MODE)

    def _validate_regular_file(self, path: Path) -> None:
        try:
            stat_result = path.lstat()
        except OSError as exc:
            raise StoreSecurityError(f"state_file_error:{exc}") from exc
        if os.path.islink(path):
            raise StoreSecurityError("state_file_symlink")
        if not os.path.isfile(path):
            raise StoreSecurityError("state_file_unexpected_type")
        if stat_result.st_uid != os.getuid():
            raise StoreSecurityError("state_file_foreign_owner")
        if stat_result.st_nlink != 1:
            raise StoreSecurityError("state_file_hardlink")
        if stat_result.st_mode & 0o177:
            os.chmod(path, STATE_FILE_MODE)


def collect_snapshot(
    *,
    state_dir: Path | None = None,
    deadline: float | None = None,
    managed_root_identities: list[tuple[int, str]] | None = None,
    caller_pid: int | None = None,
) -> dict[str, Any]:
    sysctl_values = collect_sysctl(deadline=deadline)
    vm_values = collect_vm_stat(deadline=deadline)
    pressure_values = collect_memory_pressure(sysctl_values["total_ram_bytes"], deadline=deadline)
    process_values = collect_process_snapshot(
        deadline=deadline,
        managed_root_identities=managed_root_identities,
        caller_pid=caller_pid,
    )
    disk_values = collect_disk(state_dir=state_dir, deadline=deadline)
    snapshot: dict[str, Any] = {"heavy_lanes_in_use": 0.0, "active_slots": 0.0}
    snapshot.update(sysctl_values)
    snapshot.update(vm_values)
    snapshot.update(pressure_values)
    snapshot.update(process_values)
    snapshot.update(disk_values)
    return snapshot


def collect_vm_stat(*, deadline: float | None = None) -> dict[str, Any]:
    completed = run_command(["vm_stat"], deadline=deadline)
    page_size = 4096
    values: dict[str, int] = {}
    for line in completed.splitlines():
        if "page size of" in line:
            parts = [part for part in line.split() if part.isdigit()]
            if parts:
                page_size = int(parts[0])
            continue
        if ":" not in line:
            continue
        key, raw_value = line.split(":", 1)
        number = "".join(ch for ch in raw_value if ch.isdigit())
        if number:
            values[key.strip().lower()] = int(number)
    free_pages = values.get("pages free", 0) + values.get("pages inactive", 0) + values.get("pages speculative", 0)
    return {
        "available_memory_bytes": float(free_pages * page_size),
        "swapouts_total_bytes": float(values.get("swapouts", 0) * page_size),
    }


def collect_memory_pressure(total_ram_bytes: float, *, deadline: float | None = None) -> dict[str, Any]:
    completed = run_command(["memory_pressure", "-Q"], deadline=deadline)
    free_percent = parse_memory_pressure_free_percent(completed)
    pressure = pressure_from_free_percent(free_percent)
    available = float(total_ram_bytes) * free_percent / 100.0
    return {
        "memory_pressure": pressure,
        "memory_free_percent": free_percent,
        "available_memory_bytes": available,
    }


def parse_memory_pressure_free_percent(text: str) -> float:
    for line in text.splitlines():
        lowered = line.lower()
        if "free percentage" not in lowered:
            continue
        digits = "".join(ch if ch.isdigit() or ch == "." else " " for ch in line).split()
        if digits:
            return float(digits[-1])
    raise ObservationError("measurement_unavailable:memory_pressure_free_percentage")


def pressure_from_free_percent(free_percent: float) -> str:
    if free_percent < MEMORY_PRESSURE_CRITICAL_FREE_PERCENT:
        return "critical"
    if free_percent < MEMORY_PRESSURE_WARN_FREE_PERCENT:
        return "warn"
    return "normal"


def collect_sysctl(*, deadline: float | None = None) -> dict[str, Any]:
    names = ("hw.memsize", "kern.maxprocperuid", "kern.maxfiles", "kern.num_files")
    completed = run_command(["sysctl", *names], deadline=deadline)
    values: dict[str, float] = {}
    for line in completed.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        values[key.strip()] = float(value.strip())
    soft_fd_limit, _hard_fd_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    return {
        "total_ram_bytes": values["hw.memsize"],
        "user_process_limit": values["kern.maxprocperuid"],
        "system_fd_max": values["kern.maxfiles"],
        "system_fd_used": values["kern.num_files"],
        "root_fd_soft_limit": float(soft_fd_limit),
    }


def collect_process_snapshot(
    *,
    deadline: float | None = None,
    managed_root_identities: list[tuple[int, str]] | None = None,
    caller_pid: int | None = None,
) -> dict[str, Any]:
    proof_started_at = time.time()
    rows = parse_ps_snapshot(run_command(["ps", "-axo", "pid=,ppid=,uid=,user=,lstart=,%cpu=,command="], deadline=deadline))
    uid = os.getuid()
    user_process_count = sum(1 for row in rows if row["uid"] == uid)
    cpu_used = sum(row["cpu_percent"] for row in rows)
    cpu_idle = max(0.0, 100.0 - (cpu_used / max(1, os.cpu_count() or 1)))
    codex_roots = codex_root_pids(rows, uid)
    fd_usage = root_fd_usage_for_codex_roots(codex_roots, deadline=deadline)
    occupancy = codex_root_occupancy(
        rows,
        uid,
        managed_root_identities=managed_root_identities,
        caller_pid=caller_pid,
    )
    current_identity = occupancy.get("current_codex_root_identity")
    current_fd_used = 0.0
    if isinstance(current_identity, tuple):
        current_fd_used = float(fd_usage.get("root_fd_counts", {}).get(str(current_identity[0]), 0.0))
    return {
        "user_process_count": float(user_process_count),
        "cpu_idle_percent": cpu_idle,
        "root_fd_used": float(fd_usage["root_fd_used"]),
        "current_root_fd_used": current_fd_used,
        "root_fd_state": fd_usage["root_fd_state"],
        "codex_root_count": occupancy["codex_root_count"],
        "external_codex_roots": occupancy["external_codex_roots"],
        "current_codex_root_identity": occupancy.get("current_codex_root_identity"),
        "managed_codex_root_identities": occupancy.get("managed_codex_root_identities", []),
        "codex_process_snapshot_started_at": proof_started_at,
    }


def parse_ps_snapshot(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen_pids: set[int] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        parts = line.split(None, 10)
        if len(parts) == 11:
            pid, ppid, uid, user = parts[:4]
            started_text = " ".join(parts[4:9])
            cpu = parts[9]
            command = parts[10]
            try:
                started_epoch = datetime.strptime(started_text, "%a %b %d %H:%M:%S %Y").timestamp()
            except ValueError as exc:
                raise ObservationError(f"malformed_ps_row:{line_number}") from exc
            start_marker = str(int(started_epoch))
        else:
            legacy = line.split(None, 5)
            if len(legacy) != 6:
                raise ObservationError(f"malformed_ps_row:{line_number}")
            pid, ppid, uid, user, cpu, command = legacy
            start_marker = ""
        if not command:
            raise ObservationError(f"malformed_ps_row:{line_number}")
        argv0 = command_argv0(command)
        pid_int = int(pid)
        if pid_int in seen_pids:
            raise ObservationError(f"duplicate_ps_pid:{pid_int}")
        seen_pids.add(pid_int)
        rows.append(
            {
                "pid": pid_int,
                "ppid": int(ppid),
                "uid": int(uid),
                "user": user,
                "cpu_percent": float(cpu),
                "start_marker": start_marker,
                "comm": argv0,
                "command": command,
                "executable": argv0,
            }
        )
    if not rows:
        raise ObservationError("measurement_unavailable:ps_empty")
    return rows


def command_executable(command: str) -> str:
    return command_argv0(command)


def command_argv0(command: str) -> str:
    stripped = command.strip()
    if not stripped:
        return ""
    if stripped == "codex" or stripped.startswith("codex "):
        return "codex"
    if stripped == "codex-smart" or stripped.startswith("codex-smart "):
        return "codex-smart"
    known_prefixes = (
        "/opt/",
        "/usr/local/",
        "/usr/bin/",
        "/bin/",
        "/Users/",
        os.path.expanduser("~/.local/bin/"),
    )
    if stripped.startswith("/Applications/"):
        return stripped.split(None, 1)[0]
    if stripped.startswith(known_prefixes):
        return stripped.split(None, 1)[0]
    return stripped.split(None, 1)[0]


def is_excluded_codex_helper(command: str) -> bool:
    lowered = command.lower()
    excluded_markers = (
        "codex framework",
        "codex.framework",
        "codex (service",
        "codex (renderer",
        "codex service",
        "codex renderer",
        "crashpad",
        "computer use",
        "chatgpt helper",
        "chatgpt.app",
        "/applications/",
    )
    return any(marker in lowered for marker in excluded_markers)


def is_codex_process(row: dict[str, Any]) -> bool:
    argv0 = str(row.get("comm") or row.get("executable") or "").strip()
    command = str(row.get("command", "")).strip()
    if is_excluded_codex_helper(command):
        return False
    basename = os.path.basename(argv0).lower()
    if basename in {"codex-app-server", "codex_app_server"} or (
        basename == "codex" and codex_cli_subcommand(command) == "app-server"
    ):
        return False
    return basename in {"codex", "codex-smart"}


CODEX_OPTIONS_WITH_VALUE = {
    "--add-dir",
    "--ask-for-approval",
    "--cd",
    "--config",
    "--disable",
    "--enable",
    "--image",
    "--local-provider",
    "--model",
    "--profile",
    "--remote",
    "--remote-auth-token-env",
    "--sandbox",
    "-C",
    "-a",
    "-c",
    "-i",
    "-m",
    "-p",
    "-s",
}
CODEX_FLAG_OPTIONS = {
    "--dangerously-bypass-approvals-and-sandbox",
    "--dangerously-bypass-hook-trust",
    "--help",
    "--no-alt-screen",
    "--oss",
    "--search",
    "--strict-config",
    "--version",
    "-V",
    "-h",
}
CODEX_SHORT_OPTIONS_WITH_ATTACHED_VALUE = {"-C", "-a", "-c", "-i", "-m", "-p", "-s"}


def codex_cli_subcommand(command: str) -> str | None:
    """Return the first Codex positional command after known global options."""

    try:
        arguments = shlex.split(command, posix=True)
    except ValueError:
        return None
    if len(arguments) < 2:
        return None
    index = 1
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            return None
        if argument in CODEX_OPTIONS_WITH_VALUE:
            if index + 1 >= len(arguments):
                return None
            index += 2
            continue
        if any(
            argument.startswith(f"{option}=")
            for option in CODEX_OPTIONS_WITH_VALUE
            if option.startswith("--")
        ):
            index += 1
            continue
        if argument in CODEX_FLAG_OPTIONS:
            index += 1
            continue
        if any(
            argument.startswith(option) and argument != option
            for option in CODEX_SHORT_OPTIONS_WITH_ATTACHED_VALUE
        ):
            index += 1
            continue
        if argument.startswith("-"):
            return None
        return argument
    return None


def codex_root_pids(rows: list[dict[str, Any]], uid: int) -> list[int]:
    return [int(row["pid"]) for row in codex_root_rows(rows, uid)]


def codex_root_rows(rows: list[dict[str, Any]], uid: int) -> list[dict[str, Any]]:
    by_pid = rows_by_pid(rows)
    roots: list[dict[str, Any]] = []
    for row in rows:
        if row["uid"] != uid or not is_codex_process(row):
            continue
        parent = by_pid.get(row["ppid"])
        if parent is not None and parent_started_not_after_child(parent, row) and is_codex_process(parent):
            continue
        roots.append(row)
    return sorted(roots, key=lambda item: int(item["pid"]))


def rows_by_pid(rows: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    by_pid: dict[int, dict[str, Any]] = {}
    for row in rows:
        pid = int(row["pid"])
        if pid in by_pid:
            raise ObservationError(f"duplicate_ps_pid:{pid}")
        by_pid[pid] = row
    return by_pid


def parent_started_not_after_child(parent: dict[str, Any], child: dict[str, Any]) -> bool:
    parent_marker = str(parent.get("start_marker") or "").strip()
    child_marker = str(child.get("start_marker") or "").strip()
    if not parent_marker or not child_marker:
        return True
    try:
        return int(parent_marker) <= int(child_marker)
    except ValueError as exc:
        raise ObservationError("invalid_ps_start_marker") from exc


def codex_root_occupancy(
    rows: list[dict[str, Any]],
    uid: int,
    *,
    managed_root_identities: list[tuple[int, str]] | None = None,
    caller_pid: int | None = None,
) -> dict[str, Any]:
    roots = codex_root_rows(rows, uid)
    managed = normalize_root_identity_set(managed_root_identities or [])
    current = current_codex_root_identity(rows, uid, caller_pid=caller_pid)
    if current is not None:
        managed.add(current)
    external = 0
    for root in roots:
        identity = root_identity(root)
        if identity is None or identity not in managed:
            external += 1
    return {
        "codex_root_count": float(len(roots)),
        "external_codex_roots": float(external),
        "current_codex_root_identity": current,
        "managed_codex_root_identities": live_managed_root_identities(rows, uid, managed),
    }


def live_managed_root_identities(
    rows: list[dict[str, Any]],
    uid: int,
    managed: set[tuple[int, str]],
) -> list[tuple[int, str]]:
    live: set[tuple[int, str]] = set()
    for row in rows:
        if int(row.get("uid", -1)) != uid:
            continue
        identity = root_identity(row)
        if identity is not None and identity in managed:
            live.add(identity)
    return sorted(live)


def current_codex_root_identity(
    rows: list[dict[str, Any]],
    uid: int,
    *,
    caller_pid: int | None = None,
) -> tuple[int, str] | None:
    by_pid = rows_by_pid(rows)
    pid = int(caller_pid or os.getpid())
    visited: set[int] = set()
    root: dict[str, Any] | None = None
    while pid > 1 and pid not in visited:
        visited.add(pid)
        row = by_pid.get(pid)
        if row is None:
            break
        if int(row["uid"]) == uid and is_codex_process(row):
            root = row
        parent = by_pid.get(int(row["ppid"]))
        if parent is None or not parent_started_not_after_child(parent, row):
            break
        pid = int(parent["pid"])
    return root_identity(root) if root is not None else None


def root_identity(row: dict[str, Any]) -> tuple[int, str] | None:
    marker = str(row.get("start_marker") or "").strip()
    if not marker:
        return None
    return int(row["pid"]), marker


def normalize_root_identity_set(values: list[tuple[int, str]]) -> set[tuple[int, str]]:
    identities: set[tuple[int, str]] = set()
    for pid, marker in values:
        marker_text = str(marker).strip()
        try:
            pid_int = int(pid)
        except (TypeError, ValueError):
            continue
        if pid_int > 0 and marker_text:
            identities.add((pid_int, marker_text))
    return identities


def root_fd_usage_for_codex_roots(
    root_pids: list[int],
    *,
    runner: Callable[[list[str]], str] | None = None,
    deadline: float | None = None,
) -> dict[str, Any]:
    if not root_pids:
        return {"root_fd_used": 0, "root_fd_state": "no_codex_root"}
    pid_list = ",".join(str(pid) for pid in sorted(set(root_pids)))
    try:
        output = (runner or (lambda command: run_command(command, deadline=deadline)))(["lsof", "-n", "-P", "-p", pid_list])
    except ObservationError:
        return {"root_fd_used": 0, "root_fd_state": "unavailable"}
    counts = {str(pid): 0 for pid in sorted(set(root_pids))}
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 2:
            continue
        pid = parts[1]
        if pid in counts:
            counts[pid] += 1
    missing = [pid for pid, count in counts.items() if count == 0]
    state = "measured" if not missing else "partial"
    return {"root_fd_used": max(counts.values(), default=0), "root_fd_counts": counts, "root_fd_state": state}


def collect_disk(*, state_dir: Path | None = None, deadline: float | None = None) -> dict[str, Any]:
    check_deadline(deadline)
    observed_path = Path(state_dir or default_state_dir()).expanduser()
    stat_path = existing_stat_path(observed_path)
    check_deadline(deadline)
    stats = os.statvfs(str(stat_path))
    check_deadline(deadline)
    return {
        "disk_free_bytes": float(stats.f_bavail * stats.f_frsize),
        "disk_total_bytes": float(stats.f_blocks * stats.f_frsize),
    }


def existing_stat_path(path: Path) -> Path:
    candidate = path
    while not candidate.exists():
        parent = candidate.parent
        if parent == candidate:
            raise ObservationError("measurement_unavailable:disk_path")
        candidate = parent
    return candidate


def remaining_seconds(deadline: float | None) -> float:
    if deadline is None:
        return OBSERVE_TIMEOUT_SECONDS
    return deadline - time.monotonic()


def check_deadline(deadline: float | None) -> None:
    if deadline is not None and remaining_seconds(deadline) <= 0:
        raise ObservationError("operation_timeout")


def remaining_timeout(deadline: float | None) -> float | None:
    if deadline is None:
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ObservationError("measurement_timeout:deadline")
    return max(0.001, remaining)


def run_command(command: list[str], *, deadline: float | None = None) -> str:
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    try:
        completed = subprocess.run(
            command,
            check=False,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=remaining_timeout(deadline),
        )
    except subprocess.TimeoutExpired as exc:
        raise ObservationError(f"measurement_timeout:{command[0]}") from exc
    if completed.returncode != 0:
        raise ObservationError(f"measurement_unavailable:{command[0]}")
    return completed.stdout


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=default_state_dir())
    parser.add_argument("--snapshot-json", type=Path)
    parser.add_argument("--now-epoch", type=float, default=None)
    parser.add_argument("--workload-class", choices=sorted(MIN_COSTS), default="normal")
    parser.add_argument("--calibration-status", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.calibration_status:
        try:
            result = calibration_status(state_dir=args.state_dir)
        except Exception:
            result = {
                "protocol_version": PROTOCOL_VERSION,
                "phase": "UNAVAILABLE",
                "classes": {name: default_calibration_class(name) for name in MIN_COSTS},
                "error": "calibration_state_unavailable",
            }
        json.dump(result, sys.stdout, ensure_ascii=False, sort_keys=True, allow_nan=False)
        sys.stdout.write("\n")
        return 0
    snapshot = None
    if args.snapshot_json:
        try:
            snapshot = json_loads_strict(args.snapshot_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            result = fail_closed_output(str(exc))
            json.dump(result, sys.stdout, ensure_ascii=False, sort_keys=True, allow_nan=False)
            sys.stdout.write("\n")
            return 2
    result = observe(
        snapshot=snapshot,
        state_dir=args.state_dir,
        now_epoch=args.now_epoch,
        workload_class=args.workload_class,
    )
    json.dump(result, sys.stdout, ensure_ascii=False, sort_keys=True, allow_nan=False)
    sys.stdout.write("\n")
    return 0 if result["status"] == "GREEN" else 1 if result["status"] == "YELLOW" else 2


if __name__ == "__main__":
    raise SystemExit(main())
