import concurrent.futures
import fcntl
import json
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import codex_capacity_observer as observer


MIB = 1024 * 1024
GIB = 1024 * MIB


def enable_observer_test_mode(testcase):
    previous = os.environ.get("CODEX_CAPACITY_OBSERVER_TEST_MODE")
    os.environ["CODEX_CAPACITY_OBSERVER_TEST_MODE"] = "1"

    def restore():
        if previous is None:
            os.environ.pop("CODEX_CAPACITY_OBSERVER_TEST_MODE", None)
        else:
            os.environ["CODEX_CAPACITY_OBSERVER_TEST_MODE"] = previous

    testcase.addCleanup(restore)


def clean_snapshot(**overrides):
    snapshot = {
        "total_ram_bytes": 32 * GIB,
        "available_memory_bytes": 16 * GIB,
        "memory_pressure": "normal",
        "swapouts_total_bytes": 0,
        "cpu_idle_percent": 55.0,
        "user_process_limit": 4096,
        "user_process_count": 300,
        "root_fd_soft_limit": 8192,
        "root_fd_used": 900,
        "system_fd_max": 65536,
        "system_fd_used": 6000,
        "disk_free_bytes": 250 * GIB,
        "disk_total_bytes": 1000 * GIB,
        "heavy_lanes_in_use": 0,
        "active_slots": 0,
    }
    snapshot.update(overrides)
    return snapshot


def calibration_snapshot(**overrides):
    snapshot = clean_snapshot(
        codex_root_count=1,
        external_codex_roots=0,
        current_codex_root_pid=700,
        current_codex_root_start_marker="root-start",
        root_fd_used=100,
        current_root_fd_used=100,
        root_fd_state="measured",
        _calibration_status="GREEN",
    )
    snapshot.update(overrides)
    return snapshot


def run_live_calibration_cycle(
    state_dir,
    index,
    *,
    workload_class="normal",
    baseline_slots=0,
    root_marker="root-start",
    baseline_overrides=None,
    peak_overrides=None,
    settle_overrides=None,
):
    base_time = 2000.0 + index * 10.0
    session = f"session-{index}"
    turn = f"turn-{index}"
    request = f"request-{index}"
    agent = f"agent-{index}"
    baseline_kwargs = {"active_slots": baseline_slots, "current_codex_root_start_marker": root_marker}
    baseline_kwargs.update(baseline_overrides or {})
    peak_kwargs = {
        "active_slots": baseline_slots + 1,
        "current_codex_root_start_marker": root_marker,
        "available_memory_bytes": 15 * GIB,
        "user_process_count": 310,
        "root_fd_used": 150,
        "current_root_fd_used": 150,
        "system_fd_used": 6200,
    }
    peak_kwargs.update(peak_overrides or {})
    settle_kwargs = {"active_slots": baseline_slots, "current_codex_root_start_marker": root_marker}
    settle_kwargs.update(settle_overrides or {})
    baseline = calibration_snapshot(**baseline_kwargs)
    peak = calibration_snapshot(**peak_kwargs)
    settle = calibration_snapshot(**settle_kwargs)
    observer.calibration_hook_event(
        "pretool_lease",
        state_dir=state_dir,
        snapshot=baseline,
        now_epoch=base_time,
        workload_class=workload_class,
        session_id=session,
        turn_id=turn,
        request_id=request,
    )
    observer.calibration_hook_event(
        "subagent_start",
        state_dir=state_dir,
        snapshot=peak,
        now_epoch=base_time + 1.1,
        workload_class=workload_class,
        session_id=session,
        turn_id=turn,
        agent_id=agent,
    )
    observer.calibration_hook_event(
        "subagent_stop_before_release",
        state_dir=state_dir,
        snapshot=peak,
        now_epoch=base_time + 2.3,
        workload_class=workload_class,
        session_id=session,
        agent_id=agent,
    )
    return observer.calibration_hook_event(
        "settle_snapshot",
        state_dir=state_dir,
        snapshot=settle,
        now_epoch=base_time + 4.4,
        workload_class=workload_class,
    )


class CapacityObserverTests(unittest.TestCase):
    def test_module_imports_with_calibration_store_defined(self):
        self.assertTrue(hasattr(observer, "CalibrationStore"))

    def test_calibration_status_is_safe_aggregate(self):
        with tempfile.TemporaryDirectory() as tmp:
            status = observer.calibration_status(state_dir=Path(tmp))

            json.dumps(status, allow_nan=False)
            self.assertEqual("IDLE", status["phase"])
            self.assertIn("normal", status["classes"])
            self.assertNotIn("root-start", json.dumps(status))

    def test_corrupted_symlink_hardlink_and_invalid_calibration_state_keep_fixed_six(self):
        cases = []
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corrupted = root / "corrupted"
            corrupted.mkdir()
            (corrupted / "calibration_state.json").write_text("{broken", encoding="utf-8")
            cases.append(corrupted)

            symlink_dir = root / "symlink"
            symlink_dir.mkdir()
            target = root / "outside.json"
            target.write_text("{}", encoding="utf-8")
            os.symlink(target, symlink_dir / "calibration_state.json")
            cases.append(symlink_dir)

            hardlink_dir = root / "hardlink"
            hardlink_dir.mkdir()
            original = root / "original.json"
            original.write_text("{}", encoding="utf-8")
            os.link(original, hardlink_dir / "calibration_state.json")
            cases.append(hardlink_dir)

            invalid = root / "invalid"
            invalid.mkdir()
            (invalid / "calibration_state.json").write_text(
                json.dumps(
                    {
                        "protocol_version": 1,
                        "classes": {
                            "normal": {
                                "accepted_count": 1,
                                "effective_capacity": 8,
                                "proven_capacity": 8,
                                "saturated_clean_cycles": 3,
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            cases.append(invalid)

            invalid_step = root / "invalid-step"
            invalid_step.mkdir()
            (invalid_step / "calibration_state.json").write_text(
                json.dumps(
                    {
                        "protocol_version": 1,
                        "classes": {
                            "normal": {
                                "accepted_count": 30,
                                "effective_capacity": 7,
                                "proven_capacity": 7,
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            cases.append(invalid_step)

            invalid_history = root / "invalid-history"
            invalid_history.mkdir()
            (invalid_history / "calibration_state.json").write_text(
                json.dumps(
                    {
                        "protocol_version": 1,
                        "classes": {
                            "normal": {
                                "accepted_count": 40,
                                "samples": [],
                                "effective_capacity": 8,
                                "proven_capacity": 8,
                                "saturated_clean_cycles": 0,
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            cases.append(invalid_history)

            invalid_cycle = root / "invalid-cycle"
            invalid_cycle.mkdir()
            (invalid_cycle / "calibration_state.json").write_text(
                json.dumps(
                    {
                        "protocol_version": 1,
                        "classes": {
                            "normal": {
                                "accepted_count": 30,
                                "samples": [
                                    {"memory_bytes": 1, "processes": 1, "root_fds": 1, "system_fds": 1, "heavy_lanes": 0}
                                    for _ in range(30)
                                ],
                                "effective_capacity": 6,
                                "proven_capacity": 6,
                                "saturated_clean_cycles": 10,
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            cases.append(invalid_cycle)

            for state_dir in cases:
                with self.subTest(state_dir=state_dir.name):
                    result = observer.observe(snapshot=calibration_snapshot(active_slots=0), state_dir=state_dir, now_epoch=1000.0)

                    self.assertLessEqual(result["effective_capacity"], 6)
                    self.assertLessEqual(result["admission_capacity"], 6)
                    self.assertEqual("calibration_unavailable_fixed6", result["capacity_mode"])

    def test_calibration_lock_contention_keeps_observe_fixed_six_before_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            store = observer.CalibrationStore(state_dir)
            store.load(deadline=time.monotonic() + 0.5)
            original_timeout = observer.OBSERVE_TIMEOUT_SECONDS
            observer.OBSERVE_TIMEOUT_SECONDS = 0.05
            try:
                with (state_dir / "calibration.lock").open("r+", encoding="utf-8") as handle:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    started = time.perf_counter()
                    result = observer.observe(snapshot=calibration_snapshot(active_slots=0), state_dir=state_dir, now_epoch=1000.0)
                    elapsed = time.perf_counter() - started
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            finally:
                observer.OBSERVE_TIMEOUT_SECONDS = original_timeout

            self.assertLess(elapsed, 0.5)
            self.assertEqual(6, result["effective_capacity"])
            self.assertLessEqual(result["admission_capacity"], 6)
            self.assertEqual("calibration_unavailable_fixed6", result["capacity_mode"])

    def test_live_calibration_cycle_accepts_sample_but_keeps_fixed_six_before_thirty(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)

            armed = observer.calibration_hook_event(
                "pretool_lease",
                state_dir=state_dir,
                snapshot=calibration_snapshot(active_slots=0),
                now_epoch=1000.0,
                session_id="session-secret",
                turn_id="turn-secret",
                request_id="request-secret",
            )
            measuring = observer.calibration_hook_event(
                "subagent_start",
                state_dir=state_dir,
                snapshot=calibration_snapshot(active_slots=1, available_memory_bytes=15 * GIB, user_process_count=310, root_fd_used=150, current_root_fd_used=150, system_fd_used=6200),
                now_epoch=1001.1,
                session_id="session-secret",
                turn_id="turn-secret",
                agent_id="agent-secret",
            )
            settling = observer.calibration_hook_event(
                "subagent_stop_before_release",
                state_dir=state_dir,
                snapshot=calibration_snapshot(active_slots=1, available_memory_bytes=15 * GIB, user_process_count=310, root_fd_used=150, current_root_fd_used=150, system_fd_used=6200),
                now_epoch=1002.3,
                session_id="session-secret",
                agent_id="agent-secret",
            )
            after_stop = observer.calibration_hook_event(
                "stop",
                state_dir=state_dir,
                now_epoch=1002.4,
                session_id="session-secret",
                turn_id="turn-secret",
            )
            observer.calibration_hook_event(
                "settle_snapshot",
                state_dir=state_dir,
                snapshot=calibration_snapshot(active_slots=0),
                now_epoch=1004.4,
            )
            result = observer.observe(snapshot=calibration_snapshot(active_slots=0), state_dir=state_dir, now_epoch=1005.0)

            self.assertEqual("ARMED", armed["phase"])
            self.assertEqual("MEASURING", measuring["phase"])
            self.assertEqual("SETTLING", settling["phase"])
            self.assertEqual("SETTLING", after_stop["phase"])
            self.assertEqual(1, result["accepted_calibrations"])
            self.assertEqual("fixed_until_calibrated", result["capacity_mode"])
            self.assertEqual(6, result["effective_capacity"])
            persisted = (state_dir / "calibration_state.json").read_text(encoding="utf-8")
            self.assertNotIn("session-secret", persisted)
            self.assertNotIn("agent-secret", persisted)
            self.assertNotIn("root-start", persisted)

    def test_live_calibration_opens_eight_after_thirty_plus_ten_saturated_cycles_only_for_class(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            for index in range(30):
                status = run_live_calibration_cycle(state_dir, index, baseline_slots=0)
            normal = status["classes"]["normal"]
            self.assertEqual(30, normal["accepted_count"])
            self.assertEqual(6, normal["effective_capacity"])
            self.assertEqual(0, normal["saturated_clean_cycles"])

            for index in range(30, 39):
                status = run_live_calibration_cycle(state_dir, index, baseline_slots=5)
                normal = status["classes"]["normal"]
                self.assertEqual(6, normal["effective_capacity"])
                self.assertEqual(index - 29, normal["saturated_clean_cycles"])

            opened = run_live_calibration_cycle(state_dir, 39, baseline_slots=5)
            normal = opened["classes"]["normal"]

            self.assertEqual(40, normal["accepted_count"])
            self.assertEqual(8, normal["effective_capacity"])
            self.assertEqual(8, normal["proven_capacity"])
            self.assertEqual(0, normal["saturated_clean_cycles"])
            self.assertEqual(6, opened["classes"]["browser"]["effective_capacity"])
            self.assertEqual(6, opened["classes"]["light"]["effective_capacity"])

    def test_live_calibration_non_saturated_cycle_resets_saturated_sequence(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            for index in range(30):
                run_live_calibration_cycle(state_dir, index, baseline_slots=0)
            for index in range(30, 35):
                run_live_calibration_cycle(state_dir, index, baseline_slots=5)

            reset = run_live_calibration_cycle(state_dir, 35, baseline_slots=0)

            self.assertEqual(6, reset["classes"]["normal"]["effective_capacity"])
            self.assertEqual(0, reset["classes"]["normal"]["saturated_clean_cycles"])

    def test_calibration_cancel_events_reject_active_bracket(self):
        for event in ("stop", "session_end", "spawn_failed"):
            with tempfile.TemporaryDirectory() as tmp:
                state_dir = Path(tmp)
                observer.calibration_hook_event(
                    "pretool_lease",
                    state_dir=state_dir,
                    snapshot=calibration_snapshot(active_slots=0),
                    now_epoch=1000.0,
                    session_id="session-secret",
                    turn_id="turn-secret",
                    request_id="request-secret",
                )
                status = observer.calibration_hook_event(
                    event,
                    state_dir=state_dir,
                    now_epoch=1001.0,
                    session_id="session-secret",
                    turn_id="turn-secret",
                    request_id="request-secret",
                )

                self.assertEqual("IDLE", status["phase"])
                self.assertEqual(1, status["classes"]["normal"]["rejected_count"])

    def test_calibration_token_mismatch_or_empty_agent_does_not_move_active_bracket(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            observer.calibration_hook_event("pretool_lease", state_dir=state_dir, snapshot=calibration_snapshot(active_slots=0), now_epoch=1000, session_id="s", turn_id="t", request_id="r")

            wrong_session = observer.calibration_hook_event("subagent_start", state_dir=state_dir, snapshot=calibration_snapshot(active_slots=1), now_epoch=1001.1, session_id="other", turn_id="t", agent_id="a")
            missing_agent = observer.calibration_hook_event("subagent_stop_before_release", state_dir=state_dir, snapshot=calibration_snapshot(active_slots=1), now_epoch=1002.3, session_id="s")

            self.assertEqual("ARMED", wrong_session["phase"])
            self.assertEqual("ARMED", missing_agent["phase"])
            self.assertEqual(0, missing_agent["classes"]["normal"]["rejected_count"])

    def test_out_of_order_or_identity_incomplete_events_do_not_rewrite_bracket(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            incomplete = observer.calibration_hook_event(
                "pretool_lease",
                state_dir=state_dir,
                snapshot=calibration_snapshot(active_slots=0),
                now_epoch=999.0,
                session_id="s",
                turn_id="t",
            )
            self.assertEqual("IDLE", incomplete["phase"])

            observer.calibration_hook_event("pretool_lease", state_dir=state_dir, snapshot=calibration_snapshot(active_slots=0), now_epoch=1000.0, session_id="s", turn_id="t", request_id="r")
            early_stop = observer.calibration_hook_event("subagent_stop_before_release", state_dir=state_dir, snapshot=calibration_snapshot(active_slots=1), now_epoch=1000.5, session_id="s", agent_id="a")
            empty_agent = observer.calibration_hook_event("subagent_start", state_dir=state_dir, snapshot=calibration_snapshot(active_slots=1), now_epoch=1000.8, session_id="s", turn_id="t")
            self.assertEqual("ARMED", early_stop["phase"])
            self.assertEqual("ARMED", empty_agent["phase"])

            observer.calibration_hook_event("subagent_start", state_dir=state_dir, snapshot=calibration_snapshot(active_slots=1), now_epoch=1001.1, session_id="s", turn_id="t", agent_id="a")
            duplicate_start = observer.calibration_hook_event("subagent_start", state_dir=state_dir, snapshot=calibration_snapshot(active_slots=1), now_epoch=1001.5, session_id="s", turn_id="t", agent_id="other")
            measuring = observer.CalibrationStore(state_dir).load(deadline=time.monotonic() + 0.5)["active"]
            self.assertEqual("MEASURING", duplicate_start["phase"])
            self.assertEqual(1001.1, measuring["started_at"])

            observer.calibration_hook_event("subagent_stop_before_release", state_dir=state_dir, snapshot=calibration_snapshot(active_slots=1), now_epoch=1002.3, session_id="s", agent_id="a")
            duplicate_stop = observer.calibration_hook_event("subagent_stop_before_release", state_dir=state_dir, snapshot=calibration_snapshot(active_slots=1), now_epoch=1002.5, session_id="s", agent_id="a")
            late_start = observer.calibration_hook_event("subagent_start", state_dir=state_dir, snapshot=calibration_snapshot(active_slots=1), now_epoch=1002.6, session_id="s", turn_id="t", agent_id="a")
            settling = observer.CalibrationStore(state_dir).load(deadline=time.monotonic() + 0.5)["active"]
            self.assertEqual("SETTLING", duplicate_stop["phase"])
            self.assertEqual("SETTLING", late_start["phase"])
            self.assertEqual(1002.3, settling["stopped_at"])

    def test_stop_and_session_end_preserve_only_settling_after_normal_subagent_stop(self):
        for cancel_event in ("stop", "session_end"):
            with self.subTest(cancel_event=cancel_event), tempfile.TemporaryDirectory() as tmp:
                state_dir = Path(tmp)
                observer.calibration_hook_event("pretool_lease", state_dir=state_dir, snapshot=calibration_snapshot(active_slots=0), now_epoch=1000, session_id="s", turn_id="t", request_id="r")
                canceled = observer.calibration_hook_event(cancel_event, state_dir=state_dir, now_epoch=1001, session_id="s", turn_id="t")
                self.assertEqual("IDLE", canceled["phase"])
                self.assertEqual(1, canceled["classes"]["normal"]["rejected_count"])

            with self.subTest(cancel_event=f"settling-{cancel_event}"), tempfile.TemporaryDirectory() as tmp:
                state_dir = Path(tmp)
                observer.calibration_hook_event("pretool_lease", state_dir=state_dir, snapshot=calibration_snapshot(active_slots=0), now_epoch=1000, session_id="s", turn_id="t", request_id="r")
                observer.calibration_hook_event("subagent_start", state_dir=state_dir, snapshot=calibration_snapshot(active_slots=1), now_epoch=1001.1, session_id="s", turn_id="t", agent_id="a")
                observer.calibration_hook_event("subagent_stop_before_release", state_dir=state_dir, snapshot=calibration_snapshot(active_slots=1), now_epoch=1002.3, session_id="s", agent_id="a")
                preserved = observer.calibration_hook_event(cancel_event, state_dir=state_dir, now_epoch=1002.4, session_id="s", turn_id="t")
                self.assertEqual("SETTLING", preserved["phase"])

    def test_live_calibration_rejects_unstable_brackets_with_stable_codes(self):
        cases = [
            ("external_roots_changed", {"peak_overrides": {"external_codex_roots": 1}}),
            ("active_slots_changed", {"peak_overrides": {"active_slots": 3}}),
            ("root_token_changed", {"settle_overrides": {"current_codex_root_start_marker": "other-root"}}),
            ("swap_growth", {"settle_overrides": {"swapouts_total_bytes": 1}}),
            ("settle_memory_drift", {"settle_overrides": {"available_memory_bytes": 15 * GIB - 2 * GIB}}),
            ("settle_process_drift", {"settle_overrides": {"user_process_count": 306}}),
            ("settle_root_fd_drift", {"settle_overrides": {"current_root_fd_used": 109}}),
            ("settle_system_fd_drift", {"settle_overrides": {"system_fd_used": 6200}}),
            ("resource_not_green", {"baseline_overrides": {"_calibration_status": "YELLOW"}}),
            ("resource_not_green", {"peak_overrides": {"_calibration_status": "RED"}}),
            ("resource_not_green", {"settle_overrides": {"_calibration_status": "YELLOW"}}),
        ]
        for expected_code, kwargs in cases:
            with self.subTest(expected_code=expected_code, kwargs=kwargs), tempfile.TemporaryDirectory() as tmp:
                state_dir = Path(tmp)
                status = run_live_calibration_cycle(state_dir, 1, **kwargs)

                self.assertEqual(0, status["classes"]["normal"]["accepted_count"])
                self.assertEqual(1, status["classes"]["normal"]["rejected_count"])
                self.assertEqual(expected_code, status["classes"]["normal"]["last_rejection_code"])

    def test_live_calibration_rejects_short_task_and_sleep_gap_separately(self):
        with tempfile.TemporaryDirectory() as short_tmp:
            state_dir = Path(short_tmp)
            observer.calibration_hook_event("pretool_lease", state_dir=state_dir, snapshot=calibration_snapshot(active_slots=0), now_epoch=1000, session_id="s", turn_id="t", request_id="r")
            observer.calibration_hook_event("subagent_start", state_dir=state_dir, snapshot=calibration_snapshot(active_slots=1), now_epoch=1000.1, session_id="s", turn_id="t", agent_id="a")
            observer.calibration_hook_event("subagent_stop_before_release", state_dir=state_dir, snapshot=calibration_snapshot(active_slots=1), now_epoch=1000.2, session_id="s", agent_id="a")
            status = observer.calibration_hook_event("settle_snapshot", state_dir=state_dir, snapshot=calibration_snapshot(active_slots=0), now_epoch=1003.0)
            self.assertEqual("task_too_short", status["classes"]["normal"]["last_rejection_code"])

        with tempfile.TemporaryDirectory() as gap_tmp:
            state_dir = Path(gap_tmp)
            observer.calibration_hook_event("pretool_lease", state_dir=state_dir, snapshot=calibration_snapshot(active_slots=0), now_epoch=1000, session_id="s", turn_id="t", request_id="r")
            observer.calibration_hook_event("subagent_start", state_dir=state_dir, snapshot=calibration_snapshot(active_slots=1), now_epoch=1001.1, session_id="s", turn_id="t", agent_id="a")
            observer.calibration_hook_event("subagent_stop_before_release", state_dir=state_dir, snapshot=calibration_snapshot(active_slots=1), now_epoch=1002.3, session_id="s", agent_id="a")
            status = observer.calibration_hook_event("settle_snapshot", state_dir=state_dir, snapshot=calibration_snapshot(active_slots=0), now_epoch=1130.0)
            self.assertEqual("sleep_gap", status["classes"]["normal"]["last_rejection_code"])

    def test_live_calibration_expired_is_distinct_from_sleep_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            observer.calibration_hook_event("pretool_lease", state_dir=state_dir, snapshot=calibration_snapshot(active_slots=0), now_epoch=1000, session_id="s", turn_id="t", request_id="r")
            status = observer.calibration_hook_event("pretool_lease", state_dir=state_dir, snapshot=calibration_snapshot(active_slots=0), now_epoch=2000, session_id="other", turn_id="other", request_id="other")

            self.assertEqual("expired", status["classes"]["normal"]["last_rejection_code"])

    def test_synthetic_workload_delta_without_test_mode_does_not_calibrate(self):
        os.environ.pop("CODEX_CAPACITY_OBSERVER_TEST_MODE", None)
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            for index in range(45):
                result = observer.observe(
                    snapshot=clean_snapshot(workload_delta={"memory_bytes": 512 * MIB, "processes": 9, "root_fds": 40, "system_fds": 220}),
                    state_dir=state_dir,
                    now_epoch=1000.0 + index,
                )

            self.assertEqual(0, result["accepted_calibrations"])
            self.assertEqual("fixed_until_calibrated", result["capacity_mode"])
            self.assertEqual(6, result["effective_capacity"])

    def test_production_calibration_requires_confirmed_status_and_current_root_fd(self):
        os.environ.pop("CODEX_CAPACITY_CALIBRATION_TEST_MODE", None)
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            no_status = calibration_snapshot(active_slots=0)
            no_status.pop("_calibration_status")
            no_fd = calibration_snapshot(active_slots=1)
            no_fd.pop("current_root_fd_used")

            observer.calibration_hook_event("pretool_lease", state_dir=state_dir, snapshot=no_status, now_epoch=1000, session_id="s", turn_id="t", request_id="r")
            observer.calibration_hook_event("subagent_start", state_dir=state_dir, snapshot=no_fd, now_epoch=1001.1, session_id="s", turn_id="t", agent_id="a")
            status = observer.calibration_hook_event("subagent_stop_before_release", state_dir=state_dir, snapshot=no_fd, now_epoch=1002.3, session_id="s", agent_id="a")

            self.assertEqual("ARMED", status["phase"])

        previous = os.environ.get("CODEX_CAPACITY_CALIBRATION_TEST_MODE")
        os.environ["CODEX_CAPACITY_CALIBRATION_TEST_MODE"] = "1"
        self.addCleanup(lambda: os.environ.pop("CODEX_CAPACITY_CALIBRATION_TEST_MODE", None) if previous is None else os.environ.__setitem__("CODEX_CAPACITY_CALIBRATION_TEST_MODE", previous))
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            no_fd = calibration_snapshot(active_slots=1)
            no_fd.pop("current_root_fd_used")
            observer.calibration_hook_event("pretool_lease", state_dir=state_dir, snapshot=calibration_snapshot(active_slots=0), now_epoch=1000, session_id="s", turn_id="t", request_id="r")
            moved = observer.calibration_hook_event("subagent_start", state_dir=state_dir, snapshot=no_fd, now_epoch=1001.1, session_id="s", turn_id="t", agent_id="a")
            self.assertEqual("MEASURING", moved["phase"])

    def test_light_workload_normalizes_to_normal_without_calibration_test_mode(self):
        os.environ.pop("CODEX_CAPACITY_CALIBRATION_TEST_MODE", None)
        with tempfile.TemporaryDirectory() as tmp:
            status = observer.calibration_hook_event(
                "pretool_lease",
                state_dir=Path(tmp),
                snapshot=calibration_snapshot(active_slots=0),
                now_epoch=1000,
                workload_class="light",
                session_id="s",
                turn_id="t",
                request_id="r",
            )

            self.assertEqual("normal", status["workload_class"])

    def test_missing_mandatory_measurement_fails_closed_with_machine_json_and_zero_admission(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = clean_snapshot()
            del snapshot["cpu_idle_percent"]

            result = observer.observe(snapshot=snapshot, state_dir=Path(tmp), now_epoch=1000.0)

            self.assertEqual(result["status"], "RED")
            self.assertIn("measurement_unavailable:cpu_idle_percent", result["reasons"])
            json.dumps(result, sort_keys=True)
            self.assertNotIn("processes", result)
            self.assertEqual(result["effective_capacity"], 6)
            self.assertEqual(result["admission_capacity"], 0)
            self.assertEqual(result["max_wave_size"], 0)

    def test_observe_library_fails_closed_for_normalize_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = observer.observe(snapshot=[], state_dir=Path(tmp), now_epoch=1000.0)  # type: ignore[arg-type]

            self.assertEqual(result["status"], "RED")
            self.assertEqual(result["admission_capacity"], 0)
            self.assertIn("snapshot_not_object", result["reasons"])

    def test_normalize_rejects_unknown_pressure_nan_inf_and_negative_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            unknown = observer.observe(snapshot=clean_snapshot(memory_pressure="unknown"), state_dir=Path(tmp) / "a", now_epoch=1000.0)
            nan = observer.observe(snapshot=clean_snapshot(cpu_idle_percent=float("nan")), state_dir=Path(tmp) / "b", now_epoch=1000.0)
            inf = observer.observe(snapshot=clean_snapshot(root_fd_used=float("inf")), state_dir=Path(tmp) / "c", now_epoch=1000.0)
            negative = observer.observe(snapshot=clean_snapshot(system_fd_used=-1), state_dir=Path(tmp) / "d", now_epoch=1000.0)

            for result in (unknown, nan, inf, negative):
                self.assertEqual(result["status"], "RED")
                self.assertEqual(result["admission_capacity"], 0)
                json.dumps(result, allow_nan=False)
            self.assertIn("invalid_memory_pressure", unknown["reasons"])
            self.assertIn("invalid_measurement:cpu_idle_percent", nan["reasons"])
            self.assertIn("invalid_measurement:root_fd_used", inf["reasons"])
            self.assertIn("invalid_measurement:system_fd_used", negative["reasons"])

    def test_saved_state_rejects_nan_inf_negative_type_and_unknown_structure(self):
        cases = [
            ("nan", '{"protocol_version":1,"last_status":"GREEN","cost_estimates":{"normal":{"memory_bytes":NaN}}}', "invalid_json_constant:NaN"),
            ("inf", '{"protocol_version":1,"last_status":"GREEN","cost_estimates":{"normal":{"memory_bytes":Infinity}}}', "invalid_json_constant:Infinity"),
            (
                "negative",
                json.dumps({"protocol_version": 1, "last_status": "GREEN", "cost_estimates": {"normal": {"memory_bytes": -1}}}),
                "state_negative_number:cost_estimates.normal.memory_bytes",
            ),
            (
                "wrong_type",
                json.dumps({"protocol_version": 1, "last_status": "GREEN", "successful_observations": "1"}),
                "state_invalid_type:successful_observations",
            ),
            (
                "unknown",
                json.dumps({"protocol_version": 1, "last_status": "GREEN", "unexpected": {"nested": True}}),
                "state_unknown_keys:unexpected",
            ),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            for name, payload, expected_reason in cases:
                state_dir = Path(tmp) / name
                state_dir.mkdir()
                state_path = state_dir / "observer_state.json"
                state_path.write_text(payload, encoding="utf-8")

                result = observer.observe(snapshot=clean_snapshot(), state_dir=state_dir, now_epoch=1000.0)

                self.assertEqual(result["status"], "RED")
                self.assertEqual(result["admission_capacity"], 0)
                self.assertEqual(result["max_wave_size"], 0)
                self.assertTrue(any(expected_reason in reason for reason in result["reasons"]), result["reasons"])
                self.assertEqual(state_path.read_text(encoding="utf-8"), payload)
                json.dumps(result, allow_nan=False)

    def test_corrupted_state_fails_closed_without_overwriting_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            state_dir.mkdir()
            state_path = state_dir / "observer_state.json"
            state_path.write_text("{broken", encoding="utf-8")

            result = observer.observe(snapshot=clean_snapshot(), state_dir=state_dir, now_epoch=1000.0)

            self.assertEqual(result["status"], "RED")
            self.assertEqual(result["effective_capacity"], 6)
            self.assertTrue(any(reason.startswith("database_error:") for reason in result["reasons"]))
            self.assertEqual(state_path.read_text(encoding="utf-8"), "{broken")

    def test_store_rejects_symlink_hardlink_unexpected_type_and_parent_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            symlink_dir = Path(tmp) / "symlink"
            symlink_dir.mkdir()
            target = Path(tmp) / "outside.json"
            target.write_text("{}", encoding="utf-8")
            os.symlink(target, symlink_dir / "observer_state.json")

            symlink_result = observer.observe(snapshot=clean_snapshot(), state_dir=symlink_dir, now_epoch=1000.0)

            self.assertEqual(symlink_result["status"], "RED")
            self.assertIn("state_file_symlink", symlink_result["reasons"])
            self.assertEqual(target.read_text(encoding="utf-8"), "{}")

            hardlink_dir = Path(tmp) / "hardlink"
            hardlink_dir.mkdir()
            original = Path(tmp) / "original.json"
            original.write_text("{}", encoding="utf-8")
            os.link(original, hardlink_dir / "observer_state.json")

            hardlink_result = observer.observe(snapshot=clean_snapshot(), state_dir=hardlink_dir, now_epoch=1000.0)

            self.assertEqual(hardlink_result["status"], "RED")
            self.assertIn("state_file_hardlink", hardlink_result["reasons"])

            type_dir = Path(tmp) / "type"
            type_dir.mkdir()
            (type_dir / "observer_state.json").mkdir()
            type_result = observer.observe(snapshot=clean_snapshot(), state_dir=type_dir, now_epoch=1000.0)

            self.assertEqual(type_result["status"], "RED")
            self.assertIn("state_file_unexpected_type", type_result["reasons"])

            real_parent = Path(tmp) / "real-parent"
            real_parent.mkdir()
            linked_parent = Path(tmp) / "linked-parent"
            os.symlink(real_parent, linked_parent)
            parent_result = observer.observe(snapshot=clean_snapshot(), state_dir=linked_parent / "capacity", now_epoch=1000.0)

            self.assertEqual(parent_result["status"], "RED")
            self.assertIn("state_parent_symlink", parent_result["reasons"])
            self.assertFalse((real_parent / "capacity" / "observer_state.json").exists())

    def test_held_store_lock_returns_red_before_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            store = observer.ObserverStore(state_dir)
            store.save(observer.default_state())

            with (state_dir / "observer.lock").open("r+", encoding="utf-8") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                start = time.perf_counter()
                result = observer.observe(snapshot=clean_snapshot(), state_dir=state_dir, now_epoch=1000.0)
                elapsed = time.perf_counter() - start
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

            self.assertEqual(result["status"], "RED")
            self.assertEqual(result["admission_capacity"], 0)
            self.assertLessEqual(elapsed, 0.55)
            self.assertTrue(any("timeout" in reason for reason in result["reasons"]))

    def test_parallel_updates_are_serialized_by_store_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"

            def run_one(index):
                return observer.observe(snapshot=clean_snapshot(), state_dir=state_dir, now_epoch=1000.0 + index)

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(run_one, range(20)))

            persisted = json.loads((state_dir / "observer_state.json").read_text(encoding="utf-8"))
            self.assertTrue(all(result["status"] == "GREEN" for result in results))
            self.assertEqual(persisted["successful_observations"], 20)
            self.assertFalse(list(state_dir.glob(".observer_state.*.tmp")))

    def test_green_yellow_red_and_admission_protocol(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)

            green = observer.observe(snapshot=clean_snapshot(), state_dir=state_dir, now_epoch=1000.0)
            yellow = observer.observe(
                snapshot=clean_snapshot(memory_pressure="warn"),
                state_dir=state_dir,
                now_epoch=1010.0,
            )
            red = observer.observe(
                snapshot=clean_snapshot(memory_pressure="critical"),
                state_dir=state_dir,
                now_epoch=1020.0,
            )

            self.assertEqual(green["status"], "GREEN")
            self.assertEqual(green["admission_capacity"], green["effective_capacity"])
            self.assertEqual(green["max_wave_size"], green["effective_capacity"])
            self.assertEqual(yellow["status"], "YELLOW")
            self.assertIn("memory_pressure_warning", yellow["reasons"])
            self.assertLessEqual(yellow["admission_capacity"], 6)
            self.assertEqual(yellow["max_wave_size"], 2)
            self.assertEqual(red["status"], "RED")
            self.assertIn("memory_pressure_critical", red["reasons"])
            self.assertEqual(red["admission_capacity"], 0)
            self.assertEqual(red["max_wave_size"], 0)

    def test_memory_pressure_q_free_percentage_boundaries(self):
        self.assertEqual(
            observer.parse_memory_pressure_free_percent("System-wide memory free percentage: 14%\n"),
            14.0,
        )
        self.assertEqual(observer.pressure_from_free_percent(16.0), "normal")
        self.assertEqual(observer.pressure_from_free_percent(14.9), "warn")
        self.assertEqual(observer.pressure_from_free_percent(9.9), "critical")

    def test_single_ps_snapshot_finds_codex_roots_and_uses_one_lsof_call(self):
        ps_text = "\n".join(
            [
                "100 1 501 user 2.5 /opt/homebrew/bin/codex run",
                "101 100 501 user 1.0 node child",
                "200 1 501 user 3.0 /usr/bin/python other",
                "300 100 501 user 4.0 /opt/homebrew/bin/codex nested",
                "400 1 501 user 1.0 codex exec",
            ]
        )
        rows = observer.parse_ps_snapshot(ps_text)
        roots = observer.codex_root_pids(rows, 501)
        calls = []

        def runner(command):
            calls.append(command)
            return "COMMAND PID USER FD\na 100 user txt\na 100 user 1u\nb 400 user txt\nb 400 user 1u\nb 400 user 2u\n"

        usage = observer.root_fd_usage_for_codex_roots(roots, runner=runner)

        self.assertEqual(roots, [100, 400])
        self.assertEqual(usage["root_fd_used"], 3)
        self.assertEqual(calls, [["lsof", "-n", "-P", "-p", "100,400"]])

    def test_ps_snapshot_excludes_macos_codex_helpers_with_spaces(self):
        ps_text = "\n".join(
            [
                "10 1 501 user 0.1 /Applications/ChatGPT.app/Contents/Frameworks/Codex Framework.framework/Versions/A/Codex (Service)",
                "11 1 501 user 0.1 /Applications/Codex.app/Contents/Frameworks/Codex Framework.framework/Versions/A/Codex (Renderer)",
                "12 1 501 user 0.1 /Applications/ChatGPT.app/Contents/Frameworks/Codex Framework.framework/Helpers/crashpad_handler",
                "13 1 501 user 0.1 /Applications/ChatGPT.app/Contents/Helpers/Computer Use Helper",
                "14 1 501 user 0.1 /opt/homebrew/bin/codex run",
            ]
        )

        roots = observer.codex_root_pids(observer.parse_ps_snapshot(ps_text), 501)

        self.assertEqual(roots, [14])

    def test_single_snapshot_with_macos_helper_path_is_not_split_as_cli_root(self):
        ps_text = "\n".join(
            [
                "30 1 501 user 0.1 /Applications/ChatGPT.app/Contents/Frameworks/Codex Framework.framework/Versions/A/Codex (Service)",
                "31 1 501 user 0.1 /opt/homebrew/bin/codex run",
            ]
        )

        roots = observer.codex_root_pids(observer.parse_ps_snapshot(ps_text), 501)

        self.assertEqual(roots, [31])

    def test_command_mentions_codex_binary_without_codex_comm_is_not_root(self):
        ps_text = "\n".join(
            [
                "20 1 501 user 0.1 /usr/bin/python install.py --codex-binary /opt/homebrew/bin/codex",
                "21 1 501 user 0.1 /opt/homebrew/bin/codex run",
            ]
        )

        roots = observer.codex_root_pids(observer.parse_ps_snapshot(ps_text), 501)

        self.assertEqual(roots, [21])

    def test_codex_app_server_commands_are_not_cli_roots(self):
        ps_text = "\n".join(
            [
                "20 1 501 user Mon Aug  3 10:00:00 2026 0.1 codex app-server",
                "21 1 501 user Mon Aug  3 10:00:00 2026 0.1 codex-app-server",
                "22 1 501 user Mon Aug  3 10:00:00 2026 0.1 /opt/homebrew/bin/codex app-server",
                "23 1 501 user Mon Aug  3 10:00:00 2026 0.1 codex_app_server",
                "24 1 501 user Mon Aug  3 10:00:00 2026 0.1 /opt/homebrew/bin/codex run",
                "25 1 501 user Mon Aug  3 10:00:00 2026 0.1 /opt/homebrew/bin/codex --profile local app-server",
                "26 1 501 user Mon Aug  3 10:00:00 2026 0.1 /opt/homebrew/bin/codex --profile app-server run",
                "27 1 501 user Mon Aug  3 10:00:00 2026 0.1 /opt/homebrew/bin/codex 'inspect app-server behavior'",
                "28 1 501 user Mon Aug  3 10:00:00 2026 0.1 /opt/homebrew/bin/codex -- app-server",
            ]
        )

        roots = observer.codex_root_pids(observer.parse_ps_snapshot(ps_text), 501)

        self.assertEqual(roots, [24, 26, 27, 28])

    def test_newer_reused_parent_pid_does_not_hide_codex_root(self):
        rows = observer.parse_ps_snapshot(
            "\n".join(
                [
                    "100 1 501 user Mon Aug  3 10:05:00 2026 2.5 /opt/homebrew/bin/codex run",
                    "101 100 501 user Mon Aug  3 10:00:00 2026 1.0 /opt/homebrew/bin/codex exec",
                ]
            )
        )

        roots = observer.codex_root_pids(rows, 501)
        occupancy = observer.codex_root_occupancy(rows, 501, managed_root_identities=[], caller_pid=101)

        self.assertEqual([100, 101], roots)
        self.assertEqual(2.0, occupancy["codex_root_count"])
        self.assertEqual(1.0, occupancy["external_codex_roots"])
        self.assertEqual((101, rows[1]["start_marker"]), occupancy["current_codex_root_identity"])

    def test_newer_reused_parent_pid_is_not_current_ancestor(self):
        rows = observer.parse_ps_snapshot(
            "\n".join(
                [
                    "100 1 501 user Mon Aug  3 10:05:00 2026 2.5 /opt/homebrew/bin/codex run",
                    "101 100 501 user Mon Aug  3 10:00:00 2026 1.0 /usr/bin/python hook.py",
                ]
            )
        )

        occupancy = observer.codex_root_occupancy(rows, 501, managed_root_identities=[], caller_pid=101)

        self.assertEqual(1.0, occupancy["codex_root_count"])
        self.assertEqual(1.0, occupancy["external_codex_roots"])
        self.assertIsNone(occupancy["current_codex_root_identity"])

    def test_duplicate_ps_pid_fails_closed(self):
        ps_text = "\n".join(
            [
                "100 1 501 user Mon Aug  3 10:00:00 2026 2.5 /opt/homebrew/bin/codex run",
                "100 1 501 user Mon Aug  3 10:01:00 2026 2.5 /opt/homebrew/bin/codex run",
            ]
        )

        with self.assertRaisesRegex(observer.ObservationError, "duplicate_ps_pid:100"):
            observer.parse_ps_snapshot(ps_text)

    def test_partial_or_unavailable_root_lsof_is_red_with_zero_admission(self):
        partial = clean_snapshot(root_fd_state="partial")

        result = observer.observe(snapshot=partial, state_dir=Path(tempfile.mkdtemp()), now_epoch=1000.0)

        self.assertEqual(result["status"], "RED")
        self.assertIn("root_fd_measurement_unavailable", result["reasons"])
        self.assertEqual(result["admission_capacity"], 0)

        usage = observer.root_fd_usage_for_codex_roots(
            [100, 200],
            runner=lambda command: "COMMAND PID USER FD\na 100 user txt\n",
        )
        self.assertEqual(usage["root_fd_state"], "partial")

        unavailable = observer.root_fd_usage_for_codex_roots(
            [100, 200],
            runner=lambda command: (_ for _ in ()).throw(observer.ObservationError("boom")),
        )
        self.assertEqual(unavailable["root_fd_state"], "unavailable")

    def test_collect_process_snapshot_uses_one_ps_runner_call(self):
        calls = []
        original = observer.run_command

        def fake_run(command, *, deadline=None):
            calls.append(command)
            if command[0] == "ps":
                return "100 1 501 user 2.5 /opt/homebrew/bin/codex run\n"
            if command[0] == "lsof":
                return "COMMAND PID USER FD\na 100 user txt\n"
            raise AssertionError(command)

        try:
            observer.run_command = fake_run
            snapshot = observer.collect_process_snapshot(deadline=time.monotonic() + 0.5)
        finally:
            observer.run_command = original

        ps_calls = [call for call in calls if call[0] == "ps"]
        self.assertEqual(ps_calls, [["ps", "-axo", "pid=,ppid=,uid=,user=,lstart=,%cpu=,command="]])
        self.assertEqual(snapshot["codex_root_count"], 1.0)

    def test_managed_root_registry_and_current_root_define_external_roots_from_one_ps_snapshot(self):
        rows = observer.parse_ps_snapshot(
            "\n".join(
                [
                    "100 1 501 user Mon Aug  3 10:00:00 2026 2.5 /opt/homebrew/bin/codex run",
                    "101 100 501 user Mon Aug  3 10:00:01 2026 1.0 /usr/bin/python hook.py",
                    "200 1 501 user Mon Aug  3 10:00:00 2026 2.5 /opt/homebrew/bin/codex run",
                    "300 1 501 user Mon Aug  3 10:00:00 2026 2.5 /opt/homebrew/bin/codex run",
                ]
            )
        )
        managed = [(200, rows[2]["start_marker"]), (300, "different-start-marker")]

        occupancy = observer.codex_root_occupancy(rows, 501, managed_root_identities=managed, caller_pid=101)

        self.assertEqual(3.0, occupancy["codex_root_count"])
        self.assertEqual(1.0, occupancy["external_codex_roots"])

    def test_current_root_identity_uses_topmost_codex_ancestor(self):
        rows = observer.parse_ps_snapshot(
            "\n".join(
                [
                    "100 1 501 user Mon Aug  3 10:00:00 2026 2.5 /opt/homebrew/bin/codex run",
                    "150 100 501 user Mon Aug  3 10:00:01 2026 2.5 /opt/homebrew/bin/codex exec",
                    "151 150 501 user Mon Aug  3 10:00:02 2026 1.0 /usr/bin/python hook.py",
                ]
            )
        )

        occupancy = observer.codex_root_occupancy(rows, 501, managed_root_identities=[], caller_pid=151)

        self.assertEqual(1.0, occupancy["codex_root_count"])
        self.assertEqual(0.0, occupancy["external_codex_roots"])
        self.assertEqual((100, rows[0]["start_marker"]), occupancy["current_codex_root_identity"])

    def test_collect_process_snapshot_uses_existing_ps_for_managed_roots_without_second_ps_call(self):
        calls = []
        original = observer.run_command
        ps_text = "\n".join(
            [
                "100 1 501 user Mon Aug  3 10:00:00 2026 2.5 /opt/homebrew/bin/codex run",
                "101 100 501 user Mon Aug  3 10:00:01 2026 1.0 /usr/bin/python hook.py",
                "200 1 501 user Mon Aug  3 10:00:00 2026 2.5 /opt/homebrew/bin/codex run",
            ]
        )
        parsed = observer.parse_ps_snapshot(ps_text)

        def fake_run(command, *, deadline=None):
            calls.append(command)
            if command[0] == "ps":
                return ps_text
            if command[0] == "lsof":
                return "COMMAND PID USER FD\na 100 user txt\nb 200 user txt\n"
            raise AssertionError(command)

        try:
            observer.run_command = fake_run
            snapshot = observer.collect_process_snapshot(
                managed_root_identities=[(200, parsed[2]["start_marker"])],
                caller_pid=101,
                deadline=time.monotonic() + 0.5,
            )
        finally:
            observer.run_command = original

        ps_calls = [call for call in calls if call[0] == "ps"]
        self.assertEqual(ps_calls, [["ps", "-axo", "pid=,ppid=,uid=,user=,lstart=,%cpu=,command="]])
        self.assertEqual(2.0, snapshot["codex_root_count"])
        self.assertEqual(0.0, snapshot["external_codex_roots"])
        self.assertEqual((100, parsed[0]["start_marker"]), snapshot["current_codex_root_identity"])
        self.assertEqual([(100, parsed[0]["start_marker"]), (200, parsed[2]["start_marker"])], snapshot["managed_codex_root_identities"])
        self.assertIsInstance(snapshot["codex_process_snapshot_started_at"], float)

    def test_registered_identity_is_live_even_when_command_is_not_codex(self):
        calls = []
        original = observer.run_command
        ps_text = "\n".join(
            [
                "100 1 501 user Mon Aug  3 10:00:00 2026 2.5 /opt/homebrew/bin/codex run",
                "101 100 501 user Mon Aug  3 10:00:01 2026 1.0 /usr/bin/python hook.py",
                "200 1 501 user Mon Aug  3 10:00:02 2026 2.5 /usr/bin/python after-exec.py",
            ]
        )
        parsed = observer.parse_ps_snapshot(ps_text)

        def fake_run(command, *, deadline=None):
            calls.append(command)
            if command[0] == "ps":
                return ps_text
            if command[0] == "lsof":
                return "COMMAND PID USER FD\na 100 user txt\n"
            raise AssertionError(command)

        try:
            observer.run_command = fake_run
            snapshot = observer.collect_process_snapshot(
                managed_root_identities=[(200, parsed[2]["start_marker"])],
                caller_pid=101,
                deadline=time.monotonic() + 0.5,
            )
        finally:
            observer.run_command = original

        ps_calls = [call for call in calls if call[0] == "ps"]
        self.assertEqual(ps_calls, [["ps", "-axo", "pid=,ppid=,uid=,user=,lstart=,%cpu=,command="]])
        self.assertEqual(1.0, snapshot["codex_root_count"])
        self.assertEqual(0.0, snapshot["external_codex_roots"])
        self.assertEqual((100, parsed[0]["start_marker"]), snapshot["current_codex_root_identity"])
        self.assertEqual([(100, parsed[0]["start_marker"]), (200, parsed[2]["start_marker"])], snapshot["managed_codex_root_identities"])

    def test_observe_does_not_persist_private_root_identity_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = clean_snapshot(
                current_codex_root_identity=(700, "root-secret"),
                managed_codex_root_identities=[(700, "root-secret")],
                codex_process_snapshot_started_at=1000.0,
            )

            result = observer.observe(snapshot=snapshot, state_dir=Path(tmp), now_epoch=1000.0)

            serialized = json.dumps(result, sort_keys=True)
            self.assertNotIn("root-secret", serialized)
            persisted = (Path(tmp) / "observer_state.json").read_text(encoding="utf-8")
            self.assertNotIn("root-secret", persisted)
            self.assertNotIn("managed_codex_root_identities", persisted)
            self.assertNotIn("codex_process_snapshot_started_at", persisted)

    def test_observe_passes_state_dir_to_disk_measurement(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "custom-state"
            seen = []
            original = observer.collect_snapshot

            def fake_collect_snapshot(*, state_dir=None, deadline=None):
                seen.append((state_dir, deadline))
                raise observer.ObservationError("stop_after_path_capture")

            try:
                observer.collect_snapshot = fake_collect_snapshot
                result = observer.observe(state_dir=state_dir, now_epoch=1000.0)
            finally:
                observer.collect_snapshot = original

            self.assertEqual(result["status"], "RED")
            self.assertEqual(seen[0][0], state_dir)
            self.assertIsInstance(seen[0][1], float)
            self.assertIn("stop_after_path_capture", result["reasons"])

    def test_collect_disk_uses_observed_path_and_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            state_dir.mkdir()
            calls = []
            original_statvfs = observer.os.statvfs

            class StatVfs:
                f_bavail = 7
                f_frsize = 4096
                f_blocks = 11

            def fake_statvfs(path):
                calls.append(path)
                return StatVfs()

            try:
                observer.os.statvfs = fake_statvfs
                result = observer.collect_disk(state_dir=state_dir, deadline=time.monotonic() + 0.5)
                with self.assertRaises(observer.ObservationError) as caught:
                    observer.collect_disk(state_dir=state_dir, deadline=time.monotonic() - 0.001)
            finally:
                observer.os.statvfs = original_statvfs

            self.assertEqual(calls, [str(state_dir)])
            self.assertEqual(result["disk_free_bytes"], float(7 * 4096))
            self.assertEqual(result["disk_total_bytes"], float(11 * 4096))
            self.assertIn("operation_timeout", str(caught.exception))

    def test_measurement_timeout_during_collection_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = observer.collect_snapshot

            def timeout_snapshot(*, state_dir=None, deadline=None):
                raise observer.ObservationError("operation_timeout")

            try:
                observer.collect_snapshot = timeout_snapshot
                result = observer.observe(state_dir=Path(tmp), now_epoch=1000.0)
            finally:
                observer.collect_snapshot = original

            self.assertEqual(result["status"], "RED")
            self.assertEqual(result["admission_capacity"], 0)
            self.assertIn("operation_timeout", result["reasons"])

    def test_run_command_respects_absolute_timeout(self):
        start = time.perf_counter()
        with self.assertRaises(observer.ObservationError) as caught:
            observer.run_command(
                [sys.executable, "-c", "import time; time.sleep(1)"],
                deadline=time.monotonic() + 0.05,
            )
        elapsed = time.perf_counter() - start

        self.assertLess(elapsed, 0.5)
        self.assertIn("measurement_timeout", str(caught.exception))

    def test_run_command_forces_c_locale_for_system_output(self):
        calls = []
        original = observer.subprocess.run

        class Completed:
            returncode = 0
            stdout = "ok"
            stderr = ""

        def fake_run(command, **kwargs):
            calls.append((command, kwargs))
            return Completed()

        try:
            observer.subprocess.run = fake_run
            result = observer.run_command(["ps", "-axo", "pid="], deadline=time.monotonic() + 0.5)
        finally:
            observer.subprocess.run = original

        self.assertEqual(result, "ok")
        self.assertEqual(calls[0][1]["env"]["LC_ALL"], "C")
        self.assertEqual(calls[0][1]["env"]["LANG"], "C")

    def test_two_consecutive_critical_swapout_windows_are_red(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)

            observer.observe(snapshot=clean_snapshot(swapouts_total_bytes=0), state_dir=state_dir, now_epoch=1000.0)
            warning = observer.observe(
                snapshot=clean_snapshot(swapouts_total_bytes=300 * MIB),
                state_dir=state_dir,
                now_epoch=1060.0,
            )
            critical = observer.observe(
                snapshot=clean_snapshot(swapouts_total_bytes=600 * MIB),
                state_dir=state_dir,
                now_epoch=1120.0,
            )

            self.assertEqual(warning["status"], "YELLOW")
            self.assertIn("swapout_growth_warning", warning["reasons"])
            self.assertEqual(critical["status"], "RED")
            self.assertIn("swapout_growth_critical", critical["reasons"])

    def test_yellow_requires_sixty_seconds_of_normal_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)

            first = observer.observe(
                snapshot=clean_snapshot(available_memory_bytes=4 * GIB),
                state_dir=state_dir,
                now_epoch=1000.0,
            )
            observer.observe(snapshot=clean_snapshot(), state_dir=state_dir, now_epoch=1010.0)
            early = observer.observe(snapshot=clean_snapshot(), state_dir=state_dir, now_epoch=1069.0)
            recovered = observer.observe(snapshot=clean_snapshot(), state_dir=state_dir, now_epoch=1070.0)

            self.assertEqual(first["status"], "YELLOW")
            self.assertEqual(early["status"], "YELLOW")
            self.assertIn("hysteresis_yellow", early["reasons"])
            self.assertEqual(recovered["status"], "GREEN")

    def test_red_requires_three_normal_snapshots_at_ten_second_intervals(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)

            red = observer.observe(snapshot=clean_snapshot(memory_pressure="critical"), state_dir=state_dir, now_epoch=1000.0)
            first_normal = observer.observe(snapshot=clean_snapshot(), state_dir=state_dir, now_epoch=1010.0)
            second_normal = observer.observe(snapshot=clean_snapshot(), state_dir=state_dir, now_epoch=1020.0)
            third_normal = observer.observe(snapshot=clean_snapshot(), state_dir=state_dir, now_epoch=1030.0)

            self.assertEqual(red["status"], "RED")
            self.assertEqual(first_normal["status"], "RED")
            self.assertEqual(second_normal["status"], "RED")
            self.assertIn("hysteresis_red", second_normal["reasons"])
            self.assertEqual(third_normal["status"], "GREEN")

    def test_capacity_stays_six_without_workload_delta_calibration(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            for index in range(45):
                result = observer.observe(snapshot=clean_snapshot(), state_dir=state_dir, now_epoch=1000.0 + index)
                self.assertEqual(result["effective_capacity"], 6)

            self.assertEqual(result["successful_observations"], 45)
            self.assertEqual(result["capacity_mode"], "fixed_until_calibrated")
            self.assertNotIn("capacity_step_projection", result)

            persisted = json.loads((state_dir / "observer_state.json").read_text(encoding="utf-8"))
            self.assertLessEqual(len(persisted["observations"]), 100)

    def test_capacity_steps_only_after_thirty_workload_delta_samples(self):
        enable_observer_test_mode(self)
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            workload_delta = {"memory_bytes": 512 * MIB, "processes": 9, "root_fds": 40, "system_fds": 220}
            for index in range(29):
                result = observer.observe(
                    snapshot=clean_snapshot(workload_delta=workload_delta),
                    state_dir=state_dir,
                    now_epoch=1000.0 + index,
                )
                self.assertEqual(result["effective_capacity"], 6)

            thirtieth = observer.observe(
                snapshot=clean_snapshot(workload_delta=workload_delta),
                state_dir=state_dir,
                now_epoch=1030.0,
            )
            self.assertEqual(thirtieth["successful_observations"], 30)
            self.assertEqual(thirtieth["effective_capacity"], 6)
            self.assertEqual(thirtieth["capacity_mode"], "dynamic")

            for index in range(9):
                result = observer.observe(
                    snapshot=clean_snapshot(workload_delta=workload_delta),
                    state_dir=state_dir,
                    now_epoch=1040.0 + index,
                )
                self.assertEqual(result["effective_capacity"], 6)
            result = observer.observe(
                snapshot=clean_snapshot(workload_delta=workload_delta),
                state_dir=state_dir,
                now_epoch=1050.0,
            )
            self.assertEqual(result["effective_capacity"], 8)
            self.assertEqual(result["admission_capacity"], 8)
            self.assertEqual(result["max_wave_size"], 8)

    def test_calibration_is_workload_delta_and_workload_class_specific(self):
        enable_observer_test_mode(self)
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            normal_delta = {"memory_bytes": 512 * MIB, "processes": 9, "root_fds": 40, "system_fds": 220}
            browser_delta = {"memory_bytes": 2 * GIB, "processes": 32, "root_fds": 96, "system_fds": 768}
            high_expected = {"memory_bytes": 3 * GIB, "processes": 40, "root_fds": 120, "system_fds": 900}

            for index in range(45):
                expected_only = observer.observe(
                    snapshot=clean_snapshot(),
                    state_dir=state_dir,
                    now_epoch=1000.0 + index,
                    expected_cost=high_expected,
                )
            self.assertEqual(expected_only["effective_capacity"], 6)
            self.assertEqual(expected_only["capacity_mode"], "fixed_until_calibrated")

            for index in range(40):
                normal = observer.observe(
                    snapshot=clean_snapshot(workload_delta=normal_delta),
                    state_dir=state_dir,
                    now_epoch=1100.0 + index,
                    workload_class="normal",
                )
            self.assertEqual(normal["effective_capacity"], 8)

            for index in range(29):
                browser = observer.observe(
                    snapshot=clean_snapshot(workload_delta=browser_delta),
                    state_dir=state_dir,
                    now_epoch=1200.0 + index,
                    workload_class="browser",
                )
                self.assertEqual(browser["effective_capacity"], 6)
                self.assertEqual(browser["capacity_mode"], "fixed_until_calibrated")

    def test_capacity_does_not_step_when_new_step_projection_lacks_resources(self):
        enable_observer_test_mode(self)
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            constrained = clean_snapshot(available_memory_bytes=10 * GIB, active_slots=0)
            workload_delta = {"memory_bytes": 512 * MIB, "processes": 9, "root_fds": 40, "system_fds": 220}

            for index in range(40):
                result = observer.observe(
                    snapshot=dict(constrained, workload_delta=workload_delta),
                    state_dir=state_dir,
                    now_epoch=1000.0 + index,
                )

            self.assertEqual(result["status"], "GREEN")
            self.assertEqual(result["effective_capacity"], 6)
            self.assertFalse(result["capacity_step_projection"]["ok"])
            self.assertTrue(
                any(reason.startswith("memory_reserve_") for reason in result["capacity_step_projection"]["reasons"]),
                result["capacity_step_projection"]["reasons"],
            )

    def test_capacity_drops_immediately_to_last_proven_step_for_admission(self):
        enable_observer_test_mode(self)
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            workload_delta = {"memory_bytes": 512 * MIB, "processes": 9, "root_fds": 40, "system_fds": 220}
            for index in range(40):
                result = observer.observe(
                    snapshot=clean_snapshot(workload_delta=workload_delta),
                    state_dir=state_dir,
                    now_epoch=1000.0 + index,
                )
            self.assertEqual(result["effective_capacity"], 8)

            yellow = observer.observe(snapshot=clean_snapshot(cpu_idle_percent=10.0), state_dir=state_dir, now_epoch=1100.0)

            self.assertEqual(yellow["status"], "YELLOW")
            self.assertEqual(yellow["effective_capacity"], 6)
            self.assertEqual(yellow["admission_capacity"], 6)
            self.assertEqual(yellow["max_wave_size"], 2)

    def test_external_roots_are_reported_without_reducing_observer_admission(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)

            external = observer.observe(
                snapshot=clean_snapshot(codex_root_count=99, external_codex_roots=2.2),
                state_dir=state_dir,
                now_epoch=1000.0,
            )

            self.assertEqual(external["admission_capacity"], 6)
            self.assertEqual(external["max_wave_size"], 6)
            self.assertEqual(external["measurements"]["codex_root_count"], 99.0)
            self.assertEqual(external["measurements"]["external_codex_roots"], 2.2)
            projection = external["reserves"]["target_capacity_projection"]
            self.assertEqual(projection["active_slots"], 0)
            self.assertEqual(projection["additional_slots"], 6)
            self.assertNotIn("external_capacity_occupancy", projection)
            self.assertNotIn("occupied_slots", projection)

    def test_long_gap_does_not_count_as_yellow_recovery_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)

            yellow = observer.observe(snapshot=clean_snapshot(cpu_idle_percent=10.0), state_dir=state_dir, now_epoch=1000.0)
            after_gap = observer.observe(snapshot=clean_snapshot(), state_dir=state_dir, now_epoch=1300.0)
            recovered = observer.observe(snapshot=clean_snapshot(), state_dir=state_dir, now_epoch=1360.0)

            self.assertEqual("YELLOW", yellow["status"])
            self.assertEqual("YELLOW", after_gap["status"])
            self.assertIn("hysteresis_yellow", after_gap["reasons"])
            self.assertEqual("GREEN", recovered["status"])
            persisted = json.loads((state_dir / "observer_state.json").read_text(encoding="utf-8"))
            self.assertIsNone(persisted["recovery"]["from_status"])

    def test_long_gap_resets_partial_red_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)

            observer.observe(snapshot=clean_snapshot(memory_pressure="critical"), state_dir=state_dir, now_epoch=1000.0)
            observer.observe(snapshot=clean_snapshot(), state_dir=state_dir, now_epoch=1010.0)
            observer.observe(snapshot=clean_snapshot(), state_dir=state_dir, now_epoch=1020.0)
            after_gap = observer.observe(snapshot=clean_snapshot(), state_dir=state_dir, now_epoch=1300.0)
            second_after_gap = observer.observe(snapshot=clean_snapshot(), state_dir=state_dir, now_epoch=1310.0)
            recovered = observer.observe(snapshot=clean_snapshot(), state_dir=state_dir, now_epoch=1320.0)

            self.assertEqual("RED", after_gap["status"])
            self.assertIn("hysteresis_red", after_gap["reasons"])
            self.assertEqual("RED", second_after_gap["status"])
            self.assertIn("hysteresis_red", second_after_gap["reasons"])
            self.assertEqual("GREEN", recovered["status"])
            persisted = json.loads((state_dir / "observer_state.json").read_text(encoding="utf-8"))
            self.assertIsNone(persisted["recovery"]["from_status"])

    def test_cost_uses_minimum_p95_and_maximum_and_decreases_by_ten_percent_per_day(self):
        prior = {"memory_bytes": 1000 * MIB, "processes": 30.0, "root_fds": 120.0, "system_fds": 900.0}
        samples = [
            {"memory_bytes": 100 * MIB, "processes": 4.0, "root_fds": 20.0, "system_fds": 80.0}
            for _ in range(29)
        ]
        samples.append({"memory_bytes": 800 * MIB, "processes": 20.0, "root_fds": 100.0, "system_fds": 700.0})
        small_samples = [
            {"memory_bytes": 100 * MIB, "processes": 4.0, "root_fds": 20.0, "system_fds": 80.0}
            for _ in range(30)
        ]

        increased = observer.estimate_cost(
            "normal",
            samples,
            prior_cost={"memory_bytes": 384 * MIB, "processes": 8.0, "root_fds": 32.0, "system_fds": 192.0},
            now_epoch=0.0,
            prior_updated_epoch=0.0,
        )
        decreased = observer.estimate_cost(
            "normal",
            small_samples,
            prior_cost=prior,
            now_epoch=12 * 60 * 60,
            prior_updated_epoch=0.0,
        )

        self.assertEqual(increased["memory_bytes"], 960 * MIB)
        self.assertEqual(increased["processes"], 24.0)
        self.assertEqual(increased["root_fds"], 120.0)
        self.assertEqual(increased["system_fds"], 840.0)
        self.assertEqual(decreased["memory_bytes"], 950 * MIB)

    def test_state_directory_and_file_permissions_are_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "capacity"
            observer.observe(snapshot=clean_snapshot(), state_dir=state_dir, now_epoch=1000.0)

            dir_mode = stat.S_IMODE(os.stat(state_dir).st_mode)
            file_mode = stat.S_IMODE(os.stat(state_dir / "observer_state.json").st_mode)
            lock_mode = stat.S_IMODE(os.stat(state_dir / "observer.lock").st_mode)

            self.assertEqual(dir_mode, 0o700)
            self.assertEqual(file_mode, 0o600)
            self.assertEqual(lock_mode, 0o600)


if __name__ == "__main__":
    unittest.main()
