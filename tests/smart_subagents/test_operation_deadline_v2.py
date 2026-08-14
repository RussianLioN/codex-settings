from __future__ import annotations

import importlib.util
import json
import math
import sys
import unittest
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = (
    ROOT
    / "plugins"
    / "codex-smart-subagents"
    / "src"
    / "codex_smart_subagents"
    / "operation_deadline_v2.py"
)


def _load_module() -> ModuleType:
    if not MODULE_PATH.is_file():
        raise AssertionError(f"missing module: {MODULE_PATH}")
    name = "codex_smart_subagents.operation_deadline_v2_test_subject"
    spec = importlib.util.spec_from_file_location(name, MODULE_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class _Clock:
    def __init__(self, value: int = 1_000_000_000) -> None:
        self.value = value
        self.observations = 0

    def __call__(self) -> int:
        self.observations += 1
        return self.value

    def advance(self, nanoseconds: int) -> None:
        self.value += nanoseconds


class OperationDeadlineV2Tests(unittest.TestCase):
    def test_context_bridge_exports_only_the_shared_deadline_operations(self) -> None:
        module = _load_module()

        for name in (
            "scoped_current_deadline_v2",
            "current_operation_deadline_v2",
            "checkpoint_current_operation_deadline_v2",
            "checkpoint_current_operation_deadline_if_scoped_v2",
        ):
            with self.subTest(name=name):
                self.assertTrue(hasattr(module, name), name)

    def test_exact_integer_nanosecond_boundary_is_expired(self) -> None:
        module = _load_module()
        clock = _Clock(77)
        deadline = module.OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=0.000000001,
            timeout_code="APPLY_OPERATION_DEADLINE_EXCEEDED",
            monotonic_ns=clock,
        )

        self.assertEqual(1, deadline.remaining_nanoseconds())
        clock.advance(1)
        with self.assertRaises(module.OperationDeadlineExceededV2) as captured:
            deadline.checkpoint()

        error = captured.exception
        self.assertEqual("APPLY_OPERATION_DEADLINE_EXCEEDED", error.code)
        self.assertEqual(1, error.elapsed_monotonic_nanoseconds)
        self.assertEqual("operation", error.deadline_kind)

    def test_shorter_child_uses_its_own_deadline_and_code(self) -> None:
        module = _load_module()
        clock = _Clock()
        root = module.OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=10,
            timeout_code="ROOT_EXPIRED",
            monotonic_ns=clock,
        )
        clock.advance(1_000_000_000)
        child = root.child(
            phase="probe",
            max_seconds=2,
            timeout_code="PROBE_EXPIRED",
        )

        self.assertEqual(2_000_000_000, child.remaining_nanoseconds())
        clock.advance(2_000_000_000)
        with self.assertRaises(module.OperationDeadlineExceededV2) as captured:
            child.checkpoint()

        self.assertEqual("PROBE_EXPIRED", captured.exception.code)
        self.assertEqual("phase", captured.exception.deadline_kind)
        self.assertEqual("probe", captured.exception.phase)
        self.assertEqual(
            2_000_000_000,
            captured.exception.configured_timeout_nanoseconds,
        )

    def test_longer_child_cannot_extend_root_deadline(self) -> None:
        module = _load_module()
        clock = _Clock()
        root = module.OperationDeadlineV2.start(
            operation="recovery",
            timeout_seconds=5,
            timeout_code="RECOVERY_OPERATION_DEADLINE_EXCEEDED",
            monotonic_ns=clock,
        )
        clock.advance(2_000_000_000)
        child = root.child(
            phase="cleanup",
            max_seconds=20,
            timeout_code="CLEANUP_EXPIRED",
        )

        self.assertEqual(3_000_000_000, child.remaining_nanoseconds())
        clock.advance(3_000_000_000)
        with self.assertRaises(module.OperationDeadlineExceededV2) as captured:
            child.checkpoint()

        self.assertEqual(
            "RECOVERY_OPERATION_DEADLINE_EXCEEDED", captured.exception.code
        )
        self.assertEqual("operation", captured.exception.deadline_kind)
        self.assertEqual("cleanup", captured.exception.phase)

    def test_equal_child_deadline_preserves_parent_priority(self) -> None:
        module = _load_module()
        clock = _Clock()
        root = module.OperationDeadlineV2.start(
            operation="update",
            timeout_seconds=3,
            timeout_code="COMMON_DEADLINE",
            monotonic_ns=clock,
        )
        child = root.child(
            phase="mutation",
            max_seconds=3,
            timeout_code="LOCAL_DEADLINE",
        )
        clock.advance(3_000_000_000)

        with self.assertRaises(module.OperationDeadlineExceededV2) as captured:
            child.checkpoint()

        self.assertEqual("COMMON_DEADLINE", captured.exception.code)
        self.assertEqual("operation", captured.exception.deadline_kind)

    def test_nested_children_never_extend_an_inherited_phase_deadline(self) -> None:
        module = _load_module()
        clock = _Clock()
        root = module.OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=30,
            timeout_code="ROOT_EXPIRED",
            monotonic_ns=clock,
        )
        phase = root.child(
            phase="probe",
            max_seconds=4,
            timeout_code="PROBE_EXPIRED",
        )
        clock.advance(1_000_000_000)
        nested = phase.child(
            phase="network",
            max_seconds=20,
            timeout_code="NETWORK_EXPIRED",
        )

        self.assertEqual(3_000_000_000, nested.remaining_nanoseconds())
        clock.advance(3_000_000_000)
        with self.assertRaises(module.OperationDeadlineExceededV2) as captured:
            nested.checkpoint()

        self.assertEqual("PROBE_EXPIRED", captured.exception.code)
        self.assertEqual("phase", captured.exception.deadline_kind)
        self.assertEqual("network", captured.exception.phase)

    def test_bounded_timeout_respects_cap_reserve_and_exact_exhaustion(self) -> None:
        module = _load_module()
        clock = _Clock()
        deadline = module.OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=1,
            timeout_code="ROOT_EXPIRED",
            monotonic_ns=clock,
        )

        self.assertEqual(
            300_000_000,
            deadline.bounded_timeout_nanoseconds(
                local_cap_nanoseconds=300_000_000,
                reserve_nanoseconds=100_000_000,
            ),
        )
        clock.advance(800_000_000)
        self.assertEqual(
            100_000_000,
            deadline.bounded_timeout_nanoseconds(
                local_cap_nanoseconds=300_000_000,
                reserve_nanoseconds=100_000_000,
            ),
        )
        clock.advance(100_000_000)
        with self.assertRaises(module.OperationDeadlineExceededV2):
            deadline.bounded_timeout_nanoseconds(
                local_cap_nanoseconds=300_000_000,
                reserve_nanoseconds=100_000_000,
            )

    def test_seconds_wrapper_never_returns_more_than_integer_budget(self) -> None:
        module = _load_module()
        clock = _Clock()
        deadline = module.OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=0.000000003,
            timeout_code="ROOT_EXPIRED",
            monotonic_ns=clock,
        )

        bounded = deadline.bounded_timeout_seconds(
            local_cap_seconds=0.000000002,
            reserve_seconds=0.000000001,
        )

        self.assertGreater(bounded, 0)
        self.assertLessEqual(bounded, 0.000000002)

    def test_deadline_proof_is_closed_json_without_absolute_clock_values(self) -> None:
        module = _load_module()
        clock = _Clock(123_456_789_000)
        deadline = module.OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=2,
            timeout_code="APPLY_OPERATION_DEADLINE_EXCEEDED",
            monotonic_ns=clock,
        ).child(
            phase="probe",
            max_seconds=1,
            timeout_code="PROBE_DEADLINE_EXCEEDED",
        )
        clock.advance(1_000_000_000)
        with self.assertRaises(module.OperationDeadlineExceededV2) as captured:
            deadline.checkpoint()

        proof = module.deadline_proof_v2(captured.exception)
        self.assertEqual(
            {
                "schemaVersion",
                "proofType",
                "operation",
                "phase",
                "timeoutCode",
                "deadlineKind",
                "configuredTimeoutNanoseconds",
                "elapsedMonotonicNanoseconds",
                "deadlineExceeded",
            },
            set(proof),
        )
        self.assertEqual(2, proof["schemaVersion"])
        self.assertEqual("operation-deadline-v2", proof["proofType"])
        self.assertIs(True, proof["deadlineExceeded"])
        serialized = json.dumps(proof, allow_nan=False, sort_keys=True)
        self.assertNotIn("123456789000", serialized)
        self.assertFalse(
            any(
                forbidden in key.lower()
                for key in proof
                for forbidden in ("startedat", "deadlineat", "absolutetime")
            )
        )
        self.assertEqual(proof, module.validate_deadline_proof_v2(proof))

    def test_deadline_proof_validator_rejects_open_or_malformed_documents(self) -> None:
        module = _load_module()
        valid = {
            "schemaVersion": 2,
            "proofType": "operation-deadline-v2",
            "operation": "apply",
            "phase": "probe",
            "timeoutCode": "PROBE_EXPIRED",
            "deadlineKind": "phase",
            "configuredTimeoutNanoseconds": 1,
            "elapsedMonotonicNanoseconds": 1,
            "deadlineExceeded": True,
        }
        malformed_documents = [
            {**valid, "unexpected": "open"},
            {key: value for key, value in valid.items() if key != "phase"},
            {**valid, "schemaVersion": True},
            {**valid, "deadlineKind": "unknown"},
            {**valid, "deadlineKind": []},
            {**valid, "configuredTimeoutNanoseconds": 0},
            {**valid, "elapsedMonotonicNanoseconds": -1},
            {**valid, "deadlineExceeded": 1},
        ]

        for document in malformed_documents:
            with self.subTest(document=document):
                with self.assertRaises(module.DeadlineProofValidationErrorV2):
                    module.validate_deadline_proof_v2(document)

    def test_exception_is_a_regular_timeout_with_populated_args(self) -> None:
        module = _load_module()
        clock = _Clock()
        deadline = module.OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=1,
            timeout_code="ROOT_EXPIRED",
            monotonic_ns=clock,
        )
        clock.advance(1_000_000_000)

        with self.assertRaises(module.OperationDeadlineExceededV2) as captured:
            deadline.checkpoint()

        self.assertIsInstance(captured.exception, TimeoutError)
        self.assertTrue(captured.exception.args)
        self.assertIn("ROOT_EXPIRED", str(captured.exception))

    def test_invalid_timeouts_and_clock_values_fail_closed(self) -> None:
        module = _load_module()
        invalid_timeouts = [True, 0, -1, math.inf, math.nan, 0.0000000001]
        for value in invalid_timeouts:
            with self.subTest(value=value):
                with self.assertRaises((TypeError, ValueError)):
                    module.OperationDeadlineV2.start(
                        operation="apply",
                        timeout_seconds=value,
                        timeout_code="ROOT_EXPIRED",
                    )

        for clock_value in [True, -1, 1.5]:
            with self.subTest(clock_value=clock_value):
                with self.assertRaises((TypeError, ValueError)):
                    module.OperationDeadlineV2.start(
                        operation="apply",
                        timeout_seconds=1,
                        timeout_code="ROOT_EXPIRED",
                        monotonic_ns=lambda value=clock_value: value,
                    )

    def test_nested_context_scope_accepts_only_same_object_and_restores_outer(self) -> None:
        module = _load_module()
        outer = module.OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=10,
            timeout_code="OUTER_EXPIRED",
        )

        self.assertIsNone(module.current_operation_deadline_v2())
        with module.scoped_current_deadline_v2(outer):
            self.assertIs(outer, module.current_operation_deadline_v2())
            with module.scoped_current_deadline_v2(outer):
                self.assertIs(outer, module.current_operation_deadline_v2())
            self.assertIs(outer, module.current_operation_deadline_v2())
        self.assertIsNone(module.current_operation_deadline_v2())

    def test_context_scope_restores_outer_after_exception(self) -> None:
        module = _load_module()
        outer = module.OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=10,
            timeout_code="OUTER_EXPIRED",
        )

        with module.scoped_current_deadline_v2(outer):
            with self.assertRaisesRegex(RuntimeError, "injected"):
                with module.scoped_current_deadline_v2(outer):
                    raise RuntimeError("injected")
            self.assertIs(outer, module.current_operation_deadline_v2())
        self.assertIsNone(module.current_operation_deadline_v2())

    def test_context_scope_rejects_independent_nested_replacement(self) -> None:
        module = _load_module()
        outer = module.OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=1,
            timeout_code="OUTER_EXPIRED",
        )
        replacement = module.OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=100,
            timeout_code="REPLACEMENT_EXPIRED",
        )

        with module.scoped_current_deadline_v2(outer):
            with self.assertRaises(module.CurrentOperationDeadlineConflictV2):
                with module.scoped_current_deadline_v2(replacement):
                    self.fail("independent nested deadline must not be entered")
            self.assertIs(outer, module.current_operation_deadline_v2())

    def test_context_checkpoint_fails_closed_when_scope_is_missing(self) -> None:
        module = _load_module()

        with self.assertRaises(module.CurrentOperationDeadlineUnavailableV2):
            module.checkpoint_current_operation_deadline_v2()

    def test_context_checkpoint_uses_existing_deadline_without_replacement(self) -> None:
        module = _load_module()
        clock = _Clock()
        deadline = module.OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=0.000000001,
            timeout_code="SHARED_EXPIRED",
            monotonic_ns=clock,
        )

        with module.scoped_current_deadline_v2(deadline):
            clock.advance(1)
            with self.assertRaises(module.OperationDeadlineExceededV2) as captured:
                module.checkpoint_current_operation_deadline_v2()
            self.assertEqual("SHARED_EXPIRED", captured.exception.code)
            self.assertIs(deadline, module.current_operation_deadline_v2())

    def test_optional_context_checkpoint_preserves_standalone_callers(self) -> None:
        module = _load_module()
        clock = _Clock()

        self.assertIsNone(
            module.checkpoint_current_operation_deadline_if_scoped_v2()
        )

        deadline = module.OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=0.000000001,
            timeout_code="SHARED_EXPIRED",
            monotonic_ns=clock,
        )
        with module.scoped_current_deadline_v2(deadline):
            self.assertIs(
                deadline,
                module.checkpoint_current_operation_deadline_if_scoped_v2(),
            )
            clock.advance(1)
            with self.assertRaises(module.OperationDeadlineExceededV2):
                module.checkpoint_current_operation_deadline_if_scoped_v2()


if __name__ == "__main__":
    unittest.main()
