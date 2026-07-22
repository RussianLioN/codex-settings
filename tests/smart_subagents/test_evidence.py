from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.canonical_json import (  # noqa: E402
    CanonicalJsonError,
    canonical_json_v1,
)
from codex_smart_subagents.evidence import (  # noqa: E402
    AccountEvidenceCollector,
    EvidenceError,
    build_interface_evidence,
    verify_account_evidence,
    verify_interface_evidence,
)


def load_vector(name: str) -> dict[str, Any]:
    path = ROOT / "docs" / "contracts" / "vectors" / name
    return json.loads(path.read_text(encoding="utf-8"))


def apply_operation(value: dict[str, Any], operation: dict[str, Any]) -> None:
    def resolve(pointer: str) -> Any:
        current: Any = value
        for token in pointer.removeprefix("/").split("/"):
            current = current[int(token)] if type(current) is list else current[token]
        return current

    kind = operation["kind"]
    if kind in {"swap-values"}:
        first_tokens = operation["firstPointer"].removeprefix("/").split("/")
        second_tokens = operation["secondPointer"].removeprefix("/").split("/")
        first_parent: Any = value
        second_parent: Any = value
        for token in first_tokens[:-1]:
            first_parent = first_parent[int(token)] if type(first_parent) is list else first_parent[token]
        for token in second_tokens[:-1]:
            second_parent = second_parent[int(token)] if type(second_parent) is list else second_parent[token]
        first_key, second_key = first_tokens[-1], second_tokens[-1]
        first_parent[first_key], second_parent[second_key] = (
            second_parent[second_key],
            first_parent[first_key],
        )
        return
    if kind in {"swap-array-items", "swap-array-items-and-recalculate"}:
        array = resolve(operation["pointer"])
        first, second = operation["first"], operation["second"]
        array[first], array[second] = array[second], array[first]
        return

    tokens = operation["pointer"].removeprefix("/").split("/")
    parent: Any = value
    for token in tokens[:-1]:
        parent = parent[int(token)] if type(parent) is list else parent[token]
    key = tokens[-1]
    if kind in {"add", "add-member", "replace", "replace-value"}:
        if type(parent) is list:
            parent[int(key)] = copy.deepcopy(operation["value"])
        else:
            parent[key] = copy.deepcopy(operation["value"])
    elif kind == "remove":
        if type(parent) is list:
            del parent[int(key)]
        else:
            del parent[key]
    else:
        raise AssertionError(f"unknown test operation: {kind}")


class CanonicalJsonV1Tests(unittest.TestCase):
    def test_matches_every_positive_contract_vector(self) -> None:
        vectors = load_vector("interface-evidence-v1.json")
        for case in vectors["canonicalJsonV1Cases"]["positive"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(case["canonicalUtf8"], canonical_json_v1(case["value"]))

    def test_rejects_non_contract_python_values(self) -> None:
        invalid = (
            1.0,
            float("nan"),
            float("inf"),
            float("-inf"),
            9_007_199_254_740_992,
            -9_007_199_254_740_992,
            "\ud800",
            "\udfff",
            (1,),
            b"x",
            {1: "x"},
        )
        for value in invalid:
            with self.subTest(value=repr(value)):
                with self.assertRaises(CanonicalJsonError):
                    canonical_json_v1(value)


class InterfaceEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.vectors = load_vector("interface-evidence-v1.json")
        self.base = self.vectors["base"]

    def test_builder_reproduces_the_contract_base_exactly(self) -> None:
        built = build_interface_evidence(
            subject=self.base["subject"],
            semantic=self.base["semantic"],
        )
        self.assertEqual(self.base, built)
        self.assertEqual(self.base, verify_interface_evidence(built))

    def test_root_extensions_do_not_change_protected_fingerprints(self) -> None:
        built = build_interface_evidence(
            subject=self.base["subject"],
            semantic=self.base["semantic"],
            extensions={"note": "diagnostic"},
        )
        self.assertEqual(
            {
                "subjectFingerprint": self.base["subjectFingerprint"],
                "semanticFingerprint": self.base["semanticFingerprint"],
                "compatibilityFingerprint": self.base["compatibilityFingerprint"],
            },
            {name: built[name] for name in (
                "subjectFingerprint",
                "semanticFingerprint",
                "compatibilityFingerprint",
            )},
        )
        verify_interface_evidence(built)

    def test_mtime_nanoseconds_are_an_exact_decimal_string(self) -> None:
        subject = copy.deepcopy(self.base["subject"])
        subject["mtimeNs"] = "1784000000000000000"
        built = build_interface_evidence(
            subject=subject,
            semantic=self.base["semantic"],
        )
        self.assertEqual("1784000000000000000", built["subject"]["mtimeNs"])
        verify_interface_evidence(built)

        for invalid in (3, "01", "-1", "1.0", ""):
            with self.subTest(invalid=invalid):
                changed = copy.deepcopy(subject)
                changed["mtimeNs"] = invalid
                with self.assertRaisesRegex(
                    EvidenceError,
                    "INTERFACE_SCHEMA_INVALID",
                ):
                    build_interface_evidence(
                        subject=changed,
                        semantic=self.base["semantic"],
                    )

    def test_every_negative_vector_is_rejected(self) -> None:
        for case in self.vectors["mutations"]:
            if case["name"] == "root-extension-does-not-change-projections":
                continue
            changed = copy.deepcopy(self.base)
            apply_operation(changed, case["operation"])
            with self.subTest(case=case["name"]):
                with self.assertRaises(EvidenceError):
                    verify_interface_evidence(changed)


class FakeReadExecutor:
    def __init__(
        self,
        *,
        requirements: list[Any],
        catalogs: list[list[dict[str, str]]],
        fail_at: str | None = None,
    ) -> None:
        self.requirements = list(requirements)
        self.catalogs = list(catalogs)
        self.fail_at = fail_at
        self.calls: list[dict[str, Any]] = []

    def execute(
        self,
        stage: str,
        *,
        executable_path: str,
        argv: tuple[str, ...],
        environment: dict[str, str],
        timeout_seconds: float,
        cancel_check: Callable[[], bool] | None = None,
    ) -> Any:
        del cancel_check
        self.calls.append(
            {
                "stage": stage,
                "executablePath": executable_path,
                "argv": argv,
                "environment": copy.deepcopy(environment),
                "timeoutSeconds": timeout_seconds,
            }
        )
        if stage == self.fail_at:
            raise RuntimeError("single process failed")
        if stage.startswith("requirements-"):
            return copy.deepcopy(self.requirements.pop(0))
        return copy.deepcopy(self.catalogs.pop(0))


class TickClock:
    def __init__(self) -> None:
        self.value = -1.0

    def __call__(self) -> float:
        self.value += 1.0
        return self.value


class AccountEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.interface = load_vector("interface-evidence-v1.json")["base"]
        self.vectors = load_vector("account-evidence-v1.json")
        self.base = self.vectors["base"]
        self.environment = self.base["collection"]["environment"]

    def executor(self, *, fail_at: str | None = None) -> FakeReadExecutor:
        return FakeReadExecutor(
            requirements=[None, None, None],
            catalogs=[self.base["availablePairs"], self.base["availablePairs"]],
            fail_at=fail_at,
        )

    def collector(
        self,
        executor: FakeReadExecutor,
        *,
        verifier_calls: list[str] | None = None,
        timeout_seconds: float = 180.0,
        stage_calls: list[str] | None = None,
    ) -> AccountEvidenceCollector:
        calls = [] if verifier_calls is None else verifier_calls

        def verify_subject(subject: dict[str, Any]) -> None:
            calls.append(subject["snapshotPath"])

        return AccountEvidenceCollector(
            interface_evidence=self.interface,
            codex_home=self.base["codexHome"],
            home=self.environment["HOME"],
            tmpdir=self.environment["TMPDIR"],
            executor=executor,
            verify_subject=verify_subject,
            monotonic=TickClock(),
            timeout_seconds=timeout_seconds,
            stage_callback=(
                None if stage_calls is None else stage_calls.append
            ),
        )

    def test_collector_reproduces_base_and_exact_five_stage_sequence(self) -> None:
        executor = self.executor()
        subject_checks: list[str] = []
        built = self.collector(executor, verifier_calls=subject_checks).collect()

        self.assertEqual(self.base, built)
        self.assertEqual(
            [
                "requirements-a",
                "catalog-a",
                "requirements-b",
                "catalog-b",
                "requirements-c",
            ],
            [call["stage"] for call in executor.calls],
        )
        self.assertEqual(5, len(subject_checks))
        self.assertTrue(
            all(call["executablePath"] == "/private/codex" for call in executor.calls)
        )
        self.assertTrue(
            all(
                call["argv"]
                == ("app-server", "--strict-config", "--listen", "stdio://")
                for call in executor.calls
            )
        )
        self.assertEqual(sorted(
            [call["timeoutSeconds"] for call in executor.calls], reverse=True
        ), [call["timeoutSeconds"] for call in executor.calls])
        self.assertEqual(self.base, verify_account_evidence(built, self.interface))

    def test_collector_uses_durable_remaining_budget_and_reports_each_stage(self) -> None:
        executor = self.executor()
        stages: list[str] = []

        self.collector(
            executor,
            timeout_seconds=9.0,
            stage_calls=stages,
        ).collect()

        self.assertEqual(
            [
                "requirements-a",
                "catalog-a",
                "requirements-b",
                "catalog-b",
                "requirements-c",
            ],
            stages,
        )
        self.assertEqual(8.0, executor.calls[0]["timeoutSeconds"])
        self.assertGreater(executor.calls[-1]["timeoutSeconds"], 0)
        self.assertLessEqual(executor.calls[-1]["timeoutSeconds"], 4.0)

    def test_requirements_or_catalog_drift_fails_closed(self) -> None:
        drifting_requirements = FakeReadExecutor(
            requirements=[None, {"allowedSandboxModes": ["read-only"]}, None],
            catalogs=[self.base["availablePairs"], self.base["availablePairs"]],
        )
        with self.assertRaisesRegex(EvidenceError, "ACCOUNT_REQUIREMENTS_DRIFT"):
            self.collector(drifting_requirements).collect()

        changed_pairs = copy.deepcopy(self.base["availablePairs"])
        changed_pairs.pop()
        drifting_catalog = FakeReadExecutor(
            requirements=[None, None, None],
            catalogs=[self.base["availablePairs"], changed_pairs],
        )
        with self.assertRaisesRegex(EvidenceError, "ACCOUNT_CATALOG_DRIFT"):
            self.collector(drifting_catalog).collect()

    def test_process_failure_is_not_retried_and_result_is_not_cached(self) -> None:
        failing = self.executor(fail_at="requirements-b")
        with self.assertRaisesRegex(EvidenceError, "ACCOUNT_READ_FAILED"):
            self.collector(failing).collect()
        self.assertEqual(
            ["requirements-a", "catalog-a", "requirements-b"],
            [call["stage"] for call in failing.calls],
        )

        executor = FakeReadExecutor(
            requirements=[None] * 6,
            catalogs=[self.base["availablePairs"]] * 4,
        )
        collector = self.collector(executor)
        collector.collect()
        collector.collect()
        self.assertEqual(10, len(executor.calls))

    def test_cancellation_stops_before_the_next_stage(self) -> None:
        executor = self.executor()
        checks = iter((False, True))
        collector = AccountEvidenceCollector(
            interface_evidence=self.interface,
            codex_home=self.base["codexHome"],
            home=self.environment["HOME"],
            tmpdir=self.environment["TMPDIR"],
            executor=executor,
            verify_subject=lambda _subject: None,
            monotonic=TickClock(),
            cancel_check=lambda: next(checks),
        )

        with self.assertRaisesRegex(EvidenceError, "ACCOUNT_EVIDENCE_CANCELLED"):
            collector.collect()

        self.assertEqual(["requirements-a"], [call["stage"] for call in executor.calls])

    def test_every_negative_account_vector_is_rejected(self) -> None:
        for case in self.vectors["mutations"]:
            changed = copy.deepcopy(self.base)
            apply_operation(changed, case["operation"])
            if case["operation"]["kind"] == "swap-array-items-and-recalculate":
                recalculated = case["recalculated"]
                changed["accountCatalogFingerprint"] = recalculated[
                    "accountCatalogFingerprint"
                ]
                for process, fingerprint in zip(
                    changed["collection"]["processes"],
                    recalculated["processFingerprints"],
                    strict=True,
                ):
                    process["processFingerprint"] = fingerprint
                changed["collection"]["collectionFingerprint"] = recalculated[
                    "collectionFingerprint"
                ]
                changed["accountContextFingerprint"] = recalculated[
                    "accountContextFingerprint"
                ]
                changed["recordFingerprint"] = recalculated["recordFingerprint"]
            with self.subTest(case=case["name"]):
                with self.assertRaises(EvidenceError):
                    verify_account_evidence(changed, self.interface)


if __name__ == "__main__":
    unittest.main()
