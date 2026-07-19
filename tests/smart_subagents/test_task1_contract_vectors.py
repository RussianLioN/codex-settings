from __future__ import annotations

import importlib.util
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = ROOT / "scripts/validate_task1_contract_vectors.py"


def load_json(relative_path: str) -> object:
    return json.loads((ROOT / relative_path).read_text(encoding="utf-8"))


class Task1Cycle5RedTests(unittest.TestCase):
    def test_config_cases_have_closed_source_context_and_expected_envelopes(
        self,
    ) -> None:
        schema_path = (
            ROOT
            / "docs/contracts/schemas/config-requirements-vector-case-v1.schema.json"
        )
        self.assertTrue(
            schema_path.is_file(), "нет закрытой схемы оболочки случаев требований"
        )
        vectors = load_json("docs/contracts/vectors/config-requirements-v1.json")
        self.assertEqual(22, len(vectors["cases"]))
        self.assertIn("contexts", vectors)
        for case in vectors["cases"]:
            self.assertEqual(
                {"name", "source", "contextRef", "expected"}, set(case), case["name"]
            )
            self.assertIn(case["source"]["kind"], {"parsed", "raw-utf8"})

    def test_config_oracle_ignores_expected_and_detects_expected_poisoning(
        self,
    ) -> None:
        self.assertTrue(
            VALIDATOR_PATH.is_file(), "нет отслеживаемого эталонного исполнителя"
        )
        from scripts import validate_task1_contract_vectors as oracle

        self.assertTrue(
            hasattr(oracle, "evaluate_config_requirements"),
            "нет независимого оценивателя требований",
        )
        source = {"kind": "parsed", "value": {"requirements": {}}}
        context = {
            "profileCase": "reader",
            "selectedPair": {"model": "gpt-5.6-luna", "reasoningEffort": "medium"},
        }
        actual = oracle.evaluate_config_requirements(source, context, root=ROOT)
        expected = oracle.config_evaluation_to_dict(actual)
        poisoned = json.loads(json.dumps(expected))
        poisoned["normalization"]["fingerprint"] = "0" * 64

        self.assertEqual(
            actual, oracle.evaluate_config_requirements(source, context, root=ROOT)
        )
        with self.assertRaises(AssertionError):
            oracle.compare_config_expected(actual, poisoned)

    def test_config_metamorphic_contract_is_executable(self) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        self.assertTrue(
            hasattr(oracle, "validate_config_metamorphic_cases"),
            "нет метаморфного исполнителя",
        )
        summary = oracle.validate_config_metamorphic_cases(ROOT)
        self.assertEqual((8, 8), (summary.passed, summary.total))

    def test_intentionally_defective_oracles_are_all_detected(self) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        self.assertTrue(
            hasattr(oracle, "validate_oracle_mutants"),
            "нет мутационной проверки эталона",
        )
        summary = oracle.validate_oracle_mutants(ROOT)
        self.assertGreaterEqual(summary.total, 18)
        self.assertEqual(summary.total, summary.passed)

    def test_interface_mutations_are_closed_discriminated_operations(self) -> None:
        schema_path = (
            ROOT / "docs/contracts/schemas/interface-evidence-mutation-v1.schema.json"
        )
        self.assertTrue(
            schema_path.is_file(), "нет закрытой схемы мутаций InterfaceEvidence"
        )
        vectors = load_json("docs/contracts/vectors/interface-evidence-v1.json")
        self.assertEqual(9, len(vectors["mutations"]))
        for case in vectors["mutations"]:
            self.assertIsInstance(case["operation"], dict, case["name"])
            self.assertIn(
                case["operation"]["kind"],
                {"add-member", "replace-value", "swap-values"},
            )
            self.assertIsInstance(case["expected"], dict, case["name"])

    def test_interface_mutation_oracle_applies_exact_operation_and_rejects_noop(
        self,
    ) -> None:
        self.assertTrue(
            VALIDATOR_PATH.is_file(), "нет отслеживаемого эталонного исполнителя"
        )
        from scripts import validate_task1_contract_vectors as oracle

        changed = oracle.apply_interface_operation(
            {"nested": {"value": "before"}},
            {
                "kind": "replace-value",
                "pointer": "/nested/value",
                "before": "before",
                "value": "after",
            },
        )
        self.assertEqual({"nested": {"value": "after"}}, changed)
        with self.assertRaises(oracle.ContractError):
            oracle.apply_interface_operation(
                {"value": "same"},
                {
                    "kind": "replace-value",
                    "pointer": "/value",
                    "before": "same",
                    "value": "same",
                },
            )

    def test_canonical_and_hook_legacy_vectors_are_executable(self) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        self.assertTrue(
            hasattr(oracle, "validate_canonical_json_cases"),
            "нет исполнителя canonical-json-v1",
        )
        self.assertTrue(
            hasattr(oracle, "validate_hook_output_cases"),
            "нет точного классификатора хуков",
        )
        canonical = oracle.validate_canonical_json_cases(ROOT)
        hooks = oracle.validate_hook_output_cases(ROOT)
        self.assertEqual((19, 19), (canonical.passed, canonical.total))
        self.assertEqual((6, 6), (hooks.passed, hooks.total))

    def test_environment_template_is_bound_for_three_roles_and_eight_slots(
        self,
    ) -> None:
        schema = load_json("docs/contracts/schemas/child-profile-v1.schema.json")
        trusted = schema["$defs"]["trustedLaunchContext"]
        self.assertIn("environmentSlotValues", trusted["properties"])
        self.assertIn("secretSlotFingerprints", trusted["properties"])
        vectors = load_json("docs/contracts/vectors/child-profile-v1.json")
        self.assertEqual(
            {"classifier", "reader", "writer"},
            set(vectors["concreteLaunch"]["positiveRoles"]),
        )
        slots = {case["slot"] for case in vectors["environmentNegativeCases"]}
        self.assertEqual(
            {
                "snapshotRoot",
                "codexHome",
                "codexSqliteHome",
                "home",
                "tmpDir",
                "otelEndpoint",
                "workspaceRoot",
                "otelHeaders",
            },
            slots,
        )

    def test_environment_bindings_are_materialized_and_context_bound(self) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        self.assertTrue(
            hasattr(oracle, "validate_environment_binding_cases"),
            "нет исполнителя привязки среды",
        )
        if importlib.util.find_spec("jsonschema") is None:
            with self.assertRaises(ModuleNotFoundError):
                oracle.validate_environment_binding_cases(ROOT)
        else:
            summary = oracle.validate_environment_binding_cases(ROOT)
            self.assertEqual((11, 11), (summary.passed, summary.total))

    def test_legacy_child_negative_targets_are_current_and_executable(self) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        vectors = load_json("docs/contracts/vectors/child-profile-v1.json")
        self.assertTrue(
            all(
                case["target"] != "concreteLaunch.positiveBinding"
                for case in vectors["negativeCases"]
            )
        )
        self.assertTrue(
            hasattr(oracle, "validate_child_negative_cases"),
            "нет исполнителя 15 мутаций запуска",
        )

    def test_tree_metric_contract_and_five_calibrations_are_machine_readable(
        self,
    ) -> None:
        vectors = load_json(
            "docs/contracts/vectors/config-requirements-vector-recipes-v1.json"
        )
        self.assertIn("treeMetricContract", vectors)
        self.assertIn("treeMetricCases", vectors)
        contract = vectors["treeMetricContract"]
        self.assertEqual("json-value-tree-v1", contract["version"])
        self.assertEqual(0, contract["objectMemberNameNodeWeight"])
        self.assertEqual(1, contract["rootDepth"])
        self.assertEqual(5, len(vectors["treeMetricCases"]))

    def test_tree_metric_calibrations_and_metamorphisms_are_executable(self) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        self.assertTrue(
            hasattr(oracle, "validate_tree_metric_contract"),
            "нет исполнителя метрики дерева",
        )
        summary = oracle.validate_tree_metric_contract(ROOT)
        self.assertEqual((8, 8), (summary.passed, summary.total))

    def test_cli_reports_config_and_tree_metamorphisms_as_one_total(self) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        summary = oracle.aggregate_check_summaries(
            oracle.CheckSummary(passed=8, total=8),
            oracle.CheckSummary(passed=3, total=3),
        )
        self.assertEqual((11, 11), (summary.passed, summary.total))

    def test_recipe_generator_ignores_expected_and_hits_tree_limits(self) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        self.assertTrue(
            hasattr(oracle, "generate_config_recipe"), "нет генератора рецептов"
        )
        vectors = load_json(
            "docs/contracts/vectors/config-requirements-vector-recipes-v1.json"
        )
        recipe = next(
            item for item in vectors["recipes"] if item["name"] == "raw-tree-nodes"
        )
        poisoned = json.loads(json.dumps(recipe))
        poisoned["atLimitExpected"] = "poisoned"
        at_document, _ = oracle.generate_config_recipe(poisoned, recipe["atLimit"])
        over_document, _ = oracle.generate_config_recipe(poisoned, recipe["overLimit"])
        self.assertEqual(4096, oracle.measure_json_value_tree(at_document).nodes)
        self.assertEqual(4097, oracle.measure_json_value_tree(over_document).nodes)

    def test_routing_normalization_and_availability_errors_are_explicit(self) -> None:
        vectors = load_json("docs/contracts/vectors/routing-policy-v2.json")
        self.assertEqual(2, len(vectors["normalizationCases"]))
        self.assertTrue(
            all("expected" in case for case in vectors["normalizationCases"])
        )
        self.assertTrue(
            all(
                isinstance(case["expected"], dict)
                for case in vectors["normalizationCases"]
            )
        )
        self.assertTrue(
            all("expectedError" in case for case in vectors["availabilityCases"])
        )

    def test_routing_normalization_and_availability_are_executable(self) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        self.assertTrue(
            hasattr(oracle, "validate_routing_cases"), "нет исполнителя маршрутизации"
        )
        summary = oracle.validate_routing_cases(ROOT)
        self.assertEqual((9, 9), (summary.passed, summary.total))

    def test_routing_interval_oracle_executes_criterion_states(self) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        self.assertTrue(
            hasattr(oracle, "routing_interval"), "нет исполнителя интервальной оценки"
        )
        vectors = load_json("docs/contracts/vectors/routing-policy-v2.json")
        case = vectors["criterionCases"][0]
        actual = oracle.routing_interval(
            case["factor"],
            case["criterionStates"],
            vectors["policy"]["factorDefinitions"],
        )
        self.assertEqual(case["expected"], actual)

    def test_machine_schema_hash_has_no_domain_fingerprint_rule(self) -> None:
        document = (ROOT / "docs/contracts/codex-interface-v1.md").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("codex-smart/child-result-schema/v1", document)
        self.assertIn("schemaSha256 = SHA256(точные исходные байты файла)", document)

    def test_interface_utf8_boundaries_cover_256_and_4096_bytes(self) -> None:
        vectors = load_json("docs/contracts/vectors/interface-evidence-v1.json")
        self.assertIn("utf8BoundaryCases", vectors)
        cases = vectors["utf8BoundaryCases"]
        self.assertEqual(4, len(cases))
        self.assertEqual({256, 257, 4096, 4097}, {case["utf8Bytes"] for case in cases})
        self.assertTrue(
            all(case["recalculateStoredFingerprints"] is True for case in cases)
        )

    def test_interface_utf8_boundaries_are_executable_after_recalculation(self) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        self.assertTrue(
            hasattr(oracle, "validate_interface_utf8_boundary_cases"),
            "нет внешней проверки UTF-8",
        )
        if importlib.util.find_spec("jsonschema") is None:
            with self.assertRaises(ModuleNotFoundError):
                oracle.validate_interface_utf8_boundary_cases(ROOT)
        else:
            summary = oracle.validate_interface_utf8_boundary_cases(ROOT)
            self.assertEqual((4, 4), (summary.passed, summary.total))


class Task1Cycle6RegressionTests(unittest.TestCase):
    @staticmethod
    def _reader_context() -> dict[str, object]:
        return {
            "profileCase": "reader",
            "selectedPair": {
                "model": "gpt-5.6-luna",
                "reasoningEffort": "medium",
            },
        }

    def _evaluate(self, requirements: object, **envelope_neighbors: object):
        from scripts import validate_task1_contract_vectors as oracle

        envelope = {"requirements": requirements, **envelope_neighbors}
        return oracle.evaluate_config_requirements(
            {"kind": "parsed", "value": envelope},
            self._reader_context(),
            root=ROOT,
        )

    @staticmethod
    def _empty_hooks() -> dict[str, object]:
        return {
            "PermissionRequest": [],
            "PostCompact": [],
            "PostToolUse": [],
            "PreCompact": [],
            "PreToolUse": [],
            "SessionStart": [],
            "Stop": [],
            "SubagentStart": [],
            "SubagentStop": [],
            "UserPromptSubmit": [],
        }

    def test_config_envelope_requires_requirements_but_ignores_neighbors(self) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        missing = oracle.evaluate_config_requirements(
            {"kind": "parsed", "value": {"diagnostic": "ignored"}},
            self._reader_context(),
            root=ROOT,
        )
        self.assertEqual(
            {
                "status": "rejected",
                "phase": "envelope",
                "errorCode": "MANAGED_REQUIREMENT_MALFORMED",
            },
            missing.normalization,
        )
        with_neighbor = self._evaluate({}, diagnostic={"newServerField": True})
        self.assertEqual("complete", with_neighbor.normalization["status"])
        self.assertEqual({}, with_neighbor.normalization["normalized"])

    def test_recursive_unknown_fields_are_unsupported(self) -> None:
        unknown_values = {
            "computer-use": {"computerUse": {"future": True}},
            "models": {"models": {"future": {}}},
            "new-thread": {"models": {"newThread": {"future": "x"}}},
            "network": {"network": {"future": True}},
            "hooks-root": {"hooks": {**self._empty_hooks(), "future": []}},
            "hook-group": {
                "hooks": {
                    **self._empty_hooks(),
                    "Stop": [{"hooks": [], "future": True}],
                }
            },
            "hook-handler": {
                "hooks": {
                    **self._empty_hooks(),
                    "Stop": [{"hooks": [{"type": "prompt", "future": True}]}],
                }
            },
        }
        for name, requirements in unknown_values.items():
            with self.subTest(name=name):
                actual = self._evaluate(requirements)
                self.assertEqual(
                    {
                        "status": "rejected",
                        "phase": "structure",
                        "errorCode": "MANAGED_REQUIREMENT_UNSUPPORTED",
                    },
                    actual.normalization,
                )

    def test_recursive_wrong_types_and_enums_are_malformed(self) -> None:
        malformed_values = {
            "top-boolean": {"allowAppshots": "false"},
            "computer-use-boolean": {
                "computerUse": {"allowLockedComputerUse": "false"}
            },
            "new-thread-model": {"models": {"newThread": {"model": 1}}},
            "network-domain-enum": {"network": {"domains": {"example.test": "future"}}},
            "hook-handler-kind": {
                "hooks": {
                    **self._empty_hooks(),
                    "Stop": [{"hooks": [{"type": "future"}]}],
                }
            },
        }
        for name, requirements in malformed_values.items():
            with self.subTest(name=name):
                actual = self._evaluate(requirements)
                self.assertEqual(
                    {
                        "status": "rejected",
                        "phase": "structure",
                        "errorCode": "MANAGED_REQUIREMENT_MALFORMED",
                    },
                    actual.normalization,
                )

    def test_granular_requires_three_base_flags_and_adds_only_two_defaults(
        self,
    ) -> None:
        base = {
            "mcp_elicitations": False,
            "rules": False,
            "sandbox_approval": False,
        }
        for missing in tuple(base):
            with self.subTest(missing=missing):
                incomplete = dict(base)
                del incomplete[missing]
                actual = self._evaluate(
                    {"allowedApprovalPolicies": [{"granular": incomplete}]}
                )
                self.assertEqual("rejected", actual.normalization["status"])
                self.assertEqual(
                    "MANAGED_REQUIREMENT_MALFORMED", actual.normalization["errorCode"]
                )

        complete = self._evaluate(
            {"allowedApprovalPolicies": [{"granular": dict(base)}]}
        )
        granular = complete.normalization["normalized"]["allowedApprovalPolicies"][0][
            "granular"
        ]
        self.assertEqual(
            {
                **base,
                "request_permissions": False,
                "skill_approval": False,
            },
            granular,
        )
        unknown = self._evaluate(
            {"allowedApprovalPolicies": [{"granular": {**base, "future": False}}]}
        )
        self.assertEqual(
            "MANAGED_REQUIREMENT_UNSUPPORTED", unknown.normalization["errorCode"]
        )

    def test_network_canonical_and_legacy_forms_compare_allow_and_deny_sets(
        self,
    ) -> None:
        matching = self._evaluate(
            {
                "network": {
                    "domains": {
                        "allow.test": "allow",
                        "deny.test": "deny",
                    },
                    "allowedDomains": ["allow.test"],
                    "deniedDomains": ["deny.test"],
                }
            }
        )
        self.assertEqual("complete", matching.normalization["status"])

        for name, network in {
            "allow-conflict": {
                "domains": {"allow.test": "allow"},
                "allowedDomains": [],
            },
            "deny-conflict": {
                "domains": {"deny.test": "deny"},
                "deniedDomains": [],
            },
        }.items():
            with self.subTest(name=name):
                actual = self._evaluate({"network": network})
                self.assertEqual(
                    {
                        "status": "rejected",
                        "phase": "normalization",
                        "errorCode": "MANAGED_REQUIREMENT_MALFORMED",
                    },
                    actual.normalization,
                )

        matching_socket = self._evaluate(
            {
                "network": {
                    "unixSockets": {"/private/allowed.sock": "allow"},
                    "allowUnixSockets": ["/private/allowed.sock"],
                }
            }
        )
        self.assertEqual("complete", matching_socket.normalization["status"])
        socket_conflict = self._evaluate(
            {
                "network": {
                    "unixSockets": {"/private/allowed.sock": "allow"},
                    "allowUnixSockets": [],
                }
            }
        )
        self.assertEqual(
            "MANAGED_REQUIREMENT_MALFORMED",
            socket_conflict.normalization["errorCode"],
        )

    def test_config_unhashable_and_non_json_values_are_malformed_not_exceptions(
        self,
    ) -> None:
        malformed = (
            {"network": {"domains": {"example.test": []}}},
            {
                "hooks": {
                    **self._empty_hooks(),
                    "Stop": [{"hooks": [{"type": []}]}],
                }
            },
            {1: True},
            {"defaultPermissions": "\ud800"},
        )
        for requirements in malformed:
            with self.subTest(requirements=repr(requirements)):
                actual = self._evaluate(requirements)
                self.assertEqual(
                    {
                        "status": "rejected",
                        "phase": "structure",
                        "errorCode": "MANAGED_REQUIREMENT_MALFORMED",
                    },
                    actual.normalization,
                )

    def test_config_invalid_source_wrappers_are_envelope_malformed(self) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        for source in (
            7,
            [{"kind": "parsed", "value": {}}],
            {"kind": [], "value": {}},
        ):
            with self.subTest(source=repr(source)):
                actual = oracle.evaluate_config_requirements(
                    source,
                    self._reader_context(),
                    root=ROOT,
                )
                self.assertEqual(
                    {
                        "status": "rejected",
                        "phase": "envelope",
                        "errorCode": "MANAGED_REQUIREMENT_MALFORMED",
                    },
                    actual.normalization,
                )

    def test_all_normative_compatibility_rejections_compare_normalized_artifacts(
        self,
    ) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        incompatible_values = {
            "default-permissions": {"defaultPermissions": "codex-smart-writer"},
            "service-tier": {"models": {"newThread": {"serviceTier": "priority"}}},
            "residency": {"enforceResidency": "us"},
            "network-enabled": {"network": {"enabled": True}},
            "network-http-port": {"network": {"httpPort": 1}},
            "network-socks-port": {"network": {"socksPort": 1}},
            "network-local-binding": {"network": {"allowLocalBinding": True}},
            "network-upstream-proxy": {"network": {"allowUpstreamProxy": True}},
            "network-all-unix-sockets": {
                "network": {"dangerouslyAllowAllUnixSockets": True}
            },
            "network-non-loopback-proxy": {
                "network": {"dangerouslyAllowNonLoopbackProxy": True}
            },
        }
        for name, requirements in incompatible_values.items():
            with self.subTest(name=name):
                actual = self._evaluate(requirements)
                self.assertEqual("complete", actual.normalization["status"])
                normalized = actual.normalization["normalized"]
                self.assertEqual(
                    oracle.canonical_json_v1(normalized),
                    actual.normalization["canonicalUtf8"],
                )
                self.assertEqual(
                    oracle.domain_fingerprint(oracle.REQUIREMENTS_DOMAIN, normalized),
                    actual.normalization["fingerprint"],
                )
                self.assertEqual(
                    {
                        "status": "rejected",
                        "errorCode": "MANAGED_REQUIREMENT_INCOMPATIBLE",
                    },
                    actual.compatibility,
                )

    def test_permissive_booleans_do_not_force_disabled_features_on(self) -> None:
        for name, requirements in {
            "appshots": {"allowAppshots": True},
            "remote-control": {"allowRemoteControl": True},
            "computer-use": {"computerUse": {"allowLockedComputerUse": True}},
        }.items():
            with self.subTest(name=name):
                actual = self._evaluate(requirements)
                self.assertEqual("complete", actual.normalization["status"])
                self.assertEqual({"status": "compatible"}, actual.compatibility)

    def test_config_utf8_field_and_property_name_limits_run_in_evaluator(self) -> None:
        at_limit = "é" * 2_048
        over_limit = at_limit + "a"
        self.assertEqual(4_096, len(at_limit.encode("utf-8")))
        self.assertEqual(4_097, len(over_limit.encode("utf-8")))

        self.assertEqual(
            "complete",
            self._evaluate({"defaultPermissions": at_limit}).normalization["status"],
        )
        self.assertEqual(
            "MANAGED_REQUIREMENT_MALFORMED",
            self._evaluate({"defaultPermissions": over_limit}).normalization[
                "errorCode"
            ],
        )
        self.assertEqual(
            "complete",
            self._evaluate(
                {"allowedPermissionProfiles": {at_limit: False}}
            ).normalization["status"],
        )
        self.assertEqual(
            "MANAGED_REQUIREMENT_MALFORMED",
            self._evaluate(
                {"allowedPermissionProfiles": {over_limit: False}}
            ).normalization["errorCode"],
        )

    def test_multibyte_recipe_calls_real_config_evaluator_for_both_sides(self) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        observed_values: list[int] = []
        observed_property_names: list[int] = []
        original = oracle.evaluate_config_requirements

        def tracked(source, context, *, root=ROOT, **kwargs):
            value = source.get("value") if isinstance(source, dict) else None
            if isinstance(value, dict):
                requirements = value.get("requirements", value)
                if (
                    isinstance(requirements, dict)
                    and "defaultPermissions" in requirements
                ):
                    observed_values.append(
                        len(requirements["defaultPermissions"].encode("utf-8"))
                    )
                permission_profiles = (
                    requirements.get("allowedPermissionProfiles")
                    if isinstance(requirements, dict)
                    else None
                )
                if isinstance(permission_profiles, dict):
                    observed_property_names.extend(
                        len(name.encode("utf-8")) for name in permission_profiles
                    )
            return original(source, context, root=root, **kwargs)

        with mock.patch.object(
            oracle, "evaluate_config_requirements", side_effect=tracked
        ):
            oracle.validate_config_recipe_cases(ROOT)
        self.assertIn(4_096, observed_values)
        self.assertIn(4_097, observed_values)
        self.assertIn(4_096, observed_property_names)
        self.assertIn(4_097, observed_property_names)

    def test_trusted_launch_rejects_closed_schema_and_result_file_counterexamples(
        self,
    ) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        vectors = load_json("docs/contracts/vectors/child-profile-v1.json")
        fixture = vectors["concreteLaunch"]["positiveRoles"]["reader"]
        context = fixture["trustedContext"]
        binding = fixture["binding"]
        self.assertTrue(
            oracle.verify_trusted_launch_context(binding, context, root=ROOT)
        )

        extra_context = json.loads(json.dumps(context))
        extra_context["future"] = True
        self.assertFalse(
            oracle.verify_trusted_launch_context(binding, extra_context, root=ROOT)
        )

        missing_version = json.loads(json.dumps(context))
        del missing_version["schemaVersion"]
        self.assertFalse(
            oracle.verify_trusted_launch_context(binding, missing_version, root=ROOT)
        )

        boolean_context_version = json.loads(json.dumps(context))
        boolean_context_version["schemaVersion"] = True
        self.assertFalse(
            oracle.verify_trusted_launch_context(
                binding, boolean_context_version, root=ROOT
            )
        )

        boolean_binding_version = json.loads(json.dumps(binding))
        boolean_binding_version["schemaVersion"] = True
        self.assertFalse(
            oracle.verify_trusted_launch_context(
                boolean_binding_version, context, root=ROOT
            )
        )

        extra_binding = json.loads(json.dumps(binding))
        extra_binding["future"] = True
        self.assertFalse(
            oracle.verify_trusted_launch_context(extra_binding, context, root=ROOT)
        )

        foreign_context = json.loads(json.dumps(context))
        foreign_context["resultSchemaPath"] = (
            "/private/schemas/writer-result-v1.schema.json"
        )
        foreign_binding = oracle.materialize_launch_binding(
            "reader", foreign_context, root=ROOT
        )
        self.assertFalse(
            oracle.verify_trusted_launch_context(
                foreign_binding, foreign_context, root=ROOT
            )
        )

        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            for relative in (
                "docs/contracts/vectors/child-profile-v1.json",
                "docs/contracts/vectors/interface-evidence-v1.json",
                "docs/contracts/schemas/child-profile-v1.schema.json",
            ):
                destination = temporary_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            self.assertFalse(
                oracle.verify_trusted_launch_context(
                    binding,
                    context,
                    root=temporary_root,
                )
            )

        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            for relative in (
                "docs/contracts/vectors/child-profile-v1.json",
                "docs/contracts/vectors/interface-evidence-v1.json",
                "docs/contracts/schemas/writer-result-v1.schema.json",
            ):
                destination = temporary_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            child_path = temporary_root / "docs/contracts/vectors/child-profile-v1.json"
            poisoned = json.loads(child_path.read_text(encoding="utf-8"))
            reader_case = next(
                case for case in poisoned["cases"] if case["name"] == "reader"
            )
            reader_case["profile"]["resultSchemaId"] = "writer-result-v1"
            child_path.write_text(
                json.dumps(poisoned, ensure_ascii=False), encoding="utf-8"
            )
            poisoned_context = json.loads(json.dumps(context))
            poisoned_context["resultSchemaPath"] = (
                "/private/schemas/writer-result-v1.schema.json"
            )
            poisoned_binding = oracle.materialize_launch_binding(
                "reader", poisoned_context, root=temporary_root
            )
            self.assertFalse(
                oracle.verify_trusted_launch_context(
                    poisoned_binding,
                    poisoned_context,
                    root=temporary_root,
                )
            )

    def test_virtual_result_schema_path_has_closed_machine_resolution(self) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        vectors = load_json("docs/contracts/vectors/child-profile-v1.json")
        self.assertEqual(
            {
                "virtualRoot": "/private/schemas",
                "repositoryRoot": "docs/contracts/schemas",
            },
            vectors["resultSchemaResolution"],
        )
        fixture = vectors["concreteLaunch"]["positiveRoles"]["reader"]
        logical_path = Path(fixture["trustedContext"]["resultSchemaPath"])
        self.assertFalse(logical_path.is_file())
        resolved = oracle.resolve_trusted_result_schema_path(
            "reader", fixture["trustedContext"], root=ROOT
        )
        self.assertEqual(
            (ROOT / "docs/contracts/schemas/reader-result-v1.schema.json").resolve(),
            resolved,
        )
        self.assertTrue(resolved.is_file())
        self.assertTrue(
            oracle.verify_trusted_launch_context(
                fixture["binding"], fixture["trustedContext"], root=ROOT
            )
        )

    def test_trusted_launch_contract_names_both_closed_environment_objects(
        self,
    ) -> None:
        document = (ROOT / "docs/contracts/codex-interface-v1.md").read_text(
            encoding="utf-8"
        )
        start = document.index("`TrustedLaunchContextV1`")
        section = document[start : document.index("Читающий профиль", start)]
        for required in (
            "environmentSlotValues",
            "secretSlotFingerprints",
            "snapshotRoot",
            "codexHome",
            "codexSqliteHome",
            "home",
            "tmpDir",
            "otelEndpoint",
            "workspaceRoot",
            "otelHeaders",
            "все и только",
        ):
            self.assertIn(required, section)

    def test_bare_python_path_keeps_recursive_config_classification(self) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        source = {
            "kind": "parsed",
            "value": {"requirements": {"network": {"future": True}}},
        }
        baseline = oracle.evaluate_config_requirements(
            source,
            self._reader_context(),
            root=ROOT,
        )
        with mock.patch.object(
            oracle,
            "_jsonschema_validator",
            side_effect=ModuleNotFoundError("jsonschema unavailable"),
        ):
            without_jsonschema = oracle.evaluate_config_requirements(
                source,
                self._reader_context(),
                root=ROOT,
            )
        self.assertEqual(baseline, without_jsonschema)
        self.assertEqual(
            "MANAGED_REQUIREMENT_UNSUPPORTED", baseline.normalization["errorCode"]
        )

    def test_no_open_validator_silently_weakens_without_jsonschema(self) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        with mock.patch.object(
            oracle,
            "_jsonschema_validator",
            side_effect=ModuleNotFoundError("jsonschema unavailable"),
        ) as dependency:
            successful = self._evaluate({})
            self.assertEqual("complete", successful.normalization["status"])
            dependency.assert_not_called()
            for validator, expected in (
                (oracle.validate_config_recipe_cases, (23, 23)),
                (oracle.validate_routing_cases, (9, 9)),
            ):
                summary = validator(ROOT)
                self.assertEqual(expected, (summary.passed, summary.total))
            for validator in (
                oracle.validate_config_requirement_cases,
                oracle.validate_environment_binding_cases,
                oracle.validate_child_profile_cases,
                oracle.validate_interface_utf8_boundary_cases,
            ):
                with self.assertRaises(ModuleNotFoundError):
                    validator(ROOT)

    def test_internal_recipe_validation_rejects_const_poisoning(self) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            for relative in (
                "docs/contracts/vectors/config-requirements-vector-recipes-v1.json",
                "docs/contracts/vectors/config-requirements-v1.json",
                "docs/contracts/schemas/config-requirements-vector-recipe-v1.schema.json",
            ):
                destination = temporary_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            vector_path = (
                temporary_root
                / "docs/contracts/vectors/config-requirements-vector-recipes-v1.json"
            )
            poisoned = json.loads(vector_path.read_text(encoding="utf-8"))
            poisoned["future"] = True
            vector_path.write_text(
                json.dumps(poisoned, ensure_ascii=False), encoding="utf-8"
            )
            with self.assertRaisesRegex(AssertionError, "exact schema const"):
                oracle.validate_config_recipe_cases(temporary_root)

    def test_oracle_mutants_use_real_always_compatible_and_always_utf8_computations(
        self,
    ) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        vectors = load_json("docs/contracts/vectors/interface-evidence-v1.json")
        no_op_case = next(
            case
            for case in vectors["oracleMutantCases"]
            if case["name"] == "interface-no-op-accepted"
        )
        self.assertEqual(
            {"name", "operation", "expected"},
            set(no_op_case),
        )
        self.assertEqual(
            no_op_case["operation"]["before"],
            no_op_case["operation"]["value"],
        )
        self.assertEqual({"kind": "operation-invalid"}, no_op_case["expected"])

        results = oracle.oracle_mutant_results(ROOT)
        self.assertEqual(22, len(results))
        self.assertNotIn("config-evaluator-coupled-to-expected", results)
        self.assertTrue(results["config-always-compatible"])
        self.assertTrue(results["interface-always-utf8-valid"])

    def test_cycle6_regression_counters_are_explicit(self) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        output = io.StringIO()
        with (
            mock.patch.object(
                oracle,
                "validate_environment_binding_cases",
                return_value=oracle.CheckSummary(passed=11, total=11),
            ),
            redirect_stdout(output),
        ):
            result = oracle.main(["--config", "--environment", "--mutants"])
        self.assertEqual(0, result)
        rendered = output.getvalue()
        self.assertRegex(rendered, r"config-cycle6-regressions=\d+/\d+")
        self.assertIn("trusted-launch-regressions=4/4", rendered)
        self.assertIn("oracle-mutants=22/22", rendered)


class Task1Cycle7RegressionTests(unittest.TestCase):
    @staticmethod
    def _reader_context() -> dict[str, object]:
        return {
            "profileCase": "reader",
            "selectedPair": {
                "model": "gpt-5.6-luna",
                "reasoningEffort": "medium",
            },
        }

    def _evaluate_source(self, source: object):
        from scripts import validate_task1_contract_vectors as oracle

        return oracle.evaluate_config_requirements(
            source,
            self._reader_context(),
            root=ROOT,
        )

    def assert_malformed_input(self, source: object) -> None:
        actual = self._evaluate_source(source)
        self.assertEqual(
            {
                "status": "not-run",
            },
            actual.compatibility,
        )
        self.assertEqual("rejected", actual.normalization["status"])
        self.assertEqual(
            "MANAGED_REQUIREMENT_MALFORMED",
            actual.normalization["errorCode"],
        )

    def test_granular_optional_null_absent_and_false_materialize_before_dedup(
        self,
    ) -> None:
        base = {
            "mcp_elicitations": False,
            "rules": False,
            "sandbox_approval": False,
        }
        expected_granular = {
            **base,
            "request_permissions": False,
            "skill_approval": False,
        }
        for name, optional in {
            "absent": {},
            "null": {
                "request_permissions": None,
                "skill_approval": None,
            },
            "false": {
                "request_permissions": False,
                "skill_approval": False,
            },
        }.items():
            with self.subTest(name=name):
                actual = self._evaluate_source(
                    {
                        "kind": "parsed",
                        "value": {
                            "requirements": {
                                "allowedApprovalPolicies": [
                                    "never",
                                    {"granular": {**base, **optional}},
                                ]
                            }
                        },
                    }
                )
                self.assertEqual("complete", actual.normalization["status"])
                self.assertEqual("compatible", actual.compatibility["status"])
                self.assertEqual(
                    expected_granular,
                    next(
                        policy["granular"]
                        for policy in actual.normalization["normalized"][
                            "allowedApprovalPolicies"
                        ]
                        if isinstance(policy, dict)
                    ),
                )

        deduplicated = self._evaluate_source(
            {
                "kind": "parsed",
                "value": {
                    "requirements": {
                        "allowedApprovalPolicies": [
                            "never",
                            {"granular": dict(base)},
                            {
                                "granular": {
                                    **base,
                                    "request_permissions": False,
                                    "skill_approval": False,
                                }
                            },
                        ]
                    }
                },
            }
        )
        self.assertEqual("complete", deduplicated.normalization["status"])
        self.assertEqual("compatible", deduplicated.compatibility["status"])
        self.assertEqual(
            ["never", {"granular": expected_granular}],
            deduplicated.normalization["normalized"]["allowedApprovalPolicies"],
        )

    def test_parsed_and_raw_envelope_neighbors_share_one_mebibyte_limit(self) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        empty_envelope = {"requirements": {}, "future": ""}
        overhead = len(oracle.canonical_json_v1(empty_envelope).encode("utf-8"))
        envelope = {
            "requirements": {},
            "future": "x" * (oracle.RAW_DOCUMENT_BYTES_MAX + 1 - overhead),
        }
        raw = oracle.canonical_json_v1(envelope)
        self.assertEqual(
            oracle.RAW_DOCUMENT_BYTES_MAX + 1,
            len(raw.encode("utf-8")),
        )
        for kind, value in (("parsed", envelope), ("raw-utf8", raw)):
            with self.subTest(kind=kind):
                self.assert_malformed_input({"kind": kind, "value": value})

    def test_raw_lone_surrogate_is_malformed_not_an_exception(self) -> None:
        self.assert_malformed_input(
            {
                "kind": "raw-utf8",
                "value": '{"requirements":{},"future":"\ud800"}',
            }
        )

    def test_parsed_and_raw_depth_1100_are_malformed_not_recursion_errors(self) -> None:
        nested: object = None
        for _ in range(1_100):
            nested = {"x": nested}
        parsed = {"requirements": {}, "future": nested}
        raw = (
            '{"requirements":{},"future":'
            + '{"x":' * 1_100
            + "null"
            + "}" * 1_100
            + "}"
        )
        for kind, value in (("parsed", parsed), ("raw-utf8", raw)):
            with self.subTest(kind=kind):
                self.assert_malformed_input({"kind": kind, "value": value})

    def test_raw_5000_digit_integer_is_malformed_not_a_value_error(self) -> None:
        self.assert_malformed_input(
            {
                "kind": "raw-utf8",
                "value": '{"requirements":{},"future":' + "9" * 5_000 + "}",
            }
        )

    def test_parsed_cycle_guards_terminate_before_unbounded_traversal(self) -> None:
        probes = {
            "self-dict": ("container = {}\ncontainer['self'] = container\n"),
            "self-list": ("container = []\ncontainer.append(container)\n"),
            "late-cycle-after-node-limit": (
                "container = []\n"
                "container.append(container)\n"
                "container.extend([None] * 4097)\n"
            ),
        }
        for name, construction in probes.items():
            with self.subTest(name=name):
                program = (
                    "from scripts import validate_task1_contract_vectors as oracle\n"
                    + construction
                    + "actual = oracle.evaluate_config_requirements(\n"
                    "    {'kind': 'parsed', 'value': {\n"
                    "        'requirements': {}, 'future': container,\n"
                    "    }},\n"
                    "    {\n"
                    "        'profileCase': 'reader',\n"
                    "        'selectedPair': {\n"
                    "            'model': 'gpt-5.6-luna',\n"
                    "            'reasoningEffort': 'medium',\n"
                    "        },\n"
                    "    },\n"
                    ")\n"
                    "expected_normalization = {\n"
                    "    'status': 'rejected',\n"
                    "    'phase': 'raw-guards',\n"
                    "    'errorCode': 'MANAGED_REQUIREMENT_MALFORMED',\n"
                    "}\n"
                    "if (actual.normalization != expected_normalization\n"
                    "        or actual.compatibility != {'status': 'not-run'}):\n"
                    "    raise SystemExit(repr(actual))\n"
                    "print('ok')\n"
                )
                completed = subprocess.run(
                    [sys.executable, "-c", program],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    timeout=2,
                    check=False,
                )
                self.assertEqual(
                    0,
                    completed.returncode,
                    completed.stdout + completed.stderr,
                )
                self.assertEqual("ok", completed.stdout.strip())

    def test_input_classification_does_not_hide_internal_oracle_errors(self) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        def broken_normalizer(_requirements: object) -> object:
            raise RuntimeError("internal oracle failure")

        ops = oracle._ConfigOps(
            normalize=broken_normalizer,
            validate_normalized=oracle._DEFAULT_CONFIG_OPS.validate_normalized,
            compatibility=oracle._DEFAULT_CONFIG_OPS.compatibility,
        )
        with self.assertRaisesRegex(RuntimeError, "internal oracle failure"):
            oracle._evaluate_config_requirements(
                {"kind": "parsed", "value": {"requirements": {}}},
                self._reader_context(),
                root=ROOT,
                ops=ops,
            )

    def test_mutant_detector_has_four_direct_calibration_scenarios(self) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        def raises() -> tuple[object, bool]:
            raise RuntimeError("calibration failure")

        scenarios = [
            (
                oracle._MutantSpec("equal-invoked", "same", lambda: ("same", True)),
                False,
            ),
            (
                oracle._MutantSpec(
                    "different-not-invoked", "expected", lambda: ("actual", False)
                ),
                False,
            ),
            (oracle._MutantSpec("exception", "expected", raises), False),
            (
                oracle._MutantSpec(
                    "different-invoked", "expected", lambda: ("actual", True)
                ),
                True,
            ),
        ]
        self.assertEqual(
            [expected for _, expected in scenarios],
            [oracle._mutant_detected(spec) for spec, _ in scenarios],
        )

    def test_full_mutant_run_self_calibrates_detector_semantics(self) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        self.assertTrue(hasattr(oracle, "validate_mutant_detector_calibration"))
        summary = oracle.validate_mutant_detector_calibration()
        self.assertEqual((4, 4), (summary.passed, summary.total))
        with mock.patch.object(oracle, "_mutant_detected", return_value=True):
            with self.assertRaises(AssertionError):
                oracle.main(["--mutants"])

    def test_expected_poisoning_precedes_second_evaluation_and_catches_coupling(
        self,
    ) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        self.assertTrue(hasattr(oracle, "validate_config_expected_independence"))
        summary = oracle.validate_config_expected_independence(ROOT)
        self.assertEqual((2, 2), (summary.passed, summary.total))

        real_evaluator = oracle.evaluate_config_requirements

        def selectively_coupled(
            source: object,
            context: dict[str, object],
            *,
            root: Path = ROOT,
        ):
            vectors = oracle.load_json(
                root / "docs/contracts/vectors/config-requirements-v1.json"
            )
            case = next(
                item
                for item in vectors["cases"]
                if item["name"] == "requirements-empty"
            )
            if source == case["source"]:
                return oracle.ConfigEvaluation(
                    normalization=json.loads(
                        json.dumps(case["expected"]["normalization"])
                    ),
                    compatibility=json.loads(
                        json.dumps(case["expected"]["compatibility"])
                    ),
                )
            return real_evaluator(source, context, root=root)

        with mock.patch.object(
            oracle,
            "evaluate_config_requirements",
            side_effect=selectively_coupled,
        ):
            with self.assertRaises(AssertionError):
                oracle.validate_config_expected_independence(ROOT)

    def test_cycle7_machine_cases_and_counters_are_explicit(self) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        vectors = load_json("docs/contracts/vectors/config-requirements-v1.json")
        expected_names = {
            "granular-optional-absent",
            "granular-optional-null",
            "granular-optional-false",
            "granular-equivalent-deduplicates",
            "envelope-parsed-1048577-bytes",
            "envelope-raw-1048577-bytes",
            "raw-lone-surrogate",
            "envelope-parsed-depth-1100",
            "envelope-raw-depth-1100",
            "raw-5000-digit-integer",
        }
        self.assertEqual(
            expected_names,
            {case["name"] for case in vectors["cycle7Cases"]},
        )
        output = io.StringIO()
        with redirect_stdout(output):
            result = oracle.main(["--config", "--mutants"])
        self.assertEqual(0, result)
        rendered = output.getvalue()
        self.assertIn("config-cycle7-regressions=10/10", rendered)
        self.assertIn("mutant-detector-calibration=4/4", rendered)

    def test_config_vector_root_is_closed_and_versioned(self) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        vectors = load_json("docs/contracts/vectors/config-requirements-v1.json")
        self.assertEqual(
            {
                "schemaVersion",
                "contexts",
                "cycle7Cases",
                "cycle8Cases",
                "cases",
            },
            set(vectors),
        )
        self.assertEqual(1, vectors["schemaVersion"])
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            for relative in (
                "docs/contracts/vectors/config-requirements-v1.json",
                "docs/contracts/vectors/child-profile-v1.json",
            ):
                destination = temporary_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            path = temporary_root / "docs/contracts/vectors/config-requirements-v1.json"
            poisoned = json.loads(path.read_text(encoding="utf-8"))
            poisoned["future"] = True
            path.write_text(json.dumps(poisoned, ensure_ascii=False), encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "root is not exact"):
                oracle.validate_config_requirement_cases(temporary_root)

    def test_cycle7_contract_defines_envelope_bytes_and_granular_order(self) -> None:
        document = (ROOT / "docs/contracts/codex-interface-v1.md").read_text(
            encoding="utf-8"
        )
        for required in (
            "длина UTF-8 представления `canonical-json-v1` всей проверенной оболочки",
            "исходных байтов UTF-8 `raw-utf8`",
            "до дедупликации",
            "явный `null` нормализуются в `false`",
            "Циклическая ссылка контейнера",
            "в `parsed` даёт `MANAGED_REQUIREMENT_MALFORMED`",
            "при первом доказанном превышении",
        ):
            self.assertIn(required, document)


class Task1Cycle8RegressionTests(unittest.TestCase):
    FINITE_SETS = (
        ("allowedApprovalPolicies", "never"),
        ("allowedApprovalsReviewers", "user"),
        ("allowedSandboxModes", "read-only"),
        ("allowedWebSearchModes", "disabled"),
        ("allowedWindowsSandboxImplementations", "unelevated"),
    )

    @staticmethod
    def _reader_context() -> dict[str, object]:
        return {
            "profileCase": "reader",
            "selectedPair": {
                "model": "gpt-5.6-luna",
                "reasoningEffort": "medium",
            },
        }

    def _evaluate(self, requirements: object):
        from scripts import validate_task1_contract_vectors as oracle

        return oracle.evaluate_config_requirements(
            {"kind": "parsed", "value": {"requirements": requirements}},
            self._reader_context(),
            root=ROOT,
        )

    def assert_malformed(
        self, requirements: object, *, phase: str | None = None
    ) -> None:
        actual = self._evaluate(requirements)
        self.assertEqual("rejected", actual.normalization["status"])
        self.assertEqual(
            "MANAGED_REQUIREMENT_MALFORMED",
            actual.normalization["errorCode"],
        )
        if phase is not None:
            self.assertEqual(phase, actual.normalization["phase"])
        self.assertEqual({"status": "not-run"}, actual.compatibility)

    def test_five_finite_sets_deduplicate_2049_valid_repetitions(self) -> None:
        for field, value in self.FINITE_SETS:
            with self.subTest(field=field):
                actual = self._evaluate({field: [value] * 2_049})
                self.assertEqual("complete", actual.normalization["status"])
                self.assertEqual("compatible", actual.compatibility["status"])
                self.assertEqual(
                    [value],
                    actual.normalization["normalized"][field],
                )

    def test_finite_sets_still_reject_unknown_invalid_and_common_over_limit(
        self,
    ) -> None:
        for field, value in self.FINITE_SETS:
            with self.subTest(field=field, case="unknown"):
                self.assert_malformed({field: ["future-value"]})
            with self.subTest(field=field, case="invalid-type"):
                self.assert_malformed({field: [value, 7]})
            with self.subTest(field=field, case="raw-tree-over-limit"):
                self.assert_malformed(
                    {field: [value] * 4_094},
                    phase="raw-guards",
                )

    def test_arbitrary_string_sets_and_maps_keep_2048_member_limit(self) -> None:
        self.assert_malformed(
            {"network": {"allowedDomains": ["example.invalid"] * 2_049}}
        )
        self.assert_malformed(
            {
                "allowedPermissionProfiles": {
                    f"profile-{index:04d}": True for index in range(2_049)
                }
            }
        )

    def test_cycle8_machine_cases_root_counter_and_contract_are_explicit(self) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        vectors = load_json("docs/contracts/vectors/config-requirements-v1.json")
        expected_cases = [
            {
                "name": "allowed-approval-policies-repeat-2049",
                "field": "allowedApprovalPolicies",
                "value": "never",
                "repeatCount": 2_049,
                "expected": {
                    "normalizationStatus": "complete",
                    "compatibilityStatus": "compatible",
                    "normalized": ["never"],
                },
            },
            {
                "name": "allowed-approvals-reviewers-repeat-2049",
                "field": "allowedApprovalsReviewers",
                "value": "user",
                "repeatCount": 2_049,
                "expected": {
                    "normalizationStatus": "complete",
                    "compatibilityStatus": "compatible",
                    "normalized": ["user"],
                },
            },
            {
                "name": "allowed-sandbox-modes-repeat-2049",
                "field": "allowedSandboxModes",
                "value": "read-only",
                "repeatCount": 2_049,
                "expected": {
                    "normalizationStatus": "complete",
                    "compatibilityStatus": "compatible",
                    "normalized": ["read-only"],
                },
            },
            {
                "name": "allowed-web-search-modes-repeat-2049",
                "field": "allowedWebSearchModes",
                "value": "disabled",
                "repeatCount": 2_049,
                "expected": {
                    "normalizationStatus": "complete",
                    "compatibilityStatus": "compatible",
                    "normalized": ["disabled"],
                },
            },
            {
                "name": "allowed-windows-sandbox-implementations-repeat-2049",
                "field": "allowedWindowsSandboxImplementations",
                "value": "unelevated",
                "repeatCount": 2_049,
                "expected": {
                    "normalizationStatus": "complete",
                    "compatibilityStatus": "compatible",
                    "normalized": ["unelevated"],
                },
            },
        ]
        self.assertEqual(expected_cases, vectors["cycle8Cases"])
        self.assertEqual(
            {
                "schemaVersion",
                "contexts",
                "cycle7Cases",
                "cycle8Cases",
                "cases",
            },
            set(vectors),
        )
        self.assertTrue(hasattr(oracle, "validate_config_cycle8_regressions"))
        summary = oracle.validate_config_cycle8_regressions(ROOT)
        self.assertEqual((5, 5), (summary.passed, summary.total))
        output = io.StringIO()
        with redirect_stdout(output):
            result = oracle.main(["--config"])
        self.assertEqual(0, result)
        self.assertIn("config-cycle8-regressions=5/5", output.getvalue())

        document = (ROOT / "docs/contracts/codex-interface-v1.md").read_text(
            encoding="utf-8"
        )
        for required in (
            "Пять конечных разрешительных массивов",
            "не имеют отдельного преднормализационного предела 2048",
            "произвольных строковых множеств и карт остаётся равным 2048",
            "нормализатор канонически сортирует уникальные элементы",
        ):
            self.assertIn(required, document)
        self.assertNotIn("сохраняет порядок первых вхождений", document)


class Task1Cycle9RegressionTests(unittest.TestCase):
    @staticmethod
    def _copy_with_empty_case_name(temporary_root: Path) -> None:
        for relative in (
            "docs/contracts/vectors/config-requirements-v1.json",
            "docs/contracts/vectors/child-profile-v1.json",
            "docs/contracts/schemas/config-requirements-vector-case-v1.schema.json",
        ):
            destination = temporary_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)

        vector_path = (
            temporary_root / "docs/contracts/vectors/config-requirements-v1.json"
        )
        poisoned = json.loads(vector_path.read_text(encoding="utf-8"))
        poisoned_case = next(
            case for case in poisoned["cases"] if case["name"] == "reader-limits"
        )
        poisoned_case["name"] = ""
        vector_path.write_text(
            json.dumps(poisoned, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def test_config_batch_rejects_empty_case_name_using_closed_schema(self) -> None:
        from jsonschema.exceptions import ValidationError

        from scripts import validate_task1_contract_vectors as oracle

        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            self._copy_with_empty_case_name(temporary_root)

            with self.assertRaisesRegex(ValidationError, "should be non-empty"):
                oracle.validate_config_requirement_cases(temporary_root)

    def test_all_config_cases_are_schema_checked_before_first_evaluation(self) -> None:
        from jsonschema.exceptions import ValidationError

        from scripts import validate_task1_contract_vectors as oracle

        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            self._copy_with_empty_case_name(temporary_root)

            with mock.patch.object(
                oracle,
                "evaluate_config_requirements",
                side_effect=AssertionError("evaluator ran before schema preflight"),
            ):
                with self.assertRaisesRegex(ValidationError, "should be non-empty"):
                    oracle.validate_config_requirement_cases(temporary_root)


class Task1Cycle10RegressionTests(unittest.TestCase):
    @staticmethod
    def _copy_config_batch(temporary_root: Path) -> Path:
        for relative in (
            "docs/contracts/vectors/config-requirements-v1.json",
            "docs/contracts/vectors/child-profile-v1.json",
            "docs/contracts/schemas/config-requirements-vector-case-v1.schema.json",
        ):
            destination = temporary_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        return temporary_root / "docs/contracts/vectors/config-requirements-v1.json"

    def test_config_batch_rejects_duplicate_names_before_evaluation(self) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            vector_path = self._copy_config_batch(temporary_root)
            vectors = json.loads(vector_path.read_text(encoding="utf-8"))
            duplicate = next(
                case for case in vectors["cases"] if case["name"] == "reader-limits"
            )
            duplicate["name"] = "writer-limits"
            vector_path.write_text(
                json.dumps(vectors, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )

            real_evaluator = oracle.evaluate_config_requirements
            with mock.patch.object(
                oracle,
                "evaluate_config_requirements",
                wraps=real_evaluator,
            ) as evaluator:
                try:
                    oracle.validate_config_requirement_cases(temporary_root)
                except AssertionError as error:
                    self.assertEqual(
                        "duplicate config case name: writer-limits",
                        str(error),
                    )
                else:
                    self.fail(
                        "duplicate config case name was accepted; "
                        f"evaluator calls={evaluator.call_count}"
                    )
                self.assertEqual(0, evaluator.call_count)

    def test_config_preflight_has_one_factory_and_exact_full_event_order(self) -> None:
        from scripts import validate_task1_contract_vectors as oracle

        vectors = oracle._load_config_vectors_exact(ROOT)
        cases = vectors["cases"]
        expected_names = [case["name"] for case in cases]
        source_names = {id(case["source"]): case["name"] for case in cases}
        expected_schema_path = (
            ROOT
            / "docs/contracts/schemas/config-requirements-vector-case-v1.schema.json"
        )
        factory_paths: list[Path] = []
        events: list[tuple[str, str]] = []
        real_factory = oracle._jsonschema_validator
        real_evaluator = oracle.evaluate_config_requirements

        class TrackedValidator:
            def __init__(self, delegate: object) -> None:
                self.delegate = delegate

            def validate(self, case: dict[str, object]) -> None:
                events.append(("schema", case["name"]))
                self.delegate.validate(case)

        def tracked_factory(schema_path: Path) -> TrackedValidator:
            factory_paths.append(schema_path)
            return TrackedValidator(real_factory(schema_path))

        def tracked_evaluator(
            source: object,
            context: dict[str, object],
            *,
            root: Path = ROOT,
        ):
            events.append(("evaluator", source_names[id(source)]))
            return real_evaluator(source, context, root=root)

        with (
            mock.patch.object(
                oracle,
                "_load_config_vectors_exact",
                return_value=vectors,
            ),
            mock.patch.object(
                oracle,
                "_jsonschema_validator",
                side_effect=tracked_factory,
            ),
            mock.patch.object(
                oracle,
                "evaluate_config_requirements",
                side_effect=tracked_evaluator,
            ),
        ):
            summary = oracle.validate_config_requirement_cases(ROOT)

        self.assertEqual([expected_schema_path], factory_paths)
        self.assertEqual((22, 22), (summary.passed, summary.total))
        self.assertEqual(
            [("schema", name) for name in expected_names]
            + [("evaluator", name) for name in expected_names],
            events,
        )

    def test_contract_requires_unique_names_for_all_22_primary_cases(self) -> None:
        document = (ROOT / "docs/contracts/codex-interface-v1.md").read_text(
            encoding="utf-8"
        )
        normalized_document = " ".join(document.split())
        self.assertIn(
            "Все 22 основных случая имеют непустые уникальные имена; "
            "последующие проверки адресуют их по `name` и не допускают "
            "схлопывания разных случаев.",
            normalized_document,
        )


if __name__ == "__main__":
    unittest.main()
