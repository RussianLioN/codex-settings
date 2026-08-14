from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.activation_transition_rehydration_v2 import (  # noqa: E402
    ActivationTransitionProofSnapshotV2,
    ActivationTransitionRehydrationV2Error,
    rehydrate_activation_transition_proof_v2,
)
from codex_smart_subagents.canonical_json import domain_fingerprint  # noqa: E402
from codex_smart_subagents.lifecycle_operation_v2 import ProjectionV2  # noqa: E402
from codex_smart_subagents import activation_transition_rehydration_v2  # noqa: E402
from tests.smart_subagents import test_activation_transition_v2  # noqa: E402


def _projection_with_value(
    projection: ProjectionV2,
    value: dict[str, object],
    domain: str,
) -> ProjectionV2:
    envelope = {
        "schemaId": projection.schema_id,
        "schemaSha256": projection.schema_sha256,
        "value": copy.deepcopy(value),
    }
    return ProjectionV2(
        schema_id=projection.schema_id,
        schema_sha256=projection.schema_sha256,
        value=envelope["value"],
        value_fingerprint=domain_fingerprint(domain, envelope),
    )


class ActivationTransitionRehydrationV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = test_activation_transition_v2.ActivationTransitionV2Tests(
            methodName="runTest"
        )
        self.fixture.setUp()

    def tearDown(self) -> None:
        self.fixture.tearDown()

    def _snapshot(self) -> ActivationTransitionProofSnapshotV2:
        return ActivationTransitionProofSnapshotV2.from_proof(
            self.fixture.capture(),
            operation_id="op2_" + "a" * 32,
        )

    def test_transition_proof_rehydrates_after_only_device_drift(self) -> None:
        snapshot = self._snapshot()
        original_observe_link = activation_transition_rehydration_v2._observe_link
        original_tree_projection = (
            activation_transition_rehydration_v2._tree_projection
        )
        original_file_projection = (
            activation_transition_rehydration_v2._file_projection
        )

        def observe_link(path: Path):
            projection, _info, target = original_observe_link(path)
            value = dict(projection.value)
            value["parentDevice"] = int(value["parentDevice"]) + 1
            return (
                _projection_with_value(
                    projection,
                    value,
                    "codex-smart/symlink-object/v2",
                ),
                SimpleNamespace(
                    st_dev=snapshot.link_device + 1,
                    st_ino=snapshot.link_inode,
                ),
                target,
            )

        def tree_projection(path: Path) -> dict[str, object]:
            value = dict(original_tree_projection(path))
            if path == snapshot.activation_dir:
                value["device"] = int(value["device"]) + 1
            return value

        def file_projection(path: Path) -> dict[str, object]:
            value = dict(original_file_projection(path))
            if path in {
                snapshot.commit_receipt_path,
                snapshot.installer_receipt_path,
            }:
                value["device"] = int(value["device"]) + 1
            return value

        with (
            mock.patch.object(
                activation_transition_rehydration_v2,
                "_observe_link",
                side_effect=observe_link,
            ),
            mock.patch.object(
                activation_transition_rehydration_v2,
                "_tree_projection",
                side_effect=tree_projection,
            ),
            mock.patch.object(
                activation_transition_rehydration_v2,
                "_file_projection",
                side_effect=file_projection,
            ),
        ):
            proof = rehydrate_activation_transition_proof_v2(snapshot)

        self.assertEqual(
            snapshot.activation_proof_fingerprint,
            proof.proof_fingerprint,
        )

    def test_transition_proof_rejects_stable_tree_non_device_drift(self) -> None:
        snapshot = self._snapshot()
        original_tree_projection = (
            activation_transition_rehydration_v2._tree_projection
        )

        def tree_projection(path: Path) -> dict[str, object]:
            value = dict(original_tree_projection(path))
            if path == snapshot.activation_dir:
                value["inode"] = int(value["inode"]) + 1
            return value

        with mock.patch.object(
            activation_transition_rehydration_v2,
            "_tree_projection",
            side_effect=tree_projection,
        ):
            with self.assertRaisesRegex(
                ActivationTransitionRehydrationV2Error,
                "stable activation tree changed",
            ):
                rehydrate_activation_transition_proof_v2(snapshot)

    def test_transition_proof_rejects_link_inode_drift(self) -> None:
        snapshot = self._snapshot()
        original_observe_link = activation_transition_rehydration_v2._observe_link

        def observe_link(path: Path):
            projection, _info, target = original_observe_link(path)
            value = dict(projection.value)
            value["parentDevice"] = int(value["parentDevice"]) + 1
            return (
                _projection_with_value(
                    projection,
                    value,
                    "codex-smart/symlink-object/v2",
                ),
                SimpleNamespace(
                    st_dev=snapshot.link_device + 1,
                    st_ino=snapshot.link_inode + 1,
                ),
                target,
            )

        with mock.patch.object(
            activation_transition_rehydration_v2,
            "_observe_link",
            side_effect=observe_link,
        ):
            with self.assertRaisesRegex(
                ActivationTransitionRehydrationV2Error,
                "activation_link changed without a durable journal",
            ):
                rehydrate_activation_transition_proof_v2(snapshot)


if __name__ == "__main__":
    unittest.main()
