from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
INSTALLER_PATH = ROOT / "scripts" / "install_adaptive_subagents.py"


def _load_installer(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, INSTALLER_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("installer module cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class FirstInstallCrashMatrixV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.installer = _load_installer("first_install_crash_matrix_v2_installer")

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            dir="/tmp", prefix="cf2-"
        )
        self.root = Path(self.temporary.name).resolve()
        self.codex_home = self.root / "c"
        self.bin_dir = self.root / "b"
        self.codex_home.mkdir(mode=0o700)
        self.bin_dir.mkdir(mode=0o700)
        self.codex_binary = self.root / "codex"
        self.codex_binary.write_text(
            (
                ROOT / "tests" / "smart_subagents" / "test_install_fake_codex.py"
            ).read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        self.codex_binary.chmod(0o700)
        self.layout = self.installer.InstallLayout(
            source_root=ROOT.resolve(),
            codex_home=self.codex_home,
            bin_dir=self.bin_dir,
            codex_binary=self.codex_binary,
            state_home=self.root / "s",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _journal(self) -> dict[str, object]:
        return self.installer._build_first_install_journal_v2(
            self.layout,
            source_digest=self.installer._source_digest(self.layout),
            codex_version="0.144.6",
        )

    def test_outer_intent_closes_one_operation_and_installation_identity(self) -> None:
        journal = self._journal()
        preparation = journal["activationPreparation"]

        self.assertRegex(journal["operationId"], r"^op2_[0-9a-f]{32}$")
        self.assertRegex(journal["installationId"], r"^ins2_[0-9a-f]{32}$")
        self.assertEqual({}, journal["extensions"])
        self.assertEqual(
            hashlib.sha256(self.codex_binary.read_bytes()).hexdigest(),
            journal["codexBinarySha256"],
        )
        self.assertEqual(
            str(
                self.layout.gateway_layout.manifest_root
                / "codex-smart-subagents-v2.activation-preparation.transaction.json"
            ),
            preparation["journalPath"],
        )
        self.assertEqual(
            str(
                self.layout.gateway_layout.receipts_root
                / journal["installationId"]
                / f"{journal['operationId']}.preparation.json"
            ),
            preparation["receiptPath"],
        )

        unsigned = {
            key: value
            for key, value in journal.items()
            if key != "journalFingerprint"
        }
        self.assertEqual(
            self.installer.domain_fingerprint(
                self.installer._FIRST_INSTALL_JOURNAL_DOMAIN,
                unsigned,
            ),
            journal["journalFingerprint"],
        )

    def test_closed_controller_environment_carries_the_outer_identity(self) -> None:
        journal = self._journal()

        environment = self.installer.initial_controller_environment(
            self.layout,
            {},
            first_install_journal=journal,
        )

        self.assertEqual(
            journal["operationId"], environment["CODEX_V2_FIRST_INSTALL_OPERATION_ID"]
        )
        self.assertEqual(
            journal["installationId"],
            environment["CODEX_V2_FIRST_INSTALLATION_ID"],
        )
        self.installer.require_initial_controller_environment(
            self.layout,
            environment,
            first_install_journal=journal,
        )

    def test_entrypoint_config_carries_the_outer_identity_to_health_bootstrap(
        self,
    ) -> None:
        plugin_root = ROOT / "plugins" / "codex-smart-subagents"
        plugin_source = plugin_root / "src"
        sys.path.insert(0, str(plugin_source))
        try:
            from codex_smart_subagents.controller_entrypoint_v2 import (
                load_controller_entrypoint_config_v2,
                start_full_controller_v2,
            )
            from tests.smart_subagents.test_controller_entrypoint_v2 import (
                _Command,
                _Health,
                _Production,
                _decision,
            )
        finally:
            sys.path.remove(str(plugin_source))

        journal = self._journal()
        environment = self.installer.initial_controller_environment(
            self.layout,
            {},
            first_install_journal=journal,
        )
        config = load_controller_entrypoint_config_v2(
            plugin_root=plugin_root,
            environment=environment,
        )
        self.assertEqual(journal["operationId"], config.first_install_operation_id)
        self.assertEqual(journal["installationId"], config.first_installation_id)

        health = _Health(_decision(self.layout.state_home))
        captured: dict[str, object] = {}

        def bootstrapper(**kwargs: object):
            captured.update(kwargs)
            return health

        production = _Production()
        application = start_full_controller_v2(
            config,
            policy_bundle=object(),
            dispatcher_factory=lambda *_args: None,
            bootstrapper=bootstrapper,
            decision_provider=lambda: health.gateway_decision,
            turn_context_loader=lambda _shell: None,
            production_builder=lambda **_kwargs: production,
            command_server_factory=lambda **kwargs: _Command(kwargs["handler"]),
        )
        try:
            self.assertEqual(
                journal["operationId"], captured["first_install_operation_id"]
            )
            self.assertEqual(
                journal["installationId"], captured["first_installation_id"]
            )
        finally:
            application.close()

    def test_health_materialization_uses_the_outer_identity(self) -> None:
        from tests.smart_subagents.test_health_bootstrap_v2 import (
            HealthBootstrapV2Tests,
        )

        journal = self._journal()
        fixture = HealthBootstrapV2Tests(methodName="runTest")
        fixture.setUp()
        try:
            runtime = fixture._bootstrap(
                first_install_operation_id=journal["operationId"],
                first_installation_id=journal["installationId"],
            )
            self.assertEqual(
                journal["operationId"], runtime.materialization.operation_id
            )
            self.assertEqual(
                journal["installationId"], runtime.materialization.installation_id
            )
            manifest = json.loads(
                fixture.layout.manifest_path.read_text(encoding="utf-8")
            )
            self.assertEqual(journal["operationId"], manifest["lastCommittedOperation"])
            self.assertEqual(journal["installationId"], manifest["installationId"])
            preparation_journal = (
                fixture.layout.manifest_root
                / "codex-smart-subagents-v2.activation-preparation.transaction.json"
            )
            preparation_receipt_path = (
                fixture.layout.receipts_root
                / str(journal["installationId"])
                / f"{journal['operationId']}.preparation.json"
            )
            self.assertFalse(preparation_journal.exists())
            preparation_receipt = json.loads(
                preparation_receipt_path.read_text(encoding="utf-8")
            )
            self.assertEqual(journal["operationId"], preparation_receipt["operationId"])
            self.assertEqual(
                journal["installationId"], preparation_receipt["installationId"]
            )
        finally:
            fixture.tearDown()

    def test_health_rejects_an_incomplete_outer_identity(self) -> None:
        from codex_smart_subagents.health_bootstrap_v2 import HealthBootstrapV2Error
        from tests.smart_subagents.test_health_bootstrap_v2 import (
            HealthBootstrapV2Tests,
        )

        journal = self._journal()
        fixture = HealthBootstrapV2Tests(methodName="runTest")
        fixture.setUp()
        try:
            with self.assertRaisesRegex(
                HealthBootstrapV2Error,
                "FIRST_INSTALL_IDENTITY_INVALID",
            ):
                fixture._bootstrap(
                    first_installation_id=journal["installationId"],
                )
        finally:
            fixture.tearDown()

    def test_real_sigkill_after_outer_intent_preserves_exact_recovery_input(
        self,
    ) -> None:
        driver = r'''
import importlib.util
import os
import signal
import sys
from pathlib import Path

installer_path, source_root, codex_home, bin_dir, state_home, codex_binary = sys.argv[1:]
spec = importlib.util.spec_from_file_location("crash_driver_installer", installer_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
layout = module.InstallLayout(
    source_root=Path(source_root),
    codex_home=Path(codex_home),
    bin_dir=Path(bin_dir),
    state_home=Path(state_home),
    codex_binary=Path(codex_binary),
)
original = module._atomic_create_json
def crash_after_outer_intent(path, value, **kwargs):
    original(path, value, **kwargs)
    if path == layout.first_install_journal_path:
        os.kill(os.getpid(), signal.SIGKILL)
module._atomic_create_json = crash_after_outer_intent
module.install(layout, apply=True)
'''
        completed = subprocess.run(
            (
                sys.executable,
                "-c",
                driver,
                str(INSTALLER_PATH),
                str(ROOT),
                str(self.codex_home),
                str(self.bin_dir),
                str(self.layout.state_home),
                str(self.codex_binary),
            ),
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        self.assertEqual(-signal.SIGKILL, completed.returncode, completed.stderr)
        journal = json.loads(
            self.layout.first_install_journal_path.read_text(encoding="utf-8")
        )
        validated = self.installer._load_first_install_journal_v2(self.layout)
        self.assertEqual(journal, validated)
        self.assertFalse(self.layout.launcher_path.exists())
        self.assertFalse(self.layout.admin_path.exists())

        preview = self.installer.recover_installation_v2(
            self.layout,
            execute=False,
        )
        repeated_preview = self.installer.recover_installation_v2(
            self.layout,
            execute=False,
        )
        self.assertEqual("planned", preview["status"])
        self.assertEqual(preview, repeated_preview)
        self.assertEqual(
            journal["operationId"],
            preview["extensions"]["lifecycleAdapter"]["internalOperationId"],
        )

    def test_real_sigkill_preparation_matrix_converges_via_public_recovery(
        self,
    ) -> None:
        cases = (
            ("AFTER_PREPARATION_INTENT", ""),
            ("AFTER_STEP_INTENT_BEFORE_EFFECT", "activation_tree"),
            ("AFTER_EFFECT_BEFORE_STEP_COMPLETE", "activation_tree"),
            ("AFTER_STEP_INTENT_BEFORE_EFFECT", "database_empty_file"),
            ("AFTER_EFFECT_BEFORE_STEP_COMPLETE", "database_empty_file"),
            ("BEFORE_PREPARATION_FREEZE", ""),
            ("AFTER_PREPARATION_FREEZE", ""),
            ("BEFORE_RECEIPT_PUBLISH", ""),
            ("AFTER_RECEIPT_PUBLISH", ""),
        )
        driver = r'''
import importlib.util
import os
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path

installer_path, source_root, codex_home, bin_dir, state_home, codex_binary, point, step_kind = sys.argv[1:]
source_root = Path(source_root)
sys.path.insert(0, str(source_root))
sys.path.insert(0, str(source_root / "plugins" / "codex-smart-subagents" / "src"))
spec = importlib.util.spec_from_file_location("crash_matrix_installer", installer_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
from codex_smart_subagents.activation_preparation_v2 import ActivationPreparationExecutorV2
from codex_smart_subagents.installer_upgrade_v2 import build_initial_activation_preparation_v2
from codex_smart_subagents.policy_bundle_v2 import load_policy_bundle_v2
from tests.smart_subagents.test_health_bootstrap_v2 import _InterfaceExecutor, _Snapshotter

layout = module.InstallLayout(
    source_root=source_root,
    codex_home=Path(codex_home),
    bin_dir=Path(bin_dir),
    state_home=Path(state_home),
    codex_binary=Path(codex_binary),
)
layout.manifest_root.mkdir(parents=True, mode=0o700, exist_ok=True)
module._ensure_lock_file(layout.lock_path)
journal = module._build_first_install_journal_v2(
    layout,
    source_digest=module._source_digest(layout),
    codex_version="0.144.6",
)
module._atomic_create_json(
    layout.first_install_journal_path,
    journal,
    conflict_code="FIRST_INSTALL_JOURNAL_CONFLICT",
)
vectors = source_root / "docs" / "contracts" / "vectors"
policy = load_policy_bundle_v2(
    catalog_path=source_root / ".codex" / "adaptive-subagents.toml",
    routing_vector_path=vectors / "routing-policy-v2.json",
    delegation_vector_path=vectors / "delegation-policy-v2.json",
    role_vector_path=vectors / "role-template-v1.json",
    child_profile_vector_path=vectors / "child-profile-v1.json",
)
preparation = build_initial_activation_preparation_v2(
    source_root=source_root,
    codex_home=Path(codex_home),
    state_home=Path(state_home),
    codex_binary=Path(codex_binary),
    policy_bundle=policy,
    installation_id=journal["installationId"],
    operation_id=journal["operationId"],
    snapshotter=_Snapshotter(layout.gateway_layout.managed_root / "codex-snapshots"),
    interface_executor=_InterfaceExecutor(),
    completed_at=datetime(2026, 7, 20, 12, 0, 0, tzinfo=timezone.utc),
)
def kill_at_boundary(observed_point, observed_step_kind):
    if observed_point.value == point and (not step_kind or observed_step_kind == step_kind):
        os.kill(os.getpid(), signal.SIGKILL)
ActivationPreparationExecutorV2(
    definition=preparation.definition,
    callbacks=preparation.callbacks,
    failure_injector=kill_at_boundary,
).execute()
raise AssertionError("requested SIGKILL boundary was not reached")
'''

        for point, step_kind in cases:
            with self.subTest(point=point, step_kind=step_kind):
                with tempfile.TemporaryDirectory(dir="/tmp", prefix="cfm2-") as raw:
                    root = Path(raw).resolve()
                    codex_home = root / "c"
                    bin_dir = root / "b"
                    state_home = root / "s"
                    codex_home.mkdir(mode=0o700)
                    bin_dir.mkdir(mode=0o700)
                    codex_binary = root / "codex"
                    codex_binary.write_text(
                        (
                            ROOT
                            / "tests"
                            / "smart_subagents"
                            / "test_install_fake_codex.py"
                        ).read_text(encoding="utf-8"),
                        encoding="utf-8",
                    )
                    codex_binary.chmod(0o700)
                    layout = self.installer.InstallLayout(
                        source_root=ROOT,
                        codex_home=codex_home,
                        bin_dir=bin_dir,
                        state_home=state_home,
                        codex_binary=codex_binary,
                    )
                    completed = subprocess.run(
                        (
                            sys.executable,
                            "-c",
                            driver,
                            str(INSTALLER_PATH),
                            str(ROOT),
                            str(codex_home),
                            str(bin_dir),
                            str(state_home),
                            str(codex_binary),
                            point,
                            step_kind,
                        ),
                        cwd=ROOT,
                        capture_output=True,
                        text=True,
                        timeout=30,
                        check=False,
                    )
                    self.assertEqual(
                        -signal.SIGKILL,
                        completed.returncode,
                        completed.stderr,
                    )
                    journal = self.installer._load_first_install_journal_v2(layout)
                    preview = self.installer.recover_installation_v2(
                        layout,
                        execute=False,
                        extra_environment={"FAKE_CODEX_VERSION": "0.144.6"},
                    )
                    repeated_preview = self.installer.recover_installation_v2(
                        layout,
                        execute=False,
                        extra_environment={"FAKE_CODEX_VERSION": "0.144.6"},
                    )
                    self.assertEqual(preview, repeated_preview)
                    self.assertEqual(
                        journal["operationId"],
                        preview["extensions"]["lifecycleAdapter"][
                            "internalOperationId"
                        ],
                    )

                    runtimes: list[object] = []
                    decisions: list[object] = []

                    def spawn(
                        current_layout,
                        source_environment=None,
                        *,
                        first_install_journal=None,
                    ):
                        del source_environment
                        from codex_smart_subagents.health_bootstrap_v2 import (
                            bootstrap_health_activation_v2,
                        )
                        from codex_smart_subagents.policy_bundle_v2 import (
                            load_policy_bundle_v2,
                        )
                        from tests.smart_subagents.test_health_bootstrap_v2 import (
                            _InterfaceExecutor,
                            _Snapshotter,
                        )

                        vectors = ROOT / "docs" / "contracts" / "vectors"
                        policy = load_policy_bundle_v2(
                            catalog_path=ROOT / ".codex" / "adaptive-subagents.toml",
                            routing_vector_path=vectors / "routing-policy-v2.json",
                            delegation_vector_path=vectors / "delegation-policy-v2.json",
                            role_vector_path=vectors / "role-template-v1.json",
                            child_profile_vector_path=vectors / "child-profile-v1.json",
                        )
                        runtime = bootstrap_health_activation_v2(
                            source_root=ROOT,
                            codex_home=current_layout.codex_home,
                            state_home=current_layout.state_home,
                            codex_binary=current_layout.codex_binary,
                            wrapper=current_layout.bootstrap_wrapper,
                            policy_bundle=policy,
                            snapshotter=_Snapshotter(
                                current_layout.gateway_layout.managed_root
                                / "codex-snapshots"
                            ),
                            interface_executor=_InterfaceExecutor(),
                            snapshot_verifier=lambda _subject: None,
                            first_install_operation_id=first_install_journal[
                                "operationId"
                            ],
                            first_installation_id=first_install_journal[
                                "installationId"
                            ],
                        )
                        runtimes.append(runtime)
                        decisions.append(runtime.gateway_decision)
                        return SimpleNamespace(
                            poll=lambda: None,
                            terminate=lambda: None,
                            wait=lambda timeout=None: 0,
                        )

                    try:
                        with (
                            mock.patch.object(
                                self.installer,
                                "_spawn_initial_controller",
                                side_effect=spawn,
                            ),
                            mock.patch.object(
                                self.installer,
                                "_wait_for_full_ready",
                                side_effect=lambda _layout, _process: decisions[-1],
                            ),
                        ):
                            recovered = self.installer.recover_installation_v2(
                                layout,
                                execute=True,
                                extra_environment={
                                    "FAKE_CODEX_VERSION": "0.144.6"
                                },
                            )
                        self.assertEqual("recovered", recovered["status"])
                        self.assertEqual(
                            journal["operationId"], recovered["operationId"]
                        )
                        self.assertFalse(layout.first_install_journal_path.exists())
                        self.assertTrue(layout.installer_receipt_path.exists())
                        manifest = json.loads(
                            layout.gateway_layout.manifest_path.read_text(
                                encoding="utf-8"
                            )
                        )
                        self.assertEqual(
                            journal["operationId"],
                            manifest["lastCommittedOperation"],
                        )

                        with mock.patch.object(
                            self.installer,
                            "_supervise_existing",
                            return_value=decisions[-1],
                        ):
                            repeated_recover = self.installer.recover_installation_v2(
                                layout,
                                execute=True,
                                extra_environment={
                                    "FAKE_CODEX_VERSION": "0.144.6"
                                },
                            )
                            applied = self.installer.install(
                                layout,
                                apply=True,
                                extra_environment={
                                    "FAKE_CODEX_VERSION": "0.144.6"
                                },
                            )
                        self.assertIn(
                            repeated_recover["status"],
                            {"unchanged", "recovered"},
                        )
                        self.assertEqual("unchanged", applied["status"])
                        self.assertEqual(
                            journal["installationId"], applied["installationId"]
                        )
                    finally:
                        for runtime in reversed(runtimes):
                            runtime.close()

    def test_real_sigkill_first_install_tail_converges_without_manual_cleanup(
        self,
    ) -> None:
        cases = (
            ("bin_directory", True),
            ("launcher_link", True),
            ("admin_link", True),
            ("database_committed", True),
            ("fallback_published", True),
            ("activation_manifest_published", True),
            ("commit_receipt_published", True),
            ("marketplace_current_published", True),
            ("full_ready", True),
            ("marketplace_registered", True),
            ("plugin_registered", True),
            ("installer_receipt_published", True),
            ("outer_journal_deleted", False),
        )
        driver = r'''
import importlib.util
import os
import signal
import sys
from pathlib import Path
from types import SimpleNamespace

installer_path, source_root, codex_home, bin_dir, state_home, codex_binary, boundary = sys.argv[1:]
source_root = Path(source_root)
sys.path.insert(0, str(source_root))
sys.path.insert(0, str(source_root / "plugins" / "codex-smart-subagents" / "src"))
spec = importlib.util.spec_from_file_location("tail_crash_installer", installer_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
from codex_smart_subagents.health_bootstrap_v2 import bootstrap_health_activation_v2
from codex_smart_subagents.policy_bundle_v2 import load_policy_bundle_v2
from codex_smart_subagents import activation_materializer_v2
from tests.smart_subagents.test_health_bootstrap_v2 import _InterfaceExecutor, _Snapshotter

layout = module.InstallLayout(
    source_root=source_root,
    codex_home=Path(codex_home),
    bin_dir=Path(bin_dir),
    state_home=Path(state_home),
    codex_binary=Path(codex_binary),
)
vectors = source_root / "docs" / "contracts" / "vectors"
policy = load_policy_bundle_v2(
    catalog_path=source_root / ".codex" / "adaptive-subagents.toml",
    routing_vector_path=vectors / "routing-policy-v2.json",
    delegation_vector_path=vectors / "delegation-policy-v2.json",
    role_vector_path=vectors / "role-template-v1.json",
    child_profile_vector_path=vectors / "child-profile-v1.json",
)
runtimes = []

def kill_now():
    os.kill(os.getpid(), signal.SIGKILL)

original_link = module._ensure_first_install_link_v2
original_owned_directory = module._ensure_owned_directory
def directory_then_maybe_kill(path, *, create, private):
    result = original_owned_directory(path, create=create, private=private)
    if boundary == "bin_directory" and create and path == layout.bin_dir:
        kill_now()
    return result

def link_then_maybe_kill(path, target):
    result = original_link(path, target)
    if boundary == "launcher_link" and path == layout.launcher_path:
        kill_now()
    if boundary == "admin_link" and path == layout.admin_path:
        kill_now()
    return result

def spawn(current_layout, source_environment=None, *, first_install_journal=None):
    del source_environment
    runtime = bootstrap_health_activation_v2(
        source_root=source_root,
        codex_home=current_layout.codex_home,
        state_home=current_layout.state_home,
        codex_binary=current_layout.codex_binary,
        wrapper=current_layout.bootstrap_wrapper,
        policy_bundle=policy,
        snapshotter=_Snapshotter(
            current_layout.gateway_layout.managed_root / "codex-snapshots"
        ),
        interface_executor=_InterfaceExecutor(),
        snapshot_verifier=lambda _subject: None,
        first_install_operation_id=first_install_journal["operationId"],
        first_installation_id=first_install_journal["installationId"],
    )
    runtimes.append(runtime)
    return SimpleNamespace(
        poll=lambda: None,
        terminate=lambda: None,
        wait=lambda timeout=None: 0,
    )

def wait_then_maybe_kill(_layout, _process):
    decision = runtimes[-1].gateway_decision
    if boundary == "full_ready":
        kill_now()
    return decision

original_marketplace = module._add_marketplace
def marketplace_then_maybe_kill(current_layout, extra_environment):
    result = original_marketplace(current_layout, extra_environment)
    if boundary == "marketplace_registered":
        kill_now()
    return result

original_plugin = module._add_plugin
def plugin_then_maybe_kill(current_layout, extra_environment):
    result = original_plugin(current_layout, extra_environment)
    if boundary == "plugin_registered":
        kill_now()
    return result

original_store = activation_materializer_v2.SmartStoreV2
def store_then_maybe_kill(*args, **kwargs):
    result = original_store(*args, **kwargs)
    if boundary == "database_committed":
        kill_now()
    return result

original_fallback = activation_materializer_v2._publish_fallback
def fallback_then_maybe_kill(*, layout, source_locator, snapshot_locator):
    result = original_fallback(
        layout=layout,
        source_locator=source_locator,
        snapshot_locator=snapshot_locator,
    )
    if boundary == "fallback_published":
        kill_now()
    return result

original_materializer_write = activation_materializer_v2._atomic_write_json
def materializer_write_then_maybe_kill(path, value):
    result = original_materializer_write(path, value)
    if boundary == "activation_manifest_published" and path == layout.gateway_layout.manifest_path:
        kill_now()
    if (
        boundary == "commit_receipt_published"
        and path.parent.parent == layout.gateway_layout.receipts_root
        and path.name.endswith(".commit.json")
    ):
        kill_now()
    return result

original_materializer_fsync = activation_materializer_v2._fsync_directory
def materializer_fsync_then_maybe_kill(path):
    result = original_materializer_fsync(path)
    if (
        boundary == "marketplace_current_published"
        and path == layout.gateway_layout.managed_root
        and layout.gateway_layout.marketplace_link.is_symlink()
    ):
        kill_now()
    return result

original_atomic_create = module._atomic_create_json
def atomic_create_then_maybe_kill(path, value, **kwargs):
    result = original_atomic_create(path, value, **kwargs)
    if boundary == "installer_receipt_published" and path == layout.installer_receipt_path:
        kill_now()
    return result

original_delete_journal = module._delete_first_install_journal_v2
def delete_journal_then_maybe_kill(current_layout, *, expected):
    result = original_delete_journal(current_layout, expected=expected)
    if boundary == "outer_journal_deleted":
        kill_now()
    return result

module._ensure_owned_directory = directory_then_maybe_kill
module._ensure_first_install_link_v2 = link_then_maybe_kill
module._spawn_initial_controller = spawn
module._wait_for_full_ready = wait_then_maybe_kill
module._add_marketplace = marketplace_then_maybe_kill
module._add_plugin = plugin_then_maybe_kill
activation_materializer_v2.SmartStoreV2 = store_then_maybe_kill
activation_materializer_v2._publish_fallback = fallback_then_maybe_kill
activation_materializer_v2._atomic_write_json = materializer_write_then_maybe_kill
activation_materializer_v2._fsync_directory = materializer_fsync_then_maybe_kill
module._atomic_create_json = atomic_create_then_maybe_kill
module._delete_first_install_journal_v2 = delete_journal_then_maybe_kill
module.install(
    layout,
    apply=True,
    extra_environment={"FAKE_CODEX_VERSION": "0.144.6"},
)
raise AssertionError("requested tail SIGKILL boundary was not reached")
'''

        for boundary, expected_journal_present in cases:
            with self.subTest(boundary=boundary):
                with tempfile.TemporaryDirectory(dir="/tmp", prefix="cft2-") as raw:
                    root = Path(raw).resolve()
                    codex_home = root / "c"
                    bin_dir = root / "b"
                    state_home = root / "s"
                    codex_home.mkdir(mode=0o700)
                    if boundary != "bin_directory":
                        bin_dir.mkdir(mode=0o700)
                    codex_binary = root / "codex"
                    codex_binary.write_text(
                        (
                            ROOT
                            / "tests"
                            / "smart_subagents"
                            / "test_install_fake_codex.py"
                        ).read_text(encoding="utf-8"),
                        encoding="utf-8",
                    )
                    codex_binary.chmod(0o700)
                    layout = self.installer.InstallLayout(
                        source_root=ROOT,
                        codex_home=codex_home,
                        bin_dir=bin_dir,
                        state_home=state_home,
                        codex_binary=codex_binary,
                    )
                    completed = subprocess.run(
                        (
                            sys.executable,
                            "-c",
                            driver,
                            str(INSTALLER_PATH),
                            str(ROOT),
                            str(codex_home),
                            str(bin_dir),
                            str(state_home),
                            str(codex_binary),
                            boundary,
                        ),
                        cwd=ROOT,
                        capture_output=True,
                        text=True,
                        timeout=30,
                        check=False,
                    )
                    self.assertEqual(
                        -signal.SIGKILL,
                        completed.returncode,
                        completed.stderr,
                    )

                    journal_present = layout.first_install_journal_path.exists()
                    self.assertEqual(
                        expected_journal_present,
                        journal_present,
                        boundary,
                    )
                    if journal_present:
                        journal = self.installer._load_first_install_journal_v2(layout)
                        operation_id = str(journal["operationId"])
                        installation_id = str(journal["installationId"])
                    else:
                        manifest = json.loads(
                            layout.gateway_layout.manifest_path.read_text(
                                encoding="utf-8"
                            )
                        )
                        operation_id = str(manifest["lastCommittedOperation"])
                        installation_id = str(manifest["installationId"])

                    preview = self.installer.recover_installation_v2(
                        layout,
                        execute=False,
                        extra_environment={"FAKE_CODEX_VERSION": "0.144.6"},
                    )
                    repeated_preview = self.installer.recover_installation_v2(
                        layout,
                        execute=False,
                        extra_environment={"FAKE_CODEX_VERSION": "0.144.6"},
                    )
                    self.assertEqual(preview, repeated_preview)
                    if journal_present:
                        self.assertEqual("planned", preview["status"])
                        self.assertEqual(
                            operation_id,
                            preview["extensions"]["lifecycleAdapter"][
                                "internalOperationId"
                            ],
                        )
                    else:
                        self.assertEqual("unchanged", preview["status"])

                    runtimes: list[object] = []

                    def start_health(
                        current_layout,
                        *,
                        first_install_journal=None,
                    ):
                        from codex_smart_subagents.health_bootstrap_v2 import (
                            bootstrap_health_activation_v2,
                        )
                        from codex_smart_subagents.policy_bundle_v2 import (
                            load_policy_bundle_v2,
                        )
                        from tests.smart_subagents.test_health_bootstrap_v2 import (
                            _InterfaceExecutor,
                            _Snapshotter,
                        )

                        vectors = ROOT / "docs" / "contracts" / "vectors"
                        policy = load_policy_bundle_v2(
                            catalog_path=ROOT / ".codex" / "adaptive-subagents.toml",
                            routing_vector_path=vectors / "routing-policy-v2.json",
                            delegation_vector_path=vectors / "delegation-policy-v2.json",
                            role_vector_path=vectors / "role-template-v1.json",
                            child_profile_vector_path=vectors / "child-profile-v1.json",
                        )
                        arguments: dict[str, object] = {
                            "source_root": ROOT,
                            "codex_home": current_layout.codex_home,
                            "state_home": current_layout.state_home,
                            "codex_binary": current_layout.codex_binary,
                            "wrapper": current_layout.bootstrap_wrapper,
                            "policy_bundle": policy,
                            "snapshotter": _Snapshotter(
                                current_layout.gateway_layout.managed_root
                                / "codex-snapshots"
                            ),
                            "interface_executor": _InterfaceExecutor(),
                            "snapshot_verifier": lambda _subject: None,
                        }
                        if first_install_journal is not None:
                            arguments.update(
                                {
                                    "first_install_operation_id": (
                                        first_install_journal["operationId"]
                                    ),
                                    "first_installation_id": (
                                        first_install_journal["installationId"]
                                    ),
                                }
                            )
                        runtime = bootstrap_health_activation_v2(**arguments)
                        if runtime not in runtimes:
                            runtimes.append(runtime)
                        return runtime

                    def spawn(
                        current_layout,
                        source_environment=None,
                        *,
                        first_install_journal=None,
                    ):
                        del source_environment
                        runtime = start_health(
                            current_layout,
                            first_install_journal=first_install_journal,
                        )
                        return SimpleNamespace(
                            poll=lambda: None,
                            terminate=lambda: None,
                            wait=lambda timeout=None: 0,
                            gateway_decision=runtime.gateway_decision,
                        )

                    def supervise(current_layout, extra_environment=None):
                        del extra_environment
                        for runtime in reversed(runtimes):
                            if runtime.thread_alive:
                                return runtime.gateway_decision
                        return start_health(current_layout).gateway_decision

                    try:
                        if boundary == "commit_receipt_published":
                            from codex_smart_subagents import health_bootstrap_v2

                            committed_manifest = json.loads(
                                layout.gateway_layout.manifest_path.read_text(
                                    encoding="utf-8"
                                )
                            )
                            database_path = (
                                Path(str(committed_manifest["stateHome"]))
                                / "databases"
                                / committed_manifest["activeActivation"]["databaseId"]
                                / "smart-subagents.sqlite3"
                            )
                            commit_receipt_path = (
                                layout.gateway_layout.receipts_root
                                / installation_id
                                / f"{operation_id}.commit.json"
                            )
                            protected_paths = (
                                database_path,
                                layout.gateway_layout.fallback_path,
                                layout.gateway_layout.manifest_path,
                                commit_receipt_path,
                            )

                            def durable_file_proof(path):
                                info = path.lstat()
                                if path == database_path:
                                    connection = sqlite3.connect(path)
                                    connection.row_factory = sqlite3.Row
                                    try:
                                        application_id = int(
                                            connection.execute(
                                                "pragma application_id"
                                            ).fetchone()[0]
                                        )
                                        user_version = int(
                                            connection.execute(
                                                "pragma user_version"
                                            ).fetchone()[0]
                                        )
                                        database_identity = dict(
                                            connection.execute(
                                                "select * from database_identity"
                                            ).fetchone()
                                        )
                                        controller_state = dict(
                                            connection.execute(
                                                "select * from controller_state"
                                            ).fetchone()
                                        )
                                    finally:
                                        connection.close()
                                    return (
                                        info.st_dev,
                                        info.st_ino,
                                        info.st_mode,
                                        info.st_nlink,
                                        application_id,
                                        user_version,
                                        database_identity,
                                        controller_state,
                                    )
                                return (
                                    path.read_bytes(),
                                    info.st_dev,
                                    info.st_ino,
                                    info.st_mode,
                                    info.st_nlink,
                                )

                            protected_before = {
                                path: durable_file_proof(path)
                                for path in protected_paths
                            }
                            with (
                                mock.patch.object(
                                    self.installer,
                                    "_spawn_initial_controller",
                                    side_effect=spawn,
                                ),
                                mock.patch.object(
                                    self.installer,
                                    "_wait_for_full_ready",
                                    side_effect=(
                                        lambda _layout, process: (
                                            process.gateway_decision
                                        )
                                    ),
                                ),
                                mock.patch.object(
                                    self.installer,
                                    "_supervise_existing",
                                    side_effect=supervise,
                                ),
                                mock.patch.object(
                                    health_bootstrap_v2,
                                    "activate_materialized_v2",
                                    side_effect=RuntimeError(
                                        "forced recovery validation failure"
                                    ),
                                ),
                                self.assertRaisesRegex(
                                    RuntimeError,
                                    "forced recovery validation failure",
                                ),
                            ):
                                self.installer.recover_installation_v2(
                                    layout,
                                    execute=True,
                                    extra_environment={
                                        "FAKE_CODEX_VERSION": "0.144.6"
                                    },
                                )
                            self.assertTrue(
                                layout.first_install_journal_path.exists()
                            )
                            self.assertEqual(
                                protected_before,
                                {
                                    path: durable_file_proof(path)
                                    for path in protected_paths
                                },
                            )

                        with (
                            mock.patch.object(
                                self.installer,
                                "_spawn_initial_controller",
                                side_effect=spawn,
                            ),
                            mock.patch.object(
                                self.installer,
                                "_wait_for_full_ready",
                                side_effect=(
                                    lambda _layout, process: process.gateway_decision
                                ),
                            ),
                            mock.patch.object(
                                self.installer,
                                "_supervise_existing",
                                side_effect=supervise,
                            ),
                        ):
                            recovered = self.installer.recover_installation_v2(
                                layout,
                                execute=True,
                                extra_environment={
                                    "FAKE_CODEX_VERSION": "0.144.6"
                                },
                            )
                            repeated_recover = self.installer.recover_installation_v2(
                                layout,
                                execute=True,
                                extra_environment={
                                    "FAKE_CODEX_VERSION": "0.144.6"
                                },
                            )
                            applied = self.installer.install(
                                layout,
                                apply=True,
                                extra_environment={
                                    "FAKE_CODEX_VERSION": "0.144.6"
                                },
                            )

                        if journal_present:
                            self.assertEqual("recovered", recovered["status"])
                            self.assertEqual(operation_id, recovered["operationId"])
                        else:
                            self.assertEqual("unchanged", recovered["status"])
                        self.assertIn(
                            repeated_recover["status"],
                            {"unchanged", "recovered"},
                        )
                        self.assertEqual("unchanged", applied["status"])
                        self.assertEqual(installation_id, applied["installationId"])
                        self.assertFalse(layout.first_install_journal_path.exists())
                        self.assertTrue(layout.installer_receipt_path.exists())
                        receipt = self.installer._load_installer_receipt(
                            layout.installer_receipt_path
                        )
                        identity = self.installer._load_lifecycle_identity(layout)
                        self.assertEqual(
                            self.installer._build_installer_receipt(
                                layout,
                                source_digest=applied["sourceDigest"],
                                identity=identity,
                            ),
                            receipt,
                        )
                        self.assertEqual(
                            installation_id,
                            receipt["installationId"],
                        )
                        manifest = json.loads(
                            layout.gateway_layout.manifest_path.read_text(
                                encoding="utf-8"
                            )
                        )
                        self.assertEqual(
                            operation_id,
                            manifest["lastCommittedOperation"],
                        )
                    finally:
                        for runtime in reversed(runtimes):
                            runtime.close()


if __name__ == "__main__":
    unittest.main()
