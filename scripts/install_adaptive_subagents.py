#!/usr/bin/env python3
"""Идемпотентная установка принятой активации adaptive subagents v2."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence


_REPO = Path(__file__).resolve().parents[1]
_PLUGIN_SOURCE = _REPO / "plugins" / "codex-smart-subagents" / "src"
if str(_PLUGIN_SOURCE) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_SOURCE))

from codex_smart_subagents.activation_gateway_v2 import (  # noqa: E402
    ActivationResolver,
    GatewayDecision,
    GatewayLayout,
    GatewayState,
    v2_gateway_state_present,
)
from codex_smart_subagents.activation_materializer_v2 import (  # noqa: E402
    _CONFIG_CONTRACT_VECTOR_FILES,
    _RUNTIME_SCHEMA_FILES,
    _RUNTIME_VECTOR_FILES,
    cleanup_accepted_activation_v2,
)
from codex_smart_subagents.activation_transition_v2 import (  # noqa: E402
    capture_activation_transition_proof_v2,
)
from codex_smart_subagents.compatibility import (  # noqa: E402
    MINIMUM_STABLE_CODEX_VERSION,
    codex_version_supported,
    parse_stable_codex_version,
)
from codex_smart_subagents.canonical_json import domain_fingerprint  # noqa: E402
from codex_smart_subagents import finite_file_lock_v2  # noqa: E402
from codex_smart_subagents import operation_deadline_v2  # noqa: E402
from codex_smart_subagents import (  # noqa: E402
    operation_process_group_supervisor_v2,
)
from codex_smart_subagents import supervised_subprocess_v2  # noqa: E402
from codex_smart_subagents.durable_process_ownership_v2 import (  # noqa: E402
    DurableProcessOwnershipRecordV2,
    DurableProcessOwnershipStoreV2,
    OutstandingDurableProcessOwnershipV2,
)
from codex_smart_subagents.controller_supervisor_v2 import (  # noqa: E402
    ControllerSupervisorV2,
    SupervisorStateV2,
    probe_controller_command_socket_v2,
)
from codex_smart_subagents.installer_command_v2 import (  # noqa: E402
    InstallerInvocationV2,
    InvalidInstallerInvocationV2,
    ProvenTemporaryBusyV2,
    build_lifecycle_command_result_v2,
    exit_code_v2,
    parse_installer_argv_v2,
)
from codex_smart_subagents.installer_maintenance_v2 import (  # noqa: E402
    InstallerMaintenanceLayoutV2,
    MaintenanceResultV2,
    RegistrationCallbacksV2,
    RegistrationObservationV2,
    cleanup_inactive_activations_v2,
    inspect_maintenance_inventory_v2,
    uninstall_retain_data_v2,
    _verify_completed_uninstall,
)
from codex_smart_subagents.installer_receipt_reconciliation_v2 import (  # noqa: E402
    reconcile_installer_receipt_v2,
)
from codex_smart_subagents.installer_recovery_v2 import (  # noqa: E402
    InstallerLifecycleAdapterResultV2,
    MainJournalRecoveryV2,
    PreparationJournalRecoveryV2,
    RecoveryPlanV2,
    execute_recovery_v2,
    execute_rollback_v2,
    inspect_recovery_v2,
    plan_recovery_v2,
    plan_rollback_v2,
    read_rollback_v2,
)
from codex_smart_subagents.installer_upgrade_v2 import (  # noqa: E402
    _recover_upgrade_preparation_from_main_journal_v2,
    build_persisted_upgrade_preparation_recovery_v2,
    build_upgrade_preparation_v2,
    execute_and_verify_upgrade_preparation_v2,
    installer_source_digest_from_materialized_activation_v2,
)
from codex_smart_subagents.installer_uninstall_composition_v2 import (  # noqa: E402
    build_active_uninstall_composition_v2,
    recover_active_uninstall_composition_v2,
    uninstall_maintenance_result_v2,
)
from codex_smart_subagents.lifecycle_operation_v2 import (  # noqa: E402
    OperationExecutorV2,
    OperationJournalStoreV2,
    build_operation_journal_validator_v2,
)
from codex_smart_subagents.lifecycle_plan_v2 import (  # noqa: E402
    LifecyclePlanRegistryV2,
)
from codex_smart_subagents.policy_bundle_v2 import (  # noqa: E402
    PolicyBundleError,
    load_policy_bundle_v2,
)


SCHEMA_VERSION = 2
MARKETPLACE_NAME = "codex-settings-adaptive"
PLUGIN_NAME = "codex-smart-subagents"
PLUGIN_ID = f"{PLUGIN_NAME}@{MARKETPLACE_NAME}"
INSTALLATION_NAME = "codex-smart-subagents-v2"
INSTALLER_RECEIPT_KIND = "codex-smart-installer-receipt/v2"
_FIRST_INSTALL_JOURNAL_KIND = "codex-smart-first-install-transaction/v2"
_FIRST_INSTALL_JOURNAL_DOMAIN = "codex-smart/first-install-transaction/v2"
_VERSION_PATTERN = re.compile(r"^codex-cli ([0-9]+\.[0-9]+\.[0-9]+)\n?$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_EXCLUDED_TREE_NAMES = frozenset({"__pycache__", ".DS_Store"})
_SAFE_INHERITED_ENVIRONMENT = (
    "HOME",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
)
_BOOTSTRAP_ENVIRONMENT_NAMES = (
    "CODEX_V2_SOURCE_ROOT",
    "CODEX_V2_CODEX_BIN",
    "CODEX_V2_WRAPPER_PATH",
    "CODEX_V2_STATE_HOME",
    "CODEX_V2_FIRST_INSTALL_OPERATION_ID",
    "CODEX_V2_FIRST_INSTALLATION_ID",
)
_FULL_READY_TIMEOUT_SECONDS = 120.0
_FULL_READY_POLL_SECONDS = 0.05
_INITIAL_CONTROLLER_BOOTSTRAP_TIMEOUT_SECONDS = 5.0
_SOCKET_PATH_LIMIT = 100
_CANDIDATE_READY_SOCKET_PLACEHOLDER = ".r-" + "0" * 12 + ".sock"
_SUPPORTED_MAIN_RECOVERY_OPERATIONS_V2 = frozenset(
    {
        ("activation", "apply"),
        ("rollback", "rollback"),
        ("uninstall", "uninstall"),
    }
)
_VERIFIED_CODEX_VERSION_TEXT = f">= {MINIMUM_STABLE_CODEX_VERSION}"
class InstallError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class _MarketplaceSourceContract:
    plugin_version: str
    plugin_source_path: str
    install_policy: str
    auth_policy: str


@dataclass(frozen=True)
class InstallLayout:
    source_root: Path
    codex_home: Path
    bin_dir: Path
    codex_binary: Path
    state_home: Path

    def __post_init__(self) -> None:
        for name in (
            "source_root",
            "codex_home",
            "bin_dir",
            "codex_binary",
            "state_home",
        ):
            value = getattr(self, name)
            if not isinstance(value, Path) or not value.is_absolute():
                raise ValueError(f"{name} must be an absolute Path")

    @property
    def gateway_layout(self) -> GatewayLayout:
        return GatewayLayout.for_codex_home(self.codex_home)

    @property
    def plugin_source(self) -> Path:
        return self.source_root / "plugins" / PLUGIN_NAME

    @property
    def controller_entrypoint(self) -> Path:
        return self.plugin_source / "controller" / "server.py"

    @property
    def bootstrap_wrapper(self) -> Path:
        return self.plugin_source / "bin" / "codex-smart"

    @property
    def marketplace_source(self) -> Path:
        return self.source_root / ".agents" / "plugins" / "marketplace.json"

    @property
    def codex_marketplace_source(self) -> Path:
        return self.source_root / ".claude-plugin" / "marketplace.json"

    @property
    def catalog_source(self) -> Path:
        return self.source_root / ".codex" / "adaptive-subagents.toml"

    @property
    def policy_source_paths(self) -> tuple[Path, ...]:
        root = self.source_root / "docs" / "contracts" / "vectors"
        return tuple(root / name for name in _CONFIG_CONTRACT_VECTOR_FILES)

    @property
    def runtime_schema_paths(self) -> tuple[Path, ...]:
        root = self.source_root / "docs" / "contracts" / "schemas"
        return tuple(root / name for name in _RUNTIME_SCHEMA_FILES)

    @property
    def runtime_vector_paths(self) -> tuple[Path, ...]:
        root = self.source_root / "docs" / "contracts" / "vectors"
        return tuple(root / name for name in _RUNTIME_VECTOR_FILES)

    @property
    def installer_receipt_schema_source(self) -> Path:
        return (
            self.source_root
            / "docs"
            / "contracts"
            / "schemas"
            / "installer-receipt-v2.schema.json"
        )

    @property
    def config_path(self) -> Path:
        return self.codex_home / "config.toml"

    @property
    def owned_root(self) -> Path:
        """Совместимое имя для управляемого корня жизненного цикла v2."""

        return self.gateway_layout.managed_root

    @property
    def marketplace_root(self) -> Path:
        return self.gateway_layout.marketplace_link

    @property
    def marketplace_path(self) -> Path:
        return self.marketplace_root / ".agents" / "plugins" / "marketplace.json"

    @property
    def installed_plugin_root(self) -> Path:
        return self.marketplace_root / "plugins" / PLUGIN_NAME

    @property
    def catalog_path(self) -> Path:
        return self.installed_plugin_root / "config" / "adaptive-subagents.toml"

    @property
    def launcher_path(self) -> Path:
        return self.bin_dir / "codex-smart"

    @property
    def launcher_target(self) -> Path:
        return self.installed_plugin_root / "bin" / "codex-smart"

    @property
    def admin_path(self) -> Path:
        return self.bin_dir / "codex-smart-subagents-admin"

    @property
    def admin_target(self) -> Path:
        return self.installed_plugin_root / "bin" / "codex-smart-subagents-admin"

    @property
    def highfd_path(self) -> Path:
        """Устаревший путь остаётся только для совместимости вызывающего кода."""

        return self.bin_dir / "codex-highfd"

    @property
    def manifest_root(self) -> Path:
        return self.gateway_layout.manifest_root

    @property
    def manifest_path(self) -> Path:
        return self.gateway_layout.manifest_path

    @property
    def lock_path(self) -> Path:
        return self.manifest_root / f"{INSTALLATION_NAME}.installer.lock"

    @property
    def installer_receipt_path(self) -> Path:
        return self.manifest_root / f"{INSTALLATION_NAME}.installer.json"

    @property
    def first_install_journal_path(self) -> Path:
        return (
            self.manifest_root
            / f"{INSTALLATION_NAME}.first-install.transaction.json"
        )


@dataclass
class _InstallAttempt:
    bin_dir_created: bool = False
    launcher_created: bool = False
    admin_created: bool = False
    marketplace_added: bool = False
    plugin_added: bool = False
    process: Any | None = None
    receipt: Mapping[str, Any] | None = None
    installation_id: str | None = None
    activation_id: str | None = None


class _LazyOperationJournalStoreV2:
    """Не создаёт lock-файл до фактического исполнения операции."""

    def __init__(self, *, layout: InstallLayout) -> None:
        self.journal_path = layout.gateway_layout.journal_path
        self.lock_path = layout.lock_path
        self._schema_dir = (
            layout.source_root / "docs" / "contracts" / "schemas"
        ).resolve()
        self._delegate: OperationJournalStoreV2 | None = None

    def _materialize(self) -> OperationJournalStoreV2:
        if self._delegate is None:
            self._delegate = OperationJournalStoreV2(
                journal_path=self.journal_path,
                lock_path=self.lock_path,
                validate_document=build_operation_journal_validator_v2(
                    self._schema_dir
                ),
            )
        return self._delegate

    def __getattr__(self, name: str) -> Any:
        return getattr(self._materialize(), name)


class _AlreadyHeldOperationJournalStoreV2:
    """Не брать второй ``flock`` внутри уже закрытой installer-секции."""

    def __init__(self, delegate: _LazyOperationJournalStoreV2) -> None:
        self._delegate = delegate
        self.journal_path = delegate.journal_path
        self.lock_path = delegate.lock_path

    @contextmanager
    def locked(self, *, exclusive: bool = True) -> Iterator[None]:
        del exclusive
        yield

    def __getattr__(self, name: str) -> Any:
        return getattr(self._delegate, name)


def default_layout(args: argparse.Namespace) -> InstallLayout:
    source_root = Path(args.source_root).expanduser().resolve()
    codex_home = (
        Path(
            args.codex_home or os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))
        )
        .expanduser()
        .absolute()
    )
    bin_dir = (
        Path(args.bin_dir or str(Path.home() / ".local" / "bin"))
        .expanduser()
        .absolute()
    )
    raw_binary = Path(args.codex_binary).expanduser()
    if not raw_binary.is_absolute():
        found = shutil.which(str(raw_binary))
        if found is None:
            raise InstallError(
                "CODEX_BINARY_MISSING",
                f"не найден исполняемый файл Codex: {raw_binary}",
            )
        raw_binary = Path(found)
    if args.state_home is None:
        state_home = codex_home / "state" / INSTALLATION_NAME
    else:
        state_home = Path(args.state_home).expanduser()
        if not state_home.is_absolute():
            raise InstallError(
                "STATE_HOME_INVALID",
                "--state-home должен быть абсолютным путём",
            )
    return InstallLayout(
        source_root=source_root,
        codex_home=codex_home,
        bin_dir=bin_dir,
        codex_binary=raw_binary.absolute(),
        state_home=state_home.absolute(),
    )


def install(
    layout: InstallLayout,
    *,
    apply: bool,
    extra_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    _require_socket_path_capacity(layout.state_home)
    _validate_source_layout(layout)
    version = _probe_version(layout, extra_environment)
    if not codex_version_supported(version):
        raise InstallError(
            "CODEX_VERSION_INCOMPATIBLE",
            (
                "требуется одна из проверенных версий Codex "
                f"({_VERIFIED_CODEX_VERSION_TEXT}), обнаружен {version}"
            ),
        )
    source_digest = _source_digest(layout)
    actions = [
        (
            f"создать стабильную ссылку {layout.launcher_path} через "
            f"{layout.gateway_layout.marketplace_link}"
        ),
        (
            f"создать стабильную ссылку {layout.admin_path} через "
            f"{layout.gateway_layout.marketplace_link}"
        ),
        ("запустить исходный controller/server.py --serve-v2 с закрытым окружением"),
        "дождаться ActivationResolver READY и частного command.sock",
        (
            "выполнить codex plugin marketplace add "
            f"{layout.gateway_layout.marketplace_link}"
        ),
        f"выполнить codex plugin add {PLUGIN_ID}",
        f"записать квитанцию schema 2 {layout.installer_receipt_path}",
    ]
    if not apply:
        return {
            "status": "planned",
            "actions": actions,
            "sourceDigest": source_digest,
            "codexVersion": version,
        }

    _ensure_codex_home_directory(layout.codex_home)
    _ensure_owned_directory(layout.manifest_root, create=True, private=True)
    _ensure_lock_file(layout.lock_path)
    with installation_lock(layout.lock_path):
        if os.path.lexists(layout.first_install_journal_path):
            journal = _load_first_install_journal_v2(layout)
            _require_first_install_journal_inputs_v2(
                journal,
                source_digest=source_digest,
                codex_version=version,
            )
            return _continue_first_install_v2(
                layout,
                journal=journal,
                source_digest=source_digest,
                codex_version=version,
                extra_environment=extra_environment,
                attempt=_InstallAttempt(),
            )
        if (
            layout.installer_receipt_path.exists()
            or layout.installer_receipt_path.is_symlink()
        ):
            return _repeat_install(
                layout,
                source_digest=source_digest,
                codex_version=version,
                extra_environment=extra_environment,
            )
        if v2_gateway_state_present(layout.gateway_layout):
            _raise_unowned_lifecycle_state(layout)
        return _first_install(
            layout,
            source_digest=source_digest,
            codex_version=version,
            extra_environment=extra_environment,
        )


def _first_install(
    layout: InstallLayout,
    *,
    source_digest: str,
    codex_version: str,
    extra_environment: Mapping[str, str] | None,
) -> dict[str, Any]:
    attempt = _InstallAttempt()
    _preflight_first_install(layout, extra_environment)
    journal = _build_first_install_journal_v2(
        layout,
        source_digest=source_digest,
        codex_version=codex_version,
    )
    _atomic_create_json(
        layout.first_install_journal_path,
        journal,
        conflict_code="FIRST_INSTALL_JOURNAL_CONFLICT",
    )
    try:
        return _continue_first_install_v2(
            layout,
            journal=journal,
            source_digest=source_digest,
            codex_version=codex_version,
            extra_environment=extra_environment,
            attempt=attempt,
        )
    except BaseException as raw_error:
        primary = _as_install_error(raw_error)
        rollback_errors = _rollback_failed_first_install(
            layout,
            attempt=attempt,
            extra_environment=extra_environment,
        )
        if not rollback_errors:
            try:
                _delete_first_install_journal_v2(layout, expected=journal)
            except Exception as cleanup_error:
                rollback_errors.append(f"first-install journal: {cleanup_error}")
        if rollback_errors:
            raise InstallError(
                primary.code,
                (
                    f"{primary.message}; неполный точный откат: "
                    + "; ".join(rollback_errors)
                ),
            ) from raw_error
        if isinstance(raw_error, InstallError):
            raise
        raise primary from raw_error


def _continue_first_install_v2(
    layout: InstallLayout,
    *,
    journal: Mapping[str, Any],
    source_digest: str,
    codex_version: str,
    extra_environment: Mapping[str, str] | None,
    attempt: _InstallAttempt,
) -> dict[str, Any]:
    """Продолжить первую установку, заново наблюдая каждый внешний эффект."""

    document = _validate_first_install_journal_v2(dict(journal), layout=layout)
    _require_first_install_journal_inputs_v2(
        document,
        source_digest=source_digest,
        codex_version=codex_version,
    )
    attempt.bin_dir_created = bool(document["binDirInitiallyAbsent"]) and not (
        os.path.lexists(layout.bin_dir)
    )
    _ensure_owned_directory(layout.bin_dir, create=True, private=False)
    attempt.launcher_created = _ensure_first_install_link_v2(
        layout.launcher_path,
        layout.launcher_target,
    )
    attempt.admin_created = _ensure_first_install_link_v2(
        layout.admin_path,
        layout.admin_target,
    )

    if (
        os.path.lexists(layout.gateway_layout.manifest_path)
        and (
            layout.gateway_layout.marketplace_link.exists()
            or layout.gateway_layout.marketplace_link.is_symlink()
        )
    ):
        decision = _supervise_existing(
            layout,
            extra_environment=extra_environment,
        )
    else:
        attempt.process = _spawn_initial_controller(
            layout,
            source_environment=extra_environment,
            first_install_journal=document,
        )
        decision = _wait_for_full_ready(layout, attempt.process)
    identity = _load_lifecycle_identity(layout, require_first_activation=True)
    if (
        identity["installationId"] != document["installationId"]
        or identity["operationId"] != document["operationId"]
    ):
        raise InstallError(
            "FIRST_INSTALL_IDENTITY_MISMATCH",
            "принятая активация принадлежит другой первой установке",
        )
    attempt.installation_id = identity["installationId"]
    attempt.activation_id = identity["activationId"]
    if decision.activation_id != attempt.activation_id:
        raise InstallError(
            "ACTIVATION_IDENTITY_MISMATCH",
            "READY resolver и lifecycle-манифест указывают на разные активации",
        )
    materialized_source_digest = _materialized_source_digest_v2(
        layout,
        identity=identity,
    )
    if materialized_source_digest != source_digest:
        raise InstallError(
            "INITIAL_PREPARED_SOURCE_MISMATCH",
            "sourceDigest не совпадает с принятой неизменяемой активацией",
        )
    link_problems = _stable_link_problems(layout, require_targets=True)
    if link_problems:
        raise InstallError("STABLE_LINK_MISMATCH", "; ".join(link_problems))

    marketplaces = _target_marketplaces(layout, extra_environment)
    if not marketplaces:
        _add_marketplace(layout, extra_environment)
        attempt.marketplace_added = True
    elif len(marketplaces) != 1 or not _marketplace_entry_matches(
        marketplaces[0], layout
    ):
        raise InstallError(
            "MARKETPLACE_REGISTRATION_MISMATCH",
            "существующая регистрация marketplace принадлежит другому состоянию",
        )
    _require_exact_marketplace(layout, extra_environment)

    plugins = _target_plugins(layout, extra_environment)
    if not plugins:
        _add_plugin(layout, extra_environment)
        attempt.plugin_added = True
    elif len(plugins) != 1 or not _plugin_entry_matches(plugins[0], layout):
        raise InstallError(
            "PLUGIN_REGISTRATION_MISMATCH",
            "существующая регистрация plugin принадлежит другому состоянию",
        )
    _require_exact_registration(layout, extra_environment)

    receipt = _build_installer_receipt(
        layout,
        source_digest=source_digest,
        identity=identity,
    )
    attempt.receipt = receipt
    if os.path.lexists(layout.installer_receipt_path):
        if _load_installer_receipt(layout.installer_receipt_path) != receipt:
            raise InstallError(
                "INSTALLER_RECEIPT_MISMATCH",
                "существующая квитанция не завершает эту первую установку",
            )
    else:
        _atomic_create_json(layout.installer_receipt_path, receipt)
    if attempt.process is not None:
        _release_spawned_process(attempt.process)
    _delete_first_install_journal_v2(layout, expected=document)
    return {
        "status": "installed",
        "readiness": "FULL_READY",
        "sourceDigest": source_digest,
        "codexVersion": codex_version,
        "installationId": identity["installationId"],
        "activationId": identity["activationId"],
        "operationId": document["operationId"],
    }


def _ensure_first_install_link_v2(path: Path, target: Path) -> bool:
    if not os.path.lexists(path):
        _create_stable_link(path, target)
        return True
    try:
        info = os.lstat(path)
        observed = os.readlink(path)
    except OSError as error:
        raise InstallError(
            "STABLE_LINK_CONFLICT",
            f"не удалось проверить возобновляемую ссылку {path}",
        ) from error
    if (
        not stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or observed != str(target)
    ):
        raise InstallError(
            "STABLE_LINK_CONFLICT",
            f"возобновляемая ссылка изменилась: {path}",
        )
    return False


def _require_first_install_journal_inputs_v2(
    journal: Mapping[str, Any],
    *,
    source_digest: str,
    codex_version: str,
) -> None:
    if (
        journal.get("sourceDigest") != source_digest
        or journal.get("codexVersion") != codex_version
    ):
        raise InstallError(
            "FIRST_INSTALL_INPUT_CHANGED",
            "исходники или версия Codex изменились после начала первой установки",
        )


def _build_first_install_journal_v2(
    layout: InstallLayout,
    *,
    source_digest: str,
    codex_version: str,
) -> dict[str, Any]:
    """Заморозить намерение первой установки до её первого эффекта."""

    unsigned = {
        "schemaVersion": 2,
        "kind": _FIRST_INSTALL_JOURNAL_KIND,
        "operation": "first-install",
        "phase": "INTENT_DURABLE",
        "operationId": "op2_" + secrets.token_hex(16),
        "installationId": "ins2_" + secrets.token_hex(16),
        "sourceDigest": source_digest,
        "codexVersion": codex_version,
        "sourceRoot": str(layout.source_root),
        "codexHome": str(layout.codex_home),
        "binDir": str(layout.bin_dir),
        "codexBinary": str(layout.codex_binary),
        "codexBinarySha256": file_digest(layout.codex_binary),
        "stateHome": str(layout.state_home),
        "installerReceiptPath": str(layout.installer_receipt_path),
        "binDirInitiallyAbsent": not os.path.lexists(layout.bin_dir),
        "links": [
            {
                "path": str(layout.launcher_path),
                "target": str(layout.launcher_target),
                "initiallyAbsent": True,
            },
            {
                "path": str(layout.admin_path),
                "target": str(layout.admin_target),
                "initiallyAbsent": True,
            },
        ],
        "marketplaceName": MARKETPLACE_NAME,
        "pluginId": PLUGIN_ID,
        "extensions": {},
        "createdAt": (
            datetime.now(timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        ),
    }
    unsigned["activationPreparation"] = {
        "journalPath": str(
            layout.gateway_layout.manifest_root
            / f"{INSTALLATION_NAME}.activation-preparation.transaction.json"
        ),
        "receiptPath": str(
            layout.gateway_layout.receipts_root
            / unsigned["installationId"]
            / f"{unsigned['operationId']}.preparation.json"
        ),
    }
    document = {
        **unsigned,
        "journalFingerprint": domain_fingerprint(
            _FIRST_INSTALL_JOURNAL_DOMAIN,
            unsigned,
        ),
    }
    return _validate_first_install_journal_v2(document, layout=layout)


def _validate_first_install_journal_v2(
    value: object,
    *,
    layout: InstallLayout,
) -> dict[str, Any]:
    expected_keys = {
        "schemaVersion",
        "kind",
        "operation",
        "phase",
        "operationId",
        "installationId",
        "sourceDigest",
        "codexVersion",
        "sourceRoot",
        "codexHome",
        "binDir",
        "codexBinary",
        "codexBinarySha256",
        "stateHome",
        "installerReceiptPath",
        "activationPreparation",
        "binDirInitiallyAbsent",
        "links",
        "marketplaceName",
        "pluginId",
        "extensions",
        "createdAt",
        "journalFingerprint",
    }
    if type(value) is not dict or set(value) != expected_keys:
        raise InstallError(
            "FIRST_INSTALL_JOURNAL_INVALID",
            "журнал первой установки не является закрытым документом",
        )
    document = dict(value)
    links = document.get("links")
    expected_links = [
        {
            "path": str(layout.launcher_path),
            "target": str(layout.launcher_target),
            "initiallyAbsent": True,
        },
        {
            "path": str(layout.admin_path),
            "target": str(layout.admin_target),
            "initiallyAbsent": True,
        },
    ]
    expected_preparation = {
        "journalPath": str(
            layout.gateway_layout.manifest_root
            / f"{INSTALLATION_NAME}.activation-preparation.transaction.json"
        ),
        "receiptPath": str(
            layout.gateway_layout.receipts_root
            / str(document.get("installationId"))
            / f"{document.get('operationId')}.preparation.json"
        ),
    }
    if (
        document.get("schemaVersion") != 2
        or document.get("kind") != _FIRST_INSTALL_JOURNAL_KIND
        or document.get("operation") != "first-install"
        or document.get("phase") != "INTENT_DURABLE"
        or not _identifier(document.get("operationId"), "op2_", 32)
        or not _identifier(document.get("installationId"), "ins2_", 32)
        or _SHA256_PATTERN.fullmatch(str(document.get("sourceDigest"))) is None
        or type(document.get("codexVersion")) is not str
        or document.get("sourceRoot") != str(layout.source_root)
        or document.get("codexHome") != str(layout.codex_home)
        or document.get("binDir") != str(layout.bin_dir)
        or document.get("codexBinary") != str(layout.codex_binary)
        or document.get("codexBinarySha256") != file_digest(layout.codex_binary)
        or document.get("stateHome") != str(layout.state_home)
        or document.get("installerReceiptPath")
        != str(layout.installer_receipt_path)
        or type(document.get("binDirInitiallyAbsent")) is not bool
        or links != expected_links
        or document.get("activationPreparation") != expected_preparation
        or document.get("marketplaceName") != MARKETPLACE_NAME
        or document.get("pluginId") != PLUGIN_ID
        or document.get("extensions") != {}
        or type(document.get("createdAt")) is not str
        or len(document["createdAt"].encode("utf-8")) > 64
        or _SHA256_PATTERN.fullmatch(
            str(document.get("journalFingerprint"))
        )
        is None
    ):
        raise InstallError(
            "FIRST_INSTALL_JOURNAL_INVALID",
            "поля журнала первой установки не совпадают с текущим layout",
        )
    unsigned = {
        name: document[name]
        for name in expected_keys
        if name != "journalFingerprint"
    }
    if document["journalFingerprint"] != domain_fingerprint(
        _FIRST_INSTALL_JOURNAL_DOMAIN,
        unsigned,
    ):
        raise InstallError(
            "FIRST_INSTALL_JOURNAL_INVALID",
            "отпечаток журнала первой установки не совпадает",
        )
    return document


def _load_first_install_journal_v2(layout: InstallLayout) -> dict[str, Any]:
    return _validate_first_install_journal_v2(
        _read_private_json(
            layout.first_install_journal_path,
            code="FIRST_INSTALL_JOURNAL_INVALID",
        ),
        layout=layout,
    )


def _delete_first_install_journal_v2(
    layout: InstallLayout,
    *,
    expected: Mapping[str, Any],
) -> None:
    observed = _load_first_install_journal_v2(layout)
    if observed != dict(expected):
        raise InstallError(
            "FIRST_INSTALL_JOURNAL_CHANGED",
            "журнал первой установки изменился перед завершением",
        )
    try:
        layout.first_install_journal_path.unlink()
    except OSError as error:
        raise InstallError(
            "FIRST_INSTALL_JOURNAL_DELETE_FAILED",
            "не удалось удалить завершённый журнал первой установки",
        ) from error
    _fsync_directory(layout.first_install_journal_path.parent)


def _repeat_install(
    layout: InstallLayout,
    *,
    source_digest: str,
    codex_version: str,
    extra_environment: Mapping[str, str] | None,
) -> dict[str, Any]:
    receipt = _load_installer_receipt(layout.installer_receipt_path)
    inspection = _inspect_installation_recovery_v2(layout)
    if inspection.journal_kind != "none":
        _recover_pending_install_journal_v2(
            layout,
            inspection=inspection,
            extra_environment=extra_environment,
        )
        return _repeat_install(
            layout,
            source_digest=source_digest,
            codex_version=codex_version,
            extra_environment=extra_environment,
        )
    reconciled = _try_reconcile_pending_committed_upgrade_v2(
        layout,
        previous_receipt=receipt,
        extra_environment=extra_environment,
    )
    if reconciled is not None:
        if reconciled["sourceDigest"] == source_digest:
            return reconciled
        receipt = _load_installer_receipt(layout.installer_receipt_path)
    if receipt["sourceDigest"] != source_digest:
        return _upgrade_install(
            layout,
            previous_receipt=receipt,
            source_digest=source_digest,
            codex_version=codex_version,
            extra_environment=extra_environment,
        )
    identity = _load_lifecycle_identity(layout)
    expected = _build_installer_receipt(
        layout,
        source_digest=source_digest,
        identity=identity,
    )
    if receipt != expected:
        raise InstallError(
            "INSTALLATION_MISMATCH",
            "квитанция, активация или пути установки не совпадают",
        )
    problems = _installation_problems(layout, extra_environment)
    if problems:
        raise InstallError("INSTALLATION_MISMATCH", "; ".join(problems))
    decision = _supervise_existing(layout, extra_environment=extra_environment)
    if decision.state is not GatewayState.READY:
        raise InstallError(
            "CONTROLLER_NOT_FULL_READY",
            f"супервизор не восстановил полный контроллер: {decision.reason_code}",
        )
    problems = _installation_problems(layout, extra_environment)
    if problems:
        raise InstallError("INSTALLATION_MISMATCH", "; ".join(problems))
    return {
        "status": "unchanged",
        "readiness": "FULL_READY",
        "sourceDigest": source_digest,
        "codexVersion": codex_version,
        "installationId": identity["installationId"],
        "activationId": identity["activationId"],
    }


def _upgrade_install(
    layout: InstallLayout,
    *,
    previous_receipt: Mapping[str, Any],
    source_digest: str,
    codex_version: str,
    extra_environment: Mapping[str, str] | None,
) -> dict[str, Any]:
    """Продолжить уже зафиксированное обновление либо начать новую операцию."""

    gateway = layout.gateway_layout
    if os.path.lexists(gateway.journal_path):
        return _recover_update_install_v2(
            layout,
            previous_receipt=previous_receipt,
            source_digest=source_digest,
            codex_version=codex_version,
            extra_environment=extra_environment,
        )
    reconciled = _try_reconcile_pending_committed_upgrade_v2(
        layout,
        previous_receipt=previous_receipt,
        extra_environment=extra_environment,
    )
    if reconciled is not None:
        if reconciled["sourceDigest"] == source_digest:
            return reconciled
        previous_receipt = _load_installer_receipt(layout.installer_receipt_path)

    _supervise_existing(
        layout,
        extra_environment=extra_environment,
    )
    proof = capture_activation_transition_proof_v2(
        codex_home=layout.codex_home,
        wrapper=layout.launcher_path,
        installer_receipt_path=layout.installer_receipt_path,
    )
    codex_binary_sha256 = file_digest(layout.codex_binary)
    operation_id = _update_operation_id_v2(
        installation_id=proof.installation_id,
        current_operation_id=proof.current_operation_id,
        current_activation_id=proof.activation_id,
        source_digest=source_digest,
        codex_binary_path=layout.codex_binary,
        codex_binary_sha256=codex_binary_sha256,
    )
    preparation = build_upgrade_preparation_v2(
        proof=proof,
        operation_id=operation_id,
        source_root=layout.source_root,
        codex_binary=layout.codex_binary,
        policy_bundle=_load_policy_bundle_v2(layout),
        source_digest=source_digest,
    )
    preparation_receipt = execute_and_verify_upgrade_preparation_v2(
        proof=proof,
        preparation=preparation,
    )
    run = _execute_fresh_update_composition_v2(
        layout,
        proof=proof,
        preparation=preparation,
        preparation_receipt=preparation_receipt,
        previous_receipt=previous_receipt,
        source_digest=source_digest,
        extra_environment=extra_environment,
    )
    result = _try_reconcile_committed_upgrade_v2(
        layout,
        previous_receipt=previous_receipt,
        source_digest=source_digest,
        codex_version=codex_version,
        extra_environment=extra_environment,
    )
    if result is None:
        raise InstallError(
            "UPDATE_COMMIT_NOT_RECONCILABLE",
            "завершённая операция не опубликовала согласованный манифест",
        )
    return {**result, "status": "upgraded", "attemptId": run.attempt_id}


def _execute_fresh_update_composition_v2(
    layout: InstallLayout,
    *,
    proof: Any,
    preparation: Any,
    preparation_receipt: Any,
    previous_receipt: Mapping[str, Any],
    source_digest: str,
    extra_environment: Mapping[str, str] | None,
):
    from codex_smart_subagents.installer_update_composition_v2 import (
        UpdateSourceBindingV2,
        build_candidate_spawn_action_v2,
        build_update_matched_active_composition_v2,
    )

    registry_plan = _build_update_registry_plan_v2(
        layout,
        previous_receipt=previous_receipt,
        preparation_receipt=preparation_receipt,
        operation_id=preparation_receipt.operation_id,
        extra_environment=extra_environment,
    )
    launcher_plan = _build_update_launcher_plan_v2(
        layout,
        previous_receipt=previous_receipt,
        preparation_receipt=preparation_receipt,
        operation_id=preparation_receipt.operation_id,
    )
    readiness_token = secrets.token_urlsafe(32)
    intent = preparation_receipt.activation_intent
    plugin_root = intent.activation_dir / "marketplace" / "plugins" / PLUGIN_NAME
    candidate_action = build_candidate_spawn_action_v2(
        preparation_receipt=preparation_receipt,
        readiness_token=readiness_token,
        interpreter=_bound_python_runtime_v2(),
        server_entrypoint=plugin_root / "controller" / "server.py",
        private_ready_channel_path=(
            _candidate_ready_socket_path_v2(
                intent.state_home,
                preparation_receipt.operation_id,
            )
        ),
    )
    runtime_environment = dict(os.environ)
    if extra_environment is not None:
        runtime_environment.update(extra_environment)
    composition = build_update_matched_active_composition_v2(
        registry=_lifecycle_plan_registry_v2(
            layout,
            activation_dir=intent.activation_dir,
        ),
        proof=proof,
        preparation=preparation,
        preparation_receipt=preparation_receipt,
        source_binding=UpdateSourceBindingV2(
            expected_source_digest=source_digest,
            expected_codex_sha256=intent.source_locator["sourceObservedSha256"],
            observe_source_digest=lambda: _source_digest(layout),
        ),
        registry_plan=registry_plan,
        launcher_plan=launcher_plan,
        candidate_action=candidate_action,
        readiness_token=readiness_token,
        wrapper_path=plugin_root / "bin" / "codex-smart",
        schema_directory=(
            intent.activation_dir / "marketplace" / "docs" / "contracts" / "schemas"
        ),
        runtime_environment=runtime_environment,
    )
    return composition.operation.execute()


def _recover_update_install_v2(
    layout: InstallLayout,
    *,
    previous_receipt: Mapping[str, Any],
    source_digest: str,
    codex_version: str,
    extra_environment: Mapping[str, str] | None,
) -> dict[str, Any]:
    """Восстановить main journal обновления; реализация ниже едина с recover."""

    composition = _build_update_main_recovery_composition_v2(
        layout,
        extra_environment=extra_environment,
    )
    run = composition.operation.execute()
    result = _try_reconcile_pending_committed_upgrade_v2(
        layout,
        previous_receipt=previous_receipt,
        extra_environment=extra_environment,
    )
    if result is None:
        raise InstallError(
            "UPDATE_RECOVERY_NOT_RECONCILABLE",
            "восстановленная операция не опубликовала ожидаемый манифест",
        )
    if result["sourceDigest"] != source_digest:
        return _upgrade_install(
            layout,
            previous_receipt=_load_installer_receipt(layout.installer_receipt_path),
            source_digest=source_digest,
            codex_version=codex_version,
            extra_environment=extra_environment,
        )
    return {**result, "status": "upgraded", "attemptId": run.attempt_id}


def _build_update_main_recovery_composition_v2(
    layout: InstallLayout,
    *,
    extra_environment: Mapping[str, str] | None,
):
    """Восстановить update-композицию только из journal и prep receipt."""

    from codex_smart_subagents.activation_preparation_v2 import (
        ActivationPreparationReceiptV2,
    )
    from codex_smart_subagents.installer_update_composition_v2 import (
        RegistryRuntimeBindingsV2,
        UpdateSourceBindingV2,
        recover_update_matched_active_composition_v2,
    )

    gateway = layout.gateway_layout
    bootstrap_journal = _read_private_json(
        gateway.journal_path,
        code="UPDATE_RECOVERY_JOURNAL_INVALID",
    )
    if (
        bootstrap_journal.get("kind") != "activation"
        or bootstrap_journal.get("operation") != "apply"
    ):
        raise InstallError(
            "UPDATE_RECOVERY_JOURNAL_INVALID",
            "main journal не является операцией обновления",
        )
    installation_id = bootstrap_journal.get("installationId")
    operation_id = bootstrap_journal.get("operationId")
    if not _identifier(installation_id, "ins2_", 32) or not _identifier(
        operation_id, "op2_", 32
    ):
        raise InstallError(
            "UPDATE_RECOVERY_JOURNAL_INVALID",
            "main journal не содержит устойчивые идентификаторы",
        )
    preparation_receipt_path = (
        gateway.receipts_root
        / str(installation_id)
        / f"{operation_id}.preparation.json"
    )
    preparation_receipt = ActivationPreparationReceiptV2.from_path(
        preparation_receipt_path
    )
    schema_directory = (
        preparation_receipt.activation_intent.activation_dir
        / "marketplace"
        / "docs"
        / "contracts"
        / "schemas"
    )
    store = OperationJournalStoreV2(
        journal_path=gateway.journal_path,
        lock_path=gateway.lock_path,
        validate_document=build_operation_journal_validator_v2(schema_directory),
    )
    journal = store.read()
    preparation = _recover_upgrade_preparation_from_main_journal_v2(
        preparation_receipt_path=preparation_receipt_path,
        journal=journal,
    )
    prepared_manifest = preparation.prepared_manifest_plan.manifest_document
    extensions = prepared_manifest.get("extensions")
    source_digest = (
        extensions.get("installerSourceDigest") if type(extensions) is dict else None
    )
    if (
        type(source_digest) is not str
        or _SHA256_PATTERN.fullmatch(source_digest) is None
    ):
        raise InstallError(
            "UPDATE_PREPARED_MANIFEST_INVALID",
            "prepared manifest не содержит installerSourceDigest",
        )
    previous_receipt = _load_installer_receipt(layout.installer_receipt_path)
    launcher_plan = _build_update_launcher_plan_v2(
        layout,
        previous_receipt=previous_receipt,
        preparation_receipt=preparation_receipt,
        operation_id=str(operation_id),
    )
    activation_dir = preparation_receipt.activation_intent.activation_dir
    contract = _load_activation_marketplace_contract_v2(activation_dir)
    working_directory = activation_dir
    runtime_environment = dict(os.environ)
    if extra_environment is not None:
        runtime_environment.update(extra_environment)
    return recover_update_matched_active_composition_v2(
        registry=_lifecycle_plan_registry_v2(
            layout,
            activation_dir=activation_dir,
        ),
        store=store,
        preparation=preparation,
        preparation_receipt_path=preparation_receipt_path,
        source_binding=UpdateSourceBindingV2(
            expected_source_digest=source_digest,
            expected_codex_sha256=(
                preparation_receipt.activation_intent.source_locator[
                    "sourceObservedSha256"
                ]
            ),
            observe_source_digest=lambda: (_ for _ in ()).throw(
                InstallError(
                    "UPDATE_RECOVERY_LIVE_SOURCE_FORBIDDEN",
                    "recovery не должен читать рабочий источник",
                )
            ),
        ),
        registry_runtime=RegistryRuntimeBindingsV2(
            working_directory=working_directory,
            plugin_relative_path=Path(contract.plugin_source_path),
            plugin_version=contract.plugin_version,
            install_policy=contract.install_policy,
            auth_policy=contract.auth_policy,
            command_runner=_registry_command_runner_v2(
                layout,
                extra_environment,
                working_directory=working_directory,
            ),
        ),
        launcher_bindings=launcher_plan.bindings,
        wrapper_path=(
            activation_dir
            / "marketplace"
            / "plugins"
            / PLUGIN_NAME
            / "bin"
            / "codex-smart"
        ),
        runtime_environment=runtime_environment,
    )


def _update_operation_id_v2(
    *,
    installation_id: str,
    current_operation_id: str,
    current_activation_id: str,
    source_digest: str,
    codex_binary_path: Path,
    codex_binary_sha256: str,
) -> str:
    """Стабильно адресовать один и тот же незавершённый запрос обновления."""

    if (
        not _identifier(installation_id, "ins2_", 32)
        or not _identifier(current_operation_id, "op2_", 32)
        or not _activation_identifier(current_activation_id)
        or _SHA256_PATTERN.fullmatch(source_digest) is None
        or not isinstance(codex_binary_path, Path)
        or not codex_binary_path.is_absolute()
        or _SHA256_PATTERN.fullmatch(codex_binary_sha256) is None
    ):
        raise InstallError(
            "UPDATE_OPERATION_ID_INPUT_INVALID",
            "идентичность текущей активации или sourceDigest неверны",
        )
    fingerprint = domain_fingerprint(
        "codex-smart/update-operation-id/v2",
        {
            "installationId": installation_id,
            "currentOperationId": current_operation_id,
            "currentActivationId": current_activation_id,
            "sourceDigest": source_digest,
            "codexBinaryPath": str(codex_binary_path),
            "codexBinarySha256": codex_binary_sha256,
        },
    )
    return "op2_" + fingerprint[:32]


def _registry_command_runner_v2(
    layout: InstallLayout,
    extra_environment: Mapping[str, str] | None,
    *,
    working_directory: Path | None = None,
):
    """Собрать ограниченный исполнитель команд реестра для одной установки."""

    fake_environment = {
        name: value
        for name, value in (extra_environment or {}).items()
        if name.startswith("FAKE_CODEX_") and type(value) is str and "\0" not in value
    }

    expected_working_directory = working_directory or layout.source_root

    def run(
        argv: tuple[str, ...],
        *,
        cwd: Path,
        env: dict[str, str],
        timeout_ms: int,
    ) -> subprocess.CompletedProcess[str]:
        if (
            type(argv) is not tuple
            or not argv
            or not all(type(item) is str and item and "\0" not in item for item in argv)
            or cwd != expected_working_directory
            or type(env) is not dict
            or not all(
                type(name) is str and type(value) is str for name, value in env.items()
            )
            or type(timeout_ms) is not int
            or not 1 <= timeout_ms <= 30_000
        ):
            raise InstallError(
                "REGISTRY_COMMAND_REQUEST_INVALID",
                "параметры команды реестра не совпадают с планом",
            )
        command_environment = dict(env)
        command_environment.update(fake_environment)
        try:
            return _run_supervised_completed_process_v2(
                argv,
                label="codex-registry-command",
                cwd=cwd,
                env=command_environment,
                timeout_seconds=timeout_ms / 1000.0,
            )
        except (
            OSError,
            supervised_subprocess_v2.SupervisedCommandV2Error,
        ) as error:
            raise InstallError(
                "REGISTRY_COMMAND_EXECUTION_FAILED",
                str(error),
            ) from error

    return run


def _build_update_registry_plan_v2(
    layout: InstallLayout,
    *,
    previous_receipt: Mapping[str, Any],
    preparation_receipt: Any,
    operation_id: str,
    extra_environment: Mapping[str, str] | None,
):
    from codex_smart_subagents.installer_update_composition_v2 import (
        build_registry_update_plan_v2,
    )

    contract = _load_marketplace_source_contract(layout)
    previous_marketplace = Path(
        str(previous_receipt.get("registeredMarketplacePath", ""))
    )
    candidate_marketplace = (
        preparation_receipt.activation_intent.activation_dir / "marketplace"
    )
    working_directory = preparation_receipt.activation_intent.activation_dir
    return build_registry_update_plan_v2(
        installation_id=preparation_receipt.installation_id,
        operation_id=operation_id,
        codex_binary=preparation_receipt.activation_intent.snapshot_path,
        codex_home=layout.codex_home,
        working_directory=working_directory,
        marketplace_path=layout.gateway_layout.marketplace_link,
        previous_registered_marketplace_path=previous_marketplace,
        registered_marketplace_path=candidate_marketplace,
        plugin_relative_path=Path(contract.plugin_source_path),
        plugin_version=contract.plugin_version,
        install_policy=contract.install_policy,
        auth_policy=contract.auth_policy,
        receipt_directory=(
            layout.gateway_layout.receipts_root / preparation_receipt.installation_id
        ),
        command_runner=_registry_command_runner_v2(
            layout,
            extra_environment,
            working_directory=working_directory,
        ),
    )


def _build_update_launcher_plan_v2(
    layout: InstallLayout,
    *,
    previous_receipt: Mapping[str, Any],
    preparation_receipt: Any,
    operation_id: str,
):
    from codex_smart_subagents.installer_update_composition_v2 import (
        LauncherBindingV2,
        build_launcher_update_plan_v2,
    )

    links = previous_receipt.get("links")
    if type(links) is not list or len(links) != 2:
        raise InstallError(
            "INSTALLER_RECEIPT_INVALID",
            "квитанция не содержит две стабильные ссылки",
        )
    candidate_marketplace = (
        preparation_receipt.activation_intent.activation_dir / "marketplace"
    )
    bindings = []
    seen_roles: set[str] = set()
    for value in links:
        if type(value) is not dict or set(value) != {"path", "target"}:
            raise InstallError(
                "INSTALLER_RECEIPT_INVALID",
                "описание стабильной ссылки имеет неверную форму",
            )
        path = Path(str(value["path"]))
        target = Path(str(value["target"]))
        try:
            relative_target = target.relative_to(layout.gateway_layout.marketplace_link)
        except ValueError as error:
            raise InstallError(
                "INSTALLER_RECEIPT_INVALID",
                "цель стабильной ссылки находится вне marketplace",
            ) from error
        role = {
            "codex-smart": "gateway",
            "codex-smart-subagents-admin": "admin",
        }.get(path.name)
        if role is None or role in seen_roles:
            raise InstallError(
                "INSTALLER_RECEIPT_INVALID",
                "набор ролей стабильных ссылок неоднозначен",
            )
        seen_roles.add(role)
        bindings.append(
            LauncherBindingV2(
                name=path.name,
                role=role,
                path=path,
                target=target,
                expected_resolved_target=(candidate_marketplace / relative_target),
            )
        )
    return build_launcher_update_plan_v2(
        installation_id=preparation_receipt.installation_id,
        operation_id=operation_id,
        bindings=tuple(bindings),
    )


def _inspect_pending_committed_upgrade_v2(
    layout: InstallLayout,
    *,
    previous_receipt: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Чисто распознать commit, ещё не доведённый до installer receipt."""

    manifest = _read_private_json(
        layout.gateway_layout.manifest_path,
        code="LIFECYCLE_MANIFEST_INVALID",
    )
    active = manifest.get("activeActivation")
    previous = manifest.get("previousActivation")
    extensions = manifest.get("extensions")
    installation_id = manifest.get("installationId")
    operation_id = manifest.get("lastCommittedOperation")
    active_id = active.get("activationId") if type(active) is dict else None
    previous_id = previous.get("activationId") if type(previous) is dict else None
    receipt_installation_id = previous_receipt.get("installationId")
    receipt_activation_id = previous_receipt.get("activationId")
    receipt_digest = previous_receipt.get("sourceDigest")
    committed_digest = (
        extensions.get("installerSourceDigest") if type(extensions) is dict else None
    )
    if (
        manifest.get("schemaVersion") != 2
        or not _identifier(installation_id, "ins2_", 32)
        or not _identifier(operation_id, "op2_", 32)
        or not _activation_identifier(active_id)
        or not _identifier(receipt_installation_id, "ins2_", 32)
        or not _activation_identifier(receipt_activation_id)
        or _SHA256_PATTERN.fullmatch(str(receipt_digest)) is None
    ):
        raise InstallError(
            "LIFECYCLE_MANIFEST_INVALID",
            "манифест и квитанция не задают проверяемую границу обновления",
        )
    if installation_id != receipt_installation_id:
        raise InstallError(
            "INSTALLATION_MISMATCH",
            "манифест и квитанция принадлежат разным установкам",
        )
    if active_id == receipt_activation_id:
        if committed_digest is not None and committed_digest != receipt_digest:
            raise InstallError(
                "INSTALLATION_MISMATCH",
                "sourceDigest манифеста расходится с активной квитанцией",
            )
        return None
    if (
        not _activation_identifier(previous_id)
        or previous_id != receipt_activation_id
        or _SHA256_PATTERN.fullmatch(str(committed_digest)) is None
    ):
        raise InstallError(
            "UPDATE_RECOVERY_NOT_RECONCILABLE",
            "принятая активация не продолжает активацию из квитанции",
        )
    source_locator = manifest.get("sourceLocator")
    committed_codex = (
        source_locator.get("lexicalPath") if type(source_locator) is dict else None
    )
    if not _absolute_string_path(committed_codex):
        raise InstallError(
            "UPDATE_RECOVERY_NOT_RECONCILABLE",
            "манифест не содержит зафиксированный лексический путь Codex",
        )
    return {
        "installationId": str(installation_id),
        "operationId": str(operation_id),
        "activeActivationId": str(active_id),
        "previousActivationId": str(previous_id),
        "sourceDigest": str(committed_digest),
        "codexBinary": str(committed_codex),
    }


def _try_reconcile_pending_committed_upgrade_v2(
    layout: InstallLayout,
    *,
    previous_receipt: Mapping[str, Any],
    extra_environment: Mapping[str, str] | None,
) -> dict[str, Any] | None:
    """Согласовать уже принятую активацию по её долговечному D1.

    Живой исходник и выбранный сейчас Codex могут уже задавать следующую цель
    D2. Поэтому D1 и версию Codex берём только из принятого манифеста и его
    неизменяемого снимка. Новая D2 после этого получает отдельную операцию.
    """

    pending = _inspect_pending_committed_upgrade_v2(
        layout,
        previous_receipt=previous_receipt,
    )
    if pending is None:
        _fsync_directory(layout.installer_receipt_path.parent)
        return None
    committed_runtime = _registration_runtime_layout_v2(layout)
    committed_version = _probe_version(committed_runtime, extra_environment)
    reconciliation_layout = InstallLayout(
        source_root=layout.source_root,
        codex_home=layout.codex_home,
        bin_dir=layout.bin_dir,
        codex_binary=Path(str(pending["codexBinary"])),
        state_home=layout.state_home,
    )
    result = _try_reconcile_committed_upgrade_v2(
        reconciliation_layout,
        previous_receipt=previous_receipt,
        source_digest=str(pending["sourceDigest"]),
        codex_version=committed_version,
        extra_environment=extra_environment,
    )
    if result is None:
        raise InstallError(
            "UPDATE_RECOVERY_NOT_RECONCILABLE",
            "принятая активация не согласована по зафиксированному sourceDigest",
        )
    return result


def _try_reconcile_committed_upgrade_v2(
    layout: InstallLayout,
    *,
    previous_receipt: Mapping[str, Any],
    source_digest: str,
    codex_version: str,
    extra_environment: Mapping[str, str] | None,
) -> dict[str, Any] | None:
    """Довести производную квитанцию после уже завершённого commit.

    Авария между удалением основного журнала и заменой квитанции установщика
    не должна запускать второе обновление. Новый манифест и неизменяемая
    commit-квитанция являются единственным источником истины для доведения.
    """

    manifest = _read_private_json(
        layout.gateway_layout.manifest_path,
        code="LIFECYCLE_MANIFEST_INVALID",
    )
    extensions = manifest.get("extensions")
    committed_digest = (
        extensions.get("installerSourceDigest") if type(extensions) is dict else None
    )
    if committed_digest != source_digest:
        return None
    active = manifest.get("activeActivation")
    previous = manifest.get("previousActivation")
    installation_id = manifest.get("installationId")
    operation_id = manifest.get("lastCommittedOperation")
    if (
        manifest.get("schemaVersion") != 2
        or type(active) is not dict
        or type(previous) is not dict
        or not _identifier(installation_id, "ins2_", 32)
        or not _identifier(operation_id, "op2_", 32)
        or not _activation_identifier(active.get("activationId"))
        or not _activation_identifier(previous.get("activationId"))
        or previous.get("activationId") == active.get("activationId")
    ):
        raise InstallError(
            "LIFECYCLE_MANIFEST_INVALID",
            "зафиксированный манифест не описывает завершённое обновление",
        )
    identity = {
        "installationId": str(installation_id),
        "activationId": str(active["activationId"]),
        "operationId": str(operation_id),
    }
    expected = _build_installer_receipt(
        layout,
        source_digest=source_digest,
        identity=identity,
    )
    observed_receipt = _load_installer_receipt(layout.installer_receipt_path)
    if observed_receipt not in (dict(previous_receipt), expected):
        raise InstallError(
            "INSTALLER_RECEIPT_CHANGED",
            "квитанция установщика изменилась во время доведения",
        )
    _archive_previous_installer_receipt_v2(
        layout,
        receipt=previous_receipt,
        activation_id=str(previous["activationId"]),
    )

    def verify_external_state() -> bool:
        problems = _installation_problems(layout, extra_environment)
        if problems:
            raise InstallError(
                "INSTALLATION_MISMATCH",
                "; ".join(problems),
            )
        return True

    verify_external_state()
    decision = _supervise_existing(
        layout,
        extra_environment=extra_environment,
    )
    if decision.state is not GatewayState.READY:
        raise InstallError(
            "CONTROLLER_NOT_FULL_READY",
            f"супервизор не восстановил полный контроллер: {decision.reason_code}",
        )
    result = reconcile_installer_receipt_v2(
        receipt_path=layout.installer_receipt_path,
        manifest_path=layout.gateway_layout.manifest_path,
        commit_receipt_path=(
            layout.gateway_layout.receipts_root
            / str(installation_id)
            / f"{operation_id}.commit.json"
        ),
        operation_journal_path=layout.gateway_layout.journal_path,
        expected_receipt=expected,
        verify_external_state=verify_external_state,
    )
    return {
        "status": "reconciled",
        "readiness": "FULL_READY",
        "sourceDigest": result.source_digest,
        "codexVersion": codex_version,
        "installationId": result.installation_id,
        "activationId": result.activation_id,
        "previousActivationId": str(previous["activationId"]),
        "operationId": result.operation_id,
    }


def doctor(
    layout: InstallLayout,
    *,
    extra_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    problems: list[str] = []
    if os.path.lexists(layout.first_install_journal_path):
        try:
            _load_first_install_journal_v2(layout)
        except InstallError as exc:
            problems.append(exc.code)
        else:
            problems.append("FIRST_INSTALL_RECOVERY_REQUIRED")
    receipt: Mapping[str, Any] | None = None
    identity: Mapping[str, str] | None = None
    try:
        receipt = _load_installer_receipt(layout.installer_receipt_path)
    except InstallError as exc:
        problems.append(exc.code)
    try:
        identity = _load_lifecycle_identity(layout)
    except InstallError as exc:
        problems.append(exc.code)
    if receipt is not None and identity is not None:
        try:
            committed_layout = _committed_installer_layout_v2(layout, receipt)
            expected = _build_installer_receipt(
                committed_layout,
                source_digest=str(receipt["sourceDigest"]),
                identity=identity,
            )
            if receipt != expected:
                problems.append("INSTALLER_RECEIPT_MISMATCH")
        except (InstallError, KeyError, TypeError, ValueError):
            problems.append("INSTALLER_RECEIPT_MISMATCH")
    problems.extend(_stable_link_problems(layout, require_targets=True))
    try:
        problems.extend(_registration_problems(layout, extra_environment))
    except InstallError as exc:
        problems.append(exc.code)

    decision: GatewayDecision | None = None
    reason_code = "ACTIVATION_RESOLVER_UNAVAILABLE"
    try:
        decision = _resolve_activation(layout)
        reason_code = decision.reason_code
    except Exception as exc:
        reason_code = str(getattr(exc, "code", type(exc).__name__))
    if decision is None or decision.state is GatewayState.ORDINARY:
        status = "ORDINARY"
    elif _probe_command_socket(layout):
        status = "FULL_READY"
    else:
        status = "HEALTH_ONLY"
    problems = list(dict.fromkeys(problems))
    return {
        "ok": status == "FULL_READY" and not problems,
        "status": status,
        "readiness": status,
        "gatewayReason": reason_code,
        "problems": problems,
        "sourceDigest": receipt.get("sourceDigest") if receipt else None,
        "activationId": identity.get("activationId") if identity else None,
    }


def smoke(
    layout: InstallLayout,
    *,
    extra_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    diagnosis = doctor(layout, extra_environment=extra_environment)
    if not diagnosis["ok"]:
        raise InstallError(
            "INSTALLATION_NOT_FULL_READY",
            f"дымовая проверка запрещена при состоянии {diagnosis['status']}",
        )
    completed = _run_process(
        [str(layout.launcher_path), "--version"],
        layout=layout,
        extra_environment=extra_environment,
    )
    if completed.returncode != 0:
        raise InstallError(
            "LAUNCHER_SMOKE_FAILED",
            _bounded_error(completed),
        )
    return {
        "ok": True,
        "status": "FULL_READY",
        "launcherVersion": completed.stdout.strip(),
    }


def initial_controller_environment(
    layout: InstallLayout,
    source: Mapping[str, str] | None = None,
    *,
    first_install_journal: Mapping[str, Any] | None = None,
) -> dict[str, str]:
    inherited = dict(os.environ)
    if source is not None:
        inherited.update(source)
    if not all(
        type(name) is str and type(value) is str for name, value in inherited.items()
    ):
        raise InstallError(
            "INITIAL_CONTROLLER_ENVIRONMENT_INVALID",
            "исходное окружение должно содержать только строки",
        )
    environment = {
        "PATH": os.defpath,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONUNBUFFERED": "1",
        "CODEX_HOME": str(layout.codex_home),
        "CODEX_V2_SOURCE_ROOT": str(layout.source_root),
        "CODEX_V2_CODEX_BIN": str(layout.codex_binary),
        "CODEX_V2_WRAPPER_PATH": str(layout.bootstrap_wrapper),
        "CODEX_V2_STATE_HOME": str(layout.state_home),
    }
    if first_install_journal is not None:
        journal = _validate_first_install_journal_v2(
            dict(first_install_journal),
            layout=layout,
        )
        environment["CODEX_V2_FIRST_INSTALL_OPERATION_ID"] = str(
            journal["operationId"]
        )
        environment["CODEX_V2_FIRST_INSTALLATION_ID"] = str(
            journal["installationId"]
        )
    for name in _SAFE_INHERITED_ENVIRONMENT:
        value = inherited.get(name)
        if type(value) is str and value and "\0" not in value:
            environment[name] = value
    require_initial_controller_environment(
        layout,
        environment,
        first_install_journal=first_install_journal,
    )
    return environment


def require_initial_controller_environment(
    layout: InstallLayout,
    environment: Mapping[str, str],
    *,
    first_install_journal: Mapping[str, Any] | None = None,
) -> None:
    expected = {
        "CODEX_V2_SOURCE_ROOT": str(layout.source_root),
        "CODEX_V2_CODEX_BIN": str(layout.codex_binary),
        "CODEX_V2_WRAPPER_PATH": str(layout.bootstrap_wrapper),
        "CODEX_V2_STATE_HOME": str(layout.state_home),
    }
    if first_install_journal is not None:
        journal = _validate_first_install_journal_v2(
            dict(first_install_journal),
            layout=layout,
        )
        expected.update(
            {
                "CODEX_V2_FIRST_INSTALL_OPERATION_ID": str(
                    journal["operationId"]
                ),
                "CODEX_V2_FIRST_INSTALLATION_ID": str(
                    journal["installationId"]
                ),
            }
        )
    if (
        environment.get("CODEX_HOME") != str(layout.codex_home)
        or any(environment.get(name) != value for name, value in expected.items())
        or environment.get("PATH") != os.defpath
        or environment.get("PYTHONDONTWRITEBYTECODE") != "1"
        or "PYTHONPATH" in environment
        or any(
            name.startswith(("CODEX_SMART_", "CODEX_ADAPTIVE_", "CODEX_COORDINATOR_"))
            or name == "CODEX_REAL_BIN"
            for name in environment
        )
    ):
        raise InstallError(
            "INITIAL_CONTROLLER_ENVIRONMENT_INVALID",
            "закрытое окружение первичного контроллера неполно или загрязнено",
        )


def _spawn_initial_controller(
    layout: InstallLayout,
    source_environment: Mapping[str, str] | None = None,
    *,
    first_install_journal: Mapping[str, Any] | None = None,
) -> subprocess.Popen:
    environment = initial_controller_environment(
        layout,
        source_environment,
        first_install_journal=first_install_journal,
    )
    require_initial_controller_environment(
        layout,
        environment,
        first_install_journal=first_install_journal,
    )
    supervisor = (
        operation_process_group_supervisor_v2.
        current_process_group_supervisor_v2()
    )
    if supervisor is not None:
        cleanup_deadline = (
            operation_deadline_v2.current_operation_deadline_v2()
        )
        if cleanup_deadline is None:
            cleanup_deadline = operation_deadline_v2.OperationDeadlineV2.start(
                operation="initial-controller-start",
                timeout_seconds=_FULL_READY_TIMEOUT_SECONDS,
                timeout_code="INITIAL_CONTROLLER_START_TIMEOUT",
            )
        gate_deadline = cleanup_deadline.child(
            phase="initial-controller-bootstrap",
            max_seconds=_INITIAL_CONTROLLER_BOOTSTRAP_TIMEOUT_SECONDS,
            timeout_code="INITIAL_CONTROLLER_BOOTSTRAP_TIMEOUT",
        )
        lease = supervised_subprocess_v2.spawn_gated_transient_v2(
            label="initial-controller",
            argv=(
                str(Path(sys.executable).resolve()),
                str(layout.controller_entrypoint),
                "--serve-v2",
            ),
            cwd=layout.plugin_source,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            gate_deadline=gate_deadline,
            cleanup_deadline=cleanup_deadline,
            cleanup_wait_seconds=5,
            supervisor=supervisor,
        )
        process = lease.process
        setattr(process, "_codex_process_supervisor_v2", supervisor)
        setattr(process, "_codex_process_lease_v2", lease)
        return process
    return subprocess.Popen(
        (
            str(Path(sys.executable).resolve()),
            str(layout.controller_entrypoint),
            "--serve-v2",
        ),
        cwd=layout.plugin_source,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        close_fds=True,
        start_new_session=True,
    )


def _initial_controller_exit_error(process: Any) -> str:
    communicate = getattr(process, "communicate", None)
    if not callable(communicate):
        return ""
    try:
        result = communicate(timeout=1.0)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return ""
    if not isinstance(result, tuple) or len(result) != 2:
        return ""
    stderr = result[1]
    if not isinstance(stderr, str):
        return ""
    return " ".join(stderr.split())[:4096]


def _wait_for_full_ready(
    layout: InstallLayout,
    process: Any,
) -> GatewayDecision:
    operation_deadline = operation_deadline_v2.current_operation_deadline_v2()
    timeout_seconds = _FULL_READY_TIMEOUT_SECONDS
    if operation_deadline is not None:
        timeout_seconds = operation_deadline.bounded_timeout_seconds(
            local_cap_seconds=_FULL_READY_TIMEOUT_SECONDS
        )
    deadline = time.monotonic() + timeout_seconds
    last_reason = "ACTIVATION_NOT_READY"
    ready_candidate: GatewayDecision | None = None
    while True:
        if operation_deadline is not None:
            operation_deadline.checkpoint()
        if ready_candidate is None:
            try:
                decision = _resolve_activation(layout)
                last_reason = decision.reason_code
                if decision.state is GatewayState.READY:
                    ready_candidate = decision
            except Exception as exc:
                last_reason = str(getattr(exc, "code", type(exc).__name__))
        if ready_candidate is not None and _probe_command_socket(layout):
            try:
                fresh = _resolve_activation(layout)
                last_reason = fresh.reason_code
                if (
                    fresh.state is GatewayState.READY
                    and fresh.activation_id == ready_candidate.activation_id
                    and _probe_command_socket(layout)
                ):
                    return fresh
            except Exception as exc:
                last_reason = str(getattr(exc, "code", type(exc).__name__))
            ready_candidate = None
        poll = getattr(process, "poll", None)
        if callable(poll) and poll() is not None:
            controller_error = _initial_controller_exit_error(process)
            detail = f"контроллер завершился до FULL_READY: {last_reason}"
            if controller_error:
                detail = f"{detail}; причина контроллера: {controller_error}"
            raise InstallError(
                "INITIAL_CONTROLLER_EXITED",
                detail,
            )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise InstallError(
                "FULL_READY_TIMEOUT",
                f"контроллер не достиг FULL_READY: {last_reason}",
            )
        time.sleep(min(_FULL_READY_POLL_SECONDS, remaining))


def _resolve_activation(layout: InstallLayout) -> GatewayDecision:
    return ActivationResolver(
        layout=layout.gateway_layout,
        wrapper=layout.launcher_path,
    ).resolve()


def _probe_command_socket(layout: InstallLayout) -> bool:
    return probe_controller_command_socket_v2(layout.state_home / "command.sock")


def _supervise_existing(
    layout: InstallLayout,
    *,
    extra_environment: Mapping[str, str] | None = None,
) -> GatewayDecision:
    resolver = ActivationResolver(
        layout=layout.gateway_layout,
        wrapper=layout.launcher_path,
    )
    try:
        plugin_root = layout.installed_plugin_root.resolve(strict=True)
        supervisor = ControllerSupervisorV2(
            resolver=resolver,
            manifest_path=layout.gateway_layout.manifest_path,
            state_home=layout.state_home,
            codex_home=layout.codex_home,
            plugin_root=plugin_root,
            source_environment=(
                os.environ if extra_environment is None else extra_environment
            ),
            wait_timeout_seconds=_FULL_READY_TIMEOUT_SECONDS,
        )
        result = supervisor.ensure()
    except Exception as exc:
        raise InstallError(
            "SUPERVISOR_FAILED",
            str(getattr(exc, "code", type(exc).__name__)),
        ) from exc
    if result.state is not SupervisorStateV2.READY:
        raise InstallError(
            "CONTROLLER_NOT_FULL_READY",
            result.reason_code,
        )
    return result.gateway_decision


def _preflight_first_install(
    layout: InstallLayout,
    extra_environment: Mapping[str, str] | None,
) -> None:
    for path in (layout.launcher_path, layout.admin_path):
        if os.path.lexists(path):
            raise InstallError(
                "STABLE_LINK_CONFLICT",
                f"путь стабильной ссылки уже занят: {path}",
            )
    marketplace_entries = _target_marketplaces(layout, extra_environment)
    plugin_entries = _target_plugins(layout, extra_environment)
    if marketplace_entries or plugin_entries:
        raise InstallError(
            "REGISTRATION_CONFLICT",
            "целевая регистрация уже существует без квитанции установщика",
        )


def _create_stable_link(path: Path, target: Path) -> None:
    _ensure_owned_directory(path.parent, create=False, private=False)
    try:
        os.symlink(str(target), path)
    except FileExistsError as exc:
        raise InstallError(
            "STABLE_LINK_CONFLICT",
            f"путь стабильной ссылки занят: {path}",
        ) from exc
    except OSError as exc:
        raise InstallError(
            "STABLE_LINK_CREATE_FAILED",
            f"не удалось создать стабильную ссылку {path}: {exc}",
        ) from exc
    _fsync_directory(path.parent)


def _stable_link_problems(
    layout: InstallLayout,
    *,
    require_targets: bool,
) -> list[str]:
    problems: list[str] = []
    for label, path, target in (
        ("LAUNCHER_LINK_MISMATCH", layout.launcher_path, layout.launcher_target),
        ("ADMIN_LINK_MISMATCH", layout.admin_path, layout.admin_target),
    ):
        try:
            info = os.lstat(path)
            observed = os.readlink(path)
        except OSError:
            problems.append(label)
            continue
        if (
            not stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
            or observed != str(target)
        ):
            problems.append(label)
            continue
        if require_targets:
            try:
                target_info = os.lstat(target)
            except OSError:
                problems.append(label)
                continue
            if (
                not stat.S_ISREG(target_info.st_mode)
                or target_info.st_uid != os.getuid()
            ):
                problems.append(label)
    return problems


def _load_lifecycle_identity(
    layout: InstallLayout,
    *,
    require_first_activation: bool = False,
) -> dict[str, Any]:
    path = layout.gateway_layout.manifest_path
    document = _read_private_json(path, code="LIFECYCLE_MANIFEST_INVALID")
    if document.get("schemaVersion") != 2:
        raise InstallError(
            "LEGACY_INSTALLATION_CONFLICT",
            "применяемый путь не принимает lifecycle-манифест schema 1",
        )
    active = document.get("activeActivation")
    previous = document.get("previousActivation")
    installation_id = document.get("installationId")
    operation_id = document.get("lastCommittedOperation")
    if (
        type(active) is not dict
        or not _identifier(installation_id, "ins2_", 32)
        or not _identifier(operation_id, "op2_", 32)
        or not _activation_identifier(active.get("activationId"))
        or document.get("stateHome") != str(layout.state_home)
    ):
        raise InstallError(
            "LIFECYCLE_MANIFEST_INVALID",
            "lifecycle-манифест не описывает принятую активацию",
        )
    expected_target = f"activations/{active['activationId']}/marketplace"
    if active.get("symlinkTarget") != expected_target:
        raise InstallError(
            "LIFECYCLE_MANIFEST_INVALID",
            "lifecycle-манифест содержит другую активную ссылку",
        )
    previous_activation_id: str | None = None
    if previous is not None:
        if (
            type(previous) is not dict
            or not _activation_identifier(previous.get("activationId"))
            or previous.get("activationId") == active.get("activationId")
            or previous.get("symlinkTarget")
            != f"activations/{previous.get('activationId')}/marketplace"
        ):
            raise InstallError(
                "LIFECYCLE_MANIFEST_INVALID",
                "previousActivation не описывает отдельную принятую активацию",
            )
        previous_activation_id = str(previous["activationId"])
    if require_first_activation and previous_activation_id is not None:
        raise InstallError(
            "LIFECYCLE_MANIFEST_INVALID",
            "первая установка неожиданно содержит previousActivation",
        )
    return {
        "installationId": str(installation_id),
        "activationId": str(active["activationId"]),
        "operationId": str(operation_id),
        "previousActivationId": previous_activation_id,
    }


def _materialized_source_digest_v2(
    layout: InstallLayout,
    *,
    identity: Mapping[str, str],
) -> str:
    manifest = _read_private_json(
        layout.gateway_layout.manifest_path,
        code="LIFECYCLE_MANIFEST_INVALID",
    )
    active = manifest.get("activeActivation")
    source_locator = manifest.get("sourceLocator")
    snapshot_locator = manifest.get("codexSnapshot")
    activation_id = identity.get("activationId")
    if (
        not _activation_identifier(activation_id)
        or type(active) is not dict
        or active.get("activationId") != activation_id
        or type(source_locator) is not dict
        or source_locator.get("lexicalPath") != str(layout.codex_binary)
        or type(snapshot_locator) is not dict
        or type(snapshot_locator.get("absolutePath")) is not str
    ):
        raise InstallError(
            "INITIAL_PREPARED_SOURCE_INVALID",
            "принятая активация не содержит воспроизводимую привязку исходников",
        )
    activation_dir = (
        layout.gateway_layout.managed_root / "activations" / str(activation_id)
    )
    snapshot_path = Path(str(snapshot_locator["absolutePath"]))
    try:
        return installer_source_digest_from_materialized_activation_v2(
            activation_dir=activation_dir,
            codex_binary=layout.codex_binary,
            source_locator=source_locator,
            snapshot_locator=snapshot_locator,
            snapshot_path=snapshot_path,
        )
    except Exception as exc:
        raise InstallError(
            "INITIAL_PREPARED_SOURCE_INVALID",
            str(exc),
        ) from exc


def _build_installer_receipt(
    layout: InstallLayout,
    *,
    source_digest: str,
    identity: Mapping[str, str],
) -> dict[str, Any]:
    if _SHA256_PATTERN.fullmatch(source_digest) is None:
        raise InstallError("SOURCE_DIGEST_INVALID", "sourceDigest неверен")
    try:
        installation_id = identity["installationId"]
        activation_id = identity["activationId"]
        registered_marketplace_path = str(
            layout.gateway_layout.marketplace_link.resolve(strict=True)
        )
    except (KeyError, OSError, RuntimeError) as exc:
        raise InstallError(
            "INSTALLER_RECEIPT_INVALID",
            "невозможно связать квитанцию с принятой активацией",
        ) from exc
    value = {
        "schemaVersion": 2,
        "kind": INSTALLER_RECEIPT_KIND,
        "sourceDigest": source_digest,
        "installationId": installation_id,
        "activationId": activation_id,
        "codexHome": str(layout.codex_home),
        "codexBinary": str(layout.codex_binary),
        "stateHome": str(layout.state_home),
        "marketplacePath": str(layout.gateway_layout.marketplace_link),
        "registeredMarketplacePath": registered_marketplace_path,
        "links": [
            {"path": str(layout.launcher_path), "target": str(layout.launcher_target)},
            {"path": str(layout.admin_path), "target": str(layout.admin_target)},
        ],
        "marketplaceName": MARKETPLACE_NAME,
        "pluginId": PLUGIN_ID,
        "extensions": {},
    }
    return _validate_installer_receipt_document(value)


def _committed_installer_layout_v2(
    layout: InstallLayout,
    receipt: Mapping[str, Any],
) -> InstallLayout:
    """Восстановить исторический lexical Codex из принятого манифеста."""

    manifest = _read_private_json(
        layout.gateway_layout.manifest_path,
        code="LIFECYCLE_MANIFEST_INVALID",
    )
    source_locator = manifest.get("sourceLocator")
    lexical_path = (
        source_locator.get("lexicalPath") if type(source_locator) is dict else None
    )
    if (
        not _absolute_string_path(lexical_path)
        or receipt.get("codexBinary") != lexical_path
    ):
        raise InstallError(
            "INSTALLER_RECEIPT_MISMATCH",
            "квитанция не совпадает с lexical Codex принятого манифеста",
        )
    return InstallLayout(
        source_root=layout.source_root,
        codex_home=layout.codex_home,
        bin_dir=layout.bin_dir,
        codex_binary=Path(str(lexical_path)),
        state_home=layout.state_home,
    )


def _load_installer_receipt(path: Path) -> dict[str, Any]:
    value = _read_private_json(path, code="INSTALLER_RECEIPT_INVALID")
    return _validate_installer_receipt_document(value)


def _archive_previous_installer_receipt_v2(
    layout: InstallLayout,
    *,
    receipt: Mapping[str, Any],
    activation_id: str,
) -> Path:
    """До замены сохранить точную квитанцию предыдущей активации."""

    document = _validate_installer_receipt_document(dict(receipt))
    installation_id = document["installationId"]
    if (
        not _identifier(installation_id, "ins2_", 32)
        or not _activation_identifier(activation_id)
        or document["activationId"] != activation_id
    ):
        raise InstallError(
            "INSTALLER_RECEIPT_ARCHIVE_INVALID",
            "квитанция не принадлежит архивируемой активации",
        )
    path = (
        layout.gateway_layout.receipts_root
        / str(installation_id)
        / f"{activation_id}.installer.json"
    )
    if os.path.lexists(path):
        if _load_installer_receipt(path) != document:
            raise InstallError(
                "INSTALLER_RECEIPT_ARCHIVE_CONFLICT",
                "архив предыдущей квитанции содержит другое значение",
            )
        _fsync_directory(path.parent)
        if _load_installer_receipt(path) != document:
            raise InstallError(
                "INSTALLER_RECEIPT_ARCHIVE_CONFLICT",
                "архив предыдущей квитанции изменился при синхронизации",
            )
        return path
    _atomic_create_json(path, document)
    if _load_installer_receipt(path) != document:
        raise InstallError(
            "INSTALLER_RECEIPT_ARCHIVE_FAILED",
            "архив предыдущей квитанции не подтвердился после записи",
        )
    return path


def _validate_installer_receipt_document(value: object) -> dict[str, Any]:
    expected_keys = {
        "schemaVersion",
        "kind",
        "sourceDigest",
        "installationId",
        "activationId",
        "codexHome",
        "codexBinary",
        "stateHome",
        "marketplacePath",
        "registeredMarketplacePath",
        "links",
        "marketplaceName",
        "pluginId",
        "extensions",
    }
    if type(value) is not dict:
        raise InstallError(
            "INSTALLER_RECEIPT_INVALID",
            "закрытая квитанция установщика не является объектом",
        )
    links = value.get("links")
    links_valid = bool(
        type(links) is list
        and len(links) == 2
        and all(
            type(link) is dict
            and set(link) == {"path", "target"}
            and _absolute_string_path(link.get("path"))
            and _absolute_string_path(link.get("target"))
            for link in links
        )
        and len({link["path"] for link in links}) == 2
        and len({link["target"] for link in links}) == 2
    )
    if (
        set(value) != expected_keys
        or value.get("schemaVersion") != 2
        or value.get("kind") != INSTALLER_RECEIPT_KIND
        or _SHA256_PATTERN.fullmatch(str(value.get("sourceDigest"))) is None
        or not _identifier(value.get("installationId"), "ins2_", 32)
        or not _activation_identifier(value.get("activationId"))
        or value.get("marketplaceName") != MARKETPLACE_NAME
        or value.get("pluginId") != PLUGIN_ID
        or value.get("extensions") != {}
        or not _absolute_string_path(value.get("codexHome"))
        or not _absolute_string_path(value.get("codexBinary"))
        or not _absolute_string_path(value.get("stateHome"))
        or not _absolute_string_path(value.get("marketplacePath"))
        or not _absolute_string_path(value.get("registeredMarketplacePath"))
        or not links_valid
    ):
        raise InstallError(
            "INSTALLER_RECEIPT_INVALID",
            "закрытая квитанция установщика имеет неверную форму",
        )
    return dict(value)


def _installation_problems(
    layout: InstallLayout,
    extra_environment: Mapping[str, str] | None,
) -> list[str]:
    problems = _stable_link_problems(layout, require_targets=True)
    problems.extend(_registration_problems(layout, extra_environment))
    return list(dict.fromkeys(problems))


def _registration_runtime_layout_v2(layout: InstallLayout) -> InstallLayout:
    """Выбрать Codex из принятой неизменяемой активации для реестра.

    До первой активации допустим выбранный пользователем исполняемый файл. После
    появления lifecycle-манифеста любые запросы и изменения реестра должны быть
    воспроизводимы без исходного дерева и без прежнего лексического пути Codex.
    """

    manifest_path = layout.gateway_layout.manifest_path
    if not os.path.lexists(manifest_path):
        return layout
    manifest = _read_private_json(
        manifest_path,
        code="REGISTRATION_RUNTIME_INVALID",
    )
    active = manifest.get("activeActivation")
    activation_id = active.get("activationId") if type(active) is dict else None
    manifest_snapshot = manifest.get("codexSnapshot")
    if (
        manifest.get("schemaVersion") != 2
        or not _activation_identifier(activation_id)
        or type(manifest_snapshot) is not dict
        or set(manifest_snapshot) != {"absolutePath", "sha256"}
    ):
        raise InstallError(
            "REGISTRATION_RUNTIME_INVALID",
            "lifecycle-манифест не связывает активный снимок Codex",
        )
    activation_dir = (
        layout.gateway_layout.managed_root / "activations" / str(activation_id)
    )
    activation = _read_private_json(
        activation_dir / "activation.json",
        code="REGISTRATION_RUNTIME_INVALID",
    )
    identity = activation.get("identity")
    activation_snapshot = (
        identity.get("codexSnapshot") if type(identity) is dict else None
    )
    fingerprint = activation.get("activationFingerprint")
    if (
        activation.get("schemaVersion") != 2
        or activation.get("activationId") != activation_id
        or type(fingerprint) is not str
        or activation_id != f"act2_{fingerprint}"
        or activation_snapshot != manifest_snapshot
    ):
        raise InstallError(
            "REGISTRATION_RUNTIME_INVALID",
            "activation.json не совпадает с активным снимком Codex",
        )
    snapshot_sha256 = manifest_snapshot.get("sha256")
    snapshot_value = manifest_snapshot.get("absolutePath")
    if _SHA256_PATTERN.fullmatch(
        str(snapshot_sha256)
    ) is None or not _absolute_string_path(snapshot_value):
        raise InstallError(
            "REGISTRATION_RUNTIME_INVALID",
            "адрес снимка Codex имеет неверную форму",
        )
    snapshot = Path(str(snapshot_value))
    expected_snapshot = (
        layout.gateway_layout.managed_root
        / "codex-snapshots"
        / str(snapshot_sha256)
        / "codex"
    )
    try:
        info = os.lstat(snapshot)
        resolved_snapshot = snapshot.resolve(strict=True)
        resolved_activation = activation_dir.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise InstallError(
            "REGISTRATION_RUNTIME_INVALID",
            f"не удалось подтвердить снимок Codex: {error}",
        ) from error
    if (
        snapshot != expected_snapshot
        or resolved_snapshot != snapshot
        or resolved_activation != activation_dir
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o500
        or not os.access(snapshot, os.X_OK)
        or file_digest(snapshot) != snapshot_sha256
    ):
        raise InstallError(
            "REGISTRATION_RUNTIME_INVALID",
            "неизменяемый снимок Codex не прошёл проверку целостности",
        )
    return InstallLayout(
        source_root=activation_dir,
        codex_home=layout.codex_home,
        bin_dir=layout.bin_dir,
        codex_binary=snapshot,
        state_home=layout.state_home,
    )


def _registration_problems(
    layout: InstallLayout,
    extra_environment: Mapping[str, str] | None,
) -> list[str]:
    problems: list[str] = []
    marketplaces = _target_marketplaces(layout, extra_environment)
    if len(marketplaces) != 1 or not _marketplace_entry_matches(
        marketplaces[0] if marketplaces else {}, layout
    ):
        problems.append("MARKETPLACE_REGISTRATION_MISMATCH")
    plugins = _target_plugins(layout, extra_environment)
    if len(plugins) != 1 or not _plugin_entry_matches(
        plugins[0] if plugins else {}, layout
    ):
        problems.append("PLUGIN_REGISTRATION_MISMATCH")
    return problems


def _require_exact_marketplace(
    layout: InstallLayout,
    extra_environment: Mapping[str, str] | None,
) -> None:
    entries = _target_marketplaces(layout, extra_environment)
    if len(entries) != 1 or not _marketplace_entry_matches(entries[0], layout):
        raise InstallError(
            "MARKETPLACE_REGISTRATION_MISMATCH",
            "Codex зарегистрировал не текущий неизменяемый каталог активации",
        )


def _require_exact_registration(
    layout: InstallLayout,
    extra_environment: Mapping[str, str] | None,
) -> None:
    problems = _registration_problems(layout, extra_environment)
    if problems:
        raise InstallError("PLUGIN_REGISTRATION_MISMATCH", "; ".join(problems))


def _target_marketplaces(
    layout: InstallLayout,
    extra_environment: Mapping[str, str] | None,
) -> list[Mapping[str, Any]]:
    runtime_layout = _registration_runtime_layout_v2(layout)
    document = _codex_json(
        runtime_layout,
        ["plugin", "marketplace", "list", "--json"],
        extra_environment,
        code="MARKETPLACE_LIST_FAILED",
    )
    entries = document.get("marketplaces", [])
    if type(entries) is not list:
        raise InstallError(
            "MARKETPLACE_LIST_INVALID",
            "Codex вернул неверный список рынков",
        )
    return [
        item
        for item in entries
        if isinstance(item, Mapping) and item.get("name") == MARKETPLACE_NAME
    ]


def _target_plugins(
    layout: InstallLayout,
    extra_environment: Mapping[str, str] | None,
) -> list[Mapping[str, Any]]:
    runtime_layout = _registration_runtime_layout_v2(layout)
    document = _codex_json(
        runtime_layout,
        ["plugin", "list", "--json"],
        extra_environment,
        code="PLUGIN_LIST_FAILED",
    )
    entries = document.get("installed", [])
    if type(entries) is not list:
        raise InstallError(
            "PLUGIN_LIST_INVALID", "Codex вернул неверный список расширений"
        )
    return [
        item
        for item in entries
        if isinstance(item, Mapping) and item.get("pluginId") == PLUGIN_ID
    ]


def _marketplace_entry_matches(entry: Mapping[str, Any], layout: InstallLayout) -> bool:
    try:
        expected = str(layout.gateway_layout.marketplace_link.resolve(strict=True))
    except OSError:
        return False
    source = entry.get("marketplaceSource")
    return bool(
        entry.get("name") == MARKETPLACE_NAME
        and entry.get("root") == expected
        and isinstance(source, Mapping)
        and source.get("sourceType") == "local"
        and source.get("source") == expected
    )


def _plugin_entry_matches(entry: Mapping[str, Any], layout: InstallLayout) -> bool:
    marketplace = entry.get("marketplaceSource")
    source = entry.get("source")
    try:
        expected_marketplace_path = layout.gateway_layout.marketplace_link.resolve(
            strict=True
        )
        contract = _load_activation_marketplace_contract_v2(
            expected_marketplace_path.parent
        )
        expected_plugin_path = (
            expected_marketplace_path / contract.plugin_source_path
        ).resolve(strict=True)
    except (InstallError, OSError):
        return False
    expected_marketplace = str(expected_marketplace_path)
    expected_plugin = str(expected_plugin_path)
    return bool(
        entry.get("pluginId") == PLUGIN_ID
        and entry.get("name") == PLUGIN_NAME
        and entry.get("marketplaceName") == MARKETPLACE_NAME
        and entry.get("version") == contract.plugin_version
        and entry.get("installed") is True
        and entry.get("enabled") is True
        and entry.get("installPolicy") == contract.install_policy
        and entry.get("authPolicy") == contract.auth_policy
        and isinstance(marketplace, Mapping)
        and marketplace.get("sourceType") == "local"
        and marketplace.get("source") == expected_marketplace
        and isinstance(source, Mapping)
        and source.get("source") == "local"
        and source.get("path") == expected_plugin
    )


def _add_marketplace(
    layout: InstallLayout,
    extra_environment: Mapping[str, str] | None,
) -> None:
    runtime_layout = _registration_runtime_layout_v2(layout)
    completed = _run_process(
        [
            str(runtime_layout.codex_binary),
            "plugin",
            "marketplace",
            "add",
            str(layout.gateway_layout.marketplace_link),
        ],
        layout=runtime_layout,
        extra_environment=extra_environment,
    )
    if completed.returncode != 0:
        raise InstallError("MARKETPLACE_ADD_FAILED", _bounded_error(completed))


def _add_plugin(
    layout: InstallLayout,
    extra_environment: Mapping[str, str] | None,
) -> None:
    runtime_layout = _registration_runtime_layout_v2(layout)
    completed = _run_process(
        [str(runtime_layout.codex_binary), "plugin", "add", PLUGIN_ID],
        layout=runtime_layout,
        extra_environment=extra_environment,
    )
    if completed.returncode != 0:
        raise InstallError("PLUGIN_ADD_FAILED", _bounded_error(completed))


def _remove_plugin(
    layout: InstallLayout,
    extra_environment: Mapping[str, str] | None,
) -> None:
    runtime_layout = _registration_runtime_layout_v2(layout)
    completed = _run_process(
        [str(runtime_layout.codex_binary), "plugin", "remove", PLUGIN_ID],
        layout=runtime_layout,
        extra_environment=extra_environment,
    )
    if completed.returncode != 0:
        raise InstallError("PLUGIN_REMOVE_FAILED", _bounded_error(completed))


def _remove_marketplace(
    layout: InstallLayout,
    extra_environment: Mapping[str, str] | None,
) -> None:
    runtime_layout = _registration_runtime_layout_v2(layout)
    completed = _run_process(
        [
            str(runtime_layout.codex_binary),
            "plugin",
            "marketplace",
            "remove",
            MARKETPLACE_NAME,
        ],
        layout=runtime_layout,
        extra_environment=extra_environment,
    )
    if completed.returncode != 0:
        raise InstallError("MARKETPLACE_REMOVE_FAILED", _bounded_error(completed))


def _rollback_failed_first_install(
    layout: InstallLayout,
    *,
    attempt: _InstallAttempt,
    extra_environment: Mapping[str, str] | None,
) -> list[str]:
    errors: list[str] = []
    if attempt.plugin_added:
        try:
            entries = _target_plugins(layout, extra_environment)
            if len(entries) == 1 and _plugin_entry_matches(entries[0], layout):
                _remove_plugin(layout, extra_environment)
            elif entries:
                errors.append("plugin registration changed before rollback")
        except Exception as exc:
            errors.append(f"plugin rollback: {exc}")
    if attempt.marketplace_added:
        try:
            entries = _target_marketplaces(layout, extra_environment)
            if len(entries) == 1 and _marketplace_entry_matches(entries[0], layout):
                _remove_marketplace(layout, extra_environment)
            elif entries:
                errors.append("marketplace registration changed before rollback")
        except Exception as exc:
            errors.append(f"marketplace rollback: {exc}")
    if attempt.process is not None:
        try:
            _stop_spawned_process(attempt.process)
        except Exception as exc:
            errors.append(f"controller stop: {exc}")
    try:
        if attempt.installation_id is None or attempt.activation_id is None:
            if layout.gateway_layout.manifest_path.is_file():
                identity = _load_lifecycle_identity(layout)
                attempt.installation_id = identity["installationId"]
                attempt.activation_id = identity["activationId"]
        if attempt.installation_id is not None and attempt.activation_id is not None:
            cleanup_accepted_activation_v2(
                codex_home=layout.codex_home,
                installation_id=attempt.installation_id,
                activation_id=attempt.activation_id,
            )
    except Exception as exc:
        errors.append(f"activation rollback: {exc}")
    if attempt.receipt is not None:
        try:
            if os.path.lexists(layout.installer_receipt_path):
                observed = _load_installer_receipt(layout.installer_receipt_path)
                if observed == attempt.receipt:
                    layout.installer_receipt_path.unlink()
                else:
                    errors.append("installer receipt changed before rollback")
        except Exception as exc:
            errors.append(f"installer receipt rollback: {exc}")
    for created, path, target in (
        (attempt.admin_created, layout.admin_path, layout.admin_target),
        (attempt.launcher_created, layout.launcher_path, layout.launcher_target),
    ):
        if not created:
            continue
        try:
            _remove_exact_link(path, target)
        except Exception as exc:
            errors.append(f"stable link rollback: {exc}")
    if attempt.bin_dir_created:
        try:
            layout.bin_dir.rmdir()
        except OSError:
            pass
    return errors


def _stop_spawned_process(process: Any) -> None:
    poll = getattr(process, "poll", None)
    supervisor = getattr(process, "_codex_process_supervisor_v2", None)
    lease = getattr(process, "_codex_process_lease_v2", None)
    if (
        isinstance(
            supervisor,
            operation_process_group_supervisor_v2.
            OperationProcessGroupSupervisorV2,
        )
        and isinstance(
            lease,
            operation_process_group_supervisor_v2.TransientProcessLeaseV2,
        )
    ):
        deadline = operation_deadline_v2.current_operation_deadline_v2()
        if deadline is None:
            deadline = operation_deadline_v2.OperationDeadlineV2.start(
                operation="initial-controller-cleanup",
                timeout_seconds=6,
                timeout_code="INITIAL_CONTROLLER_CLEANUP_TIMEOUT",
            )
        if callable(poll) and poll() is not None:
            result = supervisor.release_after_verified_exit(
                lease,
                deadline=deadline,
                reason_code="INITIAL_INSTALL_ROLLBACK",
            )
        else:
            result = supervisor.terminate_transient(
                lease,
                deadline=deadline,
                max_wait_seconds=5,
                reason_code="INITIAL_INSTALL_ROLLBACK",
            )
        if (
            isinstance(
                result,
                operation_process_group_supervisor_v2.
                ProcessGroupTerminationResultV2,
            )
            and not result.continuation_allowed
        ):
            raise InstallError(
                "CONTROLLER_CLEANUP_REQUIRED",
                "группа первичного контроллера не завершилась штатно",
            )
        delattr(process, "_codex_process_supervisor_v2")
        delattr(process, "_codex_process_lease_v2")
        return
    if callable(poll) and poll() is not None:
        return
    terminate = getattr(process, "terminate", None)
    wait = getattr(process, "wait", None)
    if not callable(terminate) or not callable(wait):
        raise InstallError(
            "CONTROLLER_HANDLE_INVALID",
            "запущенный процесс не предоставляет terminate/wait",
        )
    terminate()
    try:
        wait(timeout=5)
    except subprocess.TimeoutExpired as error:
        raise InstallError(
            "CONTROLLER_CLEANUP_REQUIRED",
            "первичный контроллер не завершился после terminate",
        ) from error


def _release_spawned_process(process: Any) -> None:
    """Передать доказанно готовый первичный контроллер службе."""

    supervisor = getattr(process, "_codex_process_supervisor_v2", None)
    lease = getattr(process, "_codex_process_lease_v2", None)
    if supervisor is None and lease is None:
        return
    if not isinstance(
        supervisor,
        operation_process_group_supervisor_v2.
        OperationProcessGroupSupervisorV2,
    ) or not isinstance(
        lease,
        operation_process_group_supervisor_v2.TransientProcessLeaseV2,
    ):
        raise InstallError(
            "CONTROLLER_HANDLE_INVALID",
            "надзор первичного контроллера повреждён",
        )
    accepted = supervisor.release_after_acceptance(lease)
    if accepted is not process:
        raise InstallError(
            "CONTROLLER_HANDLE_INVALID",
            "надзор вернул другой процесс первичного контроллера",
        )
    delattr(process, "_codex_process_supervisor_v2")
    delattr(process, "_codex_process_lease_v2")


def _remove_exact_link(path: Path, target: Path) -> None:
    try:
        info = os.lstat(path)
        observed = os.readlink(path)
    except FileNotFoundError:
        return
    if (
        not stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or observed != str(target)
    ):
        raise InstallError(
            "STABLE_LINK_CHANGED",
            f"ссылка изменилась до отката: {path}",
        )
    path.unlink()
    _fsync_directory(path.parent)


def _raise_unowned_lifecycle_state(layout: InstallLayout) -> None:
    path = layout.gateway_layout.manifest_path
    if path.is_file() and not path.is_symlink():
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            document = None
        if isinstance(document, Mapping) and document.get("schemaVersion") == 1:
            raise InstallError(
                "LEGACY_INSTALLATION_CONFLICT",
                "обнаружен старый изменяемый манифест schema 1",
            )
    raise InstallError(
        "INSTALLER_RECEIPT_MISSING",
        "состояние версии 2 существует без квитанции установщика",
    )


def _load_marketplace_source_contract(
    layout: InstallLayout,
) -> _MarketplaceSourceContract:
    try:
        agents_document = json.loads(
            layout.marketplace_source.read_text(encoding="utf-8")
        )
        codex_document = json.loads(
            layout.codex_marketplace_source.read_text(encoding="utf-8")
        )
        plugin_document = json.loads(
            (layout.plugin_source / ".codex-plugin" / "plugin.json").read_text(
                encoding="utf-8"
            )
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InstallError("MARKETPLACE_SOURCE_INVALID", str(exc)) from exc
    return _validate_marketplace_source_documents(
        agents_document,
        codex_document,
        plugin_document,
    )


def _load_activation_marketplace_contract_v2(
    activation_dir: Path,
) -> _MarketplaceSourceContract:
    """Прочитать договор только из уже подготовленной неизменяемой активации."""

    marketplace = activation_dir / "marketplace"
    plugin = marketplace / "plugins" / PLUGIN_NAME
    try:
        agents_document = json.loads(
            (marketplace / ".agents" / "plugins" / "marketplace.json").read_text(
                encoding="utf-8"
            )
        )
        codex_document = json.loads(
            (marketplace / ".claude-plugin" / "marketplace.json").read_text(
                encoding="utf-8"
            )
        )
        plugin_document = json.loads(
            (plugin / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InstallError(
            "PREPARED_MARKETPLACE_INVALID",
            str(error),
        ) from error
    return _validate_marketplace_source_documents(
        agents_document,
        codex_document,
        plugin_document,
    )


def _validate_marketplace_source_documents(
    agents_document: object,
    codex_document: object,
    plugin_document: object,
) -> _MarketplaceSourceContract:
    expected_source_path = f"./plugins/{PLUGIN_NAME}"
    if not all(
        type(document) is dict
        for document in (agents_document, codex_document, plugin_document)
    ):
        raise InstallError(
            "MARKETPLACE_IDENTITY_MISMATCH",
            "исходные манифесты должны быть объектами JSON",
        )

    agents_plugins = agents_document.get("plugins")
    codex_plugins = codex_document.get("plugins")
    if (
        type(agents_plugins) is not list
        or len(agents_plugins) != 1
        or type(agents_plugins[0]) is not dict
        or type(codex_plugins) is not list
        or len(codex_plugins) != 1
        or type(codex_plugins[0]) is not dict
    ):
        raise InstallError(
            "MARKETPLACE_IDENTITY_MISMATCH",
            "каждый исходный манифест должен описывать ровно одно расширение",
        )

    primary_plugin = agents_plugins[0]
    compatibility_plugin = codex_plugins[0]
    primary_source = primary_plugin.get("source")
    primary_policy = primary_plugin.get("policy")
    plugin_version = plugin_document.get("version")
    if (
        agents_document.get("name") != MARKETPLACE_NAME
        or codex_document.get("name") != MARKETPLACE_NAME
        or primary_plugin.get("name") != PLUGIN_NAME
        or primary_source != {"source": "local", "path": expected_source_path}
        or primary_policy
        != {"installation": "AVAILABLE", "authentication": "ON_INSTALL"}
        or plugin_document.get("name") != PLUGIN_NAME
        or type(plugin_version) is not str
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", plugin_version) is None
        or compatibility_plugin.get("name") != PLUGIN_NAME
        or compatibility_plugin.get("source") != expected_source_path
        or compatibility_plugin.get("version") != plugin_version
    ):
        raise InstallError(
            "MARKETPLACE_IDENTITY_MISMATCH",
            "идентичность исходных каталогов не совпадает с договором",
        )
    return _MarketplaceSourceContract(
        plugin_version=plugin_version,
        plugin_source_path=primary_source["path"],
        install_policy=primary_policy["installation"],
        auth_policy=primary_policy["authentication"],
    )


def _validate_source_layout(layout: InstallLayout) -> None:
    _ensure_owned_directory(layout.source_root, create=False, private=False)
    _ensure_codex_home_directory(layout.codex_home)
    required = (
        layout.marketplace_source,
        layout.codex_marketplace_source,
        layout.installer_receipt_schema_source,
        layout.catalog_source,
        layout.controller_entrypoint,
        layout.plugin_source / "config" / "adaptive-subagents.toml",
        layout.plugin_source / "bin" / "codex-smart",
        layout.plugin_source / "bin" / "codex-smart-subagents-admin",
        *layout.policy_source_paths,
        *layout.runtime_schema_paths,
        *layout.runtime_vector_paths,
    )
    for path in required:
        try:
            info = os.lstat(path)
        except OSError as exc:
            raise InstallError(
                "SOURCE_ARTIFACT_MISSING",
                f"отсутствует исходный артефакт: {path}",
            ) from exc
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise InstallError(
                "SOURCE_ARTIFACT_UNSAFE",
                f"исходный артефакт не является обычным файлом: {path}",
            )
    generated_paths = (
        layout.plugin_source / "config" / "contracts",
        layout.plugin_source / "config" / "bundled-catalog-v1.json",
    )
    materialized_capsule = _is_materialized_capsule_source_v2(layout)
    for path in generated_paths:
        if os.path.lexists(path):
            if materialized_capsule:
                continue
            raise InstallError(
                "SOURCE_GENERATED_PATH_CONFLICT",
                f"исходное дерево занимает зарезервированный путь: {path}",
            )
    bundled_catalog = layout.plugin_source / "config" / "adaptive-subagents.toml"
    if file_digest(layout.catalog_source) != file_digest(bundled_catalog):
        raise InstallError(
            "SOURCE_CATALOG_MISMATCH",
            "корневая и встроенная копии каталога моделей различаются",
        )
    try:
        binary_info = os.stat(layout.codex_binary)
    except OSError as exc:
        raise InstallError(
            "CODEX_BINARY_MISSING",
            f"не найден исполняемый Codex: {layout.codex_binary}",
        ) from exc
    if not stat.S_ISREG(binary_info.st_mode) or not os.access(
        layout.codex_binary, os.X_OK
    ):
        raise InstallError(
            "CODEX_BINARY_MISSING",
            f"Codex не является исполняемым файлом: {layout.codex_binary}",
        )
    _load_marketplace_source_contract(layout)
    try:
        _load_policy_bundle_v2(layout)
    except PolicyBundleError as exc:
        raise InstallError("POLICY_BUNDLE_INVALID", str(exc)) from exc


def _is_materialized_capsule_source_v2(layout: InstallLayout) -> bool:
    root = layout.source_root
    plugin_config = layout.plugin_source / "config"
    contracts = plugin_config / "contracts"
    bundled_catalog = plugin_config / "bundled-catalog-v1.json"
    installer = root / "scripts" / "install_adaptive_subagents.py"
    try:
        root_info = os.lstat(root)
        installer_info = os.lstat(installer)
        bundled_info = os.lstat(bundled_catalog)
        if (
            not stat.S_ISDIR(root_info.st_mode)
            or stat.S_ISLNK(root_info.st_mode)
            or root_info.st_uid != os.getuid()
            or stat.S_IMODE(root_info.st_mode) != 0o700
            or not stat.S_ISREG(installer_info.st_mode)
            or stat.S_ISLNK(installer_info.st_mode)
            or installer_info.st_uid != os.getuid()
            or installer_info.st_nlink != 1
            or stat.S_IMODE(installer_info.st_mode) != 0o500
            or not stat.S_ISREG(bundled_info.st_mode)
            or stat.S_ISLNK(bundled_info.st_mode)
            or bundled_info.st_uid != os.getuid()
            or bundled_info.st_nlink != 1
            or stat.S_IMODE(bundled_info.st_mode) != 0o600
            or not isinstance(
                json.loads(bundled_catalog.read_text(encoding="utf-8")),
                dict,
            )
            or not contracts.is_dir()
            or contracts.is_symlink()
            or {path.name for path in contracts.iterdir()}
            != set(_CONFIG_CONTRACT_VECTOR_FILES)
        ):
            return False
        for name in _CONFIG_CONTRACT_VECTOR_FILES:
            cached = contracts / name
            canonical = root / "docs" / "contracts" / "vectors" / name
            for path in (cached, canonical):
                info = os.lstat(path)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or stat.S_ISLNK(info.st_mode)
                    or info.st_uid != os.getuid()
                    or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600
                ):
                    return False
            if file_digest(cached) != file_digest(canonical):
                return False
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    return True


def _load_policy_bundle_v2(layout: InstallLayout):
    return load_policy_bundle_v2(
        catalog_path=layout.catalog_source,
        routing_vector_path=layout.policy_source_paths[0],
        delegation_vector_path=layout.policy_source_paths[1],
        role_vector_path=layout.policy_source_paths[2],
        child_profile_vector_path=layout.policy_source_paths[3],
    )


def _source_digest(layout: InstallLayout) -> str:
    files: dict[str, Path] = {}
    for path in _iter_source_tree(layout.plugin_source):
        plugin_relative = path.relative_to(layout.plugin_source)
        if plugin_relative == Path(
            "config/bundled-catalog-v1.json"
        ) or plugin_relative.is_relative_to(
            Path("config/contracts")
        ) or plugin_relative.is_relative_to(Path("config/runtime-schemas")):
            continue
        files[path.relative_to(layout.source_root).as_posix()] = path
    for path in (
        layout.marketplace_source,
        layout.codex_marketplace_source,
        layout.source_root / "scripts" / "install_adaptive_subagents.py",
        layout.installer_receipt_schema_source,
        layout.catalog_source,
        *layout.policy_source_paths,
        *layout.runtime_schema_paths,
        *layout.runtime_vector_paths,
    ):
        files[path.relative_to(layout.source_root).as_posix()] = path
    interpreter = _bound_python_runtime_v2()
    portable_shebang = b"#!/usr/bin/env python3\n"
    bound_shebang = f"#!{interpreter} -B\n".encode("utf-8")
    digest = hashlib.sha256()
    for relative, path in sorted(
        files.items(), key=lambda item: item[0].encode("utf-8")
    ):
        operation_deadline_v2.checkpoint_current_operation_deadline_if_scoped_v2()
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise InstallError("SOURCE_TREE_UNSAFE", f"особый объект: {path}")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0x\0" if info.st_mode & stat.S_IXUSR else b"\0f\0")
        payload_sha256 = file_digest(path)
        if (
            info.st_mode & stat.S_IXUSR
            and path.parent == layout.plugin_source / "bin"
        ):
            payload = path.read_bytes()
            if payload.startswith(bound_shebang):
                payload = portable_shebang + payload[len(bound_shebang) :]
            elif not payload.startswith(portable_shebang):
                raise InstallError(
                    "PYTHON_ENTRYPOINT_INVALID",
                    f"неизвестная исполняемая точка входа: {path.name}",
                )
            payload_sha256 = hashlib.sha256(payload).hexdigest()
        digest.update(bytes.fromhex(payload_sha256))
    digest.update(b"\0codex-binary-v1\0")
    digest.update(str(layout.codex_binary).encode("utf-8"))
    digest.update(b"\0")
    digest.update(bytes.fromhex(file_digest(layout.codex_binary)))
    digest.update(b"\0python-runtime-v1\0")
    digest.update(str(interpreter).encode("utf-8"))
    digest.update(b"\0")
    digest.update(bytes.fromhex(file_digest(interpreter)))
    return digest.hexdigest()


def _bound_python_runtime_v2() -> Path:
    try:
        interpreter = Path(sys.executable).resolve(strict=True)
        info = interpreter.stat()
    except OSError as exc:
        raise InstallError(
            "PYTHON_RUNTIME_INVALID",
            "не удалось подтвердить исполняемый Python",
        ) from exc
    if (
        sys.version_info < (3, 11)
        or not stat.S_ISREG(info.st_mode)
        or not os.access(interpreter, os.X_OK)
        or any(
            character in str(interpreter)
            for character in (" ", "\t", "\n", "\r")
        )
        or len(f"#!{interpreter} -B\n".encode("utf-8")) > 120
    ):
        raise InstallError(
            "PYTHON_RUNTIME_INVALID",
            "для активации требуется обычный исполняемый Python не ниже 3.11",
        )
    return interpreter


def _iter_source_tree(root: Path) -> Iterator[Path]:
    operation_deadline_v2.checkpoint_current_operation_deadline_if_scoped_v2()
    if not root.is_dir() or root.is_symlink():
        raise InstallError("SOURCE_TREE_UNSAFE", f"небезопасное дерево: {root}")
    for child in sorted(root.iterdir(), key=lambda item: item.name.encode("utf-8")):
        operation_deadline_v2.checkpoint_current_operation_deadline_if_scoped_v2()
        if child.name in _EXCLUDED_TREE_NAMES or child.suffix == ".pyc":
            continue
        info = child.lstat()
        if stat.S_ISDIR(info.st_mode):
            yield from _iter_source_tree(child)
        elif stat.S_ISREG(info.st_mode):
            yield child
        else:
            raise InstallError("SOURCE_TREE_UNSAFE", f"особый объект: {child}")


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            operation_deadline_v2.checkpoint_current_operation_deadline_if_scoped_v2()
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in _iter_source_tree(root):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(file_digest(path)))
    return digest.hexdigest()


def _probe_version(
    layout: InstallLayout,
    extra_environment: Mapping[str, str] | None,
) -> str:
    completed = _run_process(
        [str(layout.codex_binary), "--version"],
        layout=layout,
        extra_environment=extra_environment,
    )
    if completed.returncode != 0:
        raise InstallError("CODEX_VERSION_PROBE_FAILED", _bounded_error(completed))
    match = _VERSION_PATTERN.fullmatch(completed.stdout)
    if match is None:
        raise InstallError(
            "CODEX_VERSION_OUTPUT_INVALID",
            f"неожиданный ответ: {completed.stdout[:200]!r}",
        )
    version = match.group(1)
    try:
        parse_stable_codex_version(version)
    except ValueError as exc:
        raise InstallError(
            "CODEX_VERSION_OUTPUT_INVALID",
            f"версия Codex не является стабильной: {version!r}",
        ) from exc
    return version


def _codex_json(
    layout: InstallLayout,
    arguments: Sequence[str],
    extra_environment: Mapping[str, str] | None,
    *,
    code: str,
) -> dict[str, Any]:
    completed = _run_process(
        [str(layout.codex_binary), *arguments],
        layout=layout,
        extra_environment=extra_environment,
    )
    if completed.returncode != 0:
        raise InstallError(code, _bounded_error(completed))
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise InstallError(code, "Codex вернул не JSON") from exc
    if type(value) is not dict:
        raise InstallError(code, "Codex вернул не объект JSON")
    return value


def _run_process(
    arguments: Sequence[str],
    *,
    layout: InstallLayout,
    extra_environment: Mapping[str, str] | None,
) -> subprocess.CompletedProcess[str]:
    try:
        return _run_supervised_completed_process_v2(
            arguments,
            label="installer-command",
            cwd=layout.source_root,
            env=_command_environment(layout, extra_environment),
            timeout_seconds=30,
        )
    except (
        OSError,
        supervised_subprocess_v2.SupervisedCommandV2Error,
    ) as exc:
        raise InstallError("PROCESS_EXECUTION_FAILED", str(exc)) from exc


def _run_supervised_completed_process_v2(
    arguments: Sequence[str],
    *,
    label: str,
    cwd: Path,
    env: Mapping[str, str],
    timeout_seconds: float,
) -> subprocess.CompletedProcess[str]:
    """Выполнить короткую команду под текущим либо локальным надзором."""

    deadline = operation_deadline_v2.current_operation_deadline_v2()
    if deadline is None:
        deadline = operation_deadline_v2.OperationDeadlineV2.start(
            operation=label,
            timeout_seconds=timeout_seconds + 1.0,
            timeout_code=(
                label.upper().replace("-", "_") + "_DEADLINE_TIMEOUT"
            ),
        )
    supervisor = (
        operation_process_group_supervisor_v2.
        current_process_group_supervisor_v2()
    )
    if supervisor is None:
        supervisor = (
            operation_process_group_supervisor_v2.
            OperationProcessGroupSupervisorV2()
        )
    result = supervised_subprocess_v2.run_supervised_command_v2(
        argv=arguments,
        label=label,
        local_timeout_seconds=timeout_seconds,
        cleanup_wait_seconds=0.5,
        stdin=b"",
        max_output_bytes=4 * 1024 * 1024,
        cwd=cwd,
        env=env,
        deadline=deadline,
        supervisor=supervisor,
    )
    return subprocess.CompletedProcess(
        args=list(result.argv),
        returncode=result.returncode,
        stdout=result.stdout.decode("utf-8", errors="replace"),
        stderr=result.stderr.decode("utf-8", errors="replace"),
    )


def _command_environment(
    layout: InstallLayout,
    extra_environment: Mapping[str, str] | None,
) -> dict[str, str]:
    source = dict(os.environ)
    if extra_environment is not None:
        if not all(
            type(name) is str and type(value) is str
            for name, value in extra_environment.items()
        ):
            raise InstallError("ENVIRONMENT_INVALID", "окружение содержит не строки")
        source.update(extra_environment)
    result = {
        "CODEX_HOME": str(layout.codex_home),
        "PATH": os.defpath,
        "PYTHONNOUSERSITE": "1",
    }
    for name in _SAFE_INHERITED_ENVIRONMENT:
        value = source.get(name)
        if type(value) is str and value and "\0" not in value:
            result[name] = value
    for name, value in source.items():
        if name.startswith("FAKE_CODEX_") and "\0" not in value:
            result[name] = value
    return result


def _read_private_json(path: Path, *, code: str) -> dict[str, Any]:
    try:
        info = os.lstat(path)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise InstallError(code, f"небезопасный закрытый файл: {path}")
        value = json.loads(path.read_text(encoding="utf-8"))
    except InstallError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InstallError(code, f"не удалось прочитать {path}: {exc}") from exc
    if type(value) is not dict:
        raise InstallError(code, f"корень JSON не является объектом: {path}")
    return value


def load_manifest(path: Path) -> dict[str, Any]:
    """Совместимый читающий помощник; schema проверяет вызывающий слой."""

    return _read_private_json(path, code="MANIFEST_INVALID")


def _atomic_create_json(
    path: Path,
    value: Mapping[str, Any],
    *,
    conflict_code: str = "INSTALLER_RECEIPT_CONFLICT",
) -> None:
    _ensure_owned_directory(path.parent, create=True, private=True)
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    temporary = path.parent / f".{path.name}.{os.getpid()}.{time.time_ns()}"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise InstallError(
                conflict_code,
                f"квитанция появилась во время публикации: {path}",
            ) from exc
        temporary.unlink()
        path.chmod(0o600)
        _fsync_directory(path.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _ensure_owned_directory(path: Path, *, create: bool, private: bool) -> None:
    if create and not path.exists() and not path.is_symlink():
        path.mkdir(parents=True, mode=0o700)
        path.chmod(0o700)
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise InstallError("UNSAFE_DIRECTORY", f"каталог недоступен: {path}") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or (private and stat.S_IMODE(info.st_mode) != 0o700)
    ):
        raise InstallError("UNSAFE_DIRECTORY", f"небезопасный каталог: {path}")


def _ensure_codex_home_directory(path: Path) -> None:
    """Принять штатные режимы CODEX_HOME, не меняя пользовательский каталог."""

    _ensure_owned_directory(path, create=False, private=False)
    mode = stat.S_IMODE(os.lstat(path).st_mode)
    if mode not in {0o700, 0o755}:
        raise InstallError(
            "UNSAFE_DIRECTORY",
            f"CODEX_HOME имеет неподдерживаемый режим {mode:04o}: {path}",
        )


def _ensure_lock_file(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise InstallError(
                "INSTALLER_LOCK_INVALID", f"небезопасная блокировка: {path}"
            )
    finally:
        os.close(descriptor)


@contextmanager
def installation_lock(path: Path) -> Iterator[None]:
    descriptor = os.open(
        path,
        os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    acquired = False
    try:
        try:
            finite_file_lock_v2.acquire_flock_v2(
                descriptor,
                exclusive=True,
                timeout_seconds=(
                    finite_file_lock_v2.INSTALLATION_LOCK_TIMEOUT_SECONDS
                ),
                timeout_code="INSTALLATION_LOCK_TIMEOUT",
            )
        except finite_file_lock_v2.FileLockTimeoutV2 as error:
            raise InstallError(
                error.code,
                "установочная блокировка осталась занятой до истечения срока",
            ) from error
        acquired = True
        yield
    finally:
        if acquired:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _identifier(value: object, prefix: str, suffix_length: int) -> bool:
    return bool(
        type(value) is str
        and len(value) == len(prefix) + suffix_length
        and value.startswith(prefix)
        and all(character in "0123456789abcdef" for character in value[len(prefix) :])
    )


def _activation_identifier(value: object) -> bool:
    return _identifier(value, "act2_", 64)


def _as_install_error(error: BaseException) -> InstallError:
    if isinstance(error, InstallError):
        return error
    return InstallError(
        "INSTALL_FAILED",
        str(error)[:1024] or type(error).__name__,
    )


def _bounded_error(completed: subprocess.CompletedProcess[str]) -> str:
    return (
        completed.stderr.strip()[:1000]
        or completed.stdout.strip()[:1000]
        or f"код завершения {completed.returncode}"
    )


def _absolute_string_path(value: object) -> bool:
    return (
        type(value) is str
        and bool(value)
        and len(value) <= 4096
        and "\0" not in value
        and Path(value).is_absolute()
    )


def _require_socket_path_capacity(state_home: Path) -> None:
    if not isinstance(state_home, Path) or not state_home.is_absolute():
        raise InstallError(
            "STATE_HOME_INVALID",
            "каталог состояния должен быть абсолютным путём",
        )
    oversized = [
        state_home / name
        for name in (
            "controller.sock",
            "command.sock",
            _CANDIDATE_READY_SOCKET_PLACEHOLDER,
        )
        if len(os.fsencode(state_home / name)) >= _SOCKET_PATH_LIMIT
    ]
    if oversized:
        raise InstallError(
            "STATE_HOME_SOCKET_PATH_TOO_LONG",
            "путь локального сокета должен занимать меньше 100 байт: "
            + str(oversized[0]),
        )


def _candidate_ready_socket_path_v2(state_home: Path, operation_id: str) -> Path:
    if not isinstance(state_home, Path) or not state_home.is_absolute():
        raise InstallError(
            "STATE_HOME_INVALID",
            "каталог состояния должен быть абсолютным путём",
        )
    if not _identifier(operation_id, "op2_", 32):
        raise InstallError(
            "OPERATION_ID_INVALID",
            "operationId канала готовности имеет неверную форму",
        )
    path = state_home / f".r-{operation_id[-12:]}.sock"
    if len(os.fsencode(path)) >= _SOCKET_PATH_LIMIT:
        raise InstallError(
            "STATE_HOME_SOCKET_PATH_TOO_LONG",
            "путь локального сокета должен занимать меньше 100 байт: " + str(path),
        )
    return path


def _new_public_attempt_id() -> str:
    return "opa2_" + secrets.token_hex(16)


def _new_smoke_invocation_id() -> str:
    return "sm2_" + secrets.token_hex(16)


def _public_problem(
    code: str,
    message: str,
    *,
    component: str = "installer",
    severity: str = "error",
    remediation: str = "выполните --inspect и устраните указанную причину",
) -> dict[str, str]:
    normalized_code = (
        code if re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", code) else "INSTALL_FAILED"
    )
    return {
        "code": normalized_code,
        "severity": severity,
        "component": component[:256] or "installer",
        "message": (message[:2048] or normalized_code),
        "remediation": remediation[:4096] or "повторите проверку установки",
    }


def _public_readiness(diagnosis: Mapping[str, Any]) -> str:
    status = diagnosis.get("status")
    if diagnosis.get("ok") is True and status == "FULL_READY":
        return "READY"
    if diagnosis.get("gatewayReason") in {
        "HOOK_TRUST_REQUIRED",
        "AWAITING_HOOK_TRUST",
    }:
        return "AWAITING_HOOK_TRUST"
    if status == "HEALTH_ONLY":
        return "DEGRADED"
    if status == "ORDINARY" and not diagnosis.get("problems"):
        return "DISABLED"
    return "BROKEN"


def _diagnosis_problems(diagnosis: Mapping[str, Any]) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    raw = diagnosis.get("problems", ())
    if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes, bytearray)):
        for value in raw:
            code = str(value)
            result.append(
                _public_problem(
                    code,
                    f"диагностика установки: {code}",
                    component="doctor",
                )
            )
    readiness = _public_readiness(diagnosis)
    if readiness not in {"READY", "DISABLED"} and not result:
        reason = str(diagnosis.get("gatewayReason") or "INSTALLATION_NOT_READY")
        result.append(
            _public_problem(
                reason,
                f"шлюз не готов: {reason}",
                component="gateway",
            )
        )
    return result


def _activation_fingerprint(value: object) -> str | None:
    if _activation_identifier(value):
        return str(value)[len("act2_") :]
    return None


def _wrap_apply_result_v2(
    layout: InstallLayout,
    result: Mapping[str, Any],
    *,
    execute: bool,
) -> dict[str, Any]:
    if result.get("schemaVersion") == 2 and result.get("command") == "apply":
        return dict(result)
    status = str(result.get("status", "failed"))
    if status not in {
        "planned",
        "installed",
        "upgraded",
        "reconciled",
        "repaired",
        "unchanged",
        "failed",
    }:
        status = "failed"
    diagnosis: Mapping[str, Any]
    if execute and status != "failed":
        diagnosis = doctor(layout)
    else:
        diagnosis = {"ok": False, "status": "ORDINARY", "problems": []}
    readiness = _public_readiness(diagnosis)
    operation_id: str | None = None
    attempt_id: str | None = None
    changes: list[dict[str, Any]] = []
    if status in {"installed", "upgraded", "reconciled", "repaired"}:
        operation_id = result.get("operationId")
        if not _identifier(operation_id, "op2_", 32):
            operation_id = _load_lifecycle_identity(layout)["operationId"]
        candidate_attempt = result.get("attemptId")
        attempt_id = (
            str(candidate_attempt)
            if _identifier(candidate_attempt, "opa2_", 32)
            else _new_public_attempt_id()
        )
        after = _activation_fingerprint(result.get("activationId"))
        before = _activation_fingerprint(result.get("previousActivationId"))
        if after is not None and before != after:
            changes.append(
                {
                    "kind": "published_activation",
                    "beforeFingerprint": before,
                    "afterFingerprint": after,
                }
            )
    problems = _diagnosis_problems(diagnosis)
    return build_lifecycle_command_result_v2(
        command="apply",
        status=status,
        readiness=readiness,
        operation_id=operation_id,
        attempt_id=attempt_id,
        changes=changes,
        problems=problems,
        extensions={"installer": dict(result), "doctor": dict(diagnosis)},
    )


def _wrap_doctor_result_v2(diagnosis: Mapping[str, Any]) -> dict[str, Any]:
    readiness = _public_readiness(diagnosis)
    status = readiness if readiness != "DISABLED" else "BROKEN"
    problems = _diagnosis_problems(diagnosis)
    if readiness == "DISABLED" and not problems:
        problems = [
            _public_problem(
                "INSTALLATION_DISABLED",
                "активная установка отсутствует",
                component="doctor",
                remediation="выполните установку с --apply",
            )
        ]
    return build_lifecycle_command_result_v2(
        command="doctor",
        status=status,
        readiness=status,
        problems=problems,
        extensions={"diagnosis": dict(diagnosis)},
    )


def _wrap_smoke_result_v2(result: Mapping[str, Any]) -> dict[str, Any]:
    ready = result.get("ok") is True and result.get("status") == "FULL_READY"
    return build_lifecycle_command_result_v2(
        command="smoke",
        status="READY" if ready else "NOT_READY",
        readiness="READY" if ready else "BROKEN",
        smoke_invocation_id=_new_smoke_invocation_id(),
        problems=(
            ()
            if ready
            else (
                _public_problem(
                    "SMOKE_NOT_READY",
                    "дымовая проверка не доказала готовность",
                    component="smoke",
                ),
            )
        ),
        extensions={"smoke": dict(result)},
    )


def _maintenance_layout_v2(layout: InstallLayout) -> InstallerMaintenanceLayoutV2:
    gateway = layout.gateway_layout
    name = INSTALLATION_NAME
    return InstallerMaintenanceLayoutV2(
        codex_home=layout.codex_home,
        managed_root=gateway.managed_root,
        activations_root=gateway.managed_root / "activations",
        manifest_path=gateway.manifest_path,
        installer_receipt_path=layout.installer_receipt_path,
        marketplace_link=gateway.marketplace_link,
        receipts_root=gateway.receipts_root,
        cleanup_journal_path=(
            gateway.manifest_root / f"{name}.cleanup.transaction.json"
        ),
        uninstall_journal_path=(
            gateway.manifest_root / f"{name}.uninstall.transaction.json"
        ),
        tombstone_path=gateway.manifest_root / f"{name}.tombstone.json",
        lock_path=layout.lock_path,
        state_home=layout.state_home,
        databases_root=layout.state_home / "databases",
        backups_root=layout.state_home / "backups",
        quarantine_root=layout.state_home / "quarantine",
        recovery_entrypoint=(
            layout.source_root / "scripts" / "install_adaptive_subagents.py"
        ),
    )


def _registration_callbacks_v2(
    layout: InstallLayout,
    extra_environment: Mapping[str, str] | None,
) -> RegistrationCallbacksV2:
    def observe(kind: str, name: str) -> RegistrationObservationV2 | None:
        if kind == "marketplace" and name == MARKETPLACE_NAME:
            entries = _target_marketplaces(layout, extra_environment)
            if not entries:
                return None
            if len(entries) != 1 or not _marketplace_entry_matches(
                entries[0], layout
            ):
                raise InstallError(
                    "REGISTRATION_OWNERSHIP_AMBIGUOUS",
                    "регистрация marketplace существует, но указывает не на эту установку",
                )
            target = entries[0].get("root")
        elif kind == "plugin" and name == PLUGIN_ID:
            entries = _target_plugins(layout, extra_environment)
            if not entries:
                return None
            if len(entries) != 1 or not _plugin_entry_matches(entries[0], layout):
                raise InstallError(
                    "REGISTRATION_OWNERSHIP_AMBIGUOUS",
                    "регистрация plugin существует, но указывает не на эту установку",
                )
            source = entries[0].get("source")
            target = source.get("path") if isinstance(source, Mapping) else None
        else:
            return None
        if not _absolute_string_path(target):
            return None
        return RegistrationObservationV2(
            kind=kind,
            name=name,
            target=Path(str(target)),
        )

    def remove(expected: RegistrationObservationV2) -> None:
        if observe(expected.kind, expected.name) != expected:
            raise InstallError(
                "REGISTRATION_OWNERSHIP_AMBIGUOUS",
                "регистрация изменилась перед удалением",
            )
        if expected.kind == "plugin":
            _remove_plugin(layout, extra_environment)
        elif expected.kind == "marketplace":
            _remove_marketplace(layout, extra_environment)
        else:  # pragma: no cover - тип закрыт RegistrationObservationV2
            raise InstallError("REGISTRATION_KIND_INVALID", expected.kind)
        if observe(expected.kind, expected.name) is not None:
            raise InstallError(
                "REGISTRATION_REMOVE_FAILED",
                "регистрация осталась после штатной команды удаления",
            )

    return RegistrationCallbacksV2(observe=observe, remove=remove)


def _maintenance_now_v2() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _maintenance_public_result_v2(
    layout: InstallLayout,
    result: MaintenanceResultV2,
    *,
    extra_environment: Mapping[str, str] | None,
) -> dict[str, Any]:
    diagnosis = doctor(layout, extra_environment=extra_environment)
    readiness = (
        "DISABLED"
        if result.command == "uninstall"
        and result.status in {"uninstalled", "unchanged"}
        else _public_readiness(diagnosis)
    )
    successful = result.status in {"cleaned", "uninstalled"}
    operation_id: str | None = None
    attempt_id: str | None = None
    changes: list[dict[str, Any]] = []
    if successful:
        internal_id = str(result.operation_id or "")
        if _identifier(internal_id, "op2_", 32):
            operation_id = internal_id
        else:
            operation_id = (
                "op2_"
                + hashlib.sha256(
                    f"{result.command}\0{internal_id}".encode("utf-8")
                ).hexdigest()[:32]
            )
        attempt_id = _new_public_attempt_id()
        if result.command == "cleanup" and result.activation_ids:
            before = hashlib.sha256(
                "\0".join(result.activation_ids).encode("utf-8")
            ).hexdigest()
            changes.append(
                {
                    "kind": "retired_generation",
                    "beforeFingerprint": before,
                    "afterFingerprint": None,
                }
            )
        elif result.command == "uninstall":
            changes.append(
                {
                    "kind": "removed_installation",
                    "beforeFingerprint": hashlib.sha256(
                        result.installation_id.encode("utf-8")
                    ).hexdigest(),
                    "afterFingerprint": None,
                }
            )
    return build_lifecycle_command_result_v2(
        command=result.command,
        status=result.status,
        readiness=readiness,
        operation_id=operation_id,
        attempt_id=attempt_id,
        changes=changes,
        problems=_diagnosis_problems(diagnosis),
        extensions={
            "maintenance": {
                "installationId": result.installation_id,
                "internalOperationId": result.operation_id,
                "activationIds": list(result.activation_ids),
                "removedPaths": [str(path) for path in result.removed_paths],
                "retainedPaths": [str(path) for path in result.retained_paths],
                "receiptPath": (
                    None if result.receipt_path is None else str(result.receipt_path)
                ),
                "tombstonePath": (
                    None
                    if result.tombstone_path is None
                    else str(result.tombstone_path)
                ),
            },
            "doctor": dict(diagnosis),
        },
    )


def _durable_process_ownership_projection_v2(
    codex_home: Path,
) -> list[dict[str, str]]:
    """Expose only non-secret operator fields from exact durable records."""

    records: tuple[DurableProcessOwnershipRecordV2, ...] = (
        DurableProcessOwnershipStoreV2(codex_home).load_all()
    )
    return [
        {
            "leaseId": record.lease_id,
            "state": record.state,
            "contextKind": str(record.context["contextKind"]),
        }
        for record in records
    ]


def inspect_installation_v2(
    layout: InstallLayout,
    *,
    extra_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Прочитать пользовательски значимое состояние без восстановления."""

    diagnosis = doctor(layout, extra_environment=extra_environment)
    inventory = inspect_maintenance_inventory_v2(
        _maintenance_layout_v2(layout),
        registrations=_registration_callbacks_v2(layout, extra_environment),
    )
    gateway = layout.gateway_layout
    manifest: Mapping[str, Any] | None = None
    receipt: Mapping[str, Any] | None = None
    try:
        manifest = _read_private_json(
            gateway.manifest_path, code="LIFECYCLE_MANIFEST_INVALID"
        )
    except InstallError:
        pass
    try:
        receipt = _load_installer_receipt(layout.installer_receipt_path)
    except InstallError:
        pass
    activations: list[str] = []
    activation_root = gateway.managed_root / "activations"
    if activation_root.is_dir() and not activation_root.is_symlink():
        activations = sorted(
            child.name
            for child in activation_root.iterdir()
            if child.is_dir()
            and not child.is_symlink()
            and _activation_identifier(child.name)
        )
    readiness = _public_readiness(diagnosis)
    return build_lifecycle_command_result_v2(
        command="inspect",
        status="inspected",
        readiness=readiness,
        problems=_diagnosis_problems(diagnosis),
        extensions={
            "diagnosis": dict(diagnosis),
            "manifest": None if manifest is None else dict(manifest),
            "installerReceipt": None if receipt is None else dict(receipt),
            "journals": {
                "firstInstall": os.path.lexists(
                    layout.first_install_journal_path
                ),
                "operation": os.path.lexists(gateway.journal_path),
                "preparation": os.path.lexists(
                    gateway.manifest_root
                    / "codex-smart-subagents-v2.activation-preparation.transaction.json"
                ),
                "rollbackPreparation": os.path.lexists(
                    gateway.manifest_root
                    / "codex-smart-subagents-v2.rollback-manifest-preparation.transaction.json"
                ),
            },
            "activations": activations,
            "durableProcessOwnership": (
                _durable_process_ownership_projection_v2(layout.codex_home)
            ),
            "maintenanceInventory": {
                "installationId": inventory.installation_id,
                "activeActivationId": inventory.active_activation_id,
                "previousActivationId": inventory.previous_activation_id,
                "protectedActivationIds": list(inventory.protected_activation_ids),
                "cleanupCandidateIds": list(inventory.cleanup_candidate_ids),
                "retainedPaths": [str(path) for path in inventory.retained_paths],
                "registrations": [
                    item.to_document() for item in inventory.registrations
                ],
                "issues": [
                    {
                        "code": issue.code,
                        "path": str(issue.path),
                        "message": issue.message,
                    }
                    for issue in inventory.issues
                ],
            },
        },
    )


def cleanup_installation_v2(
    layout: InstallLayout,
    *,
    execute: bool,
    extra_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Показать или выполнить удаление только доказанных неактивных поколений."""

    result = cleanup_inactive_activations_v2(
        _maintenance_layout_v2(layout),
        execute=execute,
        now=_maintenance_now_v2,
    )
    return _maintenance_public_result_v2(
        layout,
        result,
        extra_environment=extra_environment,
    )


def uninstall_installation_v2(
    layout: InstallLayout,
    *,
    execute: bool,
    retain_data: bool,
    extra_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Показать или выполнить удаление с обязательным сохранением данных."""

    maintenance = _maintenance_layout_v2(layout)
    registrations = _registration_callbacks_v2(layout, extra_environment)
    if not retain_data or os.path.lexists(maintenance.uninstall_journal_path):
        # Единственный допустимый пакетный путь — восстановление уже созданного
        # журнала старой версии. Новая операция его больше не создаёт.
        result = uninstall_retain_data_v2(
            maintenance,
            registrations=registrations,
            execute=execute,
            retain_data=retain_data,
            now=_maintenance_now_v2,
        )
    elif os.path.lexists(layout.gateway_layout.journal_path):
        if execute:
            result = _execute_existing_uninstall_composition_v2(
                layout,
                extra_environment=extra_environment,
            )
        else:
            definition = _read_main_uninstall_definition_v2(layout)
            result = uninstall_maintenance_result_v2(
                definition,
                maintenance,
                status="planned",
            )
    elif os.path.lexists(maintenance.tombstone_path):
        result = _verify_completed_uninstall(
            maintenance,
            registrations=registrations,
        )
    elif not execute:
        result = _plan_fresh_uninstall_composition_v2(
            layout,
            extra_environment=extra_environment,
        )
    else:
        result = _execute_fresh_uninstall_composition_v2(
            layout,
            extra_environment=extra_environment,
        )
    return _maintenance_public_result_v2(
        layout,
        result,
        extra_environment=extra_environment,
    )


def _read_main_uninstall_definition_v2(
    layout: InstallLayout,
    *,
    store: Any | None = None,
):
    from codex_smart_subagents.operation_definition_rehydration_v2 import (
        operation_definition_from_journal_v2,
    )

    journal_store = store or _LazyOperationJournalStoreV2(layout=layout)
    document = journal_store.read()
    if (
        document.get("kind") != "uninstall"
        or document.get("operation") != "uninstall"
    ):
        raise InstallError(
            "UNINSTALL_RECOVERY_REQUIRED",
            "основной журнал принадлежит другой операции; сначала выполните recover --apply",
        )
    try:
        return operation_definition_from_journal_v2(document)
    except Exception as error:
        raise InstallError(
            "UNINSTALL_RECOVERY_JOURNAL_INVALID",
            f"основной журнал удаления не прошёл восстановление определения: {error}",
        ) from error


def _build_fresh_uninstall_composition_v2(
    layout: InstallLayout,
    *,
    extra_environment: Mapping[str, str] | None,
    store: Any,
):
    """Снять доказательства и собрать одну и ту же preview/apply-композицию."""

    maintenance = _maintenance_layout_v2(layout)
    if os.path.lexists(maintenance.cleanup_journal_path):
        raise InstallError(
            "OPERATION_IN_PROGRESS",
            "незавершённый cleanup блокирует uninstall",
        )
    if any(
        os.path.lexists(path)
        for path in (
            maintenance.uninstall_journal_path,
            maintenance.tombstone_path,
            layout.gateway_layout.journal_path,
        )
    ):
        raise InstallError(
            "UNINSTALL_FRESH_STATE_CHANGED",
            "состояние удаления изменилось до создания основного журнала",
        )
    registrations = _registration_callbacks_v2(layout, extra_environment)
    inventory = inspect_maintenance_inventory_v2(
        maintenance,
        registrations=registrations,
    )
    proof = capture_activation_transition_proof_v2(
        codex_home=layout.codex_home,
        wrapper=layout.launcher_path,
        installer_receipt_path=layout.installer_receipt_path,
    )
    return build_active_uninstall_composition_v2(
        registry=_lifecycle_plan_registry_v2(layout),
        proof=proof,
        maintenance_layout=maintenance,
        inventory=inventory,
        registrations=registrations,
        store=store,
    )


def _plan_fresh_uninstall_composition_v2(
    layout: InstallLayout,
    *,
    extra_environment: Mapping[str, str] | None,
) -> MaintenanceResultV2:
    """Построить точный 17-шаговый intent без создания lock и journal."""

    with installation_lock(layout.lock_path):
        composition = _build_fresh_uninstall_composition_v2(
            layout,
            extra_environment=extra_environment,
            store=_AlreadyHeldOperationJournalStoreV2(
                _LazyOperationJournalStoreV2(layout=layout)
            ),
        )
        return uninstall_maintenance_result_v2(
            composition.definition,
            composition.maintenance_layout,
            status="planned",
        )


def _execute_fresh_uninstall_composition_v2(
    layout: InstallLayout,
    *,
    extra_environment: Mapping[str, str] | None,
) -> MaintenanceResultV2:
    """Снять снимок и исполнить его под одной installer-блокировкой."""

    with installation_lock(layout.lock_path):
        store = _AlreadyHeldOperationJournalStoreV2(
            _LazyOperationJournalStoreV2(layout=layout)
        )
        composition = _build_fresh_uninstall_composition_v2(
            layout,
            extra_environment=extra_environment,
            store=store,
        )
        _run, result = composition.execute()
        return result


def _execute_existing_uninstall_composition_v2(
    layout: InstallLayout,
    *,
    extra_environment: Mapping[str, str] | None,
) -> MaintenanceResultV2:
    """Продолжить только точное определение uninstall из основного журнала."""

    with installation_lock(layout.lock_path):
        store = _AlreadyHeldOperationJournalStoreV2(
            _LazyOperationJournalStoreV2(layout=layout)
        )
        definition = _read_main_uninstall_definition_v2(
            layout,
            store=store,
        )
        composition = recover_active_uninstall_composition_v2(
            registry=_lifecycle_plan_registry_v2(layout),
            definition=definition,
            maintenance_layout=_maintenance_layout_v2(layout),
            registrations=_registration_callbacks_v2(
                layout,
                extra_environment,
            ),
            store=store,
        )
        _run, result = composition.execute()
        return result


def _lifecycle_plan_registry_v2(
    layout: InstallLayout,
    *,
    activation_dir: Path | None = None,
) -> LifecyclePlanRegistryV2:
    if activation_dir is None:
        path = (
            layout.source_root / "docs" / "contracts" / "vectors" / "lifecycle-v2.json"
        )
    else:
        if not activation_dir.is_absolute():
            raise TypeError("activation_dir must be an absolute Path")
        path = (
            activation_dir
            / "marketplace"
            / "docs"
            / "contracts"
            / "vectors"
            / "lifecycle-v2.json"
        )
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise InstallError(
            "LIFECYCLE_PLAN_REGISTRY_INVALID",
            f"нормативный реестр планов недоступен: {error}",
        ) from error
    try:
        fixture = document.get("fixtures", {}).get("automaton")
        return LifecyclePlanRegistryV2.from_document(fixture)
    except Exception as error:
        raise InstallError(
            "LIFECYCLE_PLAN_REGISTRY_INVALID",
            f"нормативный реестр планов повреждён: {error}",
        ) from error


def _operation_executor_v2(layout: InstallLayout) -> OperationExecutorV2:
    """Собрать исполнитель без преждевременного создания lock-файла."""

    return OperationExecutorV2(
        store=_LazyOperationJournalStoreV2(layout=layout),
        now=lambda: datetime.now(timezone.utc),
    )


@contextmanager
def _already_held_installation_lock_v2() -> Iterator[None]:
    """Не брать вложенный ``flock``, когда общий lock уже удерживается."""

    yield


def _rollback_runtime_environment_v2(
    extra_environment: Mapping[str, str] | None,
) -> dict[str, str]:
    environment = dict(os.environ)
    if extra_environment is not None:
        if not all(
            type(name) is str and type(value) is str
            for name, value in extra_environment.items()
        ):
            raise InstallError(
                "ENVIRONMENT_INVALID",
                "окружение отката содержит не строки",
            )
        environment.update(extra_environment)
    return environment


def _rollback_operation_executor_v2(
    layout: InstallLayout,
    evidence: Any,
) -> OperationExecutorV2:
    activation_dir = evidence.activations_root / evidence.current_activation_id
    schema_directory = activation_dir / "marketplace" / "docs" / "contracts" / "schemas"
    store = OperationJournalStoreV2(
        journal_path=layout.gateway_layout.journal_path,
        lock_path=layout.gateway_layout.lock_path,
        validate_document=build_operation_journal_validator_v2(schema_directory),
    )
    return OperationExecutorV2(
        store=store,
        now=lambda: datetime.now(timezone.utc),
    )


def _build_fresh_rollback_composition_v2(
    layout: InstallLayout,
    *,
    evidence: Any,
    execution_plan: Any,
    current_installer_receipt: Mapping[str, Any],
    extra_environment: Mapping[str, str] | None,
):
    from codex_smart_subagents.installer_rollback_composition_v2 import (
        build_rollback_composition_from_preparation_receipt_v2,
        read_rollback_external_artifacts_v2,
    )
    from codex_smart_subagents.rollback_manifest_preparation_v2 import (
        RollbackManifestPreparationExecutorV2,
        build_rollback_manifest_preparation_v2,
        rollback_manifest_preparation_paths_v2,
    )
    from codex_smart_subagents.lifecycle_operation_v2 import (
        ActivationTransitionLineageV2,
    )
    from codex_smart_subagents.rollback_runtime_bindings_v2 import (
        build_rollback_runtime_external_bindings_v2,
    )

    previous_installer_receipt_path = (
        evidence.receipts_root / f"{evidence.previous_activation_id}.installer.json"
    )
    previous_installer_receipt = _load_installer_receipt(
        previous_installer_receipt_path
    )
    if (
        previous_installer_receipt.get("installationId") != evidence.installation_id
        or previous_installer_receipt.get("activationId")
        != evidence.previous_activation_id
        or current_installer_receipt.get("installationId") != evidence.installation_id
        or current_installer_receipt.get("activationId")
        != evidence.current_activation_id
    ):
        raise InstallError(
            "ROLLBACK_INSTALLER_RECEIPT_MISMATCH",
            "архивная и текущая квитанции не совпадают с rollback evidence",
        )
    installer_source_digest = previous_installer_receipt.get("sourceDigest")
    if (
        type(installer_source_digest) is not str
        or _SHA256_PATTERN.fullmatch(installer_source_digest) is None
    ):
        raise InstallError(
            "ROLLBACK_INSTALLER_RECEIPT_MISMATCH",
            "архивная квитанция не содержит sourceDigest",
        )

    paths = rollback_manifest_preparation_paths_v2(evidence)
    current_lineage = ActivationTransitionLineageV2.from_document(
        evidence.current_receipt["transitionLineage"]
    )
    if current_lineage.source_receipt is None:
        raise InstallError(
            "ROLLBACK_PREVIOUS_TRANSITION_REQUIRED",
            "текущая активация не содержит переход с предыдущей активации",
        )
    preparation = build_rollback_manifest_preparation_v2(
        evidence=evidence,
        current_preparation_receipt_path=current_lineage.source_receipt.path,
        journal_path=paths.journal_path,
        receipt_path=paths.receipt_path,
        lock_path=paths.lock_path,
        prepared_root=paths.prepared_root,
        installer_source_digest=installer_source_digest,
    )
    preparation_receipt = RollbackManifestPreparationExecutorV2(
        definition=preparation.definition
    ).execute()
    external_artifacts = read_rollback_external_artifacts_v2(
        evidence=evidence,
        installer_receipt_path=layout.installer_receipt_path,
    )
    operation_id = preparation_receipt.operation_id
    external_bindings = build_rollback_runtime_external_bindings_v2(
        evidence=evidence,
        external_artifacts=external_artifacts,
        operation_id=operation_id,
        readiness_token=secrets.token_urlsafe(32),
        codex_home=layout.codex_home,
        state_home=layout.state_home,
        interpreter=_bound_python_runtime_v2(),
        registry_command_runner=_registry_command_runner_v2(
            layout,
            extra_environment,
            working_directory=layout.codex_home,
        ),
        runtime_environment=_rollback_runtime_environment_v2(extra_environment),
    )
    return build_rollback_composition_from_preparation_receipt_v2(
        evidence=evidence,
        execution_plan=execution_plan,
        journal_path=layout.gateway_layout.journal_path,
        preparation_receipt=preparation_receipt,
        external_bindings=external_bindings,
        external_artifacts=external_artifacts,
    )


def _rollback_plan_id_v2(evidence: Any) -> str:
    """Стабильно адресовать нормативный план одного rollback evidence."""

    installation_id = getattr(evidence, "installation_id", None)
    operation_id = getattr(evidence, "current_operation_id", None)
    fingerprint = getattr(evidence, "evidence_fingerprint", None)
    if (
        not _identifier(installation_id, "ins2_", 32)
        or not _identifier(operation_id, "op2_", 32)
        or type(fingerprint) is not str
        or _SHA256_PATTERN.fullmatch(fingerprint) is None
    ):
        raise InstallError(
            "ROLLBACK_EVIDENCE_INVALID",
            "доказательство отката не содержит устойчивые идентификаторы",
        )
    return (
        "pl2_"
        + domain_fingerprint(
            "codex-smart/rollback-plan-id/v2",
            {
                "installationId": installation_id,
                "currentOperationId": operation_id,
                "evidenceFingerprint": fingerprint,
            },
        )[:32]
    )


def _lifecycle_adapter_public_result_v2(
    layout: InstallLayout,
    result: InstallerLifecycleAdapterResultV2,
    *,
    extra_environment: Mapping[str, str] | None,
) -> dict[str, Any]:
    diagnosis = doctor(layout, extra_environment=extra_environment)
    readiness = _public_readiness(diagnosis)
    completed = result.status in {"rolled_back", "recovered"}
    operation_id = result.operation_id if completed else None
    attempt_id = _new_public_attempt_id() if completed else None
    extensions: dict[str, Any] = {
        "lifecycleAdapter": {
            "journalKind": result.journal_kind,
            "internalOperationId": result.operation_id,
        },
        "doctor": dict(diagnosis),
    }
    if result.command == "recover":
        extensions["durableProcessOwnership"] = (
            _durable_process_ownership_projection_v2(layout.codex_home)
        )
    return build_lifecycle_command_result_v2(
        command=result.command,
        status=result.status,
        readiness=readiness,
        operation_id=operation_id,
        attempt_id=attempt_id,
        problems=_diagnosis_problems(diagnosis),
        extensions=extensions,
    )


def _completed_rollback_operation_v2(
    layout: InstallLayout,
    *,
    evidence: Any,
    current_installer_receipt: Mapping[str, Any],
) -> str | None:
    """Доказать, что текущий commit уже является результатом rollback."""

    operation_id = getattr(evidence, "current_operation_id", None)
    installation_id = getattr(evidence, "installation_id", None)
    current_activation_id = getattr(evidence, "current_activation_id", None)
    previous_activation_id = getattr(evidence, "previous_activation_id", None)
    if (
        not _identifier(operation_id, "op2_", 32)
        or not _identifier(installation_id, "ins2_", 32)
        or not _activation_identifier(current_activation_id)
        or not _activation_identifier(previous_activation_id)
    ):
        raise InstallError(
            "ROLLBACK_EVIDENCE_INVALID",
            "доказательство не содержит идентичность текущего commit",
        )
    receipt_path = (
        layout.gateway_layout.receipts_root
        / str(installation_id)
        / f"{operation_id}.rollback-preparation.json"
    )
    if not os.path.lexists(receipt_path):
        return None

    from codex_smart_subagents.rollback_manifest_preparation_v2 import (
        RollbackManifestPreparationReceiptV2,
    )

    try:
        receipt = RollbackManifestPreparationReceiptV2.from_path(receipt_path)
    except Exception as exc:
        raise InstallError(
            "ROLLBACK_COMPLETION_RECEIPT_INVALID",
            str(exc),
        ) from exc
    manifest_document = getattr(evidence, "manifest_document", None)
    current_projection = getattr(evidence, "current_manifest_projection", None)
    previous_operation_id = getattr(evidence, "previous_operation_id", None)
    extensions = (
        manifest_document.get("extensions")
        if isinstance(manifest_document, Mapping)
        else None
    )
    source_digest = (
        extensions.get("installerSourceDigest")
        if isinstance(extensions, Mapping)
        else None
    )
    try:
        if (
            type(source_digest) is not str
            or _SHA256_PATTERN.fullmatch(source_digest) is None
        ):
            raise InstallError(
                "INSTALLER_RECEIPT_MISMATCH",
                "манифест не содержит закреплённый sourceDigest",
            )
        committed_layout = _committed_installer_layout_v2(
            layout,
            current_installer_receipt,
        )
        expected_installer_receipt = _build_installer_receipt(
            committed_layout,
            source_digest=source_digest,
            identity={
                "installationId": str(installation_id),
                "activationId": str(current_activation_id),
            },
        )
    except InstallError as exc:
        raise InstallError(
            "ROLLBACK_COMPLETION_RECEIPT_INVALID",
            exc.message,
        ) from exc
    if (
        receipt.installation_id != installation_id
        or receipt.operation_id != operation_id
        or receipt.current_operation_id != previous_operation_id
        or receipt.current_activation_id != previous_activation_id
        or receipt.previous_activation_id != current_activation_id
        or receipt.target_path != layout.gateway_layout.manifest_path
        or not isinstance(manifest_document, Mapping)
        or dict(receipt.manifest_document) != dict(manifest_document)
        or receipt.expected_after != current_projection
        or current_installer_receipt.get("installationId") != installation_id
        or current_installer_receipt.get("activationId") != current_activation_id
        or dict(current_installer_receipt) != expected_installer_receipt
    ):
        raise InstallError(
            "ROLLBACK_COMPLETION_RECEIPT_INVALID",
            "квитанция подготовки не доказывает текущий завершённый rollback",
        )
    return str(operation_id)


def rollback_installation_v2(
    layout: InstallLayout,
    *,
    execute: bool,
    extra_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Построить или исполнить откат через строгие адаптеры версии 2."""

    gateway = layout.gateway_layout
    if not execute:
        inspection = _inspect_installation_recovery_v2(layout)
        if inspection.journal_kind != "none":
            raise InstallError(
                "ROLLBACK_RECOVERY_REQUIRED",
                "найден незавершённый журнал; сначала выполните recover --apply",
            )
        identity = _load_lifecycle_identity(layout)
        current_installer_receipt = _load_installer_receipt(
            layout.installer_receipt_path
        )
        evidence = read_rollback_v2(
            manifest_path=gateway.manifest_path,
            receipts_root=(gateway.receipts_root / identity["installationId"]),
            activations_root=gateway.managed_root / "activations",
            marketplace_link=gateway.marketplace_link,
        )
        completed_operation_id = _completed_rollback_operation_v2(
            layout,
            evidence=evidence,
            current_installer_receipt=current_installer_receipt,
        )
        if completed_operation_id is not None:
            return _lifecycle_adapter_public_result_v2(
                layout,
                InstallerLifecycleAdapterResultV2(
                    command="rollback",
                    status="unchanged",
                    operation_id=completed_operation_id,
                    journal_kind=None,
                ),
                extra_environment=extra_environment,
            )
        plan = plan_rollback_v2(
            evidence=evidence,
            registry=_lifecycle_plan_registry_v2(
                layout,
                activation_dir=(
                    evidence.activations_root / evidence.current_activation_id
                ),
            ),
            plan_id=_rollback_plan_id_v2(evidence),
            build_definition=None,
        )
        result = execute_rollback_v2(plan=plan, preview=True)
        return _lifecycle_adapter_public_result_v2(
            layout,
            result,
            extra_environment=extra_environment,
        )

    with installation_lock(layout.lock_path):
        inspection = inspect_recovery_v2(
            journal_root=gateway.manifest_root,
            preparation_journal_path=(
                gateway.manifest_root
                / f"{INSTALLATION_NAME}.activation-preparation.transaction.json"
            ),
            rollback_preparation_journal_path=(
                gateway.manifest_root
                / (
                    f"{INSTALLATION_NAME}."
                    "rollback-manifest-preparation.transaction.json"
                )
            ),
            operation_journal_path=gateway.journal_path,
        )
        if inspection.journal_kind != "none":
            raise InstallError(
                "ROLLBACK_RECOVERY_REQUIRED",
                "найден незавершённый журнал; сначала выполните recover --apply",
            )
        current_installer_receipt = _load_installer_receipt(
            layout.installer_receipt_path
        )
        reconciled_before = _try_reconcile_pending_committed_upgrade_v2(
            layout,
            previous_receipt=current_installer_receipt,
            extra_environment=extra_environment,
        )
        if reconciled_before is not None:
            current_installer_receipt = _load_installer_receipt(
                layout.installer_receipt_path
            )
        identity = _load_lifecycle_identity(layout)
        evidence = read_rollback_v2(
            manifest_path=gateway.manifest_path,
            receipts_root=(gateway.receipts_root / identity["installationId"]),
            activations_root=gateway.managed_root / "activations",
            marketplace_link=gateway.marketplace_link,
        )
        completed_operation_id = _completed_rollback_operation_v2(
            layout,
            evidence=evidence,
            current_installer_receipt=current_installer_receipt,
        )
        if completed_operation_id is not None:
            completed_status = "unchanged"
            if reconciled_before is not None:
                if reconciled_before.get("operationId") != completed_operation_id:
                    raise InstallError(
                        "ROLLBACK_COMMIT_NOT_RECONCILABLE",
                        "согласованная квитанция относится к другой операции",
                    )
                completed_status = "rolled_back"
            result = InstallerLifecycleAdapterResultV2(
                command="rollback",
                status=completed_status,
                operation_id=completed_operation_id,
                journal_kind=None,
            )
        else:
            composition_box: dict[str, Any] = {}

            def build_definition(rollback_evidence, execution_plan):
                composition = _build_fresh_rollback_composition_v2(
                    layout,
                    evidence=rollback_evidence,
                    execution_plan=execution_plan,
                    current_installer_receipt=current_installer_receipt,
                    extra_environment=extra_environment,
                )
                composition_box["composition"] = composition
                return composition.definition

            plan = plan_rollback_v2(
                evidence=evidence,
                registry=_lifecycle_plan_registry_v2(
                    layout,
                    activation_dir=(
                        evidence.activations_root / evidence.current_activation_id
                    ),
                ),
                plan_id=_rollback_plan_id_v2(evidence),
                build_definition=build_definition,
            )
            composition = composition_box.get("composition")
            if composition is None:
                raise InstallError(
                    "ROLLBACK_PRODUCTION_COMPOSITION_REQUIRED",
                    "план отката не построил производственную композицию",
                )
            result = execute_rollback_v2(
                plan=plan,
                preview=False,
                executor=_rollback_operation_executor_v2(layout, evidence),
                callbacks=composition.callbacks,
                terminal_callbacks=composition.terminal_callbacks,
                installation_lock=_already_held_installation_lock_v2,
            )
            reconciled_after = _try_reconcile_pending_committed_upgrade_v2(
                layout,
                previous_receipt=current_installer_receipt,
                extra_environment=extra_environment,
            )
            if reconciled_after is None:
                raise InstallError(
                    "ROLLBACK_COMMIT_NOT_RECONCILABLE",
                    "завершённый откат не согласовал квитанцию установщика",
                )
    return _lifecycle_adapter_public_result_v2(
        layout,
        result,
        extra_environment=extra_environment,
    )


def _recovery_context_v2(
    layout: InstallLayout,
    inspection,
    *,
    extra_environment: Mapping[str, str] | None = None,
) -> tuple[PreparationJournalRecoveryV2 | None, MainJournalRecoveryV2 | None]:
    if inspection.journal_kind == "rollback_preparation":
        from codex_smart_subagents.rollback_manifest_preparation_v2 import (
            RollbackManifestPreparationDefinitionV2,
            RollbackManifestPreparationExecutorV2,
        )

        document = inspection.document
        definition_document = (
            document.get("definition") if isinstance(document, Mapping) else None
        )
        if not isinstance(definition_document, Mapping):
            raise InstallError(
                "ROLLBACK_PREPARATION_RECOVERY_JOURNAL_INVALID",
                "журнал подготовки отката не содержит полного определения",
            )
        try:
            definition = RollbackManifestPreparationDefinitionV2.from_document(
                definition_document
            )
        except Exception as error:
            raise InstallError(
                "ROLLBACK_PREPARATION_RECOVERY_JOURNAL_INVALID",
                str(error),
            ) from error
        if (
            definition.journal_path != inspection.journal_path
            or definition.activation_intent.operation_id != inspection.operation_id
        ):
            raise InstallError(
                "ROLLBACK_PREPARATION_RECOVERY_JOURNAL_INVALID",
                "пути или operationId подготовительного журнала изменились",
            )
        return (
            PreparationJournalRecoveryV2(
                executor=RollbackManifestPreparationExecutorV2(definition=definition)
            ),
            None,
        )
    if inspection.journal_kind == "preparation":
        journal_path = inspection.journal_path
        expected_journal_path = (
            layout.gateway_layout.manifest_root
            / f"{INSTALLATION_NAME}.activation-preparation.transaction.json"
        )
        if journal_path != expected_journal_path or not _identifier(
            inspection.operation_id, "op2_", 32
        ):
            raise InstallError(
                "PREPARATION_RECOVERY_JOURNAL_INVALID",
                "путь или operationId журнала подготовки неверны",
            )
        executor = build_persisted_upgrade_preparation_recovery_v2(
            journal_path=journal_path,
        )
        return PreparationJournalRecoveryV2(executor=executor), None
    if inspection.journal_kind != "main":
        raise InstallError(
            "RECOVERY_JOURNAL_UNKNOWN",
            f"неподдерживаемый вид журнала: {inspection.journal_kind}",
        )
    document = inspection.document
    if (
        isinstance(document, Mapping)
        and document.get("kind") == "activation"
        and document.get("operation") == "apply"
    ):
        composition = _build_update_main_recovery_composition_v2(
            layout,
            extra_environment=extra_environment,
        )
        return (
            None,
            composition.as_main_journal_recovery_v2(
                installation_lock=lambda: installation_lock(layout.lock_path),
            ),
        )
    if (
        isinstance(document, Mapping)
        and document.get("kind") == "uninstall"
        and document.get("operation") == "uninstall"
    ):
        from codex_smart_subagents.operation_definition_rehydration_v2 import (
            operation_definition_from_journal_v2,
        )

        try:
            definition = operation_definition_from_journal_v2(document)
            store = _AlreadyHeldOperationJournalStoreV2(
                _LazyOperationJournalStoreV2(layout=layout)
            )
            composition = recover_active_uninstall_composition_v2(
                registry=_lifecycle_plan_registry_v2(layout),
                definition=definition,
                maintenance_layout=_maintenance_layout_v2(layout),
                registrations=_registration_callbacks_v2(
                    layout,
                    extra_environment,
                ),
                store=store,
            )
        except Exception as error:
            raise InstallError(
                "UNINSTALL_RECOVERY_JOURNAL_INVALID",
                f"основной журнал удаления не восстановлен: {error}",
            ) from error
        return (
            None,
            MainJournalRecoveryV2(
                executor=composition.executor,
                definition=definition,
                callbacks=composition.callbacks,
                terminal_callbacks=composition.terminal_callbacks,
                installation_lock=lambda: installation_lock(layout.lock_path),
            ),
        )
    if (
        isinstance(document, Mapping)
        and document.get("kind") == "rollback"
        and document.get("operation") == "rollback"
    ):
        from codex_smart_subagents.installer_rollback_composition_v2 import (
            build_rollback_recovery_composition_from_receipt_v2,
            read_rollback_external_artifacts_v2,
        )
        from codex_smart_subagents.operation_definition_rehydration_v2 import (
            operation_definition_from_journal_v2,
        )
        from codex_smart_subagents.rollback_runtime_bindings_v2 import (
            recover_rollback_runtime_external_bindings_v2,
            rehydrate_rollback_evidence_v2,
        )

        definition = operation_definition_from_journal_v2(document)
        preparation_receipt_path = (
            layout.gateway_layout.receipts_root
            / definition.installation_id
            / f"{definition.operation_id}.rollback-preparation.json"
        )
        evidence = rehydrate_rollback_evidence_v2(
            definition=definition,
            journal=document,
            preparation_receipt_path=preparation_receipt_path,
        )
        external_artifacts = read_rollback_external_artifacts_v2(
            evidence=evidence,
            installer_receipt_path=layout.installer_receipt_path,
        )
        external_bindings = recover_rollback_runtime_external_bindings_v2(
            evidence=evidence,
            external_artifacts=external_artifacts,
            definition=definition,
            readiness_token=None,
            codex_home=layout.codex_home,
            state_home=layout.state_home,
            registry_command_runner=_registry_command_runner_v2(
                layout,
                extra_environment,
                working_directory=layout.codex_home,
            ),
            runtime_environment=_rollback_runtime_environment_v2(extra_environment),
        )
        composition = build_rollback_recovery_composition_from_receipt_v2(
            evidence=evidence,
            definition=definition,
            preparation_receipt=preparation_receipt_path,
            external_bindings=external_bindings,
            external_artifacts=external_artifacts,
        )
        return (
            None,
            MainJournalRecoveryV2(
                executor=_rollback_operation_executor_v2(layout, evidence),
                definition=definition,
                callbacks=composition.callbacks,
                terminal_callbacks=composition.terminal_callbacks,
                installation_lock=lambda: installation_lock(layout.lock_path),
            ),
        )
    raise InstallError(
        "RECOVERY_OPERATION_UNSUPPORTED",
        (
            "журнал "
            f"{inspection.journal_kind} найден, но его точное определение "
            "не относится к поддержанному переходу"
        ),
    )


def _inspect_installation_recovery_v2(layout: InstallLayout):
    gateway = layout.gateway_layout
    return inspect_recovery_v2(
        journal_root=gateway.manifest_root,
        preparation_journal_path=(
            gateway.manifest_root
            / f"{INSTALLATION_NAME}.activation-preparation.transaction.json"
        ),
        rollback_preparation_journal_path=(
            gateway.manifest_root
            / f"{INSTALLATION_NAME}.rollback-manifest-preparation.transaction.json"
        ),
        operation_journal_path=gateway.journal_path,
    )


def _recover_pending_install_journal_v2(
    layout: InstallLayout,
    *,
    inspection: Any,
    extra_environment: Mapping[str, str] | None,
) -> InstallerLifecycleAdapterResultV2:
    """Продолжить найденный журнал, когда installer lock уже удерживается."""

    preparation, main = _recovery_context_v2(
        layout,
        inspection,
        extra_environment=extra_environment,
    )
    plan = plan_recovery_v2(
        inspection=inspection,
        preparation=preparation,
        main=main,
    )
    if plan.main is not None:
        plan = replace(
            plan,
            main=replace(
                plan.main,
                installation_lock=_already_held_installation_lock_v2,
            ),
        )
    document = inspection.document
    transition_main = bool(
        inspection.journal_kind == "main"
        and isinstance(document, Mapping)
        and (
            (document.get("kind"), document.get("operation"))
            in {("activation", "apply"), ("rollback", "rollback")}
        )
    )
    previous_receipt = (
        _load_installer_receipt(layout.installer_receipt_path)
        if transition_main
        else None
    )
    result = execute_recovery_v2(plan=plan, preview=False)
    if previous_receipt is not None:
        reconciled = _try_reconcile_pending_committed_upgrade_v2(
            layout,
            previous_receipt=previous_receipt,
            extra_environment=extra_environment,
        )
        if reconciled is None:
            raise InstallError(
                "INSTALL_RECOVERY_NOT_RECONCILABLE",
                "восстановленный переход не согласовал квитанцию установщика",
            )
    return result


def recover_installation_v2(
    layout: InstallLayout,
    *,
    execute: bool,
    extra_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Без догадок продолжить ровно один известный журнал версии 2."""

    if os.path.lexists(layout.first_install_journal_path):
        journal = _load_first_install_journal_v2(layout)
        operation_id = str(journal["operationId"])
        if not execute:
            return _lifecycle_adapter_public_result_v2(
                layout,
                InstallerLifecycleAdapterResultV2(
                    command="recover",
                    status="planned",
                    operation_id=operation_id,
                    journal_kind="first-install",
                ),
                extra_environment=extra_environment,
            )
        _validate_source_layout(layout)
        codex_version = _probe_version(layout, extra_environment)
        if not codex_version_supported(codex_version):
            raise InstallError(
                "CODEX_VERSION_INCOMPATIBLE",
                (
                    "требуется одна из проверенных версий Codex "
                    f"({_VERIFIED_CODEX_VERSION_TEXT}), обнаружен {codex_version}"
                ),
            )
        source_digest = _source_digest(layout)
        _require_first_install_journal_inputs_v2(
            journal,
            source_digest=source_digest,
            codex_version=codex_version,
        )
        with installation_lock(layout.lock_path):
            journal = _load_first_install_journal_v2(layout)
            _require_first_install_journal_inputs_v2(
                journal,
                source_digest=source_digest,
                codex_version=codex_version,
            )
            _continue_first_install_v2(
                layout,
                journal=journal,
                source_digest=source_digest,
                codex_version=codex_version,
                extra_environment=extra_environment,
                attempt=_InstallAttempt(),
            )
        return _lifecycle_adapter_public_result_v2(
            layout,
            InstallerLifecycleAdapterResultV2(
                command="recover",
                status="recovered",
                operation_id=operation_id,
                journal_kind="first-install",
            ),
            extra_environment=extra_environment,
        )

    maintenance = _maintenance_layout_v2(layout)
    if os.path.lexists(maintenance.uninstall_journal_path):
        recovered_uninstall = uninstall_retain_data_v2(
            maintenance,
            registrations=_registration_callbacks_v2(
                layout, extra_environment
            ),
            execute=execute,
            retain_data=True,
            now=_maintenance_now_v2,
        )
        result = InstallerLifecycleAdapterResultV2(
            command="recover",
            status=(
                "recovered"
                if recovered_uninstall.status in {"uninstalled", "unchanged"}
                else "planned"
            ),
            operation_id=recovered_uninstall.operation_id,
            journal_kind="uninstall",
        )
        return _lifecycle_adapter_public_result_v2(
            layout,
            result,
            extra_environment=extra_environment,
        )

    def build_plan(inspection):
        if inspection.journal_kind == "none":
            return plan_recovery_v2(inspection=inspection)
        preparation, main = _recovery_context_v2(
            layout,
            inspection,
            extra_environment=extra_environment,
        )
        return plan_recovery_v2(
            inspection=inspection,
            preparation=preparation,
            main=main,
        )

    inspection = _inspect_installation_recovery_v2(layout)
    if not execute:
        if inspection.journal_kind == "none":
            pending = None
            if os.path.lexists(layout.installer_receipt_path):
                previous_receipt = _load_installer_receipt(
                    layout.installer_receipt_path
                )
                pending = _inspect_pending_committed_upgrade_v2(
                    layout,
                    previous_receipt=previous_receipt,
                )
            if pending is None:
                result = execute_recovery_v2(
                    plan=build_plan(inspection),
                    preview=True,
                )
            else:
                result = InstallerLifecycleAdapterResultV2(
                    command="recover",
                    status="planned",
                    operation_id=str(pending["operationId"]),
                    journal_kind="main",
                )
        else:
            document = inspection.document
            if inspection.journal_kind == "main" and (
                not isinstance(document, Mapping)
                or (document.get("kind"), document.get("operation"))
                not in _SUPPORTED_MAIN_RECOVERY_OPERATIONS_V2
            ):
                raise InstallError(
                    "RECOVERY_OPERATION_UNSUPPORTED",
                    "основной журнал не относится к поддержанному переходу",
                )
            result = execute_recovery_v2(
                plan=RecoveryPlanV2(inspection=inspection),
                preview=True,
            )
        return _lifecycle_adapter_public_result_v2(
            layout,
            result,
            extra_environment=extra_environment,
        )

    receipt_present = os.path.lexists(layout.installer_receipt_path)
    if inspection.journal_kind == "none" and not receipt_present:
        result = execute_recovery_v2(
            plan=build_plan(inspection),
            preview=False,
        )
        return _lifecycle_adapter_public_result_v2(
            layout,
            result,
            extra_environment=extra_environment,
        )

    with installation_lock(layout.lock_path):
        inspection = _inspect_installation_recovery_v2(layout)
        plan = build_plan(inspection)
        if getattr(plan, "main", None) is not None:
            plan = replace(
                plan,
                main=replace(
                    plan.main,
                    installation_lock=_already_held_installation_lock_v2,
                ),
            )

        document = inspection.document
        transition_main = bool(
            inspection.journal_kind == "main"
            and isinstance(document, Mapping)
            and (
                (document.get("kind"), document.get("operation"))
                in {("activation", "apply"), ("rollback", "rollback")}
            )
        )
        previous_receipt: Mapping[str, Any] | None = None
        if transition_main or inspection.journal_kind == "none":
            previous_receipt = _load_installer_receipt(layout.installer_receipt_path)

        result = execute_recovery_v2(plan=plan, preview=False)
        if previous_receipt is not None:
            reconciled = _try_reconcile_pending_committed_upgrade_v2(
                layout,
                previous_receipt=previous_receipt,
                extra_environment=extra_environment,
            )
            if transition_main and reconciled is None:
                raise InstallError(
                    "UPDATE_RECOVERY_NOT_RECONCILABLE",
                    "восстановленная операция не оставила ожидаемую активацию",
                )
            if inspection.journal_kind == "none" and reconciled is not None:
                result = InstallerLifecycleAdapterResultV2(
                    command="recover",
                    status="recovered",
                    operation_id=str(reconciled["operationId"]),
                    journal_kind="main",
                )
    return _lifecycle_adapter_public_result_v2(
        layout,
        result,
        extra_environment=extra_environment,
    )


def _public_cleanup_required_v2(
    error: BaseException,
) -> tuple[str, dict[str, Any]] | None:
    """Построить закрытое публичное описание обязанности очистки."""

    raw_obligation_ids: list[object]
    raw_cleanup_obligation: Mapping[str, object] | None
    if isinstance(error, OutstandingDurableProcessOwnershipV2):
        code = error.code
        raw_obligation_ids = list(error.lease_ids)
        raw_cleanup_obligation = None
    elif isinstance(
        error,
        operation_process_group_supervisor_v2.
        OutstandingProcessCleanupObligationV2,
    ):
        code = "OUTSTANDING_PROCESS_CLEANUP_OBLIGATION"
        raw_obligation_ids = list(error.obligation_ids)
        raw_cleanup_obligation = None
    elif isinstance(
        error,
        operation_process_group_supervisor_v2.
        DurableProcessOwnershipCallbackErrorV2,
    ):
        code = "DURABLE_PROCESS_OWNERSHIP_CALLBACK_FAILED"
        raw_obligation_ids = [error.lease_id]
        raw_cleanup_obligation = error.cleanup_obligation
    elif isinstance(
        error,
        supervised_subprocess_v2.SupervisedCommandCleanupRequiredV2,
    ):
        code = "SUPERVISED_COMMAND_CLEANUP_REQUIRED"
        raw_obligation_ids = []
        raw_cleanup_obligation = error.cleanup_obligation
    else:
        return None

    cleanup_obligation = (
        None
        if raw_cleanup_obligation is None
        else operation_process_group_supervisor_v2.
        validate_cleanup_obligation_v2(raw_cleanup_obligation)
    )
    if cleanup_obligation is not None:
        raw_obligation_ids.append(cleanup_obligation["obligationId"])
    if not raw_obligation_ids or any(
        type(value) is not str or not value
        for value in raw_obligation_ids
    ):
        raise ValueError("cleanup obligation identifiers must be non-empty strings")
    obligation_ids = sorted(set(raw_obligation_ids))
    return code, {
        "obligationIds": obligation_ids,
        "cleanupObligation": cleanup_obligation,
    }


def _failed_lifecycle_result_v2(
    command: str,
    error: BaseException,
) -> dict[str, Any]:
    cleanup_required = _public_cleanup_required_v2(error)
    code = (
        cleanup_required[0]
        if cleanup_required is not None
        else str(getattr(error, "code", "INSTALL_FAILED"))
    )
    message = str(getattr(error, "message", str(error) or type(error).__name__))
    status = "BROKEN" if command == "doctor" else "failed"
    extensions: dict[str, Any] = {
        "error": {
            "code": code[:128],
            "type": type(error).__name__[:128],
        }
    }
    if isinstance(error, ProvenTemporaryBusyV2):
        extensions["busyProof"] = dict(error.proof)
    if isinstance(error, operation_deadline_v2.OperationDeadlineExceededV2):
        extensions["deadlineProof"] = operation_deadline_v2.deadline_proof_v2(
            error
        )
    if cleanup_required is not None:
        extensions["cleanupRequired"] = cleanup_required[1]
    return build_lifecycle_command_result_v2(
        command=command,
        status=status,
        readiness="BROKEN",
        smoke_invocation_id=(
            _new_smoke_invocation_id() if command == "smoke" else None
        ),
        problems=(_public_problem(code, message),),
        extensions=extensions,
    )


def _execute_installer_invocation_without_lock_budget_v2(
    invocation: InstallerInvocationV2,
    *,
    extra_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Исполнить один разобранный публичный запрос через рабочий адаптер."""

    layout = default_layout(invocation)
    if invocation.command == "apply":
        legacy = install(
            layout,
            apply=invocation.execute,
            extra_environment=extra_environment,
        )
        return _wrap_apply_result_v2(layout, legacy, execute=invocation.execute)
    if invocation.command == "doctor":
        return _wrap_doctor_result_v2(
            doctor(layout, extra_environment=extra_environment)
        )
    if invocation.command == "smoke":
        return _wrap_smoke_result_v2(smoke(layout, extra_environment=extra_environment))
    if invocation.command == "inspect":
        return inspect_installation_v2(layout, extra_environment=extra_environment)
    if invocation.command == "rollback":
        return rollback_installation_v2(
            layout,
            execute=invocation.execute,
            extra_environment=extra_environment,
        )
    if invocation.command == "uninstall":
        return uninstall_installation_v2(
            layout,
            execute=invocation.execute,
            retain_data=invocation.retain_data,
            extra_environment=extra_environment,
        )
    if invocation.command == "recover":
        return recover_installation_v2(
            layout,
            execute=invocation.execute,
            extra_environment=extra_environment,
        )
    if invocation.command == "cleanup":
        return cleanup_installation_v2(
            layout,
            execute=invocation.execute,
            extra_environment=extra_environment,
        )
    raise InvalidInstallerInvocationV2(
        f"неподдерживаемая команда: {invocation.command}"
    )


def _durable_ownership_store_for_invocation_v2(
    invocation: InstallerInvocationV2,
) -> DurableProcessOwnershipStoreV2 | None:
    """Связать callbacks только с настоящей публичной командой, не с test-double."""

    if not isinstance(invocation, InstallerInvocationV2):
        return None
    raw_home = invocation.codex_home or os.environ.get(
        "CODEX_HOME", str(Path.home() / ".codex")
    )
    codex_home = Path(raw_home).expanduser().absolute()
    return DurableProcessOwnershipStoreV2(
        codex_home,
        operation=invocation.command,
        phase="installer-invocation",
        invocation_id="inv2_" + secrets.token_hex(16),
    )


def _raise_matching_durable_outstanding_v2(
    store: DurableProcessOwnershipStoreV2,
    *,
    context_kinds: frozenset[str] | None = None,
) -> None:
    records = store.load_all()
    if context_kinds is not None:
        records = tuple(
            record
            for record in records
            if record.context["contextKind"] in context_kinds
        )
    if records:
        raise OutstandingDurableProcessOwnershipV2(
            tuple(record.lease_id for record in records)
        )


def _recover_durable_ownership_v2(
    store: DurableProcessOwnershipStoreV2,
    *,
    context_kinds: frozenset[str],
) -> None:
    # ``False`` здесь означает только отсутствие положительного доказательства
    # принятия. Для кандидата этого недостаточно, чтобы разрешить сигнал:
    # отдельное положительное доказательство непринятия намеренно не передаётся.
    known_matching_lease_ids = tuple(
        record.lease_id
        for record in store.load_all()
        if record.context["contextKind"] in context_kinds
    )
    try:
        result = store.recover(
            accepted_candidate_proof=lambda _record: False,
            candidate_termination_authorized=None,
            context_kinds=context_kinds,
        )
    except operation_deadline_v2.OperationDeadlineExceededV2 as deadline:
        if known_matching_lease_ids:
            raise OutstandingDurableProcessOwnershipV2(
                known_matching_lease_ids
            ) from deadline
        raise
    remaining = frozenset(result.remaining_lease_ids)
    proven_remaining = tuple(
        lease_id
        for lease_id in known_matching_lease_ids
        if lease_id in remaining
    )
    if proven_remaining:
        raise OutstandingDurableProcessOwnershipV2(proven_remaining)
    _raise_matching_durable_outstanding_v2(
        store,
        context_kinds=context_kinds,
    )


def _durable_callback_error_cause_v2(
    error: BaseException,
) -> operation_process_group_supervisor_v2.DurableProcessOwnershipCallbackErrorV2 | None:
    current: BaseException | None = error
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        if isinstance(
            current,
            operation_process_group_supervisor_v2.
            DurableProcessOwnershipCallbackErrorV2,
        ):
            return current
        current = current.__cause__
    return None


def _stabilize_failed_durable_callback_v2(
    *,
    error: BaseException,
    supervisor: operation_process_group_supervisor_v2.
    OperationProcessGroupSupervisorV2,
    store: DurableProcessOwnershipStoreV2,
    durable_leases: Mapping[str, tuple[Any, Mapping[str, object]]],
) -> None:
    """Закрыть publish-окно в том же процессе либо сохранить cleanup."""

    callback_error = _durable_callback_error_cause_v2(error)
    if callback_error is None:
        return
    captured = durable_leases.get(callback_error.lease_id)
    if captured is None:
        return
    lease, context = captured
    if callback_error.outcome != "publish":
        try:
            store.transition(
                lease,
                context,
                callback_error.outcome,
                callback_error.cleanup_obligation,
            )
        except BaseException:
            return
        return
    try:
        store.publish(lease, context)
        durable_published = True
    except BaseException:
        durable_published = False
    supervisor.reconcile_completed_transients()
    if lease.lease_id not in supervisor.owned_lease_ids():
        if durable_published:
            store.transition(lease, context, "verified-exit", None)
        return
    deadline = operation_deadline_v2.current_operation_deadline_v2()
    if deadline is None:
        return
    try:
        result = supervisor.terminate_transient(
            lease,
            deadline=deadline,
            max_wait_seconds=0.5,
            reason_code="DURABLE_OWNERSHIP_PUBLICATION_FAILED",
        )
    except BaseException:
        return
    if not durable_published:
        try:
            store.publish(lease, context)
            durable_published = True
        except BaseException:
            durable_published = False
    if not durable_published:
        return
    if result.cleanup_obligation is None:
        store.transition(lease, context, "soft-terminated", None)
    else:
        store.transition(
            lease,
            context,
            "cleanup-required",
            result.cleanup_obligation,
        )


def _execute_installer_invocation_with_lock_budget_v2(
    invocation: InstallerInvocationV2,
    *,
    extra_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Исполнить запрос с одним общим сроком и бюджетом ожидания lock."""

    mutating_commands = {"apply", "rollback", "uninstall", "cleanup"}
    if invocation.execute and invocation.command in mutating_commands | {"recover"}:
        recovery = invocation.command == "recover"
        timeout_seconds = (
            finite_file_lock_v2.RECOVERY_LOCK_BUDGET_SECONDS
            if recovery
            else finite_file_lock_v2.MUTATING_LOCK_BUDGET_SECONDS
        )
        timeout_code = (
            "RECOVERY_LOCK_BUDGET_TIMEOUT"
            if recovery
            else "MUTATING_LOCK_BUDGET_TIMEOUT"
        )
        durable_store = _durable_ownership_store_for_invocation_v2(invocation)
        if durable_store is not None and not recovery:
            durable_store.assert_continuation_allowed()
        current_deadline = (
            operation_deadline_v2.current_operation_deadline_v2()
        )

        def execute_with_lock_budget() -> dict[str, Any]:
            with finite_file_lock_v2.lock_budget_v2(
                timeout_seconds=timeout_seconds,
                timeout_code=timeout_code,
            ):
                if durable_store is not None and recovery:
                    _recover_durable_ownership_v2(
                        durable_store,
                        context_kinds=frozenset(
                            {"installer-transient-v2"}
                        ),
                    )
                try:
                    result = (
                        _execute_installer_invocation_without_lock_budget_v2(
                            invocation,
                            extra_environment=extra_environment,
                        )
                    )
                except BaseException as error:
                    if durable_store is not None:
                        try:
                            durable_store.assert_continuation_allowed()
                        except OutstandingDurableProcessOwnershipV2 as outstanding:
                            raise outstanding from error
                    raise
                if durable_store is not None and recovery:
                    _recover_durable_ownership_v2(
                        durable_store,
                        context_kinds=frozenset(
                            {"candidate-dispatch-v2"}
                        ),
                    )
                supervisor = (
                    operation_process_group_supervisor_v2.
                    current_process_group_supervisor_v2()
                )
                if supervisor is not None:
                    supervisor.assert_operation_quiescent()
                if durable_store is not None:
                    durable_store.assert_continuation_allowed()
                return result

        def execute_with_process_supervision() -> dict[str, Any]:
            current_supervisor = (
                operation_process_group_supervisor_v2.
                current_process_group_supervisor_v2()
            )
            if current_supervisor is not None:
                current_supervisor.assert_continuation_allowed()
                return execute_with_lock_budget()
            durable_leases: dict[
                str,
                tuple[Any, Mapping[str, object]],
            ] = {}
            durable_published_lease_ids: set[str] = set()
            if durable_store is None:
                supervisor = (
                    operation_process_group_supervisor_v2.
                    OperationProcessGroupSupervisorV2()
                )
            else:
                def publish_ownership(
                    lease: Any,
                    context: Mapping[str, object],
                ) -> None:
                    durable_context = dict(context)
                    durable_leases[lease.lease_id] = (
                        lease,
                        durable_context,
                    )
                    durable_store.publish(lease, durable_context)
                    durable_published_lease_ids.add(lease.lease_id)

                def transition_ownership(
                    lease: Any,
                    context: Mapping[str, object],
                    outcome: str,
                    cleanup_obligation: Mapping[str, object] | None,
                ) -> None:
                    durable_store.transition(
                        lease,
                        dict(context),
                        outcome,
                        cleanup_obligation,
                    )
                    if outcome != "cleanup-required":
                        durable_leases.pop(lease.lease_id, None)
                        durable_published_lease_ids.discard(lease.lease_id)

                supervisor = (
                    operation_process_group_supervisor_v2.
                    OperationProcessGroupSupervisorV2(
                        ownership_publisher=publish_ownership,
                        ownership_transition=transition_ownership,
                    )
                )
            try:
                with (
                    operation_process_group_supervisor_v2.
                    scoped_current_process_group_supervisor_v2(supervisor)
                ):
                    return execute_with_lock_budget()
            except BaseException as error:
                if durable_store is not None:
                    _stabilize_failed_durable_callback_v2(
                        error=error,
                        supervisor=supervisor,
                        store=durable_store,
                        durable_leases=durable_leases,
                    )
                    try:
                        supervisor.reconcile_completed_transients()
                    except BaseException as reconcile_error:
                        published = tuple(
                            lease_id
                            for lease_id in durable_leases
                            if lease_id in durable_published_lease_ids
                        )
                        if published:
                            raise OutstandingDurableProcessOwnershipV2(
                                published
                            ) from reconcile_error
                        raise
                    published = tuple(
                        lease_id
                        for lease_id in durable_leases
                        if lease_id in durable_published_lease_ids
                    )
                    if published:
                        raise OutstandingDurableProcessOwnershipV2(
                            published
                        ) from error
                    try:
                        durable_store.assert_continuation_allowed()
                    except OutstandingDurableProcessOwnershipV2 as outstanding:
                        raise outstanding from error
                else:
                    supervisor.reconcile_completed_transients()
                try:
                    supervisor.assert_continuation_allowed()
                except (
                    operation_process_group_supervisor_v2.
                    OutstandingProcessCleanupObligationV2
                ) as outstanding:
                    raise outstanding from error
                raise

        if current_deadline is not None:
            current_deadline.checkpoint()
            return execute_with_process_supervision()

        deadline = operation_deadline_v2.OperationDeadlineV2.start(
            operation=invocation.command,
            timeout_seconds=timeout_seconds,
            timeout_code=(
                "RECOVERY_OPERATION_DEADLINE_TIMEOUT"
                if recovery
                else "MUTATING_OPERATION_DEADLINE_TIMEOUT"
            ),
        )
        with operation_deadline_v2.scoped_current_deadline_v2(deadline):
            deadline.checkpoint()
            return execute_with_process_supervision()
    return _execute_installer_invocation_without_lock_budget_v2(
        invocation,
        extra_environment=extra_environment,
    )


def _file_lock_timeout_cause_v2(
    error: BaseException,
) -> finite_file_lock_v2.FileLockTimeoutV2 | None:
    current: BaseException | None = error
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        if isinstance(current, finite_file_lock_v2.FileLockTimeoutV2):
            return current
        current = current.__cause__
    return None


def _operation_deadline_cause_v2(
    error: BaseException,
) -> operation_deadline_v2.OperationDeadlineExceededV2 | None:
    """Найти только явно связанную причину истечения общего срока."""

    current: BaseException | None = error
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        if isinstance(
            current, operation_deadline_v2.OperationDeadlineExceededV2
        ):
            return current
        current = current.__cause__
    return None


def _cleanup_required_cause_v2(
    error: BaseException,
) -> BaseException | None:
    """Найти блокирующее владение раньше любой вложенной ошибки срока."""

    current: BaseException | None = error
    visited: set[int] = set()
    fallback: BaseException | None = None
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        if isinstance(current, OutstandingDurableProcessOwnershipV2):
            return current
        if isinstance(
            current,
            (
                supervised_subprocess_v2.SupervisedCommandCleanupRequiredV2,
                operation_process_group_supervisor_v2.
                OutstandingProcessCleanupObligationV2,
            ),
        ) and fallback is None:
            fallback = current
        if (
            isinstance(
                current,
                operation_process_group_supervisor_v2.
                DurableProcessOwnershipCallbackErrorV2,
            )
            and fallback is None
        ):
            fallback = current
        current = current.__cause__
    return fallback


def execute_installer_invocation_v2(
    invocation: InstallerInvocationV2,
    *,
    extra_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Преобразовать доказанный lock-timeout во временную занятость."""

    try:
        return _execute_installer_invocation_with_lock_budget_v2(
            invocation,
            extra_environment=extra_environment,
        )
    except BaseException as error:
        cleanup_required = _cleanup_required_cause_v2(error)
        if cleanup_required is not None:
            raise cleanup_required from None
        deadline = _operation_deadline_cause_v2(error)
        if deadline is not None:
            raise deadline from None
        timeout = _file_lock_timeout_cause_v2(error)
        if timeout is None:
            raise
        raise ProvenTemporaryBusyV2(
            code=timeout.code,
            message=str(getattr(error, "message", str(error))),
            proof={
                "proofKind": "finite-file-lock-timeout-v2",
                "command": invocation.command,
                "execute": bool(invocation.execute),
                "timeoutCode": timeout.code,
                "timeoutSeconds": timeout.timeout_seconds,
                "timedOutLockAcquired": False,
            },
        ) from error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", default=str(_REPO))
    parser.add_argument("--codex-home")
    parser.add_argument("--bin-dir")
    parser.add_argument("--state-home")
    parser.add_argument("--codex-binary", default="codex")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--doctor", action="store_true")
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    try:
        invocation = parse_installer_argv_v2(
            raw_argv,
            default_source_root=_REPO,
        )
    except InvalidInstallerInvocationV2 as error:
        result = {
            "schemaVersion": 2,
            "status": "failed",
            "code": error.code,
            "message": error.message,
        }
        _print_result(result, as_json="--json" in raw_argv)
        return exit_code_v2(error)

    try:
        result = execute_installer_invocation_v2(invocation)
    except operation_deadline_v2.OperationDeadlineExceededV2 as error:
        result = _failed_lifecycle_result_v2(invocation.command, error)
        _print_result(result, as_json=invocation.json)
        return exit_code_v2(error)
    except ProvenTemporaryBusyV2 as error:
        result = _failed_lifecycle_result_v2(invocation.command, error)
        _print_result(result, as_json=invocation.json)
        return exit_code_v2(error)
    except BaseException as error:
        try:
            result = _failed_lifecycle_result_v2(invocation.command, error)
        except BaseException as structural_error:
            result = {
                "schemaVersion": 2,
                "status": "failed",
                "code": "RESULT_CONSTRUCTION_FAILED",
                "message": str(structural_error)[:2048],
            }
            _print_result(result, as_json=invocation.json)
            return 70
        _print_result(result, as_json=invocation.json)
        return exit_code_v2(result)
    _print_result(result, as_json=invocation.json)
    return exit_code_v2(result)


def _print_result(result: Mapping[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(
            json.dumps(
                result,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    elif "actions" in result:
        print("\n".join(str(action) for action in result["actions"]))
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(main())
