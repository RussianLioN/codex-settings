#!/usr/bin/env python3
"""Безопасная установка и проверка adaptive subagents v2."""

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
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence


SCHEMA_VERSION = 1
SUPPORTED_CODEX_VERSION = "0.144.4"
MARKETPLACE_NAME = "codex-settings-adaptive"
PLUGIN_NAME = "codex-smart-subagents"
PLUGIN_ID = f"{PLUGIN_NAME}@{MARKETPLACE_NAME}"
INSTALLATION_NAME = "codex-smart-subagents-v2"
LEGACY_HIGHFD_SHA256 = (
    "bb5dd276d00cad26f418825bd4d2bd869dc68943f3e26a0c255d3335c7ef14e4"
)
UNGUARDED_HIGHFD_SHA256 = (
    "065cddc3bb5be54915004766e41a3208a9fb720fd23dce2e0d3f5fdda721e85c"
)
_VERSION_PATTERN = re.compile(r"^codex-cli ([0-9]+\.[0-9]+\.[0-9]+)\n?$")
_EXCLUDED_TREE_NAMES = frozenset({"__pycache__", ".DS_Store"})
_EXPECTED_HOOK_EVENTS = ("userPromptSubmit", "stop")
_TRUSTED_HOOK_STATES = frozenset({"trusted", "managed"})
_KNOWN_HOOK_TRUST_STATES = frozenset(
    {"managed", "untrusted", "trusted", "modified"}
)


class InstallError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class InstallLayout:
    source_root: Path
    codex_home: Path
    bin_dir: Path
    codex_binary: Path

    def __post_init__(self) -> None:
        for name in ("source_root", "codex_home", "bin_dir", "codex_binary"):
            value = getattr(self, name)
            if not value.is_absolute():
                raise ValueError(f"{name} must be absolute")

    @property
    def plugin_source(self) -> Path:
        return self.source_root / "plugins" / PLUGIN_NAME

    @property
    def marketplace_source(self) -> Path:
        return self.source_root / ".agents" / "plugins" / "marketplace.json"

    @property
    def catalog_source(self) -> Path:
        return self.source_root / ".codex" / "adaptive-subagents.toml"

    @property
    def config_path(self) -> Path:
        return self.codex_home / "config.toml"

    @property
    def owned_root(self) -> Path:
        return self.codex_home / INSTALLATION_NAME

    @property
    def marketplace_root(self) -> Path:
        return self.owned_root / "marketplace"

    @property
    def marketplace_path(self) -> Path:
        return (
            self.marketplace_root
            / ".agents"
            / "plugins"
            / "marketplace.json"
        )

    @property
    def installed_plugin_root(self) -> Path:
        return self.marketplace_root / "plugins" / PLUGIN_NAME

    @property
    def catalog_path(self) -> Path:
        return (
            self.installed_plugin_root
            / "config"
            / "adaptive-subagents.toml"
        )

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
        return (
            self.installed_plugin_root
            / "bin"
            / "codex-smart-subagents-admin"
        )

    @property
    def highfd_source(self) -> Path:
        return self.source_root / "scripts" / "codex-highfd"

    @property
    def highfd_path(self) -> Path:
        return self.bin_dir / "codex-highfd"

    @property
    def manifest_root(self) -> Path:
        return self.codex_home / "install-manifests"

    @property
    def manifest_path(self) -> Path:
        return self.manifest_root / f"{INSTALLATION_NAME}.json"

    @property
    def lock_path(self) -> Path:
        return self.manifest_root / f"{INSTALLATION_NAME}.lock"

    @property
    def backups_root(self) -> Path:
        return self.codex_home / "backups" / INSTALLATION_NAME


def default_layout(args: argparse.Namespace) -> InstallLayout:
    source_root = Path(args.source_root).expanduser().resolve()
    codex_home = Path(
        args.codex_home
        or os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))
    ).expanduser().resolve()
    bin_dir = Path(
        args.bin_dir or str(Path.home() / ".local" / "bin")
    ).expanduser().resolve()
    binary = Path(args.codex_binary).expanduser()
    if not binary.is_absolute():
        found = shutil.which(str(binary))
        if found is None:
            raise InstallError(
                "CODEX_BINARY_MISSING",
                f"не найден исполняемый файл Codex: {binary}",
            )
        binary = Path(found)
    return InstallLayout(
        source_root=source_root,
        codex_home=codex_home,
        bin_dir=bin_dir,
        codex_binary=binary.resolve(),
    )


def install(
    layout: InstallLayout,
    *,
    apply: bool,
    extra_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    _validate_layout(layout)
    version = _probe_version(layout, extra_environment)
    if version != SUPPORTED_CODEX_VERSION:
        raise InstallError(
            "UNSUPPORTED_CODEX_VERSION",
            (
                f"требуется Codex {SUPPORTED_CODEX_VERSION}, "
                f"обнаружен {version}"
            ),
        )
    source_digest = _source_digest(layout)
    actions = [
        f"создать резервную копию {layout.config_path}",
        f"создать локальный рынок {layout.marketplace_root}",
        (
            "выполнить codex plugin marketplace add "
            f"{layout.marketplace_root}"
        ),
        f"выполнить codex plugin add {PLUGIN_ID}",
        f"создать {layout.launcher_path} как ссылку на установленную оболочку",
        f"создать {layout.admin_path} как ссылку на административную команду",
        f"установить управляемую оболочку {layout.highfd_path}",
        f"записать манифест {layout.manifest_path}",
    ]
    if not apply:
        return {
            "status": "planned",
            "actions": actions,
            "sourceDigest": source_digest,
        }

    _prepare_private_directory(layout.codex_home, create=False)
    _prepare_private_directory(layout.manifest_root)
    with installation_lock(layout.lock_path):
        if layout.manifest_path.is_file():
            manifest = load_manifest(layout.manifest_path)
            diagnosis = doctor(
                layout,
                extra_environment=extra_environment,
            )
            if (
                manifest.get("sourceDigest") == source_digest
                and _doctor_accepts_installed_state(diagnosis)
            ):
                return {
                    "status": "unchanged",
                    "manifest": str(layout.manifest_path),
                    "readiness": diagnosis["status"],
                    "hookTrust": diagnosis["hookTrust"],
                }
            raise InstallError(
                "EXISTING_INSTALLATION_MISMATCH",
                (
                    "существующая установка отличается от источника или "
                    "повреждена; выполните doctor и безопасный rollback"
                ),
            )

        _preflight_unowned_targets(layout, extra_environment)
        backup = _create_backup(layout)
        installed_marketplace = False
        installed_plugin = False
        installed_owned_tree = False
        installed_launcher = False
        installed_admin = False
        highfd_install_attempted = False
        installed_manifest = False
        try:
            _install_owned_tree(layout)
            installed_owned_tree = True
            _codex_json(
                layout,
                [
                    "plugin",
                    "marketplace",
                    "add",
                    str(layout.marketplace_root),
                    "--json",
                ],
                "CODEX_MARKETPLACE_ADD_FAILED",
                extra_environment,
            )
            installed_marketplace = True
            _codex_json(
                layout,
                ["plugin", "add", PLUGIN_ID, "--json"],
                "CODEX_PLUGIN_ADD_FAILED",
                extra_environment,
            )
            installed_plugin = True
            _seal_private_tree(layout.owned_root)
            _install_launcher(layout)
            installed_launcher = True
            _install_admin(layout)
            installed_admin = True
            highfd_install_attempted = True
            _install_highfd(layout)
            manifest = _build_manifest(
                layout,
                version=version,
                source_digest=source_digest,
                backup=backup,
            )
            _atomic_write_json(layout.manifest_path, manifest, mode=0o600)
            installed_manifest = True
            diagnosis = doctor(
                layout,
                extra_environment=extra_environment,
            )
            if not _doctor_accepts_installed_state(diagnosis):
                summary = ", ".join(
                    str(problem["code"])
                    for problem in diagnosis["problems"]
                )
                raise InstallError(
                    "POST_INSTALL_DOCTOR_FAILED",
                    summary or "неизвестная ошибка проверки",
                )
        except BaseException:
            _cleanup_failed_install(
                layout,
                backup=backup,
                installed_plugin=installed_plugin,
                installed_marketplace=installed_marketplace,
                installed_owned_tree=installed_owned_tree,
                installed_launcher=installed_launcher,
                installed_admin=installed_admin,
                highfd_install_attempted=highfd_install_attempted,
                installed_manifest=installed_manifest,
                extra_environment=extra_environment,
            )
            raise

    return {
        "status": "installed",
        "manifest": str(layout.manifest_path),
        "backup": str(backup["directory"]),
        "readiness": diagnosis["status"],
        "hookTrust": diagnosis["hookTrust"],
    }


def doctor(
    layout: InstallLayout,
    *,
    extra_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    problems: list[dict[str, str]] = []
    try:
        manifest = load_manifest(layout.manifest_path)
    except InstallError as exc:
        return {
            "ok": False,
            "status": "BROKEN",
            "problems": [{"code": exc.code, "message": exc.message}],
            "hookTrust": [],
            "hookWarnings": [],
        }

    problems.extend(verify_manifest_artifacts(layout, manifest))
    try:
        version = _probe_version(layout, extra_environment)
    except InstallError as exc:
        problems.append({"code": exc.code, "message": exc.message})
    else:
        if version != manifest.get("codexVersion"):
            problems.append(
                {
                    "code": "CODEX_VERSION_MISMATCH",
                    "message": (
                        f"манифест: {manifest.get('codexVersion')!r}, "
                        f"фактически: {version!r}"
                    ),
                }
            )

    try:
        marketplaces = _list_marketplaces(layout, extra_environment)
    except InstallError as exc:
        problems.append({"code": exc.code, "message": exc.message})
    else:
        matches = [
            item
            for item in marketplaces
            if item.get("name") == MARKETPLACE_NAME
        ]
        if len(matches) != 1 or Path(
            str(matches[0].get("root", ""))
        ).resolve() != layout.marketplace_root:
            problems.append(
                {
                    "code": "MARKETPLACE_STATE_MISMATCH",
                    "message": "рынок установки отсутствует или указывает не туда",
                }
            )

    try:
        plugins = _list_plugins(layout, extra_environment)
    except InstallError as exc:
        problems.append({"code": exc.code, "message": exc.message})
    else:
        matches = [
            item for item in plugins if item.get("pluginId") == PLUGIN_ID
        ]
        if (
            len(matches) != 1
            or matches[0].get("installed") is not True
            or matches[0].get("enabled") is not True
        ):
            problems.append(
                {
                    "code": "PLUGIN_STATE_MISMATCH",
                    "message": "расширение отсутствует, выключено или неоднозначно",
                }
            )
        elif not _plugin_source_matches(
            matches[0],
            layout.installed_plugin_root,
        ):
            problems.append(
                {
                    "code": "PLUGIN_SOURCE_MISMATCH",
                    "message": "расширение загружено не из принадлежащего установке рынка",
                }
            )

    problems.extend(_mcp_contract_problems(layout))
    structural_problems = list(problems)
    hook_report = _hook_trust_report(layout)
    problems.extend(hook_report["problems"])
    status = (
        "BROKEN"
        if structural_problems
        else str(hook_report["status"])
    )
    return {
        "ok": status == "READY",
        "status": status,
        "problems": problems,
        "hookTrust": hook_report["hooks"],
        "hookWarnings": hook_report["warnings"],
    }


def smoke(
    layout: InstallLayout,
    *,
    extra_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    diagnosis = doctor(layout, extra_environment=extra_environment)
    if not diagnosis["ok"]:
        return {
            "ok": False,
            "status": diagnosis["status"],
            "problems": diagnosis["problems"],
            "hookTrust": diagnosis["hookTrust"],
            "hookWarnings": diagnosis["hookWarnings"],
            "tools": [],
            "launcherVersion": "",
            "highfdLauncherVersion": "",
        }
    environment = _command_environment(
        layout,
        extra_environment,
        include_runtime=True,
    )
    launcher = _run_process(
        [str(layout.launcher_path), "--version"],
        environment,
        timeout=10,
    )
    if launcher.returncode != 0:
        raise InstallError(
            "LAUNCHER_SMOKE_FAILED",
            _bounded_error(launcher),
        )
    launcher_version = launcher.stdout.strip()
    if launcher_version != f"codex-cli {SUPPORTED_CODEX_VERSION}":
        raise InstallError(
            "LAUNCHER_SMOKE_FAILED",
            f"неожиданный ответ оболочки: {launcher_version!r}",
        )
    highfd = _run_process(
        [str(layout.highfd_path), "--version"],
        environment,
        timeout=10,
    )
    if highfd.returncode != 0:
        raise InstallError(
            "HIGHFD_SMOKE_FAILED",
            _bounded_error(highfd),
        )
    highfd_version = highfd.stdout.strip()
    if highfd_version != launcher_version:
        raise InstallError(
            "HIGHFD_SMOKE_FAILED",
            (
                "цепочка codex-highfd → codex-smart вернула "
                f"{highfd_version!r}"
            ),
        )

    requests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {
                    "name": "adaptive-install-smoke",
                    "version": "1",
                },
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        },
    ]
    payload = "".join(
        json.dumps(request, separators=(",", ":")) + "\n"
        for request in requests
    )
    mcp = subprocess.run(
        [
            str(
                layout.installed_plugin_root
                / "bin"
                / "codex-smart-subagents-mcp"
            ),
            "--stdio",
        ],
        input=payload,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        timeout=10,
        check=False,
        shell=False,
        close_fds=True,
    )
    if mcp.returncode != 0:
        raise InstallError("MCP_SMOKE_FAILED", _bounded_error(mcp))
    try:
        responses = [
            json.loads(line)
            for line in mcp.stdout.splitlines()
            if line.strip()
        ]
        tools = [
            tool["name"]
            for tool in responses[1]["result"]["tools"]
        ]
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise InstallError(
            "MCP_SMOKE_FAILED",
            "ответ MCP не соответствует ожидаемому протоколу",
        ) from exc
    expected = [
        "smart_plan",
        "smart_start",
        "smart_wait",
        "smart_cancel",
    ]
    if tools != expected:
        raise InstallError(
            "MCP_SMOKE_FAILED",
            f"неожиданный набор инструментов: {tools!r}",
        )
    return {
        "ok": True,
        "status": "READY",
        "problems": [],
        "hookTrust": diagnosis["hookTrust"],
        "hookWarnings": diagnosis["hookWarnings"],
        "tools": tools,
        "launcherVersion": launcher_version,
        "highfdLauncherVersion": highfd_version,
    }


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise InstallError(
            "INSTALL_MANIFEST_MISSING",
            f"нет безопасного манифеста установки: {path}",
        ) from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise InstallError(
            "INSTALL_MANIFEST_UNSAFE",
            f"манифест имеет небезопасные свойства: {path}",
        )
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InstallError(
            "INSTALL_MANIFEST_INVALID",
            f"манифест установки повреждён: {path}",
        ) from exc
    if (
        not isinstance(document, dict)
        or document.get("schemaVersion") != SCHEMA_VERSION
        or document.get("installation") != INSTALLATION_NAME
        or document.get("pluginId") != PLUGIN_ID
    ):
        raise InstallError(
            "INSTALL_MANIFEST_INVALID",
            "неподдерживаемая схема или идентичность манифеста",
        )
    return document


def verify_manifest_artifacts(
    layout: InstallLayout,
    manifest: Mapping[str, Any],
) -> list[dict[str, str]]:
    problems: list[dict[str, str]] = []
    expected_paths = {
        "ownedTree": layout.owned_root,
        "launcher": layout.launcher_path,
        "highfd": layout.highfd_path,
    }
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        return [
            {
                "code": "INSTALL_MANIFEST_INVALID",
                "message": "в манифесте нет карты артефактов",
            }
        ]
    tree = artifacts.get("ownedTree")
    if not isinstance(tree, dict) or tree.get("path") != str(
        expected_paths["ownedTree"]
    ):
        problems.append(
            {
                "code": "INSTALL_MANIFEST_INVALID",
                "message": "путь принадлежащего дерева не совпадает",
            }
        )
    else:
        try:
            actual = tree_digest(expected_paths["ownedTree"])
        except InstallError as exc:
            problems.append({"code": exc.code, "message": exc.message})
        else:
            if actual != tree.get("sha256"):
                problems.append(
                    {
                        "code": "ARTIFACT_FINGERPRINT_MISMATCH",
                        "message": str(expected_paths["ownedTree"]),
                    }
                )

    launcher = artifacts.get("launcher")
    if not isinstance(launcher, dict) or launcher.get("path") != str(
        expected_paths["launcher"]
    ):
        problems.append(
            {
                "code": "INSTALL_MANIFEST_INVALID",
                "message": "путь оболочки не совпадает",
            }
        )
    else:
        path = expected_paths["launcher"]
        if not path.is_symlink():
            problems.append(
                {
                    "code": "ARTIFACT_FINGERPRINT_MISMATCH",
                    "message": str(path),
                }
            )
        else:
            target = os.readlink(path)
            target_path = Path(target)
            if (
                target != launcher.get("target")
                or target_path != layout.launcher_target
            ):
                problems.append(
                    {
                        "code": "ARTIFACT_FINGERPRINT_MISMATCH",
                        "message": str(path),
                    }
                )
            else:
                try:
                    digest = file_digest(target_path)
                except InstallError as exc:
                    problems.append({"code": exc.code, "message": exc.message})
                else:
                    if digest != launcher.get("targetSha256"):
                        problems.append(
                            {
                                "code": "ARTIFACT_FINGERPRINT_MISMATCH",
                                "message": str(path),
                            }
                        )
    highfd = artifacts.get("highfd")
    if not isinstance(highfd, dict) or highfd.get("path") != str(
        expected_paths["highfd"]
    ):
        problems.append(
            {
                "code": "INSTALL_MANIFEST_INVALID",
                "message": "путь codex-highfd не совпадает",
            }
        )
    else:
        path = expected_paths["highfd"]
        if path.is_symlink() or not path.is_file():
            problems.append(
                {
                    "code": "ARTIFACT_FINGERPRINT_MISMATCH",
                    "message": str(path),
                }
            )
        else:
            try:
                digest = file_digest(path)
            except InstallError as exc:
                problems.append({"code": exc.code, "message": exc.message})
            else:
                if (
                    digest != highfd.get("sha256")
                    or stat.S_IMODE(path.stat().st_mode) != 0o755
                ):
                    problems.append(
                        {
                            "code": "ARTIFACT_FINGERPRINT_MISMATCH",
                            "message": str(path),
                        }
                    )
    admin = artifacts.get("admin")
    if not isinstance(admin, dict) or admin.get("path") != str(
        layout.admin_path
    ):
        problems.append(
            {
                "code": "INSTALL_MANIFEST_INVALID",
                "message": "путь административной команды не совпадает",
            }
        )
    elif not layout.admin_path.is_symlink():
        problems.append(
            {
                "code": "ARTIFACT_FINGERPRINT_MISMATCH",
                "message": str(layout.admin_path),
            }
        )
    else:
        target = os.readlink(layout.admin_path)
        if (
            target != admin.get("target")
            or Path(target) != layout.admin_target
        ):
            problems.append(
                {
                    "code": "ARTIFACT_FINGERPRINT_MISMATCH",
                    "message": str(layout.admin_path),
                }
            )
        else:
            try:
                digest = file_digest(layout.admin_target)
            except InstallError as exc:
                problems.append({"code": exc.code, "message": exc.message})
            else:
                if digest != admin.get("targetSha256"):
                    problems.append(
                        {
                            "code": "ARTIFACT_FINGERPRINT_MISMATCH",
                            "message": str(layout.admin_path),
                        }
                    )
    return problems


@contextmanager
def installation_lock(path: Path) -> Iterator[None]:
    _prepare_private_directory(path.parent)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise InstallError(
            "UNSAFE_INSTALL_LOCK",
            f"не удалось безопасно открыть блокировку: {path}",
        ) from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
        ):
            raise InstallError(
                "UNSAFE_INSTALL_LOCK",
                f"блокировка имеет небезопасные свойства: {path}",
            )
        os.fchmod(descriptor, 0o600)
        if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o600:
            raise InstallError(
                "UNSAFE_INSTALL_LOCK",
                f"не удалось ограничить права блокировки: {path}",
            )
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(descriptor)


def file_digest(path: Path) -> str:
    try:
        info = path.lstat()
    except OSError as exc:
        raise InstallError(
            "ARTIFACT_UNAVAILABLE",
            f"не удалось прочитать {path}: {exc}",
        ) from exc
    if not stat.S_ISREG(info.st_mode):
        raise InstallError(
            "UNSAFE_ARTIFACT",
            f"ожидался обычный файл: {path}",
        )
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_digest(root: Path) -> str:
    if not root.is_dir() or root.is_symlink():
        raise InstallError(
            "ARTIFACT_UNAVAILABLE",
            f"нет безопасного каталога: {root}",
        )
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            kind = b"d"
            value = b""
        elif stat.S_ISREG(info.st_mode):
            kind = b"x" if info.st_mode & stat.S_IXUSR else b"f"
            value = bytes.fromhex(file_digest(path))
        else:
            raise InstallError(
                "UNSAFE_ARTIFACT",
                f"дерево содержит ссылку или особый файл: {path}",
            )
        digest.update(kind)
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(f"{stat.S_IMODE(info.st_mode):04o}".encode("ascii"))
        digest.update(b"\0")
        digest.update(value)
    return digest.hexdigest()


def _validate_layout(layout: InstallLayout) -> None:
    for name, path in (
        ("source_root", layout.source_root),
        ("codex_home", layout.codex_home),
        ("bin_dir", layout.bin_dir),
    ):
        if path.is_symlink():
            raise InstallError(
                "UNSAFE_INSTALL_PATH",
                f"{name} не должен быть символической ссылкой: {path}",
            )
    if not layout.source_root.is_dir():
        raise InstallError(
            "SOURCE_ROOT_MISSING",
            f"нет корня исходников: {layout.source_root}",
        )
    for path in (
        layout.plugin_source / ".codex-plugin" / "plugin.json",
        layout.plugin_source / ".mcp.json",
        layout.marketplace_source,
        layout.catalog_source,
        layout.highfd_source,
    ):
        if not path.is_file() or path.is_symlink():
            raise InstallError(
                "SOURCE_ARTIFACT_MISSING",
                f"нет безопасного исходного файла: {path}",
            )
    if not layout.codex_home.is_dir():
        raise InstallError(
            "CODEX_HOME_MISSING",
            f"CODEX_HOME должен существовать: {layout.codex_home}",
        )
    if not layout.bin_dir.is_dir():
        raise InstallError(
            "BIN_DIR_MISSING",
            f"каталог оболочки должен существовать: {layout.bin_dir}",
        )
    try:
        binary_info = layout.codex_binary.stat()
    except OSError as exc:
        raise InstallError(
            "CODEX_BINARY_MISSING",
            f"не найден Codex: {layout.codex_binary}",
        ) from exc
    if (
        not stat.S_ISREG(binary_info.st_mode)
        or not os.access(layout.codex_binary, os.X_OK)
    ):
        raise InstallError(
            "CODEX_BINARY_MISSING",
            f"Codex не является исполняемым файлом: {layout.codex_binary}",
        )
    marketplace = json.loads(
        layout.marketplace_source.read_text(encoding="utf-8")
    )
    if marketplace.get("name") != MARKETPLACE_NAME:
        raise InstallError(
            "MARKETPLACE_IDENTITY_MISMATCH",
            "имя рынка не совпадает с контрактом установки",
        )


def _preflight_unowned_targets(
    layout: InstallLayout,
    extra_environment: Mapping[str, str] | None,
) -> None:
    conflicts = [
        path
        for path in (
            layout.owned_root,
            layout.launcher_path,
            layout.admin_path,
        )
        if os.path.lexists(path)
    ]
    if conflicts:
        raise InstallError(
            "TARGET_OWNERSHIP_CONFLICT",
            "существуют цели без манифеста: "
            + ", ".join(str(path) for path in conflicts),
        )
    if any(
        item.get("name") == MARKETPLACE_NAME
        for item in _list_marketplaces(layout, extra_environment)
    ):
        raise InstallError(
            "TARGET_OWNERSHIP_CONFLICT",
            f"рынок {MARKETPLACE_NAME} уже существует без манифеста",
        )
    if any(
        item.get("pluginId") == PLUGIN_ID
        for item in _list_plugins(layout, extra_environment)
    ):
        raise InstallError(
            "TARGET_OWNERSHIP_CONFLICT",
            f"расширение {PLUGIN_ID} уже существует без манифеста",
        )
    _verify_preexisting_highfd(layout)


def _source_digest(layout: InstallLayout) -> str:
    digest = hashlib.sha256()
    digest.update(bytes.fromhex(_source_tree_digest(layout.plugin_source)))
    digest.update(bytes.fromhex(file_digest(layout.marketplace_source)))
    digest.update(bytes.fromhex(file_digest(layout.catalog_source)))
    digest.update(bytes.fromhex(file_digest(layout.highfd_source)))
    return digest.hexdigest()


def _source_tree_digest(root: Path) -> str:
    if not root.is_dir() or root.is_symlink():
        raise InstallError(
            "ARTIFACT_UNAVAILABLE",
            f"нет безопасного исходного каталога: {root}",
        )
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative_path = path.relative_to(root)
        if (
            any(part in _EXCLUDED_TREE_NAMES for part in relative_path.parts)
            or path.suffix == ".pyc"
        ):
            continue
        relative = relative_path.as_posix()
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            kind = b"d"
            value = b""
        elif stat.S_ISREG(info.st_mode):
            kind = b"x" if info.st_mode & stat.S_IXUSR else b"f"
            value = bytes.fromhex(file_digest(path))
        else:
            raise InstallError(
                "UNSAFE_SOURCE_TREE",
                f"исходник содержит ссылку или особый файл: {path}",
            )
        digest.update(kind)
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(value)
    return digest.hexdigest()


def _create_backup(layout: InstallLayout) -> dict[str, Any]:
    _prepare_private_directory(layout.backups_root)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = (
        layout.backups_root
        / f"{stamp}-{secrets.token_hex(6)}"
    )
    _prepare_private_directory(directory)
    if layout.config_path.is_symlink():
        raise InstallError(
            "UNSAFE_CONFIG",
            f"config.toml не должен быть ссылкой: {layout.config_path}",
        )
    if layout.config_path.exists():
        if not layout.config_path.is_file():
            raise InstallError(
                "UNSAFE_CONFIG",
                f"config.toml не является обычным файлом: {layout.config_path}",
            )
        target = directory / "config.toml"
        shutil.copy2(layout.config_path, target)
        os.chmod(target, 0o600)
        backup: dict[str, Any] = {
            "directory": str(directory),
            "configExisted": True,
            "config": str(target),
            "configSha256": file_digest(target),
        }
    else:
        marker = directory / "config.absent"
        _atomic_write(marker, b"", mode=0o600)
        backup = {
            "directory": str(directory),
            "configExisted": False,
            "config": "",
            "configSha256": "",
        }
    backup["highfd"] = _backup_highfd(layout, directory)
    return backup


def _install_owned_tree(layout: InstallLayout) -> None:
    stage_parent = layout.owned_root.parent
    _prepare_private_directory(stage_parent, create=False)
    stage = Path(
        tempfile.mkdtemp(
            prefix=f".{INSTALLATION_NAME}.stage-",
            dir=stage_parent,
        )
    )
    os.chmod(stage, 0o700)
    published = False
    try:
        marketplace = stage / "marketplace"
        plugins = marketplace / "plugins"
        _prepare_private_directory(marketplace)
        _prepare_private_directory(plugins)
        _prepare_private_directory(
            marketplace / ".agents" / "plugins"
        )
        shutil.copy2(
            layout.marketplace_source,
            marketplace / ".agents" / "plugins" / "marketplace.json",
        )
        _copy_private_tree(
            layout.plugin_source,
            plugins / PLUGIN_NAME,
        )
        canonical_catalog = (
            plugins
            / PLUGIN_NAME
            / "config"
            / "adaptive-subagents.toml"
        )
        shutil.copy2(layout.catalog_source, canonical_catalog)
        _normalize_private_tree(stage)
        os.replace(stage, layout.owned_root)
        published = True
        _fsync_directory(stage_parent)
    except BaseException:
        if stage.exists():
            shutil.rmtree(stage)
        if (
            published
            and layout.owned_root.is_dir()
            and not layout.owned_root.is_symlink()
        ):
            _make_tree_removable(layout.owned_root)
            shutil.rmtree(layout.owned_root)
        raise


def _copy_private_tree(source: Path, target: Path) -> None:
    if target.exists():
        raise InstallError(
            "TARGET_OWNERSHIP_CONFLICT",
            f"цель копирования уже существует: {target}",
        )
    target.mkdir(mode=0o700)
    for child in sorted(source.iterdir(), key=lambda item: item.name):
        if child.name in _EXCLUDED_TREE_NAMES or child.suffix == ".pyc":
            continue
        info = child.lstat()
        destination = target / child.name
        if stat.S_ISDIR(info.st_mode):
            _copy_private_tree(child, destination)
        elif stat.S_ISREG(info.st_mode):
            shutil.copy2(child, destination)
        else:
            raise InstallError(
                "UNSAFE_SOURCE_TREE",
                f"исходник содержит ссылку или особый файл: {child}",
            )


def _normalize_private_tree(root: Path) -> None:
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            os.chmod(path, 0o700)
        elif stat.S_ISREG(info.st_mode):
            executable = bool(info.st_mode & stat.S_IXUSR)
            os.chmod(path, 0o700 if executable else 0o600)
        else:
            raise InstallError(
                "UNSAFE_SOURCE_TREE",
                f"установочное дерево содержит особый файл: {path}",
            )


def _seal_private_tree(root: Path) -> None:
    for path in sorted(
        root.rglob("*"),
        key=lambda item: (len(item.parts), item.as_posix()),
        reverse=True,
    ):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            os.chmod(path, 0o500)
        elif stat.S_ISREG(info.st_mode):
            executable = bool(info.st_mode & stat.S_IXUSR)
            os.chmod(path, 0o500 if executable else 0o400)
        else:
            raise InstallError(
                "UNSAFE_SOURCE_TREE",
                f"установочное дерево содержит особый файл: {path}",
            )
    os.chmod(root, 0o500)


def _make_tree_removable(root: Path) -> None:
    if not root.is_dir() or root.is_symlink():
        return
    os.chmod(root, 0o700)
    for path in root.rglob("*"):
        if path.is_dir() and not path.is_symlink():
            os.chmod(path, 0o700)


def _install_launcher(layout: InstallLayout) -> None:
    _install_managed_link(
        path=layout.launcher_path,
        target=layout.launcher_target,
        label="оболочка",
    )


def _install_admin(layout: InstallLayout) -> None:
    _install_managed_link(
        path=layout.admin_path,
        target=layout.admin_target,
        label="административная команда",
    )


def _install_managed_link(
    *,
    path: Path,
    target: Path,
    label: str,
) -> None:
    if os.path.lexists(path):
        raise InstallError(
            "TARGET_OWNERSHIP_CONFLICT",
            f"{label} уже существует: {path}",
        )
    if not target.is_file() or not os.access(target, os.X_OK):
        raise InstallError(
            "LAUNCHER_TARGET_INVALID",
            f"нет исполняемой цели {label}: {target}",
        )
    created = False
    try:
        os.symlink(str(target), path)
        created = True
        _fsync_directory(path.parent)
    except FileExistsError as exc:
        raise InstallError(
            "TARGET_OWNERSHIP_CONFLICT",
            f"{label} появился во время установки: {path}",
        ) from exc
    except BaseException:
        if (
            created
            and path.is_symlink()
            and os.readlink(path) == str(target)
        ):
            path.unlink()
        raise


def _install_highfd(layout: InstallLayout) -> None:
    _atomic_write(
        layout.highfd_path,
        layout.highfd_source.read_bytes(),
        mode=0o755,
    )


def _build_manifest(
    layout: InstallLayout,
    *,
    version: str,
    source_digest: str,
    backup: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schemaVersion": SCHEMA_VERSION,
        "installation": INSTALLATION_NAME,
        "pluginId": PLUGIN_ID,
        "marketplaceName": MARKETPLACE_NAME,
        "release": json.loads(
            (
                layout.installed_plugin_root
                / ".codex-plugin"
                / "plugin.json"
            ).read_text(encoding="utf-8")
        )["version"],
        "installedAt": datetime.now(timezone.utc).isoformat(),
        "codexVersion": version,
        "codexBinary": str(layout.codex_binary.resolve()),
        "codexHome": str(layout.codex_home),
        "sourceRoot": str(layout.source_root),
        "sourceDigest": source_digest,
        "backup": dict(backup),
        "artifacts": {
            "ownedTree": {
                "path": str(layout.owned_root),
                "sha256": tree_digest(layout.owned_root),
            },
            "launcher": {
                "path": str(layout.launcher_path),
                "target": os.readlink(layout.launcher_path),
                "targetSha256": file_digest(layout.launcher_target),
            },
            "admin": {
                "path": str(layout.admin_path),
                "target": os.readlink(layout.admin_path),
                "targetSha256": file_digest(layout.admin_target),
            },
            "highfd": {
                "path": str(layout.highfd_path),
                "sha256": file_digest(layout.highfd_path),
            },
        },
    }


def _cleanup_failed_install(
    layout: InstallLayout,
    *,
    backup: Mapping[str, Any],
    installed_plugin: bool,
    installed_marketplace: bool,
    installed_owned_tree: bool,
    installed_launcher: bool,
    installed_admin: bool,
    highfd_install_attempted: bool,
    installed_manifest: bool,
    extra_environment: Mapping[str, str] | None,
) -> None:
    if installed_plugin:
        _codex_best_effort(
            layout,
            ["plugin", "remove", PLUGIN_ID, "--json"],
            extra_environment,
        )
    if installed_marketplace:
        _codex_best_effort(
            layout,
            [
                "plugin",
                "marketplace",
                "remove",
                MARKETPLACE_NAME,
                "--json",
            ],
            extra_environment,
        )
    if installed_launcher:
        _remove_exact_managed_link(
            layout.launcher_path,
            layout.launcher_target,
        )
    if installed_admin:
        _remove_exact_managed_link(
            layout.admin_path,
            layout.admin_target,
        )
    if (
        installed_owned_tree
        and layout.owned_root.is_dir()
        and not layout.owned_root.is_symlink()
    ):
        _make_tree_removable(layout.owned_root)
        shutil.rmtree(layout.owned_root)
    if (
        installed_manifest
        and layout.manifest_path.is_file()
        and not layout.manifest_path.is_symlink()
    ):
        layout.manifest_path.unlink()
    if highfd_install_attempted:
        _restore_highfd_after_failed_install(layout, backup)
    _restore_config_backup(layout, backup)


def _remove_exact_managed_link(path: Path, target: Path) -> None:
    if not path.is_symlink():
        return
    if os.readlink(path) != str(target):
        return
    path.unlink()


def _restore_highfd_after_failed_install(
    layout: InstallLayout,
    backup: Mapping[str, Any],
) -> None:
    prior = backup.get("highfd")
    if not isinstance(prior, Mapping):
        raise InstallError(
            "BACKUP_FINGERPRINT_MISMATCH",
            "в резервной копии нет сведений о codex-highfd",
        )
    current_matches_installed = (
        layout.highfd_path.is_file()
        and not layout.highfd_path.is_symlink()
        and file_digest(layout.highfd_path)
        == file_digest(layout.highfd_source)
    )
    if current_matches_installed:
        _restore_highfd_backup(layout, backup)
        return
    if prior.get("existed") is True:
        prior_mode = prior.get("mode")
        if (
            layout.highfd_path.is_file()
            and not layout.highfd_path.is_symlink()
            and file_digest(layout.highfd_path) == prior.get("sha256")
            and type(prior_mode) is int
            and stat.S_IMODE(layout.highfd_path.stat().st_mode) == prior_mode
        ):
            return
    elif not os.path.lexists(layout.highfd_path):
        return
    raise InstallError(
        "TARGET_OWNERSHIP_CONFLICT",
        "codex-highfd изменился во время аварийной очистки",
    )


def _restore_config_backup(
    layout: InstallLayout,
    backup: Mapping[str, Any],
) -> None:
    if backup.get("configExisted") is True:
        path = Path(str(backup["config"]))
        if file_digest(path) != backup.get("configSha256"):
            raise InstallError(
                "BACKUP_FINGERPRINT_MISMATCH",
                f"резервная копия изменена: {path}",
            )
        expected = path.read_bytes()
        if layout.config_path.is_symlink():
            raise InstallError(
                "CONFIG_CHANGED_DURING_CLEANUP",
                "config.toml стал символической ссылкой",
            )
        if not layout.config_path.exists():
            _atomic_write(
                layout.config_path,
                expected,
                mode=0o600,
            )
            return
        if not layout.config_path.is_file():
            raise InstallError(
                "CONFIG_CHANGED_DURING_CLEANUP",
                "config.toml перестал быть обычным файлом",
            )
        if layout.config_path.read_bytes() != expected:
            raise InstallError(
                "CONFIG_CHANGED_DURING_CLEANUP",
                (
                    "config.toml изменился параллельно; "
                    "резервная копия не применена поверх новых данных"
                ),
            )
        return
    if layout.config_path.is_symlink():
        raise InstallError(
            "CONFIG_CHANGED_DURING_CLEANUP",
            "config.toml стал символической ссылкой",
        )
    if not layout.config_path.exists():
        return
    if not layout.config_path.is_file():
        raise InstallError(
            "CONFIG_CHANGED_DURING_CLEANUP",
            "config.toml перестал быть обычным файлом",
        )
    if not layout.config_path.read_bytes().strip():
        layout.config_path.unlink()
        return
    raise InstallError(
        "CONFIG_CHANGED_DURING_CLEANUP",
        (
            "после установки появился непустой config.toml; "
            "он сохранён для ручной проверки"
        ),
    )


def _verify_preexisting_highfd(layout: InstallLayout) -> None:
    if not os.path.lexists(layout.highfd_path):
        return
    if layout.highfd_path.is_symlink() or not layout.highfd_path.is_file():
        raise InstallError(
            "TARGET_OWNERSHIP_CONFLICT",
            f"codex-highfd не является обычным файлом: {layout.highfd_path}",
        )
    digest = file_digest(layout.highfd_path)
    allowed = {
        file_digest(layout.highfd_source),
        LEGACY_HIGHFD_SHA256,
        UNGUARDED_HIGHFD_SHA256,
    }
    if digest not in allowed:
        raise InstallError(
            "TARGET_OWNERSHIP_CONFLICT",
            (
                "codex-highfd имеет неизвестный отпечаток и не будет "
                f"перезаписан: {layout.highfd_path}"
            ),
        )


def _backup_highfd(
    layout: InstallLayout,
    directory: Path,
) -> dict[str, Any]:
    if not os.path.lexists(layout.highfd_path):
        marker = directory / "codex-highfd.absent"
        _atomic_write(marker, b"", mode=0o600)
        return {
            "existed": False,
            "path": "",
            "sha256": "",
            "mode": 0,
        }
    _verify_preexisting_highfd(layout)
    target = directory / "codex-highfd"
    shutil.copy2(layout.highfd_path, target)
    os.chmod(target, 0o600)
    return {
        "existed": True,
        "path": str(target),
        "sha256": file_digest(target),
        "mode": stat.S_IMODE(layout.highfd_path.stat().st_mode),
    }


def _restore_highfd_backup(
    layout: InstallLayout,
    backup: Mapping[str, Any],
) -> None:
    prior = backup.get("highfd")
    if not isinstance(prior, Mapping):
        raise InstallError(
            "BACKUP_FINGERPRINT_MISMATCH",
            "в резервной копии нет сведений о codex-highfd",
        )
    if prior.get("existed") is True:
        path = Path(str(prior.get("path", "")))
        if file_digest(path) != prior.get("sha256"):
            raise InstallError(
                "BACKUP_FINGERPRINT_MISMATCH",
                f"резервная копия codex-highfd изменена: {path}",
            )
        mode = prior.get("mode")
        if type(mode) is not int or mode & ~0o777:
            raise InstallError(
                "BACKUP_FINGERPRINT_MISMATCH",
                "неверный режим прежнего codex-highfd",
            )
        _atomic_write(layout.highfd_path, path.read_bytes(), mode=mode)
    elif os.path.lexists(layout.highfd_path):
        if layout.highfd_path.is_symlink():
            layout.highfd_path.unlink()
        elif layout.highfd_path.is_file():
            layout.highfd_path.unlink()
        else:
            raise InstallError(
                "TARGET_OWNERSHIP_CONFLICT",
                f"небезопасная цель codex-highfd: {layout.highfd_path}",
            )


def _probe_version(
    layout: InstallLayout,
    extra_environment: Mapping[str, str] | None,
) -> str:
    result = _run_process(
        [str(layout.codex_binary), "--version"],
        _command_environment(layout, extra_environment),
        timeout=10,
    )
    if result.returncode != 0:
        raise InstallError(
            "CODEX_VERSION_PROBE_FAILED",
            _bounded_error(result),
        )
    match = _VERSION_PATTERN.fullmatch(result.stdout)
    if match is None:
        raise InstallError(
            "CODEX_VERSION_OUTPUT_INVALID",
            f"неожиданный ответ: {result.stdout[:200]!r}",
        )
    return match.group(1)


def _list_marketplaces(
    layout: InstallLayout,
    extra_environment: Mapping[str, str] | None,
) -> list[dict[str, Any]]:
    document = _codex_json(
        layout,
        ["plugin", "marketplace", "list", "--json"],
        "CODEX_MARKETPLACE_LIST_FAILED",
        extra_environment,
    )
    value = document.get("marketplaces")
    if not isinstance(value, list) or not all(
        isinstance(item, dict) for item in value
    ):
        raise InstallError(
            "CODEX_MARKETPLACE_LIST_INVALID",
            "Codex вернул неверный список рынков",
        )
    return value


def _list_plugins(
    layout: InstallLayout,
    extra_environment: Mapping[str, str] | None,
) -> list[dict[str, Any]]:
    document = _codex_json(
        layout,
        ["plugin", "list", "--json"],
        "CODEX_PLUGIN_LIST_FAILED",
        extra_environment,
    )
    value = document.get("installed")
    if not isinstance(value, list) or not all(
        isinstance(item, dict) for item in value
    ):
        raise InstallError(
            "CODEX_PLUGIN_LIST_INVALID",
            "Codex вернул неверный список расширений",
        )
    return value


def _codex_json(
    layout: InstallLayout,
    arguments: Sequence[str],
    error_code: str,
    extra_environment: Mapping[str, str] | None,
) -> dict[str, Any]:
    result = _run_process(
        [str(layout.codex_binary), *arguments],
        _command_environment(layout, extra_environment),
        timeout=30,
    )
    if result.returncode != 0:
        raise InstallError(error_code, _bounded_error(result))
    try:
        document = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise InstallError(
            error_code,
            f"Codex вернул не-JSON: {result.stdout[:500]!r}",
        ) from exc
    if not isinstance(document, dict):
        raise InstallError(error_code, "Codex вернул JSON не в виде объекта")
    return document


def _codex_best_effort(
    layout: InstallLayout,
    arguments: Sequence[str],
    extra_environment: Mapping[str, str] | None,
) -> None:
    try:
        _run_process(
            [str(layout.codex_binary), *arguments],
            _command_environment(layout, extra_environment),
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return


def _run_process(
    arguments: Sequence[str],
    environment: Mapping[str, str],
    *,
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(arguments),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=dict(environment),
            timeout=timeout,
            check=False,
            shell=False,
            close_fds=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise InstallError(
            "PROCESS_START_FAILED",
            f"не удалось выполнить {arguments[0]}: {exc}",
        ) from exc


def _command_environment(
    layout: InstallLayout,
    extra: Mapping[str, str] | None,
    *,
    include_runtime: bool = False,
) -> dict[str, str]:
    environment: dict[str, str] = {
        "CODEX_HOME": str(layout.codex_home),
        "HOME": os.environ.get("HOME", str(Path.home())),
        "PATH": os.environ.get(
            "PATH",
            "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin",
        ),
        "LANG": "C",
        "LC_ALL": "C",
    }
    if "TMPDIR" in os.environ:
        environment["TMPDIR"] = os.environ["TMPDIR"]
    if include_runtime:
        state_home = layout.codex_home / "adaptive-subagents-smoke-state"
        _prepare_private_directory(state_home)
        environment.update(
            {
                "CODEX_REAL_BIN": str(layout.codex_binary),
                "CODEX_ADAPTIVE_CATALOG": str(layout.catalog_path),
                "CODEX_ADAPTIVE_SESSION_ID": "cas1_" + "A" * 43,
                "XDG_STATE_HOME": str(state_home),
                "CODEX_SMART_LAUNCHER": str(layout.launcher_path),
                "CODEX_SMART_ENABLED": "1",
                "CODEX_NOFILE_LIMIT": "64",
            }
        )
    if extra:
        environment.update(extra)
    return environment


def _plugin_source_matches(
    plugin: Mapping[str, Any],
    expected: Path,
) -> bool:
    source = plugin.get("source")
    if not isinstance(source, dict):
        return False
    raw_path = source.get("path")
    if not isinstance(raw_path, str) or not raw_path:
        return False
    return Path(raw_path).expanduser().resolve() == expected


def _mcp_contract_problems(layout: InstallLayout) -> list[dict[str, str]]:
    path = layout.installed_plugin_root / ".mcp.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        server = document["mcpServers"]["codex-smart-subagents"]
        enabled = server["enabled_tools"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError):
        return [
            {
                "code": "MCP_CONTRACT_INVALID",
                "message": f"неверный MCP-контракт: {path}",
            }
        ]
    expected = [
        "smart_plan",
        "smart_start",
        "smart_wait",
        "smart_cancel",
    ]
    if enabled != expected:
        return [
            {
                "code": "MCP_CONTRACT_INVALID",
                "message": f"неожиданный набор инструментов: {enabled!r}",
            }
        ]
    return []


def _doctor_accepts_installed_state(
    diagnosis: Mapping[str, Any],
) -> bool:
    return diagnosis.get("status") in {"READY", "AWAITING_HOOK_TRUST"}


def _hook_trust_report(layout: InstallLayout) -> dict[str, Any]:
    plugin_source = layout.plugin_source / "src"
    if str(plugin_source) not in sys.path:
        sys.path.insert(0, str(plugin_source))
    try:
        from codex_smart_subagents.live_canary import (
            AppServerError,
            StrictAppServerClient,
        )
    except (ImportError, OSError) as exc:
        return _hook_report_failure(
            "HOOK_DISCOVERY_FAILED",
            f"не удалось загрузить строгий клиент app-server: {exc}",
        )

    try:
        with tempfile.TemporaryDirectory(
            prefix="codex-hook-doctor-",
        ) as raw_runtime:
            runtime = Path(raw_runtime)
            os.chmod(runtime, 0o700)
            home = runtime / "home"
            tmpdir = runtime / "tmp"
            cwd = runtime / "cwd"
            for path in (home, tmpdir, cwd):
                path.mkdir(mode=0o700)
            client = StrictAppServerClient(
                codex_executable=layout.codex_binary,
                codex_home=layout.codex_home,
                home=home,
                tmpdir=tmpdir,
                cwd=cwd,
                timeout_seconds=5.0,
                max_output_bytes=1024 * 1024,
                client_name="adaptive_install_doctor",
                client_title="Adaptive Install Doctor",
                client_version="0.1.0",
            )
            result = client.call(
                "hooks/list",
                {"cwds": [str(cwd)]},
            )
    except AppServerError as exc:
        return _hook_report_failure(
            "HOOK_DISCOVERY_FAILED",
            f"{exc.code}: {exc.message}",
        )
    except (OSError, ValueError) as exc:
        return _hook_report_failure(
            "HOOK_DISCOVERY_FAILED",
            str(exc),
        )
    return _parse_hook_list_result(result)


def _parse_hook_list_result(result: object) -> dict[str, Any]:
    if not isinstance(result, dict) or set(result) != {"data"}:
        return _hook_report_failure(
            "HOOK_DISCOVERY_INVALID",
            "hooks/list вернул ответ без единственного поля data",
        )
    data = result["data"]
    if not isinstance(data, list) or len(data) != 1:
        return _hook_report_failure(
            "HOOK_DISCOVERY_INVALID",
            "hooks/list должен вернуть ровно один результат каталога",
        )
    entry = data[0]
    if not isinstance(entry, dict):
        return _hook_report_failure(
            "HOOK_DISCOVERY_INVALID",
            "элемент hooks/list не является объектом",
        )
    errors = entry.get("errors")
    warnings = entry.get("warnings")
    hooks = entry.get("hooks")
    cwd = entry.get("cwd")
    if (
        not isinstance(cwd, str)
        or not isinstance(errors, list)
        or not isinstance(warnings, list)
        or not all(isinstance(item, str) for item in warnings)
        or not isinstance(hooks, list)
        or not all(isinstance(item, dict) for item in hooks)
    ):
        return _hook_report_failure(
            "HOOK_DISCOVERY_INVALID",
            "элемент hooks/list имеет неверные типы полей",
        )
    if errors:
        return {
            **_hook_report_failure(
                "HOOK_DISCOVERY_ERRORS",
                "app-server сообщил ошибки загрузки хуков",
            ),
            "warnings": list(warnings),
        }

    target_hooks = [
        hook for hook in hooks if hook.get("pluginId") == PLUGIN_ID
    ]
    invalid = [
        hook
        for hook in target_hooks
        if not _valid_target_hook_metadata(hook)
    ]
    if invalid:
        return {
            **_hook_report_failure(
                "HOOK_DISCOVERY_INVALID",
                "метаданные хуков расширения неполны или имеют неверный тип",
            ),
            "warnings": list(warnings),
        }

    by_event: dict[str, list[Mapping[str, Any]]] = {
        event_name: [] for event_name in _EXPECTED_HOOK_EVENTS
    }
    unexpected: list[str] = []
    for hook in target_hooks:
        event_name = str(hook["eventName"])
        if event_name not in by_event:
            unexpected.append(event_name)
            continue
        by_event[event_name].append(hook)
    missing = [
        event_name
        for event_name, matches in by_event.items()
        if not matches
    ]
    duplicates = [
        event_name
        for event_name, matches in by_event.items()
        if len(matches) > 1
    ]
    if (
        missing
        or duplicates
        or unexpected
        or len(target_hooks) != len(_EXPECTED_HOOK_EVENTS)
    ):
        details = []
        if missing:
            details.append("нет: " + ", ".join(missing))
        if duplicates:
            details.append("дубли: " + ", ".join(duplicates))
        if unexpected:
            details.append("лишние: " + ", ".join(sorted(unexpected)))
        return {
            **_hook_report_failure(
                "HOOK_LIST_INCOMPLETE",
                "; ".join(details) or "неверное количество хуков",
                status="HOOK_DISCOVERY_INCOMPLETE",
            ),
            "warnings": list(warnings),
        }

    normalized: list[dict[str, Any]] = []
    disabled: list[str] = []
    awaiting: list[str] = []
    for event_name in _EXPECTED_HOOK_EVENTS:
        hook = by_event[event_name][0]
        enabled = bool(hook["enabled"])
        trust_status = str(hook["trustStatus"])
        ready = enabled and trust_status in _TRUSTED_HOOK_STATES
        normalized.append(
            {
                "eventName": event_name,
                "enabled": enabled,
                "trustStatus": trust_status,
                "ready": ready,
                "isManaged": bool(hook["isManaged"]),
                "key": str(hook["key"]),
                "currentHash": str(hook["currentHash"]),
            }
        )
        if not enabled:
            disabled.append(event_name)
        elif not ready:
            awaiting.append(event_name)
    if disabled:
        return {
            "status": "BROKEN",
            "problems": [
                {
                    "code": "HOOK_DISABLED",
                    "message": (
                        "хуки расширения выключены: "
                        + ", ".join(disabled)
                    ),
                }
            ],
            "hooks": normalized,
            "warnings": list(warnings),
        }
    if awaiting:
        return {
            "status": "AWAITING_HOOK_TRUST",
            "problems": [
                {
                    "code": "AWAITING_HOOK_TRUST",
                    "message": (
                        "требуется ручная проверка доверия для: "
                        + ", ".join(awaiting)
                    ),
                }
            ],
            "hooks": normalized,
            "warnings": list(warnings),
        }
    return {
        "status": "READY",
        "problems": [],
        "hooks": normalized,
        "warnings": list(warnings),
    }


def _valid_target_hook_metadata(hook: Mapping[str, Any]) -> bool:
    required = {
        "currentHash",
        "enabled",
        "eventName",
        "handlerType",
        "isManaged",
        "key",
        "pluginId",
        "source",
        "sourcePath",
        "timeoutSec",
        "trustStatus",
    }
    trust_status = hook.get("trustStatus")
    return (
        required.issubset(hook)
        and isinstance(hook.get("currentHash"), str)
        and str(hook["currentHash"]).startswith("sha256:")
        and type(hook.get("enabled")) is bool
        and isinstance(hook.get("eventName"), str)
        and hook.get("handlerType") == "command"
        and type(hook.get("isManaged")) is bool
        and isinstance(hook.get("key"), str)
        and bool(hook["key"])
        and hook.get("pluginId") == PLUGIN_ID
        and hook.get("source") == "plugin"
        and isinstance(hook.get("sourcePath"), str)
        and bool(hook["sourcePath"])
        and type(hook.get("timeoutSec")) is int
        and hook["timeoutSec"] >= 0
        and isinstance(trust_status, str)
        and trust_status in _KNOWN_HOOK_TRUST_STATES
    )


def _hook_report_failure(
    code: str,
    message: str,
    *,
    status: str = "BROKEN",
) -> dict[str, Any]:
    return {
        "status": status,
        "problems": [{"code": code, "message": message}],
        "hooks": [],
        "warnings": [],
    }


def _atomic_write_json(
    path: Path,
    document: Mapping[str, Any],
    *,
    mode: int,
) -> None:
    encoded = (
        json.dumps(
            document,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    _atomic_write(path, encoded, mode=mode)


def _atomic_write(path: Path, data: bytes, *, mode: int) -> None:
    _prepare_private_directory(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        if temporary.exists():
            temporary.unlink()
        raise


def _prepare_private_directory(
    path: Path,
    *,
    create: bool = True,
) -> None:
    if path.is_symlink():
        raise InstallError(
            "UNSAFE_INSTALL_PATH",
            f"каталог не должен быть ссылкой: {path}",
        )
    if create:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(path, 0o700)
    if not path.is_dir():
        raise InstallError(
            "UNSAFE_INSTALL_PATH",
            f"ожидался каталог: {path}",
        )


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _bounded_error(result: subprocess.CompletedProcess[str]) -> str:
    return (
        result.stderr.strip()[:1000]
        or result.stdout.strip()[:1000]
        or f"код завершения {result.returncode}"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-root",
        default=str(Path(__file__).resolve().parents[1]),
    )
    parser.add_argument("--codex-home")
    parser.add_argument("--bin-dir")
    parser.add_argument("--codex-binary", default="codex")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--doctor", action="store_true")
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.doctor and args.smoke:
        parser.error("выберите только один режим: --doctor или --smoke")
    try:
        layout = default_layout(args)
        if args.doctor:
            result = doctor(layout)
        elif args.smoke:
            result = smoke(layout)
        else:
            result = install(layout, apply=args.apply)
            if args.apply and result["status"] == "installed":
                result["doctor"] = doctor(layout)
    except InstallError as exc:
        result = {
            "ok": False,
            "code": exc.code,
            "message": exc.message,
        }
        _print_result(result, as_json=args.json)
        return 1
    _print_result(result, as_json=args.json)
    if result.get("ok") is False:
        return 1
    return 0


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
        return
    if "actions" in result:
        print("\n".join(str(action) for action in result["actions"]))
        return
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(main())
