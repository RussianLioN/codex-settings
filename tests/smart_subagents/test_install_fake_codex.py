#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path


def main() -> int:
    home = Path(os.environ["CODEX_HOME"])
    state_path = home / "fake-plugin-state.json"
    state = load_state(state_path)
    args = sys.argv[1:]
    append_command_log(home, args)
    version = os.environ.get("FAKE_CODEX_VERSION", "0.144.4")
    if args == ["--version"]:
        print(f"codex-cli {version}")
        return 0
    if args[:1] == ["app-server"]:
        return run_app_server(home, version)
    if args[:3] == ["plugin", "marketplace", "list"]:
        print(json.dumps({"marketplaces": state["marketplaces"]}))
        return 0
    if args[:3] == ["plugin", "marketplace", "add"]:
        source = str(Path(args[3]).resolve(strict=True))
        marketplace = json.loads(
            (Path(source) / ".claude-plugin" / "marketplace.json").read_text(
                encoding="utf-8"
            )
        )
        state["marketplaces"] = [
            {
                "name": marketplace["name"],
                "root": source,
                "marketplaceSource": {
                    "sourceType": "local",
                    "source": source,
                },
            }
        ]
        save_state(state_path, state)
        append_config(home, "[marketplaces.codex-settings-adaptive]\n")
        print(json.dumps({"name": marketplace["name"]}))
        return 0
    if args[:3] == ["plugin", "marketplace", "remove"]:
        if os.environ.get("FAKE_CODEX_FAIL_MARKETPLACE_REMOVE") == "1":
            print("synthetic marketplace remove failure", file=sys.stderr)
            return 8
        state["marketplaces"] = []
        save_state(state_path, state)
        remove_config_text(
            home,
            "[marketplaces.codex-settings-adaptive]\n",
        )
        print(json.dumps({"removed": True}))
        return 0
    if args[:2] == ["plugin", "add"]:
        if os.environ.get("FAKE_CODEX_FAIL_PLUGIN_ADD") == "1":
            print("synthetic plugin add failure", file=sys.stderr)
            return 7
        marketplace_root = Path(state["marketplaces"][0]["root"])
        primary_marketplace = json.loads(
            (
                marketplace_root / ".agents" / "plugins" / "marketplace.json"
            ).read_text(encoding="utf-8")
        )
        primary_plugin = primary_marketplace["plugins"][0]
        primary_source = primary_plugin["source"]
        primary_policy = primary_plugin["policy"]
        plugin_root = (marketplace_root / primary_source["path"]).resolve(strict=True)
        plugin_manifest = json.loads(
            (plugin_root / ".codex-plugin" / "plugin.json").read_text(
                encoding="utf-8"
            )
        )
        cache_root = (
            home
            / "plugins"
            / "cache"
            / "codex-settings-adaptive"
            / "codex-smart-subagents"
            / str(plugin_manifest["version"])
        )
        if cache_root.exists() or cache_root.is_symlink():
            remove_tree(cache_root)
        cache_root.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(plugin_root, cache_root)
        state["installed"] = [
            {
                "pluginId": ("codex-smart-subagents@codex-settings-adaptive"),
                "name": primary_plugin["name"],
                "marketplaceName": "codex-settings-adaptive",
                "version": plugin_manifest["version"],
                "installed": True,
                "enabled": True,
                "source": {
                    "source": primary_source["source"],
                    "path": str(plugin_root),
                },
                "marketplaceSource": {
                    "sourceType": "local",
                    "source": str(marketplace_root),
                },
                "installPolicy": primary_policy["installation"],
                "authPolicy": primary_policy["authentication"],
            }
        ]
        save_state(state_path, state)
        append_config(
            home,
            (
                "[plugins."
                '"codex-smart-subagents@codex-settings-adaptive"]\n'
                "enabled = true\n"
            ),
        )
        print(json.dumps({"installed": True}))
        return 0
    if args[:2] == ["plugin", "remove"]:
        cache_parent = (
            home
            / "plugins"
            / "cache"
            / "codex-settings-adaptive"
            / "codex-smart-subagents"
        )
        if cache_parent.exists() or cache_parent.is_symlink():
            remove_tree(cache_parent)
        state["installed"] = []
        save_state(state_path, state)
        remove_config_text(
            home,
            (
                "[plugins."
                '"codex-smart-subagents@codex-settings-adaptive"]\n'
                "enabled = true\n"
            ),
        )
        print(json.dumps({"removed": True}))
        return 0
    if args[:3] == ["plugin", "list", "--json"]:
        print(
            json.dumps(
                {
                    "installed": state["installed"],
                    "available": [],
                }
            )
        )
        return 0
    print(f"unsupported fake codex command: {args!r}", file=sys.stderr)
    return 64


def run_app_server(home: Path, version: str) -> int:
    raw_sqlite_home = os.environ.get("CODEX_SQLITE_HOME")
    if raw_sqlite_home is None:
        print("CODEX_SQLITE_HOME is required", file=sys.stderr)
        return 67
    sqlite_home = Path(raw_sqlite_home)
    if (
        not sqlite_home.is_dir()
        or sqlite_home.is_symlink()
        or sqlite_home.parent != Path(os.environ["TMPDIR"])
    ):
        print("unsafe CODEX_SQLITE_HOME", file=sys.stderr)
        return 68
    (sqlite_home / "state_5.sqlite").write_bytes(b"temporary")
    initialize = json.loads(sys.stdin.readline())
    emit(
        {
            "id": initialize["id"],
            "result": {
                "userAgent": f"fake-codex/{version}",
                "codexHome": str(home),
                "platformFamily": "unix",
                "platformOs": "macos",
            },
        }
    )
    initialized = json.loads(sys.stdin.readline())
    if initialized.get("method") != "initialized":
        return 65
    request = json.loads(sys.stdin.readline())
    if request.get("method") != "hooks/list":
        return 66
    configuration = load_hook_configuration(home)
    if configuration.get("responseMode") == "malformed":
        emit({"id": request["id"], "result": {"unexpected": []}})
        return 0
    hooks = [
        fake_hook(
            "userPromptSubmit",
            str(
                configuration.get("trustStatuses", {}).get(
                    "userPromptSubmit",
                    "trusted",
                )
            ),
        ),
        fake_hook(
            "stop",
            str(
                configuration.get("trustStatuses", {}).get(
                    "stop",
                    "trusted",
                )
            ),
        ),
    ]
    events = configuration.get("events")
    if isinstance(events, list):
        hooks = [hook for hook in hooks if hook["eventName"] in events]
    duplicate = configuration.get("duplicateEvent")
    if isinstance(duplicate, str):
        matching = [hook for hook in hooks if hook["eventName"] == duplicate]
        if matching:
            hooks.append(dict(matching[0]))
    for hook in hooks:
        disabled = configuration.get("disabledEvents", [])
        if isinstance(disabled, list) and hook["eventName"] in disabled:
            hook["enabled"] = False
    cwds = request.get("params", {}).get("cwds", [])
    cwd = cwds[0] if isinstance(cwds, list) and cwds else os.getcwd()
    emit(
        {
            "id": request["id"],
            "result": {
                "data": [
                    {
                        "cwd": cwd,
                        "errors": configuration.get("errors", []),
                        "hooks": hooks,
                        "warnings": configuration.get("warnings", []),
                    }
                ]
            },
        }
    )
    return 0


def fake_hook(event_name: str, trust_status: str) -> dict[str, object]:
    suffix = (
        "user_prompt_submit:0:0" if event_name == "userPromptSubmit" else "stop:0:0"
    )
    return {
        "command": "fake-hook",
        "currentHash": "sha256:" + "a" * 64,
        "displayOrder": 0 if event_name == "userPromptSubmit" else 1,
        "enabled": True,
        "eventName": event_name,
        "handlerType": "command",
        "isManaged": trust_status == "managed",
        "key": (
            f"codex-smart-subagents@codex-settings-adaptive:hooks/hooks.json:{suffix}"
        ),
        "matcher": None,
        "pluginId": "codex-smart-subagents@codex-settings-adaptive",
        "source": "plugin",
        "sourcePath": str(
            Path(os.environ["CODEX_HOME"])
            / "plugins"
            / "cache"
            / "codex-settings-adaptive"
            / "codex-smart-subagents"
            / "0.2.0"
            / "hooks"
            / "hooks.json"
        ),
        "statusMessage": "fake",
        "timeoutSec": 2,
        "trustStatus": trust_status,
    }


def remove_tree(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
        return
    for child in sorted(path.rglob("*"), reverse=True):
        if child.is_symlink() or child.is_file():
            child.chmod(0o600)
        elif child.is_dir():
            child.chmod(0o700)
    path.chmod(0o700)
    shutil.rmtree(path)


def load_hook_configuration(home: Path) -> dict[str, object]:
    path = home / "fake-hook-state.json"
    if not path.is_file():
        return {}
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("fake hook configuration must be an object")
    return document


def emit(value: object) -> None:
    print(json.dumps(value, separators=(",", ":")), flush=True)


def load_state(path: Path) -> dict[str, list[object]]:
    if not path.is_file():
        return {"marketplaces": [], "installed": []}
    return json.loads(path.read_text(encoding="utf-8"))


def save_state(path: Path, state: dict[str, list[object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state), encoding="utf-8")


def append_command_log(home: Path, arguments: list[str]) -> None:
    path = home / "fake-command-log.jsonl"
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(arguments, separators=(",", ":")) + "\n")


def append_config(home: Path, text: str) -> None:
    path = home / "config.toml"
    with path.open("a", encoding="utf-8") as stream:
        stream.write(text)


def remove_config_text(home: Path, text: str) -> None:
    path = home / "config.toml"
    if not path.is_file():
        return
    current = path.read_text(encoding="utf-8")
    path.write_text(current.replace(text, ""), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
