from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "scripts" / "codex_process_inventory.py"
NODE_REPL = "/Applications/ChatGPT.app/Contents/Resources/cua_node/bin/node_repl"


def load_inventory() -> ModuleType:
    spec = importlib.util.spec_from_file_location("codex_process_inventory", INVENTORY)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {INVENTORY}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def process(
    pid: int,
    ppid: int,
    command: str,
    *,
    started_epoch: float = 900.0,
    executable: str | None = None,
) -> dict[str, object]:
    return {
        "pid": pid,
        "ppid": ppid,
        "uid": 501,
        "user": "operator",
        "started_epoch": started_epoch,
        "executable": executable or command.split()[0],
        "command": command,
    }


class ProcessInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.inventory = load_inventory()

    def classify(
        self,
        rows: list[dict[str, object]],
        *,
        caller_pid: int,
        existing_paths: set[str] | None = None,
    ) -> dict[str, object]:
        existing = existing_paths or {NODE_REPL, "/opt/homebrew/bin/codex"}
        return self.inventory.classify_snapshot(
            rows,
            caller_pid=caller_pid,
            now_epoch=1_000.0,
            executable_exists=lambda path: path in existing,
        )

    def test_one_codex_root_with_twenty_one_intermediate_descendants_is_attached(
        self,
    ) -> None:
        rows = [
            process(100, 1, "/opt/homebrew/bin/codex"),
            process(101, 100, "/bin/zsh worker"),
            process(102, 101, "python3 doctor"),
        ]
        for index in range(21):
            rows.append(process(200 + index, 101, f"{NODE_REPL} --worker {index}", executable=NODE_REPL))

        summary = self.classify(rows, caller_pid=102)

        self.assertEqual(1, summary["root_counts"]["managed_codex_cli"])
        self.assertEqual(21, summary["node_repl_states"]["attached"])
        self.assertEqual(21, summary["node_repl_total"])
        self.assertEqual("unknown", summary["max_expected_node_repl_processes"])

    def test_four_codex_roots_with_eighty_one_node_repl_are_not_an_orphan_leak(
        self,
    ) -> None:
        rows: list[dict[str, object]] = [process(900, 100, "python3 doctor")]
        for root_index in range(4):
            root_pid = 100 + root_index
            rows.append(process(root_pid, 1, f"/opt/homebrew/bin/codex tab-{root_index}"))
        for index in range(81):
            owner = 100 + index % 4
            rows.append(process(1_000 + index, owner, f"{NODE_REPL} {index}", executable=NODE_REPL))

        summary = self.classify(rows, caller_pid=900)

        self.assertEqual(4, summary["root_counts"]["codex_cli"])
        self.assertEqual(81, summary["node_repl_states"]["attached"])
        self.assertEqual(0, summary["node_repl_states"]["confirmed_orphan"])

    def test_chatgpt_and_app_server_descendants_are_external(self) -> None:
        rows = [
            process(100, 1, "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT"),
            process(101, 100, f"{NODE_REPL} chatgpt", executable=NODE_REPL),
            process(200, 1, "/opt/homebrew/bin/codex app-server"),
            process(201, 200, f"{NODE_REPL} server", executable=NODE_REPL),
            process(300, 1, "/opt/homebrew/bin/codex"),
            process(301, 300, "python3 doctor"),
        ]

        summary = self.classify(rows, caller_pid=301)

        self.assertEqual(2, summary["node_repl_states"]["external"])
        self.assertEqual(1, summary["root_counts"]["chatgpt"])
        self.assertEqual(1, summary["root_counts"]["app_server"])

    def test_recent_missing_parent_is_only_an_orphan_candidate(self) -> None:
        rows = [
            process(100, 1, "/opt/homebrew/bin/codex"),
            process(101, 100, "python3 doctor"),
            process(200, 999, f"{NODE_REPL} recent", started_epoch=980.0, executable=NODE_REPL),
        ]

        summary = self.classify(rows, caller_pid=101)

        self.assertEqual(1, summary["node_repl_states"]["orphan_candidate"])
        self.assertEqual(0, summary["node_repl_states"]["confirmed_orphan"])

    def test_old_init_child_is_a_confirmed_orphan(self) -> None:
        rows = [
            process(100, 1, "/opt/homebrew/bin/codex"),
            process(101, 100, "python3 doctor"),
            process(200, 1, f"{NODE_REPL} old", started_epoch=100.0, executable=NODE_REPL),
        ]

        summary = self.classify(rows, caller_pid=101)

        self.assertEqual(1, summary["node_repl_states"]["confirmed_orphan"])

    def test_parent_pid_reused_after_child_start_is_not_treated_as_owner(self) -> None:
        rows = [
            process(100, 1, "/opt/homebrew/bin/codex", started_epoch=950.0),
            process(101, 100, "python3 doctor", started_epoch=960.0),
            process(200, 100, f"{NODE_REPL} old-child", started_epoch=900.0, executable=NODE_REPL),
        ]

        summary = self.classify(rows, caller_pid=101)

        self.assertEqual(1, summary["node_repl_states"]["orphan_candidate"])
        self.assertEqual(0, summary["node_repl_states"]["attached"])

    def test_missing_exact_executable_is_stale_path(self) -> None:
        rows = [
            process(100, 1, "/opt/homebrew/bin/codex"),
            process(101, 100, "python3 doctor"),
            process(200, 100, "/old/node_repl worker", executable="/old/node_repl"),
        ]

        summary = self.classify(
            rows,
            caller_pid=101,
            existing_paths={"/opt/homebrew/bin/codex"},
        )

        self.assertEqual(1, summary["node_repl_states"]["stale_path"])


if __name__ == "__main__":
    unittest.main()
