from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from copy import deepcopy


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.canonical_json import domain_fingerprint  # noqa: E402
from codex_smart_subagents.mcp_contracts_v2 import (  # noqa: E402
    get_tool_definitions_v2,
)
from codex_smart_subagents.mcp_server_v2 import (  # noqa: E402
    MCP_PROTOCOL,
    SERVER_NAME,
    SERVER_VERSION,
)

MODULE_NAME = "codex_smart_subagents.mcp_runtime_proof_v2"
PLUGIN_ID = "codex-smart-subagents@codex-settings-adaptive"
SERVER_ID = "codex-smart-subagents"
REQUIRED_TOOLS = (
    "smart_plan",
    "route_start",
    "smart_wait",
    "smart_cancel",
)
TOOL_DEFINITIONS = get_tool_definitions_v2()


class MCPRuntimeProofV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            dir="/tmp",
            prefix="cmrp2-",
        )
        self.root = Path(self.temporary.name).resolve()
        self.codex_home = self.root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        self.config_path = self.codex_home / "config.toml"
        self.state_home = self.codex_home / "state" / "codex-smart-subagents-v2"
        self.state_home.mkdir(parents=True, mode=0o700)
        self.environment = {
            "CODEX_HOME": str(self.codex_home),
            "CODEX_ADAPTIVE_SESSION_ID": "cas2_" + "a" * 32,
            "CODEX_SMART_STATE_HOME": str(self.state_home),
            "CODEX_SMART_ACTIVATION_ID": "act2_" + "b" * 64,
            "CODEX_SMART_GATE_FINGERPRINT": "c" * 64,
            "CODEX_SMART_MCP_SESSION_NONCE": "mcpn2_" + "d" * 64,
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _module(self):
        self.assertIsNotNone(
            importlib.util.find_spec(MODULE_NAME),
            "нужен общий модуль доказательства политики и MCP",
        )
        return importlib.import_module(MODULE_NAME)

    def _write_policy(
        self,
        *,
        plugin_enabled: object = True,
        server_overlay: str | None = None,
    ) -> bytes:
        if server_overlay is None:
            server_overlay = ""
        source = (
            f'[plugins."{PLUGIN_ID}"]\n'
            f"enabled = {str(plugin_enabled).lower()}\n"
            f"{server_overlay}"
        ).encode("utf-8")
        self.config_path.write_bytes(source)
        self.config_path.chmod(0o600)
        return source

    def test_normal_policy_proof_binds_raw_hash_identity_and_projection(self) -> None:
        module = self._module()
        raw = self._write_policy()

        encoded = module.build_user_mcp_policy_proof_v2(self.codex_home)
        proof = json.loads(encoded)
        info = self.config_path.stat()

        self.assertEqual(2, proof["schemaVersion"])
        self.assertEqual("codex-user-mcp-policy-v2", proof["proofKind"])
        self.assertEqual(str(self.config_path), proof["configPath"])
        self.assertEqual(hashlib.sha256(raw).hexdigest(), proof["rawSha256"])
        self.assertEqual(
            {
                "device": str(info.st_dev),
                "inode": str(info.st_ino),
                "size": str(info.st_size),
                "mtimeNs": str(info.st_mtime_ns),
            },
            proof["fileIdentity"],
        )
        self.assertEqual(
            {
                "pluginId": PLUGIN_ID,
                "pluginEnabled": True,
                "serverId": SERVER_ID,
                "serverOverlayPresent": False,
                "serverEnabled": None,
                "enabledTools": None,
                "disabledTools": None,
                "defaultToolsApprovalMode": "approve",
                "toolApprovalModes": {
                    name: "approve" for name in REQUIRED_TOOLS
                },
                "requiredTools": list(REQUIRED_TOOLS),
            },
            proof["policy"],
        )
        self.assertRegex(proof["proofFingerprint"], r"^[0-9a-f]{64}$")
        module.verify_user_mcp_policy_proof_v2(self.codex_home, encoded)

    def test_policy_rejects_disabled_plugin_or_server(self) -> None:
        module = self._module()
        cases = (
            (False, "", "plugin-disabled"),
            (
                True,
                f'\n[plugins."{PLUGIN_ID}".mcp_servers."{SERVER_ID}"]\n'
                "enabled = false\n"
                'default_tools_approval_mode = "approve"\n',
                "server-disabled",
            ),
        )
        for plugin_enabled, overlay, label in cases:
            with self.subTest(label=label):
                self._write_policy(
                    plugin_enabled=plugin_enabled,
                    server_overlay=overlay,
                )
                with self.assertRaises(module.MCPRuntimeProofV2Error) as caught:
                    module.build_user_mcp_policy_proof_v2(self.codex_home)
                self.assertEqual("USER_MCP_POLICY_UNPROVED", caught.exception.code)

    def test_policy_rejects_allowlist_without_smart_plan(self) -> None:
        module = self._module()
        self._write_policy(
            server_overlay=(
                f'\n[plugins."{PLUGIN_ID}".mcp_servers."{SERVER_ID}"]\n'
                'enabled_tools = ["route_start", "smart_wait", "smart_cancel"]\n'
                'default_tools_approval_mode = "approve"\n'
            )
        )

        with self.assertRaises(module.MCPRuntimeProofV2Error) as caught:
            module.build_user_mcp_policy_proof_v2(self.codex_home)

        self.assertEqual("USER_MCP_POLICY_UNPROVED", caught.exception.code)

        self._write_policy(
            server_overlay=(
                f'\n[plugins."{PLUGIN_ID}".mcp_servers."{SERVER_ID}"]\n'
                'enabled_tools = ["smart_plan", "route_start", "smart_wait", '
                '"smart_cancel", "unrelated_tool"]\n'
                'default_tools_approval_mode = "approve"\n'
            )
        )
        with self.assertRaises(module.MCPRuntimeProofV2Error):
            module.build_user_mcp_policy_proof_v2(self.codex_home)

    def test_policy_rejects_denylist_with_smart_plan(self) -> None:
        module = self._module()
        self._write_policy(
            server_overlay=(
                f'\n[plugins."{PLUGIN_ID}".mcp_servers."{SERVER_ID}"]\n'
                'disabled_tools = ["smart_plan"]\n'
                'default_tools_approval_mode = "approve"\n'
            )
        )

        with self.assertRaises(module.MCPRuntimeProofV2Error) as caught:
            module.build_user_mcp_policy_proof_v2(self.codex_home)

        self.assertEqual("USER_MCP_POLICY_UNPROVED", caught.exception.code)

        self._write_policy(
            server_overlay=(
                f'\n[plugins."{PLUGIN_ID}".mcp_servers."{SERVER_ID}"]\n'
                'disabled_tools = ["unrelated_tool"]\n'
                'default_tools_approval_mode = "approve"\n'
            )
        )
        with self.assertRaises(module.MCPRuntimeProofV2Error):
            module.build_user_mcp_policy_proof_v2(self.codex_home)

    def test_policy_accepts_explicit_approve_and_effective_inheritance(self) -> None:
        module = self._module()
        overlay = (
            f'\n[plugins."{PLUGIN_ID}".mcp_servers."{SERVER_ID}"]\n'
            'enabled_tools = ["smart_cancel", "smart_wait", "route_start", '
            '"smart_plan"]\n'
            "disabled_tools = []\n"
            'default_tools_approval_mode = "approve"\n'
            f'\n[plugins."{PLUGIN_ID}".mcp_servers."{SERVER_ID}".tools.smart_plan]\n'
            'approval_mode = "approve"\n'
            f'\n[plugins."{PLUGIN_ID}".mcp_servers."{SERVER_ID}".tools.route_start]\n'
            'approval_mode = "approve"\n'
        )
        self._write_policy(server_overlay=overlay)

        proof = json.loads(
            module.build_user_mcp_policy_proof_v2(self.codex_home)
        )

        self.assertEqual("approve", proof["policy"]["defaultToolsApprovalMode"])
        self.assertEqual(
            {
                "smart_plan": "approve",
                "route_start": "approve",
                "smart_wait": "approve",
                "smart_cancel": "approve",
            },
            proof["policy"]["toolApprovalModes"],
        )

    def test_policy_rejects_non_approve_default_and_tool_modes(self) -> None:
        module = self._module()
        cases = (
            ('default_tools_approval_mode = "auto"\n', "default-auto"),
            ('default_tools_approval_mode = "prompt"\n', "default-prompt"),
            ('default_tools_approval_mode = "writes"\n', "default-writes"),
            (
                'default_tools_approval_mode = "approve"\n'
                f'\n[plugins."{PLUGIN_ID}".mcp_servers."{SERVER_ID}".tools.smart_plan]\n'
                'approval_mode = "auto"\n',
                "tool-auto",
            ),
            (
                'default_tools_approval_mode = "approve"\n'
                f'\n[plugins."{PLUGIN_ID}".mcp_servers."{SERVER_ID}".tools.smart_plan]\n'
                'approval_mode = "prompt"\n',
                "tool-prompt",
            ),
            (
                'default_tools_approval_mode = "approve"\n'
                f'\n[plugins."{PLUGIN_ID}".mcp_servers."{SERVER_ID}".tools.smart_plan]\n'
                'approval_mode = "writes"\n',
                "tool-writes",
            ),
        )
        for approval, label in cases:
            with self.subTest(label=label):
                self._write_policy(
                    server_overlay=(
                        f'\n[plugins."{PLUGIN_ID}".mcp_servers."{SERVER_ID}"]\n'
                        + approval
                    )
                )
                with self.assertRaises(module.MCPRuntimeProofV2Error):
                    module.build_user_mcp_policy_proof_v2(self.codex_home)

        self._write_policy(
            server_overlay=(
                f'\n[plugins."{PLUGIN_ID}".mcp_servers."{SERVER_ID}"]\n'
            )
        )
        inherited = json.loads(
            module.build_user_mcp_policy_proof_v2(self.codex_home)
        )
        self.assertEqual(
            "approve",
            inherited["policy"]["defaultToolsApprovalMode"],
        )
        self.assertEqual(
            {name: "approve" for name in REQUIRED_TOOLS},
            inherited["policy"]["toolApprovalModes"],
        )

    def test_policy_rejects_top_level_raw_mcp_collision(self) -> None:
        module = self._module()
        self.config_path.write_text(
            f'[plugins."{PLUGIN_ID}"]\n'
            "enabled = true\n\n"
            f'[mcp_servers."{SERVER_ID}"]\n'
            'command = "/tmp/replacement"\n',
            encoding="utf-8",
        )
        self.config_path.chmod(0o600)

        with self.assertRaises(module.MCPRuntimeProofV2Error) as caught:
            module.build_user_mcp_policy_proof_v2(self.codex_home)

        self.assertEqual("USER_MCP_POLICY_UNPROVED", caught.exception.code)

    def test_policy_rejects_unknown_fields_in_target_plugin_server_or_tool(
        self,
    ) -> None:
        module = self._module()
        cases = (
            (
                f'[plugins."{PLUGIN_ID}"]\n'
                "enabled = true\n"
                "unexpected = true\n",
                "plugin-extra",
            ),
            (
                f'[plugins."{PLUGIN_ID}"]\n'
                "enabled = true\n\n"
                f'[plugins."{PLUGIN_ID}".mcp_servers."{SERVER_ID}"]\n'
                "unexpected = true\n",
                "server-extra",
            ),
            (
                f'[plugins."{PLUGIN_ID}"]\n'
                "enabled = true\n\n"
                f'[plugins."{PLUGIN_ID}".mcp_servers."{SERVER_ID}".tools.smart_plan]\n'
                'approval_mode = "approve"\n'
                "unexpected = true\n",
                "tool-extra",
            ),
        )
        for source, label in cases:
            with self.subTest(label=label):
                self.config_path.write_text(source, encoding="utf-8")
                self.config_path.chmod(0o600)
                with self.assertRaises(module.MCPRuntimeProofV2Error):
                    module.build_user_mcp_policy_proof_v2(self.codex_home)

    def test_policy_rejects_malformed_unrelated_plugin(self) -> None:
        module = self._module()
        self.config_path.write_text(
            f'[plugins."{PLUGIN_ID}"]\n'
            "enabled = true\n\n"
            '[plugins."unrelated@example"]\n'
            'enabled = "yes"\n',
            encoding="utf-8",
        )
        self.config_path.chmod(0o600)

        with self.assertRaises(module.MCPRuntimeProofV2Error):
            module.build_user_mcp_policy_proof_v2(self.codex_home)

    def test_policy_rejects_wrong_types_and_corrupt_proof(self) -> None:
        module = self._module()
        self.config_path.write_text(
            f'[plugins."{PLUGIN_ID}"]\nenabled = "true"\n',
            encoding="utf-8",
        )
        self.config_path.chmod(0o600)
        with self.assertRaises(module.MCPRuntimeProofV2Error):
            module.build_user_mcp_policy_proof_v2(self.codex_home)

        self._write_policy()
        encoded = module.build_user_mcp_policy_proof_v2(self.codex_home)
        with self.assertRaises(module.MCPRuntimeProofV2Error):
            module.verify_user_mcp_policy_proof_v2(self.codex_home, encoded[:-1])

    def test_policy_proof_accepts_unrelated_codex_config_rewrite(self) -> None:
        module = self._module()
        self._write_policy()
        encoded = module.build_user_mcp_policy_proof_v2(self.codex_home)

        self.config_path.write_bytes(
            self.config_path.read_bytes()
            + (
                b'\n[hooks.state."managed-hook"]\n'
                b'trusted_hash = "sha256:' + b"a" * 64 + b'"\n'
            )
        )
        self.config_path.chmod(0o600)

        verified = module.verify_user_mcp_policy_proof_v2(
            self.codex_home,
            encoded,
        )

        self.assertEqual(json.loads(encoded), verified)

    def test_policy_proof_rejects_changed_target_policy(self) -> None:
        module = self._module()
        self._write_policy()
        encoded = module.build_user_mcp_policy_proof_v2(self.codex_home)
        self._write_policy(plugin_enabled=False)

        with self.assertRaises(module.MCPRuntimeProofV2Error) as caught:
            module.verify_user_mcp_policy_proof_v2(self.codex_home, encoded)

        self.assertEqual("USER_MCP_POLICY_PROOF_MISMATCH", caught.exception.code)

    def test_policy_proof_rejects_non_string_digest_fields_cleanly(self) -> None:
        module = self._module()
        self._write_policy()
        original = json.loads(
            module.build_user_mcp_policy_proof_v2(self.codex_home)
        )

        for field in ("rawSha256", "proofFingerprint"):
            with self.subTest(field=field):
                damaged = deepcopy(original)
                damaged[field] = 7
                encoded = json.dumps(
                    damaged,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                with self.assertRaises(module.MCPRuntimeProofV2Error) as caught:
                    module.verify_user_mcp_policy_proof_v2(
                        self.codex_home,
                        encoded,
                    )
                self.assertEqual(
                    "USER_MCP_POLICY_PROOF_MISMATCH",
                    caught.exception.code,
                )

    def test_attestation_binds_live_process_nonce_and_exact_tools(self) -> None:
        module = self._module()
        self._write_policy()
        self.environment[module.USER_MCP_POLICY_PROOF_ENV_V2] = (
            module.build_user_mcp_policy_proof_v2(self.codex_home)
        )
        marker = "test-process-start-marker"
        publisher = module.MCPRuntimeAttestationPublisherV2.from_environ(
            self.environment,
            process_start_marker_provider=lambda pid: (
                marker if pid == os.getpid() else self.fail("неверный PID")
            ),
        )

        path = publisher.publish(
            TOOL_DEFINITIONS,
            server_name=SERVER_NAME,
            server_version=SERVER_VERSION,
            protocol_version=MCP_PROTOCOL,
        )

        self.assertEqual(
            module.mcp_runtime_attestation_path_v2(self.environment),
            path,
        )
        self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
        attestation = module.verify_mcp_runtime_attestation_v2(
            self.environment,
            process_start_marker_provider=lambda pid: (
                marker if pid == os.getpid() else self.fail("неверный PID")
            ),
        )
        self.assertEqual(os.getpid(), attestation["pid"])
        self.assertEqual(marker, attestation["processStartMarker"])
        self.assertEqual(list(REQUIRED_TOOLS), attestation["tools"])
        self.assertEqual(SERVER_NAME, attestation["serverName"])
        self.assertEqual(SERVER_VERSION, attestation["serverVersion"])
        self.assertEqual(MCP_PROTOCOL, attestation["protocolVersion"])
        self.assertEqual(
            domain_fingerprint(
                "codex-smart/mcp-tool-definitions/v2",
                TOOL_DEFINITIONS,
            ),
            attestation["toolDefinitionsFingerprint"],
        )
        self.assertEqual(
            self.environment["CODEX_SMART_MCP_SESSION_NONCE"],
            attestation["sessionNonce"],
        )
        policy = json.loads(
            self.environment[module.USER_MCP_POLICY_PROOF_ENV_V2]
        )
        self.assertIn("basePolicyProofFingerprint", attestation)
        self.assertEqual(
            policy["proofFingerprint"],
            attestation["basePolicyProofFingerprint"],
        )

    def test_attestation_rejects_wrong_nonce_dead_pid_marker_and_tool_set(self) -> None:
        module = self._module()
        self._write_policy()
        self.environment[module.USER_MCP_POLICY_PROOF_ENV_V2] = (
            module.build_user_mcp_policy_proof_v2(self.codex_home)
        )
        marker = "test-process-start-marker"
        publisher = module.MCPRuntimeAttestationPublisherV2.from_environ(
            self.environment,
            process_start_marker_provider=lambda _pid: marker,
        )
        publisher.publish(
            TOOL_DEFINITIONS,
            server_name=SERVER_NAME,
            server_version=SERVER_VERSION,
            protocol_version=MCP_PROTOCOL,
        )

        wrong_nonce = dict(self.environment)
        wrong_nonce["CODEX_SMART_MCP_SESSION_NONCE"] = "mcpn2_" + "e" * 64
        with self.assertRaises(module.MCPRuntimeProofV2Error):
            module.verify_mcp_runtime_attestation_v2(
                wrong_nonce,
                process_start_marker_provider=lambda _pid: marker,
            )

        with self.assertRaises(module.MCPRuntimeProofV2Error) as dead:
            module.verify_mcp_runtime_attestation_v2(
                self.environment,
                process_start_marker_provider=lambda _pid: (_ for _ in ()).throw(
                    ProcessLookupError()
                ),
            )
        self.assertEqual("MCP_ATTESTATION_PROCESS_DEAD", dead.exception.code)

        with self.assertRaises(module.MCPRuntimeProofV2Error) as reused:
            module.verify_mcp_runtime_attestation_v2(
                self.environment,
                process_start_marker_provider=lambda _pid: "other-marker",
            )
        self.assertEqual("MCP_ATTESTATION_PROCESS_REUSED", reused.exception.code)

        publisher.cleanup()
        altered = deepcopy(TOOL_DEFINITIONS)
        altered[0]["description"] += " altered"
        with self.assertRaises(module.MCPRuntimeProofV2Error):
            publisher.publish(
                altered,
                server_name=SERVER_NAME,
                server_version=SERVER_VERSION,
                protocol_version=MCP_PROTOCOL,
            )
        self.assertFalse(
            module.mcp_runtime_attestation_path_v2(self.environment).exists()
        )

    def test_cleanup_removes_only_the_publishers_own_attestation(self) -> None:
        module = self._module()
        self._write_policy()
        self.environment[module.USER_MCP_POLICY_PROOF_ENV_V2] = (
            module.build_user_mcp_policy_proof_v2(self.codex_home)
        )
        first = module.MCPRuntimeAttestationPublisherV2.from_environ(
            self.environment,
            process_start_marker_provider=lambda _pid: "marker-first",
        )
        path = first.publish(
            TOOL_DEFINITIONS,
            server_name=SERVER_NAME,
            server_version=SERVER_VERSION,
            protocol_version=MCP_PROTOCOL,
        )
        second = module.MCPRuntimeAttestationPublisherV2.from_environ(
            self.environment,
            process_start_marker_provider=lambda _pid: "marker-second",
        )
        second.publish(
            TOOL_DEFINITIONS,
            server_name=SERVER_NAME,
            server_version=SERVER_VERSION,
            protocol_version=MCP_PROTOCOL,
        )

        first.cleanup()
        self.assertTrue(path.exists())
        second.cleanup()
        self.assertFalse(path.exists())

    def test_attestation_lock_timeout_has_finite_exact_error_code(self) -> None:
        module = self._module()
        self._write_policy()
        self.environment[module.USER_MCP_POLICY_PROOF_ENV_V2] = (
            module.build_user_mcp_policy_proof_v2(self.codex_home)
        )
        publisher = module.MCPRuntimeAttestationPublisherV2.from_environ(
            self.environment,
            process_start_marker_provider=lambda _pid: "marker",
        )
        timeout = module.finite_file_lock_v2.FileLockTimeoutV2(
            "MCP_ATTESTATION_LOCK_TIMEOUT",
            30.0,
        )

        with mock.patch.object(
            module.finite_file_lock_v2,
            "acquire_flock_v2",
            side_effect=timeout,
        ) as acquire:
            with self.assertRaises(module.MCPRuntimeProofV2Error) as captured:
                publisher.publish(
                    TOOL_DEFINITIONS,
                    server_name=SERVER_NAME,
                    server_version=SERVER_VERSION,
                    protocol_version=MCP_PROTOCOL,
                )

        self.assertEqual(
            "MCP_ATTESTATION_LOCK_TIMEOUT",
            captured.exception.code,
        )
        self.assertEqual(30.0, acquire.call_args.kwargs["timeout_seconds"])
        self.assertFalse(publisher.path.exists())

    def test_attestation_requires_a_current_approved_policy_proof(self) -> None:
        module = self._module()
        self._write_policy()
        with self.assertRaises(module.MCPRuntimeProofV2Error):
            module.MCPRuntimeAttestationPublisherV2.from_environ(
                self.environment,
                process_start_marker_provider=lambda _pid: "marker",
            )

        self.environment[module.USER_MCP_POLICY_PROOF_ENV_V2] = "damaged"
        with self.assertRaises(module.MCPRuntimeProofV2Error):
            module.MCPRuntimeAttestationPublisherV2.from_environ(
                self.environment,
                process_start_marker_provider=lambda _pid: "marker",
            )


if __name__ == "__main__":
    unittest.main()
