from __future__ import annotations

import hashlib
import json
import os
import stat
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.codex_binary_snapshot import (  # noqa: E402
    CODE_SIGNATURE_REQUIREMENT,
    CodexBinarySnapshotter,
    SnapshotBinaryError,
    SnapshotCommandResult,
)
from codex_smart_subagents import codex_binary_snapshot  # noqa: E402
from codex_smart_subagents.evidence import build_interface_evidence  # noqa: E402
from codex_smart_subagents.operation_deadline_v2 import (  # noqa: E402
    OperationDeadlineExceededV2,
)


def macho_arm64(
    payload: bytes = b"codex-test\n",
    *,
    file_type: int = 2,
) -> bytes:
    header = struct.pack(
        "<IiiIIIII",
        0xFEEDFACF,
        0x0100000C,
        0,
        file_type,
        0,
        0,
        0,
        0,
    )
    return header + payload


class FakeExecutor:
    def __init__(
        self,
        *,
        lipo_archs: bytes = b"arm64\n",
        identifier: str = "codex",
        team_identifier: str = "2DC432GLL2",
        cd_hash: str = "1" * 40,
        version: bytes = b"codex-cli 0.144.6\n",
        fail_requirement: bool = False,
    ) -> None:
        self.lipo_archs = lipo_archs
        self.identifier = identifier
        self.team_identifier = team_identifier
        self.cd_hash = cd_hash
        self.version = version
        self.fail_requirement = fail_requirement
        self.calls = []

    def run(self, command):
        self.calls.append(command)
        argv = command.argv
        if argv[:2] == ("/usr/bin/lipo", "-archs"):
            return SnapshotCommandResult(0, self.lipo_archs, b"")
        if argv[:3] == ("/usr/bin/codesign", "-d", "--verbose=4"):
            metadata = (
                f"Executable={argv[-1]}\n"
                f"Identifier={self.identifier}\n"
                f"TeamIdentifier={self.team_identifier}\n"
                f"CDHash={self.cd_hash}\n"
            ).encode("utf-8")
            return SnapshotCommandResult(0, b"", metadata)
        if argv[:2] == ("/usr/bin/codesign", "-v"):
            if "-R" in argv and self.fail_requirement:
                return SnapshotCommandResult(1, b"", b"requirement failed")
            return SnapshotCommandResult(0, b"", b"")
        if argv[-1:] == ("--version",):
            return SnapshotCommandResult(0, self.version, b"")
        raise AssertionError(f"unexpected command: {argv!r}")


class CodexBinarySnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.source = self.base / "codex-source"
        self.source.write_bytes(macho_arm64())
        self.source.chmod(0o500)
        self.snapshot_root = self.base / "codex-snapshots"
        self.executor = FakeExecutor()
        self.snapshotter = CodexBinarySnapshotter(
            snapshot_root=self.snapshot_root,
            executor=self.executor,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def materialize(self):
        return self.snapshotter.materialize(os.fspath(self.source))

    def test_executor_deadline_is_not_reclassified_as_process_failure(self) -> None:
        original = OperationDeadlineExceededV2(
            code="ROOT_OPERATION_EXPIRED",
            operation="apply",
            phase="snapshot-command",
            deadline_kind="operation",
            configured_timeout_nanoseconds=1,
            elapsed_monotonic_nanoseconds=2,
        )
        executor = mock.Mock()
        executor.run.side_effect = original
        snapshotter = CodexBinarySnapshotter(
            snapshot_root=self.snapshot_root,
            executor=executor,
        )

        with self.assertRaises(OperationDeadlineExceededV2) as caught:
            snapshotter._run((str(self.source), "--version"), self.base)

        self.assertIs(original, caught.exception)

    def test_materializes_verified_subject_in_private_content_addressed_path(
        self,
    ) -> None:
        subject = self.materialize()
        expected_sha = hashlib.sha256(self.source.read_bytes()).hexdigest()
        expected_path = self.snapshot_root / expected_sha / "codex"

        self.assertEqual(os.fspath(expected_path), subject["snapshotPath"])
        self.assertEqual(expected_sha, subject["snapshotSha256"])
        self.assertEqual(expected_sha, subject["sourceObservedSha256"])
        self.assertEqual(os.fspath(self.source.absolute()), subject["sourceLocator"])
        self.assertEqual("codex-cli 0.144.6", subject["version"])
        self.assertEqual("darwin", subject["platform"])
        self.assertEqual("arm64", subject["architecture"])
        self.assertEqual("codex", subject["signatureIdentifier"])
        self.assertEqual("2DC432GLL2", subject["teamIdentifier"])
        self.assertEqual("1" * 40, subject["cdHash"])
        self.assertRegex(subject["mtimeNs"], r"^(?:0|[1-9][0-9]*)$")
        self.assertEqual(0o500, stat.S_IMODE(expected_path.stat().st_mode))
        self.assertEqual(0o700, stat.S_IMODE(self.snapshot_root.stat().st_mode))
        self.assertEqual(0o700, stat.S_IMODE(expected_path.parent.stat().st_mode))
        self.assertEqual(self.source.read_bytes(), expected_path.read_bytes())

    def test_result_is_a_strict_subject_v1_for_interface_evidence(self) -> None:
        subject = self.materialize()
        vectors = json.loads(
            (
                ROOT / "docs" / "contracts" / "vectors" / "interface-evidence-v1.json"
            ).read_text(encoding="utf-8")
        )

        evidence = build_interface_evidence(
            subject=subject,
            semantic=vectors["base"]["semantic"],
        )

        self.assertEqual(subject, evidence["subject"])

    def test_uses_only_bounded_shell_free_exact_verification_commands(self) -> None:
        self.materialize()
        argv_values = [command.argv for command in self.executor.calls]
        requirement_calls = [argv for argv in argv_values if "-R" in argv]
        ordinary_calls = [
            argv
            for argv in argv_values
            if argv[:2] == ("/usr/bin/codesign", "-v") and "-R" not in argv
        ]

        self.assertEqual(2, len(requirement_calls))
        self.assertEqual(2, len(ordinary_calls))
        for argv in requirement_calls:
            self.assertEqual(
                (
                    "/usr/bin/codesign",
                    "-v",
                    "--strict",
                    "--all-architectures",
                    "-R",
                    CODE_SIGNATURE_REQUIREMENT,
                    argv[-1],
                ),
                argv,
            )
            self.assertTrue(argv[5].startswith("="))
        for command in self.executor.calls:
            self.assertTrue(Path(command.argv[0]).is_absolute())
            self.assertGreater(command.timeout_seconds, 0)
            self.assertLessEqual(command.timeout_seconds, 30)
            self.assertLessEqual(command.max_output_bytes, 1024 * 1024)
            self.assertEqual("C", command.environment["LC_ALL"])

    def test_reuses_identical_existing_snapshot_without_replacing_inode(self) -> None:
        first = self.materialize()
        published = Path(first["snapshotPath"])
        first_inode = published.stat().st_ino
        first_mtime = published.stat().st_mtime_ns

        second = self.materialize()

        self.assertEqual(first, second)
        self.assertEqual(first_inode, published.stat().st_ino)
        self.assertEqual(first_mtime, published.stat().st_mtime_ns)

    def test_reports_created_then_reused_publication_identity(self) -> None:
        first = self.snapshotter.materialize_with_identity(os.fspath(self.source))
        second = self.snapshotter.materialize_with_identity(os.fspath(self.source))

        self.assertEqual("created", first.snapshot_disposition)
        self.assertEqual("created", first.digest_directory_disposition)
        self.assertEqual("reused", second.snapshot_disposition)
        self.assertEqual("reused", second.digest_directory_disposition)
        self.assertEqual(first.subject, second.subject)

    def test_existing_name_with_different_bytes_is_corruption_not_overwrite(
        self,
    ) -> None:
        first = self.materialize()
        published = Path(first["snapshotPath"])
        original_size = published.stat().st_size
        published.chmod(0o700)
        published.write_bytes(b"x" * original_size)
        published.chmod(0o500)

        with self.assertRaisesRegex(SnapshotBinaryError, "SNAPSHOT_CORRUPT"):
            self.materialize()

        self.assertEqual(b"x" * original_size, published.read_bytes())

    def test_initial_source_symlink_is_recorded_but_never_published_as_boundary(
        self,
    ) -> None:
        link = self.base / "selected-codex"
        link.symlink_to(self.source.name)

        subject = self.snapshotter.materialize(os.fspath(link))

        self.assertEqual(os.fspath(link.absolute()), subject["sourceLocator"])
        self.assertNotEqual(os.fspath(link), subject["snapshotPath"])
        self.assertFalse(Path(subject["snapshotPath"]).is_symlink())

    def test_rejects_non_arm64_macho_before_any_external_process(self) -> None:
        self.source.chmod(0o700)
        self.source.write_bytes(b"not-mach-o")
        self.source.chmod(0o500)

        with self.assertRaisesRegex(SnapshotBinaryError, "MACHO_INVALID"):
            self.materialize()

        self.assertEqual([], self.executor.calls)

    def test_rejects_arm64_macho_that_is_not_an_executable(self) -> None:
        self.source.chmod(0o700)
        self.source.write_bytes(macho_arm64(file_type=6))
        self.source.chmod(0o500)

        with self.assertRaisesRegex(SnapshotBinaryError, "MACHO_INVALID"):
            self.materialize()

    def test_rejects_multiple_or_wrong_lipo_architectures(self) -> None:
        self.executor.lipo_archs = b"x86_64 arm64\n"

        with self.assertRaisesRegex(SnapshotBinaryError, "ARCHITECTURE_INVALID"):
            self.materialize()

    def test_rejects_non_utf8_lipo_output_as_closed_architecture_failure(self) -> None:
        self.executor.lipo_archs = b"\xff\xfe"

        with self.assertRaisesRegex(SnapshotBinaryError, "ARCHITECTURE_INVALID"):
            self.materialize()

    def test_rejects_signature_identity_and_requirement_failures(self) -> None:
        cases = (
            (FakeExecutor(identifier="other"), "SIGNATURE_IDENTITY_INVALID"),
            (FakeExecutor(team_identifier="OTHERTEAM1"), "SIGNATURE_IDENTITY_INVALID"),
            (FakeExecutor(cd_hash="not-a-cdhash"), "SIGNATURE_METADATA_INVALID"),
            (FakeExecutor(fail_requirement=True), "SIGNATURE_INVALID"),
        )
        for executor, code in cases:
            with self.subTest(code=code):
                snapshotter = CodexBinarySnapshotter(
                    snapshot_root=self.snapshot_root,
                    executor=executor,
                )
                with self.assertRaisesRegex(SnapshotBinaryError, code):
                    snapshotter.materialize(os.fspath(self.source))

    def test_rejects_nonstable_or_too_old_version(self) -> None:
        for version in (
            b"codex-cli 0.144.3\n",
            b"codex-cli 0.144.6-beta.1\n",
            b"codex-cli " + b"9" * 60 + b".0.0\n",
        ):
            with self.subTest(version=version):
                snapshotter = CodexBinarySnapshotter(
                    snapshot_root=self.snapshot_root,
                    executor=FakeExecutor(version=version),
                )
                with self.assertRaisesRegex(SnapshotBinaryError, "VERSION_UNSUPPORTED"):
                    snapshotter.materialize(os.fspath(self.source))

    def test_accepts_homebrew_like_untrusted_source_directory_and_file(self) -> None:
        brew_root = self.base / "homebrew"
        brew_root.mkdir(mode=0o775)
        brew_root.chmod(0o2775)
        source = brew_root / "codex"
        source.write_bytes(macho_arm64(b"homebrew-like\n"))
        source.chmod(0o664)

        subject = self.snapshotter.materialize(os.fspath(source))

        self.assertEqual(os.fspath(source), subject["sourceLocator"])
        self.assertEqual(
            source.read_bytes(), Path(subject["snapshotPath"]).read_bytes()
        )

    def test_detects_source_observation_change_during_copy(self) -> None:
        original = codex_binary_snapshot._copy_and_hash

        def copy_then_change(source_fd, destination_fd, *, maximum):
            result = original(source_fd, destination_fd, maximum=maximum)
            observed = self.source.stat()
            os.utime(
                self.source,
                ns=(observed.st_atime_ns, observed.st_mtime_ns + 1),
            )
            return result

        with mock.patch.object(
            codex_binary_snapshot,
            "_copy_and_hash",
            side_effect=copy_then_change,
        ):
            with self.assertRaisesRegex(SnapshotBinaryError, "SOURCE_CHANGED"):
                self.materialize()

    def test_copy_and_hash_check_the_shared_operation_deadline_between_blocks(
        self,
    ) -> None:
        self.source.chmod(0o700)
        self.source.write_bytes(macho_arm64(b"x" * (2 * 1024 * 1024 + 17)))
        self.source.chmod(0o500)

        with mock.patch.object(
            codex_binary_snapshot,
            "checkpoint_current_operation_deadline_if_scoped_v2",
        ) as checkpoint:
            self.materialize()

        self.assertGreaterEqual(checkpoint.call_count, 3)

    def test_rejects_nonprivate_existing_snapshot_root(self) -> None:
        self.snapshot_root.mkdir(mode=0o755)
        self.snapshot_root.chmod(0o755)

        with self.assertRaisesRegex(SnapshotBinaryError, "SNAPSHOT_ROOT_UNSAFE"):
            self.materialize()

    def test_rejects_existing_snapshot_with_an_extra_hard_link(self) -> None:
        first = self.materialize()
        published = Path(first["snapshotPath"])
        os.link(published, published.parent / "second-link")

        with self.assertRaisesRegex(SnapshotBinaryError, "SNAPSHOT_CORRUPT"):
            self.materialize()


if __name__ == "__main__":
    unittest.main()
