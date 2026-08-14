#!/usr/bin/env python3
"""Refresh the adaptive source-lineage document from canonical installer inputs."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

from install_adaptive_subagents import (  # noqa: E402
    SOURCE_LINEAGE_KIND,
    InstallLayout,
    _source_implementation_digest_v2,
)


LINEAGE_RELATIVE = Path(
    "plugins/codex-smart-subagents/config/source-lineage-v2.json"
)
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class LineageRefreshError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _layout_for_source_root(source_root: Path) -> InstallLayout:
    if not source_root.is_absolute():
        raise LineageRefreshError(
            "SOURCE_ROOT_INVALID",
            "--source-root должен быть абсолютным путём",
        )
    source_root = source_root.resolve(strict=False)
    return InstallLayout(
        source_root=source_root,
        codex_home=source_root / ".lineage-refresh-unused" / "codex-home",
        bin_dir=source_root / ".lineage-refresh-unused" / "bin",
        codex_binary=source_root / ".lineage-refresh-unused" / "codex",
        state_home=source_root / ".lineage-refresh-unused" / "state",
    )


def _canonical_document(generation: int, digest: str) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "kind": SOURCE_LINEAGE_KIND,
        "generation": generation,
        "implementationDigest": digest,
    }


def _load_lineage(path: Path) -> dict[str, Any]:
    try:
        info = os.lstat(path)
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LineageRefreshError(
            "SOURCE_LINEAGE_INVALID",
            "не удалось прочитать линию исходников установщика",
        ) from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or type(value) is not dict
        or set(value)
        != {"schemaVersion", "kind", "generation", "implementationDigest"}
        or value.get("schemaVersion") != 1
        or value.get("kind") != SOURCE_LINEAGE_KIND
        or type(value.get("generation")) is not int
        or not 1 <= value["generation"] <= 2**31 - 1
        or type(value.get("implementationDigest")) is not str
        or SHA256_PATTERN.fullmatch(value["implementationDigest"]) is None
    ):
        raise LineageRefreshError(
            "SOURCE_LINEAGE_INVALID",
            "линия исходников установщика имеет неверную форму",
        )
    return _canonical_document(
        value["generation"],
        value["implementationDigest"],
    )


def _write_lineage_atomically(path: Path, document: Mapping[str, Any]) -> None:
    payload = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    parent = path.parent
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
            newline="\n",
        ) as handle:
            tmp_path = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except OSError as exc:
        try:
            tmp_path.unlink()
        except (UnboundLocalError, OSError):
            pass
        raise LineageRefreshError(
            "SOURCE_LINEAGE_WRITE_FAILED",
            "не удалось атомарно записать линию исходников",
        ) from exc


def refresh_source_lineage(
    *,
    source_root: Path,
    write: bool,
    digest_func: Callable[[InstallLayout], str] = _source_implementation_digest_v2,
) -> dict[str, Any]:
    layout = _layout_for_source_root(source_root)
    path = layout.source_lineage_source
    current = _load_lineage(path)
    observed = digest_func(layout)
    if not isinstance(observed, str) or SHA256_PATTERN.fullmatch(observed) is None:
        raise LineageRefreshError(
            "SOURCE_DIGEST_INVALID",
            "канонический отпечаток реализации имеет неверную форму",
        )

    if current["implementationDigest"] == observed:
        return {
            "status": "unchanged" if write else "ok",
            "generation": current["generation"],
            "implementationDigest": observed,
            "path": str(path),
        }

    if not write:
        raise LineageRefreshError(
            "SOURCE_LINEAGE_MISMATCH",
            "реализация изменилась без нового поколения линии исходников",
        )

    next_generation = current["generation"] + 1
    if next_generation > 2**31 - 1:
        raise LineageRefreshError(
            "SOURCE_GENERATION_EXHAUSTED",
            "поколение линии исходников исчерпано",
        )
    updated = _canonical_document(next_generation, observed)
    _write_lineage_atomically(path, updated)
    return {
        "status": "updated",
        "generation": next_generation,
        "implementationDigest": observed,
        "path": str(path),
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Refresh codex-smart source-lineage-v2.json",
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        default=Path.cwd().resolve(),
        help="absolute repository source root; defaults to the current directory",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        dest="write",
        action="store_false",
        help="verify the lineage document without writing",
    )
    mode.add_argument(
        "--write",
        dest="write",
        action="store_true",
        help="write the next canonical generation when the digest changed",
    )
    parser.set_defaults(write=False)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        result = refresh_source_lineage(
            source_root=args.source_root.expanduser(),
            write=args.write,
        )
    except LineageRefreshError as exc:
        print(
            json.dumps(
                {
                    "status": "error",
                    "code": exc.code,
                    "message": str(exc),
                    "path": str(
                        args.source_root.expanduser()
                        / LINEAGE_RELATIVE
                    ),
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
