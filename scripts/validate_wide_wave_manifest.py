#!/usr/bin/env python3
"""Validate a trusted wide subagent wave manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
from pathlib import PurePosixPath
from typing import Any


MAX_WAVE_SIZE = 20
WRITE_ACCESSES = {"workspace-write", "danger-full-access"}
READ_ACCESSES = WRITE_ACCESSES | {"read-only"}
REQUIRED_TRUST_FIELDS = {
    "skill_id",
    "sha256",
    "max_live_wave",
    "execution_kind",
    "fallback",
}
REQUIRED_MANIFEST_FIELDS = {
    "schema_version",
    "skill_id",
    "wave_size",
    "repository_root",
    "base_commit",
    "participants",
}
REQUIRED_PARTICIPANT_FIELDS = {"id", "access", "owned_write_scope"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--skill-id", required=True)
    parser.add_argument("--skill-file", required=True)
    parser.add_argument("--trusted-registry", required=True)
    return parser.parse_args()


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as stream:
        return json.load(stream)


def trust_entry(registry: Any, skill_id: str, reasons: list[str]) -> dict[str, Any] | None:
    if not isinstance(registry, dict):
        reasons.append("trusted_registry_not_object")
        return None
    if registry.get("schema_version") != 1:
        reasons.append("trusted_registry_schema_version_invalid")
    entries = registry.get("trusted_skills")
    if not isinstance(entries, list):
        reasons.append("trusted_registry_entries_invalid")
        return None
    matches: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            reasons.append("trusted_entry_not_object")
            continue
        missing = REQUIRED_TRUST_FIELDS - set(entry)
        if missing:
            reasons.append("trusted_entry_missing_fields")
            continue
        if entry.get("skill_id") == skill_id:
            matches.append(entry)
    if not matches:
        reasons.append("unknown_skill")
        return None
    if len(matches) > 1:
        reasons.append("duplicate_trusted_skill")
    return matches[0]


def validate_manifest_shape(manifest: Any, reasons: list[str]) -> None:
    if not isinstance(manifest, dict):
        reasons.append("manifest_not_object")
        return
    unknown = set(manifest) - REQUIRED_MANIFEST_FIELDS
    missing = REQUIRED_MANIFEST_FIELDS - set(manifest)
    if unknown:
        reasons.append("manifest_unknown_fields")
    if missing:
        reasons.append("manifest_missing_fields")
    if manifest.get("schema_version") != 1:
        reasons.append("manifest_schema_version_invalid")
    if not isinstance(manifest.get("skill_id"), str) or not manifest.get("skill_id"):
        reasons.append("manifest_skill_id_invalid")
    wave_size = manifest.get("wave_size")
    if type(wave_size) is not int or wave_size < 1 or wave_size > MAX_WAVE_SIZE:
        reasons.append("manifest_wave_size_invalid")
    if not isinstance(manifest.get("repository_root"), str) or not manifest.get("repository_root"):
        reasons.append("repository_root_invalid")
    base_commit = manifest.get("base_commit")
    if not isinstance(base_commit, str) or not base_commit:
        reasons.append("base_commit_invalid")
    participants = manifest.get("participants")
    if not isinstance(participants, list) or not participants:
        reasons.append("participants_invalid")
        return
    if type(wave_size) is int and len(participants) != wave_size:
        reasons.append("participant_count_mismatch_wave_size")
    participant_ids: set[str] = set()
    for participant in participants:
        if not isinstance(participant, dict):
            reasons.append("participant_not_object")
            continue
        if set(participant) - REQUIRED_PARTICIPANT_FIELDS:
            reasons.append("participant_unknown_fields")
        if REQUIRED_PARTICIPANT_FIELDS - set(participant):
            reasons.append("participant_missing_fields")
        participant_id = participant.get("id")
        if not isinstance(participant_id, str) or not participant_id:
            reasons.append("participant_id_invalid")
        elif participant_id in participant_ids:
            reasons.append("duplicate_participant_id")
        else:
            participant_ids.add(participant_id)
        access = participant.get("access")
        if access not in READ_ACCESSES:
            reasons.append("participant_access_invalid")
        scopes = participant.get("owned_write_scope")
        if not isinstance(scopes, list) or not all(isinstance(scope, str) and scope for scope in scopes):
            reasons.append("owned_write_scope_invalid")
        elif access == "read-only" and scopes:
            reasons.append("readonly_write_scope_forbidden")
        elif access in WRITE_ACCESSES and not scopes:
            reasons.append("writer_write_scope_required")


def normalized_scope(scope: str, reasons: list[str]) -> tuple[str, ...] | None:
    path = PurePosixPath(scope)
    if path.is_absolute():
        reasons.append("absolute_write_scope")
        return None
    if ".." in path.parts:
        reasons.append("write_scope_escapes_repository")
        return None
    normalized = posixpath.normpath(scope)
    if normalized in (".", ""):
        reasons.append("write_scope_empty_after_normalization")
        return None
    normalized_path = PurePosixPath(normalized)
    if normalized_path.is_absolute() or ".." in normalized_path.parts:
        reasons.append("write_scope_escapes_repository")
        return None
    return tuple(normalized_path.parts)


def scopes_overlap(left: tuple[str, ...], right: tuple[str, ...]) -> bool:
    shortest = min(len(left), len(right))
    return left[:shortest] == right[:shortest]


def validate_scopes(manifest: dict[str, Any], reasons: list[str]) -> None:
    normalized: list[tuple[str, tuple[str, ...]]] = []
    for participant in manifest.get("participants", []):
        if not isinstance(participant, dict) or participant.get("access") not in WRITE_ACCESSES:
            continue
        scopes = participant.get("owned_write_scope", [])
        if not isinstance(scopes, list):
            continue
        for scope in scopes:
            if not isinstance(scope, str):
                continue
            parts = normalized_scope(scope, reasons)
            if parts is not None:
                normalized.append((str(participant.get("id", "unknown")), parts))
    for index, (_, left) in enumerate(normalized):
        for _, right in normalized[index + 1 :]:
            if scopes_overlap(left, right):
                reasons.append("write_scope_overlap")
                return


def validate_trust(
    *,
    manifest: dict[str, Any],
    entry: dict[str, Any] | None,
    skill_id: str,
    skill_file: str,
    reasons: list[str],
) -> None:
    if manifest.get("skill_id") != skill_id:
        reasons.append("skill_id_mismatch")
    if entry is None:
        return
    expected_hash = entry.get("sha256")
    if not isinstance(expected_hash, str) or len(expected_hash) != 64:
        reasons.append("trusted_sha256_invalid")
    else:
        if not os.path.isfile(skill_file):
            reasons.append("skill_file_missing")
            actual_hash = None
        else:
            with open(skill_file, "rb") as stream:
                actual_hash = hashlib.sha256(stream.read()).hexdigest()
        if actual_hash is not None and actual_hash != expected_hash:
            reasons.append("skill_hash_mismatch")
    max_live_wave = entry.get("max_live_wave")
    if type(max_live_wave) is not int or max_live_wave < 1 or max_live_wave > MAX_WAVE_SIZE:
        reasons.append("trusted_max_live_wave_invalid")
    elif type(manifest.get("wave_size")) is int and manifest["wave_size"] > max_live_wave:
        reasons.append("wave_size_exceeds_trusted_max")
    if not isinstance(entry.get("execution_kind"), str) or not entry["execution_kind"]:
        reasons.append("trusted_execution_kind_invalid")
    if not isinstance(entry.get("fallback"), str) or not entry["fallback"]:
        reasons.append("trusted_fallback_invalid")


def main() -> int:
    args = parse_args()
    reasons: list[str] = []
    try:
        manifest = load_json(args.manifest)
        registry = load_json(args.trusted_registry)
    except OSError as error:
        print("status=BLOCK")
        print(f"reasons=file_read_error:{error.filename}")
        return 2
    except json.JSONDecodeError as error:
        print("status=BLOCK")
        print(f"reasons=json_decode_error:{error.msg}")
        return 2

    validate_manifest_shape(manifest, reasons)
    entry = trust_entry(registry, args.skill_id, reasons)
    if isinstance(manifest, dict):
        validate_scopes(manifest, reasons)
        validate_trust(
            manifest=manifest,
            entry=entry,
            skill_id=args.skill_id,
            skill_file=args.skill_file,
            reasons=reasons,
        )

    if reasons:
        print("status=BLOCK")
        print("reasons=" + ",".join(dict.fromkeys(reasons)))
        return 2
    print("status=OK")
    print("reasons=none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
