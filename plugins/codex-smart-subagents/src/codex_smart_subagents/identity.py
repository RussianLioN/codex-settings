"""Opaque identifiers and request-context binding."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RequestContext:
    shell_session_id: str
    session_id: str
    turn_id: str
    codex_home: str
    repo_root: str
    base_sha: str
    worktree_fingerprint: str

    def canonical(self) -> dict[str, str]:
        return {
            "shellSessionId": self.shell_session_id,
            "sessionId": self.session_id,
            "turnId": self.turn_id,
            "codexHomeHash": sha256_text(self.codex_home),
            "repoRootHash": sha256_text(self.repo_root),
            "baseSha": self.base_sha,
            "worktreeFingerprint": self.worktree_fingerprint,
        }

    def digest(self) -> str:
        return canonical_sha256(self.canonical())


def new_opaque_id(prefix: str) -> str:
    return f"{prefix}_{base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')}"


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

