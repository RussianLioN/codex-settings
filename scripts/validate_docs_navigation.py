#!/usr/bin/env python3
"""Проверить центральную навигацию пользовательской документации."""

from __future__ import annotations

import argparse
import os
import re
import stat
import subprocess
import sys
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence
from urllib.parse import unquote, urlsplit


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

from docs_navigation_contracts import (  # noqa: E402
    Link,
    MarkdownDocument,
    parse_markdown,
    parse_route_contract,
    root_catalog_structure_errors,
)


ROOT_README = Path("README.md")
ADAPTIVE_README = Path("plugins/codex-smart-subagents/README.md")
OPERATIONS_RUNBOOK = Path(
    "docs/runbooks/adaptive-subagents-v2-operations.md"
)
STATE_MODULE = Path(
    "plugins/codex-smart-subagents/src/"
    "codex_smart_subagents/state.py"
)
REQUIRED_ROOT_ENTRYPOINTS = (
    (
        ADAPTIVE_README,
        "как-проходит-умный-ход",
    ),
    (OPERATIONS_RUNBOOK, None),
    (Path("docs/guides/autonomous-workflow.md"), None),
    (Path("docs/guides/full-access.md"), None),
    (
        Path(
            "docs/decisions/"
            "001-adaptive-subagents-external-controller.md"
        ),
        None,
    ),
    (Path("docs/threat-models/adaptive-subagents.md"), None),
)
EXTERNAL_SCHEMES = frozenset({"http", "https", "mailto"})
REGULAR_GIT_MODES = frozenset({"100644", "100755"})
MAX_MARKDOWN_BYTES = 2 * 1024 * 1024
MAX_STATE_MODULE_BYTES = 1024 * 1024
STATE_TRANSITION_PATTERN = re.compile(
    r"^    ([A-Z][A-Z0-9_]*) --> "
    r"([A-Z][A-Z0-9_]*)$"
)


@dataclass(frozen=True)
class ValidationIssue:
    code: str
    path: str
    line: int | None
    message: str

    def render(self) -> str:
        location = self.path
        if self.line is not None:
            location = f"{location}:{self.line}"
        return f"{self.code} {location}: {self.message}"


class ValidationSetupError(RuntimeError):
    """The repository cannot be inspected reliably."""


class SourceFileError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def validate_repository(
    repo_root: Path,
) -> tuple[ValidationIssue, ...]:
    repo = repo_root.resolve()
    tracked_index = _tracked_files(repo)
    tracked = frozenset(tracked_index)
    user_documents = {
        path
        for path in tracked
        if _is_user_document(path)
    }
    issues: list[ValidationIssue] = []

    if ROOT_README not in tracked or not (repo / ROOT_README).is_file():
        issues.append(
            ValidationIssue(
                "ROOT_README_MISSING",
                ROOT_README.as_posix(),
                None,
                "центральный каталог отсутствует или не отслеживается",
            )
        )

    for path, _fragment in REQUIRED_ROOT_ENTRYPOINTS:
        if path not in tracked or not (repo / path).is_file():
            issues.append(
                ValidationIssue(
                    "REQUIRED_DOCUMENT_MISSING",
                    path.as_posix(),
                    None,
                    "обязательная точка входа отсутствует или не отслеживается",
                )
            )

    documents: dict[Path, MarkdownDocument] = {}
    document_sources: dict[Path, str] = {}
    for path in sorted(user_documents, key=Path.as_posix):
        text = _read_user_document(
            repo,
            path,
            tracked_index,
            issues,
        )
        if text is None:
            continue
        try:
            document = parse_markdown(text)
        except UnicodeError as exc:
            issues.append(
                ValidationIssue(
                    "MARKDOWN_READ_FAILED",
                    path.as_posix(),
                    None,
                    str(exc),
                )
            )
            continue
        documents[path] = document
        document_sources[path] = text
        if document.unclosed_fence_line is not None:
            issues.append(
                ValidationIssue(
                    "MARKDOWN_FENCE_UNCLOSED",
                    path.as_posix(),
                    document.unclosed_fence_line,
                    "ограждённый блок не закрыт",
                )
            )

    root_document = documents.get(ROOT_README)
    if root_document is not None and root_document.fences:
        for fence in root_document.fences:
            issues.append(
                ValidationIssue(
                    "ROOT_FENCE_FORBIDDEN",
                    ROOT_README.as_posix(),
                    fence.line,
                    "корневой README должен оставаться только каталогом",
                )
            )
    root_source = document_sources.get(ROOT_README)
    if root_source is not None:
        for message in root_catalog_structure_errors(root_source):
            issues.append(
                ValidationIssue(
                    "ROOT_CATALOG_STRUCTURE_INVALID",
                    ROOT_README.as_posix(),
                    None,
                    message,
                )
            )

    resolved: dict[Path, set[tuple[Path, str | None]]] = {
        path: set()
        for path in user_documents
    }
    for source, document in documents.items():
        for link in document.links:
            target = _resolve_local_link(
                repo=repo,
                source=source,
                link=link,
                tracked=tracked,
                documents=documents,
                issues=issues,
            )
            if target is not None:
                if link.navigable:
                    resolved[source].add(target)

    if root_document is not None:
        root_targets = resolved.get(ROOT_README, set())
        for required_path, required_fragment in REQUIRED_ROOT_ENTRYPOINTS:
            found = any(
                path == required_path
                and (
                    required_fragment is None
                    or fragment == required_fragment
                )
                for path, fragment in root_targets
            )
            if not found:
                suffix = (
                    f"#{required_fragment}"
                    if required_fragment is not None
                    else ""
                )
                issues.append(
                    ValidationIssue(
                        "ROOT_ENTRYPOINT_MISSING",
                        ROOT_README.as_posix(),
                        None,
                        (
                            "нет прямой ссылки на "
                            f"{required_path.as_posix()}{suffix}"
                        ),
                    )
                )

    if ROOT_README in documents:
        reachable = _reachable_documents(
            root=ROOT_README,
            resolved=resolved,
            user_documents=user_documents,
        )
        for path in sorted(
            user_documents - reachable,
            key=Path.as_posix,
        ):
            issues.append(
                ValidationIssue(
                    "DOCUMENT_UNREACHABLE",
                    path.as_posix(),
                    None,
                    "документ недостижим по ссылкам из корневого README",
                )
            )

    _check_mermaid_contracts(documents, issues)
    _check_state_diagram(
        repo,
        tracked_index,
        documents,
        issues,
    )
    return tuple(sorted(issues, key=_issue_sort_key))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    args = parser.parse_args(argv)
    try:
        issues = validate_repository(args.repo)
    except ValidationSetupError as exc:
        print(f"not ok docs_navigation_setup: {exc}", file=sys.stderr)
        return 2
    if issues:
        for issue in issues:
            print(
                f"not ok docs_navigation: {issue.render()}",
                file=sys.stderr,
            )
        return 1
    print("ok docs_navigation")
    return 0


def _tracked_files(repo: Path) -> dict[Path, str]:
    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "ls-files",
                "--stage",
                "-z",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise ValidationSetupError(
            f"не удалось запустить git: {exc}"
        ) from exc
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise ValidationSetupError(
            f"git ls-files завершился ошибкой: {message}"
        )
    try:
        names = result.stdout.decode("utf-8").split("\0")
    except UnicodeDecodeError as exc:
        raise ValidationSetupError(
            "индекс Git содержит путь не в UTF-8"
        ) from exc
    tracked: dict[Path, str] = {}
    for entry in names:
        if not entry:
            continue
        try:
            metadata, raw_path = entry.split("\t", maxsplit=1)
            mode, _object_id, stage = metadata.split()
        except ValueError as exc:
            raise ValidationSetupError(
                "git ls-files вернул повреждённую запись индекса"
            ) from exc
        path = Path(raw_path)
        if path.is_absolute() or stage != "0" or path in tracked:
            raise ValidationSetupError(
                f"индекс Git неоднозначен для пути: {raw_path}"
            )
        tracked[path] = mode
    return tracked


def _read_user_document(
    repo: Path,
    path: Path,
    tracked_index: Mapping[Path, str],
    issues: list[ValidationIssue],
) -> str | None:
    mode = tracked_index.get(path)
    if mode not in REGULAR_GIT_MODES:
        issues.append(
            ValidationIssue(
                "DOCUMENT_NOT_REGULAR",
                path.as_posix(),
                None,
                f"режим файла в индексе Git не является обычным: {mode}",
            )
        )
        return None
    try:
        payload = _read_regular_repo_file(
            repo,
            path,
            maximum_bytes=MAX_MARKDOWN_BYTES,
        )
        return payload.decode("utf-8")
    except SourceFileError as exc:
        issues.append(
            ValidationIssue(
                exc.code,
                path.as_posix(),
                None,
                str(exc),
            )
        )
    except UnicodeDecodeError as exc:
        issues.append(
            ValidationIssue(
                "MARKDOWN_READ_FAILED",
                path.as_posix(),
                None,
                f"документ не является UTF-8: {exc}",
            )
        )
    return None


def _read_regular_repo_file(
    repo: Path,
    path: Path,
    *,
    maximum_bytes: int,
) -> bytes:
    absolute = repo / path
    try:
        metadata = absolute.lstat()
    except OSError as exc:
        raise SourceFileError(
            "MARKDOWN_READ_FAILED",
            f"невозможно прочитать свойства файла: {exc}",
        ) from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise SourceFileError(
            "DOCUMENT_NOT_REGULAR",
            "путь рабочей копии не является обычным файлом",
        )
    try:
        resolved = absolute.resolve(strict=True)
        resolved.relative_to(repo)
    except (OSError, RuntimeError, ValueError) as exc:
        raise SourceFileError(
            "DOCUMENT_NOT_REGULAR",
            "путь рабочей копии выходит за пределы репозитория",
        ) from exc

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags)
    except OSError as exc:
        raise SourceFileError(
            "MARKDOWN_READ_FAILED",
            f"невозможно открыть обычный файл: {exc}",
        ) from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise SourceFileError(
                "DOCUMENT_NOT_REGULAR",
                "открытый путь не является обычным файлом",
            )
        if opened.st_size > maximum_bytes:
            raise SourceFileError(
                "DOCUMENT_TOO_LARGE",
                (
                    f"размер {opened.st_size} превышает предел "
                    f"{maximum_bytes}"
                ),
            )
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            payload = handle.read(maximum_bytes + 1)
        if len(payload) > maximum_bytes:
            raise SourceFileError(
                "DOCUMENT_TOO_LARGE",
                f"содержимое превышает предел {maximum_bytes}",
            )
        return payload
    finally:
        os.close(descriptor)


def _is_user_document(path: Path) -> bool:
    if path.parts and path.parts[0] == ".smart-subagents":
        return False
    if path == ROOT_README:
        return True
    if path.suffix.lower() != ".md":
        return False
    if path.parts and path.parts[0] == "docs":
        return True
    return (
        len(path.parts) >= 3
        and path.parts[0] == "plugins"
        and path.name == "README.md"
    )


def _resolve_local_link(
    *,
    repo: Path,
    source: Path,
    link: Link,
    tracked: frozenset[Path],
    documents: dict[Path, MarkdownDocument],
    issues: list[ValidationIssue],
) -> tuple[Path, str | None] | None:
    target = link.target
    lowered = target.casefold()
    if target.startswith("//") or any(
        lowered.startswith(f"{scheme}:")
        for scheme in EXTERNAL_SCHEMES
    ):
        return None
    try:
        parsed = urlsplit(target)
    except ValueError:
        issues.append(
            ValidationIssue(
                "LOCAL_LINK_INVALID",
                source.as_posix(),
                link.line,
                f"невозможно разобрать цель ссылки: {target}",
            )
        )
        return None
    if parsed.scheme.casefold() in EXTERNAL_SCHEMES or parsed.netloc:
        return None
    if parsed.scheme:
        issues.append(
            ValidationIssue(
                "LOCAL_LINK_OUTSIDE_REPO",
                source.as_posix(),
                link.line,
                f"неподдерживаемая схема локальной ссылки: {target}",
            )
        )
        return None

    raw_path = unquote(parsed.path)
    if any(ord(character) < 32 for character in raw_path):
        issues.append(
            ValidationIssue(
                "LOCAL_LINK_INVALID",
                source.as_posix(),
                link.line,
                "цель локальной ссылки содержит управляющий символ",
            )
        )
        return None
    if raw_path.startswith("/") or re.match(r"^[A-Za-z]:[/\\]", raw_path):
        issues.append(
            ValidationIssue(
                "LOCAL_LINK_OUTSIDE_REPO",
                source.as_posix(),
                link.line,
                f"абсолютная локальная ссылка запрещена: {target}",
            )
        )
        return None

    try:
        source_absolute = repo / source
        target_absolute = (
            Path(os.path.abspath(source_absolute.parent / raw_path))
            if raw_path
            else source_absolute
        )
        resolved_absolute = target_absolute.resolve(strict=False)
        target_absolute.relative_to(repo)
        resolved_absolute.relative_to(repo)
    except (OSError, RuntimeError, ValueError):
        issues.append(
            ValidationIssue(
                "LOCAL_LINK_OUTSIDE_REPO",
                source.as_posix(),
                link.line,
                f"ссылка выходит за пределы репозитория: {target}",
            )
        )
        return None

    relative = target_absolute.relative_to(repo)
    try:
        target_exists = target_absolute.exists()
    except OSError:
        target_exists = False
    if not target_exists:
        issues.append(
            ValidationIssue(
                "LOCAL_LINK_TARGET_MISSING",
                source.as_posix(),
                link.line,
                f"цель не существует: {relative.as_posix()}",
            )
        )
        return None
    if relative not in tracked:
        issues.append(
            ValidationIssue(
                "LOCAL_LINK_TARGET_UNTRACKED",
                source.as_posix(),
                link.line,
                f"цель не отслеживается Git: {relative.as_posix()}",
            )
        )
        return None

    fragment = unquote(parsed.fragment) or None
    if fragment is not None and relative.suffix.lower() == ".md":
        target_document = documents.get(relative)
        if target_document is None:
            issues.append(
                ValidationIssue(
                    "LOCAL_LINK_ANCHOR_UNSUPPORTED",
                    source.as_posix(),
                    link.line,
                    (
                        "невозможно проверить якорь в непользовательском "
                        f"документе: {relative.as_posix()}"
                    ),
                )
            )
            return None
        if fragment not in target_document.anchors:
            issues.append(
                ValidationIssue(
                    "LOCAL_LINK_ANCHOR_MISSING",
                    source.as_posix(),
                    link.line,
                    (
                        f"якорь #{fragment} отсутствует в "
                        f"{relative.as_posix()}"
                    ),
                )
            )
            return None
    return relative, fragment


def _reachable_documents(
    *,
    root: Path,
    resolved: dict[Path, set[tuple[Path, str | None]]],
    user_documents: set[Path],
) -> set[Path]:
    visited: set[Path] = set()
    pending: deque[Path] = deque([root])
    while pending:
        source = pending.popleft()
        if source in visited:
            continue
        visited.add(source)
        for target, _fragment in resolved.get(source, set()):
            if target in user_documents and target not in visited:
                pending.append(target)
    return visited


def _check_mermaid_contracts(
    documents: dict[Path, MarkdownDocument],
    issues: list[ValidationIssue],
) -> None:
    expectations = {
        ADAPTIVE_README: ("sequenceDiagram", "flowchart LR"),
        OPERATIONS_RUNBOOK: ("stateDiagram-v2",),
    }
    for path, expected in expectations.items():
        document = documents.get(path)
        if document is None:
            continue
        mermaid = [
            fence
            for fence in document.fences
            if fence.language == "mermaid"
        ]
        if len(mermaid) != len(expected):
            issues.append(
                ValidationIssue(
                    "MERMAID_COUNT_INVALID",
                    path.as_posix(),
                    None,
                    (
                        f"ожидалось {len(expected)} блоков Mermaid, "
                        f"обнаружено {len(mermaid)}"
                    ),
                )
            )
        kinds = tuple(
            _first_content_line(fence.content)
            for fence in mermaid
        )
        if sorted(kinds) != sorted(expected):
            issues.append(
                ValidationIssue(
                    "MERMAID_KIND_INVALID",
                    path.as_posix(),
                    None,
                    (
                        f"ожидались {sorted(expected)}, "
                        f"обнаружены {sorted(kinds)}"
                    ),
                )
            )


def _first_content_line(content: str) -> str:
    return next(
        (
            line.strip()
            for line in content.splitlines()
            if line.strip()
        ),
        "",
    )


def _check_state_diagram(
    repo: Path,
    tracked_index: Mapping[Path, str],
    documents: dict[Path, MarkdownDocument],
    issues: list[ValidationIssue],
) -> None:
    runbook = documents.get(OPERATIONS_RUNBOOK)
    if runbook is None:
        return
    blocks = [
        fence
        for fence in runbook.fences
        if fence.language == "mermaid"
        and _first_content_line(fence.content) == "stateDiagram-v2"
    ]
    if len(blocks) != 1:
        return
    (
        expected_states,
        expected_transitions,
        expected_terminals,
    ) = _load_route_contract(
        repo,
        STATE_MODULE,
        tracked_index,
    )
    content_lines = blocks[0].content.splitlines()
    observed_transition_lines: list[tuple[str, str]] = []
    header_seen = False
    for index, line in enumerate(content_lines, start=1):
        if not line.strip():
            continue
        if not header_seen:
            header_seen = True
            if line.strip() == "stateDiagram-v2":
                continue
        match = STATE_TRANSITION_PATTERN.match(line)
        if match is not None:
            observed_transition_lines.append(
                (match.group(1), match.group(2))
            )
        elif "-->" in line:
            issues.append(
                ValidationIssue(
                    "STATE_DIAGRAM_TRANSITION_FORMAT_INVALID",
                    OPERATIONS_RUNBOOK.as_posix(),
                    blocks[0].line + index,
                    (
                        "переход должен иметь точный формат "
                        "SOURCE --> TARGET с четырьмя пробелами"
                    ),
                )
            )
        else:
            issues.append(
                ValidationIssue(
                    "STATE_DIAGRAM_CONTENT_INVALID",
                    OPERATIONS_RUNBOOK.as_posix(),
                    blocks[0].line + index,
                    (
                        "диаграмма должна содержать только заголовок, "
                        "пустые строки и канонические переходы"
                    ),
                )
            )
    observed_transitions = set(observed_transition_lines)
    observed_states = {
        state
        for transition in observed_transitions
        for state in transition
    }
    observed_terminals = observed_states - {
        before
        for before, _after in observed_transitions
    }
    if len(observed_transition_lines) != len(observed_transitions):
        counts: dict[tuple[str, str], int] = {}
        for transition in observed_transition_lines:
            counts[transition] = counts.get(transition, 0) + 1
        duplicates = [
            f"{before}->{after} ({count})"
            for (before, after), count in sorted(counts.items())
            if count > 1
        ]
        issues.append(
            ValidationIssue(
                "STATE_DIAGRAM_DUPLICATE_TRANSITION",
                OPERATIONS_RUNBOOK.as_posix(),
                blocks[0].line,
                f"повторяющиеся переходы={duplicates}",
            )
        )
    if observed_states != expected_states:
        issues.append(
            ValidationIssue(
                "STATE_DIAGRAM_STATES_MISMATCH",
                OPERATIONS_RUNBOOK.as_posix(),
                blocks[0].line,
                _set_difference_message(
                    expected_states,
                    observed_states,
                ),
            )
        )
    if observed_terminals != expected_terminals:
        issues.append(
            ValidationIssue(
                "STATE_DIAGRAM_TERMINALS_MISMATCH",
                OPERATIONS_RUNBOOK.as_posix(),
                blocks[0].line,
                _set_difference_message(
                    expected_terminals,
                    observed_terminals,
                ),
            )
        )
    if observed_transitions != expected_transitions:
        issues.append(
            ValidationIssue(
                "STATE_DIAGRAM_TRANSITIONS_MISMATCH",
                OPERATIONS_RUNBOOK.as_posix(),
                blocks[0].line,
                _transition_difference_message(
                    expected_transitions,
                    observed_transitions,
                ),
            )
        )


def _load_route_contract(
    repo: Path,
    path: Path,
    tracked_index: Mapping[Path, str],
) -> tuple[set[str], set[tuple[str, str]], set[str]]:
    mode = tracked_index.get(path)
    if mode not in REGULAR_GIT_MODES:
        raise ValidationSetupError(
            (
                "модуль состояний отсутствует в индексе Git "
                f"или имеет небезопасный режим: {path}"
            )
        )
    try:
        source = _read_regular_repo_file(
            repo,
            path,
            maximum_bytes=MAX_STATE_MODULE_BYTES,
        ).decode("utf-8")
    except (SourceFileError, UnicodeDecodeError) as exc:
        raise ValidationSetupError(
            f"невозможно безопасно прочитать модуль состояний {path}: {exc}"
        ) from exc
    try:
        return parse_route_contract(
            source,
            filename=str(repo / path),
        )
    except (SyntaxError, ValueError) as exc:
        raise ValidationSetupError(
            f"неверный контракт состояний в {path}: {exc}"
        ) from exc


def _set_difference_message(
    expected: set[str],
    observed: set[str],
) -> str:
    missing = sorted(expected - observed)
    extra = sorted(observed - expected)
    return f"отсутствуют={missing}; лишние={extra}"


def _transition_difference_message(
    expected: set[tuple[str, str]],
    observed: set[tuple[str, str]],
) -> str:
    missing = [
        f"{before}->{after}"
        for before, after in sorted(expected - observed)
    ]
    extra = [
        f"{before}->{after}"
        for before, after in sorted(observed - expected)
    ]
    return f"отсутствуют={missing}; лишние={extra}"


def _issue_sort_key(
    issue: ValidationIssue,
) -> tuple[str, int, str, str]:
    return (
        issue.path,
        issue.line if issue.line is not None else 0,
        issue.code,
        issue.message,
    )


if __name__ == "__main__":
    raise SystemExit(main())
