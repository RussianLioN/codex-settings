"""Живой процессный выбор пары корневого координатора версии 2."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, ClassVar, Mapping, Protocol, Sequence

from .canonical_json import domain_fingerprint
from .live_canary import AppServerError
from .model_catalog import AppServerModelCatalogInspector, ModelCatalogError
from .operation_deadline_v2 import OperationDeadlineExceededV2


_SELECTION = "first-verified-available"
_SELECTED = "SELECTED"
_UNAVAILABLE = "UNAVAILABLE"
_SHA256_CHARACTERS = frozenset("0123456789abcdef")


class CoordinatorCatalogInspectorV2(Protocol):
    def inspect(self) -> Mapping[str, frozenset[str]]: ...


@dataclass(frozen=True)
class CoordinatorSelectionV2:
    """Сохранённый только в процессе результат отдельной проверки координатора."""

    ACCOUNT_CATALOG_DOMAIN: ClassVar[str] = (
        "codex-smart/coordinator-account-catalog/v2"
    )
    ACCOUNT_CONTEXT_DOMAIN: ClassVar[str] = (
        "codex-smart/coordinator-account-context/v2"
    )

    selection: str
    status: str
    reason_code: str
    selected_pair: Mapping[str, str] | None
    candidate_index: int | None
    account_catalog_fingerprint: str | None
    account_context_fingerprint: str | None
    _account_catalog: tuple[tuple[str, tuple[str, ...]], ...] | None = None
    _candidates: tuple[tuple[str, str], ...] = ()
    _active_context_fingerprint: str | None = None

    def to_document(self) -> dict[str, object]:
        return {
            "selection": self.selection,
            "status": self.status,
            "reasonCode": self.reason_code,
            "selectedPair": (
                None if self.selected_pair is None else dict(self.selected_pair)
            ),
            "candidateIndex": self.candidate_index,
            "accountCatalogFingerprint": self.account_catalog_fingerprint,
            "accountContextFingerprint": self.account_context_fingerprint,
        }

    def recompute_account_catalog_fingerprint(self) -> str | None:
        if self._account_catalog is None:
            return None
        return domain_fingerprint(
            self.ACCOUNT_CATALOG_DOMAIN,
            _account_catalog_projection(self._account_catalog),
        )

    def recompute_account_context_fingerprint(
        self,
        *,
        active_context_fingerprint: str | None = None,
    ) -> str | None:
        catalog_fingerprint = self.recompute_account_catalog_fingerprint()
        active_context = (
            self._active_context_fingerprint
            if active_context_fingerprint is None
            else active_context_fingerprint
        )
        if active_context is None:
            return None
        _require_sha256(
            active_context,
            "active coordinator context fingerprint",
        )
        return _account_context_fingerprint(
            selection=self.selection,
            candidates=self._candidates,
            status=self.status,
            reason_code=self.reason_code,
            selected_pair=self.selected_pair,
            candidate_index=self.candidate_index,
            account_catalog_fingerprint=catalog_fingerprint,
            active_context_fingerprint=active_context,
        )


def collect_coordinator_selection_v2(
    *,
    selection: str,
    candidates: Sequence[Mapping[str, str]],
    inspector: CoordinatorCatalogInspectorV2,
    active_context_fingerprint: str,
) -> CoordinatorSelectionV2:
    """Один раз читает каталог и выбирает первого доступного кандидата."""

    if selection != _SELECTION:
        raise ValueError("coordinator selection strategy is unsupported")
    normalized_candidates = _normalize_candidates(candidates)
    _require_sha256(
        active_context_fingerprint,
        "active coordinator context fingerprint",
    )
    if not callable(getattr(inspector, "inspect", None)):
        raise TypeError("coordinator catalog inspector must provide inspect()")
    try:
        observed = _normalize_account_catalog(inspector.inspect())
    except ModelCatalogError as exc:
        return _failed_catalog_selection(
            selection=selection,
            candidates=normalized_candidates,
            reason_code=_coordinator_catalog_reason(exc.code),
            active_context_fingerprint=active_context_fingerprint,
        )
    except (AppServerError, OperationDeadlineExceededV2):
        return _failed_catalog_selection(
            selection=selection,
            candidates=normalized_candidates,
            reason_code="COORDINATOR_ACCOUNT_CATALOG_UNAVAILABLE",
            active_context_fingerprint=active_context_fingerprint,
        )

    catalog_fingerprint = domain_fingerprint(
        CoordinatorSelectionV2.ACCOUNT_CATALOG_DOMAIN,
        _account_catalog_projection(observed),
    )
    selected_index: int | None = None
    for index, (model, effort) in enumerate(normalized_candidates):
        efforts = dict(observed).get(model, ())
        if effort in efforts:
            selected_index = index
            break
    selected_pair = (
        None
        if selected_index is None
        else {
            "model": normalized_candidates[selected_index][0],
            "reasoningEffort": normalized_candidates[selected_index][1],
        }
    )
    status = _SELECTED if selected_pair is not None else _UNAVAILABLE
    reason_code = (
        "COORDINATOR_PAIR_SELECTED"
        if selected_pair is not None
        else "COORDINATOR_PAIR_UNAVAILABLE"
    )
    context_fingerprint = _account_context_fingerprint(
        selection=selection,
        candidates=normalized_candidates,
        status=status,
        reason_code=reason_code,
        selected_pair=selected_pair,
        candidate_index=selected_index,
        account_catalog_fingerprint=catalog_fingerprint,
        active_context_fingerprint=active_context_fingerprint,
    )
    return CoordinatorSelectionV2(
        selection=selection,
        status=status,
        reason_code=reason_code,
        selected_pair=selected_pair,
        candidate_index=selected_index,
        account_catalog_fingerprint=catalog_fingerprint,
        account_context_fingerprint=context_fingerprint,
        _account_catalog=observed,
        _candidates=normalized_candidates,
        _active_context_fingerprint=active_context_fingerprint,
    )


def inspect_coordinator_selection_v2(
    *,
    codex_executable: Path,
    codex_home: Path,
    runtime_parent: Path,
    selection: str,
    candidates: Sequence[Mapping[str, str]],
    active_context_fingerprint: str,
    inspector_factory: Callable[..., Any] = AppServerModelCatalogInspector,
) -> CoordinatorSelectionV2:
    """Создаёт один inspector и сохраняет результат его единственного чтения."""

    if not callable(inspector_factory):
        raise TypeError("coordinator inspector factory must be callable")
    if selection != _SELECTION:
        raise ValueError("coordinator selection strategy is unsupported")
    normalized_candidates = _normalize_candidates(candidates)
    _require_sha256(
        active_context_fingerprint,
        "active coordinator context fingerprint",
    )
    try:
        inspector = inspector_factory(
            codex_executable=codex_executable,
            codex_home=codex_home,
            runtime_parent=runtime_parent,
        )
    except ModelCatalogError as exc:
        return _failed_catalog_selection(
            selection=selection,
            candidates=normalized_candidates,
            reason_code=_coordinator_catalog_reason(exc.code),
            active_context_fingerprint=active_context_fingerprint,
        )
    except (AppServerError, OperationDeadlineExceededV2):
        return _failed_catalog_selection(
            selection=selection,
            candidates=normalized_candidates,
            reason_code="COORDINATOR_ACCOUNT_CATALOG_UNAVAILABLE",
            active_context_fingerprint=active_context_fingerprint,
        )
    return collect_coordinator_selection_v2(
        selection=selection,
        candidates=candidates,
        inspector=inspector,
        active_context_fingerprint=active_context_fingerprint,
    )


def coordinator_selection_from_health_v2(
    payload: Mapping[str, object],
    *,
    catalog_schema_version: int,
    candidates: Sequence[Mapping[str, str]],
) -> tuple[dict[str, object] | None, dict[str, str] | None]:
    """Связывает новый health с каталогом, сохраняя временный путь версии 1."""

    if catalog_schema_version not in {1, 2}:
        raise ValueError("coordinator catalog schema version is invalid")
    if not isinstance(payload, Mapping):
        raise TypeError("health payload must be a mapping")
    normalized_candidates = _normalize_candidates(candidates)
    raw_selection = payload.get("coordinatorSelection")
    if raw_selection is None:
        if catalog_schema_version == 2:
            raise ValueError("catalog v2 health has no coordinator selection")
        model, effort = normalized_candidates[0]
        return None, {
            "model": model,
            "reasoning_effort": effort,
        }
    selection = validate_coordinator_selection_document_v2(
        raw_selection,
        candidates=candidates,
    )
    active_context_fingerprint = payload.get("activationFingerprint")
    _require_sha256(
        active_context_fingerprint,
        "active coordinator context fingerprint",
    )
    expected_context_fingerprint = _account_context_fingerprint(
        selection=selection["selection"],
        candidates=normalized_candidates,
        status=selection["status"],
        reason_code=selection["reasonCode"],
        selected_pair=selection["selectedPair"],
        candidate_index=selection["candidateIndex"],
        account_catalog_fingerprint=selection[
            "accountCatalogFingerprint"
        ],
        active_context_fingerprint=active_context_fingerprint,
    )
    if (
        selection["accountContextFingerprint"]
        != expected_context_fingerprint
    ):
        raise ValueError("coordinator context fingerprint differs")
    pair = selection["selectedPair"]
    if pair is None:
        return selection, None
    return selection, {
        "model": pair["model"],
        "reasoning_effort": pair["reasoningEffort"],
    }


def validate_coordinator_selection_document_v2(
    value: object,
    *,
    candidates: Sequence[Mapping[str, str]] | None = None,
) -> dict[str, object]:
    """Строго проверяет процессную проекцию выбора из ``health``."""

    expected_keys = {
        "selection",
        "status",
        "reasonCode",
        "selectedPair",
        "candidateIndex",
        "accountCatalogFingerprint",
        "accountContextFingerprint",
    }
    if type(value) is not dict or set(value) != expected_keys:
        raise ValueError("coordinator selection fields differ")
    if value["selection"] != _SELECTION:
        raise ValueError("coordinator selection strategy differs")
    status = value["status"]
    if status not in {_SELECTED, _UNAVAILABLE}:
        raise ValueError("coordinator selection status is invalid")
    reason_code = value["reasonCode"]
    if (
        type(reason_code) is not str
        or not reason_code
        or any(
            character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
            for character in reason_code
        )
    ):
        raise ValueError("coordinator selection reason code is invalid")
    catalog_fingerprint = value["accountCatalogFingerprint"]
    context_fingerprint = value["accountContextFingerprint"]
    if catalog_fingerprint is not None and not _is_sha256(
        catalog_fingerprint
    ):
        raise ValueError("coordinator catalog fingerprint is invalid")
    if not _is_sha256(context_fingerprint):
        raise ValueError("coordinator context fingerprint is invalid")

    selected_pair = value["selectedPair"]
    candidate_index = value["candidateIndex"]
    if status == _SELECTED:
        if (
            reason_code != "COORDINATOR_PAIR_SELECTED"
            or type(selected_pair) is not dict
            or set(selected_pair) != {"model", "reasoningEffort"}
            or type(selected_pair["model"]) is not str
            or not selected_pair["model"]
            or type(selected_pair["reasoningEffort"]) is not str
            or not selected_pair["reasoningEffort"]
            or type(candidate_index) is not int
            or not 0 <= candidate_index < 8
            or catalog_fingerprint is None
        ):
            raise ValueError("selected coordinator pair is invalid")
        if candidates is not None:
            normalized = _normalize_candidates(candidates)
            if (
                candidate_index >= len(normalized)
                or normalized[candidate_index]
                != (
                    selected_pair["model"],
                    selected_pair["reasoningEffort"],
                )
            ):
                raise ValueError("selected coordinator candidate diverges")
    elif selected_pair is not None or candidate_index is not None:
        raise ValueError("unavailable coordinator selection carries a pair")
    elif reason_code == "COORDINATOR_PAIR_UNAVAILABLE":
        if catalog_fingerprint is None:
            raise ValueError("read coordinator catalog has no fingerprints")
    elif reason_code not in {
        "COORDINATOR_ACCOUNT_CATALOG_UNAVAILABLE",
        "COORDINATOR_ACCOUNT_CATALOG_INVALID",
    }:
        raise ValueError("unavailable coordinator reason code is invalid")
    elif catalog_fingerprint is not None:
        raise ValueError("failed coordinator catalog read has catalog fingerprint")
    return {
        **value,
        "selectedPair": (
            None if selected_pair is None else dict(selected_pair)
        ),
    }


def _normalize_candidates(
    candidates: Sequence[Mapping[str, str]],
) -> tuple[tuple[str, str], ...]:
    if not isinstance(candidates, Sequence) or isinstance(
        candidates, (str, bytes)
    ):
        raise TypeError("coordinator candidates must be a sequence")
    normalized: list[tuple[str, str]] = []
    for candidate in candidates:
        if (
            not isinstance(candidate, Mapping)
            or set(candidate) != {"model", "reasoningEffort"}
            or type(candidate["model"]) is not str
            or not candidate["model"]
            or type(candidate["reasoningEffort"]) is not str
            or not candidate["reasoningEffort"]
        ):
            raise ValueError("coordinator candidate is invalid")
        pair = (candidate["model"], candidate["reasoningEffort"])
        if pair in normalized:
            raise ValueError("coordinator candidates must be unique")
        normalized.append(pair)
    if not 1 <= len(normalized) <= 8:
        raise ValueError("coordinator candidates must contain 1 to 8 pairs")
    return tuple(normalized)


def _normalize_account_catalog(
    observed: Mapping[str, frozenset[str]],
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    if not isinstance(observed, Mapping):
        raise ModelCatalogError(
            "MODEL_LIST_INVALID",
            "account model catalog must be a mapping",
        )
    normalized: list[tuple[str, tuple[str, ...]]] = []
    for model in sorted(observed, key=lambda value: str(value).encode("utf-8")):
        efforts = observed[model]
        if (
            type(model) is not str
            or not model
            or not isinstance(efforts, frozenset)
            or any(type(effort) is not str or not effort for effort in efforts)
        ):
            raise ModelCatalogError(
                "MODEL_LIST_INVALID",
                "account model catalog is malformed",
            )
        normalized.append(
            (
                model,
                tuple(sorted(efforts, key=lambda value: value.encode("utf-8"))),
            )
        )
    return tuple(normalized)


def _account_catalog_projection(
    observed: tuple[tuple[str, tuple[str, ...]], ...],
) -> dict[str, object]:
    return {
        "models": [
            {
                "model": model,
                "supportedReasoningEfforts": list(efforts),
            }
            for model, efforts in observed
        ]
    }


def _account_context_fingerprint(
    *,
    selection: str,
    candidates: tuple[tuple[str, str], ...],
    status: object,
    reason_code: object,
    selected_pair: object,
    candidate_index: object,
    account_catalog_fingerprint: object,
    active_context_fingerprint: str,
) -> str:
    return domain_fingerprint(
        CoordinatorSelectionV2.ACCOUNT_CONTEXT_DOMAIN,
        {
            "selection": selection,
            "candidates": [
                {"model": model, "reasoningEffort": effort}
                for model, effort in candidates
            ],
            "status": status,
            "reasonCode": reason_code,
            "selectedPair": (
                None
                if selected_pair is None
                else dict(selected_pair)
            ),
            "candidateIndex": candidate_index,
            "accountCatalogFingerprint": account_catalog_fingerprint,
            "activeContextFingerprint": active_context_fingerprint,
        },
    )


def _failed_catalog_selection(
    *,
    selection: str,
    candidates: tuple[tuple[str, str], ...],
    reason_code: str,
    active_context_fingerprint: str,
) -> CoordinatorSelectionV2:
    context_fingerprint = _account_context_fingerprint(
        selection=selection,
        candidates=candidates,
        status=_UNAVAILABLE,
        reason_code=reason_code,
        selected_pair=None,
        candidate_index=None,
        account_catalog_fingerprint=None,
        active_context_fingerprint=active_context_fingerprint,
    )
    return CoordinatorSelectionV2(
        selection=selection,
        status=_UNAVAILABLE,
        reason_code=reason_code,
        selected_pair=None,
        candidate_index=None,
        account_catalog_fingerprint=None,
        account_context_fingerprint=context_fingerprint,
        _candidates=candidates,
        _active_context_fingerprint=active_context_fingerprint,
    )


def _coordinator_catalog_reason(code: str) -> str:
    if code in {"MODEL_LIST_INVALID", "MODEL_CATALOG_INVALID"}:
        return "COORDINATOR_ACCOUNT_CATALOG_INVALID"
    return "COORDINATOR_ACCOUNT_CATALOG_UNAVAILABLE"


def _require_sha256(value: object, label: str) -> str:
    if not _is_sha256(value):
        raise ValueError(f"{label} is invalid")
    return value


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and set(value) <= _SHA256_CHARACTERS
    )
