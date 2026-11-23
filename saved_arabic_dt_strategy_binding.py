"""Standalone binding for one saved Arabic digital-transformation strategy.

Revision 20261101-01 corrects the remaining ordinary backing-state
boundary in BIND-S1-F001 and the container-count boundary in
BIND-S1-F004. Those two findings remain pending review. The static
review MIZAN-BINDING-SLICE-REV02-STATIC-REVIEW-20261101-01 closed
BIND-S1-F002 and BIND-S1-F003. This is not an accepted or integrated
implementation.

This module does not authenticate a session, validate CSRF, authorize an
export task, or implement HTTP routing. It does not import the application.
A caller supplies record aliases, the authenticated caller id, and a
server-side reader or connection. Request JSON is not an authority for
caller identity, domain, language, document type, generation mode, or body.

None for strategy_id or artifact_id means that alias was not supplied.
The signature cannot distinguish an omitted keyword from an explicit None.
That is the internal contract for this function. It is not a check of JSON
key presence. A later HTTP route must decide what a supplied null alias
means. This module does not set that route policy.

The read is parameterized and scoped by both record id and owner. The
selected columns are the source-declared strategies fields plus the later
generation_mode column. strategies.document_type is not selected.

Accepted facts come from the owned row. The snapshot is an independent
frozen copy. Its digest identifies that snapshot only.

Writing this file does not activate a route. Tests of this module are a
separate source file and are not executed by importing this module.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

OWNED_STRATEGY_SQL = (
    "SELECT id, user_id, domain, language, content, sections_json, "
    "content_json, generation_mode "
    "FROM strategies WHERE id = ? AND user_id = ?"
)

DIGEST_FIELDS = (
    "record_id",
    "owner_id",
    "domain",
    "language",
    "document_type",
    "document_type_raw",
    "document_type_origin",
    "generation_mode",
    "content",
    "sections",
    "content_json",
)

READ_NOT_ATTEMPTED = "not_attempted"
READ_ROW = "row"
READ_NO_ROW = "no_row"
READ_ERROR = "error"

# Container bound for one saved snapshot. The saved root is the first
# container and its depth is 0. The 48th container has depth 47. A scalar
# stored in that container is not another container. Freeze and thaw both
# apply this bound only when the value is a container. This is a binding
# limit. It does not read or change the interpreter recursion limit.
_MAX_STRUCTURE_DEPTH = 48

_CANONICAL_ID = re.compile(r"[1-9][0-9]*\Z")
_DT_LABELS = frozenset({
    "digital transformation",
    "digital_transformation",
    "dt",
    "التحول الرقمي",
})
_ARABIC_LABELS = frozenset({"ar", "arabic", "عربي", "العربية"})
_GENERATION_MODES = frozenset({"drafting", "consulting", "assurance"})
_REQUIRED_ROW_KEYS = (
    "id",
    "user_id",
    "domain",
    "language",
    "content",
    "sections_json",
    "content_json",
    "generation_mode",
)
_DOCUMENT_TYPE_PATHS = (
    ("sections_json._document_type", ("sections", "_document_type")),
    ("content_json.document_type", ("content", "document_type")),
    (
        "content_json._contract_meta.document_type",
        ("content", "_contract_meta", "document_type"),
    ),
)
_LANGUAGE_PATHS = (
    ("sections", "_contract_meta", "lang"),
    ("sections", "_contract_meta", "language"),
    ("sections", "metadata", "language"),
    ("content", "_contract_meta", "lang"),
    ("content", "_contract_meta", "language"),
    ("content", "metadata", "language"),
)


class OwnedStrategyReadError(Exception):
    """A read failed. The public attribute is the original exception type name."""

    def __init__(self, error_type_name: str) -> None:
        self.error_type_name = str(error_type_name)
        super().__init__(self.error_type_name)


class _UnsupportedSavedValue(Exception):
    """A stored container holds a value this snapshot cannot freeze."""


class _DuplicateObjectKey(Exception):
    """A JSON object repeated a name. The values are not repaired."""


class _StructureLimit(Exception):
    """A stored structure is cyclic or deeper than the supported bound."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class FrozenList(tuple):
    """Immutable sequence. Callers must freeze items before construction."""

    def __new__(cls, items: Any) -> "FrozenList":
        return tuple.__new__(cls, tuple(items))

    def __repr__(self) -> str:
        return "FrozenList(" + repr(list(self)) + ")"


class FrozenMap(Mapping):
    """Immutable mapping. One tuple of pairs is the only backing store.

    Item lookup and iteration both read that tuple. Ordinary attribute
    assignment and deletion are refused after construction, including
    assignment or deletion of the backing tuple. A prebuilt FrozenMap is
    not itself proof that nested values were copied; _freeze rebuilds one.
    """

    __slots__ = ("_pairs",)

    def __init__(self, pairs: Any) -> None:
        stored = []
        seen = set()
        for key, value in pairs:
            if key in seen:
                raise _UnsupportedSavedValue
            seen.add(key)
            stored.append((key, value))
        object.__setattr__(self, "_pairs", tuple(stored))

    def __setattr__(self, name: str, value: Any) -> None:
        raise TypeError("FrozenMap does not support attribute assignment")

    def __delattr__(self, name: str) -> None:
        raise TypeError("FrozenMap does not support attribute deletion")

    def __getitem__(self, key: Any) -> Any:
        for stored_key, value in self._pairs:
            if stored_key == key:
                return value
        raise KeyError(key)

    def __iter__(self):
        for key, _value in self._pairs:
            yield key

    def __len__(self) -> int:
        return len(self._pairs)

    def __hash__(self) -> int:
        return hash(self._pairs)

    def __setitem__(self, key: Any, value: Any) -> None:
        raise TypeError("FrozenMap does not support item assignment")

    def __repr__(self) -> str:
        return "FrozenMap(" + repr(list(self._pairs)) + ")"


@dataclass(frozen=True)
class BindingRefusal:
    code: str
    detail: str


@dataclass(frozen=True)
class SavedStrategySnapshot:
    record_id: int
    owner_id: int
    domain: str
    domain_code: str
    domain_origin: str
    language: str
    language_code: str
    document_type: str
    document_type_raw: str
    document_type_origin: str
    generation_mode: str
    content: str
    sections: FrozenMap
    content_json: FrozenMap | None
    digest: str


@dataclass(frozen=True)
class BindingResult:
    accepted: bool
    snapshot: SavedStrategySnapshot | None
    refusal: BindingRefusal | None
    read_attempted: bool
    read_status: str


def _refuse(
        code: str,
        detail: str,
        *,
        read_attempted: bool,
        read_status: str,
) -> BindingResult:
    return BindingResult(
        accepted=False,
        snapshot=None,
        refusal=BindingRefusal(code, detail),
        read_attempted=read_attempted,
        read_status=read_status,
    )


def _parse_supplied_id(value: Any, *, required: bool) -> tuple[str, int | None]:
    """Return absent, missing, invalid, or ok.

    None is absent for an optional alias and missing for the required owner.
    A supplied empty string is invalid. Booleans, floats, containers, signs,
    leading zeros, fractions, and hash- prefixes are invalid. Positive ints
    and canonical decimal strings are ok. int() ValueError, including a
    digit string past the interpreter's conversion limit, is invalid. This
    function does not read or change that limit.
    """
    if value is None:
        return ("missing", None) if required else ("absent", None)
    if isinstance(value, bool) or isinstance(value, float):
        return ("invalid", None)
    if type(value) is int:
        if value > 0:
            return ("ok", value)
        return ("invalid", None)
    if isinstance(value, str):
        text = value.strip()
        if not _CANONICAL_ID.fullmatch(text):
            return ("invalid", None)
        try:
            parsed = int(text)
        except ValueError:
            return ("invalid", None)
        if parsed > 0:
            return ("ok", parsed)
        return ("invalid", None)
    return ("invalid", None)


def _classify_domain(raw: str) -> str | None:
    """Explicit digital-transformation labels only.

    The lookup copies the strip, case, hyphen, and space steps used for
    those labels. It does not copy the cyber substring fallback or the
    unknown-key return.
    """
    stripped = raw.strip()
    if not stripped:
        return None
    key = stripped.lower().replace("-", "_")
    key_sp = key.replace("_", " ")
    compact = stripped.lower().replace("-", " ").replace("_", " ")
    for candidate in (key, key_sp, compact):
        if candidate in _DT_LABELS:
            return "dt"
    return "other"


def _classify_language(raw: str) -> str | None:
    """Explicit Arabic labels only. A blank value is not Arabic."""
    token = raw.strip().lower()
    if not token:
        return None
    if token in _ARABIC_LABELS:
        return "ar"
    return "other"


def _column_label_decision(value: Any, classify) -> tuple[str, str | None]:
    if value is None:
        return ("missing", None)
    if not isinstance(value, str):
        return ("unsupported", None)
    kind = classify(value)
    if kind is None:
        return ("missing", None)
    if kind == "other":
        return ("unsupported", None)
    return ("ok", value)


def _walk(root: Any, path: tuple[str, ...]) -> tuple[str, Any]:
    """Walk a stored path.

    A missing root and a missing key are absent. A null value with further
    keys remaining is an absent subtree. A list, number, string, or other
    non-mapping in that same intermediate position is malformed_container.
    The leaf itself is returned as found, including null and blank strings.
    """
    if root is None:
        return ("absent", None)
    current = root
    last = len(path) - 1
    for index, key in enumerate(path):
        if not isinstance(current, Mapping):
            return ("malformed_container", None)
        if key not in current:
            return ("absent", None)
        current = current[key]
        if current is None and index < last:
            return ("absent", None)
    return ("found", current)


def _path_token(root: Any, path: tuple[str, ...]) -> tuple[str, Any]:
    state, current = _walk(root, path)
    if state != "found":
        return (state, None)
    if current is None or (isinstance(current, str) and current.strip() == ""):
        return ("absent", None)
    if isinstance(current, str):
        return ("present", current)
    return ("malformed", None)


def _path_exact(root: Any, path: tuple[str, ...]) -> tuple[str, Any]:
    state, current = _walk(root, path)
    if state != "found":
        return (state, None)
    if current is None:
        return ("absent", None)
    if isinstance(current, str):
        return ("present", current)
    return ("malformed", None)


def _object_from_pairs(pairs: list[tuple[Any, Any]]) -> dict[str, Any]:
    seen = set()
    ordered: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise _DuplicateObjectKey
        seen.add(key)
        ordered[key] = value
    return ordered


def _decode_json_value(value: str) -> tuple[str, Any]:
    """Decode JSON text without collapsing repeated object names.

    JSONDecodeError is caught before ValueError because it is a ValueError
    subclass. A numeric conversion failure remains a separate kind.
    """
    try:
        parsed = json.loads(value, object_pairs_hook=_object_from_pairs)
    except _DuplicateObjectKey:
        return ("duplicate", None)
    except json.JSONDecodeError:
        return ("decode", None)
    except ValueError:
        return ("number", None)
    except RecursionError:
        return ("depth", None)
    return ("value", parsed)


def _json_text_refusal(kind: str, *, duplicate_detail: str, malformed_code: str):
    if kind == "duplicate":
        return _refuse(
            "SAVED_JSON_DUPLICATE_KEY",
            duplicate_detail,
            read_attempted=True,
            read_status=READ_ROW,
        )
    if kind == "number":
        detail = "json_number"
    elif kind == "depth":
        detail = "json_depth"
    else:
        detail = duplicate_detail
    return _refuse(
        malformed_code,
        detail,
        read_attempted=True,
        read_status=READ_ROW,
    )


def _parse_sections(value: Any) -> FrozenMap | BindingResult:
    if value is None:
        return _refuse(
            "SAVED_SECTIONS_MISSING",
            "sections_missing",
            read_attempted=True,
            read_status=READ_ROW,
        )
    parsed = value
    if isinstance(value, str):
        kind, parsed = _decode_json_value(value)
        if kind != "value":
            return _json_text_refusal(
                kind,
                duplicate_detail="sections_json",
                malformed_code="SAVED_SECTIONS_MALFORMED",
            )
    if not isinstance(parsed, dict):
        return _refuse(
            "SAVED_SECTIONS_MALFORMED",
            "sections_not_object",
            read_attempted=True,
            read_status=READ_ROW,
        )
    try:
        frozen = _freeze(parsed)
    except _UnsupportedSavedValue:
        return _refuse(
            "SAVED_VALUE_UNSUPPORTED",
            "sections_value",
            read_attempted=True,
            read_status=READ_ROW,
        )
    except _StructureLimit as exc:
        return _refuse(
            "SAVED_VALUE_UNSUPPORTED",
            exc.reason,
            read_attempted=True,
            read_status=READ_ROW,
        )
    if not isinstance(frozen, FrozenMap):
        return _refuse(
            "SAVED_SECTIONS_MALFORMED",
            "sections_not_object",
            read_attempted=True,
            read_status=READ_ROW,
        )
    return frozen


def _sections_strategy_token(sections: FrozenMap) -> tuple[str, Any]:
    return _path_token(sections, ("_document_type",))


def _parse_content_json(value: Any, *, sections_strategy: bool) -> Any:
    if value is None:
        if sections_strategy:
            return None
        return _refuse(
            "SAVED_CONTENT_JSON_MALFORMED",
            "content_json_null",
            read_attempted=True,
            read_status=READ_ROW,
        )
    parsed = value
    if isinstance(value, str):
        kind, parsed = _decode_json_value(value)
        if kind != "value":
            return _json_text_refusal(
                kind,
                duplicate_detail="content_json",
                malformed_code="SAVED_CONTENT_JSON_MALFORMED",
            )
    if parsed is None:
        if sections_strategy:
            return None
        return _refuse(
            "SAVED_CONTENT_JSON_MALFORMED",
            "content_json_null",
            read_attempted=True,
            read_status=READ_ROW,
        )
    if not isinstance(parsed, dict):
        return _refuse(
            "SAVED_CONTENT_JSON_MALFORMED",
            "content_json_not_object",
            read_attempted=True,
            read_status=READ_ROW,
        )
    try:
        frozen = _freeze(parsed)
    except _UnsupportedSavedValue:
        return _refuse(
            "SAVED_VALUE_UNSUPPORTED",
            "content_json_value",
            read_attempted=True,
            read_status=READ_ROW,
        )
    except _StructureLimit as exc:
        return _refuse(
            "SAVED_VALUE_UNSUPPORTED",
            exc.reason,
            read_attempted=True,
            read_status=READ_ROW,
        )
    if not isinstance(frozen, FrozenMap):
        return _refuse(
            "SAVED_CONTENT_JSON_MALFORMED",
            "content_json_not_object",
            read_attempted=True,
            read_status=READ_ROW,
        )
    return frozen


def _freeze(value: Any) -> Any:
    try:
        return _freeze_bounded(value, set(), 0)
    except RecursionError:
        raise _StructureLimit("structure_depth")


def _freeze_bounded(value: Any, seen: set[int], depth: int) -> Any:
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, bool):
        return value
    if type(value) is int:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise _UnsupportedSavedValue
        return value
    if isinstance(value, (bytes, bytearray, memoryview, set, frozenset)):
        raise _UnsupportedSavedValue
    if isinstance(value, (Mapping, list, tuple)):
        if depth >= _MAX_STRUCTURE_DEPTH:
            raise _StructureLimit("structure_depth")
        marker = id(value)
        if marker in seen:
            raise _StructureLimit("structure_cycle")
        seen.add(marker)
        try:
            if isinstance(value, Mapping):
                pairs = []
                for key, inner in value.items():
                    if not isinstance(key, str):
                        raise _UnsupportedSavedValue
                    pairs.append((
                        key,
                        _freeze_bounded(inner, seen, depth + 1),
                    ))
                return FrozenMap(pairs)
            return FrozenList(
                _freeze_bounded(inner, seen, depth + 1) for inner in value
            )
        finally:
            seen.discard(marker)
    raise _UnsupportedSavedValue


def _thaw(value: Any, depth: int = 0) -> Any:
    """Restore plain containers for the one-time digest.

    The depth argument counts containers. The saved root is depth 0.
    A scalar is returned without consuming a container. The same 48
    container maximum used by _freeze_bounded applies here.
    """
    if isinstance(value, FrozenMap):
        if depth >= _MAX_STRUCTURE_DEPTH:
            raise _StructureLimit("structure_depth")
        return {
            key: _thaw(inner, depth + 1) for key, inner in value.items()
        }
    if isinstance(value, FrozenList):
        if depth >= _MAX_STRUCTURE_DEPTH:
            raise _StructureLimit("structure_depth")
        return [_thaw(inner, depth + 1) for inner in value]
    return value


def _digest_from_fields(fields: dict[str, Any]) -> str:
    payload = {name: fields[name] for name in DIGEST_FIELDS}
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _stored_document_type(
        sections: FrozenMap,
        content: FrozenMap | None,
) -> BindingResult | tuple[str, str, str]:
    roots = {"sections": sections, "content": content}
    present: list[tuple[str, str]] = []
    normalized: list[str] = []
    for origin, path in _DOCUMENT_TYPE_PATHS:
        root_name, *keys = path
        state, raw = _path_token(roots[root_name], tuple(keys))
        if state == "malformed_container":
            return _refuse(
                "DOCUMENT_TYPE_MALFORMED",
                "malformed_container",
                read_attempted=True,
                read_status=READ_ROW,
            )
        if state == "malformed":
            return _refuse(
                "DOCUMENT_TYPE_MALFORMED",
                "token_type",
                read_attempted=True,
                read_status=READ_ROW,
            )
        if state == "present":
            present.append((origin, raw))
            normalized.append(raw.strip().lower())
    if not present:
        return _refuse(
            "DOCUMENT_TYPE_UNRESOLVED",
            "no_stored_token",
            read_attempted=True,
            read_status=READ_ROW,
        )
    distinct = set(normalized)
    if len(distinct) != 1:
        return _refuse(
            "DOCUMENT_TYPE_CONFLICT",
            "tokens_disagree",
            read_attempted=True,
            read_status=READ_ROW,
        )
    token = normalized[0]
    origin = "+".join(item[0] for item in present)
    return (token, present[0][1], origin)


def stored_gap_assessment(sections_json: Any, content_json: Any) -> bool:
    """Recognize only consistent, explicit gap metadata from an owned strategy row."""
    sections = _parse_sections(sections_json)
    if isinstance(sections, BindingResult):
        return False
    content = _parse_content_json(content_json, sections_strategy=True)
    if isinstance(content, BindingResult):
        return False
    decision = _stored_document_type(sections, content)
    return isinstance(decision, tuple) and decision[0] == "gap_assessment"


def _document_type_decision(sections: FrozenMap, content: FrozenMap | None):
    decision = _stored_document_type(sections, content)
    if isinstance(decision, BindingResult):
        return decision
    token = decision[0]
    if token != "strategy":
        return _refuse(
            "DOCUMENT_TYPE_UNSUPPORTED",
            "not_strategy",
            read_attempted=True,
            read_status=READ_ROW,
        )
    return decision


def _language_conflict(
        sections: FrozenMap,
        content: FrozenMap | None,
) -> BindingResult | None:
    roots = {"sections": sections, "content": content}
    for root_name, *keys in _LANGUAGE_PATHS:
        state, raw = _path_token(roots[root_name], tuple(keys))
        if state == "absent":
            continue
        if state == "malformed_container":
            return _refuse(
                "LANGUAGE_CONFLICT",
                "malformed_container",
                read_attempted=True,
                read_status=READ_ROW,
            )
        if state == "malformed" or _classify_language(raw) != "ar":
            return _refuse(
                "LANGUAGE_CONFLICT",
                "stored_language_disagrees",
                read_attempted=True,
                read_status=READ_ROW,
            )
    return None


def _generation_mode_decision(
        column: Any,
        sections: FrozenMap,
        content: FrozenMap | None,
) -> BindingResult | str:
    if column is None or (isinstance(column, str) and column.strip() == ""):
        return _refuse(
            "GENERATION_MODE_MISSING",
            "stored_mode_missing",
            read_attempted=True,
            read_status=READ_ROW,
        )
    if not isinstance(column, str) or column not in _GENERATION_MODES:
        return _refuse(
            "GENERATION_MODE_UNSUPPORTED",
            "stored_mode_unsupported",
            read_attempted=True,
            read_status=READ_ROW,
        )
    for root in (sections, content):
        if root is None:
            continue
        state, raw = _path_exact(root, ("generation_mode",))
        if state == "absent":
            continue
        if state in ("malformed", "malformed_container") or raw != column:
            return _refuse(
                "GENERATION_MODE_CONFLICT",
                "stored_mode_disagrees",
                read_attempted=True,
                read_status=READ_ROW,
            )
    return column


def _content_decision(value: Any) -> BindingResult | str:
    if value is None or value == "":
        return _refuse(
            "SAVED_CONTENT_MISSING",
            "content_missing",
            read_attempted=True,
            read_status=READ_ROW,
        )
    if not isinstance(value, str):
        return _refuse(
            "SAVED_CONTENT_MALFORMED",
            "content_type",
            read_attempted=True,
            read_status=READ_ROW,
        )
    return value


def _row_mapping(row: Any) -> BindingResult | Mapping[str, Any]:
    if not isinstance(row, Mapping):
        return _refuse(
            "SAVED_ROW_MALFORMED",
            "not_a_mapping",
            read_attempted=True,
            read_status=READ_ROW,
        )
    if any(key not in row for key in _REQUIRED_ROW_KEYS):
        return _refuse(
            "SAVED_ROW_MALFORMED",
            "missing_key",
            read_attempted=True,
            read_status=READ_ROW,
        )
    return row


def _identity_decision(
        row: Mapping[str, Any],
        record_id: int,
        owner_id: int,
) -> BindingResult | None:
    if type(row["id"]) is not int or type(row["user_id"]) is not int:
        return _refuse(
            "ROW_IDENTITY_INCONSISTENT",
            "identity_type",
            read_attempted=True,
            read_status=READ_ROW,
        )
    if row["id"] != record_id or row["user_id"] != owner_id:
        return _refuse(
            "ROW_IDENTITY_INCONSISTENT",
            "identity_mismatch",
            read_attempted=True,
            read_status=READ_ROW,
        )
    return None


def _reference_decision(
        strategy_id: Any,
        artifact_id: Any,
) -> BindingResult | int:
    strategy_state, strategy_value = _parse_supplied_id(
        strategy_id, required=False)
    artifact_state, artifact_value = _parse_supplied_id(
        artifact_id, required=False)
    if strategy_state == "absent" and artifact_state == "absent":
        return _refuse(
            "REFERENCE_MISSING",
            "reference_missing",
            read_attempted=False,
            read_status=READ_NOT_ATTEMPTED,
        )
    if strategy_state == "invalid" and artifact_state == "invalid":
        return _refuse(
            "REFERENCE_INVALID",
            "reference_invalid",
            read_attempted=False,
            read_status=READ_NOT_ATTEMPTED,
        )
    if strategy_state == "invalid":
        return _refuse(
            "STRATEGY_ID_INVALID",
            "strategy_id_invalid",
            read_attempted=False,
            read_status=READ_NOT_ATTEMPTED,
        )
    if artifact_state == "invalid":
        return _refuse(
            "ARTIFACT_ID_INVALID",
            "artifact_id_invalid",
            read_attempted=False,
            read_status=READ_NOT_ATTEMPTED,
        )
    if (
            strategy_state == "ok"
            and artifact_state == "ok"
            and strategy_value != artifact_value
    ):
        return _refuse(
            "REFERENCE_CONFLICT",
            "aliases_differ",
            read_attempted=False,
            read_status=READ_NOT_ATTEMPTED,
        )
    if strategy_state == "ok":
        return strategy_value
    return artifact_value


def _accepted_snapshot(
        *,
        record_id: int,
        owner_id: int,
        domain: str,
        language: str,
        document_type: str,
        document_type_raw: str,
        document_type_origin: str,
        generation_mode: str,
        content: str,
        sections: FrozenMap,
        content_json: FrozenMap | None,
) -> BindingResult:
    try:
        digest_fields = {
            "record_id": record_id,
            "owner_id": owner_id,
            "domain": domain,
            "language": language,
            "document_type": document_type,
            "document_type_raw": document_type_raw,
            "document_type_origin": document_type_origin,
            "generation_mode": generation_mode,
            "content": content,
            "sections": _thaw(sections),
            "content_json": (
                None if content_json is None else _thaw(content_json)
            ),
        }
        digest = _digest_from_fields(digest_fields)
    except _StructureLimit as exc:
        return _refuse(
            "SAVED_VALUE_UNSUPPORTED",
            exc.reason,
            read_attempted=True,
            read_status=READ_ROW,
        )
    except RecursionError:
        return _refuse(
            "SAVED_VALUE_UNSUPPORTED",
            "structure_depth",
            read_attempted=True,
            read_status=READ_ROW,
        )
    except (TypeError, ValueError):
        return _refuse(
            "SAVED_VALUE_UNSUPPORTED",
            "digest_value",
            read_attempted=True,
            read_status=READ_ROW,
        )
    snapshot = SavedStrategySnapshot(
        record_id=record_id,
        owner_id=owner_id,
        domain=domain,
        domain_code="dt",
        domain_origin="strategies.domain",
        language=language,
        language_code="ar",
        document_type=document_type,
        document_type_raw=document_type_raw,
        document_type_origin=document_type_origin,
        generation_mode=generation_mode,
        content=content,
        sections=sections,
        content_json=content_json,
        digest=digest,
    )
    return BindingResult(
        accepted=True,
        snapshot=snapshot,
        refusal=None,
        read_attempted=True,
        read_status=READ_ROW,
    )


def bind_saved_arabic_dt_strategy(
        *,
        strategy_id: Any = None,
        artifact_id: Any = None,
        caller_id: Any,
        reader: Any,
) -> BindingResult:
    """Bind one owned saved Arabic digital-transformation strategy.

    strategy_id and artifact_id are request record aliases. Explicit None
    means the alias was not supplied; this function cannot see whether the
    keyword was omitted. caller_id is the authenticated owner supplied by
    trusted server code. reader is a server-side dependency with
    read_owned_strategy(record_id, owner_id).

    Keyword arguments other than these four, including content, domain,
    language, document_type, generation_mode, and csrf_valid, are rejected
    by the signature before a read. That rejection does not decide whether
    a future HTTP route must reject or ignore the mere presence of those
    fields, including an explicit JSON null alias.
    """
    owner_state, owner_id = _parse_supplied_id(caller_id, required=True)
    if owner_state != "ok":
        detail = "caller_missing" if owner_state == "missing" else "caller_invalid"
        return _refuse(
            "CALLER_INVALID",
            detail,
            read_attempted=False,
            read_status=READ_NOT_ATTEMPTED,
        )
    record = _reference_decision(strategy_id, artifact_id)
    if isinstance(record, BindingResult):
        return record
    read = getattr(reader, "read_owned_strategy", None)
    if not callable(read):
        raise TypeError("reader must provide read_owned_strategy")
    try:
        row = read(record, owner_id)
    except OwnedStrategyReadError as exc:
        return _refuse(
            "SAVED_STRATEGY_READ_FAILED",
            exc.error_type_name,
            read_attempted=True,
            read_status=READ_ERROR,
        )
    except Exception as exc:
        return _refuse(
            "SAVED_STRATEGY_READ_FAILED",
            type(exc).__name__,
            read_attempted=True,
            read_status=READ_ERROR,
        )
    if row is None:
        return _refuse(
            "OWNED_STRATEGY_ABSENT",
            "no_owned_row",
            read_attempted=True,
            read_status=READ_NO_ROW,
        )
    mapped = _row_mapping(row)
    if isinstance(mapped, BindingResult):
        return mapped
    identity = _identity_decision(mapped, record, owner_id)
    if identity is not None:
        return identity
    sections = _parse_sections(mapped["sections_json"])
    if isinstance(sections, BindingResult):
        return sections
    section_token = _sections_strategy_token(sections)
    if section_token[0] == "malformed_container":
        return _refuse(
            "DOCUMENT_TYPE_MALFORMED",
            "malformed_container",
            read_attempted=True,
            read_status=READ_ROW,
        )
    if section_token[0] == "malformed":
        return _refuse(
            "DOCUMENT_TYPE_MALFORMED",
            "token_type",
            read_attempted=True,
            read_status=READ_ROW,
        )
    sections_strategy = (
        section_token[0] == "present"
        and section_token[1].strip().lower() == "strategy"
    )
    content_json = _parse_content_json(
        mapped["content_json"],
        sections_strategy=sections_strategy,
    )
    if isinstance(content_json, BindingResult):
        return content_json
    document_type = _document_type_decision(sections, content_json)
    if isinstance(document_type, BindingResult):
        return document_type
    dtype, dtype_raw, dtype_origin = document_type
    domain_state, domain = _column_label_decision(
        mapped["domain"], _classify_domain)
    if domain_state == "missing":
        return _refuse(
            "DOMAIN_MISSING",
            "domain_missing",
            read_attempted=True,
            read_status=READ_ROW,
        )
    if domain_state != "ok":
        return _refuse(
            "DOMAIN_UNSUPPORTED",
            "domain_not_dt",
            read_attempted=True,
            read_status=READ_ROW,
        )
    language_state, language = _column_label_decision(
        mapped["language"], _classify_language)
    if language_state == "missing":
        return _refuse(
            "LANGUAGE_MISSING",
            "language_missing",
            read_attempted=True,
            read_status=READ_ROW,
        )
    if language_state != "ok":
        return _refuse(
            "LANGUAGE_UNSUPPORTED",
            "language_not_arabic",
            read_attempted=True,
            read_status=READ_ROW,
        )
    language_refusal = _language_conflict(sections, content_json)
    if language_refusal is not None:
        return language_refusal
    mode = _generation_mode_decision(
        mapped["generation_mode"], sections, content_json)
    if isinstance(mode, BindingResult):
        return mode
    content = _content_decision(mapped["content"])
    if isinstance(content, BindingResult):
        return content
    return _accepted_snapshot(
        record_id=record,
        owner_id=owner_id,
        domain=domain,
        language=language,
        document_type=dtype,
        document_type_raw=dtype_raw,
        document_type_origin=dtype_origin,
        generation_mode=mode,
        content=content,
        sections=sections,
        content_json=content_json,
    )


def _mapping_from_driver_row(row: Any) -> dict[str, Any]:
    if isinstance(row, Mapping):
        return {key: row[key] for key in row}
    keys = getattr(row, "keys", None)
    if callable(keys):
        return {key: row[key] for key in keys()}
    raise OwnedStrategyReadError("RowShape")


class OwnedStrategyReadAdapter:
    """Owner-scoped reader over a DB-API connection.

    The connection is supplied by server code. This adapter does not open a
    database and does not import sqlite3. execute exceptions become
    OwnedStrategyReadError carrying the exception type name only.
    """

    def __init__(self, connection: Any) -> None:
        self._connection = connection

    def read_owned_strategy(self, record_id: int, owner_id: int) -> Any:
        if (
                type(record_id) is not int
                or type(owner_id) is not int
                or record_id <= 0
                or owner_id <= 0
        ):
            raise OwnedStrategyReadError("IdentifierType")
        try:
            cursor = self._connection.execute(
                OWNED_STRATEGY_SQL,
                (record_id, owner_id),
            )
            row = cursor.fetchone()
        except OwnedStrategyReadError:
            raise
        except Exception as exc:
            raise OwnedStrategyReadError(type(exc).__name__) from None
        if row is None:
            return None
        return _mapping_from_driver_row(row)
