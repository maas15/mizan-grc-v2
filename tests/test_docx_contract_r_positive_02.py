"""Contract R saved Arabic DT DOCX verification harness.

Correction 02 of the isolated eight-case source. Authoring did not import
the application, collect this module, or call these cases.

A future run keeps the handlers, binder, export gate, selector,
authoritative route, quality functions, renderer adapter, writer, and
worker threads real. Wrappers record the real call and return or raise
whatever the real function returns or raises.
"""

import hashlib
import json
import os
import re
import sqlite3
import threading
import time
import zipfile
import xml.etree.ElementTree as ET
from io import BytesIO
from pathlib import Path

import app as app_module
from docx import Document
from docx.text.run import Run

import release_engine_v3.canonical_document as canon
import release_engine_v3.orchestrator as orchestrator
import release_engine_v3.rel31_authority as rel31
import release_engine_v3.rel32_frozen_export_lock as rel32
from release_engine_v3.contracts import ExportManifest, FinalDocumentArtifact


SECTION_ORDER = (
    "vision",
    "pillars",
    "environment",
    "gaps",
    "roadmap",
    "kpis",
    "confidence",
    "governance",
    "traceability",
)
ACCEPTED_SHA256 = {
    "positive_fixture": "b7a333a41a7cebf4e9747cafb74d9ae1b31d17d4c3df8255e5a130acf03f3495",
    "positive_expected": "d83a727971abd8f5af4f0250a5ca79a689876584d030312cd88bfcc57e99c240",
    "refusal_fixture": "03fef15d3982faf6751da59958fe2f3e2254889dd6164e6e55eba8e3189dc96e",
    "refusal_expected": "446b5d44a8fa04aa643068de4184b470a1194b51b20037439744f0a2be571410",
}
POSITIVE_FIXTURE = Path(os.environ.get(
    "MIZAN_DOCX_POSITIVE_FIXTURE",
    "/opt/cursor/artifacts/mizan-contract-r-positive-preparation-20261102-02/"
    "MIZAN_CONTRACT_R_POSITIVE_STRATEGY_02.md",
))
POSITIVE_EXPECTED = Path(os.environ.get(
    "MIZAN_DOCX_POSITIVE_EXPECTED",
    "/opt/cursor/artifacts/mizan-contract-r-positive-preparation-20261102-02/"
    "MIZAN_CONTRACT_R_POSITIVE_EXPECTED_CONTENT_02.json",
))
REFUSAL_FIXTURE = Path(os.environ.get(
    "MIZAN_DOCX_REFUSAL_FIXTURE",
    "/opt/cursor/artifacts/docx-real-render-preparation-20261102/"
    "REAL_DOCX_STRATEGY_FIXTURE.md",
))
REFUSAL_EXPECTED = Path(os.environ.get(
    "MIZAN_DOCX_REFUSAL_EXPECTED",
    "/opt/cursor/artifacts/docx-real-render-preparation-20261102/"
    "REAL_DOCX_EXPECTED_CONTENT.json",
))
OWNER_ID = 7
DEADLINE_SECONDS = int(os.environ.get("MIZAN_DOCX_DEADLINE_SECONDS", "120"))
CSRF = "synthetic-csrf-token-docx-contract-r-02"
OBJECTIVE_REFUSAL = "rel3_generation_contract_failed:objectives"
SYNC_REFUSAL_REASON = "rel3_export_evidence_failed"
RESPONSE_BLOCKER_LIMIT = 12
SAVED_WRITER_DOMAINS = frozenset({
    "dt",
    "Digital Transformation",
    "التحول الرقمي",
})
FRESH_REPAIR_TAGS = (
    "saved_docx_fidelity:original_snapshot_validated",
    "saved_docx_fidelity:validator_replacements_not_applied",
)
FIXTURE_RECORD_IDS = (701, 702)
# Visible forms justified by the corrected proposed app.py.
# _build_document_control_rows maps doc_type strategy to this Arabic value
# at the Arabic branch (label نوع الوثيقة). artifact_status is copied from
# metadata status with no Arabic alias; the saved token is publishable.
# The same function's Arabic default مسودة is a conflicting status value.
VISIBLE_DOCUMENT_TYPE = "وثيقة استراتيجية"
VISIBLE_ARTIFACT_STATUS = "publishable"
CONFLICTING_STATUS_VALUES = ("مسودة", "Draft")
CONTROL_LABELS = (
    "المنظمة",
    "القطاع",
    "المجال",
    "نوع الوثيقة",
    "التصنيف",
    "الإصدار",
    "الحالة",
    "تاريخ الإعداد",
    "أعد بواسطة",
    "Organization",
    "Sector",
    "Domain",
    "Document Type",
    "Classification",
    "Version",
    "Status",
    "Prepared",
    "Prepared by",
)
# Literals emitted by that control-row function and the DOCX cover block.
COVER_CHROME = (
    "سري",
    "Confidential",
    "1.0",
    "منصة ميزان GRC",
    "Mizan GRC Platform",
    "—",
)
# Label-to-field association for a control row. A row is not required.
# A pre-body paragraph equal to the accepted value can satisfy the same
# field. Title labels are recognized when a row presents them. They are
# source-justified document-title labels. _build_document_control_rows
# does not emit them, and this harness does not require that row.
FIELD_CONTROL_LABELS = (
    ("المنظمة", "organization"),
    ("Organization", "organization"),
    ("القطاع", "sector"),
    ("Sector", "sector"),
    ("المجال", "domain_display"),
    ("Domain", "domain_display"),
    ("نوع الوثيقة", "document_type"),
    ("Document Type", "document_type"),
    ("الحالة", "artifact_status"),
    ("Status", "artifact_status"),
    ("عنوان الوثيقة", "document_title"),
    ("Document Title", "document_title"),
)

_ORIG_THREAD = threading.Thread
_UNRESOLVED_PRIOR_CASE = None
_OBS_LOCK = threading.Lock()
_ACTIVE_DEADLINE = [None]


class RecordingThread(_ORIG_THREAD):
    """The real Thread. The export worker waits at entry until released.

    The wait lets the test read the handler's pending store entry before
    the real target can replace it. The wrapper does not write a task
    entry. After release, the real target runs. If the deadline expires
    first, the wrapper returns without writing a terminal state.
    """

    created = []

    def __init__(self, *args, **kwargs):
        target = kwargs.get("target", None)
        if target is None and len(args) >= 2:
            target = args[1]
        self._export_worker = getattr(target, "__name__", "") == "_build"
        self._entered = threading.Event()
        self._release = threading.Event()
        self._barrier_expired = False
        if self._export_worker:
            real_target = target

            def _build(*target_args, **target_kwargs):
                self._entered.set()
                deadline = _ACTIVE_DEADLINE[0]
                timeout = None
                if deadline is not None:
                    timeout = max(0.0, deadline - time.monotonic())
                if not self._release.wait(timeout):
                    self._barrier_expired = True
                    return None
                return real_target(*target_args, **target_kwargs)

            _build.__name__ = "_build"
            if "target" in kwargs or not args:
                kwargs = dict(kwargs)
                kwargs["target"] = _build
            else:
                args = (args[0], _build) + tuple(args[2:])
        super().__init__(*args, **kwargs)
        RecordingThread.created.append(self)

    def start(self):
        return super().start()


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _run_dir():
    return Path(os.environ["DATABASE_PATH"]).parent


def _write_bytes(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {"path": str(path), "bytes": len(data), "sha256": _sha(data)}


def _write_text(path, text):
    data = text.encode("utf-8")
    if not data.endswith(b"\n"):
        data += b"\n"
    return _write_bytes(path, data)


def _edge(value):
    """Route and writer handoff whitespace is an edge strip only."""
    return str(value or "").strip()


def _extract_norm(value):
    """Extraction-only conversion. It is not the handoff edge strip."""
    text = str(value or "").replace("\u00a0", " ")
    return re.sub(r"\s+", " ", text).strip()


def _note(observations, name, detail):
    with _OBS_LOCK:
        observations["order"].append({
            "name": name,
            "detail": detail,
            "monotonic": time.monotonic(),
        })


def _block_if_prior_worker_unresolved():
    prior = _UNRESOLVED_PRIOR_CASE
    if not prior:
        return
    lifecycle = prior["lifecycle"]
    thread = lifecycle.get("thread")
    alive = bool(thread is not None and thread.is_alive())
    if alive or not lifecycle.get("restored"):
        raise AssertionError(
            "prior_worker_unresolved:"
            + prior["name"]
            + ":alive="
            + str(alive).lower()
        )


def _remember_case(name, lifecycle):
    global _UNRESOLVED_PRIOR_CASE
    thread = lifecycle.get("thread")
    alive = bool(thread is not None and thread.is_alive())
    if alive or not lifecycle.get("restored"):
        _UNRESOLVED_PRIOR_CASE = {"name": name, "lifecycle": lifecycle}
    else:
        _UNRESOLVED_PRIOR_CASE = None


def _current_workers(lifecycle):
    """Export workers created after this case's mark.

    Threads recorded by an earlier case stay before the mark. A missing
    mark selects no thread, so a case cannot adopt a prior worker.
    """
    created = RecordingThread.created
    mark = lifecycle.get("worker_mark")
    if not isinstance(mark, int) or mark < 0 or mark > len(created):
        return []
    return [
        thread for thread in created[mark:]
        if getattr(thread, "_export_worker", False)
    ]


def _export_thread(lifecycle):
    found = _current_workers(lifecycle)
    if found:
        return found[-1]
    return None


def _release_export_barrier(lifecycle):
    released = 0
    for thread in _current_workers(lifecycle):
        release = getattr(thread, "_release", None)
        if release is not None:
            release.set()
            released += 1
    return released


def _join_recorded_worker(lifecycle):
    if lifecycle.get("join_invoked"):
        return lifecycle.get("thread")
    if lifecycle.get("thread") is None:
        lifecycle["thread"] = _export_thread(lifecycle)
    thread = lifecycle.get("thread")
    if thread is None:
        return None
    deadline = lifecycle.get("deadline")
    remaining = 0.0 if deadline is None else max(0.0, deadline - time.monotonic())
    thread.join(remaining)
    lifecycle["join_invoked"] = True
    return thread


def _accepted_bytes(path, digest):
    data = Path(path).read_bytes()
    actual = _sha(data)
    if actual != digest:
        raise AssertionError("identity_mismatch:" + str(path) + ":" + actual)
    return data


def _load_pair(record):
    if record == 702:
        fixture = _accepted_bytes(POSITIVE_FIXTURE, ACCEPTED_SHA256["positive_fixture"])
        expected_bytes = _accepted_bytes(
            POSITIVE_EXPECTED, ACCEPTED_SHA256["positive_expected"])
    elif record == 701:
        fixture = _accepted_bytes(REFUSAL_FIXTURE, ACCEPTED_SHA256["refusal_fixture"])
        expected_bytes = _accepted_bytes(
            REFUSAL_EXPECTED, ACCEPTED_SHA256["refusal_expected"])
    else:
        raise AssertionError("record_not_in_harness:" + str(record))
    if fixture.count(b"\r") or not fixture.endswith(b"\n"):
        raise AssertionError("fixture_newline_identity:" + str(record))
    text = fixture.decode("utf-8")
    expected = json.loads(expected_bytes.decode("utf-8"))
    sections = {}
    for key in SECTION_ORDER:
        item = expected["saved_sections"][key]
        sections[key] = item["text"] if isinstance(item, dict) else item
        if not isinstance(sections[key], str) or not sections[key].strip():
            raise AssertionError("section_missing:" + key)
    return text, expected, sections, fixture, expected_bytes


def _assert_body_layout(record, fixture_text, sections):
    body = fixture_text.encode("utf-8")
    parts = [sections[key].encode("utf-8") for key in SECTION_ORDER]
    if record == 701:
        if len(body) != 6645 or sum(len(part) for part in parts) != 6637:
            raise AssertionError("record_701_body_size")
        joined = sections["vision"]
        for key in SECTION_ORDER[1:]:
            joined += "\n" + sections[key]
        if joined != fixture_text or "".join(sections[key] for key in SECTION_ORDER) == fixture_text:
            raise AssertionError("record_701_separator_layout")
        return
    if "".join(sections[key] for key in SECTION_ORDER) != fixture_text:
        raise AssertionError("record_702_section_concatenation")


def _cleanup_process_state(observations):
    """Registry and frozen-lock cleanup, then the real render-tree cache.

    clear_rel3_caches is the real orchestrator function. Its cache key is
    artifact id plus canonical hash, and a hit returns without assigning
    render_tree_hash. Calling it here is cache maintenance. It is not the
    proof that a later resolver returned the registered object.
    """
    canon.clear_artifact_registry()
    rel32.clear_rel32_frozen_export_lock()
    orchestrator.clear_rel3_caches()
    observations["order"] = []
    observations["resolver"] = []
    observations["refusal"] = []
    observations["quality"] = []
    observations["repairs"] = []
    observations["exports"] = []
    observations["writer_calls"] = []
    observations["problems"] = []
    for key in ("701", "702"):
        if key in canon._ARTIFACT_REGISTRY:
            raise AssertionError("stale_registry_key:" + key)


def _secret_file_absent():
    secret = Path(app_module.__file__).resolve().parent / ".secret_key"
    if secret.exists():
        raise AssertionError("secret_file_present:" + str(secret))


def _assert_database_path():
    expected = os.environ["DATABASE_PATH"]
    if app_module.config.DB_PATH != expected:
        raise AssertionError(
            "database_path_mismatch:" + str(app_module.config.DB_PATH))
    if os.environ.get("MIZAN_DOCX_DATABASE_PATH") not in (None, "", expected):
        raise AssertionError("harness_database_alias_mismatch")
    _secret_file_absent()


def _sections_for_row(sections):
    row = {key: sections[key] for key in SECTION_ORDER}
    row["_document_type"] = "strategy"
    return row


def _saved_specification(record, expected):
    if record == 702:
        spec = expected["database_specification"]
        user = spec["users_design_example"]
        strategy = spec["strategies_candidate"]
        gate = spec["traceability_records_gate_row"]
        context = expected["saved_context"]
    else:
        spec = expected["database_row"]
        user = spec["users_insert_order_first"]
        strategy = spec["strategies"]
        gate = spec["traceability_records_gate_row"]
        context = {
            "organization": strategy["org_name"],
            "sector": strategy["sector"],
            "document_title": strategy["document_title"],
            "domain_display": strategy["domain"],
            "domain_code": "dt",
            "language_code": strategy["language"],
            "document_type": "strategy",
            "generation_mode": strategy["generation_mode"],
            "artifact_status": strategy["artifact_status"],
        }
    return user, strategy, gate, context


def _open_db():
    conn = sqlite3.connect(os.environ["DATABASE_PATH"])
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _insert(record, expected, fixture_text, sections):
    """Seed one fixture record without deleting a user that rows still reference.

    Foreign keys stay enabled. Traceability rows and both fixture strategy
    rows are removed before the shared owner is inserted or updated. The
    owner row is not deleted. Unrelated users and strategy ids stay.
    """
    user, strategy, gate, _context = _saved_specification(record, expected)
    conn = _open_db()
    try:
        if conn.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise AssertionError("foreign_keys_disabled")
        conn.execute(
            "DELETE FROM traceability_records "
            "WHERE user_id = ? AND artifact_id IN (?, ?)",
            (OWNER_ID, FIXTURE_RECORD_IDS[0], FIXTURE_RECORD_IDS[1]),
        )
        conn.execute(
            "DELETE FROM strategies WHERE id IN (?, ?)",
            FIXTURE_RECORD_IDS,
        )
        existing = conn.execute(
            "SELECT id FROM users WHERE id = ?",
            (user["id"],),
        ).fetchone()
        if existing is None:
            conn.execute(
                "INSERT INTO users "
                "(id, username, email, password_hash, role, is_active) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    user["id"], user["username"], user["email"],
                    user["password_hash"], user["role"], user["is_active"],
                ),
            )
        else:
            conn.execute(
                "UPDATE users SET username = ?, email = ?, password_hash = ?, "
                "role = ?, is_active = ? WHERE id = ?",
                (
                    user["username"], user["email"], user["password_hash"],
                    user["role"], user["is_active"], user["id"],
                ),
            )
        conn.execute(
            "INSERT INTO strategies ("
            "id, user_id, domain, language, generation_mode, artifact_status, "
            "publishability_score, org_name, sector, document_title, content, "
            "content_json, sections_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record,
                OWNER_ID,
                strategy["domain"],
                strategy["language"],
                strategy["generation_mode"],
                strategy["artifact_status"],
                strategy["publishability_score"],
                strategy["org_name"],
                strategy["sector"],
                strategy["document_title"],
                fixture_text,
                None,
                json.dumps(_sections_for_row(sections), ensure_ascii=False),
            ),
        )
        conn.execute(
            "INSERT INTO traceability_records ("
            "user_id, artifact_type, artifact_id, section_key, "
            "source_frameworks, evidence_sufficiency, linked_kpis, "
            "linked_roadmap_tasks) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                OWNER_ID,
                "strategy",
                str(record),
                gate["section_key"],
                gate["source_frameworks"],
                gate["evidence_sufficiency"],
                gate["linked_kpis"],
                gate["linked_roadmap_tasks"],
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _assert_disposable_database(record, expected):
    """Read back the fixture rows. This check is not registry cleanup."""
    user, strategy, gate, _context = _saved_specification(record, expected)
    conn = _open_db()
    try:
        foreign_keys = conn.execute("PRAGMA foreign_keys").fetchone()[0]
        owner = conn.execute(
            "SELECT id, username, email, role, is_active FROM users WHERE id = ?",
            (OWNER_ID,),
        ).fetchone()
        strategies = conn.execute(
            "SELECT id, user_id, language, generation_mode, artifact_status, "
            "content_json FROM strategies WHERE id IN (?, ?) ORDER BY id",
            FIXTURE_RECORD_IDS,
        ).fetchall()
        gates = conn.execute(
            "SELECT user_id, artifact_type, artifact_id, section_key "
            "FROM traceability_records "
            "WHERE user_id = ? AND artifact_id IN (?, ?) ORDER BY artifact_id",
            (OWNER_ID, FIXTURE_RECORD_IDS[0], FIXTURE_RECORD_IDS[1]),
        ).fetchall()
        other_users = conn.execute(
            "SELECT COUNT(*) FROM users WHERE id != ?",
            (OWNER_ID,),
        ).fetchone()[0]
    finally:
        conn.close()
    state = {
        "foreign_keys": foreign_keys,
        "owner_id": None if owner is None else owner[0],
        "owner_username": None if owner is None else owner[1],
        "strategy_ids": [row[0] for row in strategies],
        "strategy_user_ids": [row[1] for row in strategies],
        "gate_artifact_ids": [row[2] for row in gates],
        "unrelated_user_count_observed": other_users,
        "checked_separately_from_registry_cleanup": True,
    }
    if foreign_keys != 1:
        raise AssertionError("database_fixture_foreign_keys")
    if owner is None or owner[1] != user["username"] or owner[2] != user["email"]:
        raise AssertionError(
            "database_fixture_owner:" + json.dumps(state, ensure_ascii=False))
    if owner[3] != user["role"] or owner[4] != user["is_active"]:
        raise AssertionError("database_fixture_owner_role")
    if state["strategy_ids"] != [record] or strategies[0][1] != OWNER_ID:
        raise AssertionError(
            "database_fixture_strategies:" + json.dumps(state, ensure_ascii=False))
    if strategies[0][2] != strategy["language"] or strategies[0][3] != strategy["generation_mode"]:
        raise AssertionError("database_fixture_saved_mode")
    if strategies[0][4] != strategy["artifact_status"] or strategies[0][5] is not None:
        raise AssertionError("database_fixture_status_or_content_json")
    if state["gate_artifact_ids"] != [record]:
        raise AssertionError(
            "database_fixture_gates:" + json.dumps(state, ensure_ascii=False))
    if gates[0][1] != "strategy" or gates[0][3] != gate["section_key"]:
        raise AssertionError("database_fixture_gate_fields")
    return state


def _payload(record, expected):
    _user, strategy, _gate, context = _saved_specification(record, expected)
    if record == 702:
        request = expected["prospective_request_context"]
        content = request["content"]
        filename = request["filename"]
        org_name = request["org_name"]
        sector = request["sector"]
        domain = request["domain"]
    else:
        content = (
            "CLIENT CONFLICT MARKER: unsaved English drafting sentence "
            "must not appear in the DOCX."
        )
        filename = "dt-consulting-strategy-701"
        org_name = strategy["org_name"]
        sector = strategy["sector"]
        domain = "Digital Transformation"
    if "risk" in (str(expected.get("artifact_type") or ""),):
        raise AssertionError("risk_namespace_selected")
    return {
        "content": content,
        "filename": filename,
        "language": "en",
        "org_name": org_name,
        "sector": sector,
        "doc_type": "risk",
        "domain": domain,
        "selected_frameworks": ["DGA"],
        "artifact_id": record,
        "strategy_id": record,
        "artifact_type": "strategy",
        "document_type": "strategy",
        "generation_mode": "drafting",
        "_saved_context_for_observations": {
            "organization": context["organization"],
            "document_title": context["document_title"],
            "domain_display": context["domain_display"],
            "language_code": "ar",
            "document_type": "strategy",
            "generation_mode": context["generation_mode"],
            "owner_id": OWNER_ID,
            "record_id": record,
        },
    }


def _claim(record, fixture_text, sections):
    return {
        "route": "docx",
        "domain_code": "dt",
        "language_code": "ar",
        "document_type": "strategy",
        "record_id": record,
        "owner_id": OWNER_ID,
        "content_sha256": canon.saved_docx_content_digest(fixture_text),
        "sections_sha256": canon.saved_docx_section_digest(sections),
    }


def _register_702(fixture_text, sections, observations):
    legacy = {
        "sections": {key: sections[key] for key in SECTION_ORDER},
        "final_markdown": fixture_text,
        "domain": "dt",
        "language": "ar",
        "lang": "ar",
        "document_type": "strategy",
        "strategy_id": "702",
        "artifact_id": "702",
        "_rel32_export_user_id": OWNER_ID,
        "_saved_docx_fidelity": _claim(702, fixture_text, sections),
        "selected_frameworks": ["DGA"],
        "contract_meta": {
            "lang": "ar",
            "domain": "dt",
            "selected_frameworks": ["DGA"],
        },
    }
    artifact = canon.build_final_document_artifact(legacy, strategy_id="702")
    blockers = list(artifact.blocking_errors or [])
    observations["constructor_blockers"] = blockers
    if blockers or artifact.frozen:
        raise AssertionError(
            "constructor_setup:" + json.dumps(blockers, ensure_ascii=False))
    registered = canon.freeze_artifact(artifact)
    if "702" not in canon._ARTIFACT_REGISTRY or "701" in canon._ARTIFACT_REGISTRY:
        raise AssertionError("registry_after_702_freeze")
    if canon._ARTIFACT_REGISTRY["702"] is not registered:
        raise AssertionError("registry_702_identity")
    observations["preloaded_id"] = id(registered)
    return registered


def _register_701(fixture_text, sections, observations):
    canonical = canon.saved_source_canonical_sections(
        {key: sections[key] for key in SECTION_ORDER})
    canonical_hash = canon.compute_canonical_hash(canonical)
    artifact = FinalDocumentArtifact(
        artifact_id="701",
        domain="dt",
        language="ar",
        document_type="strategy",
        strategy_type="technical",
        selected_frameworks=["DGA"],
        canonical_sections=canonical,
        quality_repairs=[],
        quality_results={},
        frozen=False,
        canonical_hash=canonical_hash,
        render_tree_hash="",
        export_manifest=ExportManifest(
            routes={},
            render_tree_hash="",
            canonical_hash=canonical_hash,
        ),
        blocking_errors=[],
        release_ready_final_passed=False,
        strategy_id="701",
        legacy_sections={key: sections[key] for key in SECTION_ORDER},
        final_markdown_view=fixture_text,
    )
    if "owner" in getattr(FinalDocumentArtifact, "__dataclass_fields__", {}):
        raise AssertionError("owner_field_on_frozen_contract")
    if artifact.frozen or artifact.blocking_errors or artifact.render_tree_hash:
        raise AssertionError("synthetic_701_initial_state")
    if artifact.release_ready_final_passed or artifact.quality_results:
        raise AssertionError("synthetic_701_quality_state")
    registered = canon.freeze_artifact(artifact)
    if not registered.frozen or list(registered.blocking_errors or []):
        raise AssertionError("synthetic_701_freeze_state")
    if canon._ARTIFACT_REGISTRY.get("701") is not registered:
        raise AssertionError("registry_701_identity")
    if "702" in canon._ARTIFACT_REGISTRY:
        raise AssertionError("registry_702_present_for_701")
    if registered.render_tree_hash:
        raise AssertionError("synthetic_701_render_hash_assigned_at_setup")
    observations["preloaded_id"] = id(registered)
    observations["preloaded_render_tree_hash_at_setup"] = registered.render_tree_hash
    return registered


def _install(observations, run, record):
    originals = {
        "gate": app_module._enforce_export_gate,
        "route": app_module._rel31_authoritative_export_route,
        "writer": app_module._build_docx_bytes,
        "thread": threading.Thread,
        "resolve": rel32.resolve_frozen_artifact_for_export,
        "repair": rel31.repair_canonical_before_freeze,
        "validate": rel31.validate_saved_snapshot_original,
        "refusal": canon.saved_frozen_source_refusal,
        "export": rel31.rel3_export_with_evidence,
    }
    threading.Thread = RecordingThread

    def gate_wrap(*args, **kwargs):
        content = args[2] if len(args) > 2 else kwargs.get("content")
        record_obs = {
            "artifact_type": args[0] if args else kwargs.get("artifact_type"),
            "artifact_id": args[1] if len(args) > 1 else kwargs.get("artifact_id"),
            "generation_mode": args[3] if len(args) > 3 else kwargs.get("generation_mode"),
            "user_id": args[4] if len(args) > 4 else kwargs.get("user_id"),
            "content_edge_is_fixture": _edge(content) == _edge(observations["fixture_text"]),
            "client_conflict_in_content": "CLIENT CONFLICT MARKER" in str(content or ""),
        }
        _note(observations, "export_gate", record_obs["artifact_id"])
        try:
            result = originals["gate"](*args, **kwargs)
        except Exception as exc:
            record_obs["exception"] = repr(exc)
            observations["gate"] = record_obs
            raise
        record_obs["allowed"] = bool((result or {}).get("allowed")) if isinstance(result, dict) else None
        observations["gate"] = record_obs
        return result

    def route_wrap(*args, **kwargs):
        art = dict(kwargs.get("artifact_dict") or {})
        sections = dict(art.get("sections") or {})
        saved = _write_bytes(
            run / "route_input_final_markdown.md",
            str(art.get("final_markdown") or "").encode("utf-8"),
        )
        _write_text(
            run / "route_input_sections.json",
            json.dumps(sections, ensure_ascii=False, indent=2),
        )
        route_obs = {
            "route": args[0] if args else kwargs.get("route"),
            "domain": kwargs.get("domain"),
            "lang": kwargs.get("lang"),
            "document_type": art.get("document_type"),
            "strategy_id": str(art.get("strategy_id") or ""),
            "artifact_id": str(art.get("artifact_id") or ""),
            "export_user_id": art.get("_rel32_export_user_id"),
            "final_markdown_sha256": saved["sha256"],
            "final_markdown_edge_is_fixture": (
                _edge(art.get("final_markdown")) == _edge(observations["fixture_text"])
            ),
            "section_edge_match": {
                key: _edge(sections.get(key)) == _edge(observations["sections"][key])
                for key in SECTION_ORDER
            },
        }
        claim = art.get("_saved_docx_fidelity")
        if isinstance(claim, dict):
            route_obs["fidelity_record_id"] = claim.get("record_id")
            route_obs["fidelity_owner_id"] = claim.get("owner_id")
        _note(observations, "authoritative_route", route_obs["artifact_id"])
        backend = app_module._rel31_backend_callables()

        def load_artifact(key, _record=str(record)):
            raise KeyError("contract_r_no_frozen_row:" + str(key))

        backend["load_artifact"] = load_artifact
        kwargs = dict(kwargs)
        kwargs["backend"] = backend
        try:
            result = originals["route"](*args, **kwargs)
        except Exception as exc:
            route_obs["exception"] = repr(exc)
            observations["route"] = route_obs
            raise
        route_obs["result_is_none"] = result is None
        if isinstance(result, tuple) and len(result) == 2:
            export, evidence = result
            raw = getattr(export, "docx_bytes", None) or getattr(export, "bytes_data", None) or b""
            route_obs.update({
                "export_return_allowed": bool(getattr(evidence, "export_return_allowed", False)),
                "blocking_errors": list(getattr(evidence, "blocking_errors", None) or []),
                "returned_byte_count": len(raw) if isinstance(raw, (bytes, bytearray)) else 0,
            })
        observations["route"] = route_obs
        return result

    def writer_wrap(*args, **kwargs):
        call_no = len(observations["writer_calls"]) + 1
        content = args[0] if args else kwargs.get("content")
        sections = kwargs.get("sections")
        if sections is None and len(args) >= 12:
            sections = args[11]
        section_copy = dict(sections or {}) if isinstance(sections, dict) else {}
        _note(observations, "writer", call_no)
        item = {
            "call": call_no,
            "lang": args[2] if len(args) > 2 else kwargs.get("lang"),
            "doc_type": kwargs.get("doc_type", args[5] if len(args) > 5 else ""),
            "domain": kwargs.get("domain", args[6] if len(args) > 6 else ""),
            "content_edge_is_fixture": _edge(content) == _edge(observations["fixture_text"]),
            "client_conflict_in_content": "CLIENT CONFLICT MARKER" in str(content or ""),
            "section_edge_match": {
                key: _edge(section_copy.get(key)) == _edge(observations["sections"][key])
                for key in SECTION_ORDER
            },
        }
        _write_bytes(
            run / f"writer_input_{call_no}_content.md",
            str(content or "").encode("utf-8"),
        )
        date_evidence = None
        if _saved_reference_selected(observations, record, "sync_owner_response"):
            date_evidence = {
                "policy_id": _SAVED_PREPARATION_DATE_POLICY,
                "timezone": _SAVED_PREPARATION_DATE_ZONE,
                "before_utc": None,
                "after_utc": None,
                "errors": [],
            }
            item["preparation_date_evidence"] = date_evidence
            _saved_preparation_date_capture(date_evidence, "before_utc")
        try:
            result = originals["writer"](*args, **kwargs)
        except Exception as exc:
            if date_evidence is not None:
                _saved_preparation_date_capture(date_evidence, "after_utc")
            item["exception"] = repr(exc)
            observations["writer_calls"].append(item)
            raise
        if date_evidence is not None:
            _saved_preparation_date_capture(date_evidence, "after_utc")
        if isinstance(result, (bytes, bytearray)):
            item["diagnostic"] = _write_bytes(
                run / f"diagnostic_writer_{call_no}.docx", bytes(result))
        observations["writer_calls"].append(item)
        return result

    def resolve_wrap(*args, **kwargs):
        _note(observations, "resolve_frozen_artifact_for_export", None)
        result = originals["resolve"](*args, **kwargs)
        frozen, meta = result if isinstance(result, tuple) and len(result) == 2 else (result, {})
        meta = meta or {}
        registered = canon._ARTIFACT_REGISTRY.get(str(record))
        observations["resolver"].append({
            "returned_is_none": frozen is None,
            "returned_is_registered_object": frozen is registered and registered is not None,
            "frozen_artifact_loaded_for_docx": bool(meta.get("frozen_artifact_loaded_for_docx")),
            "artifact_loaded_from": meta.get("artifact_loaded_from"),
            "render_tree_hash_after": getattr(frozen, "render_tree_hash", None),
            "render_tree_hash_is_not_reuse_proof": True,
        })
        return result

    def repair_wrap(*args, **kwargs):
        _note(observations, "repair_canonical_before_freeze", None)
        result = originals["repair"](*args, **kwargs)
        repairs = list(result[1]) if isinstance(result, tuple) and len(result) > 1 else []
        observations["repairs"].append(repairs)
        return result

    def validate_wrap(*args, **kwargs):
        _note(observations, "validate_saved_snapshot_original", None)
        result = originals["validate"](*args, **kwargs)
        observations["quality"].append(list(result or []))
        return result

    def refusal_wrap(*args, **kwargs):
        _note(observations, "saved_frozen_source_refusal", None)
        result = originals["refusal"](*args, **kwargs)
        observations["refusal"].append(result)
        return result

    def export_wrap(*args, **kwargs):
        route_name = args[0] if args else kwargs.get("route")
        _note(observations, "rel3_export_with_evidence", route_name)
        observations["exports"].append({"route": route_name})
        return originals["export"](*args, **kwargs)

    app_module._enforce_export_gate = gate_wrap
    app_module._rel31_authoritative_export_route = route_wrap
    app_module._build_docx_bytes = writer_wrap
    rel32.resolve_frozen_artifact_for_export = resolve_wrap
    rel31.repair_canonical_before_freeze = repair_wrap
    rel31.validate_saved_snapshot_original = validate_wrap
    canon.saved_frozen_source_refusal = refusal_wrap
    rel31.rel3_export_with_evidence = export_wrap
    return originals


def _restore(originals, thread):
    if thread is not None and thread.is_alive():
        return False
    app_module._enforce_export_gate = originals["gate"]
    app_module._rel31_authoritative_export_route = originals["route"]
    app_module._build_docx_bytes = originals["writer"]
    threading.Thread = originals["thread"]
    rel32.resolve_frozen_artifact_for_export = originals["resolve"]
    rel31.repair_canonical_before_freeze = originals["repair"]
    rel31.validate_saved_snapshot_original = originals["validate"]
    canon.saved_frozen_source_refusal = originals["refusal"]
    rel31.rel3_export_with_evidence = originals["export"]
    return True


def _names(observations):
    return [item["name"] for item in observations["order"]]


def _assert_common_saved_path(observations, record):
    gate = observations.get("gate") or {}
    route = observations.get("route") or {}
    if gate.get("user_id") != OWNER_ID or str(gate.get("artifact_id")) != str(record):
        raise AssertionError("gate_owner_or_record")
    if gate.get("artifact_type") != "strategy" or gate.get("generation_mode") != "consulting":
        raise AssertionError("gate_saved_selection:" + json.dumps(gate, ensure_ascii=False))
    if gate.get("client_conflict_in_content") or not gate.get("content_edge_is_fixture"):
        raise AssertionError("gate_body")
    if route.get("export_user_id") != OWNER_ID:
        raise AssertionError("route_owner")
    if route.get("fidelity_owner_id") != OWNER_ID or route.get("fidelity_record_id") != record:
        raise AssertionError("claim_identity")
    if route.get("lang") != "ar" or route.get("document_type") != "strategy":
        raise AssertionError("route_saved_selection")
    if not route.get("final_markdown_edge_is_fixture"):
        raise AssertionError("route_body")
    for key, matched in (route.get("section_edge_match") or {}).items():
        if not matched:
            raise AssertionError("route_section:" + key)
    for call in observations.get("writer_calls") or []:
        if call.get("lang") != "ar" or call.get("doc_type") != "strategy":
            raise AssertionError("writer_saved_selection")
        if str(call.get("domain") or "").strip() not in SAVED_WRITER_DOMAINS:
            raise AssertionError("writer_domain")
        if call.get("client_conflict_in_content") or not call.get("content_edge_is_fixture"):
            raise AssertionError("writer_body")
        for key, matched in (call.get("section_edge_match") or {}).items():
            if not matched:
                raise AssertionError("writer_section:" + key)


def _assert_fresh(observations):
    if any(item.get("returned_is_none") is not True for item in observations["resolver"]):
        raise AssertionError("fresh_resolver_not_none")
    if not observations["resolver"]:
        raise AssertionError("fresh_resolver_absent")
    loaded = [item.get("artifact_loaded_from") for item in observations["resolver"]]
    if "rel33_compiler_first_sections" not in loaded:
        raise AssertionError("fresh_compiler_first_metadata:" + json.dumps(loaded, ensure_ascii=False))
    if len(observations["repairs"]) != 1:
        raise AssertionError("fresh_repair_count:" + str(len(observations["repairs"])))
    repairs = observations["repairs"][0]
    for tag in FRESH_REPAIR_TAGS:
        if tag not in repairs:
            raise AssertionError("fresh_repair_tag_absent:" + tag)
    names = _names(observations)
    if "validate_saved_snapshot_original" not in names:
        raise AssertionError("fresh_quality_absent")
    quality_at = names.index("validate_saved_snapshot_original")
    export_at = [index for index, name in enumerate(names) if name == "rel3_export_with_evidence"]
    if any(index < quality_at for index in export_at):
        raise AssertionError("fresh_export_before_quality")


def _assert_reuse(observations, record):
    if len(observations["repairs"]) != 0:
        raise AssertionError("reuse_fresh_repair_called")
    if not observations["resolver"]:
        raise AssertionError("reuse_resolver_absent")
    for item in observations["resolver"]:
        if not item.get("returned_is_registered_object"):
            raise AssertionError("reuse_resolver_identity")
        if not item.get("frozen_artifact_loaded_for_docx"):
            raise AssertionError("reuse_loaded_flag")
        if item.get("returned_is_none"):
            raise AssertionError("reuse_resolver_none")
    if observations["refusal"] != [""]:
        raise AssertionError(
            "reuse_source_refusal:" + json.dumps(observations["refusal"], ensure_ascii=False))
    names = _names(observations)
    if "validate_saved_snapshot_original" not in names:
        raise AssertionError("reuse_quality_absent")
    quality_at = names.index("validate_saved_snapshot_original")
    export_at = [index for index, name in enumerate(names) if name == "rel3_export_with_evidence"]
    if any(index < quality_at for index in export_at):
        raise AssertionError("reuse_export_before_quality")
    if record == 701 and (export_at or observations.get("writer_calls")):
        raise AssertionError("refusal_entered_export_or_writer")
    registered = canon._ARTIFACT_REGISTRY.get(str(record))
    if registered is None or id(registered) != observations.get("preloaded_id"):
        raise AssertionError("registered_object_replaced")


_SAVED_MAIN_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_SAVED_XML_NS = "http://www.w3.org/XML/1998/namespace"
_SAVED_READER_ID = "prospective_wdir_ltr_one_run_v1"
MIZAN_CONTRACT_R_F003_RAW_REFERENCE_PATH_NAME = (
    "MIZAN_CONTRACT_R_F003_RAW_REFERENCE_PATH")
_SAVED_RAW_REFERENCE_BYTES = 125620
_SAVED_RAW_REFERENCE_SHA256 = (
    "8bf9c039011b507ac3c5aedf2b7b63f55ec42b1251a3f09d15e090a911629e5e")
_SAVED_RAW_REFERENCE_TABLES = (
    (5, 7, 2),
    (25, 9, 6),
    (39, 5, 5),
    (54, 11, 6),
    (60, 6, 8),
    (72, 5, 5),
    (78, 5, 4),
)
_SAVED_PREPARATION_DATE_POLICY = "saved_cover_current_preparation_date_riyadh_v1"
_SAVED_PREPARATION_DATE_ZONE = "Asia/Riyadh"
_SAVED_PREPARATION_DATE_LABEL = "تاريخ الإعداد"
_SAVED_PREPARATION_MONTHS = (
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
)
_SAVED_RPR_PLAIN = ("rtl", "rFonts", "sz", "szCs", "b", "bCs")
_SAVED_RPR_COLOR = ("color", "rtl", "rFonts", "sz", "szCs", "b", "bCs")
_SAVED_HALF_POINTS = {"18", "20", "22", "28"}
_SAVED_COLORS = {"1D2B4F", "FFFFFF"}


def _saved_clark(namespace, local):
    return "{%s}%s" % (namespace, local)


def _saved_ns(tag):
    if isinstance(tag, str) and tag.startswith("{"):
        return tag[1:].split("}", 1)[0]
    return ""


def _saved_local(tag):
    if isinstance(tag, str) and tag.startswith("{") and "}" in tag:
        return tag.split("}", 1)[1]
    if isinstance(tag, str):
        return tag
    return ""


def _saved_element_children(element):
    return [child for child in list(element) if isinstance(child.tag, str)]


def _saved_named_children(element, local):
    return [
        child for child in _saved_element_children(element)
        if _saved_ns(child.tag) == _SAVED_MAIN_NS and _saved_local(child.tag) == local
    ]


def _saved_blank(value):
    return value is None or value == ""


def _saved_ascii_alnum(char):
    return (
        "0" <= char <= "9"
        or "A" <= char <= "Z"
        or "a" <= char <= "z")


def _saved_match_iso_token(text, index):
    if index + 10 > len(text):
        return None
    if index > 0 and "0" <= text[index - 1] <= "9":
        return None
    chunk = text[index:index + 10]
    if (
            all("0" <= char <= "9" for char in chunk[0:4])
            and chunk[4] == "-"
            and all("0" <= char <= "9" for char in chunk[5:7])
            and chunk[7] == "-"
            and all("0" <= char <= "9" for char in chunk[8:10])):
        return 10
    return None


def _saved_match_bracket_token(text, index):
    size = len(text)
    if index >= size or text[index] != "[":
        return None
    cursor = index + 1
    start = cursor
    while cursor < size and _saved_ascii_alnum(text[cursor]):
        cursor += 1
    if cursor == start:
        return None
    groups = 0
    while cursor < size and text[cursor] == "-":
        next_cursor = cursor + 1
        if next_cursor >= size or not _saved_ascii_alnum(text[next_cursor]):
            break
        next_cursor += 1
        while next_cursor < size and _saved_ascii_alnum(text[next_cursor]):
            next_cursor += 1
        groups += 1
        cursor = next_cursor
    if groups >= 1 and cursor < size and text[cursor] == "]":
        return cursor + 1 - index
    return None


def _saved_technical_body(body):
    if body == "":
        return False
    alphanumeric = 0
    previous_space = False
    for char in body:
        if char == " ":
            if previous_space:
                return False
            previous_space = True
            continue
        previous_space = False
        if char == "." or _saved_ascii_alnum(char):
            if _saved_ascii_alnum(char):
                alphanumeric += 1
            continue
        return False
    return alphanumeric >= 1


def _saved_match_parenthesis_token(text, index):
    if index >= len(text) or text[index] != "(":
        return None
    close = text.find(")", index + 1)
    if close < 0:
        return None
    if not _saved_technical_body(text[index + 1:close]):
        return None
    return close + 1 - index


def _saved_match_token(text, index):
    matched = _saved_match_iso_token(text, index)
    if matched is not None:
        return matched
    matched = _saved_match_bracket_token(text, index)
    if matched is not None:
        return matched
    return _saved_match_parenthesis_token(text, index)


def _saved_recognized_spans(text):
    spans = []
    index = 0
    size = len(text)
    while index < size:
        matched = _saved_match_token(text, index)
        if matched is None:
            index += 1
            continue
        spans.append((index, index + matched))
        index += matched
    return spans


def _saved_ordinary_run_text(run):
    parts = []
    for child in _saved_element_children(run):
        if _saved_ns(child.tag) != _SAVED_MAIN_NS:
            continue
        name = _saved_local(child.tag)
        if name == "t":
            parts.append(child.text or "")
        elif name == "br":
            if child.get(_saved_clark(_SAVED_MAIN_NS, "type")) in (None, "textWrapping"):
                parts.append("\n")
        elif name == "cr":
            parts.append("\n")
        elif name == "noBreakHyphen":
            parts.append("-")
        elif name == "ptab":
            parts.append("\t")
        elif name == "tab":
            parts.append("\t")
    return "".join(parts)


def _saved_hyperlink_text(link):
    parts = []
    for child in _saved_element_children(link):
        if _saved_ns(child.tag) == _SAVED_MAIN_NS and _saved_local(child.tag) == "r":
            parts.append(_saved_ordinary_run_text(child))
    return "".join(parts)


def _saved_run_record(oxml_run, paragraph, text):
    run = Run(oxml_run, paragraph)
    size = run.font.size
    return {
        "text": text,
        "bold": run.bold,
        "size_pt": None if size is None else size.pt,
    }


def _saved_fail(reason):
    return {"status": "unsupported", "reason": reason, "text": None}


def _saved_single_attribute(element, local, allowed):
    expected = _saved_clark(_SAVED_MAIN_NS, local)
    if list(element.attrib) != [expected]:
        return "attribute"
    if element.attrib[expected] not in allowed:
        return "run_content"
    return None


def _saved_property_inventory(prop, bold_value, size_value):
    if _saved_ns(prop.tag) != _SAVED_MAIN_NS:
        return "namespace", bold_value, size_value
    if prop.text not in (None, "") or prop.tail not in (None, "") or _saved_element_children(prop):
        return "run_content", bold_value, size_value
    name = _saved_local(prop.tag)
    if name == "rtl":
        failure = _saved_single_attribute(prop, "val", {"0"})
        if failure == "run_content":
            return "direction", bold_value, size_value
        return failure, bold_value, size_value
    if name == "rFonts":
        expected = {
            _saved_clark(_SAVED_MAIN_NS, "ascii"): "Arial",
            _saved_clark(_SAVED_MAIN_NS, "hAnsi"): "Arial",
            _saved_clark(_SAVED_MAIN_NS, "cs"): "Arial",
            _saved_clark(_SAVED_MAIN_NS, "eastAsia"): "Arial",
        }
        if dict(prop.attrib) != expected:
            return "attribute", bold_value, size_value
        return None, bold_value, size_value
    if name in ("sz", "szCs"):
        failure = _saved_single_attribute(prop, "val", _SAVED_HALF_POINTS)
        if failure:
            return failure, bold_value, size_value
        value = prop.attrib[_saved_clark(_SAVED_MAIN_NS, "val")]
        if size_value is None:
            size_value = value
        elif size_value != value:
            return "run_content", bold_value, size_value
        return None, bold_value, size_value
    if name in ("b", "bCs"):
        failure = _saved_single_attribute(prop, "val", {"0", "1"})
        if failure:
            return failure, bold_value, size_value
        value = prop.attrib[_saved_clark(_SAVED_MAIN_NS, "val")]
        if bold_value is None:
            bold_value = value
        elif bold_value != value:
            return "run_content", bold_value, size_value
        return None, bold_value, size_value
    if name == "color":
        failure = _saved_single_attribute(prop, "val", _SAVED_COLORS)
        return failure, bold_value, size_value
    return "run_content", bold_value, size_value


def _saved_offer_inventory(et_dir):
    if _saved_ns(et_dir.tag) != _SAVED_MAIN_NS:
        return _saved_fail("namespace")
    if not _saved_blank(et_dir.text) or not _saved_blank(et_dir.tail):
        return _saved_fail("parent_text")
    val_name = _saved_clark(_SAVED_MAIN_NS, "val")
    if list(et_dir.attrib) != [val_name]:
        return _saved_fail("attribute")
    if et_dir.attrib[val_name] != "ltr":
        return _saved_fail("direction")
    children = _saved_element_children(et_dir)
    if len(children) != 1:
        return _saved_fail("child_count")
    run = children[0]
    if _saved_ns(run.tag) != _SAVED_MAIN_NS:
        return _saved_fail("namespace")
    run_name = _saved_local(run.tag)
    if run_name in ("dir", "bdo"):
        return _saved_fail("nested")
    if run_name != "r":
        return _saved_fail("child_kind")
    if run.attrib or not _saved_blank(run.text) or not _saved_blank(run.tail):
        return _saved_fail("attribute" if run.attrib else "run_content")
    run_children = _saved_element_children(run)
    if len(run_children) != 2:
        return _saved_fail("run_content")
    rpr, text_element = run_children
    if _saved_ns(rpr.tag) != _SAVED_MAIN_NS or _saved_ns(text_element.tag) != _SAVED_MAIN_NS:
        return _saved_fail("namespace")
    if _saved_local(rpr.tag) != "rPr" or _saved_local(text_element.tag) != "t":
        return _saved_fail("run_content")
    if rpr.attrib or not _saved_blank(rpr.text) or not _saved_blank(rpr.tail):
        return _saved_fail("attribute" if rpr.attrib else "run_content")
    properties = _saved_element_children(rpr)
    order = tuple(_saved_local(prop.tag) for prop in properties)
    if order not in (_SAVED_RPR_PLAIN, _SAVED_RPR_COLOR):
        return _saved_fail("run_content")
    bold_value = None
    size_value = None
    for prop in properties:
        failure, bold_value, size_value = _saved_property_inventory(
            prop, bold_value, size_value)
        if failure:
            return _saved_fail(failure)
    space_name = _saved_clark(_SAVED_XML_NS, "space")
    text_attributes = list(text_element.attrib)
    if text_attributes not in ([], [space_name]):
        return _saved_fail("attribute")
    if text_attributes and text_element.attrib[space_name] != "preserve":
        return _saved_fail("attribute")
    if _saved_element_children(text_element) or not _saved_blank(text_element.tail):
        return _saved_fail("run_content")
    return {
        "status": "ok",
        "reason": None,
        "text": text_element.text or "",
    }


def _saved_unsupported_view(reason, offered_indexes, paragraph_index):
    return {
        "status": "unsupported",
        "raw_text": None,
        "runs": [],
        "profile": "unsupported_token_parent",
        "reason": reason,
        "offered_indexes": offered_indexes,
        "paragraph_index": paragraph_index,
    }


def _saved_pair_children(et_parent, oxml_parent):
    et_children = _saved_element_children(et_parent)
    ox_children = _saved_element_children(oxml_parent)
    if len(et_children) != len(ox_children):
        return None
    paired = []
    for et_child, ox_child in zip(et_children, ox_children):
        if _saved_ns(et_child.tag) != _saved_ns(ox_child.tag):
            return None
        if _saved_local(et_child.tag) != _saved_local(ox_child.tag):
            return None
        paired.append((et_child, ox_child))
    return paired


def _saved_paragraph_offer_indexes(paragraph):
    """Direct dir children of a main-namespace paragraph. Not a nested parent."""
    if paragraph is None:
        return []
    if _saved_ns(paragraph.tag) != _SAVED_MAIN_NS or _saved_local(paragraph.tag) != "p":
        return []
    indexes = []
    for index, child in enumerate(_saved_element_children(paragraph)):
        if _saved_local(child.tag) == "dir":
            indexes.append(index)
    return indexes


def _saved_tc_offer_paragraphs(cell):
    if cell is None:
        return []
    found = []
    for index, paragraph in enumerate(_saved_named_children(cell, "p")):
        if _saved_paragraph_offer_indexes(paragraph):
            found.append(index)
    return found


def _saved_library_view(paragraph, paragraph_index):
    return {
        "status": "library",
        "raw_text": paragraph.text,
        "runs": None,
        "profile": "direct",
        "reason": None,
        "offered_indexes": [],
        "paragraph_index": paragraph_index,
    }


def _saved_materialize_run(oxml_run, paragraph, text):
    if paragraph is None:
        return {"text": text, "bold": None, "size_pt": None}
    return _saved_run_record(oxml_run, paragraph, text)


def _saved_paragraph_view(et_p, oxml_p, paragraph, paragraph_index):
    paired = _saved_pair_children(et_p, oxml_p)
    if paired is None:
        offered_indexes = _saved_paragraph_offer_indexes(et_p)
        if not offered_indexes:
            offered_indexes = _saved_paragraph_offer_indexes(oxml_p)
        if offered_indexes:
            return _saved_unsupported_view(
                "parent_text", offered_indexes, paragraph_index)
        if paragraph is None:
            return {
                "status": "ok",
                "raw_text": "",
                "runs": [],
                "profile": "direct",
                "reason": None,
                "offered_indexes": [],
                "paragraph_index": paragraph_index,
            }
        return _saved_library_view(paragraph, paragraph_index)
    offered_indexes = []
    payloads = {}
    for index, (et_child, _ox_child) in enumerate(paired):
        if _saved_local(et_child.tag) != "dir":
            continue
        offered_indexes.append(index)
        inventory = _saved_offer_inventory(et_child)
        if inventory["status"] != "ok":
            return _saved_unsupported_view(
                inventory["reason"], offered_indexes, paragraph_index)
        payloads[index] = inventory["text"]
    parts = []
    runs = []
    intervals = []
    cursor = 0
    for index, (et_child, ox_child) in enumerate(paired):
        local = _saved_local(et_child.tag)
        namespace = _saved_ns(et_child.tag)
        if local == "dir":
            ox_runs = _saved_element_children(ox_child)
            if (
                    len(ox_runs) != 1
                    or _saved_ns(ox_runs[0].tag) != _SAVED_MAIN_NS
                    or _saved_local(ox_runs[0].tag) != "r"):
                return _saved_unsupported_view(
                    "parent_text", offered_indexes, paragraph_index)
            text = payloads[index]
            intervals.append((cursor, cursor + len(text)))
            parts.append(text)
            runs.append(_saved_materialize_run(ox_runs[0], paragraph, text))
            cursor += len(text)
            continue
        if namespace == _SAVED_MAIN_NS and local == "r":
            text = _saved_ordinary_run_text(et_child)
            parts.append(text)
            runs.append(_saved_materialize_run(ox_child, paragraph, text))
            cursor += len(text)
            continue
        if namespace == _SAVED_MAIN_NS and local == "hyperlink":
            text = _saved_hyperlink_text(et_child)
            parts.append(text)
            cursor += len(text)
    logical = "".join(parts)
    recognized = set(_saved_recognized_spans(logical))
    for start, end in intervals:
        if (start, end) not in recognized:
            return _saved_unsupported_view(
                "eligibility", offered_indexes, paragraph_index)
    return {
        "status": "ok",
        "raw_text": logical,
        "runs": runs,
        "profile": "eligible_dir" if intervals else "direct",
        "reason": None,
        "offered_indexes": offered_indexes,
        "paragraph_index": paragraph_index,
    }


def _saved_parent_record(reason, body_child_index, paragraph_index, table_index,
                         row_index, cell_index, cell_paragraph_index, *,
                         physical_row_index=None, physical_tc_index=None,
                         logical_cell_represented=True):
    record = {
        "kind": "unsupported_token_parent",
        "reason": reason,
        "body_child_index": body_child_index,
        "paragraph_index": paragraph_index,
        "table_index": table_index,
        "row_index": row_index,
        "cell_index": cell_index,
        "cell_paragraph_index": cell_paragraph_index,
        "role": None,
    }
    if physical_row_index is not None:
        record["physical_row_index"] = physical_row_index
    if physical_tc_index is not None:
        record["physical_tc_index"] = physical_tc_index
    if not logical_cell_represented:
        record["row_index"] = None
        record["cell_index"] = None
        record["logical_cell_represented"] = False
    return record


def _saved_cell_text(et_tc, oxml_tc, cell, table_index, row_index, cell_index,
                     body_child_index, paragraph_index, unsupported, *,
                     physical_row_index=None, physical_tc_index=None):
    et_paragraphs = _saved_named_children(et_tc, "p")
    ox_paragraphs = _saved_named_children(oxml_tc, "p")
    doc_paragraphs = list(cell.paragraphs)
    next_index = paragraph_index + len(doc_paragraphs)
    if not (len(et_paragraphs) == len(ox_paragraphs) == len(doc_paragraphs)):
        offered = []
        seen = set()
        for index in (
                _saved_tc_offer_paragraphs(et_tc)
                + _saved_tc_offer_paragraphs(oxml_tc)):
            if index not in seen:
                seen.add(index)
                offered.append(index)
        if not offered:
            return {
                "status": "ok",
                "raw_text": cell.text,
                "paragraphs": [],
                "reasons": [],
                "failures": [],
            }, next_index
        failures = []
        for cell_paragraph_index in offered:
            paragraph_at = paragraph_index + cell_paragraph_index
            failures.append({
                "reason": "parent_text",
                "cell_paragraph_index": cell_paragraph_index,
                "paragraph_index": paragraph_at,
            })
            unsupported.append(_saved_parent_record(
                "parent_text", body_child_index, paragraph_at, table_index,
                row_index, cell_index, cell_paragraph_index,
                physical_row_index=physical_row_index,
                physical_tc_index=physical_tc_index))
        return {
            "status": "unsupported",
            "raw_text": None,
            "paragraphs": [],
            "reasons": [item["reason"] for item in failures],
            "failures": failures,
        }, next_index
    views = []
    failures = []
    for cell_paragraph_index, (et_p, ox_p, doc_p) in enumerate(
            zip(et_paragraphs, ox_paragraphs, doc_paragraphs)):
        view = _saved_paragraph_view(
            et_p, ox_p, doc_p, paragraph_index + cell_paragraph_index)
        views.append(view)
        if view["status"] == "unsupported":
            failures.append({
                "reason": view["reason"],
                "cell_paragraph_index": cell_paragraph_index,
                "paragraph_index": view["paragraph_index"],
            })
            unsupported.append(_saved_parent_record(
                view["reason"], body_child_index, view["paragraph_index"],
                table_index, row_index, cell_index, cell_paragraph_index,
                physical_row_index=physical_row_index,
                physical_tc_index=physical_tc_index))
    if failures:
        return {
            "status": "unsupported",
            "raw_text": None,
            "paragraphs": views,
            "reasons": [item["reason"] for item in failures],
            "failures": failures,
        }, next_index
    return {
        "status": "ok",
        "raw_text": "\n".join(view["raw_text"] for view in views),
        "paragraphs": views,
        "reasons": [],
        "failures": [],
    }, next_index


def _saved_original_document_root(data):
    with zipfile.ZipFile(BytesIO(data)) as package:
        xml_bytes = package.read("word/document.xml")
    return ET.fromstring(xml_bytes)


def _saved_body_blocks(root):
    body = None
    for child in list(root):
        if _saved_ns(child.tag) == _SAVED_MAIN_NS and _saved_local(child.tag) == "body":
            body = child
            break
    if body is None:
        return []
    return [
        child for child in _saved_element_children(body)
        if _saved_ns(child.tag) == _SAVED_MAIN_NS
        and _saved_local(child.tag) in ("p", "tbl")
    ]


def _saved_reference_selected(observations, record, provenance):
    return bool(
        record == 702
        and observations.get("record_id") == 702
        and observations.get("case") == "test_contract_r_702_sync_fresh"
        and observations.get("transport") == "sync"
        and observations.get("freshness") == "fresh"
        and provenance == "sync_owner_response")


def _saved_preparation_date_capture(evidence, phase):
    """Observe the real writer boundary without replacing its return/raise."""
    try:
        from datetime import datetime, timezone
        evidence[phase] = datetime.now(timezone.utc).isoformat()
    except Exception as exc:
        evidence["errors"].append({
            "phase": phase,
            "error_type": type(exc).__name__,
        })


def _saved_preparation_date_context(observations, record, provenance, saved):
    """Bind one independently timed writer to the actual saved owner bytes."""
    if not _saved_reference_selected(observations, record, provenance):
        return None
    context = {
        "selected": True,
        "policy_id": _SAVED_PREPARATION_DATE_POLICY,
        "timezone": _SAVED_PREPARATION_DATE_ZONE,
        "case": observations.get("case"),
        "record_id": record,
        "owner_id": observations.get("owner_id"),
        "provenance": provenance,
        "writer_call": None,
        "before_utc": None,
        "after_utc": None,
        "before_local_date": None,
        "after_local_date": None,
        "expected_date": None,
        "owner_identity": dict(saved),
        "writer_identity": None,
        "writer_owner_bytes_match": False,
        "evidence_valid": False,
        "errors": [],
    }
    errors = context["errors"]
    gate = observations.get("gate")
    route = observations.get("route")
    if not isinstance(gate, dict):
        errors.append("gate_record_invalid")
        gate = {}
    if not isinstance(route, dict):
        errors.append("route_record_invalid")
        route = {}
    context["gate_identity"] = {
        key: gate.get(key) for key in
        ("user_id", "artifact_id", "artifact_type", "generation_mode", "allowed")
    }
    context["route_identity"] = {
        key: route.get(key) for key in
        ("route", "strategy_id", "artifact_id", "export_user_id",
         "fidelity_owner_id", "fidelity_record_id", "lang", "document_type",
         "export_return_allowed", "blocking_errors", "returned_byte_count")
    }
    if observations.get("owner_id") != OWNER_ID:
        errors.append("observation_owner")
    if (gate.get("user_id") != OWNER_ID
            or str(gate.get("artifact_id")) != str(record)
            or gate.get("artifact_type") != "strategy"
            or gate.get("generation_mode") != "consulting"
            or gate.get("allowed") is not True
            or gate.get("exception") is not None):
        errors.append("gate_identity_or_permission")
    if (route.get("route") != "docx"
            or route.get("export_user_id") != OWNER_ID
            or route.get("fidelity_owner_id") != OWNER_ID
            or route.get("fidelity_record_id") != record
            or route.get("strategy_id") != str(record)
            or route.get("artifact_id") != str(record)
            or route.get("lang") != "ar"
            or route.get("document_type") != "strategy"
            or route.get("export_return_allowed") is not True
            or not isinstance(route.get("blocking_errors"), list)
            or route.get("blocking_errors")
            or route.get("returned_byte_count") != saved.get("bytes")
            or route.get("exception") is not None):
        errors.append("route_identity_or_permission")
    calls = observations.get("writer_calls")
    if not isinstance(calls, list) or len(calls) != 1 or not isinstance(calls[0], dict):
        errors.append("writer_count_or_record")
        return context
    call = calls[0]
    context["writer_call"] = call.get("call")
    if (call.get("call") != 1 or call.get("exception") is not None
            or call.get("lang") != "ar" or call.get("doc_type") != "strategy"
            or str(call.get("domain") or "").strip() not in SAVED_WRITER_DOMAINS):
        errors.append("writer_identity_or_failure")
    diagnostic = call.get("diagnostic")
    if not isinstance(diagnostic, dict):
        errors.append("writer_diagnostic_missing")
    else:
        context["writer_identity"] = dict(diagnostic)
        count = diagnostic.get("bytes")
        digest = diagnostic.get("sha256")
        bound = bool(
            type(count) is int and count > 0
            and count == saved.get("bytes")
            and isinstance(digest, str)
            and re.fullmatch(r"[0-9a-f]{64}", digest)
            and digest == saved.get("sha256")
            and isinstance(diagnostic.get("path"), str)
            and diagnostic.get("path")
            and diagnostic.get("path") != saved.get("path"))
        context["writer_owner_bytes_match"] = bound
        if not bound:
            errors.append("writer_owner_byte_binding")
    evidence = call.get("preparation_date_evidence")
    if not isinstance(evidence, dict):
        errors.append("writer_date_evidence_missing")
        return context
    context["before_utc"] = evidence.get("before_utc")
    context["after_utc"] = evidence.get("after_utc")
    context["clock_capture_errors"] = evidence.get("errors")
    if (evidence.get("policy_id") != _SAVED_PREPARATION_DATE_POLICY
            or evidence.get("timezone") != _SAVED_PREPARATION_DATE_ZONE
            or evidence.get("errors") != []):
        errors.append("writer_date_evidence_invalid")
    try:
        from datetime import datetime, timedelta
        from zoneinfo import ZoneInfo
        bounds = []
        for phase in ("before_utc", "after_utc"):
            value = evidence.get(phase)
            if not isinstance(value, str) or re.fullmatch(
                    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
                    r"(?:\.[0-9]{1,6})?\+00:00", value) is None:
                raise ValueError("utc_observation_format")
            observed = datetime.fromisoformat(value)
            if observed.tzinfo is None or observed.utcoffset() != timedelta(0):
                raise ValueError("utc_observation_offset")
            bounds.append(observed)
        if bounds[1] < bounds[0]:
            raise ValueError("utc_observations_reversed")
        zone = ZoneInfo(_SAVED_PREPARATION_DATE_ZONE)
        before_day, after_day = [bound.astimezone(zone).date() for bound in bounds]
        context["before_local_date"] = before_day.isoformat()
        context["after_local_date"] = after_day.isoformat()
        if before_day != after_day:
            errors.append("writer_day_ambiguous_at_midnight")
        else:
            context["expected_date"] = (
                f"{before_day.day:02d} {_SAVED_PREPARATION_MONTHS[before_day.month - 1]} "
                f"{before_day.year:04d}")
    except Exception as exc:
        context["clock_or_zone_error_type"] = type(exc).__name__
        errors.append("writer_clock_or_zone_invalid")
    context["evidence_valid"] = not errors
    return context


def _saved_preparation_date_policy(extraction, raw_reference, context, literal):
    """Validate every selected date; retain literal snapshot differences."""
    selected = bool(
        (isinstance(raw_reference, dict) and raw_reference.get("selected"))
        or (isinstance(context, dict) and context.get("selected")))
    report = dict(context) if isinstance(context, dict) else {}
    report.update({
        "selected": selected,
        "policy_id": _SAVED_PREPARATION_DATE_POLICY,
        "timezone": _SAVED_PREPARATION_DATE_ZONE,
        "mixed_index": 5,
        "table_ordinal": 0,
        "row_index": 5,
        "cell_index": 1,
        "label": _SAVED_PREPARATION_DATE_LABEL,
        "raw_reference_identity": {
            "bytes": _SAVED_RAW_REFERENCE_BYTES,
            "sha256": _SAVED_RAW_REFERENCE_SHA256,
        },
        "reference_date": None,
        "actual_date": None,
        "verdict": "not_selected",
        "errors": list(context.get("errors") or []) if isinstance(context, dict) else [],
        "accepted_date_differences": [],
    })
    if not selected:
        return report, []
    errors = report["errors"]
    if not isinstance(context, dict) or context.get("selected") is not True:
        errors.append("date_context_missing")
    elif context.get("evidence_valid") is not True:
        errors.append("date_context_invalid")
    if (not isinstance(raw_reference, dict)
            or raw_reference.get("selected") is not True
            or raw_reference.get("error")
            or not isinstance(raw_reference.get("reference"), dict)):
        errors.append("raw_reference_unmapped")
        reference = None
    else:
        reference = raw_reference["reference"]
    if any(item.get("kind") == "raw_reference_unmapped" for item in literal):
        errors.append("raw_structure_unmapped")
    if extraction.get("unsupported_parents"):
        errors.append("unsupported_token_parent_present")
    if reference is not None:
        reference_shape = _saved_reference_shape(reference)
        actual_shape = _saved_reference_shape(extraction)
        if reference_shape or actual_shape:
            report["reference_shape_error"] = reference_shape
            report["actual_shape_error"] = actual_shape
            errors.append("date_cover_structure")
        else:
            ref_elements = reference["elements"]
            act_elements = extraction["elements"]
            ref_table, act_table = ref_elements[5], act_elements[5]
            if (ref_table.get("role") != "cover" or act_table.get("role") != "cover"
                    or _saved_table_ordinal(ref_elements, 5) != 0
                    or _saved_table_ordinal(act_elements, 5) != 0
                    or act_table.get("table_index") != 0
                    or act_table.get("body_child_index") != 5):
                errors.append("date_cover_location")
            report["reference_date"] = ref_table["raw_rows"][5][1]
            report["actual_date"] = act_table["raw_rows"][5][1]
            if (ref_table["raw_rows"][5][0] != _SAVED_PREPARATION_DATE_LABEL
                    or act_table["raw_rows"][5][0] != _SAVED_PREPARATION_DATE_LABEL):
                errors.append("date_label")
            # Inventory duplicates only; this never selects an alternative field.
            for side, elements in (("reference", ref_elements), ("actual", act_elements)):
                label_positions = []
                for mixed_index, element in enumerate(elements):
                    if element.get("role") != "cover":
                        continue
                    if element.get("kind") == "paragraph":
                        if element.get("text") == _SAVED_PREPARATION_DATE_LABEL:
                            label_positions.append((mixed_index, None, None))
                    else:
                        for row_index, row in enumerate(element["raw_rows"]):
                            for cell_index, cell in enumerate(row):
                                if cell == _SAVED_PREPARATION_DATE_LABEL:
                                    label_positions.append((mixed_index, row_index, cell_index))
                if label_positions != [(5, 5, 0)]:
                    report[side + "_date_label_positions"] = label_positions
                    errors.append(side + "_date_field_duplicated_or_moved")
    expected_date = report.get("expected_date")
    if not isinstance(expected_date, str) or not expected_date:
        errors.append("expected_event_day_unavailable")
    elif report["actual_date"] != expected_date:
        errors.append("actual_date_not_expected_event_day")
    eligible = [
        index for index, item in enumerate(literal)
        if item.get("kind") == "raw_character_difference"
        and item.get("mixed_index") == 5
        and item.get("table_ordinal") == 0
        and item.get("row_index") == 5
        and item.get("cell_index") == 1
        and item.get("reference_text") == report["reference_date"]
        and item.get("actual_text") == report["actual_date"]
    ]
    expected_delta_count = int(report["reference_date"] != report["actual_date"])
    if len(eligible) != expected_delta_count:
        errors.append("date_literal_delta_mapping")
    if errors:
        report["verdict"] = "failed"
        return report, []
    report["verdict"] = "valid_current_preparation_date"
    report["accepted_date_differences"] = [dict(literal[index]) for index in eligible]
    return report, eligible


def _saved_reference_shape(parsed):
    elements = parsed.get("elements") if isinstance(parsed, dict) else None
    if not isinstance(elements, list) or len(elements) != 81:
        return "element_count"
    table_indexes = {index for index, _rows, _width in _SAVED_RAW_REFERENCE_TABLES}
    for index, element in enumerate(elements):
        if not isinstance(element, dict):
            return "element_type"
        kind = element.get("kind")
        if index in table_indexes:
            if kind != "table":
                return "table_kind"
        elif kind != "paragraph":
            return "paragraph_kind"
        elif not isinstance(element.get("text"), str):
            return "paragraph_text"
    for index, row_count, width in _SAVED_RAW_REFERENCE_TABLES:
        raw_rows = elements[index].get("raw_rows")
        if not isinstance(raw_rows, list) or len(raw_rows) != row_count:
            return "row_count"
        for row in raw_rows:
            if not isinstance(row, list) or len(row) != width:
                return "cell_count"
            if any(not isinstance(cell, str) for cell in row):
                return "cell_text"
    return None


def _saved_raw_reference_context(observations, record, provenance):
    if not _saved_reference_selected(observations, record, provenance):
        return None
    path = os.environ.get(MIZAN_CONTRACT_R_F003_RAW_REFERENCE_PATH_NAME)
    context = {
        "selected": True,
        "path": path,
        "identity_bytes": _SAVED_RAW_REFERENCE_BYTES,
        "identity_sha256": _SAVED_RAW_REFERENCE_SHA256,
        "error": None,
        "identity_detail": None,
        "reference": None,
    }
    if not path:
        context["error"] = "reference_identity"
        context["identity_detail"] = "path_absent"
        return context
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        context["error"] = "reference_identity"
        context["identity_detail"] = type(exc).__name__
        return context
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != _SAVED_RAW_REFERENCE_BYTES or digest != _SAVED_RAW_REFERENCE_SHA256:
        context["error"] = "reference_identity"
        context["identity_detail"] = "digest"
        return context
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        context["error"] = "reference_identity"
        context["identity_detail"] = "json"
        return context
    shape = _saved_reference_shape(parsed)
    if shape:
        context["error"] = "reference_identity"
        context["identity_detail"] = shape
        return context
    context["reference"] = parsed
    return context


def _saved_table_ordinal(elements, index):
    return sum(1 for item in elements[:index] if item.get("kind") == "table")


def _saved_cell_unsupported(extraction, table_index, row_index, cell_index):
    for record in extraction.get("unsupported_parents") or []:
        if (
                record.get("table_index") == table_index
                and record.get("row_index") == row_index
                and record.get("cell_index") == cell_index):
            return True
    return False


def _saved_structural_record(reason, mixed_index, **fields):
    record = {
        "kind": "raw_reference_unmapped",
        "reason": reason,
        "mixed_index": mixed_index,
    }
    record.update(fields)
    return record


def _saved_character_record(mixed_index, reference_text, actual_text, **fields):
    record = {
        "kind": "raw_character_difference",
        "mixed_index": mixed_index,
        "reference_text": reference_text,
        "actual_text": actual_text,
    }
    record.update(fields)
    return record


def _saved_raw_pair(extraction, mixed_index, reference, actual, ref_ordinal, act_ordinal):
    structural = []
    character = []
    ref_kind = reference.get("kind")
    act_kind = actual.get("kind")
    if ref_kind != act_kind:
        structural.append(_saved_structural_record(
            "kind_mismatch", mixed_index,
            reference_table_ordinal=ref_ordinal,
            actual_table_ordinal=act_ordinal,
            reference_kind=ref_kind,
            actual_kind=act_kind,
        ))
        return structural, character
    if ref_kind == "paragraph":
        actual_text = actual.get("text")
        reference_text = reference.get("text")
        if actual.get("reader_status") == "unsupported" or actual_text is None:
            if actual.get("reader_status") != "unsupported":
                structural.append(_saved_structural_record(
                    "unsupported_null", mixed_index))
            return structural, character
        if not isinstance(actual_text, str) or not isinstance(reference_text, str):
            structural.append(_saved_structural_record(
                "unsupported_null", mixed_index))
            return structural, character
        if actual_text != reference_text:
            character.append(_saved_character_record(
                mixed_index, reference_text, actual_text))
        return structural, character
    ref_rows = reference.get("raw_rows") if isinstance(reference.get("raw_rows"), list) else []
    act_rows = actual.get("raw_rows") if isinstance(actual.get("raw_rows"), list) else []
    row_counts_differ = len(ref_rows) != len(act_rows)
    if row_counts_differ:
        for row_index in range(len(act_rows), len(ref_rows)):
            structural.append(_saved_structural_record(
                "missing_actual_row", mixed_index,
                table_ordinal=ref_ordinal, row_index=row_index))
        for row_index in range(len(ref_rows), len(act_rows)):
            structural.append(_saved_structural_record(
                "extra_actual_row", mixed_index,
                table_ordinal=act_ordinal, row_index=row_index))
    for row_index, (ref_row, act_row) in enumerate(zip(ref_rows, act_rows)):
        if not isinstance(ref_row, list) or not isinstance(act_row, list):
            structural.append(_saved_structural_record(
                "unsupported_null", mixed_index,
                table_ordinal=act_ordinal, row_index=row_index))
            continue
        if len(ref_row) != len(act_row):
            for cell_index in range(len(act_row), len(ref_row)):
                structural.append(_saved_structural_record(
                    "missing_actual_cell", mixed_index,
                    table_ordinal=ref_ordinal, row_index=row_index,
                    cell_index=cell_index))
            for cell_index in range(len(ref_row), len(act_row)):
                structural.append(_saved_structural_record(
                    "extra_actual_cell", mixed_index,
                    table_ordinal=act_ordinal, row_index=row_index,
                    cell_index=cell_index))
            continue
        if row_counts_differ:
            continue
        for cell_index, (reference_text, actual_text) in enumerate(zip(ref_row, act_row)):
            if not isinstance(actual_text, str):
                if not _saved_cell_unsupported(
                        extraction, act_ordinal, row_index, cell_index):
                    structural.append(_saved_structural_record(
                        "unsupported_null", mixed_index,
                        table_ordinal=act_ordinal, row_index=row_index,
                        cell_index=cell_index))
                continue
            if not isinstance(reference_text, str):
                structural.append(_saved_structural_record(
                    "unsupported_null", mixed_index,
                    table_ordinal=act_ordinal, row_index=row_index,
                    cell_index=cell_index))
                continue
            if actual_text != reference_text:
                character.append(_saved_character_record(
                    mixed_index, reference_text, actual_text,
                    table_ordinal=act_ordinal, row_index=row_index,
                    cell_index=cell_index))
    return structural, character


def _saved_raw_reference_differences(extraction, raw_reference):
    if not raw_reference or not raw_reference.get("selected"):
        return []
    if raw_reference.get("error") or raw_reference.get("reference") is None:
        return [{
            "kind": "raw_reference_unmapped",
            "reason": "reference_identity",
            "selected": True,
            "path": raw_reference.get("path"),
            "identity_detail": raw_reference.get("identity_detail"),
        }]
    reference_elements = list(raw_reference["reference"].get("elements") or [])
    actual_elements = list(extraction.get("elements") or [])
    structural = []
    character = []
    shared = min(len(reference_elements), len(actual_elements))
    for index in range(shared):
        pair_structural, pair_character = _saved_raw_pair(
            extraction,
            index,
            reference_elements[index],
            actual_elements[index],
            _saved_table_ordinal(reference_elements, index),
            _saved_table_ordinal(actual_elements, index),
        )
        structural.extend(pair_structural)
        character.extend(pair_character)
    for index in range(shared, len(reference_elements)):
        structural.append({
            "kind": "raw_reference_unmapped",
            "reason": "missing_actual_element",
            "mixed_index": index,
        })
    for index in range(shared, len(actual_elements)):
        structural.append({
            "kind": "raw_reference_unmapped",
            "reason": "extra_actual_element",
            "mixed_index": index,
        })
    return structural + character



def _saved_record_unpaired_et_offers(et_block, unsupported, body_child_index):
    """Report original direct offers that this mixed index cannot inspect."""
    if et_block is None or _saved_ns(et_block.tag) != _SAVED_MAIN_NS:
        return
    local = _saved_local(et_block.tag)
    if local == "p":
        if _saved_paragraph_offer_indexes(et_block):
            unsupported.append(_saved_parent_record(
                "parent_text", body_child_index, None, None, None, None, None))
        return
    if local != "tbl":
        return
    for physical_row_index, row in enumerate(_saved_named_children(et_block, "tr")):
        for physical_tc_index, cell in enumerate(_saved_named_children(row, "tc")):
            for cell_paragraph_index, paragraph in enumerate(
                    _saved_named_children(cell, "p")):
                if not _saved_paragraph_offer_indexes(paragraph):
                    continue
                unsupported.append(_saved_parent_record(
                    "parent_text", body_child_index, None, None,
                    None, None, cell_paragraph_index,
                    physical_row_index=physical_row_index,
                    physical_tc_index=physical_tc_index,
                    logical_cell_represented=False))


def _saved_inspect_unrepresented_tc(et_tc, ox_tc, body_child_index, table_index,
                                    physical_row_index, physical_tc_index,
                                    unsupported):
    et_paragraphs = _saved_named_children(et_tc, "p")
    ox_paragraphs = (
        _saved_named_children(ox_tc, "p") if ox_tc is not None else [])
    aligned = ox_tc is not None and len(et_paragraphs) == len(ox_paragraphs)
    for cell_paragraph_index, et_p in enumerate(et_paragraphs):
        if not _saved_paragraph_offer_indexes(et_p):
            continue
        ox_p = ox_paragraphs[cell_paragraph_index] if aligned else None
        if ox_p is None:
            reason = "parent_text"
        else:
            view = _saved_paragraph_view(et_p, ox_p, None, None)
            if view["status"] == "ok":
                continue
            reason = view["reason"]
        unsupported.append(_saved_parent_record(
            reason, body_child_index, None, table_index,
            None, None, cell_paragraph_index,
            physical_row_index=physical_row_index,
            physical_tc_index=physical_tc_index,
            logical_cell_represented=False))


def _table_matrix(table, et_table, table_index, body_child_index, unsupported,
                  paragraph_index):
    raw_rows = []
    norm_rows = []
    doc_rows = list(table.rows)
    et_rows = _saved_named_children(et_table, "tr") if et_table is not None else []
    ox_to_et = {}
    ox_physical = {}
    physical = []
    if et_table is not None and len(et_rows) == len(doc_rows):
        for physical_row_index, (et_row, doc_row) in enumerate(zip(et_rows, doc_rows)):
            et_cells = _saved_named_children(et_row, "tc")
            ox_cells = _saved_named_children(doc_row._tr, "tc")
            aligned = len(et_cells) == len(ox_cells)
            for physical_tc_index, et_cell in enumerate(et_cells):
                ox_cell = ox_cells[physical_tc_index] if aligned else None
                if ox_cell is not None:
                    ox_to_et[id(ox_cell)] = et_cell
                    ox_physical[id(ox_cell)] = (
                        physical_row_index, physical_tc_index)
                physical.append((
                    physical_row_index, physical_tc_index, et_cell, ox_cell))
    elif et_table is not None:
        for physical_row_index, et_row in enumerate(et_rows):
            for physical_tc_index, et_cell in enumerate(
                    _saved_named_children(et_row, "tc")):
                physical.append((
                    physical_row_index, physical_tc_index, et_cell, None))
    represented = set()
    for doc_row in doc_rows:
        for cell in doc_row.cells:
            represented.add(id(cell._tc))
    for physical_row_index, physical_tc_index, et_cell, ox_cell in physical:
        if ox_cell is not None and id(ox_cell) in represented:
            continue
        _saved_inspect_unrepresented_tc(
            et_cell, ox_cell, body_child_index, table_index,
            physical_row_index, physical_tc_index, unsupported)
    cache = {}
    for row_index, doc_row in enumerate(doc_rows):
        raw = []
        norm = []
        for cell_index, cell in enumerate(doc_row.cells):
            key = id(cell._tc)
            physical_pos = ox_physical.get(key)
            if key in cache:
                raw_text, norm_text, failures = cache[key]
                for failure in failures:
                    unsupported.append(_saved_parent_record(
                        failure["reason"], body_child_index,
                        failure.get("paragraph_index"), table_index,
                        row_index, cell_index, failure["cell_paragraph_index"],
                        physical_row_index=(
                            None if physical_pos is None else physical_pos[0]),
                        physical_tc_index=(
                            None if physical_pos is None else physical_pos[1])))
                raw.append(raw_text)
                norm.append(norm_text)
                continue
            et_cell = ox_to_et.get(key)
            if et_cell is None:
                offered = _saved_tc_offer_paragraphs(cell._tc)
                if offered:
                    failures = []
                    for cell_paragraph_index in offered:
                        paragraph_at = paragraph_index + cell_paragraph_index
                        failures.append({
                            "reason": "parent_text",
                            "cell_paragraph_index": cell_paragraph_index,
                            "paragraph_index": paragraph_at,
                        })
                        unsupported.append(_saved_parent_record(
                            "parent_text", body_child_index, paragraph_at,
                            table_index, row_index, cell_index,
                            cell_paragraph_index))
                    stored = (None, None, failures)
                else:
                    text = cell.text
                    stored = (text, _extract_norm(text), [])
                paragraph_index += len(list(cell.paragraphs))
            else:
                cell_view, paragraph_index = _saved_cell_text(
                    et_cell, cell._tc, cell, table_index, row_index, cell_index,
                    body_child_index, paragraph_index, unsupported,
                    physical_row_index=physical_pos[0],
                    physical_tc_index=physical_pos[1])
                if cell_view["status"] != "ok":
                    stored = (None, None, list(cell_view.get("failures") or []))
                else:
                    stored = (
                        cell_view["raw_text"],
                        _extract_norm(cell_view["raw_text"]),
                        [])
            cache[key] = stored
            raw.append(stored[0])
            norm.append(stored[1])
        raw_rows.append(raw)
        norm_rows.append(norm)
    return raw_rows, norm_rows, paragraph_index


def _pipe_cells(line):
    """Bordered pipe row. A backslash-escaped pipe stays inside the cell."""
    raw = str(line or "").strip()
    if len(raw) < 2 or not raw.startswith("|") or not raw.endswith("|"):
        return None
    body = raw[1:-1]
    cells = []
    buf = []
    index = 0
    while index < len(body):
        char = body[index]
        if char == "\\" and index + 1 < len(body) and body[index + 1] == "|":
            buf.append("|")
            index += 2
            continue
        if char == "|":
            cells.append("".join(buf).strip())
            buf = []
            index += 1
            continue
        buf.append(char)
        index += 1
    cells.append("".join(buf).strip())
    return cells


def _separator_row(cells):
    return bool(cells) and all(
        re.fullmatch(r":?-{3,}:?", cell or "") for cell in cells)


def _section_text(expected, key):
    item = expected["saved_sections"][key]
    if isinstance(item, dict):
        return item["text"]
    return item


def _walk_section(section, text):
    """Ordered heading, paragraph and table blocks for one saved section."""
    blocks = []
    prose = []

    def flush():
        chunk = "\n".join(prose).strip()
        prose.clear()
        if chunk:
            blocks.append({
                "kind": "paragraph",
                "section": section,
                "text": chunk,
            })

    lines = str(text or "").splitlines()
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped:
            flush()
            index += 1
            continue
        heading = re.match(r"^(#{1,6})\s+(\S.*?)\s*$", stripped)
        if heading:
            flush()
            blocks.append({
                "kind": "heading",
                "section": section,
                "level": len(heading.group(1)),
                "text": heading.group(2).strip(),
            })
            index += 1
            continue
        if stripped.startswith("|") and stripped.endswith("|"):
            flush()
            raw_rows = []
            while index < len(lines) and "|" in lines[index]:
                if not lines[index].strip():
                    break
                cells = _pipe_cells(lines[index])
                if cells is None:
                    raise AssertionError("oracle_malformed_table:" + section)
                raw_rows.append(cells)
                index += 1
            if len(raw_rows) < 2 or not _separator_row(raw_rows[1]):
                raise AssertionError("oracle_malformed_table:" + section)
            header = raw_rows[0]
            if len(raw_rows[1]) != len(header):
                raise AssertionError("oracle_malformed_table:" + section)
            data = []
            for row in raw_rows[2:]:
                if _separator_row(row) or len(row) != len(header):
                    raise AssertionError("oracle_malformed_table:" + section)
                data.append(row)
            blocks.append({
                "kind": "table",
                "section": section,
                "header": header,
                "rows": data,
            })
            continue
        prose.append(lines[index])
        index += 1
    flush()
    return blocks


def _expected_stream(expected):
    """Fixture order checked against the accepted EXPECTED lists.

    The stream is built from the saved section texts. EXPECTED headings,
    paragraphs and tables have to agree with that walk. A disagreement
    stops the comparison before any delivered byte is treated as the oracle.
    """
    walked = []
    for key in SECTION_ORDER:
        walked.extend(_walk_section(key, _section_text(expected, key)))
    headings = list(expected.get("headings_in_order") or [])
    paragraphs = list(expected.get("paragraphs_in_order") or [])
    tables = list((expected.get("tables") or {}).items())
    walked_headings = [item for item in walked if item["kind"] == "heading"]
    walked_paragraphs = [item for item in walked if item["kind"] == "paragraph"]
    walked_tables = [item for item in walked if item["kind"] == "table"]
    if len(walked_headings) != len(headings):
        raise AssertionError("oracle_heading_count")
    for walked_item, accepted in zip(walked_headings, headings):
        if walked_item["section"] != accepted.get("section"):
            raise AssertionError("oracle_heading_section:" + walked_item["section"])
        if int(walked_item["level"]) != int(accepted.get("level") or 0):
            raise AssertionError("oracle_heading_level:" + walked_item["text"])
        if walked_item["text"] != accepted.get("text"):
            raise AssertionError("oracle_heading_text:" + walked_item["section"])
    if len(walked_paragraphs) != len(paragraphs):
        raise AssertionError("oracle_paragraph_count")
    for walked_item, accepted in zip(walked_paragraphs, paragraphs):
        if walked_item["section"] != accepted.get("section"):
            raise AssertionError("oracle_paragraph_section:" + walked_item["section"])
        if walked_item["text"] != accepted.get("text"):
            raise AssertionError("oracle_paragraph_text:" + walked_item["section"])
    if len(walked_tables) != len(tables):
        raise AssertionError("oracle_table_count")
    for walked_item, (name, accepted) in zip(walked_tables, tables):
        if list(walked_item["header"]) != list(accepted.get("header") or []):
            raise AssertionError("oracle_table_header:" + name)
        if list(walked_item["rows"]) != list(accepted.get("rows") or []):
            raise AssertionError("oracle_table_rows:" + name)
        walked_item["name"] = name
        walked_item["row_identities"] = list(accepted.get("row_identities") or [])
    return walked


def _paragraph_bold(paragraph, runs=None):
    if runs is None:
        selected = [run for run in paragraph.runs if str(run.text or "").strip()]
        return bool(selected) and all(bool(run.bold) for run in selected)
    selected = [run for run in runs if str(run.get("text") or "").strip()]
    return bool(selected) and all(bool(run.get("bold")) for run in selected)


def _paragraph_max_pt(paragraph, runs=None):
    if runs is None:
        selected = [run for run in paragraph.runs if str(run.text or "").strip()]
        sizes = [run.font.size.pt for run in selected if run.font.size is not None]
        return max(sizes) if sizes else None
    selected = [run for run in runs if str(run.get("text") or "").strip()]
    sizes = [run.get("size_pt") for run in selected if run.get("size_pt") is not None]
    return max(sizes) if sizes else None


def _extract(data, heading_norms):
    document = Document(BytesIO(data))
    original_root = _saved_original_document_root(data)
    et_blocks = _saved_body_blocks(original_root)
    para_by_el = {paragraph._p: paragraph for paragraph in document.paragraphs}
    table_by_el = {table._tbl: table for table in document.tables}
    ox_blocks = [
        child for child in document.element.body.iterchildren()
        if child in para_by_el or child in table_by_el
    ]
    paragraphs = []
    tables = []
    elements = []
    unsupported = []
    body_started = False
    paragraph_index = 0
    table_index = 0
    first_heading = heading_norms[0] if heading_norms else ""
    heading_set = set(heading_norms)
    for body_child_index, ox_child in enumerate(ox_blocks):
        et_child = et_blocks[body_child_index] if body_child_index < len(et_blocks) else None
        et_kind = _saved_local(et_child.tag) if et_child is not None else None
        ox_kind = "p" if ox_child in para_by_el else "tbl"
        kinds_match = et_child is not None and et_kind == ox_kind
        if ox_child in para_by_el:
            paragraph = para_by_el[ox_child]
            if kinds_match:
                view = _saved_paragraph_view(
                    et_child, ox_child, paragraph, paragraph_index)
            else:
                if et_child is not None:
                    _saved_record_unpaired_et_offers(
                        et_child, unsupported, body_child_index)
                ox_offers = _saved_paragraph_offer_indexes(ox_child)
                if ox_offers:
                    view = _saved_unsupported_view(
                        "parent_text", ox_offers, paragraph_index)
                else:
                    view = _saved_library_view(paragraph, paragraph_index)
            paragraph_index += 1
            if view["status"] == "ok":
                text = view["raw_text"]
                normalized = _extract_norm(text)
                bold = _paragraph_bold(paragraph, view["runs"])
                max_pt = _paragraph_max_pt(paragraph, view["runs"])
                reader_status = "ok"
                reader_profile = view["profile"]
                reader_reason = None
            elif view["status"] == "library":
                text = view["raw_text"]
                normalized = _extract_norm(text)
                bold = _paragraph_bold(paragraph)
                max_pt = _paragraph_max_pt(paragraph)
                reader_status = "ok"
                reader_profile = "direct"
                reader_reason = None
            else:
                text = None
                normalized = None
                bold = False
                max_pt = None
                reader_status = view["status"]
                reader_profile = view["profile"]
                reader_reason = view["reason"]
                unsupported.append(_saved_parent_record(
                    view["reason"], body_child_index, view["paragraph_index"],
                    None, None, None, None))
            starts_body = bool(
                first_heading
                and not body_started
                and bold
                and max_pt is not None
                and max_pt >= 14
                and normalized == first_heading
            )
            if starts_body:
                body_started = True
            role = "body" if body_started else "cover"
            element = {
                "kind": "paragraph",
                "text": text,
                "normalized": normalized,
                "style": paragraph.style.name if paragraph.style is not None else "",
                "bold": bold,
                "max_pt": max_pt,
                "starts_body": starts_body,
                "bold_heading": bool(
                    body_started and bold and normalized in heading_set),
                "role": role,
                "body_child_index": body_child_index,
                "reader_status": reader_status,
                "reader_profile": reader_profile,
                "reader_reason": reader_reason,
            }
            elements.append(element)
            paragraphs.append({
                "text": text,
                "normalized": normalized,
                "style": element["style"],
                "bold_heading": element["bold_heading"],
                "bold": bold,
                "role": role,
            })
        elif ox_child in table_by_el:
            role = "body" if body_started else "cover"
            before = len(unsupported)
            if not kinds_match and et_child is not None:
                _saved_record_unpaired_et_offers(
                    et_child, unsupported, body_child_index)
            raw_rows, norm_rows, paragraph_index = _table_matrix(
                table_by_el[ox_child],
                et_child if kinds_match else None,
                table_index, body_child_index, unsupported, paragraph_index)
            for record in unsupported[before:]:
                record["role"] = role
            element = {
                "kind": "table",
                "raw_rows": raw_rows,
                "rows": norm_rows,
                "role": role,
                "body_child_index": body_child_index,
                "table_index": table_index,
            }
            elements.append(element)
            tables.append(element)
            table_index += 1
    for body_child_index in range(len(ox_blocks), len(et_blocks)):
        before = len(unsupported)
        _saved_record_unpaired_et_offers(
            et_blocks[body_child_index], unsupported, body_child_index)
        role = "body" if body_started else "cover"
        for record in unsupported[before:]:
            record["role"] = role
    if not any(item.get("starts_body") for item in elements):
        for record in unsupported:
            record["role"] = "unknown"
    else:
        for record in unsupported:
            if record.get("role") is None and record.get("body_child_index") is not None:
                index = record["body_child_index"]
                if isinstance(index, int) and 0 <= index < len(elements):
                    source = elements[index]
                    record["role"] = source.get("role")
    return {
        "paragraphs": paragraphs,
        "tables": tables,
        "elements": elements,
        "unsupported_parents": unsupported,
        "comparison_reader": _SAVED_READER_ID,
        "rtl_flag_count": document.element.xml.count("w:rtl"),
        "bidi_flag_count": document.element.xml.count("w:bidi"),
        "rtl_flags_are_not_visual_acceptance": True,
        "pagination_not_established": True,
        "full_heading_outline_not_established": True,
    }


def _visible(extraction):
    parts = [item["normalized"] for item in extraction["paragraphs"]]
    for table in extraction["tables"]:
        for row in table["rows"]:
            parts.extend(row)
    return "\n".join(part for part in parts if part)


def _saved_metadata_values(expected):
    context = expected.get("saved_context") or {}
    return [
        ("organization", context.get("organization")),
        ("sector", context.get("sector")),
        ("document_title", context.get("document_title")),
        ("domain_display", context.get("domain_display")),
        ("document_type", VISIBLE_DOCUMENT_TYPE),
        ("artifact_status", VISIBLE_ARTIFACT_STATUS),
    ]


def _control_label_norms():
    norms = {_extract_norm(item) for item in CONTROL_LABELS}
    norms.update(_extract_norm(label) for label, _field in FIELD_CONTROL_LABELS)
    return norms


def _field_for_control_label(norm):
    for label, field in FIELD_CONTROL_LABELS:
        if norm == _extract_norm(label):
            return field
    return ""


def _raw_cell(item, row_index, cell_index, fallback):
    raw_rows = item.get("raw_rows") or []
    if row_index < len(raw_rows) and cell_index < len(raw_rows[row_index]):
        return raw_rows[row_index][cell_index]
    return fallback


def _cover_cell_difference(kind, item, table_index, row_index, cell_index, normalized):
    return {
        "kind": kind,
        "table_index": table_index,
        "row_index": row_index,
        "cell_index": cell_index,
        "text": _raw_cell(item, row_index, cell_index, normalized),
        "normalized": normalized,
    }


def _judge_control_values(differences, satisfied, table_index, field, label_norm, value_cells, expected_fields):
    """A labeled control value satisfies only when every value cell matches.

    An extra or contradictory cell remains a difference when the expected
    value is also present. The row then does not satisfy the field.
    """
    expected_value = ""
    expected_norm = ""
    for name, value, norm in expected_fields:
        if name == field:
            expected_value = value
            expected_norm = norm
            break
    if not expected_norm or not value_cells:
        return
    mismatched = [cell for cell in value_cells if cell["normalized"] != expected_norm]
    for cell in mismatched:
        differences.append({
            "kind": "control_value_conflict",
            "field": field,
            "label": label_norm,
            "expected": expected_value,
            "table_index": table_index,
            "row_index": cell["row_index"],
            "cell_index": cell["cell_index"],
            "text": cell["text"],
            "normalized": cell["normalized"],
        })
    if not mismatched:
        satisfied.add(field)


def _cover_class(norm, expected, heading_norms):
    if not norm:
        return "empty"
    labels = {
        _extract_norm(item)
        for item in (
            (expected.get("business_content_versus_cover") or {}).get(
                "cover_and_contents_labels_are_presentation") or [])
        if item
    }
    headings = set(heading_norms)
    if norm in labels:
        return "presentation_label"
    if norm in headings:
        return "contents_heading_label"
    metadata = {
        _extract_norm(value)
        for _name, value in _saved_metadata_values(expected)
        if value
    }
    if norm in metadata:
        return "saved_metadata"
    control_labels = {_extract_norm(item) for item in CONTROL_LABELS}
    control_labels.update(_extract_norm(label) for label, _field in FIELD_CONTROL_LABELS)
    if norm in control_labels:
        return "control_label"
    if norm in {_extract_norm(item) for item in COVER_CHROME}:
        return "cover_chrome"
    if re.fullmatch(r"\d{1,2} [A-Za-z]+ \d{4}", norm):
        return "preparation_date_chrome"
    numbered = re.fullmatch(r"\d+\s+(.+)", norm)
    if numbered and _extract_norm(numbered.group(1)) in labels | headings:
        return "contents_entry"
    return ""


def _public_expected(item):
    if item["kind"] == "heading":
        return {
            "kind": "heading",
            "section": item["section"],
            "normalized": _extract_norm(item["text"]),
        }
    if item["kind"] == "paragraph":
        return {
            "kind": "paragraph",
            "section": item["section"],
            "normalized": _extract_norm(item["text"]),
        }
    return {
        "kind": "table",
        "section": item["section"],
        "name": item.get("name"),
        "header": [_extract_norm(cell) for cell in item["header"]],
        "rows": [[_extract_norm(cell) for cell in row] for row in item["rows"]],
    }


def _compare_delivered(expected, extraction, raw_reference=None, date_context=None):
    differences = []
    for record in list(extraction.get("unsupported_parents") or []):
        item = dict(record)
        item["kind"] = "unsupported_token_parent"
        differences.append(item)
    literal_raw_differences = (
        _saved_raw_reference_differences(extraction, raw_reference)
        if raw_reference is not None else [])
    date_policy, accepted_date_indexes = _saved_preparation_date_policy(
        extraction, raw_reference, date_context, literal_raw_differences)
    raw_blocking = [
        item for index, item in enumerate(literal_raw_differences)
        if index not in accepted_date_indexes]
    differences.extend(
        item for item in raw_blocking if item.get("kind") == "raw_reference_unmapped")
    if date_policy["verdict"] == "failed":
        differences.append({
            "kind": "preparation_date_validation_failed",
            "policy_id": _SAVED_PREPARATION_DATE_POLICY,
            "mixed_index": 5,
            "table_ordinal": 0,
            "row_index": 5,
            "cell_index": 1,
            "reasons": list(date_policy["errors"]),
        })
    differences.extend(
        item for item in raw_blocking if item.get("kind") != "raw_reference_unmapped")
    visible = _visible(extraction)
    for marker in list(expected.get("forbidden_client_conflict_and_type_markers") or []):
        if marker and marker in visible:
            differences.append({"kind": "forbidden_marker", "marker": marker})
    for marker in list(expected.get("absent_from_document") or []):
        if marker and marker in visible:
            differences.append({"kind": "absent_marker_present", "marker": marker})
    stream = _expected_stream(expected)
    expected_public = [_public_expected(item) for item in stream]
    heading_norms = [
        item["normalized"] for item in expected_public if item["kind"] == "heading"]
    saved_paragraphs = {
        item["normalized"] for item in expected_public if item["kind"] == "paragraph"}
    business_headers = [
        tuple(item["header"]) for item in expected_public if item["kind"] == "table"]
    elements = list(extraction.get("elements") or [])
    boundary = next(
        (index for index, item in enumerate(elements) if item.get("starts_body")),
        None,
    )
    if boundary is None:
        differences.append({
            "kind": "body_boundary_absent",
            "heading": heading_norms[0] if heading_norms else "",
        })
    cover_elements = elements if boundary is None else elements[:boundary]
    cover_report = []
    satisfied_fields = set()
    label_norms = _control_label_norms()
    conflicting_status = {_extract_norm(value) for value in CONFLICTING_STATUS_VALUES}
    expected_fields = [
        (field, value, _extract_norm(value) if value else "")
        for field, value in _saved_metadata_values(expected)
    ]
    table_index = 0
    for item in cover_elements:
        if item["kind"] == "paragraph":
            classification = _cover_class(item["normalized"], expected, heading_norms)
            cover_report.append({
                "kind": "paragraph",
                "normalized": item["normalized"],
                "classification": classification or "unsourced",
                "text": item["text"],
            })
            if not item["normalized"]:
                continue
            for field, _value, norm in expected_fields:
                if norm and item["normalized"] == norm:
                    satisfied_fields.add(field)
            if item["normalized"] in saved_paragraphs:
                differences.append({
                    "kind": "misplaced_business_prose",
                    "text": item["text"],
                })
            elif item["normalized"] in conflicting_status:
                differences.append({
                    "kind": "conflicting_status_value",
                    "text": item["text"],
                })
            elif not classification:
                differences.append({
                    "kind": "unsourced_pre_body_prose",
                    "text": item["text"],
                })
            continue
        header = item["rows"][0] if item["rows"] else []
        cell_report = []
        pending = None
        if tuple(header) in business_headers:
            differences.append({
                "kind": "misplaced_business_table",
                "header": header,
                "table_index": table_index,
            })
        for row_index, row in enumerate(item["rows"]):
            labels_in_row = []
            nonempty = []
            for cell_index, cell in enumerate(row):
                if not cell:
                    continue
                text = _raw_cell(item, row_index, cell_index, cell)
                classification = _cover_class(cell, expected, heading_norms)
                cell_report.append({
                    "row_index": row_index,
                    "cell_index": cell_index,
                    "normalized": cell,
                    "text": text,
                    "classification": classification or "unsourced",
                })
                nonempty.append({
                    "row_index": row_index,
                    "cell_index": cell_index,
                    "normalized": cell,
                    "text": text,
                })
                field = _field_for_control_label(cell)
                if field:
                    labels_in_row.append((field, cell, cell_index))
                if cell in saved_paragraphs:
                    differences.append(_cover_cell_difference(
                        "misplaced_business_prose", item, table_index,
                        row_index, cell_index, cell))
                elif cell in conflicting_status:
                    differences.append(_cover_cell_difference(
                        "conflicting_status_value", item, table_index,
                        row_index, cell_index, cell))
                elif not classification:
                    differences.append(_cover_cell_difference(
                        "unsourced_pre_body_prose", item, table_index,
                        row_index, cell_index, cell))
            value_cells = [
                cell for cell in nonempty if cell["normalized"] not in label_norms]
            if labels_in_row:
                pending = None
                if len(labels_in_row) == 1 and not value_cells:
                    pending = labels_in_row[0][:2]
                elif len(labels_in_row) == 1:
                    field, label_norm, _label_at = labels_in_row[0]
                    _judge_control_values(
                        differences, satisfied_fields, table_index,
                        field, label_norm, value_cells, expected_fields)
                else:
                    for index, (field, label_norm, label_at) in enumerate(labels_in_row):
                        next_at = (
                            labels_in_row[index + 1][2]
                            if index + 1 < len(labels_in_row) else None)
                        assigned = [
                            cell for cell in value_cells
                            if cell["cell_index"] > label_at
                            and (next_at is None or cell["cell_index"] < next_at)
                        ]
                        _judge_control_values(
                            differences, satisfied_fields, table_index,
                            field, label_norm, assigned, expected_fields)
            elif pending is not None:
                field, label_norm = pending
                pending = None
                if value_cells:
                    _judge_control_values(
                        differences, satisfied_fields, table_index,
                        field, label_norm, value_cells, expected_fields)
        cover_report.append({
            "kind": "table",
            "table_index": table_index,
            "header": header,
            "rows": item["rows"],
            "raw_rows": item["raw_rows"],
            "cells": cell_report,
        })
        table_index += 1
    for field, value, _norm in expected_fields:
        if not value:
            differences.append({
                "kind": "saved_metadata_missing_from_expected",
                "field": field,
            })
            continue
        if field not in satisfied_fields:
            differences.append({
                "kind": "cover_metadata_absent",
                "field": field,
                "expected": value,
            })
    if boundary is None:
        actual = []
    else:
        actual = []
        heading_queue = [
            item for item in expected_public if item["kind"] == "heading"]
        queue_index = 0
        current_section = None
        for item in elements[boundary:]:
            if item["kind"] == "paragraph" and not item["normalized"]:
                continue
            next_heading = (
                heading_queue[queue_index]
                if queue_index < len(heading_queue) else None)
            if (
                    item["kind"] == "paragraph"
                    and item.get("bold")
                    and next_heading is not None
                    and item["normalized"] == next_heading["normalized"]):
                current_section = next_heading["section"]
                queue_index += 1
                actual.append({
                    "kind": "heading",
                    "section": current_section,
                    "normalized": item["normalized"],
                    "text": item["text"],
                })
                continue
            if item["kind"] == "paragraph":
                actual.append({
                    "kind": "paragraph",
                    "section": current_section,
                    "normalized": item["normalized"],
                    "text": item["text"],
                    "bold": bool(item.get("bold")),
                })
                continue
            actual.append({
                "kind": "table",
                "section": current_section,
                "rows": item["rows"],
                "raw_rows": item["raw_rows"],
            })
    compared = min(len(expected_public), len(actual))
    for index in range(compared):
        left = expected_public[index]
        right = actual[index]
        if left["kind"] != right["kind"] or left["section"] != right.get("section"):
            differences.append({
                "kind": "stream_placement",
                "index": index,
                "expected": left,
                "actual_kind": right["kind"],
                "actual_section": right.get("section"),
                "actual_text": right.get("text"),
                "actual_normalized": right.get("normalized"),
                "actual_header": (right.get("rows") or [[]])[0] if right["kind"] == "table" else None,
            })
            continue
        if left["kind"] in ("heading", "paragraph"):
            if left["normalized"] != right.get("normalized"):
                differences.append({
                    "kind": "stream_text",
                    "index": index,
                    "section": left["section"],
                    "expected": left["normalized"],
                    "actual": right.get("text"),
                })
            continue
        actual_rows = list(right.get("rows") or [])
        raw_rows = list(right.get("raw_rows") or [])
        expected_rows = [left["header"]] + list(left["rows"])
        if actual_rows != expected_rows:
            differences.append({
                "kind": "stream_table",
                "index": index,
                "section": left["section"],
                "name": left.get("name"),
                "expected": expected_rows,
                "actual_normalized": actual_rows,
                "actual_raw": raw_rows,
            })
        source = next(
            item for item in stream
            if item["kind"] == "table" and item.get("name") == left.get("name"))
        for row_index, identity in enumerate(source.get("row_identities") or []):
            if row_index >= len(actual_rows) - 1:
                differences.append({
                    "kind": "source_row_absent",
                    "table": left.get("name"),
                    "index": row_index,
                })
                continue
            actual_row = actual_rows[row_index + 1]
            column = identity.get("business_identifier_column_index")
            identifier = identity.get("business_identifier")
            if column is not None and identifier is not None:
                if column >= len(actual_row) or actual_row[column] != _extract_norm(identifier):
                    differences.append({
                        "kind": "identifier_column",
                        "table": left.get("name"),
                        "index": row_index,
                        "column": column,
                        "expected": identifier,
                        "actual": actual_row[column] if column < len(actual_row) else None,
                    })
            first_column = identity.get("first_cell_column_index")
            first_cell = identity.get("first_cell")
            if first_column is not None and first_cell is not None:
                if (
                        first_column >= len(actual_row)
                        or actual_row[first_column] != _extract_norm(first_cell)):
                    differences.append({
                        "kind": "first_cell_column",
                        "table": left.get("name"),
                        "index": row_index,
                        "expected": first_cell,
                        "actual": (
                            actual_row[first_column]
                            if first_column < len(actual_row) else None),
                    })
    if len(actual) > len(expected_public):
        for index, item in enumerate(actual[len(expected_public):], len(expected_public)):
            differences.append({
                "kind": "stream_extra",
                "index": index,
                "actual_kind": item["kind"],
                "actual_section": item.get("section"),
                "actual_text": item.get("text"),
                "actual_normalized": item.get("normalized"),
                "actual_header": (item.get("rows") or [[]])[0] if item["kind"] == "table" else None,
            })
            if item["kind"] == "table":
                differences.append({
                    "kind": "alternative_body_table",
                    "index": index,
                    "header": (item.get("rows") or [[]])[0],
                })
    if len(expected_public) > len(actual):
        for index, item in enumerate(expected_public[len(actual):], len(actual)):
            differences.append({
                "kind": "stream_absent",
                "index": index,
                "expected": item,
            })
    seen_headers = [
        tuple(item["rows"][0])
        for item in actual
        if item["kind"] == "table" and item.get("rows")]
    for header in business_headers:
        if seen_headers.count(header) > 1:
            differences.append({
                "kind": "duplicate_source_table",
                "header": list(header),
            })
    if "82 من 100" not in visible:
        differences.append({"kind": "confidence_statement_absent"})
    confidence_section = "\n".join(
        item["normalized"]
        for item in actual
        if item.get("kind") == "paragraph" and item.get("section") == "confidence"
    )
    if confidence_section and _extract_norm("99.5%") == confidence_section.strip():
        differences.append({"kind": "confidence_replaced_by_operational_percent"})
    return {
        "expected_stream": expected_public,
        "actual_stream": actual,
        "cover_elements": cover_report,
        "literal_raw_differences": literal_raw_differences,
        "literal_raw_difference_count": len(literal_raw_differences),
        "preparation_date_policy": date_policy,
        "accepted_date_differences": date_policy["accepted_date_differences"],
        "differences": differences,
        "text_comparison_does_not_establish_pagination": True,
        "text_comparison_does_not_establish_full_heading_outline": True,
        "text_comparison_does_not_establish_visual_acceptance": True,
    }


def _assert_positive_delivery(observations, expected, delivered, provenance, run,
                              raw_reference=None):
    if not delivered or not delivered.startswith(b"PK"):
        raise AssertionError(provenance + "_not_docx_package")
    saved = _write_bytes(run / f"delivered_{provenance}.docx", delivered)
    observations["delivered"] = saved
    heading_norms = [
        _extract_norm(item["text"])
        for item in expected.get("headings_in_order") or []
    ]
    extraction = _extract(delivered, heading_norms)
    _write_text(
        run / f"extraction_{provenance}.json",
        json.dumps(extraction, ensure_ascii=False, indent=2),
    )
    date_context = _saved_preparation_date_context(
        observations, observations.get("record_id"), provenance, saved)
    report = _compare_delivered(expected, extraction, raw_reference, date_context)
    if report["preparation_date_policy"]["selected"]:
        observations["preparation_date_policy"] = report["preparation_date_policy"]
    differences = list(report.get("differences") or [])
    _write_text(
        run / f"comparison_{provenance}.txt",
        json.dumps(report, ensure_ascii=False, indent=2),
    )
    observations["difference_count"] = len(differences)
    if differences:
        raise AssertionError(provenance + "_comparison:" + str(len(differences)))
    for call in observations.get("writer_calls") or []:
        diagnostic = (call.get("diagnostic") or {}).get("sha256")
        if diagnostic and diagnostic == saved["sha256"]:
            observations["diagnostic_hash_matches_delivery"] = True
        observations["diagnostic_is_not_owner_delivery"] = True


def _assert_refusal_evidence(observations):
    route = observations.get("route") or {}
    full = list(route.get("blocking_errors") or [])
    observations["full_authoritative_blockers"] = full
    if OBJECTIVE_REFUSAL not in full:
        raise AssertionError("objective_refusal_absent:" + json.dumps(full, ensure_ascii=False))
    if route.get("export_return_allowed") is not False:
        raise AssertionError("refusal_permission_true")
    if observations.get("writer_calls"):
        raise AssertionError("refusal_writer_entered")
    if "rel3_export_with_evidence" in _names(observations):
        raise AssertionError("refusal_export_entered")
    return full


def _sync_case(client, payload, observations, expected, run, record):
    started = time.monotonic()
    observations["http_call_started"] = True
    response = client.post(
        "/api/generate-docx",
        json={key: value for key, value in payload.items() if key != "_saved_context_for_observations"},
        headers={"X-CSRFToken": CSRF},
    )
    body = response.get_json(silent=True)
    observations["http"] = {
        "status_code": response.status_code,
        "content_type": response.content_type,
        "body": body,
        "byte_count": len(response.data or b""),
        "elapsed_seconds": time.monotonic() - started,
    }
    _write_bytes(run / "sync_response_bytes.bin", response.data or b"")
    if record == 701:
        full = _assert_refusal_evidence(observations)
        if response.status_code != 422 or not isinstance(body, dict):
            raise AssertionError("sync_refusal_status")
        if body.get("reason") != SYNC_REFUSAL_REASON:
            raise AssertionError("sync_refusal_reason")
        if body.get("blocking_errors") != full[:RESPONSE_BLOCKER_LIMIT]:
            raise AssertionError("sync_refusal_projection")
        if (response.data or b"").startswith(b"PK"):
            raise AssertionError("sync_refusal_docx_body")
        disposition = response.headers.get("Content-Disposition", "")
        if "attachment" in disposition.lower():
            raise AssertionError("sync_refusal_attachment")
        return
    if response.status_code != 200:
        raise AssertionError("sync_positive_status:" + str(response.status_code))
    raw_reference = _saved_raw_reference_context(
        observations, record, "sync_owner_response")
    _assert_positive_delivery(
        observations, expected, response.data or b"", "sync_owner_response", run,
        raw_reference)


def _task_store_snapshot(task_id):
    """Read the real export-task entry. This does not create one."""
    store = getattr(app_module, "_export_store", None)
    if not isinstance(store, dict) or task_id not in store:
        return {"present": False, "task_id": task_id}
    entry = store.get(task_id)
    if not isinstance(entry, dict):
        return {
            "present": False,
            "task_id": task_id,
            "entry_type": type(entry).__name__,
        }
    return {
        "present": True,
        "task_id": task_id,
        "status": entry.get("status"),
        "user_id": entry.get("user_id"),
        "record_id": entry.get("record_id"),
        "has_user_id": "user_id" in entry,
        "has_record_id": "record_id" in entry,
        "error": entry.get("error") if "error" in entry else None,
    }


def _assert_task_store(snapshot, record, phase):
    if not snapshot.get("present"):
        raise AssertionError(phase + "_task_store_absent")
    if not snapshot.get("has_user_id") or not snapshot.get("has_record_id"):
        raise AssertionError(phase + "_task_fields_absent")
    if snapshot.get("user_id") != OWNER_ID or snapshot.get("record_id") != record:
        raise AssertionError(
            phase + "_task_metadata:" + json.dumps({
                "observed_user_id": snapshot.get("user_id"),
                "observed_record_id": snapshot.get("record_id"),
                "expected_user_id": OWNER_ID,
                "expected_record_id": record,
            }, ensure_ascii=False))


def _async_case(client, payload, observations, expected, run, record, lifecycle):
    started = time.monotonic()
    lifecycle["deadline"] = started + DEADLINE_SECONDS
    _ACTIVE_DEADLINE[0] = lifecycle["deadline"]
    observations["task_expected"] = {"user_id": OWNER_ID, "record_id": record}
    observations["http_call_started"] = True
    posted = client.post(
        "/api/generate-docx-async",
        json={key: value for key, value in payload.items() if key != "_saved_context_for_observations"},
        headers={"X-CSRFToken": CSRF},
    )
    post_body = posted.get_json(silent=True)
    task_id = (post_body or {}).get("task_id") if posted.status_code == 200 else None
    observations["post"] = {
        "status_code": posted.status_code,
        "body": post_body,
        "task_id": task_id,
    }
    if posted.status_code != 200 or not task_id:
        raise AssertionError("async_post")
    lifecycle["task_id"] = task_id
    thread = _export_thread(lifecycle)
    lifecycle["thread"] = thread
    if thread is None or not getattr(thread, "_export_worker", False):
        raise AssertionError("async_worker_not_recorded")
    remaining = lifecycle["deadline"] - time.monotonic()
    if remaining <= 0 or not thread._entered.wait(remaining):
        raise AssertionError("async_worker_not_entered")
    pending = _task_store_snapshot(task_id)
    observations["task_store_pending_observed"] = pending
    if pending.get("status") != "pending":
        raise AssertionError("async_pending_status")
    _assert_task_store(pending, record, "async_pending")
    thread._release.set()
    lifecycle["barrier_released"] = True
    statuses = []
    while time.monotonic() < lifecycle["deadline"]:
        response = client.get("/api/export-status/" + task_id)
        body = response.get_json(silent=True)
        item = {
            "status_code": response.status_code,
            "body": body,
            "status_body_keys": sorted(body.keys()) if isinstance(body, dict) else [],
            "elapsed_seconds": time.monotonic() - started,
        }
        statuses.append(item)
        state = body.get("status") if isinstance(body, dict) else None
        if state in ("done", "error", "not_found") or response.status_code in (403, 404, 500):
            break
        time.sleep(0.25)
    observations["statuses"] = statuses
    terminal_store = _task_store_snapshot(task_id)
    observations["task_store_terminal_observed"] = terminal_store
    _assert_task_store(terminal_store, record, "async_terminal")
    terminal = statuses[-1] if statuses else None
    if record == 701:
        full = _assert_refusal_evidence(observations)
        observations["worker_objective_refusal_recorded"] = OBJECTIVE_REFUSAL in full
        if terminal_store.get("status") != "error":
            raise AssertionError("async_terminal_store_status")
        if not terminal or terminal["status_code"] != 500:
            raise AssertionError("async_refusal_status")
        if (terminal["body"] or {}).get("status") != "error":
            raise AssertionError("async_refusal_state")
        downloaded = client.get("/api/export-download/" + task_id)
        if (downloaded.data or b"").startswith(b"PK") or downloaded.status_code == 200:
            raise AssertionError("async_refusal_download")
        return
    if terminal_store.get("status") != "done":
        raise AssertionError("async_terminal_store_status")
    if not terminal or terminal["status_code"] != 200 or (terminal["body"] or {}).get("status") != "done":
        raise AssertionError("async_positive_status")
    downloaded = client.get("/api/export-download/" + task_id)
    if downloaded.status_code != 200:
        raise AssertionError("async_owner_download_status")
    _assert_positive_delivery(
        observations, expected, downloaded.data or b"", "async_owner_download", run)


def _observation_availability(observations):
    if observations.get("wrappers_installed"):
        observations["route_observation"] = (
            "entered" if "route" in observations else "not_entered")
        observations["writer_observation"] = (
            "entered" if observations.get("writer_calls") else "not_entered")
    else:
        observations["route_observation"] = "unavailable"
        observations["writer_observation"] = "unavailable"
        observations["writer_calls_not_an_observation"] = True
    call_started = bool(observations.get("http_call_started"))
    response_present = ("http" in observations) or ("post" in observations)
    if call_started and response_present:
        observations["http_observation"] = "entered"
        observations["record_role"] = "case_result"
    elif call_started:
        observations["http_observation"] = "started_without_response"
        observations["record_role"] = "started_without_response"
    else:
        observations["http_observation"] = "unavailable"
        observations["record_role"] = "setup_stage"


def _run_case(name, record, transport, freshness):
    _block_if_prior_worker_unresolved()
    observations = {
        "case": name,
        "record_id": record,
        "owner_id": OWNER_ID,
        "transport": transport,
        "freshness": freshness,
        "failure_stage": "not_started",
        "http_call_started": False,
        "wrappers_installed": False,
        "order": [],
    }
    lifecycle = {
        "deadline": None,
        "thread": None,
        "join_invoked": False,
        "restored": False,
        "barrier_released": False,
        "worker_mark": len(RecordingThread.created),
        "released_current_workers": 0,
    }
    originals = None
    run = None
    fixture_bytes = b""
    expected_bytes = b""
    try:
        observations["failure_stage"] = "database_path"
        _assert_database_path()
        observations["failure_stage"] = "fixture_load"
        fixture_text, expected, sections, fixture_bytes, expected_bytes = _load_pair(record)
        observations["fixture_text"] = fixture_text
        observations["sections"] = sections
        observations["failure_stage"] = "body_layout"
        _assert_body_layout(record, fixture_text, sections)
        run = _run_dir() / name
        run.mkdir(parents=True, exist_ok=True)
        observations["failure_stage"] = "registry_cleanup"
        _cleanup_process_state(observations)
        observations["failure_stage"] = "init_db"
        app_module.init_db()
        observations["failure_stage"] = "fixture_insert"
        _insert(record, expected, fixture_text, sections)
        observations["failure_stage"] = "database_fixture_state"
        observations["database_fixture_state"] = _assert_disposable_database(record, expected)
        observations["failure_stage"] = "registry_registration"
        if freshness == "fresh":
            if "701" in canon._ARTIFACT_REGISTRY or "702" in canon._ARTIFACT_REGISTRY:
                raise AssertionError("fresh_registry_not_empty")
            observations["registry_writes_before_post"] = []
        elif record == 702:
            _register_702(fixture_text, sections, observations)
        else:
            _register_701(fixture_text, sections, observations)
        payload = _payload(record, expected)
        observations["client_conflict_marker"] = "CLIENT CONFLICT MARKER"
        observations["failure_stage"] = "wrapper_install"
        originals = _install(observations, run, record)
        observations["wrappers_installed"] = True
        observations["failure_stage"] = "http"
        client = app_module.app.test_client()
        with client.session_transaction() as sess:
            sess["user_id"] = OWNER_ID
            sess["csrf_token"] = CSRF
        if transport == "sync":
            _sync_case(client, payload, observations, expected, run, record)
        else:
            _async_case(client, payload, observations, expected, run, record, lifecycle)
        observations["failure_stage"] = "saved_path"
        _assert_common_saved_path(observations, record)
        observations["failure_stage"] = "freshness"
        if freshness == "fresh":
            _assert_fresh(observations)
        else:
            _assert_reuse(observations, record)
        if record == 702 and observations.get("route", {}).get("export_return_allowed") is not True:
            raise AssertionError("positive_permission_false")
        if record == 702 and not observations.get("exports"):
            raise AssertionError("positive_export_absent")
        if record == 702 and not observations.get("writer_calls"):
            raise AssertionError("positive_writer_absent")
        if record == 702 and any(observations.get("quality") or []):
            raise AssertionError(
                "positive_quality_blockers:"
                + json.dumps(observations.get("quality"), ensure_ascii=False))
        observations["failure_stage"] = "completed"
    except Exception as exc:
        observations["setup_exception"] = type(exc).__name__ + ": " + str(exc)
        raise
    finally:
        released = _release_export_barrier(lifecycle)
        lifecycle["released_current_workers"] = released
        observations["current_worker_count"] = len(_current_workers(lifecycle))
        observations["released_current_workers"] = released
        if released:
            lifecycle["barrier_released"] = True
        if lifecycle.get("deadline") is None and _export_thread(lifecycle) is not None:
            lifecycle["deadline"] = time.monotonic()
        if lifecycle.get("thread") is None:
            lifecycle["thread"] = _export_thread(lifecycle)
        _join_recorded_worker(lifecycle)
        if originals is None:
            lifecycle["restored"] = lifecycle.get("thread") is None or not lifecycle["thread"].is_alive()
        else:
            lifecycle["restored"] = _restore(originals, lifecycle.get("thread"))
        _remember_case(name, lifecycle)
        _ACTIVE_DEADLINE[0] = None
        task_id = lifecycle.get("task_id")
        if task_id and "task_store_terminal_observed" not in observations:
            observations["task_store_at_cleanup_observed"] = _task_store_snapshot(task_id)
        _observation_availability(observations)
        if run is not None:
            _write_text(
                run / "observations.json",
                json.dumps({
                    key: value for key, value in observations.items()
                    if key not in ("fixture_text", "sections")
                }, ensure_ascii=False, indent=2, default=str),
            )
    if transport == "async" and observations.get("http_call_started"):
        thread = lifecycle.get("thread")
        if thread is None or not lifecycle.get("join_invoked") or thread.is_alive():
            raise AssertionError("async_worker_unjoined")
    if run is not None and observations.get("failure_stage") == "completed":
        _write_bytes(run / "fixture_bytes.bin", fixture_bytes)
        _write_bytes(run / "expected_bytes.bin", expected_bytes)


def test_contract_r_702_sync_fresh():
    _run_case("test_contract_r_702_sync_fresh", 702, "sync", "fresh")


def test_contract_r_702_sync_matching_reuse():
    _run_case("test_contract_r_702_sync_matching_reuse", 702, "sync", "reuse")


def test_contract_r_702_async_fresh():
    _run_case("test_contract_r_702_async_fresh", 702, "async", "fresh")


def test_contract_r_702_async_matching_reuse():
    _run_case("test_contract_r_702_async_matching_reuse", 702, "async", "reuse")


def test_contract_r_701_sync_fresh_refusal():
    _run_case("test_contract_r_701_sync_fresh_refusal", 701, "sync", "fresh")


def test_contract_r_701_sync_matching_reuse_refusal():
    _run_case("test_contract_r_701_sync_matching_reuse_refusal", 701, "sync", "reuse")


def test_contract_r_701_async_fresh_refusal():
    _run_case("test_contract_r_701_async_fresh_refusal", 701, "async", "fresh")


def test_contract_r_701_async_matching_reuse_refusal():
    _run_case("test_contract_r_701_async_matching_reuse_refusal", 701, "async", "reuse")
