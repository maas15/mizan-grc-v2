"""One real DOCX render of saved Arabic-DT strategy 701.

Authorization:
MIZAN-SAVED-ARABIC-DT-REAL-DOCX-VERIFICATION-AUTHORIZATION-20261102-01
Authorized request:
MIZAN-SAVED-ARABIC-DT-REAL-DOCX-VERIFICATION-REQUEST-20261102-01

The module reads the unchanged preparation files. It does not stub the
gate, the authority route, the worker, or the DOCX writer.
"""

import hashlib
import json
import os
import re
import sqlite3
import threading
import time
import zipfile
from io import BytesIO
from pathlib import Path

import app as app_module
from docx import Document
from docx.oxml.ns import qn


PREP = Path("/opt/cursor/artifacts/docx-real-render-preparation-20261102")
FIXTURE_PATH = PREP / "REAL_DOCX_STRATEGY_FIXTURE.md"
EXPECTED_PATH = PREP / "REAL_DOCX_EXPECTED_CONTENT.json"
DATABASE = "/tmp/mizan-docx-real-render-20261102-01/app.db"
CSRF = "synthetic-csrf-token-docx-real-701"
CLIENT_CONFLICT = (
    "CLIENT CONFLICT MARKER: unsaved English drafting sentence "
    "must not appear in the DOCX."
)
MARKER_TOKEN = "CLIENT CONFLICT MARKER"
DEADLINE_SECONDS = 120
PAYLOAD = {
    "content": CLIENT_CONFLICT,
    "filename": "dt-consulting-strategy-701",
    "language": "en",
    "org_name": "مؤسسة الميزان التجريبية",
    "sector": "الخدمات الحكومية الرقمية",
    "doc_type": "risk",
    "domain": "Digital Transformation",
    "selected_frameworks": ["DGA"],
    "artifact_id": 701,
    "strategy_id": 701,
    "artifact_type": "strategy",
    "document_type": "strategy",
    "generation_mode": "drafting",
}

_ORIG_THREAD = threading.Thread
_UNRESOLVED_PRIOR_CASE = None
_SAVED_WRITER_DOMAINS = frozenset({
    "dt",
    "Digital Transformation",
    "التحول الرقمي",
})


class RecordingThread(_ORIG_THREAD):
    """Real thread. The export worker stays available for one join."""

    created = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        RecordingThread.created.append(self)

    def start(self):
        return super().start()


def _run_dir():
    return Path(os.environ["DATABASE_PATH"]).parent


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _write_bytes(path, data):
    path = Path(path)
    path.write_bytes(data)
    return {"path": str(path), "bytes": len(data), "sha256": _sha(data)}


def _write_text(path, text):
    data = text.encode("utf-8")
    if not data.endswith(b"\n"):
        data += b"\n"
    return _write_bytes(path, data)


def _write_exact(path, text):
    """Argument-byte capture. No added final LF."""
    return _write_bytes(path, str(text or "").encode("utf-8"))


def _norm(value):
    text = str(value or "").replace("\u00a0", " ")
    return re.sub(r"\s+", " ", text).strip()


def _json_ready(value):
    try:
        json.dumps(value, ensure_ascii=False)
        return value
    except TypeError:
        return str(value)


def _block_if_prior_worker_unresolved():
    """Fail a later case while an earlier worker or its observers remain.

    This does not join, replace observers, clear thread records, or open
    another waiting window.
    """
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


def _remember_case_after_cleanup(name, lifecycle):
    global _UNRESOLVED_PRIOR_CASE
    thread = lifecycle.get("thread")
    alive = bool(thread is not None and thread.is_alive())
    if alive or not lifecycle.get("restored"):
        _UNRESOLVED_PRIOR_CASE = {"name": name, "lifecycle": lifecycle}
    else:
        _UNRESOLVED_PRIOR_CASE = None


def _export_thread():
    found = []
    for thread in RecordingThread.created:
        target = getattr(thread, "_target", None)
        if getattr(target, "__name__", "") == "_build":
            found.append(thread)
    if found:
        return found[-1]
    return RecordingThread.created[-1] if RecordingThread.created else None


def _install(observations, run):
    originals = {
        "gate": app_module._enforce_export_gate,
        "route": app_module._rel31_authoritative_export_route,
        "writer": app_module._build_docx_bytes,
        "thread": threading.Thread,
    }
    RecordingThread.created = []
    threading.Thread = RecordingThread

    def gate_wrap(*args, **kwargs):
        content = args[2] if len(args) > 2 else kwargs.get("content")
        record = {
            "artifact_type": args[0] if args else kwargs.get("artifact_type"),
            "artifact_id": args[1] if len(args) > 1 else kwargs.get("artifact_id"),
            "generation_mode": (
                args[3] if len(args) > 3 else kwargs.get("generation_mode")
            ),
            "user_id": args[4] if len(args) > 4 else kwargs.get("user_id"),
            "content_is_fixture": content == observations["fixture_text"],
            "client_conflict_in_content": CLIENT_CONFLICT in str(content or ""),
        }
        saved = _write_exact(run / "gate_input_content.txt", str(content or ""))
        record["content_sha256"] = saved["sha256"]
        record["content_capture_exact_bytes"] = True
        try:
            result = originals["gate"](*args, **kwargs)
        except Exception as exc:
            record["exception"] = repr(exc)
            observations["gate"] = record
            raise
        record["result"] = result
        observations["gate"] = record
        return result

    def route_wrap(*args, **kwargs):
        art = dict(kwargs.get("artifact_dict") or {})
        sections = dict(art.get("sections") or {})
        meta = dict(art.get("contract_meta") or {})
        record = {
            "route": args[0] if args else kwargs.get("route"),
            "domain": kwargs.get("domain"),
            "lang": kwargs.get("lang"),
            "document_type": art.get("document_type"),
            "strategy_id": str(art.get("strategy_id") or ""),
            "artifact_id": str(art.get("artifact_id") or ""),
            "contract_meta": meta,
            "section_keys": sorted(sections),
            "export_user_id": art.get("_rel32_export_user_id"),
            "fidelity_owner_id": (
                (art.get("_saved_docx_fidelity") or {}).get("owner_id")
                if isinstance(art.get("_saved_docx_fidelity"), dict) else None
            ),
            "fidelity_record_id": (
                (art.get("_saved_docx_fidelity") or {}).get("record_id")
                if isinstance(art.get("_saved_docx_fidelity"), dict) else None
            ),
            "final_markdown_is_fixture": (
                art.get("final_markdown") == observations["fixture_text"]
            ),
            "export_kwargs": {
                key: _json_ready(value)
                for key, value in dict(kwargs.get("export_kwargs") or {}).items()
                if key != "backend"
            },
        }
        saved_markdown = _write_exact(
            run / "route_input_final_markdown.md",
            str(art.get("final_markdown") or ""),
        )
        record["final_markdown_sha256"] = saved_markdown["sha256"]
        record["final_markdown_capture_exact_bytes"] = True
        _write_text(
            run / "route_input_sections.json",
            json.dumps(sections, ensure_ascii=False, indent=2),
        )
        try:
            result = originals["route"](*args, **kwargs)
        except Exception as exc:
            record["exception"] = repr(exc)
            observations["route"] = record
            raise
        record["result_is_none"] = result is None
        if isinstance(result, tuple) and len(result) == 2:
            export, evidence = result
            raw = getattr(export, "docx_bytes", None) or getattr(
                export, "bytes_data", None
            ) or b""
            record.update({
                "export_return_allowed": bool(
                    getattr(evidence, "export_return_allowed", False)
                ),
                "evidence_passed": bool(getattr(evidence, "evidence_passed", False)),
                "blocking_errors": list(
                    getattr(evidence, "blocking_errors", None) or []
                ),
                "export_blocking_errors": list(
                    getattr(export, "blocking_errors", None) or []
                ),
                "route_name": getattr(evidence, "route_name", ""),
                "returned_bytes": len(raw) if isinstance(raw, (bytes, bytearray)) else 0,
            })
        observations["route"] = record
        return result

    def writer_wrap(*args, **kwargs):
        call_no = len(observations["writer_calls"]) + 1
        content = args[0] if args else kwargs.get("content")
        sections = kwargs.get("sections")
        if sections is None and len(args) >= 12:
            sections = args[11]
        section_copy = dict(sections or {}) if isinstance(sections, dict) else {}
        record = {
            "call": call_no,
            "filename": args[1] if len(args) > 1 else kwargs.get("filename"),
            "lang": args[2] if len(args) > 2 else kwargs.get("lang"),
            "org_name": kwargs.get("org_name", args[3] if len(args) > 3 else ""),
            "sector": kwargs.get("sector", args[4] if len(args) > 4 else ""),
            "doc_type": kwargs.get("doc_type", args[5] if len(args) > 5 else ""),
            "domain": kwargs.get("domain", args[6] if len(args) > 6 else ""),
            "selected_frameworks": _json_ready(
                kwargs.get("selected_frameworks")
            ),
            "rel2_export_validation": kwargs.get("rel2_export_validation"),
            "section_keys": sorted(section_copy),
            "traceability_present": bool(
                str(section_copy.get("traceability") or "").strip()
            ),
            "content_is_fixture": content == observations["fixture_text"],
            "client_conflict_in_content": CLIENT_CONFLICT in str(content or ""),
        }
        suffix = "" if call_no == 1 else f"_{call_no}"
        saved_content = _write_exact(
            run / f"writer_input{suffix}_content.md", str(content or ""))
        record["content_sha256"] = saved_content["sha256"]
        record["content_capture_exact_bytes"] = True
        _write_text(
            run / f"writer_input{suffix}_sections.json",
            json.dumps(section_copy, ensure_ascii=False, indent=2),
        )
        try:
            result = originals["writer"](*args, **kwargs)
        except Exception as exc:
            record["exception"] = repr(exc)
            observations["writer_calls"].append(record)
            raise
        if isinstance(result, (bytes, bytearray)):
            name = (
                "diagnostic_renderer_output.docx"
                if call_no == 1
                else f"diagnostic_renderer_output_{call_no}.docx"
            )
            saved = _write_bytes(run / name, bytes(result))
            record["returned_bytes"] = saved
        else:
            record["returned_type"] = type(result).__name__
        observations["writer_calls"].append(record)
        return result

    app_module._enforce_export_gate = gate_wrap
    app_module._rel31_authoritative_export_route = route_wrap
    app_module._build_docx_bytes = writer_wrap
    return originals


def _restore(originals, thread):
    if thread is not None and thread.is_alive():
        return False
    app_module._enforce_export_gate = originals["gate"]
    app_module._rel31_authoritative_export_route = originals["route"]
    app_module._build_docx_bytes = originals["writer"]
    threading.Thread = originals["thread"]
    return True


def _insert(expected, fixture_text):
    user = expected["database_row"]["users_insert_order_first"]
    strategy = expected["database_row"]["strategies"]
    gate_row = expected["database_row"]["traceability_records_gate_row"]
    sections_json = json.dumps(
        strategy["sections_json"], ensure_ascii=False
    )
    conn = sqlite3.connect(os.environ["DATABASE_PATH"])
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute(
        "DELETE FROM traceability_records WHERE user_id = ? AND artifact_id = ?",
        (gate_row["user_id"], gate_row["artifact_id"]),
    )
    conn.execute("DELETE FROM strategies WHERE id = ?", (strategy["id"],))
    conn.execute("DELETE FROM users WHERE id = ?", (user["id"],))
    conn.execute(
        "INSERT INTO users "
        "(id, username, email, password_hash, role, is_active) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            user["id"], user["username"], user["email"],
            user["password_hash"], user["role"], user["is_active"],
        ),
    )
    conn.execute(
        "INSERT INTO strategies ("
        "id, user_id, domain, language, generation_mode, artifact_status, "
        "publishability_score, org_name, sector, document_title, content, "
        "content_json, sections_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            strategy["id"], strategy["user_id"], strategy["domain"],
            strategy["language"], strategy["generation_mode"],
            strategy["artifact_status"], strategy["publishability_score"],
            strategy["org_name"], strategy["sector"],
            strategy["document_title"], fixture_text, None, sections_json,
        ),
    )
    conn.execute(
        "INSERT INTO traceability_records ("
        "user_id, artifact_type, artifact_id, section_key, "
        "source_frameworks, evidence_sufficiency, linked_kpis, "
        "linked_roadmap_tasks) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            gate_row["user_id"], gate_row["artifact_type"],
            gate_row["artifact_id"], gate_row["section_key"],
            gate_row["source_frameworks"], gate_row["evidence_sufficiency"],
            gate_row["linked_kpis"], gate_row["linked_roadmap_tasks"],
        ),
    )
    conn.commit()
    conn.close()


def _valid_package(data):
    if not data or not data.startswith(b"PK"):
        return False, "missing_zip_signature"
    try:
        with zipfile.ZipFile(BytesIO(data)) as package:
            names = package.namelist()
        if "word/document.xml" not in names:
            return False, "missing_word_document_xml"
        Document(BytesIO(data))
    except Exception as exc:
        return False, repr(exc)
    return True, "valid_docx_package"


_BODY_HEADINGS = (
    ("الرؤية والأهداف الاستراتيجية", "vision"),
    ("الركائز الاستراتيجية", "pillars"),
    ("البيئة التنظيمية والتهديدات", "environment"),
    ("تحليل الفجوات", "gaps"),
    ("خارطة الطريق التنفيذية", "roadmap"),
    ("مؤشرات الأداء الرئيسية", "kpis"),
    ("تقييم الثقة والمخاطر", "confidence"),
    ("نموذج الحوكمة والمسؤوليات", "governance"),
    ("مصفوفة تتبع الأطر المرجعية", "traceability"),
)


def _heading_key(text):
    sample = _norm(text)
    for title, key in _BODY_HEADINGS:
        if sample == _norm(title):
            return key
    return ""


def _is_saved_body_heading(paragraph):
    """Bold 14pt full-title paragraph emitted by the saved heading renderer.

    A contents entry, a cover tagline, or a body sentence that merely
    mentions a section is not a heading. Word Heading styles are not required.
    """
    if not _heading_key(paragraph.text):
        return False
    runs = [run for run in paragraph.runs if str(run.text or "").strip()]
    if not runs or any(not run.bold for run in runs):
        return False
    sizes = [
        run.font.size.pt for run in runs
        if run.font.size is not None]
    return bool(sizes) and max(sizes) >= 14


def _extract(data):
    document = Document(BytesIO(data))
    xml = document.element.xml
    para_by_el = {paragraph._p: paragraph for paragraph in document.paragraphs}
    table_by_el = {table._tbl: table for table in document.tables}
    paragraphs = []
    tables = []
    stream = []
    section = "cover"
    body_started = False
    for child in document.element.body.iterchildren():
        if child in para_by_el:
            paragraph = para_by_el[child]
            mapped = ""
            if _is_saved_body_heading(paragraph):
                mapped = _heading_key(paragraph.text)
                section = mapped
                body_started = True
            item = {
                "index": len(paragraphs),
                "text": paragraph.text,
                "style": paragraph.style.name if paragraph.style is not None else "",
                "section": section,
                "role": "body" if body_started else "cover",
                "body_heading": bool(mapped),
            }
            paragraphs.append(item)
            stream.append({"kind": "paragraph", **item})
        elif child in table_by_el:
            table = table_by_el[child]
            rows = []
            for row_index, row in enumerate(table.rows):
                cells = []
                for col_index, cell in enumerate(row.cells):
                    tc_xml = cell._tc.xml
                    cells.append({
                        "row": row_index,
                        "column": col_index,
                        "text": cell.text,
                        "paragraphs": [p.text for p in cell.paragraphs],
                        "grid_span": "w:gridSpan" in tc_xml,
                        "v_merge": "w:vMerge" in tc_xml,
                    })
                rows.append(cells)
            item = {
                "index": len(tables),
                "rows": rows,
                "section": section if body_started else "cover",
                "role": "body" if body_started else "cover_metadata",
            }
            tables.append(item)
            stream.append({"kind": "table", "index": item["index"], "section": section})
    return {
        "paragraph_count": len(paragraphs),
        "table_count": len(tables),
        "paragraphs": paragraphs,
        "tables": tables,
        "stream": stream,
        "rtl_flag_count": xml.count("w:rtl"),
        "bidi_flag_count": xml.count("w:bidi"),
        "rtl_flags_are_not_visual_acceptance": True,
    }


def _table_matrix(table):
    width = max((len(row) for row in table["rows"]), default=0)
    matrix = []
    for row in table["rows"]:
        values = [cell["text"] for cell in row]
        values.extend([""] * (width - len(values)))
        matrix.append(values)
    return matrix


def _body_lines(section_text):
    lines = []
    for raw in str(section_text or "").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("|"):
            continue
        if set(stripped) <= set("-: "):
            continue
        lines.append(stripped)
    return lines


def _row_identity(section_name, row):
    cells = tuple(_norm(cell) for cell in row)
    if section_name == "traceability":
        return cells
    return cells[:1]


def _without_brackets(text):
    return _norm(text).replace("[", "").replace("]", "")


def _compare(expected, extraction, provenance):
    differences = []
    paragraphs = extraction["paragraphs"]
    section_paragraphs = {}
    for item in paragraphs:
        section_paragraphs.setdefault(item.get("section") or "cover", []).append(item)
    matrices = []
    for table in extraction["tables"]:
        matrix = _table_matrix(table)
        matrices.append({
            "section": table.get("section") or "cover",
            "role": table.get("role") or "",
            "matrix": matrix,
            "index": table["index"],
        })

    visible_parts = []
    for item in paragraphs:
        visible_parts.append(_norm(item["text"]))
    for entry in matrices:
        for row in entry["matrix"]:
            visible_parts.extend(_norm(cell) for cell in row)
    visible = "\n".join(part for part in visible_parts if part)
    if CLIENT_CONFLICT in visible or _norm(CLIENT_CONFLICT) in _norm(visible):
        differences.append({
            "kind": "client_conflict_sentence",
            "provenance": provenance,
        })
    if MARKER_TOKEN in visible:
        differences.append({
            "kind": "client_conflict_marker",
            "provenance": provenance,
        })

    matched_tables = set()
    for section_name, tables in (expected.get("tables") or {}).items():
        for source_index, source in enumerate(tables):
            header = [_norm(cell) for cell in source["header"]]
            found_tables = []
            elsewhere = []
            for entry in matrices:
                matrix = entry["matrix"]
                if not matrix or [_norm(cell) for cell in matrix[0]] != header:
                    continue
                if entry["section"] == section_name and entry["index"] not in matched_tables:
                    found_tables.append(entry)
                else:
                    elsewhere.append({
                        "document_table": entry["index"],
                        "section": entry["section"],
                    })
            label = f"{section_name}[{source_index}]"
            found = found_tables[0] if found_tables else None
            if found is None:
                differences.append({
                    "kind": "source_table_absent",
                    "table": label,
                    "section": section_name,
                    "header": source["header"],
                    "same_header_in_other_sections": elsewhere,
                    "provenance": provenance,
                })
                continue
            if len(found_tables) > 1:
                differences.append({
                    "kind": "duplicate_source_table",
                    "table": label,
                    "section": section_name,
                    "document_tables": [entry["index"] for entry in found_tables],
                    "provenance": provenance,
                })
            for entry in found_tables:
                matched_tables.add(entry["index"])
            actual_rows = []
            for entry in found_tables:
                actual_rows.extend(entry["matrix"][1:])
            expected_counts = {}
            for source_row in source["rows"]:
                ident = _row_identity(section_name, source_row)
                expected_counts[ident] = expected_counts.get(ident, 0) + 1
            actual_counts = {}
            actual_by_ident = {}
            for offset, row in enumerate(actual_rows, start=1):
                ident = _row_identity(section_name, row)
                actual_counts[ident] = actual_counts.get(ident, 0) + 1
                actual_by_ident.setdefault(ident, []).append((offset, row))
            for ident, expected_count in expected_counts.items():
                actual_count = actual_counts.get(ident, 0)
                if actual_count > expected_count:
                    differences.append({
                        "kind": "duplicate_row_in_table",
                        "table": label,
                        "section": section_name,
                        "document_table": found["index"],
                        "identity": list(ident),
                        "expected_count": expected_count,
                        "actual_count": actual_count,
                        "provenance": provenance,
                    })
                if actual_count < expected_count:
                    differences.append({
                        "kind": "source_row_absent",
                        "table": label,
                        "section": section_name,
                        "document_table": found["index"],
                        "identity": list(ident),
                        "expected_count": expected_count,
                        "actual_count": actual_count,
                        "provenance": provenance,
                    })
                if actual_count <= 0:
                    continue
                actual = actual_by_ident[ident][0][1]
                source_row = next(
                    row for row in source["rows"]
                    if _row_identity(section_name, row) == ident)
                for col, expected_cell in enumerate(source_row):
                    header_name = (
                        source["header"][col]
                        if col < len(source["header"]) else f"column_{col}")
                    actual_cell = actual[col] if col < len(actual) else ""
                    if _norm(actual_cell) != _norm(expected_cell):
                        differences.append({
                            "kind": "cell_differs",
                            "table": label,
                            "section": section_name,
                            "document_table": found["index"],
                            "column": col,
                            "header": header_name,
                            "identity": list(ident),
                            "expected": expected_cell,
                            "actual": actual_cell,
                            "provenance": provenance,
                        })
            for ident, actual_count in actual_counts.items():
                if ident not in expected_counts and any(ident):
                    differences.append({
                        "kind": "unexpected_extra_row",
                        "table": label,
                        "section": section_name,
                        "document_table": found["index"],
                        "identity": list(ident),
                        "actual_count": actual_count,
                        "provenance": provenance,
                    })
    additional_tables = []
    for entry in matrices:
        if entry["index"] in matched_tables or not entry["matrix"]:
            continue
        record = {
            "document_table": entry["index"],
            "section": entry["section"],
            "role": entry.get("role"),
            "header": entry["matrix"][0],
            "data_rows": len(entry["matrix"]) - 1,
        }
        if entry.get("role") == "cover_metadata" or entry.get("section") == "cover":
            record["classification"] = "cover_or_contents_presentation"
            additional_tables.append(record)
            continue
        differences.append({
            "kind": "alternative_business_table",
            "provenance": provenance,
            **record,
        })

    for name, section in (expected.get("saved_sections") or {}).items():
        section_items = section_paragraphs.get(name) or []
        section_norms = [_norm(item["text"]) for item in section_items]
        for table in extraction["tables"]:
            if table.get("section") != name:
                continue
            for row in table["rows"]:
                section_norms.extend(_norm(cell["text"]) for cell in row)
        for line in _body_lines(section.get("text")):
            wanted = _norm(line)
            if any(wanted and wanted in item for item in section_norms):
                continue
            loosened = _without_brackets(line)
            loosened_items = [_without_brackets(item) for item in section_norms]
            if loosened and any(loosened in item for item in loosened_items):
                differences.append({
                    "kind": "reference_punctuation_loss",
                    "section": name,
                    "expected": line,
                    "provenance": provenance,
                })
                continue
            differences.append({
                "kind": "paragraph_absent",
                "section": name,
                "expected": line,
                "provenance": provenance,
            })
        source_norm = _norm(section.get("text"))
        for item in section_items:
            if item.get("body_heading") or not _norm(item["text"]):
                continue
            if _norm(item["text"]) not in source_norm:
                differences.append({
                    "kind": "unexplained_business_prose",
                    "section": name,
                    "paragraph": item["index"],
                    "actual": item["text"],
                    "provenance": provenance,
                })

    confidence_items = section_paragraphs.get("confidence") or []
    confidence_text = "\n".join(_norm(item["text"]) for item in confidence_items)
    for table in extraction["tables"]:
        if table.get("section") != "confidence":
            continue
        for row in table["rows"]:
            confidence_text += "\n" + "\n".join(_norm(cell["text"]) for cell in row)
    if "70 من 100" not in confidence_text:
        differences.append({
            "kind": "confidence_statement_absent",
            "section": "confidence",
            "expected": "70 من 100",
            "provenance": provenance,
        })
    operational_targets = []
    for item in paragraphs:
        if "99.5%" in item["text"]:
            operational_targets.append({
                "section": item.get("section"),
                "paragraph": item["index"],
                "text": item["text"],
            })

    negative_hits = []
    cover_hits = []

    def _consider_type_token(text, location):
        for token in ("Risk Analysis", "تحليل المخاطر"):
            if token not in str(text or ""):
                continue
            hit = {"token": token, "text": text, **location}
            negative_hits.append(hit)
            if location.get("role") in ("cover", "cover_metadata"):
                cover_hits.append(hit)

    for item in paragraphs:
        _consider_type_token(item["text"], {
            "role": "cover" if item.get("role") == "cover" else "body",
            "paragraph": item["index"],
            "section": item.get("section"),
        })
    for table in extraction["tables"]:
        if table.get("role") != "cover_metadata":
            continue
        for row in table["rows"]:
            for cell in row:
                _consider_type_token(cell["text"], {
                    "role": "cover_metadata",
                    "document_table": table["index"],
                    "row": cell["row"],
                    "column": cell["column"],
                    "section": "cover",
                })
    return {
        "provenance": provenance,
        "differences": differences,
        "additional_tables": additional_tables,
        "additional_tables_are_not_defects": False,
        "document_type_negative_occurrences": negative_hits,
        "cover_document_type_hits": cover_hits,
        "operational_percentage_occurrences": operational_targets,
        "paragraph_count": extraction["paragraph_count"],
        "table_count": extraction["table_count"],
    }


def _location_text(item):
    """Format a paragraph or a table cell. Do not invent a paragraph index."""
    if "paragraph" in item:
        return f"paragraph={item['paragraph']}"
    if "document_table" in item:
        return (
            f"document_table={item['document_table']} "
            f"row={item.get('row')} column={item.get('column')}"
        )
    return "location=unspecified"


def _report(comparison):
    lines = [
        f"provenance={comparison['provenance']}",
        f"paragraphs={comparison['paragraph_count']}",
        f"tables={comparison['table_count']}",
        f"differences={len(comparison['differences'])}",
        f"additional_tables={len(comparison['additional_tables'])}",
        "",
    ]
    for item in comparison["additional_tables"]:
        lines.append(
            "additional_table "
            f"{item['document_table']} header={item['header']}"
        )
    for item in comparison["document_type_negative_occurrences"]:
        lines.append(
            "document_type_string "
            f"role={item.get('role')} {_location_text(item)} "
            f"section={item.get('section')} "
            f"token={item['token']} text={item['text']}"
        )
    for item in comparison.get("cover_document_type_hits") or []:
        lines.append(
            "cover_document_type "
            f"role={item.get('role')} {_location_text(item)} "
            f"token={item['token']} text={item['text']}"
        )
    for item in comparison.get("operational_percentage_occurrences") or []:
        lines.append(
            "operational_percentage "
            f"section={item['section']} paragraph={item['paragraph']}"
        )
    for item in comparison["differences"]:
        kind = item["kind"]
        if kind == "cell_differs":
            lines.append(
                "cell "
                f"{item['table']} row={item['identity']} "
                f"column={item['column']} header={item['header']}"
            )
            lines.append(f"expected={item['expected']}")
            lines.append(f"actual={item['actual']}")
        else:
            lines.append(json.dumps(item, ensure_ascii=False))
        lines.append("")
    return "\n".join(lines)


def _edge(value):
    """Allowed handoff whitespace is an edge strip only."""
    return str(value or "").strip()


def _join_recorded_worker(lifecycle):
    """Join the export worker at most once, on the original deadline.

    A thread that is already finished is still joined once so the record
    does not treat "not alive" as proof that join() ran. No new deadline
    is created when a worker exists.
    """
    if lifecycle.get("join_invoked"):
        return lifecycle.get("thread")
    if lifecycle.get("thread") is None:
        lifecycle["thread"] = _export_thread()
    thread = lifecycle.get("thread")
    if thread is None:
        return None
    deadline = lifecycle.get("deadline")
    remaining = 0.0 if deadline is None else max(0.0, deadline - time.monotonic())
    thread.join(remaining)
    lifecycle["join_invoked"] = True
    return thread


def _restore_after_worker(lifecycle, originals, observations):
    """Recover and join before any observer restoration."""
    thread = _join_recorded_worker(lifecycle)
    alive = bool(thread is not None and thread.is_alive())
    observations["thread_alive_at_cleanup"] = alive
    observations["join_invoked"] = bool(lifecycle.get("join_invoked"))
    if alive:
        observations["observers_left_installed"] = True
        return False
    if not lifecycle.get("restored"):
        lifecycle["restored"] = _restore(originals, thread)
    return bool(lifecycle.get("restored"))


def _thread_observation(lifecycle, started):
    thread = lifecycle.get("thread")
    join_invoked = bool(lifecycle.get("join_invoked"))
    alive = bool(thread is not None and thread.is_alive())
    return {
        "created": len(RecordingThread.created),
        "recorded": thread is not None,
        "join_invoked": join_invoked,
        "joined": bool(join_invoked and thread is not None and not alive),
        "alive": alive,
        "deadline_seconds": DEADLINE_SECONDS,
        "elapsed_seconds": time.monotonic() - started,
    }


def _append_source_handoff_problems(observations, expected, run):
    """Fail route and writer mismatches. Flags alone do not reach the assert."""
    fixture = observations["fixture_text"]
    expected_sections = expected.get("saved_sections") or {}
    route_path = run / "route_input_final_markdown.md"
    if route_path.is_file():
        route_text = route_path.read_bytes().decode("utf-8")
        if _edge(route_text) != _edge(fixture):
            observations["saved_body_changed_before_route"] = True
            observations["problems"].append("route_markdown_edge_mismatch")
    route_sections_path = run / "route_input_sections.json"
    if route_sections_path.is_file():
        route_sections = json.loads(route_sections_path.read_text("utf-8"))
        for key, section in expected_sections.items():
            actual = route_sections.get(key)
            if not isinstance(actual, str) or _edge(actual) != _edge(section.get("text")):
                observations["problems"].append("route_section_map_mismatch:" + key)
    for index, call in enumerate(observations.get("writer_calls") or []):
        suffix = "" if call.get("call") == 1 else f"_{call.get('call')}"
        if call.get("lang") != "ar" or call.get("doc_type") != "strategy":
            observations["problems"].append(
                "writer_type_mismatch:" + json.dumps(
                    {"lang": call.get("lang"), "doc_type": call.get("doc_type")},
                    ensure_ascii=False,
                )
            )
        writer_domain = str(call.get("domain") or "").strip()
        if writer_domain not in _SAVED_WRITER_DOMAINS:
            observations["problems"].append(
                "writer_domain_mismatch:" + json.dumps(
                    {"domain": call.get("domain")},
                    ensure_ascii=False,
                )
            )
        content_path = run / f"writer_input{suffix}_content.md"
        if content_path.is_file() and _edge(
                content_path.read_bytes().decode("utf-8")) != _edge(fixture):
            observations["saved_body_changed_before_writer"] = True
            observations["problems"].append("writer_content_edge_mismatch")
        sections_path = run / f"writer_input{suffix}_sections.json"
        if sections_path.is_file():
            writer_sections = json.loads(sections_path.read_text("utf-8"))
            for key, section in expected_sections.items():
                actual = writer_sections.get(key)
                if not isinstance(actual, str) or _edge(actual) != _edge(
                        section.get("text")):
                    observations["problems"].append(
                        "writer_section_map_mismatch:" + key)
        elif index == 0:
            observations["problems"].append("writer_section_map_absent")


def _inspect(run, data, provenance, expected):
    valid, reason = _valid_package(data)
    record = {"provenance": provenance, "valid": valid, "reason": reason}
    if not valid:
        _write_text(
            run / f"comparison_{provenance}.txt",
            f"provenance={provenance}\npackage={reason}\n",
        )
        return record
    extraction = _extract(data)
    _write_text(
        run / f"extraction_{provenance}.json",
        json.dumps(extraction, ensure_ascii=False, indent=2),
    )
    comparison = _compare(expected, extraction, provenance)
    record["comparison"] = comparison
    record["comparison"]["difference_count"] = len(comparison["differences"])
    record["comparison"]["first_difference"] = (
        comparison["differences"][0] if comparison["differences"] else None
    )
    try:
        report = _report(comparison)
    except Exception as exc:
        report = "report_format_failed=" + repr(exc) + "\n"
    _write_text(run / f"comparison_{provenance}.txt", report)
    record["rtl_flag_count"] = extraction["rtl_flag_count"]
    record["bidi_flag_count"] = extraction["bidi_flag_count"]
    return record


def test_saved_arabic_dt_consulting_real_docx():
    _block_if_prior_worker_unresolved()
    assert os.environ.get("DATABASE_PATH") == DATABASE
    run = _run_dir()
    fixture_bytes = FIXTURE_PATH.read_bytes()
    expected_bytes = EXPECTED_PATH.read_bytes()
    _write_bytes(run / FIXTURE_PATH.name, fixture_bytes)
    _write_bytes(run / EXPECTED_PATH.name, expected_bytes)
    fixture_text = fixture_bytes.decode("utf-8")
    expected = json.loads(expected_bytes.decode("utf-8"))
    observations = {
        "fixture_text": fixture_text,
        "fixture_sha256": _sha(fixture_bytes),
        "expected_sha256": _sha(expected_bytes),
        "writer_calls": [],
        "gate": None,
        "route": None,
        "problems": [],
    }
    app_module.init_db()
    _insert(expected, fixture_text)
    originals = _install(observations, run)
    lifecycle = {
        "deadline": None,
        "thread": None,
        "join_invoked": False,
        "restored": False,
    }
    try:
        client = app_module.app.test_client()
        with client.session_transaction() as sess:
            sess["user_id"] = 7
            sess["csrf_token"] = CSRF
        started = time.monotonic()
        lifecycle["deadline"] = started + DEADLINE_SECONDS
        posted = client.post(
            "/api/generate-docx-async",
            json=PAYLOAD,
            headers={"X-CSRFToken": CSRF},
        )
        post_body = posted.get_json(silent=True)
        observations["post"] = {
            "status_code": posted.status_code,
            "body": post_body,
            "elapsed_seconds": time.monotonic() - started,
        }
        _write_text(
            run / "post_response.json",
            json.dumps(observations["post"], ensure_ascii=False, indent=2),
        )
        task_id = (post_body or {}).get("task_id") if posted.status_code == 200 else None
        statuses = []
        terminal = None
        if task_id:
            while time.monotonic() < lifecycle["deadline"]:
                response = client.get(f"/api/export-status/{task_id}")
                body = response.get_json(silent=True)
                item = {
                    "status_code": response.status_code,
                    "body": body,
                    "elapsed_seconds": time.monotonic() - started,
                }
                statuses.append(item)
                state = (body or {}).get("status")
                if state in ("done", "error", "not_found") or response.status_code in (
                    403, 404, 500
                ):
                    terminal = item
                    break
                time.sleep(0.25)
        lifecycle["thread"] = _export_thread()
        _join_recorded_worker(lifecycle)
        observations["statuses"] = statuses
        observations["thread"] = _thread_observation(lifecycle, started)
        _write_text(
            run / "status_observations.json",
            json.dumps(statuses, ensure_ascii=False, indent=2),
        )
        owner = None
        if terminal and (terminal.get("body") or {}).get("status") == "done":
            downloaded = client.get(f"/api/export-download/{task_id}")
            owner = _write_bytes(run / "owner_download.docx", downloaded.data)
            owner["status_code"] = downloaded.status_code
            owner["mimetype"] = downloaded.mimetype
            observations["owner_download"] = owner
        else:
            observations["owner_download"] = None

        route = observations.get("route") or {}
        gate = observations.get("gate") or {}
        if observations["post"]["status_code"] != 200 or not task_id:
            observations["problems"].append(
                "post_refused:" + json.dumps(post_body, ensure_ascii=False)
            )
        if route.get("result_is_none"):
            observations["problems"].append("authoritative_route_returned_none")
        if route.get("exception"):
            observations["problems"].append("route_exception:" + route["exception"])
        if route and route.get("export_return_allowed") is False:
            observations["problems"].append(
                "export_return_refused:"
                + json.dumps(route.get("blocking_errors"), ensure_ascii=False)
            )
        if not observations["writer_calls"]:
            observations["problems"].append("writer_not_called")
        for call in observations["writer_calls"]:
            if call.get("exception"):
                observations["problems"].append(
                    "writer_exception:" + call["exception"]
                )
        if gate and gate.get("result", {}).get("allowed") is False:
            observations["problems"].append(
                "gate_refused:" + json.dumps(gate.get("result"), ensure_ascii=False)
            )
        if gate and (
            gate.get("generation_mode") != "consulting"
            or gate.get("client_conflict_in_content")
            or not gate.get("content_is_fixture")
        ):
            observations["problems"].append("gate_input_is_not_saved_consulting_fixture")
        if route and (
            route.get("document_type") != "strategy"
            or route.get("lang") != "ar"
            or str(route.get("domain") or "") not in (
                "Digital Transformation", "التحول الرقمي", "dt"
            )
            or (route.get("contract_meta") or {}).get("lang") != "ar"
        ):
            observations["problems"].append("route_input_is_not_saved_arabic_dt_strategy")
        if observations["thread"]["alive"]:
            observations["problems"].append("worker_still_alive")
        elif task_id and not observations["thread"]["recorded"]:
            observations["problems"].append("worker_absent")
        elif task_id and not observations["thread"]["join_invoked"]:
            observations["problems"].append("worker_not_joined")
        if terminal is None or (terminal.get("body") or {}).get("status") != "done":
            error = (terminal or {}).get("body")
            observations["problems"].append(
                "task_not_done:" + json.dumps(error, ensure_ascii=False)
            )
        if not owner or owner["status_code"] != 200 or owner["bytes"] <= 0:
            observations["problems"].append("owner_download_absent")
        else:
            inspected = _inspect(run, (run / "owner_download.docx").read_bytes(), "owner_download", expected)
            observations["owner_inspection"] = inspected
            if not inspected["valid"]:
                observations["problems"].append(
                    "owner_package_invalid:" + inspected["reason"]
                )
            elif inspected["comparison"]["difference_count"]:
                first = inspected["comparison"]["first_difference"]
                observations["problems"].append(
                    "content_difference:" + json.dumps(first, ensure_ascii=False)
                )
            negatives = (
                inspected.get("comparison") or {}
            ).get("cover_document_type_hits") or []
            title_hit = list(negatives)
            if title_hit:
                observations["problems"].append(
                    "cover_uses_risk_document_title:"
                    + json.dumps(title_hit, ensure_ascii=False)
                )
        diagnostic = run / "diagnostic_renderer_output.docx"
        if diagnostic.is_file():
            diagnostic_bytes = diagnostic.read_bytes()
            observations["diagnostic_renderer_output"] = {
                "bytes": len(diagnostic_bytes),
                "sha256": _sha(diagnostic_bytes),
            }
            observations["diagnostic_inspection"] = _inspect(
                run, diagnostic_bytes, "diagnostic_renderer_output", expected
            )
            if owner:
                observations["owner_equals_diagnostic_bytes"] = (
                    owner["sha256"] == observations["diagnostic_renderer_output"]["sha256"]
                )
        else:
            observations["diagnostic_renderer_output"] = None
        if route.get("final_markdown_is_fixture") is False:
            observations["saved_body_changed_before_route"] = True
        if observations["writer_calls"] and not observations["writer_calls"][0].get(
            "content_is_fixture"
        ):
            observations["saved_body_changed_before_writer"] = True
        _append_source_handoff_problems(observations, expected, run)
        observations["first_problem"] = (
            observations["problems"][0] if observations["problems"] else None
        )
        _persist(run, observations)
        assert not observations["problems"], observations["first_problem"]
    finally:
        _restore_after_worker(lifecycle, originals, observations)
        _remember_case_after_cleanup("async_real_docx", lifecycle)
        _persist(run, observations)


def test_saved_arabic_dt_consulting_sync_docx_owner_handoff():
    """Prospective synchronous owner handoff. Not a content-success test.

    A roadmap or objectives quality refusal is recorded and does not by
    itself fail this handoff. Returned bytes are still compared.
    """
    _block_if_prior_worker_unresolved()
    assert os.environ.get("DATABASE_PATH") == DATABASE
    run = _run_dir() / "sync-owner-handoff"
    run.mkdir(parents=True, exist_ok=True)
    fixture_bytes = FIXTURE_PATH.read_bytes()
    expected_bytes = EXPECTED_PATH.read_bytes()
    fixture_text = fixture_bytes.decode("utf-8")
    expected = json.loads(expected_bytes.decode("utf-8"))
    observations = {
        "fixture_text": fixture_text,
        "fixture_sha256": _sha(fixture_bytes),
        "expected_sha256": _sha(expected_bytes),
        "writer_calls": [],
        "gate": None,
        "route": None,
        "problems": [],
    }
    app_module.init_db()
    _insert(expected, fixture_text)
    originals = _install(observations, run)
    lifecycle = {
        "deadline": None,
        "thread": None,
        "join_invoked": False,
        "restored": False,
    }
    try:
        client = app_module.app.test_client()
        with client.session_transaction() as sess:
            sess["user_id"] = 7
            sess["csrf_token"] = CSRF
        started = time.monotonic()
        lifecycle["deadline"] = started + DEADLINE_SECONDS
        posted = client.post(
            "/api/generate-docx",
            json=PAYLOAD,
            headers={"X-CSRFToken": CSRF},
        )
        post_body = posted.get_json(silent=True)
        observations["post"] = {
            "status_code": posted.status_code,
            "body": post_body,
            "content_type": posted.content_type,
            "bytes": len(posted.data or b""),
            "elapsed_seconds": time.monotonic() - started,
        }
        route = observations.get("route") or {}
        blockers = list(route.get("blocking_errors") or [])
        blockers.extend(route.get("export_blocking_errors") or [])
        observations["recorded_blockers"] = blockers
        if not route:
            observations["problems"].append("missing_route_record")
        else:
            if int(route.get("export_user_id") or 0) != 7:
                observations["problems"].append("sync_export_user_mismatch")
            if int(route.get("fidelity_owner_id") or 0) != 7:
                observations["problems"].append("sync_fidelity_owner_mismatch")
            if int(route.get("fidelity_record_id") or 0) != 701:
                observations["problems"].append("sync_fidelity_record_mismatch")
        if any(
                "saved_docx_fidelity_refused:identity" in str(item)
                for item in blockers):
            observations["problems"].append("sync_identity_refusal")
        _append_source_handoff_problems(observations, expected, run)
        returned = posted.data or b""
        if returned.startswith(b"PK"):
            inspected = _inspect(run, returned, "sync_response", expected)
            observations["sync_inspection"] = inspected
            if not inspected["valid"]:
                observations["problems"].append(
                    "sync_package_invalid:" + inspected["reason"])
            elif inspected["comparison"]["difference_count"]:
                observations["problems"].append(
                    "content_difference:" + json.dumps(
                        inspected["comparison"]["first_difference"],
                        ensure_ascii=False,
                    )
                )
            if (inspected.get("comparison") or {}).get("cover_document_type_hits"):
                observations["problems"].append("cover_uses_risk_document_title")
        lifecycle["thread"] = _export_thread()
        _join_recorded_worker(lifecycle)
        observations["thread"] = _thread_observation(lifecycle, started)
        if observations["thread"]["alive"]:
            observations["problems"].append("worker_still_alive")
        observations["first_problem"] = (
            observations["problems"][0] if observations["problems"] else None
        )
        observations["quality_blockers_recorded"] = blockers
        observations["content_success_claimed"] = False
        _persist(run, observations)
        assert not observations["problems"], observations["first_problem"]
    finally:
        _restore_after_worker(lifecycle, originals, observations)
        _remember_case_after_cleanup("sync_owner_handoff", lifecycle)
        _persist(run, observations)


def _persist(run, observations):
    stored = dict(observations)
    stored.pop("fixture_text", None)
    _write_text(
        run / "scenario_observation.json",
        json.dumps(stored, ensure_ascii=False, indent=2, default=str),
    )
