"""Native DT governance content must survive real exports and fail closed.

The fixture is synthetic QA input. It is never a production text fallback.
Set MIZAN_GOVERNANCE_APP_ROOT to test the same assertions against another
checkout. MIZAN_GOVERNANCE_EVIDENCE_DIR retains each case in a unique folder.
No positive renderer or exporter is substituted by this module.
"""

from copy import deepcopy
from functools import wraps
from hashlib import sha256
from html.parser import HTMLParser
from io import BytesIO
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import uuid
from unittest.mock import Mock

import pytest


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "rel33_dt_governance_model_ar.json"
SECTION_KEYS = ("roles", "committees", "escalation", "raci")
FLAGS = {"rel3": True, "rel31": True, "rel32": True}
# Independent expectations: do not derive these from renderer output or its
# section/table parser. A lost section or changed RACI assignment must fail.
EXPECTED_MARKERS = (
    "DTGROLE01", "DTGROLE02", "DTGCOMM01", "DTGESC01", "DTGRACI01", "DTGRACI02",
)
EXPECTED_RACI_HEADER = (
    "المعرّف", "النشاط", "مدير التحول الرقمي", "مالك الخدمة", "فريق المنصات", "مكتب البيانات",
)
EXPECTED_RACI_ROWS = (
    ("DTGRACI01", "اعتماد إطلاق الخدمة", "A", "R", "C", "I"),
    ("DTGRACI02", "معالجة تعثر التكامل", "I", "A", "R", "C"),
)
EXPECTED_ROLES = ("مدير التحول الرقمي", "مالك الخدمة", "لجنة التحول الرقمي")
EXPECTED_SECTION_HEADINGS = (
    "الأدوار والمسؤوليات", "اللجان وصلاحياتها", "مسارات التصعيد", "مصفوفة المسؤوليات RACI",
)
EXPECTED_NATIVE_TABLE_HEADERS = (
    ("المعرّف", "الدور", "المسؤولية"),
    ("المعرّف", "اللجنة", "القرار", "دورية الاجتماع"),
    ("المعرّف", "الحالة", "المسؤول عن التصعيد", "جهة القرار", "المهلة"),
    EXPECTED_RACI_HEADER,
)
EXPORT_KWARGS = {
    "filename": "dt-governance-native.docx",
    "lang": "ar",
    "domain": "dt",
    "document_type": "governance_model",
    "doc_type": "نموذج الحوكمة",
    "org_name": "جهة اختبار حوكمة التحول الرقمي",
    "selected_frameworks": [],
}


class _VisibleHTML(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)


class _PreviewTables(HTMLParser):
    """Read actual HTML table boundaries independently of the renderer."""

    def __init__(self):
        super().__init__()
        self.tables = []
        self.errors = []
        self._table = None
        self._row = None
        self._cell = None

    def handle_starttag(self, tag, attrs):
        if tag == "table":
            if self._table is not None:
                self.errors.append("nested_table")
            self._table = []
            self.tables.append(self._table)
        elif tag == "tr":
            if self._table is None or self._row is not None:
                self.errors.append("row_boundary")
            self._row = []
            if self._table is not None:
                self._table.append(self._row)
        elif tag in ("td", "th"):
            if self._row is None or self._cell is not None:
                self.errors.append("cell_boundary")
            self._cell = []
        elif tag == "br" and self._cell is not None:
            self._cell.append("\n")

    def handle_data(self, data):
        if self._cell is not None:
            self._cell.append(data)

    def handle_endtag(self, tag):
        if tag in ("td", "th"):
            if self._cell is None or self._row is None:
                self.errors.append("cell_close_boundary")
            else:
                self._row.append(_cell_text("".join(self._cell)))
            self._cell = None
        elif tag == "tr":
            if self._cell is not None or self._row is None:
                self.errors.append("row_close_boundary")
            self._row = None
        elif tag == "table":
            if self._row is not None or self._table is None:
                self.errors.append("table_close_boundary")
            self._table = None

    def finish(self):
        self.close()
        if any(value is not None for value in (self._table, self._row, self._cell)):
            self.errors.append("unclosed_table_structure")
        return [[tuple(row) for row in table] for table in self.tables]


def _visible_html(value):
    parser = _VisibleHTML()
    parser.feed(value)
    return "\n".join(parser.parts)


def _cell_text(value):
    # Ignore only layout controls and whitespace, not Arabic letters/marks,
    # role names, punctuation, identifiers, or responsibility assignments.
    bidi_controls = "\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
    return " ".join(value.translate(str.maketrans("", "", bidi_controls)).split())


@pytest.fixture(scope="module")
def production_app(tmp_path_factory):
    root = Path(os.environ.get(
        "MIZAN_GOVERNANCE_APP_ROOT", str(Path(__file__).resolve().parents[1])
    )).resolve()
    assert (root / "app.py").is_file(), f"Missing application: {root}"
    # A baseline comparison must never silently reuse candidate modules.
    for name in ("app", "release_engine_v3", "release_engine"):
        loaded = sys.modules.get(name)
        filename = getattr(loaded, "__file__", None)
        if filename:
            assert Path(filename).resolve().is_relative_to(root), (name, filename, root)
    environment = pytest.MonkeyPatch()
    isolated = tmp_path_factory.mktemp("dt-governance-app")
    defaults = {
        "DATABASE_PATH": str(isolated / "app.db"),
        "DATABASE_URL": "sqlite:///" + str(isolated / "app.db"),
        "SECRET_KEY": "dt-governance-synthetic-qa-key",
        "ADMIN_PASSWORD": "dt-governance-synthetic-qa-password",
        "OPENAI_API_KEY": "",
    }
    for key, value in defaults.items():
        if key not in os.environ:
            environment.setenv(key, value)
    environment.syspath_prepend(str(root))
    try:
        # Import failures are failures, not skipped coverage.
        module = importlib.import_module("app")
        assert Path(module.__file__).resolve() == root / "app.py"
        yield module
    finally:
        environment.undo()


@pytest.fixture
def native_sections():
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    assert fixture["provenance"] == "synthetic_qa"
    assert (fixture["domain"], fixture["document_type"], fixture["lang"]) == (
        "dt", "governance_model", "ar"
    )
    assert tuple(fixture["sections"]) == SECTION_KEYS
    return deepcopy(fixture["sections"])


@pytest.fixture
def evidence_dir(tmp_path, request):
    configured = os.environ.get("MIZAN_GOVERNANCE_EVIDENCE_DIR")
    if configured:
        base = Path(configured)
        base.mkdir(parents=True, exist_ok=True)
        # Preserve earlier results, including development failures.
        target = Path(tempfile.mkdtemp(prefix=request.node.name + "--", dir=base))
    else:
        target = tmp_path
    print("governance_evidence_directory=" + str(target))
    return target


def _fresh_backend(production_app):
    from release_engine_v3.rel33_quality_matrix import _reset_export_state

    _reset_export_state()
    backend = dict(production_app._rel31_backend_callables())
    backend.update(flags=dict(FLAGS), domain="dt", lang="ar", document_type="governance_model")
    return backend


def _artifact(sections):
    return {
        "strategy_id": "qa-dt-governance-" + uuid.uuid4().hex,
        "domain": "dt",
        "language": "ar",
        "document_type": "governance_model",
        "artifact_type": "governance_model",
        "sections": deepcopy(sections),
        "final_markdown": "\n\n".join(
            sections[key].strip() for key in SECTION_KEYS if key in sections
        ),
        "contract_meta": {
            "lang": "ar", "domain": "dt", "document_type": "governance_model",
        },
    }


def _summarize_export(result, evidence):
    return {
        "export_return_allowed": getattr(evidence, "export_return_allowed", None),
        "evidence_passed": getattr(evidence, "evidence_passed", None),
        "result_blockers": list(getattr(result, "blocking_errors", None) or []),
        "evidence_blockers": list(getattr(evidence, "blocking_errors", None) or []),
        "canonical_hash": getattr(result, "canonical_hash", ""),
        "render_tree_hash": getattr(result, "render_tree_hash", ""),
        "docx_bytes": len(getattr(result, "docx_bytes", b"") or b""),
        "pdf_bytes": len(getattr(result, "pdf_bytes", b"") or b""),
        "returned_bytes_sha256": getattr(result, "returned_bytes_sha256", ""),
    }


def _save_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n",
                    encoding="utf-8")


def _block_writers(backend, calls):
    def forbidden(name):
        def invoke(*_args, **_kwargs):
            calls.append(name)
            raise AssertionError("Incomplete governance input reached writer: " + name)
        return invoke

    for name in ("build_docx_bytes", "build_pdf_bytes"):
        backend[name] = forbidden(name)


def _assert_refusal(exports, missing_key, writer_calls):
    expected = "rel33_section_missing:" + missing_key
    assert writer_calls == [], writer_calls
    for route, (result, evidence) in exports.items():
        errors = (list(getattr(result, "blocking_errors", None) or [])
                  + list(getattr(evidence, "blocking_errors", None) or []))
        assert getattr(evidence, "export_return_allowed", None) is False, (route, errors)
        assert any(expected in str(error) for error in errors), (route, errors)
        assert not getattr(result, "docx_bytes", None), route
        assert not getattr(result, "pdf_bytes", None), route
        assert not getattr(result, "bytes_data", None), route


def test_native_governance_survives_actual_preview_docx_pdf(
        production_app, native_sections, monkeypatch, evidence_dir):
    from docx import Document
    import fitz
    from release_engine_v3 import rel32_compiler
    from release_engine_v3.rel31_authority import (
        apply_rel31_authoritative_contract, rel3_export_authoritative,
    )

    backend = _fresh_backend(production_app)
    compiler = Mock(wraps=rel32_compiler.compile_canonical_strategy_document)
    monkeypatch.setattr(rel32_compiler, "compile_canonical_strategy_document", compiler)
    writer_calls = {"build_docx_bytes": 0, "build_pdf_bytes": 0}
    for name in writer_calls:
        original = backend[name]

        def make_observer(writer_name, writer):
            @wraps(writer)
            def observe(*args, **kwargs):
                writer_calls[writer_name] += 1
                return writer(*args, **kwargs)
            return observe

        backend[name] = make_observer(name, original)

    source = _artifact(native_sections)
    contracted = None
    exports = {}
    trace = {"source": source, "writer_calls": writer_calls, "routes": {}}
    try:
        contracted = apply_rel31_authoritative_contract(
            source, backend=backend, flags=dict(FLAGS)
        )
        trace["contracted_artifact"] = contracted
        for route in ("preview", "docx", "pdf"):
            result, evidence = rel3_export_authoritative(
                route, contracted, backend=backend, flags=dict(FLAGS),
                export_kwargs=dict(EXPORT_KWARGS),
            )
            exports[route] = (result, evidence)
            trace["routes"][route] = _summarize_export(result, evidence)
            if route == "preview":
                (evidence_dir / "preview.html").write_text(
                    result.preview_html or "", encoding="utf-8"
                )
                (evidence_dir / "preview.txt").write_text(
                    result.preview_text or "", encoding="utf-8"
                )
            else:
                data = getattr(result, route + "_bytes", b"") or b""
                if data:
                    (evidence_dir / ("governance." + route)).write_bytes(data)

        contract = contracted.get("rel31_generation_contract") or {}
        assert contract.get("generation_save_allowed") is True, contract
        frozen = contracted.get("rel3_artifact") or {}
        assert frozen.get("document_type") == "governance_model", frozen
        assert set(frozen.get("canonical_sections") or {}) == set(SECTION_KEYS), frozen
        assert compiler.call_count == 0, compiler.call_args_list
        canonical_text = json.dumps(frozen.get("canonical_sections"), ensure_ascii=False)
        for marker in EXPECTED_MARKERS:
            assert marker in canonical_text, marker

        for route, (result, evidence) in exports.items():
            assert evidence.export_return_allowed is True, (route, evidence.blocking_errors)
            assert not result.blocking_errors, (route, result.blocking_errors)
        preview = exports["preview"][0]
        assert preview.preview_html
        preview_text = _visible_html(preview.preview_html)
        for value in EXPECTED_MARKERS + EXPECTED_ROLES + EXPECTED_SECTION_HEADINGS:
            assert value in preview_text, ("preview", value)
        html_tables = _PreviewTables()
        html_tables.feed(preview.preview_html)
        preview_tables = html_tables.finish()
        _save_json(evidence_dir / "preview-tables.json", preview_tables)
        assert not html_tables.errors, html_tables.errors
        assert len(preview_tables) == 4, preview_tables
        for expected_header, actual_table in zip(EXPECTED_NATIVE_TABLE_HEADERS, preview_tables):
            assert actual_table and actual_table[0] == expected_header, (expected_header, actual_table)
        # A header-only table followed by a separate data table is a visible
        # defect even when all text tokens are somewhere in the preview.
        assert preview_tables[-1] == [EXPECTED_RACI_HEADER, *EXPECTED_RACI_ROWS], preview_tables[-1]

        docx_bytes = exports["docx"][0].docx_bytes
        pdf_bytes = exports["pdf"][0].pdf_bytes
        assert docx_bytes.startswith(b"PK")
        assert pdf_bytes.startswith(b"%PDF")
        assert all(count >= 1 for count in writer_calls.values()), writer_calls
        for route, data in (("docx", docx_bytes), ("pdf", pdf_bytes)):
            exported = exports[route][0]
            assert exported.returned_bytes_sha256 == sha256(data).hexdigest()
            assert exported.evidence_bytes_sha256 == sha256(data).hexdigest()

        document = Document(BytesIO(docx_bytes))
        tables = [
            [tuple(_cell_text(cell.text) for cell in row.cells) for row in table.rows]
            for table in document.tables
        ]
        docx_text = "\n".join(
            [paragraph.text for paragraph in document.paragraphs]
            + [" | ".join(row) for table in tables for row in table]
        )
        (evidence_dir / "docx-visible.txt").write_text(docx_text, encoding="utf-8")
        _save_json(evidence_dir / "docx-tables.json", tables)
        for value in EXPECTED_MARKERS + EXPECTED_ROLES:
            assert value in docx_text, ("docx", value)
        raci_tables = [table for table in tables if any("DTGRACI01" in row for row in table)]
        assert len(raci_tables) == 1, raci_tables
        raci = raci_tables[0]
        assert EXPECTED_RACI_HEADER in raci, raci
        for expected_row in EXPECTED_RACI_ROWS:
            assert expected_row in raci, (expected_row, raci)

        with fitz.open(stream=pdf_bytes, filetype="pdf") as pdf:
            assert pdf.page_count > 0
            trace["pdf_page_count"] = pdf.page_count
            pdf_text = "\n".join(page.get_text("text") for page in pdf)
        (evidence_dir / "pdf-visible.txt").write_text(pdf_text, encoding="utf-8")
        for marker in EXPECTED_MARKERS:
            assert marker in pdf_text, ("pdf", marker)
    finally:
        trace["strategy_compiler_calls"] = compiler.call_count
        _save_json(evidence_dir / "observations.json", trace)


@pytest.mark.parametrize("missing_key", SECTION_KEYS)
@pytest.mark.parametrize("mutation", ("absent", "blank"))
def test_incomplete_governance_contract_refuses_before_writers(
        production_app, native_sections, evidence_dir, missing_key, mutation):
    from release_engine_v3.rel31_authority import (
        apply_rel31_authoritative_contract, rel3_export_authoritative,
    )

    if mutation == "absent":
        native_sections.pop(missing_key)
    else:
        native_sections[missing_key] = "  \n\t"
    backend = _fresh_backend(production_app)
    writer_calls = []
    _block_writers(backend, writer_calls)
    source = _artifact(native_sections)
    trace = {"source": source, "writer_calls": writer_calls, "routes": {}}
    exports = {}
    try:
        contracted = apply_rel31_authoritative_contract(
            source, backend=backend, flags=dict(FLAGS)
        )
        trace["contracted_artifact"] = contracted
        for route in ("docx", "pdf"):
            result, evidence = rel3_export_authoritative(
                route, contracted, backend=backend, flags=dict(FLAGS),
                export_kwargs=dict(EXPORT_KWARGS),
            )
            exports[route] = (result, evidence)
            trace["routes"][route] = _summarize_export(result, evidence)
        contract = contracted.get("rel31_generation_contract") or {}
        expected = "rel33_section_missing:" + missing_key
        assert contract.get("generation_save_allowed") is False, contract
        assert any(expected in str(error) for error in contract.get("blocking_errors", [])), contract
        assert not str((contracted.get("sections") or {}).get(missing_key) or "").strip()
        _assert_refusal(exports, missing_key, writer_calls)
    finally:
        _save_json(evidence_dir / "observations.json", trace)


@pytest.mark.parametrize("missing_key", SECTION_KEYS)
@pytest.mark.parametrize("mutation", ("absent", "blank"))
def test_direct_incomplete_governance_export_refuses_before_writers(
        production_app, native_sections, evidence_dir, missing_key, mutation):
    from release_engine_v3.rel31_authority import rel3_export_authoritative

    if mutation == "absent":
        native_sections.pop(missing_key)
    else:
        native_sections[missing_key] = "  \n\t"
    backend = _fresh_backend(production_app)
    writer_calls = []
    _block_writers(backend, writer_calls)
    source = _artifact(native_sections)
    trace = {"source": source, "writer_calls": writer_calls, "routes": {}}
    exports = {}
    try:
        # Deliberately do not call the generation contract first: the export
        # boundary must reject an incomplete supplied artifact by itself.
        for route in ("docx", "pdf"):
            result, evidence = rel3_export_authoritative(
                route, source, backend=backend, flags=dict(FLAGS),
                export_kwargs=dict(EXPORT_KWARGS),
            )
            exports[route] = (result, evidence)
            trace["routes"][route] = _summarize_export(result, evidence)
        _assert_refusal(exports, missing_key, writer_calls)
    finally:
        _save_json(evidence_dir / "observations.json", trace)


@pytest.mark.parametrize("tamper", ("raci_assignment", "committee_marker"))
def test_actual_docx_content_tamper_is_refused(
        production_app, native_sections, evidence_dir, tamper):
    """Matching byte hashes cannot make a semantically changed DOCX acceptable."""
    from docx import Document
    from release_engine_v3.rel31_authority import (
        apply_rel31_authoritative_contract, rel3_export_authoritative,
    )

    backend = _fresh_backend(production_app)
    source = _artifact(native_sections)
    original_source = deepcopy(source)
    contracted = apply_rel31_authoritative_contract(
        source, backend=backend, flags=dict(FLAGS)
    )
    contract = contracted.get("rel31_generation_contract") or {}
    assert contract.get("generation_save_allowed") is True, contract
    source_sections = deepcopy(contracted["sections"])
    source_markdown = contracted["final_markdown"]
    source_canonical = deepcopy(contracted["rel3_artifact"]["canonical_sections"])
    original_writer = backend["build_docx_bytes"]
    writer_results = []
    trace = {"tamper": tamper, "source_sections": source_sections, "writer_results": writer_results}

    @wraps(original_writer)
    def altered_real_docx(*args, **kwargs):
        # Generate genuine production bytes first. Only the returned file is
        # changed; no canonical artifact, expected source, or evidence is forged.
        original_bytes = original_writer(*args, **kwargs)
        document = Document(BytesIO(original_bytes))
        before = [
            [tuple(_cell_text(cell.text) for cell in row.cells) for row in table.rows]
            for table in document.tables
        ]
        marker = "DTGRACI01" if tamper == "raci_assignment" else "DTGCOMM01"
        matches = [
            (table_index, row_index, row)
            for table_index, table in enumerate(document.tables)
            for row_index, row in enumerate(table.rows)
            if any(_cell_text(cell.text) == marker for cell in row.cells)
        ]
        assert len(matches) == 1, (tamper, matches)
        table_index, row_index, row = matches[0]
        if tamper == "raci_assignment":
            column_index = 2
            assert _cell_text(row.cells[column_index].text) == "A"
            row.cells[column_index].text = "I"
        else:
            column_index = 0
            assert _cell_text(row.cells[column_index].text) == "DTGCOMM01"
            row.cells[column_index].text = ""
        stream = BytesIO()
        document.save(stream)
        altered_bytes = stream.getvalue()
        reopened = Document(BytesIO(altered_bytes))
        after = [
            [tuple(_cell_text(cell.text) for cell in row.cells) for row in table.rows]
            for table in reopened.tables
        ]
        changes = [
            (ti, ri, ci, old_value, after[ti][ri][ci])
            for ti, table in enumerate(before)
            for ri, cells in enumerate(table)
            for ci, old_value in enumerate(cells)
            if old_value != after[ti][ri][ci]
        ]
        assert len(changes) == 1
        assert changes[0][:3] == (table_index, row_index, column_index)
        (evidence_dir / "original-production.docx").write_bytes(original_bytes)
        (evidence_dir / "tampered-production.docx").write_bytes(altered_bytes)
        writer_results.append({
            "changes": changes,
            "original_sha256": sha256(original_bytes).hexdigest(),
            "altered_sha256": sha256(altered_bytes).hexdigest(),
        })
        return altered_bytes

    backend["build_docx_bytes"] = altered_real_docx
    try:
        result, evidence = rel3_export_authoritative(
            "docx", contracted, backend=backend, flags=dict(FLAGS),
            export_kwargs=dict(EXPORT_KWARGS),
        )
        trace["result"] = _summarize_export(result, evidence)
        assert len(writer_results) == 1, writer_results
        errors = list(result.blocking_errors or []) + list(evidence.blocking_errors or [])
        assert evidence.export_return_allowed is False, errors
        assert any("rel33_governance_export_mismatch:docx:" in str(error) for error in errors), errors
        altered_digest = writer_results[0]["altered_sha256"]
        # The returned-file/evidence hashes are internally consistent. The
        # refusal must therefore come from comparison with the native source.
        assert result.returned_bytes_sha256 == altered_digest
        assert result.evidence_bytes_sha256 == altered_digest
        assert evidence.returned_bytes_sha256 == altered_digest
        assert sha256(result.docx_bytes).hexdigest() == altered_digest
        assert source == original_source
        assert contracted["sections"] == source_sections
        assert contracted["final_markdown"] == source_markdown
        assert contracted["rel3_artifact"]["canonical_sections"] == source_canonical
    finally:
        _save_json(evidence_dir / "observations.json", trace)


def test_native_pdf_mismatch_diagnostic_survives_strategy_words(
        production_app, native_sections, evidence_dir):
    """Source text mentioning strategy terms must not erase a native refusal."""
    from release_engine_v3.evidence.pdf_text_extractor import extract_pdf_visible_text
    from release_engine_v3.rel31_authority import (
        apply_rel31_authoritative_contract, rel3_export_authoritative,
    )
    from release_engine_v3.validators import validate_export_text

    backend = _fresh_backend(production_app)
    source = _artifact(native_sections)
    fixture_before = deepcopy(native_sections)
    trace = {"source": source}
    try:
        contracted = apply_rel31_authoritative_contract(
            source, backend=backend, flags=dict(FLAGS)
        )
        contract = contracted.get("rel31_generation_contract") or {}
        assert contract.get("generation_save_allowed") is True, contract
        result, evidence = rel3_export_authoritative(
            "pdf", contracted, backend=backend, flags=dict(FLAGS),
            export_kwargs=dict(EXPORT_KWARGS),
        )
        trace["accepted_export"] = _summarize_export(result, evidence)
        assert evidence.export_return_allowed is True, evidence.blocking_errors
        native_pdf = result.pdf_bytes
        assert native_pdf.startswith(b"%PDF")
        original_pdf_digest = sha256(native_pdf).hexdigest()
        pdf_path = evidence_dir / "original-production.pdf"
        pdf_path.write_bytes(native_pdf)
        native_text = extract_pdf_visible_text(native_pdf)
        (evidence_dir / "pdf-visible.txt").write_text(native_text, encoding="utf-8")

        original_sections = deepcopy(contracted["sections"])
        altered_sections = deepcopy(original_sections)
        assert altered_sections["raci"].count("اعتماد إطلاق الخدمة") == 1
        altered_sections["raci"] = altered_sections["raci"].replace(
            "اعتماد إطلاق الخدمة", "objectives kpi_missing", 1
        )
        altered_before_validation = deepcopy(altered_sections)
        trace["original_sections"] = original_sections
        trace["altered_expected_sections"] = altered_sections
        trace["pdf_sha256"] = original_pdf_digest
        # The bytes are the real accepted PDF. A deliberately changed expected
        # RACI activity creates a genuine painted-content mismatch. Both words
        # are ordinary source data here, not strategy-only blocker identities.
        gate = validate_export_text(
            "pdf", pdf_text=native_text, pdf_bytes=native_pdf,
            pdf_bytes_had=True, canonical_sections=altered_sections,
            domain="dt", document_type="governance_model", lang="ar",
        )
        trace["mismatch_gate"] = gate
        assert gate.get("export_return_allowed") is False, gate
        assert gate.get("export_evidence_passed") is False, gate
        native_errors = [
            str(error) for error in gate.get("blocking_errors", [])
            if "rel33_governance_export_mismatch:pdf:" in str(error)
        ]
        assert native_errors, gate
        assert any("objectives" in error and "kpi_missing" in error for error in native_errors), native_errors
        assert native_sections == fixture_before
        assert contracted["sections"] == original_sections
        assert altered_sections == altered_before_validation
        assert sha256(native_pdf).hexdigest() == original_pdf_digest
        assert sha256(pdf_path.read_bytes()).hexdigest() == original_pdf_digest
    finally:
        _save_json(evidence_dir / "observations.json", trace)
