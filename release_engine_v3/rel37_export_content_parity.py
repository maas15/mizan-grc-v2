"""REL37 actual export content-parity acceptance.

Download/parse success is not content parity. This checker compares the
validated CanonicalDocument to preview, DOCX, and PDF independently.
"""
from __future__ import annotations

import hashlib
import io
import re
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from xml.etree import ElementTree as ET

from release_engine_v3.rel37_canonical_document import CanonicalDocument
from release_engine_v3.rel37_professional_projection import projection_tables
from release_engine_v3.rel37_sector_context import (
    UI_SECTOR_PAIRS,
    cover_sector_from_hashed_narrative,
    environment_narrative_paragraphs,
    sector_reference_aliases,
)

_ENV_HEAD_RE = re.compile(
    r'(البيئة التنظيمية والتهديدات|البيئة والمحركات|'
    r'Business Environment|Environment and Drivers)',
    re.I,
)
_ENV_NEXT_RE = re.compile(
    r'(تحليل الفجوات|Gap Analysis|خارطة الطريق|Roadmap|'
    r'الركائز الاستراتيجية|Strategic Pillars)',
    re.I,
)
_COVER_LABELS = ('القطاع', 'Sector')
_GENERIC_ENV_AR = 'تعمل الجهة في بيئة تنظيمية'

_AR_RE = re.compile(r'[\u0600-\u06FF]')
_W_NS = '{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'


@dataclass
class ParityResult:
    persist_success: str = 'not_run'
    download_parse_success: str = 'not_run'
    content_parity: str = 'not_run'
    language_correctness: str = 'not_run'
    rendering_readability: str = 'not_run'
    security_acceptance: str = 'not_run'
    blockers: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    file_sha256: str = ''
    model_hash: str = ''
    source_hash: str = ''
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        dims = (
            self.persist_success,
            self.download_parse_success,
            self.content_parity,
            self.language_correctness,
            self.rendering_readability,
        )
        return all(item == 'passed' for item in dims) and not self.blockers


def arabic_char_count(text: str, *, org_name: str = '') -> int:
    blob = str(text or '').replace(org_name or '', '')
    return len(_AR_RE.findall(blob))


def inventory_docx_bytes(raw: bytes) -> Dict[str, Any]:
    paragraphs: List[str] = []
    tables: List[List[List[str]]] = []
    headers: List[str] = []
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        for name in zf.namelist():
            if not name.startswith('word/') or not name.endswith('.xml'):
                continue
            root = ET.fromstring(zf.read(name))
            is_hf = 'header' in name or 'footer' in name
            for p in root.iter(f'{_W_NS}p'):
                if list(p.iter(f'{_W_NS}tbl')):
                    continue
                text = ''.join(
                    (t.text or '') + (t.tail or '')
                    for t in p.iter(f'{_W_NS}t')
                ).strip()
                if not text:
                    continue
                if is_hf:
                    headers.append(text)
                else:
                    paragraphs.append(text)
            for tbl in root.iter(f'{_W_NS}tbl'):
                rows: List[List[str]] = []
                for tr in tbl.findall(f'{_W_NS}tr'):
                    cells = []
                    for tc in tr.findall(f'{_W_NS}tc'):
                        cells.append(''.join(
                            (t.text or '') + (t.tail or '')
                            for t in tc.iter(f'{_W_NS}t')
                        ).strip())
                    if any(cells):
                        rows.append(cells)
                if rows:
                    tables.append(rows)
    return {
        'paragraphs': paragraphs,
        'tables': tables,
        'headers_footers': headers,
        'text': '\n'.join(paragraphs + [
            ' | '.join(cell for cell in row)
            for table in tables for row in table
        ] + headers),
    }


def _normalize_extracted_pdf_text(text: str) -> str:
    """Keep extractor output, but recover logical Arabic from presentation forms.

    This does not invent missing text. It only NFKC-normalizes glyphs that
    were actually extracted, and drops NUL placeholders left by missing
    Latin glyphs inside Arabic runs.
    """
    import unicodedata
    return unicodedata.normalize('NFKC', text or '').replace('\x00', '')


def _extract_pdf_actual_text(raw: bytes) -> Tuple[str, int]:
    """Read producer-emitted PDF ActualText spans (UTF-16BE hex).

    This is file evidence, not a substitution of canonical model text.
    ReportLab emits logical Arabic as ActualText while painting shaped
    visual glyphs; pymupdf ``get_text()`` keeps the visual run.
    """
    parts: List[str] = []
    try:
        import pymupdf
        doc = pymupdf.open(stream=raw, filetype='pdf')
        for xref in range(1, doc.xref_length()):
            try:
                stream = doc.xref_stream(xref)
            except Exception:  # noqa: BLE001
                continue
            if not stream or b'ActualText' not in stream:
                continue
            for match in re.finditer(
                    br'/ActualText\s*<([0-9A-Fa-f]+)>', stream):
                hx = match.group(1).decode('ascii')
                if hx.upper().startswith('FEFF'):
                    hx = hx[4:]
                try:
                    parts.append(bytes.fromhex(hx).decode('utf-16-be'))
                except Exception:  # noqa: BLE001
                    continue
    except Exception:  # noqa: BLE001
        return '', 0
    return '\n'.join(parts), len(parts)


def extract_pdf_text(raw: bytes) -> Tuple[str, Dict[str, Any]]:
    meta: Dict[str, Any] = {'pages': 0, 'extractor': '', 'reliable': False}
    if not raw.startswith(b'%PDF'):
        return '', meta
    actual, actual_count = _extract_pdf_actual_text(raw)
    meta['actual_text_spans'] = actual_count
    try:
        import pymupdf
        doc = pymupdf.open(stream=raw, filetype='pdf')
        pages = [page.get_text() or '' for page in doc]
        meta['pages'] = len(doc)
        meta['extractor'] = 'pymupdf+actualtext' if actual else 'pymupdf'
        text = _normalize_extracted_pdf_text('\n'.join(pages + [actual]))
        meta['reliable'] = bool(text.strip()) and meta['pages'] > 0
        return text, meta
    except Exception as exc:  # noqa: BLE001
        meta['extractor_error'] = type(exc).__name__
    try:
        from PyPDF2 import PdfReader
        reader = PdfReader(io.BytesIO(raw))
        pages = [(page.extract_text() or '') for page in reader.pages]
        meta['pages'] = len(reader.pages)
        meta['extractor'] = 'pypdf2+actualtext' if actual else 'pypdf2'
        text = _normalize_extracted_pdf_text('\n'.join(pages + [actual]))
        meta['reliable'] = bool(text.strip()) and meta['pages'] > 0
        return text, meta
    except Exception as exc:  # noqa: BLE001
        meta['extractor_error'] = type(exc).__name__
        if actual:
            meta['extractor'] = 'actualtext'
            text = _normalize_extracted_pdf_text(actual)
            meta['reliable'] = bool(text.strip())
            return text, meta
        return '', meta


def _norm(value: Any) -> str:
    return re.sub(r'\s+', ' ', str(value or '')).strip()


def _ordered_subsequence(want: Sequence[str], have: Sequence[str]) -> bool:
    """True when expected cells appear on the same row in order.

    Extra presentation columns may sit between fields. A swapped
    owner/deliverable or missing field still fails.
    """
    if not want:
        return False
    idx = 0
    for cell in have:
        if idx < len(want) and cell == want[idx]:
            idx += 1
    return idx == len(want)


def _row_present(expected: Sequence[str], tables: Sequence[Sequence[Sequence[str]]]) -> bool:
    want = [_norm(cell) for cell in expected]
    if not any(want):
        return False
    for table in tables:
        for row in table:
            have = [_norm(cell) for cell in row]
            if _ordered_subsequence(want, have):
                return True
    return False


def _text_has_row(expected: Sequence[str], text: str) -> bool:
    blob = _norm(text).lower()
    return all(_norm(cell).lower() in blob for cell in expected if _norm(cell))


def expected_rows(model: CanonicalDocument) -> Dict[str, List[List[str]]]:
    tables = projection_tables(model)
    return {
        'roadmap': [list(row.cells()) for row in model.roadmap],
        'confidence': [list(row.cells()) for row in model.confidence],
        'traceability': [list(row.cells()) for row in model.traceability],
        'kpis': [list(row.cells()) for row in model.kpis],
        'gaps': [list(row.cells()) for row in model.gaps],
        'governance': [list(row.cells()) for row in model.governance],
        'risks': [
            [row.risk, row.impact, row.mitigation, row.owner]
            for row in model.risks
        ],
        '_headers': {
            'roadmap': tables['roadmap']['header'],
            'confidence': tables['confidence']['header'],
        },
    }


def compare_traceability_association(
        model: CanonicalDocument,
        raw: bytes,
) -> List[str]:
    """Number-keyed row/field check for saved traceability relationships."""
    inv = inventory_docx_bytes(raw)
    blockers: List[str] = []
    expected_rows_list = [list(row.cells()) for row in model.traceability]
    tables = inv.get('tables') or []

    def _score(table: Sequence[Sequence[str]]) -> int:
        score = 0
        for exp in expected_rows_list:
            want = [_norm(cell) for cell in exp]
            for raw_row in table:
                have = [_norm(cell) for cell in raw_row]
                if want and have and have[0] == want[0]:
                    score += sum(1 for cell in want if cell and cell in have)
                    break
        return score

    ranked = sorted(tables, key=_score, reverse=True)
    chosen = ranked[0] if ranked and _score(ranked[0]) else []
    flat_rows = [[_norm(cell) for cell in row] for row in chosen]
    for idx, expected in enumerate(expected_rows_list):
        want = [_norm(cell) for cell in expected]
        number = want[0] if want else ''
        match = None
        for have in flat_rows:
            if have and have[0] == number:
                match = have
                break
        if match is None:
            blockers.append(
                f'docx_missing_traceability_row:{idx}:{number}')
            continue
        if not _ordered_subsequence(want, match):
            blockers.append(
                f'docx_row_field_mismatch:traceability:{idx}:{number}')
    return blockers


def compare_model_to_docx(
        model: CanonicalDocument,
        raw: bytes,
) -> List[str]:
    inv = inventory_docx_bytes(raw)
    blockers: List[str] = []
    for family, rows in expected_rows(model).items():
        if family.startswith('_'):
            continue
        for idx, row in enumerate(rows):
            identity = row[:3] if len(row) >= 3 else row
            if not _row_present(identity, inv['tables']) and not _text_has_row(identity, inv['text']):
                blockers.append(f'docx_missing_{family}_row:{idx}:{_norm(row[0] if row else "")}')
                continue
            # Field association: every non-empty cell must appear on the
            # same row, not merely somewhere in the document.
            if not _row_present(row, inv['tables']):
                blockers.append(
                    f'docx_row_field_mismatch:{family}:{idx}:{_norm(row[0] if row else "")}')
    blockers.extend(compare_environment_narrative_to_docx(model, raw))
    blockers.extend(compare_cover_sector_to_docx(model, raw))
    return blockers


def _section_after_heading(
        paragraphs: Sequence[str],
        heading_re: re.Pattern,
        next_re: re.Pattern,
) -> str:
    taking = False
    collected: List[str] = []
    for para in paragraphs:
        text = str(para or '').strip()
        if not text:
            continue
        if heading_re.search(text) and len(text) < 120:
            taking = True
            continue
        if taking and next_re.search(text) and len(text) < 120:
            break
        if taking:
            collected.append(text)
    return '\n'.join(collected)


def docx_environment_section_text(raw: bytes) -> str:
    inv = inventory_docx_bytes(raw)
    return _section_after_heading(inv.get('paragraphs') or [], _ENV_HEAD_RE, _ENV_NEXT_RE)


def docx_cover_sector_value(raw: bytes) -> str:
    inv = inventory_docx_bytes(raw)
    for table in inv.get('tables') or []:
        for row in table:
            if len(row) >= 2 and _norm(row[0]) in _COVER_LABELS:
                return _norm(row[1])
    return ''


def compare_environment_narrative_to_docx(
        model: CanonicalDocument,
        raw: bytes,
) -> List[str]:
    narrative = str(model.environment_narrative or '').strip()
    if not narrative:
        return []
    section = docx_environment_section_text(raw)
    blob = _norm(section)
    if not blob:
        return ['docx_environment_section_missing']
    blockers: List[str] = []
    for idx, para in enumerate(environment_narrative_paragraphs(narrative)):
        if _norm(para) not in blob:
            blockers.append(f'docx_environment_narrative_missing:{idx}')
    if (
            _GENERIC_ENV_AR in section
            and _norm(narrative) not in blob
            and 'سياق تشغيلي' in narrative
            and 'سياق تشغيلي' not in section
    ):
        blockers.append('docx_environment_generic_leftover')
    return blockers


def compare_cover_sector_to_docx(
        model: CanonicalDocument,
        raw: bytes,
) -> List[str]:
    expected = cover_sector_from_hashed_narrative(
        model.environment_narrative, model.lang)
    cover = docx_cover_sector_value(raw)
    if not expected:
        if _conflicting_cover_value(cover):
            return ['docx_cover_sector_injected']
        return []
    if not cover:
        return ['docx_cover_sector_missing']
    aliases = sector_reference_aliases(expected)
    if cover not in aliases and not any(alias in cover for alias in aliases):
        return [f'docx_cover_sector_mismatch:{cover}']
    return []


def _conflicting_cover_value(value: str) -> bool:
    raw = _norm(value)
    if not raw or raw in ('—', '-', '\u2014'):
        return False
    known = {english for english, _arabic in UI_SECTOR_PAIRS}
    known.update(arabic for _english, arabic in UI_SECTOR_PAIRS)
    return raw in known


def pdf_cover_and_body_text(raw: bytes) -> Tuple[str, str, Dict[str, Any]]:
    """Keep cover visual evidence distinct from body ActualText."""
    meta: Dict[str, Any] = {'pages': 0, 'reliable': False}
    if not raw.startswith(b'%PDF'):
        return '', '', meta
    actual, actual_count = _extract_pdf_actual_text(raw)
    meta['actual_text_spans'] = actual_count
    cover = ''
    pages: List[str] = []
    try:
        import pymupdf
        doc = pymupdf.open(stream=raw, filetype='pdf')
        pages = [page.get_text() or '' for page in doc]
        meta['pages'] = len(doc)
        cover = pages[0] if pages else ''
        meta['reliable'] = bool(pages)
    except Exception as exc:  # noqa: BLE001
        meta['extractor_error'] = type(exc).__name__
    body = _normalize_extracted_pdf_text(actual)
    if not body:
        body = _normalize_extracted_pdf_text('\n'.join(pages))
    env_page = ''
    for page in pages[1:]:
        if _ENV_HEAD_RE.search(page):
            env_page = page
            break
    meta['environment_page_present'] = bool(env_page or ('سياق تشغيلي' in body))
    return cover, body, meta


def compare_environment_narrative_to_pdf(
        model: CanonicalDocument,
        raw: bytes,
) -> List[str]:
    narrative = str(model.environment_narrative or '').strip()
    if not narrative:
        return []
    _cover, body, meta = pdf_cover_and_body_text(raw)
    if raw.startswith(b'%PDF') and not meta.get('reliable') and not body.strip():
        return ['pdf_extraction_unreliable']
    blob = _norm(body)
    if not blob:
        return ['pdf_environment_text_empty']
    blockers: List[str] = []
    for idx, para in enumerate(environment_narrative_paragraphs(narrative)):
        if _norm(para) not in blob:
            blockers.append(f'pdf_environment_narrative_missing:{idx}')
    return blockers


def _first_cover_sector_window(text: str) -> str:
    blob = str(text or '')
    earliest = None
    window = ''
    for label in _COVER_LABELS:
        idx = blob.find(label)
        if idx < 0:
            continue
        if earliest is None or idx < earliest:
            earliest = idx
            window = blob[idx:idx + 96]
    return window


def compare_cover_sector_to_pdf(
        model: CanonicalDocument,
        raw: bytes,
) -> List[str]:
    expected = cover_sector_from_hashed_narrative(
        model.environment_narrative, model.lang)
    cover, _body, _meta = pdf_cover_and_body_text(raw)
    actual, _count = _extract_pdf_actual_text(raw)
    cover_window = _first_cover_sector_window(actual) or _first_cover_sector_window(cover)
    if not expected:
        if 'Healthcare' in cover or 'رعاية صحية' in cover:
            return ['pdf_cover_sector_injected']
        return []
    aliases = sector_reference_aliases(expected)
    if ('Healthcare' in cover or 'رعاية صحية' in cover) and (
            'Healthcare' not in aliases and 'رعاية صحية' not in aliases):
        return ['pdf_cover_sector_mismatch:Healthcare']
    if any(alias in cover_window for alias in aliases):
        return []
    if any(alias in cover for alias in aliases):
        return []
    return ['pdf_cover_sector_mismatch']


def rel37_returned_bytes_blockers(
        model: CanonicalDocument,
        *,
        docx_bytes: bytes = b'',
        pdf_bytes: bytes = b'',
        route: str = '',
) -> List[str]:
    """Route-local returned-byte blockers. Preview cannot substitute PDF."""
    route_n = str(route or '').strip().lower()
    blockers: List[str] = []
    check_docx = route_n in ('', 'docx', 'docx-async') and docx_bytes
    check_pdf = route_n in ('', 'pdf', 'pdf-async') and pdf_bytes
    if route_n in ('docx', 'docx-async') and not docx_bytes:
        blockers.append('docx_bytes_missing')
    if route_n in ('pdf', 'pdf-async') and not pdf_bytes:
        blockers.append('pdf_bytes_missing')
    if check_docx:
        blockers.extend(compare_environment_narrative_to_docx(model, docx_bytes))
        blockers.extend(compare_cover_sector_to_docx(model, docx_bytes))
    if check_pdf:
        blockers.extend(compare_environment_narrative_to_pdf(model, pdf_bytes))
        blockers.extend(compare_cover_sector_to_pdf(model, pdf_bytes))
    return list(dict.fromkeys(blockers))


def gate_rel37_returned_bytes(
        model: CanonicalDocument,
        *,
        docx_bytes: bytes = b'',
        pdf_bytes: bytes = b'',
        route: str = '',
) -> Tuple[bool, List[str]]:
    blockers = rel37_returned_bytes_blockers(
        model, docx_bytes=docx_bytes, pdf_bytes=pdf_bytes, route=route)
    return not blockers, blockers


def compare_model_to_text(
        model: CanonicalDocument,
        text: str,
        *,
        route: str,
) -> List[str]:
    blockers: List[str] = []
    blob = _norm(text)
    if not blob:
        return [f'{route}_text_empty']
    for family, rows in expected_rows(model).items():
        if family.startswith('_'):
            continue
        for idx, row in enumerate(rows):
            if not _text_has_row(row[:3] if len(row) >= 3 else row, blob):
                blockers.append(f'{route}_missing_{family}_row:{idx}:{_norm(row[0] if row else "")}')
    return blockers


def language_blockers(model: CanonicalDocument, text: str) -> List[str]:
    if model.lang != 'en':
        return []
    count = arabic_char_count(text, org_name=model.org_name)
    if count:
        return [f'en_unexpected_arabic_chars:{count}']
    return []


def evaluate_export_parity(
        *,
        model: CanonicalDocument,
        persist_ok: bool,
        download_ok: bool,
        parsed_ok: bool,
        preview_text: str = '',
        docx_bytes: bytes = b'',
        pdf_bytes: bytes = b'',
        source_hash: str = '',
        security: str = 'not_run',
) -> ParityResult:
    result = ParityResult(
        persist_success='passed' if persist_ok else 'failed',
        download_parse_success='passed' if (download_ok and parsed_ok) else 'failed',
        security_acceptance=security,
        model_hash=model.model_hash,
        source_hash=source_hash,
    )
    if source_hash and model.model_hash and source_hash != model.model_hash:
        # Matching/mismatching source hash never overrides actual content.
        result.notes.append('source_hash_recorded_separately')
    if not persist_ok:
        result.blockers.append('persist_failed')
    if not (download_ok and parsed_ok):
        result.blockers.append('download_or_parse_failed')

    preview_blockers = compare_model_to_text(model, preview_text, route='preview') if preview_text else []
    docx_blockers = compare_model_to_docx(model, docx_bytes) if docx_bytes else ['docx_bytes_missing']
    pdf_text, pdf_meta = extract_pdf_text(pdf_bytes) if pdf_bytes else ('', {'reliable': False})
    if pdf_bytes and not pdf_meta.get('reliable'):
        pdf_blockers = ['pdf_extraction_unreliable']
    elif pdf_bytes:
        pdf_blockers = compare_model_to_text(model, pdf_text, route='pdf')
        pdf_blockers.extend(compare_environment_narrative_to_pdf(model, pdf_bytes))
        pdf_blockers.extend(compare_cover_sector_to_pdf(model, pdf_bytes))
    else:
        pdf_blockers = ['pdf_bytes_missing']

    content_blockers = preview_blockers + docx_blockers + pdf_blockers
    result.content_parity = 'failed' if content_blockers else 'passed'
    result.blockers.extend(content_blockers)

    lang_text = '\n'.join([
        preview_text,
        inventory_docx_bytes(docx_bytes)['text'] if docx_bytes else '',
        pdf_text,
    ])
    lang_blockers = language_blockers(model, lang_text)
    result.language_correctness = 'failed' if lang_blockers else 'passed'
    result.blockers.extend(lang_blockers)

    readable = bool(docx_bytes) and bool(pdf_meta.get('reliable'))
    if pdf_bytes and not pdf_meta.get('reliable'):
        result.rendering_readability = 'failed'
        result.blockers.append('pdf_unreadable_or_unextractable')
    elif not readable:
        result.rendering_readability = 'failed'
        result.blockers.append('export_not_readable')
    else:
        result.rendering_readability = 'passed'

    if docx_bytes:
        result.file_sha256 = hashlib.sha256(docx_bytes).hexdigest()
    matching_hash = bool(
        source_hash and model.model_hash and source_hash == model.model_hash)
    docx_content_failed = any(
        item.startswith('docx_row_field_mismatch')
        or item.startswith('docx_missing_')
        for item in docx_blockers)
    result.details = {
        'preview_blockers': preview_blockers,
        'docx_blockers': docx_blockers,
        'pdf_blockers': pdf_blockers,
        'pdf_meta': pdf_meta,
        'source_hash_matches_model': matching_hash,
        'source_hash_does_not_override_content': bool(
            matching_hash and docx_content_failed),
    }
    result.blockers = list(dict.fromkeys(result.blockers))
    return result


def negative_control_arabic_cell_fails(model: CanonicalDocument) -> bool:
    """A readable DOCX with one unexpected generated Arabic cell fails parity."""
    from docx import Document
    doc = Document()
    table = doc.add_table(rows=1, cols=6)
    cells = list(model.roadmap[0].cells())
    cells[4] = 'إطار حوكمة NDMO معتمد'
    for idx, value in enumerate(cells):
        table.cell(0, idx).text = value
    buf = io.BytesIO()
    doc.save(buf)
    blockers = compare_model_to_docx(model, buf.getvalue())
    return any('row_field_mismatch' in item or 'missing_roadmap' in item for item in blockers)


def negative_control_english_wording_fails(model: CanonicalDocument) -> bool:
    from docx import Document
    doc = Document()
    table = doc.add_table(rows=1, cols=6)
    cells = list(model.roadmap[0].cells())
    cells[4] = 'Approved NDMO framework charter'
    for idx, value in enumerate(cells):
        table.cell(0, idx).text = value
    buf = io.BytesIO()
    doc.save(buf)
    blockers = compare_model_to_docx(model, buf.getvalue())
    return any('row_field_mismatch' in item or 'missing_roadmap' in item for item in blockers)
