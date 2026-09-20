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
    r'Regulatory Environment|Business Environment|'
    r'Environment and Drivers|Threat Landscape)',
    re.I,
)
_ENV_NEXT_RE = re.compile(
    r'(تحليل الفجوات|Gap Analysis|خارطة الطريق|Roadmap|'
    r'الركائز الاستراتيجية|Strategic Pillars)',
    re.I,
)
_APPENDIX_RE = re.compile(
    r'(Appendix|Annex|الملحق|الملاحق|ملحق)',
    re.I,
)
_TOC_LINE_RE = re.compile(r'^\d{1,2}\s+\S')
_COVER_LABELS = ('القطاع', 'Sector')
_GENERIC_ENV_AR = 'تعمل الجهة في بيئة تنظيمية'
_REL37_NARRATIVE_DOMAINS = frozenset({'data', 'ai', 'dt'})

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


def _decode_actual_text_hex(hx: str) -> str:
    raw_hx = str(hx or '')
    if raw_hx.upper().startswith('FEFF'):
        raw_hx = raw_hx[4:]
    try:
        return bytes.fromhex(raw_hx).decode('utf-16-be')
    except Exception:  # noqa: BLE001
        return ''


def _actual_text_spans_from_stream(stream: bytes) -> List[str]:
    parts: List[str] = []
    if not stream or b'ActualText' not in stream:
        return parts
    for match in re.finditer(br'/ActualText\s*<([0-9A-Fa-f]+)>', stream):
        text = _decode_actual_text_hex(match.group(1).decode('ascii'))
        if text:
            parts.append(text)
    return parts


def _page_content_xrefs(page) -> List[int]:
    xrefs: List[int] = []
    try:
        contents = page.get_contents() or []
        if isinstance(contents, int):
            contents = [contents]
        xrefs.extend(int(item) for item in contents if item)
    except Exception:  # noqa: BLE001
        pass
    try:
        xobjects = page.get_xobjects() or []
        for item in xobjects:
            if isinstance(item, int):
                xrefs.append(item)
                continue
            if isinstance(item, (tuple, list)) and item:
                xref = item[0]
                if isinstance(xref, int):
                    xrefs.append(xref)
    except Exception:  # noqa: BLE001
        pass
    return list(dict.fromkeys(xrefs))


def extract_pdf_pages(raw: bytes) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Page-bound visible text and ActualText. Never a global bag.

    Visual evidence and ActualText stay separate on each page. Cover is
    page 0. If page association cannot be established, ``associated`` is
    false and callers must report an evidence failure instead of
    accepting a document-wide substring.
    """
    pages: List[Dict[str, Any]] = []
    meta: Dict[str, Any] = {
        'pages': 0,
        'reliable': False,
        'associated': False,
        'extractor': '',
        'actual_text_spans': 0,
    }
    if not raw.startswith(b'%PDF'):
        return pages, meta
    try:
        import pymupdf
        doc = pymupdf.open(stream=raw, filetype='pdf')
        meta['pages'] = len(doc)
        span_count = 0
        for index, page in enumerate(doc):
            visible = page.get_text() or ''
            actual_parts: List[str] = []
            for xref in _page_content_xrefs(page):
                try:
                    stream = doc.xref_stream(xref)
                except Exception:  # noqa: BLE001
                    continue
                spans = _actual_text_spans_from_stream(stream)
                span_count += len(spans)
                actual_parts.extend(spans)
            pages.append({
                'index': index,
                'visible': _normalize_extracted_pdf_text(visible),
                'actual': _normalize_extracted_pdf_text('\n'.join(actual_parts)),
            })
        meta['actual_text_spans'] = span_count
        meta['extractor'] = 'pymupdf+page-actualtext'
        meta['associated'] = bool(pages)
        meta['reliable'] = bool(pages) and any(
            (item['visible'] or item['actual']).strip() for item in pages)
        return pages, meta
    except Exception as exc:  # noqa: BLE001
        meta['extractor_error'] = type(exc).__name__
        return pages, meta


def _extract_pdf_actual_text(raw: bytes) -> Tuple[str, int]:
    """Read producer-emitted PDF ActualText spans, page-associated first.

    Global xref fallback is retained only for inventory/readability, not
    for narrative or cover comparison.
    """
    pages, meta = extract_pdf_pages(raw)
    associated = '\n'.join(
        item['actual'] for item in pages if item.get('actual'))
    if associated.strip():
        return associated, int(meta.get('actual_text_spans') or 0)
    parts: List[str] = []
    try:
        import pymupdf
        doc = pymupdf.open(stream=raw, filetype='pdf')
        for xref in range(1, doc.xref_length()):
            try:
                stream = doc.xref_stream(xref)
            except Exception:  # noqa: BLE001
                continue
            parts.extend(_actual_text_spans_from_stream(stream))
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
        # Numbered TOC lines share heading words but are not the body.
        if _TOC_LINE_RE.match(text) and len(text) < 80:
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


def _compact_sector_token(value: str) -> str:
    return re.sub(r'[\s/\-—–]+', '', _norm(value))


def _conflicting_cover_value(value: str) -> bool:
    raw = _norm(value)
    if not raw or raw in ('—', '-', '\u2014'):
        return False
    known = {english for english, _arabic in UI_SECTOR_PAIRS}
    known.update(arabic for _english, arabic in UI_SECTOR_PAIRS)
    if raw in known:
        return True
    compact = _compact_sector_token(raw)
    return bool(compact) and any(
        _compact_sector_token(item) == compact for item in known)


def _normalize_cover_visual(text: str) -> str:
    """Recover logical Arabic from shaped cover glyphs without inventing words."""
    import unicodedata
    return unicodedata.normalize('NFKC', text or '').replace('\x00', '/')


def _page_lines(page: Dict[str, Any]) -> List[str]:
    blob = '\n'.join(
        part for part in (page.get('actual') or '', page.get('visible') or '')
        if part)
    return [line.strip() for line in blob.splitlines() if line.strip()]


def _looks_like_toc_page(lines: Sequence[str]) -> bool:
    if not lines:
        return False
    toc_hits = sum(
        1 for line in lines
        if _TOC_LINE_RE.match(line) and len(line) < 80)
    return toc_hits >= 3 and toc_hits >= max(1, len(lines) // 2)


def pdf_environment_section_text(raw: bytes) -> Tuple[str, Dict[str, Any]]:
    """Environment-section text only: not cover, TOC, or appendix."""
    pages, meta = extract_pdf_pages(raw)
    detail = dict(meta)
    if not pages:
        detail['associated'] = False
        return '', detail
    if not meta.get('associated'):
        return '', detail
    collected: List[str] = []
    visible_parts: List[str] = []
    actual_parts: List[str] = []
    taking = False
    heading_page = None
    for page in pages:
        index = int(page.get('index') or 0)
        if index == 0:
            continue
        visible_lines = [
            line.strip()
            for line in str(page.get('visible') or '').splitlines()
            if line.strip()
        ]
        if _looks_like_toc_page(visible_lines) and not taking:
            continue
        page_took = False
        stop_page = False
        for line in visible_lines:
            if _APPENDIX_RE.search(line) and len(line) < 80:
                if taking:
                    taking = False
                stop_page = True
                break
            if _ENV_HEAD_RE.search(line) and len(line) < 120:
                if _TOC_LINE_RE.match(line) and len(line) < 80:
                    continue
                taking = True
                heading_page = index
                page_took = True
                continue
            if taking and _ENV_NEXT_RE.search(line) and len(line) < 120:
                taking = False
                stop_page = True
                break
            if taking:
                collected.append(line)
                page_took = True
        if stop_page:
            continue
        if page_took:
            actual = page.get('actual') or ''
            if actual.strip():
                collected.append(actual)
                actual_parts.append(actual)
            visible_parts.append(page.get('visible') or '')
    section = '\n'.join(collected)
    detail['environment_heading_page'] = heading_page
    detail['environment_associated'] = heading_page is not None
    detail['environment_visible'] = '\n'.join(visible_parts)
    detail['environment_actual'] = '\n'.join(actual_parts)
    return section, detail


def _cover_value_matches(value: str, expected: str) -> bool:
    aliases = sector_reference_aliases(expected)
    raw = _norm(value)
    if raw in aliases:
        return True
    compact = _compact_sector_token(value)
    if not compact:
        return False
    return any(
        alias in raw or _compact_sector_token(alias) == compact
        for alias in aliases
    )


def _cover_label_aliases() -> Tuple[str, ...]:
    aliases = []
    for label in _COVER_LABELS:
        aliases.append(label)
        if label.isascii():
            aliases.append(label.upper())
            aliases.append(label.lower())
            aliases.append(label.title())
    return tuple(dict.fromkeys(aliases))


def _labeled_cover_sector(text: str) -> Tuple[str, bool]:
    """Return (value, field_found) for the labeled Sector/القطاع field.

    A missing label is not a successful empty field. A found label with
    no readable value is an unreadable field, not a neutral dash.
    """
    labels = _cover_label_aliases()
    lines = [line.strip() for line in str(text or '').splitlines() if line.strip()]
    for idx, line in enumerate(lines):
        n = _norm(line)
        for label in labels:
            if n == label:
                if idx + 1 < len(lines):
                    nxt = _norm(lines[idx + 1])
                    if nxt in labels:
                        return '', True
                    return nxt, True
                return '', True
            if n.startswith(label + ' ') or n.startswith(label + ':') or n.startswith(label + '\t'):
                rest = n[len(label):].lstrip(' :|\t')
                return rest, True
            if n.startswith(label) and len(n) > len(label):
                rest = n[len(label):].lstrip(' :|\t')
                if rest:
                    return rest, True
    blob = _norm(text)
    for label in labels:
        pos = blob.find(label)
        if pos < 0:
            continue
        after = blob[pos + len(label):].lstrip(' :|\t')
        token = after.split(' ')[0] if after else ''
        return token, True
    return '', False


def pdf_cover_sector_value(raw: bytes) -> Tuple[str, Dict[str, Any]]:
    """Labeled cover-sector value from page 0 only."""
    pages, meta = extract_pdf_pages(raw)
    detail = dict(meta)
    detail['field_found'] = False
    detail['field_readable'] = False
    if not pages or not meta.get('associated'):
        return '', detail
    cover = pages[0]
    actual = cover.get('actual') or ''
    visual = _normalize_cover_visual(cover.get('visible') or '')
    value, found = _labeled_cover_sector(actual)
    source = 'actual'
    if not found:
        value, found = _labeled_cover_sector(visual)
        source = 'visible'
    detail['field_found'] = found
    detail['field_source'] = source if found else ''
    detail['field_readable'] = bool(found and value)
    detail['cover_page_index'] = 0
    return value, detail


def pdf_cover_and_body_text(raw: bytes) -> Tuple[str, str, Dict[str, Any]]:
    """Keep cover visual evidence distinct from the environment section."""
    pages, meta = extract_pdf_pages(raw)
    cover = ''
    if pages:
        cover = pages[0].get('visible') or ''
    section, env_meta = pdf_environment_section_text(raw)
    merged = dict(meta)
    merged.update(env_meta)
    merged['environment_page_present'] = bool(env_meta.get('environment_associated'))
    return cover, section, merged


def compare_environment_narrative_to_pdf(
        model: CanonicalDocument,
        raw: bytes,
) -> List[str]:
    narrative = str(model.environment_narrative or '').strip()
    if not narrative:
        return []
    section, meta = pdf_environment_section_text(raw)
    if raw.startswith(b'%PDF') and not meta.get('reliable') and not section.strip():
        return ['pdf_extraction_unreliable']
    if not meta.get('associated'):
        return ['pdf_environment_section_unassociated']
    if not meta.get('environment_associated'):
        return ['pdf_environment_section_unassociated']
    blob = _norm(section)
    if not blob:
        return ['pdf_environment_text_empty']
    visible = meta.get('environment_visible') or ''
    actual = meta.get('environment_actual') or ''
    blockers: List[str] = []
    for idx, para in enumerate(environment_narrative_paragraphs(narrative)):
        blockers.extend(_paragraph_pdf_blockers(
            idx, para, section, visible=visible, actual=actual))
    return blockers


_LATIN_TOKEN_RE = re.compile(r'[A-Za-z][A-Za-z0-9_-]*')


def _latin_tokens(text: str) -> List[str]:
    return _LATIN_TOKEN_RE.findall(str(text or ''))


def _semantic_latin_tokens(text: str) -> List[str]:
    """Identity-bearing Latin tokens, not ordinary wrapped English words."""
    out: List[str] = []
    for token in _latin_tokens(text):
        if token.isupper() and len(token) >= 2:
            out.append(token)
        elif any(ch.isdigit() for ch in token) and any(ch.isalpha() for ch in token):
            out.append(token)
        elif len(token) >= 4 and sum(1 for ch in token if ch.isupper()) >= 2:
            out.append(token)
    return out


def _ordered_latin_match(want: Sequence[str], have: Sequence[str]) -> bool:
    if not want:
        return True
    idx = 0
    for token in have:
        if idx < len(want) and token == want[idx]:
            idx += 1
    return idx == len(want)


def _paragraph_pdf_blockers(
        idx: int,
        para: str,
        section: str,
        *,
        visible: str = '',
        actual: str = '',
) -> List[str]:
    """Compare one saved paragraph inside the associated environment section.

    Latin tokens keep identity and order. Layout may collapse whitespace.
    ASCII-drop equality is not accepted.
    """
    want = _norm(para)
    have = _norm(section)
    if not want:
        return []
    blockers: List[str] = []
    want_lat = _semantic_latin_tokens(para)
    have_lat = _semantic_latin_tokens(section)
    if want_lat:
        missing = [token for token in want_lat if token not in have_lat]
        if missing:
            for token in missing:
                blockers.append(
                    f'pdf_environment_latin_missing:{idx}:{token}')
        elif not _ordered_latin_match(want_lat, have_lat):
            blockers.append(f'pdf_environment_latin_order:{idx}')
        vis_lat = _semantic_latin_tokens(visible)
        act_lat = _semantic_latin_tokens(actual)
        vis_need = [token for token in want_lat if token in vis_lat]
        act_need = [token for token in want_lat if token in act_lat]
        if act_need and vis_need != act_need:
            blockers.append(
                f'pdf_environment_actual_visible_disagree:{idx}')
    if want not in have:
        blockers.append(f'pdf_environment_narrative_missing:{idx}')
    return blockers


def _paragraph_in_pdf_section(para: str, section: str) -> bool:
    return not _paragraph_pdf_blockers(0, para, section)


def compare_cover_sector_to_pdf(
        model: CanonicalDocument,
        raw: bytes,
) -> List[str]:
    expected = cover_sector_from_hashed_narrative(
        model.environment_narrative, model.lang)
    value, meta = pdf_cover_sector_value(raw)
    if raw.startswith(b'%PDF') and not meta.get('associated'):
        return ['pdf_cover_sector_unassociated']
    if not meta.get('field_found'):
        if expected:
            return ['pdf_cover_sector_unreadable']
        return ['pdf_cover_sector_unreadable']
    if not expected:
        if _conflicting_cover_value(value):
            return [f'pdf_cover_sector_injected:{value}']
        return []
    if not value:
        return ['pdf_cover_sector_unreadable']
    if not _cover_value_matches(value, expected):
        return [f'pdf_cover_sector_mismatch:{value}']
    return []


def hashed_narrative_requires_section_parity(model: CanonicalDocument) -> bool:
    """Required nonempty REL37 environment_narrative is compared.

    Applicability is the authorized REL37 model contract, not a keyword
    test for ``سياق تشغيلي`` / ``operating context``. Empty narrative
    follows the existing schema omission contract. Cyber/ERM/Global and
    other non-REL37 domains are not selected here. The route gate still
    requires ``is_rel37_authoritative`` before this helper runs.
    """
    domain = str(getattr(model, 'domain', '') or '').strip().lower()
    if domain not in _REL37_NARRATIVE_DOMAINS:
        return False
    text = str(getattr(model, 'environment_narrative', '') or '').strip()
    return bool(text)


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
    require_narrative = hashed_narrative_requires_section_parity(model)
    if check_docx:
        if require_narrative:
            blockers.extend(compare_environment_narrative_to_docx(model, docx_bytes))
        blockers.extend(compare_cover_sector_to_docx(model, docx_bytes))
    if check_pdf:
        if require_narrative:
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
