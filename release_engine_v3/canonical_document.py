"""PR-REL3 — build and freeze canonical document artifacts."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

from release_engine.section_model import legacy_sections_to_canonical
from release_engine_v3.contracts import (
    CanonicalSection,
    ExportManifest,
    FinalDocumentArtifact,
    compute_canonical_hash,
)
from release_engine_v3.section_models import (
    build_strategy_document,
    enrich_kpi_section,
    enrich_traceability_section,
    section_to_markdown,
    strategy_document_to_markdown,
)
from release_engine_v3.validators import validate_canonical_quality


_ARTIFACT_REGISTRY: Dict[str, FinalDocumentArtifact] = {}

SAVED_DOCX_FIDELITY_KEY = '_saved_docx_fidelity'
SAVED_DOCX_REQUIRED_SECTIONS = (
    'vision', 'pillars', 'environment', 'gaps', 'roadmap',
    'kpis', 'confidence', 'governance', 'traceability',
)


def _saved_docx_positive_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if type(value) is int and value > 0:
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            parsed = int(text)
            if parsed > 0:
                return parsed
    return None


def saved_docx_section_strings(sections: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """String section bodies only. Underscore keys are not business content."""
    out: Dict[str, str] = {}
    for key, value in dict(sections or {}).items():
        if str(key).startswith('_'):
            continue
        if isinstance(value, str):
            out[str(key)] = value
    return out


def saved_docx_section_digest(sections: Optional[Dict[str, Any]]) -> str:
    payload = saved_docx_section_strings(sections)
    raw = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(',', ':'),
    ).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


def saved_docx_content_digest(content: Any) -> str:
    return hashlib.sha256(str(content or '').encode('utf-8')).hexdigest()


def _saved_norm_text(value: Any) -> str:
    """Benign comparison whitespace. Brackets and punctuation stay."""
    text = str(value or '').replace('\u00a0', ' ')
    return re.sub(r'\s+', ' ', text).strip()


def _saved_split_pipe_row(line: str) -> Optional[List[str]]:
    """Split one bordered pipe row. A backslash-escaped pipe stays in the cell."""
    raw = str(line or '').strip()
    if len(raw) < 2 or not raw.startswith('|') or not raw.endswith('|'):
        return None
    body = raw[1:-1]
    cells: List[str] = []
    buf: List[str] = []
    index = 0
    while index < len(body):
        char = body[index]
        if char == '\\' and index + 1 < len(body) and body[index + 1] == '|':
            buf.append('|')
            index += 2
            continue
        if char == '|':
            cells.append(''.join(buf).strip())
            buf = []
            index += 1
            continue
        buf.append(char)
        index += 1
    cells.append(''.join(buf).strip())
    return cells


def _saved_separator_row(cells: List[str]) -> bool:
    return bool(cells) and all(
        re.fullmatch(r':?-{3,}:?', cell or '') for cell in cells)


def parse_saved_markdown_structure(
        text: Any) -> Tuple[List[Dict[str, Any]], str]:
    """Ordered headings, prose and tables. A non-empty error refuses export.

    Supported Markdown is ATX headings, blank-line-separated prose, and pipe
    tables with a leading and trailing pipe, one separator row of the header
    width, and data rows of the header width. A header plus its separator and
    no data rows is a table with an empty row list; the writer must draw that
    header. Escaped pipes and empty cells are kept. Any other pipe line is
    unsupported and is not truncated into a shorter row.
    """
    blocks: List[Dict[str, Any]] = []
    prose: List[str] = []

    def flush() -> None:
        chunk = '\n'.join(prose).strip()
        prose.clear()
        if chunk:
            blocks.append({'kind': 'prose', 'text': chunk})

    lines = str(text or '').splitlines()
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped:
            flush()
            index += 1
            continue
        heading = re.match(r'^(#{1,6})\s+(\S.*?)\s*$', stripped)
        if heading:
            flush()
            blocks.append({
                'kind': 'heading',
                'level': len(heading.group(1)),
                'text': heading.group(2).strip(),
            })
            index += 1
            continue
        if '|' in stripped and not (
                stripped.startswith('|') and stripped.endswith('|')):
            return blocks, 'saved_docx_fidelity_refused:unsupported_markdown'
        if stripped.startswith('|') and stripped.endswith('|'):
            flush()
            raw_rows: List[List[str]] = []
            while index < len(lines) and '|' in lines[index]:
                if not lines[index].strip():
                    break
                cells = _saved_split_pipe_row(lines[index])
                if cells is None:
                    return blocks, 'saved_docx_fidelity_refused:unsupported_markdown'
                raw_rows.append(cells)
                index += 1
            if len(raw_rows) < 2 or not _saved_separator_row(raw_rows[1]):
                return blocks, 'saved_docx_fidelity_refused:malformed_table'
            header = raw_rows[0]
            if len(raw_rows[1]) != len(header):
                return blocks, 'saved_docx_fidelity_refused:malformed_table'
            data: List[List[str]] = []
            for row in raw_rows[2:]:
                if _saved_separator_row(row) or len(row) != len(header):
                    return blocks, 'saved_docx_fidelity_refused:malformed_table'
                data.append(row)
            blocks.append({'kind': 'table', 'header': header, 'rows': data})
            continue
        prose.append(lines[index])
        index += 1
    flush()
    return blocks, ''


def saved_markdown_signature(blocks: List[Dict[str, Any]]) -> Tuple[Any, ...]:
    """Order-sensitive structure after benign whitespace normalization."""
    signature: List[Any] = []
    for block in blocks:
        kind = block.get('kind')
        if kind == 'heading':
            signature.append((
                'heading', int(block.get('level') or 0),
                _saved_norm_text(block.get('text'))))
        elif kind == 'prose':
            signature.append(('prose', _saved_norm_text(block.get('text'))))
        elif kind == 'table':
            header = tuple(
                _saved_norm_text(cell) for cell in (block.get('header') or []))
            rows = tuple(
                tuple(_saved_norm_text(cell) for cell in row)
                for row in (block.get('rows') or []))
            signature.append(('table', header, rows))
    return tuple(signature)


def saved_body_sections_consistency(
        content: Any, sections: Optional[Dict[str, Any]]) -> str:
    """Refuse when the saved body and section map are not the same structure.

    Digests are not this check. The nine section structures, in order, must
    equal the body structure. A stale map, an extra business section, or a
    malformed table is a concrete refusal.
    """
    strings = saved_docx_section_strings(sections)
    unexpected = [
        key for key in strings if key not in SAVED_DOCX_REQUIRED_SECTIONS]
    if unexpected:
        return 'saved_docx_fidelity_refused:unexpected_section:' + unexpected[0]
    body_blocks, body_error = parse_saved_markdown_structure(content)
    if body_error:
        return body_error
    combined: List[Dict[str, Any]] = []
    for key in SAVED_DOCX_REQUIRED_SECTIONS:
        part_blocks, part_error = parse_saved_markdown_structure(
            strings.get(key) or '')
        if part_error:
            return part_error
        if not part_blocks:
            return f'saved_docx_fidelity_refused:section_missing:{key}'
        combined.extend(part_blocks)
    if saved_markdown_signature(body_blocks) != saved_markdown_signature(combined):
        return 'saved_docx_fidelity_refused:body_sections_disagree'
    return ''


_SAVED_CANON_KEYS = {
    'vision': 'vision_objectives',
    'pillars': 'pillars',
    'environment': 'environment',
    'gaps': 'gap_analysis',
    'roadmap': 'roadmap',
    'kpis': 'kpi_kri',
    'confidence': 'confidence_risk',
    'governance': 'governance',
    'traceability': 'traceability',
}


def saved_source_canonical_sections(
        sections: Optional[Dict[str, Any]]) -> Dict[str, CanonicalSection]:
    """Canonical slots whose narrative is the original section markdown.

    table_rows stays empty and the key is not a catalog section key, so
    section_to_markdown returns that narrative instead of inventing a header
    or treating the source header as a data row. The title is empty so no
    second heading is prefixed.
    """
    strings = saved_docx_section_strings(sections)
    out: Dict[str, CanonicalSection] = {}
    for legacy_key, canon_key in _SAVED_CANON_KEYS.items():
        body = strings.get(legacy_key) or ''
        if not body.strip():
            continue
        out[canon_key] = CanonicalSection(
            key='saved_source',
            title='',
            narrative=body,
            table_rows=(),
        )
    return out


_SAVED_CANONICAL_RENDER_ORDER = (
    'executive_summary',
    'vision_objectives',
    'pillars',
    'environment',
    'gap_analysis',
    'roadmap',
    'kpi_kri',
    'confidence_risk',
    'governance',
    'traceability',
    'appendices',
)


def _saved_structure_blocks(text: Any) -> Tuple[List[Dict[str, Any]], str]:
    return parse_saved_markdown_structure(text)


def _saved_frozen_context_refusal(
        artifact: Dict[str, Any], frozen: Any) -> str:
    """Record, domain, language and type from fields the frozen object has.

    The frozen contract has no owner field. This check does not invent one.
    """
    claim = artifact.get(SAVED_DOCX_FIDELITY_KEY) or {}
    from release_engine_v3.domain_codes import normalize_domain_code
    domain_code = normalize_domain_code(
        str(getattr(frozen, 'domain', '') or ''), default='')
    if domain_code != 'dt':
        return 'saved_docx_fidelity_refused:frozen_domain'
    language = str(getattr(frozen, 'language', '') or '').strip().lower()
    if not language.startswith('ar'):
        return 'saved_docx_fidelity_refused:frozen_language'
    document_type = str(
        getattr(frozen, 'document_type', '') or '').strip().lower()
    if document_type != 'strategy':
        return 'saved_docx_fidelity_refused:frozen_document_type'
    record_id = _saved_docx_positive_int(claim.get('record_id'))
    frozen_record = _saved_docx_positive_int(getattr(frozen, 'strategy_id', None))
    if frozen_record is None:
        frozen_record = _saved_docx_positive_int(
            getattr(frozen, 'artifact_id', None))
    if record_id is None or frozen_record is None or frozen_record != record_id:
        return 'saved_docx_fidelity_refused:frozen_record'
    return ''


def _saved_canonical_render_signature(frozen: Any) -> Tuple[Optional[Tuple[Any, ...]], str]:
    """Signature of the markdown the strategy render tree would draw.

    This follows the unchanged render order and section_to_markdown. It does
    not treat a legacy-string match as proof that the canonical tables match.
    """
    sections = getattr(frozen, 'canonical_sections', None)
    if not isinstance(sections, dict) or not sections:
        return None, 'saved_docx_fidelity_refused:frozen_canonical_unavailable'
    rendered_blocks: List[Dict[str, Any]] = []
    saw_section = False
    for key in _SAVED_CANONICAL_RENDER_ORDER:
        section = sections.get(key)
        if section is None:
            continue
        saw_section = True
        try:
            rendered = section_to_markdown(section)
        except Exception:  # noqa: BLE001
            return None, 'saved_docx_fidelity_refused:frozen_canonical_unavailable'
        if not str(rendered or '').strip():
            continue
        blocks, error = _saved_structure_blocks(rendered)
        if error:
            return None, 'saved_docx_fidelity_refused:frozen_canonical_differs'
        rendered_blocks.extend(blocks)
    if not saw_section:
        return None, 'saved_docx_fidelity_refused:frozen_canonical_unavailable'
    return saved_markdown_signature(rendered_blocks), ''


def _saved_snapshot_signature(artifact: Dict[str, Any]) -> Tuple[Optional[Tuple[Any, ...]], str]:
    strings = saved_docx_section_strings(artifact.get('sections'))
    combined: List[Dict[str, Any]] = []
    for key in SAVED_DOCX_REQUIRED_SECTIONS:
        blocks, error = _saved_structure_blocks(strings.get(key) or '')
        if error:
            return None, error
        combined.extend(blocks)
    return saved_markdown_signature(combined), ''


def saved_frozen_source_refusal(artifact: Optional[Dict[str, Any]], frozen: Any) -> str:
    """Refuse a preloaded frozen artifact that is not this saved source.

    Legacy strings and the canonical rendering are both required. A legacy
    match with a different canonical table is frozen_canonical_differs.
    """
    fidelity = evaluate_saved_docx_fidelity(artifact)
    if not fidelity:
        return ''
    if fidelity.startswith('saved_docx_fidelity_refused'):
        return fidelity
    if not isinstance(artifact, dict):
        return 'saved_docx_fidelity_refused:malformed_context'
    context_error = _saved_frozen_context_refusal(artifact, frozen)
    if context_error:
        return context_error
    frozen_sections = getattr(frozen, 'legacy_sections', None) or {}
    frozen_markdown = getattr(frozen, 'final_markdown_view', '') or ''
    section_error = saved_body_sections_consistency(
        artifact.get('final_markdown'),
        artifact.get('sections'))
    if section_error:
        return section_error
    frozen_error = saved_body_sections_consistency(
        frozen_markdown, frozen_sections)
    if frozen_error:
        return 'saved_docx_fidelity_refused:frozen_source_differs'
    art_blocks, _art_err = parse_saved_markdown_structure(
        artifact.get('final_markdown'))
    frozen_blocks, _frozen_err = parse_saved_markdown_structure(frozen_markdown)
    if saved_markdown_signature(art_blocks) != saved_markdown_signature(frozen_blocks):
        return 'saved_docx_fidelity_refused:frozen_source_differs'
    rendered_signature, rendered_error = _saved_canonical_render_signature(frozen)
    if rendered_error:
        return rendered_error
    snapshot_signature, snapshot_error = _saved_snapshot_signature(artifact)
    if snapshot_error:
        return snapshot_error
    if rendered_signature != snapshot_signature:
        return 'saved_docx_fidelity_refused:frozen_canonical_differs'
    return ''


def evaluate_saved_docx_fidelity(artifact: Optional[Dict[str, Any]]) -> str:
    """Return '' , 'preserve', or a saved_docx_fidelity_refused code.

    '' means this export is not the server-accepted saved DOCX path.
    A claim is read only from the artifact field created after binder
    acceptance. contract_meta and request JSON are not a claim.
    """
    if not isinstance(artifact, dict) or SAVED_DOCX_FIDELITY_KEY not in artifact:
        return ''
    claim = artifact.get(SAVED_DOCX_FIDELITY_KEY)
    if not isinstance(claim, dict):
        return 'saved_docx_fidelity_refused:malformed_context'
    if claim.get('route') != 'docx':
        return 'saved_docx_fidelity_refused:route'
    if claim.get('domain_code') != 'dt':
        return 'saved_docx_fidelity_refused:domain'
    if claim.get('language_code') != 'ar':
        return 'saved_docx_fidelity_refused:language'
    if claim.get('document_type') != 'strategy':
        return 'saved_docx_fidelity_refused:document_type'
    record_id = _saved_docx_positive_int(claim.get('record_id'))
    owner_id = _saved_docx_positive_int(claim.get('owner_id'))
    artifact_record = _saved_docx_positive_int(
        artifact.get('strategy_id') or artifact.get('artifact_id'))
    artifact_owner = _saved_docx_positive_int(
        artifact.get('_rel32_export_user_id'))
    if (
            record_id is None or owner_id is None
            or artifact_record != record_id or artifact_owner != owner_id):
        return 'saved_docx_fidelity_refused:identity'
    sections = saved_docx_section_strings(artifact.get('sections'))
    for key in SAVED_DOCX_REQUIRED_SECTIONS:
        if not str(sections.get(key) or '').strip():
            return f'saved_docx_fidelity_refused:section_missing:{key}'
    content = artifact.get('final_markdown')
    if not isinstance(content, str) or not content.strip():
        return 'saved_docx_fidelity_refused:content_missing'
    if saved_docx_content_digest(content) != str(claim.get('content_sha256') or ''):
        return 'saved_docx_fidelity_refused:content_digest'
    if saved_docx_section_digest(sections) != str(claim.get('sections_sha256') or ''):
        return 'saved_docx_fidelity_refused:sections_digest'
    consistency = saved_body_sections_consistency(
        content, artifact.get('sections'))
    if consistency:
        return consistency
    return 'preserve'


def _artifact_id_from(legacy: Dict[str, Any]) -> str:
    aid = (
        str(legacy.get('artifact_id') or '')
        or str(legacy.get('strategy_id') or '')
        or str(legacy.get('task_id') or '')
    )
    if aid:
        return aid
    fh = legacy.get('final_hash') or ''
    if fh:
        return f'hash-{fh[:16]}'
    return f'rel3-{uuid.uuid4().hex[:12]}'


# REL3.3 — forbidden strategy heading markers used to assert the final risk
# markdown carries no strategy sections (defense-in-depth reporting only).
_FA_FORBIDDEN_STRATEGY_HEADING_MARKERS = (
    'الرؤية', 'الأهداف الاستراتيجية', 'الاهداف الاستراتيجية',
    'الركائز الاستراتيجية', 'خارطة الطريق', 'خريطة الطريق',
    'مصفوفة التتبع', 'مصفوفة تتبع', 'نموذج الحوكمة',
    'مؤشرات الأداء الرئيسية', 'المواءمة الاستراتيجية',
    'المبادرات الاستراتيجية', 'strategic objectives', 'strategic pillars',
    'roadmap', 'traceability matrix', 'governance model', 'strategic vision',
)


def _fa_forbidden_headings_in(markdown: str) -> List[str]:
    hits: List[str] = []
    for ln in str(markdown or '').splitlines():
        s = ln.strip()
        if not s.startswith('##'):
            continue
        h = s.lstrip('#').strip().lower()
        for m in _FA_FORBIDDEN_STRATEGY_HEADING_MARKERS:
            if m.lower() in h:
                hits.append(s.lstrip('#').strip())
                break
    return list(dict.fromkeys(hits))


def _emit_rel33_final_artifact_document_type_diag(
        *,
        document_type: str,
        artifact_type: str,
        domain: str,
        risk_id: str,
        legacy_sections: Dict[str, Any],
        markdown_view: str,
        markdown_view_source: str,
        strategy_fallback_considered: bool,
        strategy_fallback_applied: bool,
        strategy_fallback_skipped_reason: str,
        risk_native_fallback_applied: bool,
        risk_native_fallback_source: str,
        blocking_errors: List[str],
) -> None:
    """Emit [REL33-FINAL-ARTIFACT-DOCUMENT-TYPE-DIAG] (never alters output)."""
    import json as _json_fa
    keys = [str(k) for k in (legacy_sections or {}).keys()
            if not str(k).startswith('_')]
    forbidden = _fa_forbidden_headings_in(markdown_view)
    final_heads = [
        ln.strip().lstrip('#').strip()
        for ln in str(markdown_view or '').splitlines()
        if ln.strip().startswith('##')]
    diag = {
        'tag': '[REL33-FINAL-ARTIFACT-DOCUMENT-TYPE-DIAG]',
        'route': 'build_final_document_artifact',
        'output_type': 'final_artifact',
        'domain': str(domain or ''),
        'document_type': str(document_type or ''),
        'artifact_type': str(artifact_type or ''),
        'risk_id': str(risk_id or ''),
        'legacy_sections_count': len(keys),
        'legacy_sections_keys': keys,
        'markdown_view_source': str(markdown_view_source or ''),
        'strategy_fallback_considered': bool(strategy_fallback_considered),
        'strategy_fallback_applied': bool(strategy_fallback_applied),
        'strategy_fallback_skipped_reason': str(
            strategy_fallback_skipped_reason or ''),
        'risk_native_fallback_applied': bool(risk_native_fallback_applied),
        'risk_native_fallback_source': str(risk_native_fallback_source or ''),
        'final_markdown_hash': hashlib.sha256(
            str(markdown_view or '').encode('utf-8')).hexdigest()[:16],
        'final_heading_keys': final_heads,
        'forbidden_strategy_headings_in_final': forbidden,
        'blocking_errors': list(blocking_errors or []),
        'passed': not forbidden and not blocking_errors,
    }
    try:
        print('[REL33-FINAL-ARTIFACT-DOCUMENT-TYPE-DIAG] '
              + _json_fa.dumps(diag, ensure_ascii=False, default=str),
              flush=True)
    except Exception:  # noqa: BLE001
        pass


def _legacy_to_canonical_sections(
        legacy_sections: Dict[str, str],
        *,
        lang: str = 'ar',
        domain: str = 'cyber',
        backend: Optional[Dict[str, Any]] = None,
        document_type: str = 'strategy',
        route: str = '',
        phase: str = 'freeze',
        preserve_saved: bool = False,
) -> Tuple[Dict[str, CanonicalSection], Dict[str, str], List[str]]:
    """Build canonical sections. REL3.3 document-type compiler authority:

    the REL32 strategy compiler (which synthesizes vision/pillars/environment/
    roadmap/kpis) runs ONLY for document_type=strategy. Risk/gap artifacts are
    compiled from their native sections and never synthesized into a strategy.
    If the strategy compiler is somehow attempted for a non-strategy artifact
    it fails closed with ``rel33_wrong_compiler_for_document_type:<dtype>``.
    """
    from release_engine_v3.rel33_domain_guard import (
        emit_rel33_document_type_compiler_authority,
        select_rel33_compiler,
    )
    sections_src = dict(legacy_sections)
    dtype = str(document_type or 'strategy').strip().lower()
    is_risk = dtype in ('risk', 'risk_assessment')
    compiler_selected = select_rel33_compiler(dtype)
    authority_blockers: List[str] = []
    strategy_compiler_attempted = False
    strategy_compiler_blocked = False
    synthetic_sections_created = False
    native_present = sorted(
        str(k) for k, v in sections_src.items()
        if not str(k).startswith('_') and str(v or '').strip())
    try:
        from release_engine_v3.rel32_compiler import (
            compile_canonical_strategy_document,
            is_rel32_compiler_first,
        )
        flags = (backend or {}).get('flags') or {}
        if is_risk:
            # REL3.3 P0 — a risk artifact must NEVER be compiled as a strategy
            # (that synthesizes vision/pillars/environment/roadmap/kpis and
            # contaminates the risk document). Select the risk-native authority
            # and never invoke the strategy compiler. compile_canonical_strategy_document
            # itself fails closed if it is ever reached with a risk document_type.
            compiler_selected = 'risk_native'
        elif preserve_saved:
            # Saved DOCX fidelity: keep the accepted section text. The
            # strategy compiler would replace objectives, initiatives, KPI
            # rows and roadmap rows with registry content.
            compiler_selected = 'saved_docx_fidelity'
        else:
            # Preserve existing strategy/gap behavior exactly: the compiler
            # authority is decided as before (strategy-shaped) for non-risk.
            if is_rel32_compiler_first(domain=domain, lang=lang, flags=flags):
                strategy_compiler_attempted = True
                compiled = compile_canonical_strategy_document(
                    sections_src,
                    request_context={
                        'lang': lang,
                        'domain': domain,
                        'backend': backend or {},
                    },
                )
                if compiled.legacy_sections:
                    sections_src = dict(compiled.legacy_sections)
                    synthetic_sections_created = True
    except Exception:  # noqa: BLE001
        pass
    emit_rel33_document_type_compiler_authority({
        'route': str(route or ''),
        'domain': str(domain or ''),
        'artifact_type': dtype,
        'document_type': dtype,
        'phase': str(phase or ''),
        'compiler_selected': compiler_selected,
        'compiler_requested': 'strategy' if strategy_compiler_attempted else compiler_selected,
        'compiler_allowed': not strategy_compiler_blocked,
        'freeze_authority': compiler_selected,
        'strategy_compiler_attempted': strategy_compiler_attempted,
        'strategy_compiler_blocked': strategy_compiler_blocked,
        'native_sections_present': native_present,
        'synthetic_strategy_sections_created': synthetic_sections_created,
        'blocking_errors': list(authority_blockers),
    })
    if preserve_saved:
        # Do not parse through build_strategy_document. Its table parser
        # keeps a source header as a data row, and the later markdown
        # renderer then invents a replacement header.
        return (
            saved_source_canonical_sections(sections_src),
            sections_src,
            authority_blockers,
        )
    doc = build_strategy_document(sections_src)
    sections = doc.as_dict()
    raw_kpi = (
        sections_src.get('kpis')
        or sections_src.get('kpi_kri')
        or '')
    if raw_kpi:
        sections['kpi_kri'] = enrich_kpi_section(
            sections['kpi_kri'], raw_kpi)
    raw_trace = (
        sections_src.get('traceability')
        or sections_src.get('traceability_matrix')
        or '')
    if raw_trace:
        sections['traceability'] = enrich_traceability_section(
            sections['traceability'], raw_trace)
    return sections, sections_src, authority_blockers


def _scrub_legacy_sections_arabic(
        sections: Dict[str, str], lang: str) -> Dict[str, str]:
    """Pre-scrub Arabic glue before canonical quality validation."""
    if str(lang or '').lower().startswith('en'):
        return sections
    from release_engine.arabic_language_gate import (
        apply_arabic_final_gate,
        repair_arabic_canonical_text_before_freeze,
    )
    from release_engine.rendered_evidence_validator import _repair_arabic_blob
    out = {
        k: _repair_arabic_blob(v)
        if isinstance(v, str) and not str(k).startswith('_') else v
        for k, v in sections.items()}
    out, _ = apply_arabic_final_gate(out, lang=lang)
    out, _ = repair_arabic_canonical_text_before_freeze(out, lang=lang)
    return out


def build_final_document_artifact(
        legacy_artifact: Dict[str, Any],
        *,
        freeze: bool = False,
        strategy_id: str = '',
) -> FinalDocumentArtifact:
    """Build FinalDocumentArtifact from post-REL2 legacy artifact dict."""
    legacy_sections = dict(legacy_artifact.get('sections') or {})
    if not legacy_sections:
        cj = legacy_artifact.get('content_json') or {}
        if isinstance(cj, dict):
            legacy_sections = dict(cj.get('sections') or {})
    meta = legacy_artifact.get('contract_meta') or {}
    fws = list(
        meta.get('selected_frameworks')
        or legacy_artifact.get('selected_frameworks')
        or [])
    # REL3.3 P0 — never rebrand a blank-domain artifact as Cyber. Blank
    # stays blank; the canonical artifact then carries a blocking error so
    # exports fail closed instead of rendering Cyber content.
    try:
        from release_engine_v3.domain_codes import normalize_domain_code
        domain = normalize_domain_code(
            str(
                legacy_artifact.get('domain')
                or meta.get('domain')
                or ''),
            default='')
    except Exception:  # noqa: BLE001
        domain = str(
            legacy_artifact.get('domain')
            or meta.get('domain')
            or '')
    lang = meta.get('lang') or legacy_artifact.get('language') or 'ar'
    document_type = str(
        meta.get('document_type')
        or legacy_artifact.get('document_type')
        or legacy_sections.get('_document_type')
        or 'strategy').strip().lower()
    backend = dict(legacy_artifact.get('_rel32_backend') or {})
    backend.setdefault('flags', {
        'rel3': True,
        'rel31': True,
        'rel32': True,
    })
    backend.setdefault('selected_frameworks', fws)
    backend.setdefault('lang', lang)
    # REL3.3 — document-type-aware content propagation. For a risk artifact the
    # authoritative build must carry the COMPILED risk-native markdown. When the
    # legacy sections arrive empty (e.g. a frozen/authoritative build that lost
    # the section map), derive risk-native sections from the compiled
    # ``final_markdown`` so the artifact renders compiled risk content — never a
    # synthesized strategy document.
    _dtype_risk = str(document_type or '').strip().lower() in (
        'risk', 'risk_assessment')
    _compiled_md = str(legacy_artifact.get('final_markdown') or '').strip()
    _risk_secs_present = any(
        (not str(k).startswith('_')) and str(v).strip()
        for k, v in legacy_sections.items())
    if _dtype_risk and _compiled_md and not _risk_secs_present:
        try:
            from release_engine_v3.rel33_risk_artifact import (
                _split_risk_markdown as _split_risk_md_fa,
                normalize_risk_export_sections as _norm_risk_secs_fa,
            )
            legacy_sections = _norm_risk_secs_fa(
                _split_risk_md_fa(_compiled_md))
            _risk_secs_present = any(
                (not str(k).startswith('_')) and str(v).strip()
                for k, v in legacy_sections.items())
        except Exception:  # noqa: BLE001
            pass
    fidelity = evaluate_saved_docx_fidelity(legacy_artifact)
    preserve_saved = fidelity == 'preserve'
    fidelity_refused = fidelity.startswith('saved_docx_fidelity_refused')
    # Refusal keeps the accepted text too. The compiler must not invent a
    # replacement document for a claim that is about to be blocked.
    keep_saved_source = preserve_saved or fidelity_refused
    canon_map, legacy_sections, _authority_blockers = _legacy_to_canonical_sections(
        legacy_sections, lang=lang, domain=domain, backend=backend,
        document_type=document_type, phase='build_final_document_artifact',
        preserve_saved=keep_saved_source)
    canon_hash = compute_canonical_hash(canon_map)
    if not keep_saved_source:
        legacy_sections = _scrub_legacy_sections_arabic(legacy_sections, lang)
    blockers = list(legacy_artifact.get('blocking_errors') or [])
    blockers.extend(_authority_blockers)
    if fidelity_refused:
        blockers.append(fidelity)
    if not str(domain or '').strip() and document_type == 'strategy':
        blockers.append('rel33_export_domain_missing:canonical_artifact')
    quality = validate_canonical_quality(
        canon_map,
        legacy_sections=legacy_sections,
        domain=domain,
        lang=lang,
        document_type=document_type,
    )
    blockers.extend(quality.get('blocking_errors') or [])
    rel2 = ((legacy_artifact.get('diagnostics') or {}).get('rel2') or {})
    rel28 = rel2.get('rel28') or {}
    release_ready = bool(
        rel28.get('finalize_route', {}).get('export_return_allowed')
        if rel28 else not blockers)
    if blockers:
        release_ready = False
    aid = _artifact_id_from({**legacy_artifact, 'strategy_id': strategy_id})
    legacy_join = '\n\n'.join(
        str(v).strip()
        for k, v in legacy_sections.items()
        if isinstance(v, str) and v.strip() and not str(k).startswith('_'))
    # ── REL3.3 — final-artifact markdown_view is document_type-aware ──
    # The strategy-document fallback (build_strategy_document → synthesizes
    # vision/objectives/pillars/roadmap/KPI/governance/traceability) must NEVER
    # run for a risk artifact. For risk: use the compiled/risk-native markdown,
    # or fail closed — never synthesize a strategy document.
    _artifact_type = str(
        legacy_artifact.get('artifact_type')
        or meta.get('artifact_type') or '').strip().lower()
    _is_risk_final = _dtype_risk or _artifact_type in (
        'risk', 'risk_assessment')
    _fa_strategy_fallback_considered = False
    _fa_strategy_fallback_applied = False
    _fa_strategy_fallback_skipped_reason = ''
    _fa_risk_native_fallback_applied = False
    _fa_risk_native_fallback_source = ''
    if preserve_saved:
        md_view = legacy_artifact['final_markdown']
        _fa_md_source = 'validated_saved_markdown'
    elif _is_risk_final:
        _fa_strategy_fallback_skipped_reason = 'document_type_risk'
        # Prefer the COMPILED risk markdown directly — it preserves every
        # risk-native table (register/treatments/KRI). Reconstructing from the
        # slugified sections is lossy (the risk splitter collapses multiple
        # ``مخاطر`` headings onto one ``register`` key), which would drop the
        # register table from the exported bytes.
        if _compiled_md:
            md_view = _compiled_md
            _fa_md_source = 'compiled_risk_content'
            _fa_risk_native_fallback_applied = True
            _fa_risk_native_fallback_source = 'final_markdown'
        elif legacy_join:
            md_view = legacy_join
            _fa_md_source = 'risk_native_sections'
            _fa_risk_native_fallback_applied = True
            _fa_risk_native_fallback_source = 'legacy_sections'
        else:
            md_view = ''
            _fa_md_source = 'none'
            blockers.append('rel33_risk_artifact_empty_sections')
    else:
        if legacy_join:
            md_view = legacy_join
            _fa_md_source = 'legacy_sections'
        else:
            _fa_strategy_fallback_considered = True
            _fa_strategy_fallback_applied = True
            md_view = strategy_document_to_markdown(
                build_strategy_document(legacy_sections))
            _fa_md_source = 'strategy_document_builder'
    _emit_rel33_final_artifact_document_type_diag(
        document_type=document_type,
        artifact_type=_artifact_type,
        domain=domain,
        risk_id=str(legacy_artifact.get('risk_id')
                    or legacy_artifact.get('artifact_id') or ''),
        legacy_sections=legacy_sections,
        markdown_view=md_view,
        markdown_view_source=_fa_md_source,
        strategy_fallback_considered=_fa_strategy_fallback_considered,
        strategy_fallback_applied=_fa_strategy_fallback_applied,
        strategy_fallback_skipped_reason=_fa_strategy_fallback_skipped_reason,
        risk_native_fallback_applied=_fa_risk_native_fallback_applied,
        risk_native_fallback_source=_fa_risk_native_fallback_source,
        blocking_errors=list(dict.fromkeys(blockers)),
    )
    artifact = FinalDocumentArtifact(
        artifact_id=aid,
        strategy_id=strategy_id or aid,
        domain=str(domain or ''),
        language='ar' if str(lang).lower().startswith('ar') else 'en',
        document_type=document_type,
        strategy_type=str(
            meta.get('doc_subtype') or legacy_artifact.get('strategy_type')
            or 'technical'),
        selected_frameworks=fws,
        canonical_sections=canon_map,
        quality_repairs=list(legacy_artifact.get('repair_actions') or []),
        quality_results=quality,
        frozen=bool(freeze and not blockers),
        canonical_hash=canon_hash,
        render_tree_hash='',
        export_manifest=ExportManifest(canonical_hash=canon_hash),
        blocking_errors=list(dict.fromkeys(blockers)),
        release_ready_final_passed=release_ready and not blockers,
        legacy_sections=legacy_sections,
        final_markdown_view=md_view,
    )
    return artifact


def freeze_artifact(artifact: FinalDocumentArtifact) -> FinalDocumentArtifact:
    if artifact.frozen:
        return artifact
    if artifact.blocking_errors:
        artifact.frozen = False
        return artifact
    artifact.frozen = True
    _ARTIFACT_REGISTRY[artifact.artifact_id] = artifact
    if artifact.strategy_id and artifact.strategy_id != artifact.artifact_id:
        _ARTIFACT_REGISTRY[artifact.strategy_id] = artifact
    return artifact


def get_frozen_artifact(
        artifact_or_id: Any,
        *,
        backend: Optional[Dict[str, Any]] = None) -> FinalDocumentArtifact:
    """Resolve frozen artifact by id or dict."""
    if isinstance(artifact_or_id, FinalDocumentArtifact):
        if not artifact_or_id.frozen:
            return freeze_artifact(artifact_or_id)
        return artifact_or_id
    if isinstance(artifact_or_id, dict):
        if artifact_or_id.get('_rel32_persisted_frozen'):
            from release_engine_v3.rel32_frozen_artifact_persist import (
                rehydrate_frozen_from_persisted_dict,
            )
            return rehydrate_frozen_from_persisted_dict(artifact_or_id)
        sealed = bool(artifact_or_id.get('sealed'))
        art = build_final_document_artifact(
            artifact_or_id,
            freeze=sealed,
            strategy_id=str(artifact_or_id.get('strategy_id') or ''),
        )
        if sealed and not art.blocking_errors:
            return freeze_artifact(art)
        if art.frozen:
            return art
        return freeze_artifact(art) if not art.blocking_errors else art
    key = str(artifact_or_id or '')
    if key in _ARTIFACT_REGISTRY:
        return _ARTIFACT_REGISTRY[key]
    if backend and backend.get('load_artifact'):
        loaded = backend['load_artifact'](key)
        if isinstance(loaded, dict):
            return get_frozen_artifact(loaded, backend=backend)
    raise KeyError(f'rel3_frozen_artifact_not_found:{key}')


def guard_post_seal_mutation(
        artifact: FinalDocumentArtifact,
        section_key: str,
        *,
        operation: str = 'mutate') -> Optional[str]:
    if not artifact.frozen:
        return None
    return f'rel3_post_seal_mutation_blocked:{section_key}:{operation}'


def store_artifact(artifact: FinalDocumentArtifact) -> None:
    _ARTIFACT_REGISTRY[artifact.artifact_id] = artifact
    if artifact.strategy_id:
        _ARTIFACT_REGISTRY[artifact.strategy_id] = artifact


def clear_artifact_registry() -> None:
    _ARTIFACT_REGISTRY.clear()
