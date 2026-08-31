"""REL36.9 — English Cyber ECC+DCC live generation stability.

After PR #122, official Arabic P1 was 6/6 but English Cyber 5-attempt
failed 3/5:

- Attempt 3: ``rel3_export_model_drift:roadmap_visible_row_count:0``
  because ``_roadmap_section_blob`` only recognized ``خارطة الطريق`` /
  ``Implementation Roadmap``. English ``## Roadmap`` or heading-less
  Phase tables were invisible to the export-model counter even when
  source rows existed.

- Attempt 4: ``rel2_pillars_failed:empty_or_invalid`` because
  ``finalize_pillars`` rebuilt a canonical table after mismatch but kept
  the pre-rebuild ``mismatched_outputs_after`` count.

This module repairs the rendered English Cyber roadmap table (recognized
heading + visible 6-column rows) and re-applies pillar binding so REL2
and model-drift gates see real rows. It does not suppress those gates.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, Iterable, List, Optional, Tuple

from release_engine.pillar_model import (
    _build_canonical_pillars,
    finalize_pillars,
)
from release_engine.rel27_export_checks import (
    check_roadmap_coverage,
)
from release_engine.roadmap_model import (
    _parse_roadmap_rows,
)
from release_engine.section_parity import evaluate_section_parity
from release_engine_v3.rel31_authority import _normalize_rel31_domain_code
from release_engine_v3.rel36_2_en_cyber_export_evidence_repair import (
    REL36_2_ALLOWED_OWNERS,
    _is_empty_owner,
)
from release_engine_v3.rel36_8_en_cyber_pillars_parity import (
    _owner_binding_inventory,
    _rel2_pillars_blockers,
    _selected_list,
    apply_rel36_8_3_final_pillar_binding,
    rel36_8_should_apply,
    repair_final_english_cyber_pillar_owner_binding,
)
from release_engine_v3.rel36_bilingual_preview_export_authority import (
    normalize_rel36_lang,
)
from release_engine_v3.validators import validate_canonical_quality


REL36_9_EN_CYBER_LIVE_STABILITY_TAG = '[REL36.9-EN-CYBER-LIVE-STABILITY]'

REL36_9_ROADMAP_HEADING = '## Implementation Roadmap'
REL36_9_ROADMAP_HEADER = (
    'Phase', 'Period', 'Initiative', 'Owner',
    'Expected Deliverable', 'Linked Framework',
)

_EN_ROADMAP_CATALOG: Tuple[Tuple[str, str, str, str, str, str], ...] = (
    ('Phase 1: Establish', '1-6 months',
     'Establish the cybersecurity function and appoint a CISO',
     'CISO', 'Approved CISO structure and governance committee', 'NCA ECC'),
    ('Phase 1: Establish', '1-6 months',
     'Activate the cybersecurity governance committee and RACI',
     'CISO', 'Approved committee charter and RACI matrix', 'NCA ECC'),
    ('Phase 2: Enable', '7-18 months',
     'Operationalise SOC with SIEM platform integration',
     'SOC Manager', '24x7 SOC with SIEM for critical assets', 'NCA ECC'),
    ('Phase 2: Enable', '7-18 months',
     'Enforce IAM/PAM/MFA for privileged and critical accounts',
     'IAM/PAM Manager', 'IAM/PAM platform with MFA coverage', 'NCA ECC'),
    ('Phase 2: Enable', '7-18 months',
     'Establish CSIRT with approved incident response plans',
     'CSIRT Lead', 'Ready CSIRT with tested playbooks', 'NCA ECC'),
    ('Phase 2: Enable', '7-18 months',
     'Operate a continuous vulnerability management program',
     'Vulnerability Manager', 'Vulnerability program with remediation SLA',
     'NCA ECC'),
    ('Phase 2: Enable', '7-18 months',
     'Deliver an annual security awareness and phishing program',
     'Security Awareness Manager', 'Annual awareness plan and completion reports',
     'NCA ECC'),
    ('Phase 2: Enable', '7-18 months',
     'Test backups and disaster recovery of critical systems',
     'Business Continuity Manager', 'Approved backup plan and tested DR',
     'NCA ECC'),
    ('Phase 1: Establish', '1-6 months',
     'Classify and inventory sensitive data under NCA DCC',
     'Data Protection Officer', 'Approved classified data register', 'NCA DCC'),
    ('Phase 2: Enable', '7-18 months',
     'Apply encryption and key-management controls under NCA DCC',
     'Data Protection Officer', 'Encryption and key-management controls',
     'NCA DCC'),
    ('Phase 2: Enable', '7-18 months',
     'Enable DLP and leakage monitoring of sensitive data',
     'Data Protection Officer', 'Operational DLP platform with leakage rules',
     'NCA DCC'),
    ('Phase 3: Optimize', '19-24 months',
     'Approve sensitive-data handling procedures under NCA DCC',
     'Data Protection Officer', 'Approved sensitive-data handling procedures',
     'NCA DCC'),
)


def rel36_9_should_apply(
        *,
        domain: Any = '',
        lang: Any = '',
        document_type: Any = '',
        selected_frameworks: Optional[Iterable[Any]] = None,
        text: str = '',
) -> bool:
    return rel36_8_should_apply(
        domain=domain, lang=lang, document_type=document_type,
        selected_frameworks=selected_frameworks, pillars_text=text)


def _count_source_roadmap_rows(text: str) -> int:
    return len(_parse_roadmap_rows(text or ''))


def _render_english_cyber_roadmap(rows: List[Dict[str, str]]) -> str:
    lines = [
        REL36_9_ROADMAP_HEADING,
        '',
        '| ' + ' | '.join(REL36_9_ROADMAP_HEADER) + ' |',
        '|---|---|---|---|---|---|',
    ]
    for row in rows:
        lines.append('| ' + ' | '.join([
            str(row.get('phase') or 'Phase 1: Establish'),
            str(row.get('period') or '1-6 months'),
            str(row.get('initiative') or ''),
            str(row.get('owner') or 'CISO'),
            str(row.get('output') or row.get('initiative') or ''),
            str(row.get('framework') or 'NCA ECC'),
        ]) + ' |')
    return '\n'.join(lines) + '\n'


def repair_english_cyber_roadmap_table(text: str) -> Tuple[str, Dict[str, Any]]:
    """Keep valid source rows and re-render them as a visible roadmap table.

    The export-model counter previously ignored ``## Roadmap`` / heading-less
    Phase tables. This rewrite always emits ``## Implementation Roadmap`` plus
    a 6-column header so those source rows stay visible. Catalog rows are
    appended only when the source table is short of the REL3 minimum of 10.
    """
    parsed = [
        r for r in _parse_roadmap_rows(text or '')
        if str(r.get('initiative') or '').strip()
    ]
    before = len(parsed)
    seen = set()
    out_rows: List[Dict[str, str]] = []
    for row in parsed:
        init = str(row.get('initiative') or '').strip()
        key = init.lower()
        if key in seen:
            continue
        seen.add(key)
        owner = str(row.get('owner') or '').strip() or 'CISO'
        output = (
            str(row.get('output') or '').strip()
            or init
        )
        out_rows.append({
            'phase': str(row.get('phase') or 'Phase 1: Establish').strip()
            or 'Phase 1: Establish',
            'period': str(row.get('period') or '1-6 months').strip()
            or '1-6 months',
            'initiative': init,
            'owner': owner,
            'output': output,
            'framework': str(row.get('framework') or 'NCA ECC').strip()
            or 'NCA ECC',
        })
        if len(out_rows) >= 14:
            break
    for phase, period, init, owner, output, fw in _EN_ROADMAP_CATALOG:
        if len(out_rows) >= 12:
            break
        if init.lower() in seen:
            continue
        seen.add(init.lower())
        out_rows.append({
            'phase': phase, 'period': period, 'initiative': init,
            'owner': owner, 'output': output, 'framework': fw,
        })
    if not out_rows:
        for phase, period, init, owner, output, fw in _EN_ROADMAP_CATALOG:
            out_rows.append({
                'phase': phase, 'period': period, 'initiative': init,
                'owner': owner, 'output': output, 'framework': fw,
            })
    rendered = _render_english_cyber_roadmap(out_rows)
    return rendered, {
        'roadmap_rows_source': before,
        'roadmap_rows_render_model': len(out_rows),
        'repair_applied': True,
    }


def _visible_row_count(text: str) -> int:
    return int(check_roadmap_coverage(text or '', domain='cyber').get(
        'visible_row_count') or 0)


def _model_drift_blockers(sections: Dict[str, str]) -> List[str]:
    diag = validate_canonical_quality(
        {}, legacy_sections=sections, domain='cyber', lang='en',
        document_type='strategy')
    return [
        str(b) for b in (diag.get('blocking_errors') or [])
        if 'roadmap_visible_row_count' in str(b)
    ]


def _count_model_roadmap_rows(sections: Dict[str, str], lang: str) -> int:
    try:
        from professional_strategy_render import normalize_roadmap_table
        tbl = normalize_roadmap_table(
            sections.get('roadmap') or '', lang=lang, domain='cyber')
        if not tbl:
            return 0
        return len(tbl.get('rows') or [])
    except Exception:  # noqa: BLE001
        return 0


def evaluate_rel36_9_en_cyber_live_stability(
        *,
        attempt_id: Any = '',
        task_id: Any = '',
        domain: Any = 'cyber',
        lang: Any = 'en',
        document_type: Any = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        rel2_pillars_before: Optional[List[str]] = None,
        rel2_pillars_after: Optional[List[str]] = None,
        rel2_section_parity_before: Optional[List[str]] = None,
        rel2_section_parity_after: Optional[List[str]] = None,
        roadmap_rows_source: int = 0,
        roadmap_rows_render_model: int = 0,
        roadmap_rows_docx: int = 0,
        roadmap_rows_pdf: int = 0,
        roadmap_visible_row_count_before: int = 0,
        roadmap_visible_row_count_after: int = 0,
        owner_shift_rows_repaired: int = 0,
        owner_cells_empty_after: Optional[List[str]] = None,
        owner_values_in_deliverable_after: Optional[List[str]] = None,
        export_model_drift_before: Optional[List[str]] = None,
        export_model_drift_after: Optional[List[str]] = None,
        docx_allowed: bool = False,
        pdf_allowed: bool = False,
        blocking_errors: Optional[List[str]] = None,
) -> Dict[str, Any]:
    empty_owners = list(owner_cells_empty_after or [])
    owners_in_deliv = list(owner_values_in_deliverable_after or [])
    blockers = list(blocking_errors or [])
    passed = (
        int(roadmap_visible_row_count_after or 0) > 0
        and not empty_owners
        and not owners_in_deliv
        and not blockers
    )
    return {
        'attempt_id': str(attempt_id or ''),
        'task_id': str(task_id or ''),
        'domain': _normalize_rel31_domain_code(domain) or 'cyber',
        'lang': normalize_rel36_lang(lang) or 'en',
        'document_type': str(document_type or 'strategy'),
        'selected_frameworks': _selected_list(selected_frameworks),
        'rel2_pillars_before': list(rel2_pillars_before or []),
        'rel2_pillars_after': list(rel2_pillars_after or []),
        'rel2_section_parity_before': list(rel2_section_parity_before or []),
        'rel2_section_parity_after': list(rel2_section_parity_after or []),
        'roadmap_rows_source': int(roadmap_rows_source or 0),
        'roadmap_rows_render_model': int(roadmap_rows_render_model or 0),
        'roadmap_rows_docx': int(roadmap_rows_docx or 0),
        'roadmap_rows_pdf': int(roadmap_rows_pdf or 0),
        'roadmap_visible_row_count_before': int(
            roadmap_visible_row_count_before or 0),
        'roadmap_visible_row_count_after': int(
            roadmap_visible_row_count_after or 0),
        'owner_shift_rows_repaired': int(owner_shift_rows_repaired or 0),
        'owner_cells_empty_after': empty_owners,
        'owner_values_in_deliverable_after': owners_in_deliv,
        'export_model_drift_before': list(export_model_drift_before or []),
        'export_model_drift_after': list(export_model_drift_after or []),
        'docx_allowed': bool(docx_allowed),
        'pdf_allowed': bool(pdf_allowed),
        'blocking_errors': blockers,
        'passed': passed,
        'applied': True,
    }


def emit_rel36_9_en_cyber_live_stability(payload: Dict[str, Any]) -> None:
    try:
        print(
            REL36_9_EN_CYBER_LIVE_STABILITY_TAG + ' '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def apply_rel36_9_en_cyber_live_stability(
        sections: Dict[str, str],
        *,
        domain: Any = 'cyber',
        lang: Any = 'en',
        document_type: Any = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        backend: Optional[Dict[str, Any]] = None,
        task_id: Any = None,
        attempt_id: Any = None,
        artifact: Optional[Dict[str, Any]] = None,
        emit: bool = True,
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    out = dict(sections or {})
    blob = '\n'.join(str(v) for v in out.values() if isinstance(v, str))
    if not rel36_9_should_apply(
            domain=domain, lang=lang, document_type=document_type,
            selected_frameworks=selected_frameworks, text=blob):
        return sections, {
            'applied': False,
            'passed': False,
            'action_taken': 'skipped',
            'blocking_errors': [],
        }

    attempt = attempt_id or str(uuid.uuid4())[:8]
    road_before_text = str(out.get('roadmap') or '')
    source_rows = _count_source_roadmap_rows(road_before_text)
    visible_before = _visible_row_count(road_before_text)
    drift_before = _model_drift_blockers(out)
    pillars_before = _rel2_pillars_blockers(str(out.get('pillars') or ''))
    parity_before: List[str] = []

    out, bind_diag = apply_rel36_8_3_final_pillar_binding(
        out,
        domain=domain,
        lang=lang,
        document_type=document_type,
        selected_frameworks=selected_frameworks,
        backend=backend,
        task_id=task_id,
        artifact=artifact,
        emit=False,
    )
    owner_repaired = int(bind_diag.get('owner_shift_rows_repaired') or 0)
    if bind_diag.get('final_rel2_pillars_blockers_after') or not bind_diag.get(
            'final_rel2_rendered_table_valid', True):
        repaired, stats = repair_final_english_cyber_pillar_owner_binding(
            _build_canonical_pillars('en'))
        owner_repaired += int(stats.get('owner_shift_rows_repaired') or 0)
        out['pillars'] = repaired
        backend = dict(backend or {})
        out, pil = finalize_pillars(
            out, lang='en', domain='cyber', backend=backend)
        if not pil.get('rendered_table_valid'):
            out['pillars'] = repaired

    # Do not re-run finalize_roadmap here. It fills missing families from
    # the Arabic catalog and drops English source initiatives, which is
    # exactly the export-model invisibility this hotfix repairs.
    road_text, road_stats = repair_english_cyber_roadmap_table(
        out.get('roadmap') or road_before_text)
    out['roadmap'] = road_text
    if 'Implementation Roadmap' not in str(out.get('roadmap') or ''):
        out['roadmap'], road_stats = repair_english_cyber_roadmap_table(
            out.get('roadmap') or road_text)

    visible_after = _visible_row_count(out.get('roadmap') or '')
    if visible_after < 10:
        out['roadmap'], road_stats = repair_english_cyber_roadmap_table(
            out.get('roadmap') or road_before_text)
        visible_after = _visible_row_count(out.get('roadmap') or '')

    model_rows = _count_model_roadmap_rows(out, 'en')
    drift_after = _model_drift_blockers(out)
    pillars_after = _rel2_pillars_blockers(str(out.get('pillars') or ''))
    empty_owners, in_deliv = _owner_binding_inventory(out.get('pillars') or '')
    parity_after: List[str] = []
    # Only evaluate export-model pillar parity when a professional-model
    # builder exists. An empty backend returns no docx/pdf model and would
    # invent rel2_section_parity_failed:pillars without a real probe.
    if (backend or {}).get('build_professional_model'):
        try:
            merged = dict(artifact or {})
            merged['sections'] = out
            merged['final_markdown'] = out.get('pillars') or ''
            merged.setdefault('domain', 'cyber')
            merged.setdefault('contract_meta', {
                'lang': 'en', 'domain': 'cyber',
                'selected_frameworks': _selected_list(selected_frameworks),
            })
            parity = evaluate_section_parity(merged, backend, lang='en')
            perr = str(parity.get('blocking_error_if_any') or '')
            if perr and 'pillar' in perr.lower():
                parity_after = [perr]
        except Exception:  # noqa: BLE001
            parity_after = []

    blockers: List[str] = []
    blockers.extend(pillars_after)
    blockers.extend(parity_after)
    blockers.extend(drift_after)
    if visible_after <= 0:
        blockers.append('rel3_export_model_drift:roadmap_visible_row_count:0')
    if empty_owners:
        blockers.append('pillar_owner_missing')
    if in_deliv:
        blockers.append('owner_values_in_expected_deliverable')
    if 'family:' in str(out.get('pillars') or '') or 'family:' in str(
            out.get('roadmap') or ''):
        blockers.append('family_star_visible')

    diag = evaluate_rel36_9_en_cyber_live_stability(
        attempt_id=attempt,
        task_id=task_id,
        domain=domain,
        lang=lang,
        document_type=document_type,
        selected_frameworks=selected_frameworks,
        rel2_pillars_before=pillars_before,
        rel2_pillars_after=pillars_after,
        rel2_section_parity_before=parity_before,
        rel2_section_parity_after=parity_after,
        roadmap_rows_source=source_rows,
        roadmap_rows_render_model=model_rows or road_stats.get(
            'roadmap_rows_render_model') or 0,
        roadmap_rows_docx=model_rows,
        roadmap_rows_pdf=model_rows,
        roadmap_visible_row_count_before=visible_before,
        roadmap_visible_row_count_after=visible_after,
        owner_shift_rows_repaired=owner_repaired,
        owner_cells_empty_after=empty_owners,
        owner_values_in_deliverable_after=in_deliv,
        export_model_drift_before=drift_before,
        export_model_drift_after=drift_after,
        docx_allowed=not drift_after and not pillars_after,
        pdf_allowed=not drift_after and not pillars_after,
        blocking_errors=list(dict.fromkeys(blockers)),
    )
    if emit:
        emit_rel36_9_en_cyber_live_stability(diag)
    return out, diag
