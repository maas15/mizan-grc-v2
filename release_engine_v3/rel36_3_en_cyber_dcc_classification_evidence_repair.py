"""REL36.3 — English cyber DCC classification export-evidence repair.

English Cyber freeze/export injects the Arabic pillar catalog
(``تصنيف البيانات`` / ``جرد وتصنيف البيانات الحساسة`` next to
``مدير IAM/PAM``). Export evidence then fail-closes on
``traceability_dcc_classification_invalid`` because the Arabic-only
predicate sees ``تصنيف البيانات`` without
``ضعف تصنيف وجرد البيانات الحساسة`` and IAM/PAM is in the 200-char
window.

Bound preview stays English, so the same check is a no-op there.

This repair restores English DCC classification semantics and English
pillar headers/owners before the evidence gate. It does not weaken
``traceability_dcc_classification_invalid``, suppress blockers, or
bypass export evidence.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional, Tuple

from release_engine.rel31_acceptance_checks import (
    check_traceability_dcc_classification_invalid,
)
from release_engine.traceability_substance_model import (
    TRACE_CANONICAL_REGISTRY_EN,
)
from release_engine_v3.rel31_authority import _normalize_rel31_domain_code
from release_engine_v3.rel36_2_en_cyber_export_evidence_repair import (
    REL36_2_PILLAR_HEADER_EN,
    inventory_english_cyber_pillar_rows,
    repair_english_cyber_export_evidence_sections,
)
from release_engine_v3.rel36_bilingual_preview_export_authority import (
    normalize_rel36_lang,
)
from release_engine_v3.rel36_dcc_traceability_en_repair import (
    canonical_english_dcc_row,
    dcc_selected,
    repair_english_dcc_traceability_sections,
)


REL36_3_EN_CYBER_DCC_CLASS_DIAG_TAG = (
    '[REL36.3-EN-CYBER-DCC-CLASSIFICATION-EVIDENCE-REPAIR]')

REL36_3_CLASSIFICATION_TOKENS: Tuple[str, ...] = (
    'Data classification',
    'sensitive data classification and inventory',
    'Classify and inventory sensitive data',
    'Sensitive data classification coverage',
    'Unclassified sensitive data risk',
)

_ARABIC_PILLAR_HEADER = 'المبادرة'
_ARABIC_CLASS_TOKEN = 'تصنيف البيانات'
_ARABIC_CLASS_INITIATIVE = 'جرد وتصنيف البيانات الحساسة'


def _blob(sections: Dict[str, Any]) -> str:
    parts: List[str] = []
    for v in (sections or {}).values():
        if isinstance(v, str):
            parts.append(v)
    return '\n'.join(parts)


def _classification_row(text: str) -> Dict[str, str]:
    spec = TRACE_CANONICAL_REGISTRY_EN['data_classification']
    found = {
        'framework': '',
        'capability': '',
        'gap': '',
        'initiative': '',
        'metric': '',
        'risk': '',
    }
    for ln in str(text or '').splitlines():
        s = ln.strip()
        if not s.startswith('|') or set(s.replace('|', '').replace(':', '')) <= set('- '):
            continue
        cells = [c.strip() for c in s.strip('|').split('|')]
        blob = ' '.join(cells).lower()
        if 'data classification' not in blob and _ARABIC_CLASS_TOKEN not in ln:
            continue
        found = {
            'framework': cells[0] if cells else '',
            'capability': cells[1] if len(cells) > 1 else '',
            'gap': cells[2] if len(cells) > 2 else '',
            'initiative': cells[3] if len(cells) > 3 else '',
            'metric': cells[4] if len(cells) > 4 else '',
            'risk': cells[5] if len(cells) > 5 else '',
        }
        break
    found['expected'] = {
        'framework': spec['framework'],
        'capability': spec['capability'],
        'gap': spec['expected_gap'],
        'initiative': spec['initiative'],
        'metric': spec['metric'],
        'risk': spec['risk'],
    }
    return found


def _classification_tokens_present(text: str) -> List[str]:
    blob = str(text or '')
    return [tok for tok in REL36_3_CLASSIFICATION_TOKENS if tok in blob]


def _pillar_header(text: str) -> List[str]:
    inv = inventory_english_cyber_pillar_rows(text)
    header = list(inv.get('header') or [])
    if header:
        return header
    for ln in str(text or '').splitlines():
        s = ln.strip()
        if not s.startswith('|'):
            continue
        cells = [c.strip() for c in s.strip('|').split('|')]
        blob = ' '.join(cells).lower()
        if any(tok in blob for tok in (
                'initiative', 'description', 'owner',
                'المبادرة', 'الوصف', 'المسؤول')):
            return cells
    return []


def _needs_english_pillar_rebuild(text: str) -> bool:
    blob = str(text or '')
    if _ARABIC_CLASS_INITIATIVE in blob or (
            _ARABIC_CLASS_TOKEN in blob and 'Data classification' not in blob):
        return True
    if _ARABIC_PILLAR_HEADER in blob and 'Owner' not in blob:
        return True
    header = _pillar_header(blob)
    header_blob = ' '.join(header)
    if _ARABIC_PILLAR_HEADER in header_blob and 'Owner' not in header_blob:
        return True
    if header and 'Owner' not in header and 'owner' not in header_blob.lower():
        return True
    return False


def _ensure_classification_row(text: str) -> Tuple[str, bool]:
    row = _classification_row(text)
    spec = TRACE_CANONICAL_REGISTRY_EN['data_classification']
    complete = (
        row.get('capability') == spec['capability']
        and spec['expected_gap'] in (row.get('gap') or '')
        and spec['initiative'] in (row.get('initiative') or '')
        and spec['metric'] in (row.get('metric') or '')
        and spec['risk'] in (row.get('risk') or '')
    )
    if complete:
        return str(text or ''), False
    from release_engine_v3.rel36_dcc_traceability_en_repair import (
        repair_english_dcc_traceability_text,
    )
    repaired, added = repair_english_dcc_traceability_text(text)
    if spec['capability'] not in repaired:
        # Force-append the canonical English classification row.
        canon = canonical_english_dcc_row('data_classification')
        repaired = (
            (repaired.rstrip() + '\n') if repaired.strip() else
            '| Reference Framework | Capability / Control | Related Gap | '
            'Initiative / Activity | Metric | Related Risk |\n'
            '|---|---|---|---|---|---|\n'
        )
        repaired = repaired.rstrip() + '\n| ' + ' | '.join(canon) + ' |\n'
        return repaired, True
    return repaired, bool(added) or repaired != str(text or '')


def repair_english_cyber_dcc_classification_evidence_sections(
        sections: Optional[Dict[str, Any]],
        *,
        lang: str = 'en',
        domain: str = 'cyber',
        document_type: str = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        strategy_id: Any = None,
        export_type: str = '',
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    out = dict(sections or {})
    nlang = normalize_rel36_lang(lang)
    dcode = _normalize_rel31_domain_code(domain) or str(domain or '').strip().lower()
    dtype = str(document_type or 'strategy').strip().lower() or 'strategy'
    selected = [str(x) for x in (selected_frameworks or []) if x]
    before_blob = _blob(out)
    class_before = _classification_row(str(out.get('traceability') or '') or before_blob)
    tokens_before = _classification_tokens_present(
        str(out.get('traceability') or '') or before_blob)
    header_before = _pillar_header(str(out.get('pillars') or ''))
    pred_before = check_traceability_dcc_classification_invalid(before_blob)
    diag: Dict[str, Any] = {
        'tag': 'REL36.3-EN-CYBER-DCC-CLASSIFICATION-EVIDENCE-REPAIR',
        'lang': nlang,
        'domain': dcode,
        'document_type': dtype,
        'selected_frameworks': selected,
        'strategy_id': strategy_id,
        'export_type': export_type,
        'classification_row_before': class_before,
        'classification_row_after': class_before,
        'classification_tokens_before': tokens_before,
        'classification_tokens_after': tokens_before,
        'export_blob_contains_data_classification': (
            'Data classification' in before_blob),
        'export_blob_contains_sensitive_data_classification': (
            'sensitive data classification and inventory' in before_blob),
        'export_blob_contains_classify_and_inventory': (
            'Classify and inventory sensitive data' in before_blob),
        'validator_predicate_before': pred_before,
        'validator_predicate_after': pred_before,
        'pillar_header_before': header_before,
        'pillar_header_after': header_before,
        'repaired': False,
        'blocking_errors': [],
        'passed': False,
    }
    if (
            nlang != 'en'
            or dcode != 'cyber'
            or dtype not in ('strategy', 'strategy_document', '')):
        diag['passed'] = True
        return out, diag

    dcc_on = dcc_selected(selected) or (
        _ARABIC_CLASS_TOKEN in before_blob
        or 'Data classification' in before_blob
        or _ARABIC_CLASS_INITIATIVE in before_blob)

    if _needs_english_pillar_rebuild(str(out.get('pillars') or '')):
        from release_engine.pillar_model import _build_canonical_pillars
        out['pillars'] = _build_canonical_pillars('en')
        diag['repaired'] = True
    out, _own = repair_english_cyber_export_evidence_sections(
        out, lang='en', domain='cyber', document_type=dtype,
        selected_frameworks=selected, strategy_id=strategy_id,
        export_type=export_type)
    if _own.get('repaired'):
        diag['repaired'] = True

    if dcc_on:
        out, _dcc = repair_english_dcc_traceability_sections(
            out, lang='en', domain='cyber',
            selected_frameworks=selected or ['NCA DCC'])
        if _dcc.get('repaired'):
            diag['repaired'] = True
        repaired_trace, class_changed = _ensure_classification_row(
            str(out.get('traceability') or ''))
        if class_changed:
            out['traceability'] = repaired_trace
            diag['repaired'] = True

    after_blob = _blob(out)
    class_after = _classification_row(str(out.get('traceability') or ''))
    tokens_after = _classification_tokens_present(str(out.get('traceability') or ''))
    header_after = _pillar_header(str(out.get('pillars') or ''))
    pred_after = check_traceability_dcc_classification_invalid(after_blob)
    diag['classification_row_after'] = class_after
    diag['classification_tokens_after'] = tokens_after
    diag['export_blob_contains_data_classification'] = (
        'Data classification' in after_blob)
    diag['export_blob_contains_sensitive_data_classification'] = (
        'sensitive data classification and inventory' in after_blob)
    diag['export_blob_contains_classify_and_inventory'] = (
        'Classify and inventory sensitive data' in after_blob)
    diag['validator_predicate_after'] = pred_after
    diag['pillar_header_after'] = header_after
    header_ok = (
        list(header_after[:4]) == list(REL36_2_PILLAR_HEADER_EN)
        or (
            'Initiative' in header_after
            and 'Owner' in header_after
            and _ARABIC_PILLAR_HEADER not in header_after
        )
    )
    class_ok = (not dcc_on) or all(
        tok in (str(out.get('traceability') or '') or after_blob)
        for tok in REL36_3_CLASSIFICATION_TOKENS)
    if pred_after:
        diag['blocking_errors'].extend(pred_after)
    if not header_ok:
        diag['blocking_errors'].append('english_pillar_header_missing_owner')
    if dcc_on and not class_ok:
        diag['blocking_errors'].append('english_dcc_classification_row_incomplete')
    diag['passed'] = not diag['blocking_errors']
    return out, diag


def evaluate_rel36_3_en_cyber_dcc_classification_evidence(
        sections: Optional[Dict[str, Any]],
        *,
        lang: str = 'en',
        domain: str = 'cyber',
        document_type: str = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        strategy_id: Any = None,
        export_type: str = '',
        blocking_errors: Optional[Iterable[Any]] = None,
) -> Dict[str, Any]:
    _repaired, diag = repair_english_cyber_dcc_classification_evidence_sections(
        sections, lang=lang, domain=domain, document_type=document_type,
        selected_frameworks=selected_frameworks, strategy_id=strategy_id,
        export_type=export_type)
    blockers = [str(b) for b in (blocking_errors or []) if b]
    diag['blocking_errors'] = list(dict.fromkeys(
        list(diag.get('blocking_errors') or []) + blockers))
    diag['passed'] = bool(diag.get('passed')) and not diag['blocking_errors']
    return diag


def emit_rel36_3_en_cyber_dcc_classification_evidence_repair(
        diag: Dict[str, Any]) -> None:
    try:
        print(
            f"{REL36_3_EN_CYBER_DCC_CLASS_DIAG_TAG} "
            f"{json.dumps(diag, ensure_ascii=False, default=str)}",
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass
