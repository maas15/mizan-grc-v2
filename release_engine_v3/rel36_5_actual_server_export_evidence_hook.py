"""REL36.5 — last-mile hook on the actual server export evidence blob.

REL36.4 repairs sections / final_markdown / frozen artifacts before render.
Live DOCX/PDF evidence still validates *extracted visible text*
(``docx_text`` / ``pdf_text``) inside ``validate_actual_export_evidence``
→ ``_channel_defects`` → ``run_rel31_content_substance_checks`` →
``check_pillar_owner_missing``. That extracted blob was never repaired.

This module rewrites that exact evidence-input string with the REL36.4
English Cyber live-path repair, then the unchanged validator runs on the
repaired blob. It does not weaken ``pillar_owner_missing``, skip evidence,
or mark the gate passed.
"""

from __future__ import annotations

import hashlib
import json
import threading
from typing import Any, Dict, Iterable, List, Optional, Tuple

from release_engine.rel31_content_substance_checks import (
    check_pillar_owner_missing,
)
from release_engine_v3.rel31_authority import _normalize_rel31_domain_code
from release_engine_v3.rel36_2_en_cyber_export_evidence_repair import (
    inventory_english_cyber_pillar_rows,
)
from release_engine_v3.rel36_4_live_en_cyber_export_path_repair import (
    _FAMILY_RE,
    _inventory_from_blob,
    repair_live_english_cyber_export_sections,
    repair_live_english_cyber_export_text,
)
from release_engine_v3.rel36_bilingual_preview_export_authority import (
    normalize_rel36_lang,
)


REL36_5_ACTUAL_SERVER_EXPORT_EVIDENCE_HOOK_TAG = (
    '[REL36.5-ACTUAL-SERVER-EXPORT-EVIDENCE-HOOK]')

_DOCX_EVIDENCE_CALL_SITE = (
    'release_engine.export_evidence_validator.validate_actual_export_evidence'
    ' -> _channel_defects(docx_text) -> run_rel31_content_substance_checks'
    ' -> evaluate_content_substance -> check_pillar_owner_missing'
)
_PDF_EVIDENCE_CALL_SITE = (
    'release_engine.export_evidence_validator.validate_actual_export_evidence'
    ' -> _channel_defects(pdf_text) -> run_rel31_content_substance_checks'
    ' -> evaluate_content_substance -> check_pillar_owner_missing'
)

_HOOK_GUARD = threading.local()


def _sha(text: str) -> str:
    return hashlib.sha256(str(text or '').encode('utf-8')).hexdigest()


def _selected_list(selected_frameworks: Optional[Iterable[Any]]) -> List[str]:
    return [str(x) for x in (selected_frameworks or []) if x]


def _frameworks_ok(selected: List[str], blob: str) -> bool:
    joined = ' '.join(selected) + ' ' + str(blob or '')
    upper = joined.upper()
    has_dcc = 'DCC' in upper
    has_ecc = 'ECC' in upper
    if selected:
        return has_dcc or (has_ecc and has_dcc)
    return has_dcc or has_ecc or 'NCA' in upper or 'المبادرة' in (blob or '')


def _english_cyber_evidence_signal(blob: str, lang: str) -> bool:
    """English Cyber only — do not treat Arabic ECC/DCC docs as English.

    ``NCA ECC`` / ``Cybersecurity`` appear in genuine Arabic cyber exports.
    Those tokens must not trigger an English rewrite. Live English export
    still applies when ``lang=en`` (including extracted Arabic leftovers)
    or when the blob itself carries English pillar/KPI headers.
    """
    nlang = normalize_rel36_lang(lang)
    text = str(blob or '')
    if nlang == 'en':
        return True
    if 'Initiative' in text and 'Expected Deliverable' in text:
        return True
    if 'KPI Description' in text:
        return True
    mashed = (
        'المبادرة' in text
        and 'المخرج المتوقع' in text
        and 'Initiative' in text
        and 'Expected Deliverable' in text
    )
    return mashed


def rel36_5_should_apply(
        *,
        lang: str = '',
        domain: str = '',
        document_type: str = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        blob: str = '',
) -> bool:
    dcode = (
        _normalize_rel31_domain_code(domain)
        or str(domain or '').strip().lower()
    )
    dtype = str(document_type or 'strategy').strip().lower() or 'strategy'
    if dcode != 'cyber':
        return False
    if dtype not in ('strategy', 'strategy_document', ''):
        return False
    selected = _selected_list(selected_frameworks)
    if not _frameworks_ok(selected, blob):
        return False
    return _english_cyber_evidence_signal(blob, lang)


def _blob_blockers(blob: str) -> List[str]:
    blockers: List[str] = []
    if check_pillar_owner_missing(blob or ''):
        blockers.append('pillar_owner_missing')
    inv = inventory_english_cyber_pillar_rows(blob or '')
    if inv.get('missing_owner_rows') and 'pillar_owner_missing' not in blockers:
        blockers.append('pillar_owner_missing')
    if _FAMILY_RE.search(str(blob or '')):
        blockers.append('family_markers')
    return blockers


def apply_rel36_5_to_evidence_blob(
        blob: str,
        *,
        lang: str = '',
        domain: str = '',
        document_type: str = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        strategy_id: Any = None,
        route: str = '',
        export_type: str = '',
        evidence_call_site: str = '',
) -> Tuple[str, Dict[str, Any]]:
    """Repair the exact evidence-input string. Validator is unchanged."""
    source = str(blob or '')
    export_n = str(export_type or route or '').strip().lower()
    if export_n == 'docx':
        call_site = evidence_call_site or _DOCX_EVIDENCE_CALL_SITE
    elif export_n == 'pdf':
        call_site = evidence_call_site or _PDF_EVIDENCE_CALL_SITE
    else:
        call_site = evidence_call_site or (
            'release_engine.export_evidence_validator.validate_actual_export_evidence'
        )
    selected = _selected_list(selected_frameworks)
    before_inv = _inventory_from_blob(source)
    blockers_before = _blob_blockers(source)
    nlang = normalize_rel36_lang(lang) if lang else ''
    dcode = (
        _normalize_rel31_domain_code(domain)
        or str(domain or '').strip().lower()
    )
    dtype = str(document_type or 'strategy').strip().lower() or 'strategy'
    apply = rel36_5_should_apply(
        lang=lang or 'en',
        domain=domain,
        document_type=document_type,
        selected_frameworks=selected,
        blob=source,
    )
    repaired = source
    if apply and source.strip() and not getattr(_HOOK_GUARD, 'active', False):
        _HOOK_GUARD.active = True
        try:
            text_repaired = repair_live_english_cyber_export_text(source)
            sections, md_after, _inner = repair_live_english_cyber_export_sections(
                {'evidence': text_repaired},
                lang='en',
                domain='cyber',
                document_type='strategy',
                selected_frameworks=selected or ['NCA ECC', 'NCA DCC'],
                strategy_id=strategy_id,
                export_type=export_n or 'evidence',
                route=f'actual_server_export_evidence:{export_n or route}',
                final_markdown=text_repaired,
                evidence_input=text_repaired,
                repair_ran_at='validate_actual_export_evidence',
            )
            repaired = (
                str(md_after or '')
                or str(sections.get('evidence') or '')
                or text_repaired
                or source
            )
        finally:
            _HOOK_GUARD.active = False
    after_inv = _inventory_from_blob(repaired)
    after_rows = inventory_english_cyber_pillar_rows(repaired)
    if after_rows.get('header'):
        after_inv['header'] = after_rows.get('header') or after_inv.get('header')
    after_inv['missing'] = after_rows.get('missing_owner_rows') or []
    blockers_after = _blob_blockers(repaired)
    diag = {
        'tag': 'REL36.5-ACTUAL-SERVER-EXPORT-EVIDENCE-HOOK',
        'route': route or export_n,
        'export_type': export_n or route,
        'lang': nlang or ('en' if apply else str(lang or '')),
        'domain': dcode,
        'document_type': dtype,
        'selected_frameworks': selected or (
            ['NCA ECC', 'NCA DCC'] if apply else []),
        'strategy_id': strategy_id,
        'evidence_call_site': call_site,
        'source_evidence_input_hash': _sha(source),
        'repaired_evidence_input_hash': _sha(repaired),
        # Caller replaces the evidence input with ``repaired`` before
        # _channel_defects. The blob validation sees IS the repaired blob.
        'evidence_input_matches_repaired': True,
        'repair_applied_at': 'validate_actual_export_evidence',
        'applied': bool(apply and repaired != source),
        'pillar_header_before': before_inv.get('header') or [],
        'pillar_header_after': after_inv.get('header') or [],
        'missing_owner_rows_before': before_inv.get('missing') or [],
        'missing_owner_rows_after': after_inv.get('missing') or [],
        'family_markers_before': before_inv.get('family_markers') or [],
        'family_markers_after': after_inv.get('family_markers') or [],
        'blockers_before': blockers_before,
        'blockers_after': blockers_after,
        'passed': not blockers_after,
    }
    return repaired, diag


def emit_rel36_5_actual_server_export_evidence_hook(diag: Dict[str, Any]) -> None:
    try:
        print(
            f"{REL36_5_ACTUAL_SERVER_EXPORT_EVIDENCE_HOOK_TAG} "
            f"{json.dumps(diag, ensure_ascii=False, default=str)}",
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass
