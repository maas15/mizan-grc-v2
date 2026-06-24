"""PR-REL3.1 — positive Document Quality Specification for Cyber Arabic Technical.

Schema-driven board-ready contract: a document passes only when it satisfies
the complete positive model below. Missing forbidden patterns alone is insufficient.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from release_engine.rel27_export_checks import (
    ROADMAP_FAMILIES,
    check_kpi_canonical,
    check_roadmap_coverage,
)
from release_engine.rel31_content_substance_checks import (
    GENERIC_RISK_TREATMENT,
    check_arabic_residues_substance,
    check_generic_risk_treatments,
    check_kpi_semantic_defects,
    check_pillar_owner_missing,
    check_shallow_pillar_rows,
    check_traceability_bad_mappings,
    evaluate_content_substance,
)
from release_engine.rel31_acceptance_checks import (
    flat_kpi_kri_section_blob,
    flat_pillar_initiative_blob,
)

# ── Positive model constants ─────────────────────────────────────────────

REQUIRED_SO_FAMILIES = (
    'governance_ciso',
    'framework_compliance',
    'soc_siem',
    'iam_pam_mfa',
    'vulnerability_management',
    'awareness_training',
    'csirt_incident_response',
    'data_protection_dcc',
)

REQUIRED_PILLAR_TITLES = (
    'حوكمة ونموذج التشغيل',
    'الحماية والكشف والاستجابة',
    'الهوية وحماية البيانات',
    'المرونة واستمرارية الأعمال',
)

REQUIRED_ROADMAP_FAMILIES = ROADMAP_FAMILIES

REQUIRED_KPI_FAMILIES = (
    'governance',
    'compliance',
    'soc_mttd',
    'incident_response_mttr',
    'iam_mfa_pam',
    'vulnerability_sla',
    'awareness_phishing',
    'backup_dr',
    'data_classification',
    'encryption',
    'dlp',
    'third_party_risk',
)

REQUIRED_TRACE_MAPPINGS: Dict[str, str] = {
    'data_classification': 'ضعف تصنيف وجرد البيانات الحساسة',
    'encryption': 'ضعف ضوابط التشفير وإدارة المفاتيح',
    'dlp': 'ضعف ضوابط منع تسرب البيانات',
    'sensitive_data_handling': 'ضعف معالجة البيانات الحساسة',
    'data_protection': 'ضعف حماية البيانات أثناء النقل والتخزين',
    'ecc_governance': 'غياب وظيفة CISO وهيكل حوكمة الأمن السيبراني',
    'ecc_iam': 'ضعف إدارة الهوية والوصول IAM/PAM/MFA',
    'ecc_soc_monitoring': 'غياب مركز العمليات الأمنية SOC ومنصة SIEM',
    'ecc_incident_response': (
        'غياب فريق الاستجابة للحوادث CSIRT وخطط الاستجابة'),
    'ecc_vulnerability': (
        'ضعف إدارة الثغرات الأمنية وبرنامج التصحيح الدوري'),
}

_KPI_SPEC_TO_SUBSTANCE = {
    'governance': 'governance',
    'compliance': 'compliance',
    'soc_mttd': 'mttd',
    'incident_response_mttr': 'mttr',
    'iam_mfa_pam': 'iam_pam_mfa',
    'vulnerability_sla': 'vulnerability_sla',
    'awareness_phishing': 'awareness',
    'backup_dr': 'backup',
    'data_classification': 'classification',
    'encryption': 'encryption',
    'dlp': 'dlp',
    'third_party_risk': 'third_party',
}

_KPI_FAMILY_TOKENS = {
    'governance': ('حوكمة', 'ciso', 'لجنة'),
    'compliance': ('امتثال', 'ecc', 'dcc'),
    'soc_mttd': ('mttd', 'زمن الكشف', 'كشف'),
    'incident_response_mttr': ('mttr', 'زمن الاستجابة', 'استجابة'),
    'iam_mfa_pam': ('iam', 'pam', 'mfa', 'هوية'),
    'vulnerability_sla': ('ثغرات', 'vulnerability', 'sla'),
    'awareness_phishing': ('توعية', 'phishing', 'تدريب', 'تصيد'),
    'backup_dr': ('نسخ', 'backup', 'dr', 'تعافي'),
    'data_classification': ('تصنيف', 'جرد'),
    'encryption': ('تشفير', 'مفاتيح'),
    'dlp': ('dlp', 'تسرب'),
    'third_party_risk': ('أطراف ثالثة', 'third', 'مورد'),
}

ARABIC_ROLE_CORRUPTION_PATTERNS = (
    r'المسؤول\s+أمن\s+السيبراني\s*e',
    r'المسؤول\s+أمن\s+السيبراني\s*Lead',
    r'\bCSISO\b',
    r'segmentation-Micro',
    r'segmentation\s*-\s*Micro',
    r'Lead\s+e\b',
)

ARABIC_GLUE_RESIDUE_PATTERNS = (
    'النقرفي',
    'الناجمةعن',
    'ال مناسبة',
    'ال مناسب',
    'ال معنية',
    'المراقبة المست',
    'ال معالجة',
    'ال منظمة',
    'ال معلومات',
    'بال منصات',
    'المحددةفي',
    'الحاليةفي',
    'الموظفينفي',
    'حلولمنع',
    'لل معالجة',
    'ل معالجة',
    'ال منقولة',
)

GENERIC_RISK_TREATMENTS = (
    GENERIC_RISK_TREATMENT,
    'تخصيص موارد وطاقات تشغيلية للأمن السيبراني',
)

MIN_PILLAR_DESC_WORDS = 8
MIN_RISK_TREATMENT_WORDS = 8
MIN_ROADMAP_ROWS = 10
MAX_ROADMAP_ROWS = 14
MIN_SO_OBJECTIVES = 6
MAX_SO_OBJECTIVES = 8


def _risk_treatment_substantive(treatment: str) -> bool:
    """Treatment plan must be substantive (Arabic words or mixed technical plan)."""
    t = (treatment or '').strip()
    if not t:
        return False
    if _arabic_word_count(t) >= MIN_RISK_TREATMENT_WORDS:
        return True
    return len(re.findall(r'[\w\u0600-\u06FF]+', t)) >= MIN_RISK_TREATMENT_WORDS


def _kpi_export_surface_present(blob: str) -> bool:
    """True when exported route text includes a rendered KPI/KRI table."""
    kpi_scan = flat_kpi_kri_section_blob(blob) or blob or ''
    if not kpi_scan.strip():
        return False
    chk = check_kpi_canonical(kpi_scan)
    if (chk.get('exported_kpi_table_count') or 0) > 0:
        return True
    return len(_kpi_families_present(kpi_scan)) >= 3


def _count_so_objective_rows(vision: str) -> int:
    """Count canonical SO rows; ignore duplicate re-rendered objective tables."""
    nums = [
        int(m) for m in re.findall(r'^\|\s*(\d+)\s*\|', vision or '', re.MULTILINE)
    ]
    if not nums:
        return 0
    uniq = sorted(set(nums))
    if len(nums) > len(uniq) and uniq and max(uniq) <= MAX_SO_OBJECTIVES:
        return len(uniq)
    return len(nums)
MIN_RISKS = 6
MAX_RISKS = 8

_PRCY88_SO_TO_SPEC = {
    'governance_ciso': 'governance_ciso',
    'compliance_ecc_dcc': 'framework_compliance',
    'soc_monitoring_detection': 'soc_siem',
    'iam_pam_mfa': 'iam_pam_mfa',
    'vulnerability_management': 'vulnerability_management',
    'incident_response_csirt': 'csirt_incident_response',
    'data_protection_dcc': 'data_protection_dcc',
    'awareness_or_resilience': 'awareness_training',
}

_PILLAR_HEADING_FAMILY = {
    'حوكمة ونموذج التشغيل': 'governance_operating_model',
    'الحماية والكشف والاستجابة': 'protection_detection_response',
    'الهوية وحماية البيانات': 'identity_data_protection',
    'المرونة واستمرارية الأعمال': 'resilience_continuity',
}

_EVIDENCE_ARTIFACT_MARKERS = (
    'معتمد', 'منصة', 'فريق', 'خطة', 'سجل', 'تغطية', 'مختبر', 'مفعّل',
    'لوحات', 'RTO', 'RACI', 'SIEM', 'CSIRT', 'DLP', 'MFA',
)

_CONTROL_FAMILY_KEYWORDS = {
    'compliance': ('امتثال', 'ecc', 'dcc', 'تنظيمي'),
    'soc_monitoring': ('soc', 'siem', 'رصد'),
    'iam': ('iam', 'pam', 'mfa', 'هوية', 'صلاحيات'),
    'incident_response': (
        'csirt', 'حوادث', 'استجابة', 'فدية', 'تجزئة', 'segmentation',
        'تصيد', 'phishing'),
    'vulnerability': ('ثغر', 'vulnerab', 'patch'),
    'data_protection': ('بيانات', 'dlp', 'تصنيف', 'تشفير'),
    'resilience': ('نسخ', 'dr', 'استمرارية', 'تعافي'),
    'awareness': ('توعية', 'تدريب', 'awareness'),
    'resource_capacity': ('موارد', 'طاقات', 'ميزانية', 'كفاءات'),
    'third_party': (
        'أطراف', 'طرف ثالث', 'الأطراف', 'من الأطر', 'مورد', 'supplier',
        'vendor'),
}


def _sha256_text(text: str) -> str:
    return hashlib.sha256((text or '').encode('utf-8')).hexdigest()


def _arabic_word_count(text: str) -> int:
    return len(re.findall(r'[\u0600-\u06FF]+', text or ''))


def _emit_quality_compiler(payload: Dict[str, Any]) -> None:
    try:
        print(
            '[REL3-DOCUMENT-QUALITY-SPEC] '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


# ── Visible-text positive checks ─────────────────────────────────────────

def check_pillar_duplicate_narratives(blob: str) -> List[str]:
    """Fail when pillar narrative paragraphs repeat across pillars."""
    section = flat_pillar_initiative_blob(blob) or blob or ''
    narratives: List[str] = []
    dupes: List[str] = []
    for chunk in re.split(r'(?=^#{3,4}\s+)', section, flags=re.MULTILINE):
        lines = [ln for ln in chunk.splitlines() if ln.strip()]
        if len(lines) < 2:
            continue
        body = '\n'.join(
            ln for ln in lines[1:]
            if not ln.strip().startswith('|')).strip()
        if len(body) < 40:
            continue
        norm = re.sub(r'\s+', ' ', body)[:120]
        if norm in narratives:
            dupes.append(norm[:80])
        else:
            narratives.append(norm)
    text = blob or ''
    start = text.rfind('2. الركائز الاستراتيجية')
    if start < 0:
        start = text.rfind('حوكمة ونموذج التشغيل')
    end = text.find('البيئة التنظيمية', start + 100) if start >= 0 else -1
    if start >= 0 and end > start:
        seen_para: List[str] = []
        for ln in text[start:end].splitlines():
            stripped = (ln or '').strip()
            if len(stripped) < 50:
                continue
            if stripped in ('—', '-', '#') or stripped.startswith('|'):
                continue
            norm = re.sub(r'\s+', ' ', stripped)
            if norm in seen_para:
                dupes.append(norm[:80])
            else:
                seen_para.append(norm)
    return list(dict.fromkeys(dupes))[:6]


def check_pillar_generic_outputs(blob: str) -> List[str]:
    shallow = check_shallow_pillar_rows(blob)
    return list(dict.fromkeys(shallow))[:12]


def _parse_canonical_kpi_rows(canonical_kpis: str) -> List[List[str]]:
    """Parse KPI markdown rows from canonical section (not flat export text)."""
    from release_engine.kpi_model import _parse_kpi_rows

    raw = (canonical_kpis or '').strip()
    if not raw:
        return []
    _lines, rows = _parse_kpi_rows(raw)
    if rows:
        return rows
    flat = flat_kpi_kri_section_blob(raw) or raw
    _lines, rows = _parse_kpi_rows(flat)
    return rows


def _metric_tag_row_count(section_text: str, tag: str) -> int:
    """Canonical KPI table rows containing a metric tag (not flat-text repeats)."""
    from release_engine.rel27_export_checks import _extract_kpi_main_rows

    rows = _parse_canonical_kpi_rows(section_text)
    if not rows:
        section = flat_kpi_kri_section_blob(section_text) or section_text or ''
        rows = _extract_kpi_main_rows(section) or _extract_kpi_main_rows(
            section_text or '')
    if not rows:
        return 0
    return sum(
        1 for cells in rows
        if tag in ((cells[1] if len(cells) > 1 else '') or '').upper())


def check_duplicate_metric_labels(
        blob: str,
        *,
        docx_reference: str = '',
        canonical_kpis: str = '') -> List[str]:
    """Duplicate MTTD/MTTR or other metric labels in KPI section."""
    from release_engine.kpi_model import (
        _duplicate_kpi_families_from_rows,
        _parse_kpi_rows,
        resolve_kpi_canonical_family,
    )
    from release_engine.rel27_export_checks import parse_flat_professional_kpi_cards

    section = flat_kpi_kri_section_blob(blob) or blob or ''
    canon_rows = _parse_canonical_kpi_rows(canonical_kpis)
    if canon_rows:
        dup_fams, dup_labels = _duplicate_kpi_families_from_rows(canon_rows)
        canon_dupes: List[str] = []
        for fam in dup_fams:
            if fam == 'soc_mttd':
                canon_dupes.append('duplicate_mttd')
            elif fam == 'incident_response_mttr':
                canon_dupes.append('duplicate_mttr')
            else:
                canon_dupes.append(f'duplicate_{fam}')
        name_targets: Dict[str, List[str]] = {}
        for cells in canon_rows:
            name = (cells[1] if len(cells) > 1 else '').strip()
            target = (cells[2] if len(cells) > 2 else '').strip()
            if name:
                name_targets.setdefault(name, []).append(target)
        for name, targets in name_targets.items():
            if len(targets) > 1:
                uniq = {t for t in targets if t}
                if len(uniq) > 1:
                    canon_dupes.append('conflicting_kpi_targets')
        if not canon_dupes:
            return []
        return list(dict.fromkeys(canon_dupes))
    _lines, rows = _parse_kpi_rows(section)
    if not rows and blob:
        _lines, rows = _parse_kpi_rows(blob)
    dupes: List[str] = []
    if rows:
        dup_fams, _ = _duplicate_kpi_families_from_rows(rows)
        for fam in dup_fams:
            if fam == 'soc_mttd':
                dupes.append('duplicate_mttd')
            elif fam == 'incident_response_mttr':
                dupes.append('duplicate_mttr')
            else:
                dupes.append(f'duplicate_{fam}')
        return dupes
    cards = parse_flat_professional_kpi_cards(section)
    if cards:
        name_targets: Dict[str, List[str]] = {}
        for card in cards:
            name = re.sub(r'\s+', ' ', (card.get('name') or '').strip())
            if not name:
                continue
            name_targets.setdefault(name, []).append(card.get('target') or '')
        for name, targets in name_targets.items():
            if len(targets) > 1:
                uniq = {t.strip() for t in targets if t.strip()}
                if len(uniq) > 1:
                    dupes.append('conflicting_kpi_targets')
                low = name.upper()
                if 'MTTD' in low or 'اكتشاف' in name:
                    dupes.append('duplicate_mttd')
                if 'MTTR' in low or 'استجابة' in name:
                    dupes.append('duplicate_mttr')
        return list(dict.fromkeys(dupes))
    low = section.upper()
    ref_low = (flat_kpi_kri_section_blob(docx_reference) or docx_reference or '').upper()
    canon_section = flat_kpi_kri_section_blob(canonical_kpis) or canonical_kpis or ''
    for tag in ('MTTD', 'MTTR'):
        count = low.count(tag)
        if not count:
            continue
        ref_rows = 0
        for src in (canon_section, docx_reference):
            if src.strip():
                ref_rows = _metric_tag_row_count(src, tag)
                if ref_rows:
                    break
        if ref_rows <= 1 and count <= 4:
            continue
        ref_flat = ref_low.count(tag) if ref_low else 0
        if not ref_rows and ref_flat and ref_flat <= 2 and count <= max(4, ref_flat * 2):
            continue
        if ref_rows > 1 or count > 3:
            dupes.append(f'duplicate_{tag}')
    return dupes


def check_mixed_metric_formulas(
        blob: str, *, canonical_kpis: str = '') -> List[str]:
    """DLP rows with encryption formulas or vice versa."""
    from release_engine.kpi_model import _parse_kpi_rows
    from release_engine.rel27_export_checks import parse_flat_professional_kpi_cards

    section = flat_kpi_kri_section_blob(blob) or blob or ''
    mixed: List[str] = []
    canon_rows = _parse_canonical_kpi_rows(canonical_kpis)
    if canon_rows:
        mixed_canon: List[str] = []
        for cells in canon_rows:
            name = (cells[1] if len(cells) > 1 else '').lower()
            formula = (cells[3] if len(cells) > 3 else '').lower()
            if not formula:
                continue
            if ('dlp' in name or 'تسرب' in name) and (
                    'تشفير' in formula or 'مفاتيح' in formula):
                mixed_canon.append('dlp_encryption_formula_mix')
            if ('تشفير' in name or 'encryption' in name) and (
                    'dlp' in formula or 'تسرب' in formula):
                mixed_canon.append('encryption_dlp_formula_mix')
        if not mixed_canon:
            return []
        return list(dict.fromkeys(mixed_canon))
    _lines, rows = _parse_kpi_rows(section)
    if rows:
        for cells in rows:
            name = (cells[1] if len(cells) > 1 else '').lower()
            formula = (cells[3] if len(cells) > 3 else '').lower()
            if not formula:
                continue
            if ('dlp' in name or 'تسرب' in name) and (
                    'تشفير' in formula or 'مفاتيح' in formula):
                mixed.append('dlp_encryption_formula_mix')
            if ('تشفير' in name or 'encryption' in name) and (
                    'dlp' in formula or 'تسرب' in formula):
                mixed.append('encryption_dlp_formula_mix')
            if 'تصنيف' in name and 'kri' in name.lower():
                if 'مخاطر' not in name and 'risk' not in name:
                    mixed.append('classification_as_kri_not_risk')
            if 'أطراف ثالثة' in name or 'third' in name:
                target = cells[2] if len(cells) > 2 else ''
                if re.search(r'100%|المنجز|المخطط|completion', target, re.I):
                    mixed.append('third_party_completion_percent')
        return list(dict.fromkeys(mixed))
    cards = parse_flat_professional_kpi_cards(section)
    if cards:
        data_names = [
            c.get('name') or '' for c in cards
            if any(k in (c.get('name') or '') for k in ('DLP', 'تشفير', 'تصنيف', 'تسرب'))]
        if len(data_names) >= 3:
            mixed.append('dlp_encryption_classification_metric_mix')
    for ln in section.splitlines():
        low = ln.lower()
        if ('dlp' in low or 'تسرب' in ln) and (
                'تشفير' in ln or 'encryption' in low):
            if '÷' in ln or '×' in ln or '/' in ln:
                if 'تسرب' in ln and 'تشفير' in ln:
                    mixed.append('dlp_encryption_formula_mix')
    return list(dict.fromkeys(mixed))


_SO_PLACEHOLDER_MARKERS = (
    'tbd', 'placeholder', 'سيتم لاحق', 'سيتم لاحقاً', 'لاحقاً', 'مؤقت',
    'example', 'sample', 'xxx', '...',
)


def _parse_vision_objective_cells(vision: str) -> List[str]:
    objectives: List[str] = []
    for row in _parse_so_table_rows(vision):
        objectives.append(row.get('objective') or '')
    return [o for o in objectives if o]


def _parse_so_table_rows(vision: str) -> List[Dict[str, str]]:
    """Parse SO markdown table into objective/target/rationale/timeframe rows."""
    rows: List[Dict[str, str]] = []
    in_table = False
    col_map: Dict[str, int] = {}
    for ln in (vision or '').splitlines():
        if '|' in ln and ('الهدف' in ln or 'objective' in ln.lower()):
            in_table = True
            headers = [c.strip().lower() for c in ln.strip('|').split('|')]
            col_map = {}
            for i, h in enumerate(headers):
                if re.search(r'(?:^|\s)ال?هدف|objective', h) and 'مستهد' not in h:
                    col_map['objective'] = i
                elif 'مستهد' in h or 'target' in h:
                    col_map['target'] = i
                elif 'مبر' in h or 'rationale' in h:
                    col_map['rationale'] = i
                elif 'إطار' in h or 'time' in h or 'frame' in h:
                    col_map['timeframe'] = i
            continue
        if in_table and ln.strip().startswith('|') and '---' not in ln:
            cells = [c.strip() for c in ln.strip('|').split('|')]
            if not cells or cells[0] in ('#', 'الهدف', ''):
                continue
            if cells[0].isdigit() and len(cells) > 1:
                offset = 1
            else:
                offset = 0
            obj_i = col_map.get('objective', 0 + offset)
            tgt_i = col_map.get('target', 1 + offset)
            rat_i = col_map.get('rationale', 2 + offset)
            tf_i = col_map.get('timeframe', 3 + offset)
            rows.append({
                'objective': cells[obj_i] if len(cells) > obj_i else '',
                'target': cells[tgt_i] if len(cells) > tgt_i else '',
                'rationale': cells[rat_i] if len(cells) > rat_i else '',
                'timeframe': cells[tf_i] if len(cells) > tf_i else '',
            })
    return rows


def _is_so_placeholder(text: str) -> bool:
    t = (text or '').strip().lower()
    if not t or t in ('—', '-', 'n/a'):
        return True
    return any(m in t for m in _SO_PLACEHOLDER_MARKERS)


def _so_target_has_scope(target: str, timeframe: str = '') -> bool:
    """Target must include measurable threshold and scope/timeframe cue."""
    t = (target or '').strip()
    if not t:
        return False
    has_threshold = bool(re.search(r'\d|%|≤|≥|<|>|sla', t, re.I))
    has_scope = bool(re.search(
        r'حساب|أصل|عض|موظف|نظام|شهر|سنة|ربع|ECC|DCC|CISO|SOC|IAM|%',
        t, re.I))
    if has_threshold and (has_scope or _arabic_word_count(t) >= 4):
        return True
    if (timeframe or '').strip() and _arabic_word_count(t) >= 5:
        if re.search(
                r'إكمال|تشغيل|معالجة|تغطية|اختبار|حماية|تنفيذ|برنامج|تطبيق|مستوى',
                t):
            return True
    return False


def check_strategic_objectives_positive_model(vision: str) -> List[str]:
    """Positive SO schema: complete rows, scoped targets, unique families."""
    from cyber_board_ready_prcy88 import _detect_so_family

    defects: List[str] = []
    rows = _parse_so_table_rows(vision)
    if not rows:
        return ['so_table_missing']
    family_hits: Dict[str, int] = {}
    for row in rows:
        obj = row.get('objective') or ''
        target = row.get('target') or ''
        rationale = row.get('rationale') or ''
        timeframe = row.get('timeframe') or ''
        if not all((obj, target, rationale, timeframe)):
            defects.append('so_row_incomplete')
        if _is_so_placeholder(obj) or _is_so_placeholder(target):
            defects.append('so_placeholder')
        if re.match(r'^\s*\d+\s*%\s*$', target):
            defects.append('so_target_percent_only')
        elif target.strip().endswith('%') and _arabic_word_count(target) < 3:
            defects.append('so_target_percent_only')
        if target and not _so_target_has_scope(target, timeframe):
            defects.append('so_target_without_scope')
        prcy = _detect_so_family(obj)
        if prcy:
            spec = _PRCY88_SO_TO_SPEC.get(prcy)
            if spec:
                family_hits[spec] = family_hits.get(spec, 0) + 1
    for fam, count in family_hits.items():
        if count > 1:
            defects.append(f'so_duplicate_family:{fam}')
    return list(dict.fromkeys(defects))[:12]


def check_so_families_present(vision: str) -> Tuple[List[str], Dict[str, bool]]:
    """Positive SO family coverage (maps PRCY88 families to spec families)."""
    from cyber_board_ready_prcy88 import (
        PRCY88_SO_FAMILIES,
        PRCY88_SO_FAMILY_TOKENS,
        _detect_so_family,
    )

    present: Dict[str, bool] = {f: False for f in REQUIRED_SO_FAMILIES}
    for obj in _parse_vision_objective_cells(vision):
        prcy = _detect_so_family(obj)
        if prcy and prcy in _PRCY88_SO_TO_SPEC:
            present[_PRCY88_SO_TO_SPEC[prcy]] = True
    blob = vision or ''
    for prcy in PRCY88_SO_FAMILIES:
        spec = _PRCY88_SO_TO_SPEC.get(prcy)
        if not spec or present.get(spec):
            continue
        for tok in PRCY88_SO_FAMILY_TOKENS.get(prcy, ()):
            if tok.isascii():
                if tok.lower() in blob.lower():
                    present[spec] = True
                    break
            elif tok in blob:
                present[spec] = True
                break
    missing = [f for f in REQUIRED_SO_FAMILIES if not present.get(f)]
    return missing, present


def _parse_pillar_initiative_rows(chunk: str) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    in_table = False
    for ln in (chunk or '').splitlines():
        if 'المبادرة' in ln:
            in_table = True
            continue
        if in_table and ln.strip().startswith('|') and '---' not in ln:
            cells = [c.strip() for c in ln.strip('|').split('|')]
            if len(cells) < 2 or cells[0] in ('المبادرة', ''):
                continue
            rows.append({
                'initiative': cells[0],
                'description': cells[1] if len(cells) > 1 else '',
                'output': cells[2] if len(cells) > 2 else '',
                'owner': cells[3] if len(cells) > 3 else '',
            })
    return rows


def check_pillar_positive_model(pillars: str) -> List[str]:
    """Canonical pillar positive model: capability family, framework, evidence."""
    defects: List[str] = []
    narratives_seen: List[str] = []
    for chunk in re.split(r'(?=^###\s+)', pillars or '', flags=re.MULTILINE):
        if not chunk.strip().startswith('###'):
            continue
        title_line = chunk.splitlines()[0]
        cap_family = None
        for key, fam in _PILLAR_HEADING_FAMILY.items():
            if key in title_line:
                cap_family = fam
                break
        if not cap_family:
            defects.append(f'pillar_missing_capability_family:{title_line[:40]}')
        body = '\n'.join(
            ln for ln in chunk.splitlines()[1:]
            if not ln.strip().startswith('|')).strip()
        norm = re.sub(r'\s+', ' ', body)[:120]
        if len(norm) >= 40:
            if norm in narratives_seen:
                defects.append('pillar_duplicate_narrative')
            narratives_seen.append(norm)
        if not re.search(r'NCA\s*(ECC|DCC)|\bECC\b|\bDCC\b', chunk):
            defects.append(f'pillar_framework_mapping_missing:{cap_family or "unknown"}')
        inits = _parse_pillar_initiative_rows(chunk)
        if len(inits) < 3 or len(inits) > 5:
            defects.append(f'pillar_initiative_count_invalid:{len(inits)}')
        for row in inits:
            if _arabic_word_count(row['description']) < MIN_PILLAR_DESC_WORDS:
                defects.append(
                    f'weak_pillar_description:{row["initiative"][:30]}')
            out = row['output']
            if not any(m in out for m in _EVIDENCE_ARTIFACT_MARKERS):
                if len(out) < 15:
                    defects.append(
                        f'missing_evidence_artifact:{row["initiative"][:30]}')
            owner = (row.get('owner') or '').strip()
            if owner in ('—', '-', ''):
                if 'المالك' in chunk or 'المسؤول' in chunk:
                    defects.append(
                        f'pillar_owner_missing:{row["initiative"][:30]}')
    return list(dict.fromkeys(defects))[:20]


def _confidence_has_risk_register(text: str) -> bool:
    """True when confidence section contains a substantive risk register."""
    blob = text or ''
    if not re.search(r'خطة المعالجة|treatment', blob, re.I):
        return False
    return bool(re.search(r'المخاطر|الاحتمالية|التأثير', blob))


def check_risk_register_schema(
        confidence: str) -> Tuple[List[str], List[Dict[str, str]]]:
    """6–8 risks with concrete treatment, owner, and linked control family."""
    from release_engine.risk_treatment_model import (
        _GENERIC_TREATMENT,
        _parse_risk_rows,
        _treatment_col_idx,
    )

    defects: List[str] = []
    lines, hdr, rows = _parse_risk_rows(confidence or '')
    treat_idx = 4
    if hdr >= 0:
        treat_idx = _treatment_col_idx(lines[hdr])
    treatments: List[Dict[str, str]] = []
    if not rows:
        treatments = _parse_flat_risk_register(confidence or '')
        row_count = len(treatments)
    else:
        row_count = len(rows)
    if row_count < MIN_RISKS or row_count > MAX_RISKS:
        defects.append(f'risk_count_invalid:{row_count}')
    seen_treatments: Dict[str, int] = {}
    if rows:
        for cells in rows:
            risk = cells[1] if len(cells) > 1 else (cells[0] if cells else '')
            treatment = cells[treat_idx] if len(cells) > treat_idx else ''
            owner = ''
            if 'المالك' in treatment:
                owner = treatment.split('المالك', 1)[-1].strip(' :：-')
            elif len(cells) > treat_idx + 1:
                owner = cells[treat_idx + 1]
            linked = ''
            blob = ' '.join(cells).lower()
            for fam, kws in _CONTROL_FAMILY_KEYWORDS.items():
                if any(k in blob for k in kws):
                    linked = fam
                    break
            treatments.append({
                'risk': risk,
                'treatment': treatment,
                'owner': owner,
                'linked_control_family': linked,
            })
            _append_risk_schema_defects(
                defects, seen_treatments, risk, treatment, owner, linked)
    else:
        for item in treatments:
            _append_risk_schema_defects(
                defects,
                seen_treatments,
                item.get('risk', ''),
                item.get('treatment', ''),
                item.get('owner', ''),
                item.get('linked_control_family', ''),
            )
    return list(dict.fromkeys(defects))[:12], treatments


def _parse_flat_risk_register(text: str) -> List[Dict[str, str]]:
    """Parse flat confidence risk register (no markdown pipes)."""
    lines = [ln.strip() for ln in (text or '').splitlines() if ln.strip()]
    start = -1
    for i, ln in enumerate(lines):
        if ln == 'المالك' and i >= 4 and lines[i - 1] == 'خطة المعالجة':
            start = i + 1
            break
    if start < 0:
        return []
    rows: List[Dict[str, str]] = []
    i = start
    while i < len(lines):
        if lines[i].isdigit() and i + 5 < len(lines):
            risk = lines[i + 1]
            treatment = lines[i + 4]
            owner = lines[i + 5]
            blob = ' '.join(lines[i:i + 6]).lower()
            linked = ''
            for fam, kws in _CONTROL_FAMILY_KEYWORDS.items():
                if any(k in blob for k in kws):
                    linked = fam
                    break
            rows.append({
                'risk': risk,
                'treatment': treatment,
                'owner': owner,
                'linked_control_family': linked,
            })
            i += 6
            continue
        i += 1
    return rows


def _append_risk_schema_defects(
        defects: List[str],
        seen_treatments: Dict[str, int],
        risk: str,
        treatment: str,
        owner: str,
        linked: str) -> None:
    from release_engine.risk_treatment_model import _GENERIC_TREATMENT

    if any(g in (treatment or '') for g in GENERIC_RISK_TREATMENTS):
        if treatment.strip() in GENERIC_RISK_TREATMENTS:
            defects.append('risk_treatment_generic')
    if treatment.strip() == _GENERIC_TREATMENT:
        defects.append('risk_treatment_generic')
    if not _risk_treatment_substantive(treatment):
        defects.append('risk_treatment_too_short')
    if not owner and 'المالك' not in treatment:
        defects.append('risk_treatment_missing_owner')
    if not linked:
        defects.append(f'risk_missing_control_family:{risk[:30]}')
    key = re.sub(r'\s+', ' ', treatment.strip())[:80]
    seen_treatments[key] = seen_treatments.get(key, 0) + 1
    if seen_treatments.get(key, 0) >= 2 and key:
        defects.append('risk_treatment_repeated')


def check_kpi_row_schema(kpis: str) -> List[str]:
    """Positive KPI row schema: owner, cadence, formula, measurable target."""
    from release_engine.kpi_model import _parse_kpi_rows

    defects: List[str] = []
    _lines, rows = _parse_kpi_rows(kpis or '')
    if not rows:
        return ['kpi_row_schema_missing_table']
    header_has_owner = any(
        'المالك' in ln or 'owner' in ln.lower()
        for ln in _lines if ln.strip().startswith('|'))
    header_has_cadence = any(
        'التكرار' in ln or 'cadence' in ln.lower() or 'الدورية' in ln
        for ln in _lines if ln.strip().startswith('|'))
    for cells in rows:
        name = cells[1] if len(cells) > 1 else ''
        target = cells[2] if len(cells) > 2 else ''
        formula = cells[3] if len(cells) > 3 else ''
        if not formula.strip():
            defects.append(f'kpi_formula_missing:{name[:30]}')
        if '%' in target and formula and (
                '÷' not in formula and '/' not in formula and '×' not in formula):
            defects.append(f'kpi_percent_without_denominator:{name[:30]}')
        if len(cells) >= 6 and header_has_owner and not cells[5].strip():
            defects.append(f'kpi_owner_missing:{name[:30]}')
        if len(cells) >= 7 and header_has_cadence and not cells[6].strip():
            defects.append(f'kpi_cadence_missing:{name[:30]}')
        if target.strip() and target.strip() == name.strip():
            defects.append(f'kpi_target_repeats_name:{name[:30]}')
    return list(dict.fromkeys(defects))[:12]


def check_arabic_tokenization_quality(blob: str) -> Dict[str, Any]:
    """Positive Arabic tokenization report (residues + glue + role corruption)."""
    residues = check_arabic_residues_substance(blob)
    role = check_arabic_role_corruption(blob)
    glue: List[str] = []
    text = blob or ''
    for pat in (
            r'(?:الحالية|الموظفين|النقر|الناجمة)(?=في|عن|مع)',
            r'(?<![\u0600-\u06FF])ال\s+(?:معالجة|مناسبة|منظمة|منقولة|معنية|منظمات|عنصر)',
            r'(?<![\u0600-\u06FF])ل[\s\u200f\u200e\u200b\u200c\u200d\u00a0\u202f]+معالجة',
    ):
        if re.search(pat, text):
            glue.append(pat[:40])
    all_defects = list(dict.fromkeys(residues + role + glue))
    return {
        'passed': not all_defects,
        'residues': residues,
        'role_corruption': role,
        'glue_particle_defects': glue,
        'blocking_defects': all_defects,
    }


def extract_risk_treatments_list(confidence: str) -> List[Dict[str, str]]:
    """Risk treatments for mandatory proof report."""
    _defects, treatments = check_risk_register_schema(confidence or '')
    return treatments


def build_traceability_mapping_report(blob: str) -> List[Dict[str, Any]]:
    """Required traceability semantic mappings with pass/fail per family."""
    from release_engine.traceability_substance_model import (
        _cap_col_idx,
        _detect_family,
        _gap_col_idx,
        _parse_trace_rows,
    )

    report: List[Dict[str, Any]] = []
    lines, hdr, rows = _parse_trace_rows(blob or '')
    cap_idx = gap_idx = -1
    if hdr >= 0:
        cap_idx = _cap_col_idx(lines[hdr])
        gap_idx = _gap_col_idx(lines[hdr])
    actual_by_family: Dict[str, str] = {}
    _fam_aliases = {
        'ecc_soc': 'ecc_soc_monitoring',
        'sensitive_handling': 'sensitive_data_handling',
    }
    if hdr >= 0:
        for cells in rows:
            fam = _detect_family(cells, cap_idx) or ''
            fam = _fam_aliases.get(fam, fam)
            gap = cells[gap_idx] if len(cells) > gap_idx else ''
            if fam and gap and gap not in ('—', '-', ''):
                actual_by_family[fam] = gap
            cap_text = cells[cap_idx] if len(cells) > cap_idx else ''
            if re.search(r'soc|siem', cap_text, re.I):
                actual_by_family.setdefault('ecc_soc_monitoring', gap or cap_text)
    for fam_key, expected_gap in REQUIRED_TRACE_MAPPINGS.items():
        actual = actual_by_family.get(fam_key, '')
        if not actual and expected_gap in (blob or ''):
            actual = expected_gap
        if not actual and fam_key == 'ecc_soc_monitoring':
            for g in (
                    'غياب مركز العمليات الأمنية SOC / SIEM',
                    'غياب مركز العمليات الأمنية SOC'):
                if g in (blob or ''):
                    actual = g
                    break
        report.append({
            'family': fam_key,
            'expected_gap': expected_gap,
            'actual_gap': actual,
            'passed': bool(actual) and (
                expected_gap in actual
                or actual in expected_gap
                or (fam_key == 'ecc_incident_response' and 'csirt' in actual.lower())),
        })
    return report


def check_arabic_role_corruption(blob: str) -> List[str]:
    found: List[str] = []
    text = blob or ''
    for pat in ARABIC_ROLE_CORRUPTION_PATTERNS:
        if re.search(pat, text, re.I):
            found.append(pat.replace('\\s+', ' ').replace('\\b', '')[:40])
    for pat in ARABIC_GLUE_RESIDUE_PATTERNS:
        from release_engine.rel31_acceptance_checks import (
            arabic_glue_residue_present as _glue_present,
        )
        if _glue_present(text, pat):
            found.append(pat)
    if re.search(r'(?<![\u0600-\u06FF])ال\s+(?:معالجة|مناسبة|منظمة|منقولة|معنية|منظمات|عنصر)', text):
        found.append('separated_definite_article')
    if re.search(
            r'(?<![\u0600-\u06FF])ل[\s\u200f\u200e\u200b\u200c\u200d\u00a0\u202f]+معالجة',
            text):
        found.append('lam_mualeda_split')
    if re.search(
            r'(?:الحالية|الموظفين|النقر|الناجمة)(?=في|عن|مع)',
            text):
        found.append('arabic_glued_particle')
    return list(dict.fromkeys(found))


def check_pdf_layout_semantic(
        pdf_text: str,
        *,
        docx_text: str = '',
        pdf_bytes: bytes = b'',
) -> Tuple[bool, List[str]]:
    """PDF must not flatten required tables into unreadable card-only text."""
    defects: List[str] = []
    pt = (pdf_text or '').strip()
    if not pt and pdf_bytes:
        defects.append('pdf_text_empty')
        return False, defects
    if len(pt) < 200:
        defects.append('pdf_text_too_short')
    dt = docx_text or ''
    if dt:
        for marker in (
                'مؤشرات الأداء', 'خارطة الطريق', 'الركائز', 'مصفوفة تتبع'):
            if marker in dt and marker not in pt:
                defects.append(f'pdf_missing_section:{marker[:20]}')
        road_docx = check_roadmap_coverage(dt).get('visible_row_count') or 0
        road_pdf = check_roadmap_coverage(pt).get('visible_row_count') or 0
        if road_docx >= 10 and road_pdf < 8:
            defects.append('pdf_roadmap_table_flattened')
    card_only = (
        'المرحلة 1:' in pt and '|' not in pt
        and pt.count('\n') > 50 and 'المبادرة' not in pt)
    if card_only:
        defects.append('pdf_card_layout_instead_of_table')
    return not defects, defects


def _roadmap_family_count(blob: str) -> int:
    road = check_roadmap_coverage(blob or '')
    present = [f for f in ROADMAP_FAMILIES if f not in (road.get('missing_families') or [])]
    return len(present)


def _kpi_families_present(blob: str) -> List[str]:
    from release_engine.kpi_substance_model import (
        REQUIRED_KPI_FAMILIES as SUBSTANCE_FAMILIES,
        _families_present,
    )

    present = _families_present(flat_kpi_kri_section_blob(blob) or blob or '')
    found: List[str] = []
    for spec_fam, sub_fam in _KPI_SPEC_TO_SUBSTANCE.items():
        if present.get(sub_fam):
            found.append(spec_fam)
    return found


def _evaluate_visible_route(
        blob: str,
        *,
        route: str,
        pdf_bytes: bytes = b'',
        peer_row_counts: Optional[Dict[str, int]] = None,
        docx_reference: str = '',
        canonical_kpis: str = '',
) -> Dict[str, Any]:
    substance = evaluate_content_substance(
        blob, route=route, pdf_bytes=pdf_bytes,
        peer_row_counts=peer_row_counts,
        docx_reference=docx_reference,
        canonical_kpis=canonical_kpis)
    pillar_dupes = check_pillar_duplicate_narratives(blob)
    pillar_generic = check_pillar_generic_outputs(blob)
    dup_metrics = check_duplicate_metric_labels(
        blob, docx_reference=docx_reference,
        canonical_kpis=canonical_kpis)
    mixed_formulas = check_mixed_metric_formulas(
        blob, canonical_kpis=canonical_kpis)
    role_corrupt = check_arabic_role_corruption(blob)
    pdf_layout_ok = True
    pdf_layout_defects: List[str] = []
    if route == 'pdf':
        pdf_layout_ok, pdf_layout_defects = check_pdf_layout_semantic(
            blob, docx_text=docx_reference, pdf_bytes=pdf_bytes)

    road = check_roadmap_coverage(blob or '')
    kpi_scan = flat_kpi_kri_section_blob(blob) or blob or ''
    kpi_fams = _kpi_families_present(kpi_scan)
    missing_kpi = [f for f in REQUIRED_KPI_FAMILIES if f not in kpi_fams]
    canon_fams: set = set()
    if canonical_kpis.strip():
        canon_fams = set(_kpi_families_present(canonical_kpis))
        # Export parity applies only to families present in canonical KPI section.
        missing_kpi = [f for f in missing_kpi if f in canon_fams]

    blocking = list(substance.get('blocking_errors') or [])
    if pillar_dupes:
        blocking.append('pillar_duplicate_narratives')
    if pillar_generic and 'shallow_pillar_outputs' not in blocking:
        blocking.append('pillar_generic_outputs')
    blocking.extend(dup_metrics)
    blocking.extend(mixed_formulas)
    if role_corrupt:
        blocking.append('arabic_role_corruption')
    if not pdf_layout_ok:
        blocking.extend(pdf_layout_defects)
    kpi_surface = _kpi_export_surface_present(kpi_scan)
    if route == 'docx' and kpi_surface:
        for fam in missing_kpi:
            err = f'missing_kpi_family:{fam}'
            if err not in blocking:
                blocking.append(err)
    elif route == 'pdf' and docx_reference.strip():
        docx_kpi_scan = flat_kpi_kri_section_blob(docx_reference) or docx_reference
        docx_fams = set(_kpi_families_present(docx_kpi_scan))
        if _kpi_export_surface_present(docx_kpi_scan):
            for fam in missing_kpi:
                if fam in docx_fams:
                    continue
                err = f'missing_kpi_family:{fam}'
                if err not in blocking:
                    blocking.append(err)
        elif kpi_surface:
            for fam in missing_kpi:
                err = f'missing_kpi_family:{fam}'
                if err not in blocking:
                    blocking.append(err)
    elif route == 'pdf' and kpi_surface:
        for fam in missing_kpi:
            err = f'missing_kpi_family:{fam}'
            if err not in blocking:
                blocking.append(err)

    evidence = {
        'route_name': route,
        'pillar_owner_missing': substance.get('pillar_owner_missing') or [],
        'pillar_duplicate_narratives': pillar_dupes,
        'pillar_generic_outputs': pillar_generic,
        'roadmap_visible_row_count': substance.get('roadmap_visible_row_count') or 0,
        'roadmap_visible_family_count': _roadmap_family_count(blob),
        'roadmap_required_families_missing': (
            substance.get('roadmap_required_families_missing') or []),
        'roadmap_preview_docx_pdf_consistent': (
            substance.get('roadmap_preview_docx_pdf_consistent', True)),
        'duplicate_metric_labels': dup_metrics,
        'mixed_metric_formulas': mixed_formulas,
        'generic_risk_treatments': substance.get('risk_generic_treatments') or [],
        'pdf_layout_semantic_passed': pdf_layout_ok,
        'arabic_role_corruption': role_corrupt,
        'arabic_residues': list(dict.fromkeys(
            (substance.get('arabic_residues') or []) + role_corrupt)),
        'kpi_semantic_defects': substance.get('kpi_semantic_defects') or [],
        'traceability_bad_mappings': (
            substance.get('traceability_bad_mappings') or []),
        'content_substance_passed': not blocking,
        'blocking_errors': list(dict.fromkeys(blocking)),
    }
    return evidence


def _evaluate_canonical_sections(sections: Dict[str, str]) -> Dict[str, Any]:
    """Positive model on canonical section markdown (pre-export)."""
    blob = '\n\n'.join(
        str(v) for v in (sections or {}).values() if isinstance(v, str))
    blockers: List[str] = []
    section_results: Dict[str, Any] = {}

    vision = (sections or {}).get('vision', '') or ''
    so_rows = _count_so_objective_rows(vision)
    so_missing_fams, so_fam_present = check_so_families_present(vision)
    so_schema_defects = check_strategic_objectives_positive_model(vision)
    so_ok = (
        MIN_SO_OBJECTIVES <= so_rows <= MAX_SO_OBJECTIVES
        and not so_missing_fams
        and not so_schema_defects)
    if so_rows < MIN_SO_OBJECTIVES or so_rows > MAX_SO_OBJECTIVES:
        blockers.append(f'so_count_invalid:{so_rows}')
    if so_missing_fams:
        blockers.extend(f'so_family_missing:{f}' for f in so_missing_fams[:8])
    blockers.extend(so_schema_defects[:8])
    section_results['strategic_objectives'] = {
        'passed': so_ok,
        'row_count': so_rows,
        'families_present': so_fam_present,
        'missing_families': so_missing_fams,
        'schema_defects': so_schema_defects,
    }

    pillars = (sections or {}).get('pillars', '') or ''
    pillar_titles_found = sum(
        1 for t in REQUIRED_PILLAR_TITLES if t in pillars)
    pillar_defects = check_pillar_positive_model(pillars)
    pillars_ok = pillar_titles_found >= 4 and not pillar_defects
    if pillar_titles_found < 4:
        blockers.append(f'pillar_count_invalid:{pillar_titles_found}')
    blockers.extend(pillar_defects[:8])
    section_results['strategic_pillars'] = {
        'passed': pillars_ok,
        'titles_found': pillar_titles_found,
        'positive_model_defects': pillar_defects,
    }

    road = check_roadmap_coverage((sections or {}).get('roadmap', '') or blob)
    road_count = int(road.get('visible_row_count') or 0)
    road_ok = (
        MIN_ROADMAP_ROWS <= road_count <= MAX_ROADMAP_ROWS
        and not road.get('missing_families'))
    if not road_ok:
        blockers.append('roadmap_canonical_invalid')
    section_results['roadmap'] = {
        'passed': road_ok,
        'row_count': road_count,
        'missing_families': road.get('missing_families') or [],
    }

    kpi_text = (sections or {}).get('kpis', '') or blob
    kpi_chk = check_kpi_canonical(kpi_text)
    kpi_schema_defects = check_kpi_row_schema(kpi_text)
    kpi_ok = bool(kpi_chk.get('exported_kpi_canonical_valid')) and not kpi_schema_defects
    if not kpi_chk.get('exported_kpi_canonical_valid'):
        blockers.extend(kpi_chk.get('defects') or ['kpi_canonical_invalid'])
    blockers.extend(kpi_schema_defects[:6])
    section_results['kpi_kri'] = {
        'passed': kpi_ok,
        'check': kpi_chk,
        'row_schema_defects': kpi_schema_defects,
        'canonical_row_count': len(kpi_chk.get('duplicate_metrics') or []) + (
            kpi_chk.get('exported_kpi_table_count') or 0),
    }

    risk_blob = (sections or {}).get('confidence', '') or ''
    if _confidence_has_risk_register(risk_blob):
        risk_defects, risk_treatments = check_risk_register_schema(risk_blob)
        risk_generic = check_generic_risk_treatments(blob)
        risk_ok = not risk_generic and not risk_defects
        if risk_generic:
            blockers.append('risk_treatment_generic')
        blockers.extend(risk_defects[:8])
    else:
        risk_defects, risk_treatments = [], []
        risk_generic = check_generic_risk_treatments(blob)
        risk_ok = not risk_generic
        if risk_generic:
            blockers.append('risk_treatment_generic')
    section_results['risk_register'] = {
        'passed': risk_ok,
        'generic_treatments': risk_generic,
        'schema_defects': risk_defects,
        'treatments': risk_treatments,
        'risk_count': len(risk_treatments),
    }

    trace_bad = check_traceability_bad_mappings(blob)
    trace_report = build_traceability_mapping_report(blob)
    trace_ok = not trace_bad
    if not trace_ok:
        blockers.extend(trace_bad[:6])
    section_results['traceability'] = {
        'passed': trace_ok,
        'bad_mappings': trace_bad,
        'mapping_table': trace_report,
    }

    arabic_tok = check_arabic_tokenization_quality(blob)
    arabic_ok = arabic_tok.get('passed', False)
    if not arabic_ok:
        blockers.append('arabic_canonical_invalid')
    section_results['arabic'] = {
        'passed': arabic_ok,
        'tokenization': arabic_tok,
    }

    return {
        'passed': not blockers,
        'blocking_errors': list(dict.fromkeys(blockers)),
        'section_results': section_results,
        'risk_treatments': risk_treatments,
        'traceability_mapping_table': trace_report,
        'arabic_tokenization_report': arabic_tok,
    }


def canonical_kpi_families_complete(canonical_kpis: str) -> bool:
    """True when canonical KPI markdown includes every required family."""
    fams = set(_kpi_families_present(canonical_kpis or ''))
    return all(f in fams for f in REQUIRED_KPI_FAMILIES)


def evaluate_document_quality(
        *,
        canonical_artifact: Any = None,
        legacy_sections: Optional[Dict[str, str]] = None,
        render_tree: Any = None,
        extracted_preview_text: str = '',
        extracted_docx_text: str = '',
        extracted_pdf_text: str = '',
        pdf_bytes: bytes = b'',
) -> Dict[str, Any]:
    """Single authority compiler for Cyber Arabic Technical board-ready quality."""
    sections = dict(legacy_sections or {})
    if canonical_artifact is not None:
        if hasattr(canonical_artifact, 'legacy_sections'):
            sections.update(dict(canonical_artifact.legacy_sections or {}))
        elif isinstance(canonical_artifact, dict):
            sections.update(dict(canonical_artifact.get('sections') or {}))

    canonical_eval = _evaluate_canonical_sections(sections)
    canonical_kpis = (sections or {}).get('kpis', '') or ''

    peer_counts: Dict[str, int] = {}
    route_evidence: Dict[str, Any] = {}
    if extracted_preview_text.strip():
        route_evidence['preview'] = _evaluate_visible_route(
            extracted_preview_text, route='preview')
        peer_counts['preview'] = route_evidence['preview'].get(
            'roadmap_visible_row_count') or 0
    if extracted_docx_text.strip():
        route_evidence['docx'] = _evaluate_visible_route(
            extracted_docx_text, route='docx',
            peer_row_counts=peer_counts)
        peer_counts['docx'] = route_evidence['docx'].get(
            'roadmap_visible_row_count') or 0
    if extracted_pdf_text.strip() or pdf_bytes:
        route_evidence['pdf'] = _evaluate_visible_route(
            extracted_pdf_text, route='pdf',
            pdf_bytes=pdf_bytes,
            peer_row_counts=peer_counts,
            docx_reference=extracted_docx_text)
        peer_counts['pdf'] = route_evidence['pdf'].get(
            'roadmap_visible_row_count') or 0

    # Re-run parity with full peer set
    for route_name, text in (
            ('preview', extracted_preview_text),
            ('docx', extracted_docx_text),
            ('pdf', extracted_pdf_text)):
        if text.strip():
            route_evidence[route_name] = _evaluate_visible_route(
                text,
                route=route_name,
                pdf_bytes=pdf_bytes if route_name == 'pdf' else b'',
                peer_row_counts=peer_counts,
                docx_reference=extracted_docx_text,
                canonical_kpis=canonical_kpis)

    blocking: List[str] = list(canonical_eval.get('blocking_errors') or [])
    for route, ev in route_evidence.items():
        if not ev.get('content_substance_passed'):
            for err in ev.get('blocking_errors') or []:
                blocking.append(f'{route}:{err}')

    counts = [c for c in peer_counts.values() if c > 0]
    equivalence_ok = True
    if len(counts) >= 2:
        equivalence_ok = max(counts) - min(counts) <= 2
    if not equivalence_ok:
        blocking.append('preview_docx_pdf_roadmap_drift')

    _DRIFT_SUBSTANCE_KEYS = (
        'shallow_pillar', 'pillar_owner', 'pillar_duplicate', 'duplicate_',
        'conflicting_kpi', 'dlp_encryption', 'third_party', 'trace_gap',
        'mixed_metric', 'kpi_semantic', 'arabic_residue', 'arabic_role',
    )

    def _substance_blockers(ev: Dict[str, Any]) -> set:
        return {
            err for err in (ev.get('blocking_errors') or [])
            if any(k in err for k in _DRIFT_SUBSTANCE_KEYS)
        }

    if 'docx' in route_evidence and 'pdf' in route_evidence:
        docx_sub = _substance_blockers(route_evidence['docx'])
        pdf_sub = _substance_blockers(route_evidence['pdf'])
        if docx_sub != pdf_sub:
            blocking.append('preview_docx_pdf_semantic_drift')
            equivalence_ok = False

    visible_hashes = {
        'preview': _sha256_text(extracted_preview_text),
        'docx': _sha256_text(extracted_docx_text),
        'pdf': _sha256_text(extracted_pdf_text),
    }
    if render_tree is not None and hasattr(render_tree, 'render_tree_hash'):
        visible_hashes['render_tree'] = render_tree.render_tree_hash

    passed = not blocking
    result = {
        'passed': passed,
        'section_results': canonical_eval.get('section_results') or {},
        'route_evidence': route_evidence,
        'blocking_errors': list(dict.fromkeys(blocking)),
        'evidence': {
            'canonical': canonical_eval,
            'routes': route_evidence,
            'roadmap_family_coverage': {
                route: ev.get('roadmap_visible_family_count')
                for route, ev in route_evidence.items()
            },
            'equivalence_ok': equivalence_ok,
            'risk_treatments_list': canonical_eval.get('risk_treatments') or [],
            'traceability_mapping_table': (
                canonical_eval.get('traceability_mapping_table') or []),
            'arabic_tokenization_report': (
                canonical_eval.get('arabic_tokenization_report') or {}),
            'kpi_canonical_model': (
                (canonical_eval.get('section_results') or {})
                .get('kpi_kri', {}).get('check') or {}),
        },
        'visible_text_hashes': visible_hashes,
        'national_launch_ready': passed,
        'export_return_allowed': passed,
        'release_ready_final_passed': passed,
    }
    _emit_quality_compiler({
        'passed': passed,
        'blocking_errors': result['blocking_errors'][:12],
        'route_count': len(route_evidence),
        'equivalence_ok': equivalence_ok,
    })
    return result


_SPEC_TO_PRCY88 = {v: k for k, v in _PRCY88_SO_TO_SPEC.items()}


def _inject_missing_dqs_so_families(
        sections: Dict[str, str],
        *,
        lang: str = 'ar',
        backend: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, str], List[str]]:
    """Insert catalog SO rows for DQS-required families missing from vision."""
    backend = backend or {}
    app_mod = backend.get('app_module')
    if not app_mod:
        return sections, []
    try:
        from cyber_board_ready_prcy88 import (
            PRCY88_SO_CATALOG_AR,
            _detect_so_family,
            _parse_so_specs,
            _render_so_table,
        )
    except Exception:  # noqa: BLE001
        return sections, []
    vision = sections.get('vision', '') or ''
    missing, _ = check_so_families_present(vision)
    if not missing:
        return sections, []
    specs, _ = _parse_so_specs(app_mod, vision)
    if not specs:
        return sections, []
    repairs: List[str] = []
    replace_priority = (
        'compliance_ecc_dcc', 'governance_ciso', 'soc_monitoring_detection',
        'iam_pam_mfa', 'incident_response_csirt', 'vulnerability_management',
        'data_protection_dcc', 'awareness_or_resilience',
    )
    for spec_fam in missing:
        prcy = _SPEC_TO_PRCY88.get(spec_fam)
        cat = PRCY88_SO_CATALOG_AR.get(prcy or '')
        if not cat:
            continue
        target_idx = None
        for pri in replace_priority:
            if pri == prcy:
                continue
            for idx, spec in enumerate(specs):
                if _detect_so_family(spec.get('objective') or '') == pri:
                    target_idx = idx
                    break
            if target_idx is not None:
                break
        if target_idx is None and len(specs) >= MAX_SO_OBJECTIVES:
            target_idx = len(specs) - 1
        elif target_idx is None:
            specs.append({})
            target_idx = len(specs) - 1
        specs[target_idx].update({
            'row_index': target_idx + 1,
            'objective': cat[0],
            'measurable_target': cat[1],
            'rationale': cat[2],
            'timeframe': cat[3],
            'source': f'dqs_insert_{spec_fam}',
        })
        repairs.append(f'dqs:so_family_insert:{spec_fam}')
    for i, spec in enumerate(specs, 1):
        spec['row_index'] = i
    while len(specs) > MAX_SO_OBJECTIVES:
        specs.pop()
    out = dict(sections)
    out['vision'] = _render_so_table(app_mod, vision, specs, lang)
    return out, repairs


def repair_document_quality_sections(
        sections: Dict[str, str],
        *,
        lang: str = 'ar',
        domain: str = 'cyber',
        backend: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, str], List[str]]:
    """Canonical repairs for DQS compiler blockers before re-export."""
    backend = dict(backend or {})
    repairs: List[str] = []
    out = dict(sections or {})
    fws = backend.get('selected_frameworks') or []

    try:
        from release_engine.arabic_language_gate import apply_arabic_final_gate
        from release_engine.rendered_evidence_validator import _repair_arabic_blob
        out = {
            k: _repair_arabic_blob(v) if isinstance(v, str) else v
            for k, v in out.items()}
        out, _ = apply_arabic_final_gate(out, lang=lang)
        repairs.append('dqs:arabic_final_gate')
    except Exception:  # noqa: BLE001
        pass

    if backend.get('baseline_strategic_objectives'):
        try:
            out, _ = backend['baseline_strategic_objectives'](out, lang, fws)
            repairs.append('dqs:baseline_strategic_objectives')
        except Exception:  # noqa: BLE001
            pass

    out, so_rep = _inject_missing_dqs_so_families(
        out, lang=lang, backend=backend)
    repairs.extend(so_rep)

    try:
        from release_engine.kpi_model import (
            _apply_inline_kpi_repairs,
            finalize_kpi_semantics,
            repair_kpi_canonical_families,
        )
        out, _ = finalize_kpi_semantics(
            out, lang=lang, backend=backend)
        out, kpi_diag = repair_kpi_canonical_families(
            out, lang=lang, backend=backend)
        if not kpi_diag.get('kpi_canonical_repair_passed'):
            repairs.append('dqs:kpi_canonical_repair_blocked')
        else:
            repairs.append('dqs:kpi_canonical_families_repaired')
        out, _ = _apply_inline_kpi_repairs(out)
        repairs.append('dqs:kpi_percent_formula_repaired')
    except Exception:  # noqa: BLE001
        pass

    try:
        from release_engine.traceability_substance_model import (
            repair_traceability_canonical_families,
        )
        out, trace_diag = repair_traceability_canonical_families(
            out, lang=lang, backend=backend)
        if trace_diag.get('action_taken') != 'no_changes':
            repairs.append('dqs:traceability_canonical_families_repaired')
    except Exception:  # noqa: BLE001
        pass

    try:
        from release_engine.rel31_content_substance_checks import (
            repair_sections_generic_gap_treatments,
        )
        out = repair_sections_generic_gap_treatments(out)
        repairs.append('dqs:generic_gap_treatments_diversified')
    except Exception:  # noqa: BLE001
        pass

    try:
        from release_engine.roadmap_model import finalize_roadmap
        out, rm_diag = finalize_roadmap(
            out,
            lang=lang,
            domain=domain,
            selected_frameworks=fws,
            backend=backend)
        if (rm_diag.get('action_taken') or '').strip() not in (
                '', 'no_changes', 'skipped_non_cyber'):
            repairs.append('dqs:roadmap_owners_finalized')
    except Exception:  # noqa: BLE001
        pass

    try:
        from release_engine.risk_treatment_model import (
            finalize_risk_treatment,
            trim_risk_register_rows,
        )
        out, _ = finalize_risk_treatment(out, lang=lang)
        out, trimmed = trim_risk_register_rows(out, max_rows=MAX_RISKS)
        if trimmed:
            repairs.append('dqs:risk_register_trimmed')
    except Exception:  # noqa: BLE001
        pass

    try:
        from release_engine.rendered_evidence_validator import (
            repair_sections_for_rendered_evidence,
        )
        out = repair_sections_for_rendered_evidence(
            out, lang=lang, domain=domain, backend=backend)
        repairs.append('dqs:rendered_evidence_pipeline')
    except Exception:  # noqa: BLE001
        pass

    return out, list(dict.fromkeys(repairs))


def document_quality_blockers(result: Dict[str, Any]) -> List[str]:
    """Standardized blocker codes for generation contract."""
    return [
        f'rel3_document_quality_failed:{e}'
        for e in (result.get('blocking_errors') or [])
    ]
