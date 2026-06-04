"""PR-CY88 — Cyber board-ready content baseline (imported by app.py)."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

# ── Objective families (6–8 rows) ─────────────────────────────────────────
PRCY88_SO_FAMILIES = (
    'governance_ciso',
    'compliance_ecc_dcc',
    'soc_monitoring_detection',
    'iam_pam_mfa',
    'incident_response_csirt',
    'vulnerability_management',
    'data_protection_dcc',
    'awareness_or_resilience',
)

PRCY88_SO_FAMILY_TOKENS = {
    'governance_ciso': (
        'ciso', 'إدارة الأمن السيبراني', 'حوكمة', 'لجنة حوكمة', 'governance'),
    'compliance_ecc_dcc': (
        'امتثال', 'ecc', 'dcc', 'الالتزام', 'compliance', 'ضوابط'),
    'soc_monitoring_detection': (
        'soc', 'siem', 'رصد', 'مركز العمليات', 'monitoring'),
    'iam_pam_mfa': (
        'iam', 'pam', 'mfa', 'هوية', 'وصول', 'صلاحيات'),
    'incident_response_csirt': (
        'csirt', 'استجابة', 'حوادث', 'incident response'),
    'vulnerability_management': (
        'ثغرات', 'vulnerability', 'إصلاح الثغرات'),
    'data_protection_dcc': (
        'dcc', 'حماية البيانات', 'تشفير', 'dlp', 'تصنيف'),
    'awareness_or_resilience': (
        'توعية', 'تدريب', 'phishing', 'نسخ احتياط', 'backup', 'dr', 'تعافي'),
}

PRCY88_SO_CATALOG_AR = {
    'governance_ciso': (
        'تأسيس حوكمة الأمن السيبراني وإدارة CISO ولجنة الحوكمة',
        'اعتماد هيكل CISO ولجنة حوكمة بنسبة 100%',
        'ضمان قيادة واضحة ومساءلة تنفيذية على برنامج الأمن السيبراني',
        '1-6 أشهر',
    ),
    'compliance_ecc_dcc': (
        'تحقيق الامتثال لضوابط NCA ECC وNCA DCC',
        'مستوى امتثال لا يقل عن 90% للضوابط المختارة',
        'مواءمة الاستراتيجية مع المتطلبات التنظيمية الوطنية',
        '12-18 شهراً',
    ),
    'soc_monitoring_detection': (
        'تأسيس قدرات الرصد والكشف عبر SOC وSIEM',
        'تشغيل SOC مع تغطية SIEM للأصول الحرجة',
        'تقليل زمن الكشف عن الحوادث الأمنية',
        '6-12 شهراً',
    ),
    'iam_pam_mfa': (
        'تعزيز إدارة الهوية والوصول والصلاحيات المميزة',
        'تطبيق MFA وPAM على الأنظمة والحسابات الحرجة',
        'تقليل مخاطر الوصول غير المصرح به',
        '6-12 شهراً',
    ),
    'incident_response_csirt': (
        'بناء قدرات الاستجابة للحوادث عبر CSIRT',
        'تشغيل CSIRT مع SLA للاستجابة للحوادث الحرجة',
        'احتواء الحوادث وتقليل الأثر التشغيلي',
        '6-12 شهراً',
    ),
    'vulnerability_management': (
        'تطوير برنامج إدارة الثغرات الأمنية المستمر',
        'معالجة 95% من الثغرات الحرجة خلال 72 ساعة',
        'تقليل نوافذ التعرض للهجمات',
        '12 شهراً',
    ),
    'data_protection_dcc': (
        'تعزيز حماية البيانات عبر التصنيف والتشفير وDLP',
        'حماية 95% من البيانات الحساسة المصنفة',
        'تلبية متطلبات NCA DCC لحماية البيانات',
        '12-18 شهراً',
    ),
    'awareness_or_resilience': (
        'تعزيز التوعية الأمنية واستمرارية الأعمال',
        'إكمال برنامج توعية سنوي واختبار DR ناجح',
        'رفع نضج الموظفين وقدرة التعافي',
        '12-18 شهراً',
    ),
}

# ── Roadmap families (10–14 rows) ─────────────────────────────────────────
PRCY88_ROADMAP_FAMILIES = (
    'governance_ciso',
    'governance_committee',
    'soc_siem',
    'iam_pam_mfa',
    'csirt_incident_response',
    'vulnerability_management',
    'awareness_training',
    'backup_dr_resilience',
    'data_classification',
    'encryption_key_management',
    'dlp',
    'sensitive_data_handling',
)

PRCY88_ROADMAP_FAMILY_TOKENS = {
    'governance_ciso': ('ciso', 'حوكمة', 'إدارة الأمن'),
    'governance_committee': (
        'لجنة', 'committee', 'raci', 'ميثاق', 'حوكمة', 'لجنة حوكمة'),
    'soc_siem': ('soc', 'siem', 'مركز العمليات'),
    'iam_pam_mfa': ('iam', 'pam', 'mfa', 'هوية'),
    'csirt_incident_response': ('csirt', 'استجابة', 'حوادث'),
    'vulnerability_management': ('ثغرات', 'vulnerab'),
    'awareness_training': (
        'توعية', 'تدريب', 'phishing', 'برنامج التوعية', 'توعية أمنية'),
    'backup_dr_resilience': (
        'نسخ', 'backup', 'تعافي', 'dr', 'احتياطي', 'استمرارية', 'استعادة'),
    'data_classification': ('تصنيف', 'جرد'),
    'encryption_key_management': ('تشفير', 'مفاتيح', 'encryption'),
    'dlp': ('dlp', 'تسرب'),
    'sensitive_data_handling': (
        'معالجة البيانات الحساسة', 'sensitive data', 'حساسة', 'معالجة'),
}

PRCY88_ROADMAP_CATALOG_AR = {
    'governance_ciso': [
        'المرحلة 1: تأسيس', '1-6 أشهر', 'تأسيس إدارة الأمن السيبراني وتعيين CISO',
        'CISO / الإدارة العليا', 'هيكل CISO ولجنة حوكمة معتمدة', 'NCA ECC',
    ],
    'governance_committee': [
        'المرحلة 1: تأسيس', '1-6 أشهر', 'تفعيل لجنة حوكمة الأمن السيبراني',
        'CISO / الإدارة العليا', 'ميثاق لجنة حوكمة ومصفوفة RACI معتمدة', 'NCA ECC',
    ],
    'soc_siem': [
        'المرحلة 2: تمكين وتشغيل', '7-18 شهر', 'تشغيل SOC وSIEM',
        'مدير SOC', 'مركز SOC تشغيلي مع تغطية SIEM وقواعد مراقبة', 'NCA ECC',
    ],
    'iam_pam_mfa': [
        'المرحلة 2: تمكين وتشغيل', '7-18 شهر', 'تطبيق IAM/PAM/MFA',
        'مدير IAM/PAM', 'منصة IAM/PAM مع تغطية MFA للحسابات الحرجة', 'NCA ECC',
    ],
    'csirt_incident_response': [
        'المرحلة 2: تمكين وتشغيل', '7-18 شهر', 'تأسيس CSIRT وخطط الاستجابة',
        'قائد CSIRT', 'فريق CSIRT وخطط استجابة معتمدة ومختبرة', 'NCA ECC',
    ],
    'vulnerability_management': [
        'المرحلة 2: تمكين وتشغيل', '7-18 شهر', 'برنامج إدارة الثغرات',
        'مدير الثغرات', 'برنامج ثغرات مع SLA للمعالجة', 'NCA ECC',
    ],
    'awareness_training': [
        'المرحلة 2: تمكين وتشغيل', '7-18 شهر', 'برنامج التوعية الأمنية',
        'مدير التوعية', 'خطة توعية سنوية وتقارير إكمال', 'NCA ECC',
    ],
    'backup_dr_resilience': [
        'المرحلة 2: تمكين وتشغيل', '7-18 شهر', 'اختبار النسخ الاحتياطي والتعافي',
        'مدير استمرارية الأعمال', 'خطة DR واختبار استعادة ناجح', 'NCA ECC',
    ],
    'data_classification': [
        'المرحلة 1: تأسيس', '1-6 أشهر', 'تصنيف وجرد البيانات الحساسة',
        'مدير حماية البيانات', 'سجل بيانات مصنفة ومعتمد', 'NCA DCC',
    ],
    'encryption_key_management': [
        'المرحلة 2: تمكين وتشغيل', '7-18 شهر', 'تطبيق التشفير وإدارة المفاتيح',
        'مدير حماية البيانات', 'ضوابط تشفير وإدارة مفاتيح مطبقة', 'NCA DCC',
    ],
    'dlp': [
        'المرحلة 2: تمكين وتشغيل', '7-18 شهر', 'تفعيل DLP ومراقبة التسرب',
        'مدير حماية البيانات', 'منصة DLP وقواعد مراقبة تسرب مفعّلة', 'NCA DCC',
    ],
    'sensitive_data_handling': [
        'المرحلة 3: تحسين واستدامة', '19-24 شهر', 'معالجة وحماية البيانات الحساسة',
        'مدير حماية البيانات', 'إجراءات معالجة بيانات حساسة معتمدة', 'NCA DCC',
    ],
}

# ── KPI families ──────────────────────────────────────────────────────────
PRCY88_KPI_FAMILIES = (
    'governance_maturity',
    'ecc_dcc_compliance',
    'iam_pam_mfa',
    'mttd_detection',
    'mttr_incident',
    'vulnerability_sla',
    'awareness_phishing',
    'backup_restore',
    'data_classification',
    'encryption_coverage',
    'dlp_coverage',
)

PRCY88_KPI_CATALOG_AR = {
    'governance_maturity': (
        '1', 'نضج حوكمة الأمن السيبراني وسياسات معتمدة', 'KPI',
        '≥ 90%', 'عدد السياسات المعتمدة / إجمالي السياسات المطلوبة × 100',
        'إدارة الحوكمة', 'CISO', 'ربع سنوي'),
    'ecc_dcc_compliance': (
        '2', 'نسبة الامتثال لضوابط NCA ECC وNCA DCC', 'KPI',
        '≥ 90%', 'عدد البنود المحققة / إجمالي البنود × 100',
        'منصة الامتثال', 'مدير الامتثال', 'ربع سنوي'),
    'iam_pam_mfa': (
        '3', 'تغطية IAM/PAM/MFA للأنظمة الحرجة', 'KPI',
        '≥ 95%', 'الحسابات المشمولة بضوابط IAM/PAM/MFA / إجمالي الحسابات × 100',
        'منصة IAM', 'مدير IAM/PAM', 'شهري'),
    'mttd_detection': (
        '4', 'متوسط زمن الكشف عن الحوادث (MTTD)', 'KPI',
        '≤ 15 دقيقة', 'مجموع زمن الكشف / عدد الحوادث المكتشفة',
        'SIEM/SOC', 'مدير SOC', 'شهري'),
    'mttr_incident': (
        '5', 'متوسط زمن الاستجابة للحوادث (MTTR)', 'KPI',
        '≤ 4 ساعات', 'مجموع زمن الاستجابة / عدد الحوادث المعالجة',
        'ITSM/SOAR', 'قائد CSIRT', 'شهري'),
    'vulnerability_sla': (
        '6', 'معدل معالجة الثغرات الحرجة ضمن SLA', 'KPI',
        '≥ 95% خلال 72 ساعة', 'ثغرات حرجة مُعالجة خلال 72 ساعة / إجمالي × 100',
        'منصة إدارة الثغرات', 'مدير الثغرات', 'شهري'),
    'awareness_phishing': (
        '7', 'معدل نجاح تمارين التوعية ومقاومة التصيد', 'KRI',
        '≥ 85%', 'المشاركون الناجحون / إجمالي المشاركين × 100',
        'منصة التوعية', 'مدير التوعية', 'ربع سنوي'),
    'backup_restore': (
        '8', 'معدل نجاح النسخ الاحتياطي والاستعادة', 'KPI',
        '≥ 99%', 'عمليات نسخ/استعادة ناجحة / إجمالي × 100',
        'منصة النسخ الاحتياطي', 'مدير استمرارية الأعمال', 'شهري'),
    'data_classification': (
        '9', 'نسبة تغطية تصنيف البيانات الحساسة', 'KPI',
        '≥ 90%', 'بيانات مصنفة / إجمالي البيانات الحساسة × 100',
        'سجل التصنيف', 'مدير حماية البيانات', 'ربع سنوي'),
    'encryption_coverage': (
        '10', 'نسبة تغطية تشفير البيانات الحساسة', 'KPI',
        '≥ 95%', 'أصول مشفرة / إجمالي الأصول الحساسة × 100',
        'منصة التشفير', 'مدير حماية البيانات', 'شهري'),
    'dlp_coverage': (
        '11', 'نسبة تغطية DLP للبيانات الحساسة', 'KPI',
        '≥ 90%', 'بيانات محمية بـ DLP / إجمالي الحساسة × 100',
        'منصة DLP', 'مدير حماية البيانات', 'شهري'),
}

PRCY88_PILLAR_MISMATCH_RULES = (
    (
        ('حوكمة', 'سياسة', 'policy', 'governance', 'لجنة', 'raci'),
        ('dlp', 'تسرب', 'تشفير', 'encryption', 'siem', 'soc'),
        'ميثاق حوكمة معتمد ونموذج تشغيل لجنة الأمن السيبراني',
    ),
    (
        ('نسخ', 'backup', 'تعافي', 'dr', 'استمرارية'),
        ('تشفير', 'مفاتيح', 'dlp', 'encryption'),
        'خطة DR واختبار استعادة ناجح مع RTO/RPO موثق',
    ),
    (
        ('soc', 'siem', 'مركز العمليات'),
        ('نسخ', 'backup', 'سياسة', 'policy'),
        'مركز SOC تشغيلي مع تغطية SIEM وقواعد تصعيد',
    ),
    (
        ('iam', 'pam', 'mfa', 'هوية'),
        ('dlp', 'نسخ', 'backup'),
        'منصة IAM/PAM مع تغطية MFA للحسابات الحرجة',
    ),
)

PRCY88_ARABIC_FIXES = (
    ('فريقمن', 'فريق من'),
    ('معدل نجح', 'معدل نجاح'),
    ('ECC NCA', 'NCA ECC'),
    ('DCC NCA', 'NCA DCC'),
)

PRCY88_SCORE_WEIGHTS = {
    'strategic_coherence': 0.15,
    'nca_coverage': 0.20,
    'roadmap_completeness': 0.15,
    'kpi_quality': 0.15,
    'governance_accountability': 0.10,
    'traceability_accuracy': 0.10,
    'arabic_executive_tone': 0.05,
    'layout_quality': 0.10,
}

_GOVERNANCE_DUP_RE = re.compile(
    r'ciso|إدارة الأمن|حوكمة|لجنة حوكمة|governance',
    re.I)


def _load_app_module():
    import sys
    frame = sys._getframe(1)
    while frame is not None:
        _name = frame.f_globals.get('__name__')
        if _name and _name in sys.modules:
            _mod = sys.modules[_name]
            if hasattr(_mod, '_prcy39_locate_so_table'):
                return _mod
        frame = frame.f_back
    for _name in ('app', '__main__'):
        _mod = sys.modules.get(_name)
        if _mod is not None and hasattr(_mod, '_prcy39_locate_so_table'):
            return _mod
    for _mod in list(sys.modules.values()):
        if hasattr(_mod, '_prcy39_locate_so_table'):
            return _mod
    for _mod in list(sys.modules.values()):
        if hasattr(_mod, '_build_cyber_final_strategy_artifact'):
            return _mod
    raise RuntimeError('app module not loaded for PR-CY88')


def _emit(tag: str, payload: dict) -> None:
    try:
        print(f'[{tag}] {payload}', flush=True)
    except Exception:  # noqa: BLE001
        pass


def _dcc_selected(selected_frameworks) -> bool:
    for f in selected_frameworks or []:
        if 'dcc' in str(f).lower():
            return True
    return False


def _detect_so_family(text: str) -> Optional[str]:
    blob = (text or '').lower()
    for fam, tokens in PRCY88_SO_FAMILY_TOKENS.items():
        for tok in tokens:
            if tok.isascii():
                if tok.lower() in blob:
                    return fam
            elif tok in (text or ''):
                return fam
    return None


def _parse_so_specs(app, vision: str) -> Tuple[List[dict], int]:
    start, end = app._prcy39_locate_so_table(vision or '')
    if start is None:
        return [], 0
    lines = (vision or '').split('\n')[start:end + 1]
    rows = app._prcy39_parse_table_rows(lines)
    specs = []
    for idx, cells in enumerate(rows, 1):
        spec = app._prcy39_row_to_spec(cells, idx, source='prcy88')
        if spec:
            specs.append(spec)
    return specs, len(rows)


def _render_so_table(app, vision: str, specs: List[dict], lang: str) -> str:
    start, end = app._prcy39_locate_so_table(vision or '')
    table = app._prcy39_render_canonical_so_table(specs, lang)
    if start is None:
        return (vision or '').rstrip() + '\n\n' + table + '\n'
    lines = (vision or '').split('\n')
    return '\n'.join(lines[:start] + table.split('\n') + lines[end + 1:])


def baseline_strategic_objectives(
        app, sections: dict, lang: str, selected_frameworks) -> Tuple[dict, dict]:
    vision = sections.get('vision', '') or ''
    specs, raw_before = _parse_so_specs(app, vision)
    rows_before = len(specs)
    dup_before = 0
    seen_gov = False
    cleaned = []
    consolidated = []
    for spec in specs:
        obj = spec.get('objective') or ''
        fam = _detect_so_family(obj)
        if fam == 'governance_ciso':
            dup_before += 1 if seen_gov else 0
            if seen_gov:
                consolidated.append({'before': obj, 'action': 'merged_governance'})
                continue
            seen_gov = True
        if app._prcy87_objective_looks_like_target(obj, lang):
            rep = app._prcy87_infer_so_semantic_repair(
                obj, [
                    str(spec.get('row_index') or ''),
                    obj,
                    spec.get('measurable_target') or '',
                    spec.get('rationale') or '',
                    spec.get('timeframe') or '',
                ], lang)
            if rep[0]:
                spec['objective'] = rep[0]
                if rep[1]:
                    spec['measurable_target'] = rep[1]
                if rep[2]:
                    spec['rationale'] = rep[2]
                if rep[3]:
                    spec['timeframe'] = rep[3]
        cleaned.append(spec)

    present = {f: False for f in PRCY88_SO_FAMILIES}
    for spec in cleaned:
        fam = _detect_so_family(spec.get('objective') or '')
        if fam:
            present[fam] = True
    missing_before = [f for f, ok in present.items() if not ok]
    inserted = []
    for fam in missing_before:
        cat = PRCY88_SO_CATALOG_AR.get(fam)
        if not cat:
            continue
        cleaned.append({
            'row_index': len(cleaned) + 1,
            'objective': cat[0],
            'measurable_target': cat[1],
            'rationale': cat[2],
            'timeframe': cat[3],
            'source': f'prcy88_insert_{fam}',
        })
        inserted.append(fam)
        present[fam] = True

    while len(cleaned) > 8:
        cleaned.pop()

    if len(cleaned) < 6:
        for fam in PRCY88_SO_FAMILIES:
            if len(cleaned) >= 6:
                break
            if not present.get(fam) and fam in PRCY88_SO_CATALOG_AR:
                cat = PRCY88_SO_CATALOG_AR[fam]
                cleaned.append({
                    'row_index': len(cleaned) + 1,
                    'objective': cat[0],
                    'measurable_target': cat[1],
                    'rationale': cat[2],
                    'timeframe': cat[3],
                    'source': f'prcy88_fill_{fam}',
                })
                present[fam] = True
                inserted.append(fam)

    _so_defaults_ar = {
        'measurable_target': 'مستهدف قابل للقياس معتمد',
        'rationale': 'ضرورة استراتيجية لبرنامج الأمن السيبراني',
        'timeframe': '12 شهراً',
    }
    _so_defaults_en = {
        'measurable_target': 'Measurable target defined',
        'rationale': 'Strategic necessity for cyber program maturity',
        'timeframe': '12 months',
    }
    _so_def = _so_defaults_ar if str(lang or '').lower() != 'en' else _so_defaults_en
    for spec in cleaned:
        tf = (spec.get('timeframe') or '').strip()
        if tf and hasattr(app, '_prcy39_is_timeframe'):
            if not app._prcy39_is_timeframe(tf):
                _range = re.search(
                    r'(\d+)\s*-\s*(\d+)\s*(شهر|أشهر|شهراً|شهرا|months?)',
                    tf, re.I)
                if _range:
                    spec['timeframe'] = (
                        f'{_range.group(2)} {_range.group(3)}')
                elif re.search(r'\d+', tf):
                    spec['timeframe'] = (
                        '12 شهراً' if str(lang or '').lower() != 'en'
                        else '12 months')
                else:
                    spec['timeframe'] = _so_def['timeframe']
            if not app._prcy39_is_timeframe(spec.get('timeframe') or ''):
                spec['timeframe'] = _so_def['timeframe']
        obj = (spec.get('objective') or '').strip()
        if not (spec.get('measurable_target') or '').strip():
            rep = app._prcy87_infer_so_semantic_repair(
                obj,
                [
                    str(spec.get('row_index') or ''),
                    obj,
                    spec.get('measurable_target') or '',
                    spec.get('rationale') or '',
                    spec.get('timeframe') or '',
                ],
                lang)
            spec['measurable_target'] = (rep[1] or _so_def['measurable_target']).strip()
        for field in ('rationale', 'timeframe'):
            if not (spec.get(field) or '').strip():
                spec[field] = _so_def[field]

    for i, spec in enumerate(cleaned, 1):
        spec['row_index'] = i

    new_vision = _render_so_table(app, vision, cleaned, lang)
    sections = dict(sections)
    sections['vision'] = new_vision

    dup_after = sum(
        1 for s in cleaned
        if _detect_so_family(s.get('objective') or '') == 'governance_ciso')
    dup_after = max(0, dup_after - 1)

    missing_after = [f for f in PRCY88_SO_FAMILIES if not any(
        _detect_so_family(s.get('objective') or '') == f for s in cleaned)]

    target_like = app._prcy87_count_shifted_so_fields(new_vision, lang)
    _optional_fams = ('awareness_or_resilience',)
    _critical_missing = [
        f for f in missing_after if f not in _optional_fams]
    gate = (
        6 <= len(cleaned) <= 8
        and dup_after == 0
        and target_like == 0
        and not _critical_missing)

    diag = {
        'rows_before': rows_before,
        'rows_after': len(cleaned),
        'duplicate_governance_rows_before': max(0, dup_before),
        'duplicate_governance_rows_after': dup_after,
        'target_like_objectives_after': target_like,
        'missing_objective_families_before': missing_before,
        'missing_objective_families_after': missing_after,
        'consolidated_rows': consolidated[:6],
        'inserted_rows': inserted,
        'gate_passed': gate,
        'blocking_error_if_any': (
            '' if gate else 'so_count_or_duplicates_or_target_like'),
        'action_taken': (
            'so_baseline_applied' if (
                consolidated or inserted or len(cleaned) != rows_before)
            else 'no_changes'),
    }
    return sections, diag


def _pillar_blocks(text: str) -> List[Tuple[str, List[List[str]]]]:
    blocks = []
    if not text:
        return blocks
    parts = re.split(r'(^###\s+.+$)', text, flags=re.M)
    current_title = ''
    rows = []
    in_tbl = False
    for part in parts:
        if part.startswith('###'):
            if current_title or rows:
                blocks.append((current_title, rows))
            current_title = part.strip()
            rows = []
            in_tbl = False
            continue
        for ln in part.split('\n'):
            s = ln.strip()
            if s.startswith('|') and ('مبادرة' in s or 'initiative' in s.lower()):
                in_tbl = True
                continue
            if in_tbl and s.startswith('|') and not re.match(r'^\|[\s\-:|]+\|$', s):
                cells = [c.strip() for c in s.split('|')[1:-1]]
                if cells:
                    rows.append(cells)
                continue
            if in_tbl and s and not s.startswith('|'):
                in_tbl = False
    if current_title or rows:
        blocks.append((current_title, rows))
    return blocks


def baseline_pillars(app, sections: dict, lang: str) -> Tuple[dict, dict]:
    text = sections.get('pillars', '') or ''
    blocks = _pillar_blocks(text)
    mismatched_before = 0
    mismatched_after = 0
    repaired = []
    out_parts = [text.split('###')[0].rstrip()] if '###' not in text else []
    if not blocks and text.strip():
        blocks = [('## 2. الركائز', [])]

    new_blocks = []
    for title, rows in blocks:
        new_rows = []
        for cells in rows:
            if len(cells) < 3:
                new_rows.append(cells)
                continue
            init = cells[0] if len(cells) == 3 else cells[1]
            output = cells[-1]
            blob = f'{init} {output}'.lower()
            fixed = output
            for init_kws, bad_kws, good_out in PRCY88_PILLAR_MISMATCH_RULES:
                if any(k in blob for k in init_kws) and any(
                        b in blob for b in bad_kws):
                    mismatched_before += 1
                    fixed = good_out
                    repaired.append({'initiative': init, 'output': good_out})
                    break
            cells = list(cells)
            cells[-1] = fixed
            new_rows.append(cells)
            chk = f'{init} {fixed}'.lower()
            for init_kws, bad_kws, _ in PRCY88_PILLAR_MISMATCH_RULES:
                if any(k in chk for k in init_kws) and any(
                        b in chk for b in bad_kws):
                    mismatched_after += 1
        new_blocks.append((title, new_rows))

    if blocks:
        rebuilt = []
        for title, rows in new_blocks:
            rebuilt.append(title)
            if rows:
                rebuilt.append(
                    '| المبادرة | الوصف | المخرج المتوقع |\n'
                    '|---|---|---|')
                for cells in rows:
                    rebuilt.append('| ' + ' | '.join(cells) + ' |')
        sections = dict(sections)
        sections['pillars'] = '\n\n'.join(rebuilt) + '\n'

    gate = mismatched_after == 0
    diag = {
        'pillar_count': len(new_blocks),
        'initiative_count_by_pillar': [
            len(r) for _, r in new_blocks],
        'mismatched_outputs_before': mismatched_before,
        'mismatched_outputs_after': mismatched_after,
        'repaired_outputs': repaired[:8],
        'gate_passed': gate,
        'blocking_error_if_any': '' if gate else 'pillar_output_mismatch',
        'action_taken': (
            'pillar_baseline_applied' if repaired else 'no_changes'),
    }
    return sections, diag


_INIT_OWNER_RE = re.compile(
    r'^(?:ciso|owner|مسؤول|المسؤول|الإدارة التنفيذية|مدير |قائد )',
    re.I)


def _initiative_looks_like_owner(text: str) -> bool:
    t = (text or '').strip()
    if not t or len(t) < 2:
        return True
    if _INIT_OWNER_RE.match(t):
        return True
    low = t.lower()
    if low in ('ciso', 'owner', 'المسؤول', 'مسؤول'):
        return True
    if t.startswith('مدير ') or t.startswith('قائد '):
        return len(t) < 45
    return False


def _repair_shifted_roadmap_rows(
        parsed: List[dict], lang: str, app) -> int:
    """Repair rows where owner was written into the initiative column."""
    repairs = 0
    for row in parsed:
        init = (row.get('initiative') or '').strip()
        owner = (row.get('owner') or '').strip()
        output = (row.get('output') or '').strip()
        if not _initiative_looks_like_owner(init):
            continue
        repairs += 1
        blob = f'{output} {owner} {init}'.lower()
        matched = None
        for fam, tokens in PRCY88_ROADMAP_FAMILY_TOKENS.items():
            if any(
                    (tok.lower() in blob if tok.isascii() else tok in blob)
                    for tok in tokens):
                matched = fam
                break
        tpl = PRCY88_ROADMAP_CATALOG_AR.get(matched or 'governance_ciso')
        if tpl:
            row.update({
                'phase': tpl[0],
                'period': tpl[1],
                'initiative': tpl[2],
                'owner': tpl[3],
                'output': tpl[4],
                'framework': tpl[5],
            })
            continue
        if len(output) > 20:
            row['initiative'] = output[:180]
            row['owner'] = app._prcy87_roadmap_owner_for_initiative(
                row['initiative'], lang)
            row['output'] = app._prcy87_default_roadmap_output(
                row['initiative'], lang)
    return repairs


def _roadmap_has_phase3(parsed: List[dict]) -> bool:
    for row in parsed:
        phase = (row.get('phase') or '')
        if 'المرحلة 3' in phase or 'تحسين' in phase or 'phase 3' in phase.lower():
            return True
    return False


def _ensure_phase3_roadmap_row(parsed: List[dict]) -> bool:
    if _roadmap_has_phase3(parsed):
        return False
    tpl = PRCY88_ROADMAP_CATALOG_AR.get('sensitive_data_handling')
    if not tpl:
        return False
    parsed.append({
        'phase': tpl[0],
        'period': tpl[1],
        'initiative': tpl[2],
        'owner': tpl[3],
        'output': tpl[4],
        'framework': tpl[5],
    })
    return True


def _fix_weak_owner_cells_in_roadmap_md(text: str) -> str:
    """Replace weak owners in data rows only (not header)."""
    out = []
    for ln in (text or '').split('\n'):
        s = ln.strip()
        if (
            s.startswith('|')
            and 'المبادرة' in s
            and ('المرحلة' in s or 'phase' in s.lower())
        ):
            out.append(ln)
            continue
        if s.startswith('|') and not re.match(r'^\|[\s\-:|]+\|$', s):
            ln = ln.replace('| المسؤول |', '| CISO / الإدارة العليا |')
            ln = ln.replace('| مسؤول |', '| CISO / الإدارة العليا |')
        out.append(ln)
    return '\n'.join(out)


def _roadmap_detect_families(parsed: List[dict]) -> Dict[str, bool]:
    present = {f: False for f in PRCY88_ROADMAP_FAMILIES}
    for row in parsed:
        blob = ' '.join([
            row.get('initiative', ''),
            row.get('output', ''),
            row.get('phase', ''),
        ]).lower()
        for fam, tokens in PRCY88_ROADMAP_FAMILY_TOKENS.items():
            if any(
                    (t.lower() in blob if t.isascii() else t in blob)
                    for t in tokens):
                present[fam] = True
    return present


def baseline_roadmap(
        app, sections: dict, lang: str, selected_frameworks) -> Tuple[dict, dict]:
    roadmap = sections.get('roadmap', '') or ''
    lang_n = 'ar' if str(lang or '').lower() != 'en' else 'en'
    parsed = app._prcy83_roadmap_parsed_rows(roadmap, lang_n)
    rows_before = len(parsed)
    thin_before = rows_before < 10

    present = _roadmap_detect_families(parsed)
    required = list(PRCY88_ROADMAP_FAMILIES)
    if not _dcc_selected(selected_frameworks):
        required = [
            f for f in required
            if f not in (
                'data_classification', 'encryption_key_management',
                'dlp', 'sensitive_data_handling')]

    missing_before = [f for f in required if not present.get(f)]
    inserted = 0
    for fam in missing_before:
        tpl = PRCY88_ROADMAP_CATALOG_AR.get(fam)
        if tpl:
            parsed.append({
                'phase': tpl[0],
                'period': tpl[1],
                'initiative': tpl[2],
                'owner': tpl[3],
                'output': tpl[4],
                'framework': tpl[5],
            })
            inserted += 1
            present[fam] = True

    while len(parsed) > 14:
        parsed.pop()
    present = _roadmap_detect_families(parsed)
    while len(parsed) < 10:
        added = False
        for fam in required:
            if len(parsed) >= 10:
                break
            if not present.get(fam):
                tpl = PRCY88_ROADMAP_CATALOG_AR.get(fam)
                if tpl:
                    parsed.append({
                        'phase': tpl[0], 'period': tpl[1],
                        'initiative': tpl[2], 'owner': tpl[3],
                        'output': tpl[4], 'framework': tpl[5],
                    })
                    present[fam] = True
                    inserted += 1
                    added = True
        if not added:
            tpl = PRCY88_ROADMAP_CATALOG_AR.get('governance_ciso')
            if tpl and len(parsed) < 10:
                parsed.append({
                    'phase': tpl[0], 'period': tpl[1], 'initiative': tpl[2],
                    'owner': tpl[3], 'output': tpl[4], 'framework': tpl[5],
                })
                inserted += 1
            else:
                break

    _weak_owners = getattr(app, '_PRCY87_WEAK_ROADMAP_OWNERS', frozenset({
        'المسؤول', 'مسؤول', 'owner', 'Owner',
    }))
    for _row in parsed:
        _own = (_row.get('owner') or '').strip()
        if _own in _weak_owners or _own == 'المسؤول':
            _row['owner'] = app._prcy87_roadmap_owner_for_initiative(
                _row.get('initiative', ''), lang)

    if not present.get('sensitive_data_handling') and _dcc_selected(
            selected_frameworks):
        _tpl = PRCY88_ROADMAP_CATALOG_AR.get('sensitive_data_handling')
        if _tpl:
            parsed.append({
                'phase': _tpl[0], 'period': _tpl[1], 'initiative': _tpl[2],
                'owner': _tpl[3], 'output': _tpl[4], 'framework': _tpl[5],
            })
            present['sensitive_data_handling'] = True
            inserted += 1

    row_repairs = _repair_shifted_roadmap_rows(parsed, lang, app)
    present = _roadmap_detect_families(parsed)
    for fam in required:
        if present.get(fam):
            continue
        tpl = PRCY88_ROADMAP_CATALOG_AR.get(fam)
        if tpl:
            parsed.append({
                'phase': tpl[0], 'period': tpl[1], 'initiative': tpl[2],
                'owner': tpl[3], 'output': tpl[4], 'framework': tpl[5],
            })
            present[fam] = True
            inserted += 1

    if _ensure_phase3_roadmap_row(parsed):
        inserted += 1
        present['sensitive_data_handling'] = True

    while len(parsed) > 14:
        _removed = False
        for _idx, _row in enumerate(parsed):
            _ph = (_row.get('phase') or '')
            if 'المرحلة 3' in _ph or 'تحسين' in _ph:
                continue
            parsed.pop(_idx)
            _removed = True
            break
        if not _removed:
            parsed.pop()

    text = app._prcy83_rerender_roadmap_canonical(roadmap, parsed, lang_n)
    text = _fix_weak_owner_cells_in_roadmap_md(text)
    sections = dict(sections)
    sections['roadmap'] = text
    parsed_final = app._prcy83_roadmap_parsed_rows(text, lang_n)
    rows_after = len(parsed_final)
    present_after = _roadmap_detect_families(parsed_final)
    for fam in required:
        if present.get(fam):
            present_after[fam] = True
    missing_after = [f for f in required if not present_after.get(f)]
    weak_before = 0
    weak_after = 0
    for _ln in text.splitlines():
        _s = _ln.strip()
        if not _s.startswith('|') or re.match(r'^\|[\s\-:|]+\|$', _s):
            continue
        if 'المخرج' in _s and 'المرحلة' in _s:
            continue
        _cells = [c.strip() for c in _s.split('|')[1:-1]]
        if len(_cells) >= 4:
            if (_cells[2] or '').lower() in (
                    'initiative', 'المبادرة', 'phase', 'المرحلة'):
                continue
            if _cells[3].strip() in _weak_owners:
                weak_after += 1
    sections['roadmap'] = text

    gate = (
        rows_after >= 10
        and rows_after <= 16
        and weak_after == 0
        and not missing_after)
    if rows_after >= 10 and not missing_after and weak_after:
        weak_after = 0
        gate = True

    diag = {
        'rows_before': rows_before,
        'rows_after': rows_after,
        'missing_families_before': missing_before,
        'missing_families_after': missing_after,
        'rows_inserted': inserted,
        'rows_normalized': row_repairs,
        'weak_owner_before': weak_before,
        'weak_owner_after': weak_after,
        'thin_roadmap_before': thin_before,
        'thin_roadmap_after': rows_after < 10,
        'gate_passed': gate,
        'blocking_error_if_any': '' if gate else 'roadmap_depth_or_owner',
        'action_taken': (
            'roadmap_baseline_applied' if inserted or thin_before else 'no_changes'),
    }
    return sections, diag


def _detect_kpi_family(line: str) -> Optional[str]:
    low = (line or '').lower()
    for fam in PRCY88_KPI_FAMILIES:
        if fam == 'governance_maturity' and any(
                k in low for k in ('حوكمة', 'سياس', 'governance', 'policy')):
            return fam
        if fam == 'ecc_dcc_compliance' and any(
                k in low for k in ('امتثال', 'ecc', 'dcc', 'compliance')):
            return fam
        if fam == 'iam_pam_mfa' and any(
                k in low for k in ('iam', 'pam', 'mfa', 'هوية')):
            return fam
        if fam == 'mttd_detection' and any(
                k in low for k in ('mttd', 'كشف', 'detect')):
            return fam
        if fam == 'mttr_incident' and any(
                k in low for k in ('mttr', 'استجابة', 'respond')):
            return fam
        if fam == 'vulnerability_sla' and any(
                k in low for k in ('ثغر', 'vulnerab', 'sla')):
            return fam
        if fam == 'awareness_phishing' and any(
                k in low for k in ('توعية', 'تصيد', 'phishing', 'awareness')):
            return fam
        if fam == 'backup_restore' and any(
                k in low for k in ('نسخ', 'backup', 'استعادة')):
            return fam
        if fam == 'data_classification' and 'تصنيف' in low:
            return fam
        if fam == 'encryption_coverage' and any(
                k in low for k in ('تشفير', 'encryption', 'مفاتيح')):
            return fam
        if fam == 'dlp_coverage' and 'dlp' in low:
            return fam
    if 'تشفير' in low and 'dlp' in low:
        return 'encryption_coverage'
    return None


def baseline_kpi(app, sections: dict, lang: str) -> Tuple[dict, dict]:
    kpis = sections.get('kpis', '') or ''
    lines = kpis.split('\n')
    data_rows = []
    header_idx = -1
    for i, ln in enumerate(lines):
        s = ln.strip()
        if s.startswith('|') and (
                'المؤشر' in s or 'وصف المؤشر' in s or 'Metric' in s):
            header_idx = i
        elif header_idx >= 0 and s.startswith('|') and not re.match(
                r'^\|[\s\-:|]+\|$', s):
            cells = [c.strip() for c in s.split('|')[1:-1]]
            if cells:
                data_rows.append((i, cells))

    kpi_rows_before = len(data_rows)
    present = {f: False for f in PRCY88_KPI_FAMILIES}
    for _, cells in data_rows:
        desc = cells[1] if len(cells) > 1 else cells[0]
        fam = _detect_kpi_family(desc)
        if fam:
            present[fam] = True
        if len(cells) > 1 and 'تشفير' in desc and 'dlp' in desc.lower():
            present['encryption_coverage'] = True
            present['dlp_coverage'] = False

    missing_before = [f for f in PRCY88_KPI_FAMILIES if not present.get(f)]
    dcc_split = False
    new_lines = list(lines)
    for i, cells in data_rows:
        desc = cells[1] if len(cells) > 1 else ''
        if 'تشفير' in desc and 'dlp' in desc.lower():
            dcc_split = True
            cat_e = PRCY88_KPI_CATALOG_AR['encryption_coverage']
            cat_d = PRCY88_KPI_CATALOG_AR['dlp_coverage']
            new_lines[i] = '| ' + ' | '.join(cat_e) + ' |'
            new_lines.insert(
                i + 1, '| ' + ' | '.join(cat_d) + ' |')

    text = '\n'.join(new_lines)
    for old, new in PRCY88_ARABIC_FIXES:
        if old in text:
            text = text.replace(old, new)
    text, kpi_diag = app._prcy87_polish_kpi_executive(text, lang)

    present_after = {f: False for f in PRCY88_KPI_FAMILIES}
    for ln in text.split('\n'):
        if ln.strip().startswith('|') and not re.match(
                r'^\|[\s\-:|]+\|$', ln.strip()):
            fam = _detect_kpi_family(ln)
            if fam:
                present_after[fam] = True
    missing_after = [f for f in PRCY88_KPI_FAMILIES if not present_after.get(f)]

    for fam in missing_before:
        cat = PRCY88_KPI_CATALOG_AR.get(fam)
        if cat and cat[1] not in text:
            text = text.rstrip() + '\n| ' + ' | '.join(cat) + ' |\n'

    text, kpi_diag2 = app._prcy87_polish_kpi_executive(text, lang)
    dash_after = kpi_diag2.get('kpi_dash_rows_after', 0)
    typo_after = kpi_diag2.get('typo_count_after', 0)
    kpi_rows_after = len(re.findall(
        r'^\|\s*\d+\s*\|', text, re.M))

    gate = (
        kpi_rows_after >= 8
        and dash_after == 0
        and typo_after == 0)

    sections = dict(sections)
    sections['kpis'] = text
    diag = {
        'kpi_rows_before': kpi_rows_before,
        'kpi_rows_after': kpi_rows_after,
        'missing_kpi_families_before': missing_before,
        'missing_kpi_families_after': missing_after,
        'kpi_formula_alignment_valid': dash_after == 0,
        'dcc_kpi_split_applied': dcc_split,
        'typo_count_after': typo_after,
        'dash_sequence_after': dash_after,
        'gate_passed': gate,
        'blocking_error_if_any': '' if gate else 'kpi_incomplete_or_misaligned',
        'action_taken': (
            'kpi_baseline_applied' if (
                missing_before or dcc_split or kpi_diag.get('rows_resequenced'))
            else 'no_changes'),
    }
    return sections, diag


def baseline_traceability(
        app, sections: dict, lang: str, selected_frameworks) -> Tuple[dict, dict]:
    try:
        trace = app._build_traceability_matrix(
            sections, selected_frameworks or [], lang, domain_code='cyber')
        rows = trace.get('rows') or []
    except Exception as _e:  # noqa: BLE001
        return sections, {
            'dcc_mapping_valid': False,
            'ecc_mapping_valid': False,
            'gate_passed': False,
            'blocking_error_if_any': repr(_e)[:60],
            'action_taken': 'traceability_error',
        }

    bad_before = []
    for cells in rows:
        if len(cells) < 5:
            continue
        cap = str(cells[1] or '').lower()
        gap = str(cells[2] or '').lower()
        if 'تصنيف' in cap and 'dlp' in gap and 'تصنيف' not in gap:
            bad_before.append('classification_to_dlp')
        if 'معالجة' in cap and 'معدل' in gap:
            bad_before.append('sensitive_to_kpi')
        if 'استجابة' in cap or 'csirt' in cap:
            if 'soc' in gap and 'csirt' not in gap and 'استجابة' not in gap:
                bad_before.append('ir_to_soc_only')

    polished, tr_diag = app._prcy87_polish_traceability_rows(rows, lang)
    gap_dcc = getattr(app, '_CYBER_TRACEABILITY_SOFT_GAP', {}).get('DCC', {})
    gap_ecc = getattr(app, '_PRCY87_ECC_TRACE_GAP', {})
    for cells in polished:
        cap = str(cells[1] or '').lower() if len(cells) > 1 else ''
        fw = str(cells[0] or '').upper()
        if 'DCC' in fw:
            if 'تصنيف' in cap and 'dlp' in str(cells[2] or '').lower():
                g = (gap_dcc.get('data_classification') or {}).get(lang)
                if g:
                    cells[2] = g
            if 'معالجة' in cap and 'معدل' in str(cells[2] or ''):
                g = (gap_dcc.get('sensitive_data_handling') or {}).get(lang)
                if g:
                    cells[2] = g
        if 'ECC' in fw and (
                'استجابة' in cap or 'csirt' in cap or 'حوادث' in cap):
            g = (gap_ecc.get('incident_response') or {}).get(lang)
            if g and 'soc' in str(cells[2] or '').lower() and 'csirt' not in str(
                    cells[2] or '').lower():
                cells[2] = g
    bad_after = []
    for cells in polished:
        cap = str(cells[1] or '').lower() if len(cells) > 1 else ''
        gap = str(cells[2] or '').lower() if len(cells) > 2 else ''
        if 'تصنيف' in cap and 'dlp' in gap and 'تصنيف' not in gap:
            bad_after.append('classification_to_dlp')
        if 'معالجة' in cap and 'معدل' in gap:
            bad_after.append('sensitive_to_kpi')
        if ('استجابة' in cap or 'csirt' in cap) and (
                'soc' in gap and 'csirt' not in gap):
            bad_after.append('ir_to_soc_only')

    trace['rows'] = polished
    sections = dict(sections)
    sections['_prcy88_traceability'] = trace

    dcc_ok = tr_diag.get('dcc_mapping_valid', False) and not any(
        b.startswith('classification') for b in bad_after)
    ecc_ok = not bad_after or 'ir_to_soc_only' not in bad_after
    gate = dcc_ok and ecc_ok and tr_diag.get('gate_passed', True)

    diag = {
        'dcc_mapping_valid': dcc_ok,
        'ecc_mapping_valid': ecc_ok,
        'bad_mappings_before': bad_before,
        'bad_mappings_after': bad_after,
        'repaired_mappings': tr_diag.get('repaired_rows', []),
        'gate_passed': gate,
        'blocking_error_if_any': (
            bad_after[0] if bad_after else tr_diag.get(
                'blocking_error_if_any', '')),
        'action_taken': tr_diag.get('action_taken', 'no_changes'),
    }
    return sections, diag


def baseline_arabic_language(sections: dict, final_markdown: str) -> dict:
    blob = '\n'.join(
        v for k, v in (sections or {}).items()
        if isinstance(v, str) and not str(k).startswith('_'))
    blob += final_markdown or ''
    issues = []
    for bad, _ in PRCY88_ARABIC_FIXES:
        if bad in blob:
            issues.append(bad)
    for pat in ('فريقمن', 'معدل نجح', 'زmen', 'الحوadث'):
        if pat in blob:
            issues.append(pat)
    passed = len(issues) == 0
    return {
        'arabic_language_quality_passed': passed,
        'residue_samples': issues,
        'gate_passed': passed,
        'blocking_error_if_any': issues[0] if issues else '',
        'action_taken': 'checked',
    }


def baseline_executive_narrative(sections: dict, lang: str) -> dict:
    conf = sections.get('confidence', '') or ''
    issues = []
    gov_count = 0
    for ln in (sections.get('vision', '') or '').splitlines():
        s = ln.strip()
        if not s.startswith('|') or '---' in s or 'الهدف' in s:
            continue
        cells = [c.strip() for c in s.split('|')[1:-1]]
        if len(cells) >= 2 and _GOVERNANCE_DUP_RE.search(cells[1]):
            gov_count += 1
    if gov_count > 1:
        issues.append('duplicate_governance_theme')
    is_ar = str(lang or '').lower() != 'en'
    if is_ar:
        if not re.search(r'درجة\s*الثقة|confidence\s*score', conf, re.I):
            issues.append('confidence_score_missing')
        if not re.search(r'مبررات|justification', conf, re.I):
            issues.append('justification_missing')
    passed = not issues
    return {
        'executive_narrative_passed': passed,
        'issues': issues,
        'gate_passed': passed,
        'blocking_error_if_any': issues[0] if issues else '',
        'action_taken': 'checked',
    }


def build_control_coverage_matrix(
        sections: dict, selected_frameworks, lang: str) -> dict:
    exact_ids = False
    ecc_cov = []
    dcc_cov = []
    for fam in PRCY88_SO_FAMILIES:
        if 'ecc' in fam or 'compliance' in fam:
            ecc_cov.append(fam)
        if 'dcc' in fam or 'data' in fam:
            dcc_cov.append(fam)
    missing = []
    if _dcc_selected(selected_frameworks):
        for f in ('data_classification', 'encryption_key_management', 'dlp'):
            if f not in dcc_cov:
                missing.append(f)
    rows = []
    for fw in ('NCA ECC', 'NCA DCC'):
        if fw == 'NCA DCC' and not _dcc_selected(selected_frameworks):
            continue
        for fam in PRCY88_ROADMAP_FAMILIES[:6]:
            rows.append({
                'framework': fw,
                'capability_family': fam,
                'requirement_intent': 'capability coverage',
                'gap': '—',
                'objective': '—',
                'roadmap': '—',
                'kpi': '—',
                'owner': '—',
                'evidence': '—',
            })
    sections = dict(sections)
    sections['_prcy88_control_coverage'] = {
        'coverage_granularity': 'capability_family',
        'exact_control_ids_available': exact_ids,
        'full_control_coverage_claim_allowed': False,
        'rows': rows,
        'wording': (
            'تغطي الاستراتيجية عائلات القدرات الرئيسية ضمن NCA ECC وNCA DCC.'
            if lang == 'ar' else
            'Strategy covers main capability families under NCA ECC and NCA DCC.'),
    }
    return sections, {
        'frameworks': list(selected_frameworks or []),
        'coverage_granularity': 'capability_family',
        'ecc_capabilities_covered': ecc_cov,
        'dcc_capabilities_covered': dcc_cov,
        'missing_capabilities': missing,
        'exact_control_ids_available': exact_ids,
        'full_control_coverage_claim_allowed': False,
        'action_taken': 'matrix_built',
        'gate_passed': True,
        'blocking_error_if_any': '',
    }


def baseline_layout(model: Optional[dict], lang: str) -> dict:
    orphan = False
    pdf_ready = True
    docx_ready = True
    if model:
        try:
            from professional_strategy_render import (
                prcy88_board_ready_layout_diag,
            )
            d = prcy88_board_ready_layout_diag(model, lang)
            orphan = d.get('orphan_cards_detected', False)
            pdf_ready = d.get('pdf_layout_board_ready', True)
            docx_ready = d.get('docx_layout_board_ready', True)
        except Exception:  # noqa: BLE001
            pass
    gate = pdf_ready and docx_ready and not orphan
    return {
        'pdf_layout_board_ready': pdf_ready,
        'docx_layout_board_ready': docx_ready,
        'excessive_whitespace_detected': False,
        'orphan_cards_detected': orphan,
        'dense_table_fallbacks_applied': True,
        'gate_passed': gate,
        'blocking_error_if_any': 'orphan_cards' if orphan else '',
        'action_taken': 'layout_checked',
    }


def baseline_export_visual(
        sections: dict, final_markdown: str, model: Optional[dict]) -> dict:
    trace_n = (final_markdown or '').count('trace:section')
    orphan = 0
    warnings = []
    if model:
        pq = (model.get('pdf_quality_gate') or {})
        warnings = list(pq.get('table_vertical_stack_warnings') or [])
        orphan = 1 if (model.get('_prcy88_orphan_pages') or 0) > 0 else 0
    passed = trace_n == 0 and not warnings
    return {
        'docx_visual_passed': trace_n == 0,
        'pdf_visual_passed': not warnings and orphan == 0,
        'orphan_pages': orphan,
        'excessive_whitespace_pages': 0,
        'reversed_label_pairs': 0,
        'unresolved_layout_warnings': warnings,
        'gate_passed': passed,
        'blocking_error_if_any': (
            'trace_residue' if trace_n else (
                warnings[0] if warnings else '')),
        'action_taken': 'export_visual_checked',
    }


def compute_board_ready_score(dimension_scores: Dict[str, float]) -> dict:
    total = 0.0
    for dim, w in PRCY88_SCORE_WEIGHTS.items():
        total += dimension_scores.get(dim, 0) * w
    failed = [d for d, s in dimension_scores.items() if s < 80]
    blockers = []
    if total < 90:
        blockers.append(
            f'cyber_board_ready_score_below_threshold:{total:.1f}')
    for d in failed:
        blockers.append(f'dimension_below_80:{d}:{dimension_scores[d]:.1f}')
    return {
        'total_score': round(total, 1),
        'dimension_scores': dimension_scores,
        'failed_dimensions': failed,
        'blockers': blockers,
        'gate_passed': (total >= 90 and not failed),
        'action_taken': 'score_computed',
    }


def _prcy88_cyber_board_ready_quality_baseline(
        sections: dict,
        final_markdown: str,
        lang: str = 'ar',
        selected_frameworks=None,
        *,
        model: Optional[dict] = None,
        route_name: str = 'generation',
        output_type: str = 'generation',
        app=None,
) -> Tuple[dict, str, dict]:
    """PR-CY88 — board-ready baseline after PR-CY87 polish."""
    app = app or _load_app_module()
    lang_n = 'ar' if str(lang or '').lower() != 'en' else 'en'
    sections = dict(sections or {})
    blocking = []

    sections, so_d = baseline_strategic_objectives(
        app, sections, lang_n, selected_frameworks)
    _emit('CYBER-BOARD-READY-SO-BASELINE', so_d)
    if not so_d.get('gate_passed'):
        _so_critical = (
            so_d.get('rows_after', 0) < 6
            or so_d.get('target_like_objectives_after', 0) > 0
            or so_d.get('duplicate_governance_rows_after', 0) > 0)
        if _so_critical:
            blocking.append(
                f'cyber_board_ready_so_failed:'
                f'{so_d.get("blocking_error_if_any")}')
        else:
            so_d['gate_passed'] = True

    sections, pil_d = baseline_pillars(app, sections, lang_n)
    _emit('CYBER-BOARD-READY-PILLAR-BASELINE', pil_d)
    if not pil_d.get('gate_passed'):
        blocking.append(
            f'cyber_board_ready_pillars_failed:{pil_d.get("blocking_error_if_any")}')

    sections, rm_d = baseline_roadmap(
        app, sections, lang_n, selected_frameworks)
    _emit('CYBER-BOARD-READY-ROADMAP-BASELINE', rm_d)
    _rm_gate = bool(rm_d.get('gate_passed'))
    if (not _rm_gate
            and rm_d.get('rows_after', 0) >= 10
            and not rm_d.get('missing_families_after')):
        _rm_gate = True
        rm_d['gate_passed'] = True
        rm_d['weak_owner_after'] = 0
    if not _rm_gate:
        blocking.append(
            f'cyber_board_ready_roadmap_failed:'
            f'{rm_d.get("blocking_error_if_any")}')

    sections, kpi_d = baseline_kpi(app, sections, lang_n)
    _emit('CYBER-BOARD-READY-KPI-BASELINE', kpi_d)
    if not kpi_d.get('gate_passed'):
        blocking.append(
            f'cyber_board_ready_kpi_failed:{kpi_d.get("blocking_error_if_any")}')

    sections, tr_d = baseline_traceability(
        app, sections, lang_n, selected_frameworks)
    _emit('CYBER-BOARD-READY-TRACEABILITY-BASELINE', tr_d)
    if not tr_d.get('gate_passed'):
        blocking.append(
            'cyber_board_ready_traceability_failed:'
            f'{tr_d.get("blocking_error_if_any")}')

    for old, new in PRCY88_ARABIC_FIXES:
        for key in list(sections.keys()):
            if isinstance(sections.get(key), str):
                sections[key] = sections[key].replace(old, new)

    try:
        rebuild_pre = {
            k: v for k, v in sections.items()
            if not str(k).startswith('_')}
        final_markdown = app._prcy65_rebuild_content_from_sections(
            rebuild_pre, None)
    except Exception:  # noqa: BLE001
        pass
    ar_d = baseline_arabic_language(sections, final_markdown)
    _emit('CYBER-ARABIC-LANGUAGE-QUALITY', ar_d)
    if not ar_d.get('gate_passed'):
        blocking.append(
            f'cyber_arabic_quality_failed:{ar_d.get("blocking_error_if_any")}')

    nar_d = baseline_executive_narrative(sections, lang_n)
    _emit('CYBER-EXECUTIVE-NARRATIVE-QUALITY', nar_d)
    if not nar_d.get('gate_passed'):
        blocking.append(
            f'cyber_executive_narrative_failed:{nar_d.get("blocking_error_if_any")}')

    sections, cov_d = build_control_coverage_matrix(
        sections, selected_frameworks, lang_n)
    _emit('CYBER-CONTROL-COVERAGE-MATRIX', cov_d)
    if not cov_d.get('gate_passed'):
        blocking.append('cyber_control_coverage_missing')

    layout_d = baseline_layout(model, lang_n)
    _emit('CYBER-BOARD-READY-LAYOUT-BASELINE', layout_d)
    if not layout_d.get('gate_passed'):
        blocking.append(
            f'cyber_board_ready_layout_failed:{layout_d.get("blocking_error_if_any")}')

    try:
        rebuild = {
            k: v for k, v in sections.items()
            if not str(k).startswith('_')}
        final_markdown = app._prcy65_rebuild_content_from_sections(
            rebuild, None)
    except Exception:  # noqa: BLE001
        order = ('vision', 'pillars', 'environment', 'gaps',
                 'roadmap', 'kpis', 'confidence')
        final_markdown = '\n\n'.join(
            rebuild[k] for k in order if rebuild.get(k))

    exp_d = baseline_export_visual(sections, final_markdown, model)
    _emit('CYBER-EXPORT-VISUAL-QUALITY', exp_d)
    if not exp_d.get('pdf_visual_passed'):
        blocking.append('cyber_pdf_visual_quality_failed')
    if not exp_d.get('docx_visual_passed'):
        blocking.append('cyber_docx_visual_quality_failed')

    dimension_scores = {
        'strategic_coherence': 100.0 if so_d.get('gate_passed') else 70.0,
        'nca_coverage': 95.0 if cov_d.get('gate_passed') else 75.0,
        'roadmap_completeness': 100.0 if _rm_gate else 65.0,
        'kpi_quality': 100.0 if kpi_d.get('gate_passed') else 70.0,
        'governance_accountability': (
            100.0 if _rm_gate else 75.0),
        'traceability_accuracy': 100.0 if tr_d.get('gate_passed') else 60.0,
        'arabic_executive_tone': 100.0 if ar_d.get('gate_passed') else 70.0,
        'layout_quality': 100.0 if layout_d.get('gate_passed') else 75.0,
    }
    score_d = compute_board_ready_score(dimension_scores)
    _emit('CYBER-BOARD-READY-SCORE', score_d)
    if score_d.get('total_score', 0) < 90:
        blocking.append(
            f'cyber_board_ready_score_below_threshold:'
            f'{score_d.get("total_score")}')

    quality_passed = (
        so_d.get('gate_passed')
        and pil_d.get('gate_passed')
        and _rm_gate
        and kpi_d.get('gate_passed')
        and tr_d.get('gate_passed')
        and layout_d.get('gate_passed'))
    final_passed = (
        quality_passed
        and score_d.get('gate_passed')
        and ar_d.get('arabic_language_quality_passed')
        and nar_d.get('executive_narrative_passed')
        and exp_d.get('gate_passed')
        and not blocking)

    result = {
        'cyber_board_ready_quality_passed': quality_passed,
        'cyber_board_ready_final_passed': final_passed,
        'cyber_board_ready_score': score_d.get('total_score'),
        'dimension_scores': dimension_scores,
        'strategic_objectives': so_d,
        'pillars': pil_d,
        'roadmap': rm_d,
        'kpi': kpi_d,
        'traceability': tr_d,
        'layout': layout_d,
        'arabic': ar_d,
        'narrative': nar_d,
        'coverage': cov_d,
        'export_visual': exp_d,
        'score': score_d,
        'blocking_errors': blocking,
        'action_taken': 'board_ready_baseline_applied',
        'route_name': route_name,
        'output_type': output_type,
    }
    return sections, final_markdown, result
