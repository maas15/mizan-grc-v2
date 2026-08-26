"""REL35 — domain/framework fidelity and DGA interoperability coverage.

Visible-export and generation-section repairs only. Does not weaken
REL3.3/REL34 gates, suppress blockers, or bypass export evidence.
Cyber-specific catalogs stay cyber-only.
"""

from __future__ import annotations

import json
import re
from copy import deepcopy
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from release_engine_v3.domain_codes import normalize_domain_code

REL35_DIAG_TAG = '[REL35-DOMAIN-FRAMEWORK-FIDELITY]'

CYBER_FRAMEWORK_TOKENS = (
    'NCA ECC', 'NCA DCC', 'NCA ECCو', 'NCA DCCو',
)
CYBER_TERM_TOKENS = (
    'CISO', 'SIEM', 'SOAR', 'SOC', 'CSIRT', 'IAM/PAM', 'IAM', 'PAM', 'MFA',
    'فريق الأمن السيبراني',
)
NIST_AI_TOKENS = (
    'NIST AI RMF', 'NIST_AI_RMF', 'NIST AI Risk Management',
)
NIST_CSF_TOKENS = (
    'NIST Cybersecurity Framework (NIST CSF)',
    'NIST Cybersecurity Framework',
    'NIST CSF 2.0',
    'NIST CSF',
    'NIST_CSF',
    'إطار نيست للأمن السيبراني',
)
DGA_INTEROP_AR = (
    'التشغيل البيني',
    'التكامل الحكومي',
    'تكامل الخدمات الحكومية',
    'الربط البيني بين الأنظمة',
    'واجهات API موحدة',
    'إدارة تكامل القنوات الرقمية',
    'تبادل البيانات بين الجهات',
    'كتالوج خدمات رقمية',
    'قياس نضج التكامل وقابلية التشغيل البيني',
)
DGA_INTEROP_EN = (
    'interoperability',
    'government integration',
)
REL35_AR_LABEL_FIXES: Tuple[Tuple[str, str], ...] = (
    ('المسؤولإشراف البشري', 'مسؤول الإشراف البشري'),
    ('المسؤول عن الإشراف البشري', 'مسؤول الإشراف البشري'),
    ('المسؤولوصفية', 'مدير البيانات الوصفية'),
    ('سجلمعالجة', 'سجل\u00a0معالجة'),
)

DATA_OWNERS = (
    'CDO', 'رئيس البيانات التنفيذي', 'مدير حوكمة البيانات',
    'مدير جودة البيانات', 'مدير البيانات الوصفية والكتالوج',
    'مسؤول حماية البيانات الشخصية', 'مدير البيانات الرئيسية',
    'مسؤول الخصوصية / DPO',
)
DATA_SOURCES = (
    'Data catalog', 'Data quality platform', 'RoPA register',
    'Consent management platform', 'Metadata repository', 'MDM platform',
    'DSR workflow', 'Privacy incident register',
    'كتالوج البيانات', 'منصة جودة البيانات', 'سجل المعالجة',
    'منصة إدارة الموافقة', 'مستودع البيانات الوصفية', 'منصة MDM',
    'سير عمل طلبات أصحاب البيانات', 'سجل حوادث الخصوصية',
)
DATA_ROADMAP: Tuple[Tuple[str, str, str, str, str, str], ...] = (
    ('المرحلة 1: تأسيس (1-6 أشهر)', '1-6 أشهر',
     'تأسيس حوكمة البيانات وتعيين CDO', 'CDO',
     'إطار حوكمة NDMO معتمد', 'NDMO'),
    ('المرحلة 1: تأسيس (1-6 أشهر)', '1-6 أشهر',
     'تفعيل برنامج جودة البيانات', 'مدير جودة البيانات',
     'لوحة جودة بيانات تشغيلية', 'NDMO'),
    ('المرحلة 1: تأسيس (1-6 أشهر)', '1-6 أشهر',
     'تشغيل كتالوج البيانات الوصفية', 'مدير البيانات الوصفية والكتالوج',
     'كتالوج بيانات معتمد', 'NDMO'),
    ('المرحلة 2: تمكين وتشغيل (7-18 شهر)', '7-18 شهر',
     'تفعيل الامتثال لنظام حماية البيانات الشخصية',
     'مسؤول حماية البيانات الشخصية',
     'سجل\u00a0معالجة وضوابط خصوصية', 'PDPL'),
    ('المرحلة 2: تمكين وتشغيل (7-18 شهر)', '7-18 شهر',
     'تشغيل إدارة البيانات الرئيسية MDM', 'مدير البيانات الرئيسية',
     'منصة MDM للبيانات الحرجة', 'NDMO'),
    ('المرحلة 2: تمكين وتشغيل (7-18 شهر)', '7-18 شهر',
     'تفعيل سير عمل طلبات أصحاب البيانات DSR',
     'مسؤول حماية البيانات الشخصية',
     'قناة DSR موثقة', 'PDPL'),
    ('المرحلة 3: تحسين واستدامة (19-24 شهر)', '19-24 شهر',
     'تشغيل سجل المعالجة RoPA وإدارة الموافقة',
     'مسؤول الخصوصية / DPO',
     'سجل\u00a0معالجة ومنصة موافقة', 'PDPL'),
)
AI_ROADMAP: Tuple[Tuple[str, str, str, str, str, str], ...] = (
    ('المرحلة 1: تأسيس (1-6 أشهر)', '1-6 أشهر',
     'تأسيس حوكمة الذكاء الاصطناعي', 'رئيس حوكمة الذكاء الاصطناعي',
     'سياسة حوكمة AI معتمدة', 'SDAIA'),
    ('المرحلة 1: تأسيس (1-6 أشهر)', '1-6 أشهر',
     'تعيين مسؤول أخلاقيات الذكاء الاصطناعي',
     'مسؤول أخلاقيات الذكاء الاصطناعي',
     'ميثاق أخلاقيات AI', 'SDAIA'),
    ('المرحلة 2: تمكين وتشغيل (7-18 شهر)', '7-18 شهر',
     'تشغيل إدارة مخاطر النماذج', 'مدير مخاطر النماذج',
     'سجل نماذج ومخاطر معتمد', 'SDAIA'),
    ('المرحلة 2: تمكين وتشغيل (7-18 شهر)', '7-18 شهر',
     'تشغيل دورة MLOps للنماذج المعتمدة', 'مهندس MLOps',
     'خط إنتاج نماذج موثق', 'SDAIA'),
    ('المرحلة 2: تمكين وتشغيل (7-18 شهر)', '7-18 شهر',
     'حوكمة بيانات التدريب', 'مدير بيانات التدريب',
     'سجل بيانات تدريب مصنّف', 'SDAIA'),
    ('المرحلة 3: تحسين واستدامة (19-24 شهر)', '19-24 شهر',
     'تفعيل امتثال الذكاء الاصطناعي', 'قائد امتثال الذكاء الاصطناعي',
     'تقارير امتثال SDAIA دورية', 'SDAIA'),
    ('المرحلة 3: تحسين واستدامة (19-24 شهر)', '19-24 شهر',
     'تفعيل الإشراف البشري على القرارات الآلية',
     'مسؤول الإشراف البشري',
     'ضوابط إشراف بشري موثقة', 'SDAIA'),
)
DT_ROADMAP: Tuple[Tuple[str, str, str, str, str, str], ...] = (
    ('المرحلة 1: تأسيس (1-6 أشهر)', '1-6 أشهر',
     'تكامل الخدمات الحكومية', 'مدير التحول الرقمي',
     'خارطة خدمات رقمية متكاملة', 'DGA'),
    ('المرحلة 1: تأسيس (1-6 أشهر)', '1-6 أشهر',
     'الربط البيني بين الأنظمة', 'مهندس تكامل',
     'قنوات ربط بيني معتمدة', 'DGA'),
    ('المرحلة 2: تمكين وتشغيل (7-18 شهر)', '7-18 شهر',
     'واجهات API موحدة', 'مهندس تكامل',
     'كتالوج API موحد', 'DGA'),
    ('المرحلة 2: تمكين وتشغيل (7-18 شهر)', '7-18 شهر',
     'إدارة تكامل القنوات الرقمية', 'مدير التحول الرقمي',
     'منصة قنوات رقمية متكاملة', 'DGA'),
    ('المرحلة 2: تمكين وتشغيل (7-18 شهر)', '7-18 شهر',
     'تبادل البيانات بين الجهات', 'مدير التكامل',
     'اتفاقيات تبادل بيانات', 'DGA'),
    ('المرحلة 3: تحسين واستدامة (19-24 شهر)', '19-24 شهر',
     'كتالوج خدمات رقمية', 'مدير التحول الرقمي',
     'كتالوج خدمات حكومية منشور', 'DGA'),
    ('المرحلة 3: تحسين واستدامة (19-24 شهر)', '19-24 شهر',
     'قياس نضج التكامل وقابلية التشغيل البيني',
     'مدير التحول الرقمي',
     'مؤشر نضج التشغيل البيني', 'DGA'),
)

_FW_DETECT = (
    ('NCA ECC', re.compile(r'\bNCA\s*ECC\b', re.I)),
    ('NCA DCC', re.compile(r'\bNCA\s*DCC\b', re.I)),
    ('NIST CSF', re.compile(
        r'\bNIST\s*CSF\b|\bNIST\s+Cybersecurity\s+Framework\b', re.I)),
    ('NIST AI RMF', re.compile(r'\bNIST\s*AI\s*(RMF|Risk Management)\b', re.I)),
    ('SDAIA', re.compile(r'\bSDAIA\b', re.I)),
    ('NDMO', re.compile(r'\bNDMO\b', re.I)),
    ('PDPL', re.compile(r'\bPDPL\b', re.I)),
    ('DGA', re.compile(r'\bDGA\b', re.I)),
    ('ISO 31000', re.compile(r'\bISO\s*31000\b', re.I)),
    ('COSO ERM', re.compile(r'\bCOSO\s*ERM\b', re.I)),
)


def is_cyber_strategy(domain: str = '', document_type: str = 'strategy') -> bool:
    """True only for cyber/cybersecurity strategy — never data/ai/dt/erm/global."""
    dtype = str(document_type or 'strategy').strip().lower()
    if dtype and dtype not in ('strategy', 'strategy_document'):
        return False
    return normalize_domain_code(str(domain or ''), default='') == 'cyber'


def apply_rel35_arabic_label_fixes(text: str, lang: str = 'ar') -> str:
    if lang != 'ar' or not text:
        return text or ''
    out = str(text)
    for src, dst in REL35_AR_LABEL_FIXES:
        out = out.replace(src, dst)
    return out


def normalize_selected_frameworks(raw: Optional[Iterable[Any]]) -> List[str]:
    out: List[str] = []
    for item in raw or []:
        s = str(item or '').strip()
        if not s:
            continue
        up = s.upper()
        if 'ECC' in up and 'NCA' in up:
            label = 'NCA ECC'
        elif up == 'ECC' or 'ESSENTIAL CYBER' in up:
            label = 'NCA ECC'
        elif 'DCC' in up and 'NCA' in up:
            label = 'NCA DCC'
        elif up == 'DCC' or 'DATA CYBER' in up:
            label = 'NCA DCC'
        elif 'NIST' in up and 'AI' in up:
            label = 'NIST AI RMF'
        elif 'NIST' in up and 'CSF' in up:
            label = 'NIST CSF'
        elif 'SDAIA' in up:
            label = 'SDAIA'
        elif 'NDMO' in up:
            label = 'NDMO'
        elif 'PDPL' in up:
            label = 'PDPL'
        elif up == 'DGA' or 'DIGITAL GOVERNMENT' in up or 'الحكومة الرقمية' in s:
            label = 'DGA'
        else:
            label = s
        if label not in out:
            out.append(label)
    return out


def detect_visible_frameworks(text: str) -> List[str]:
    blob = str(text or '')
    found: List[str] = []
    for label, pat in _FW_DETECT:
        if pat.search(blob) and label not in found:
            found.append(label)
    return found


def detect_forbidden_domain_terms(text: str) -> List[str]:
    blob = str(text or '')
    found: List[str] = []
    for tok in (
            CYBER_TERM_TOKENS + CYBER_FRAMEWORK_TOKENS
            + NIST_AI_TOKENS + NIST_CSF_TOKENS):
        if tok in blob and tok not in found:
            found.append(tok)
    return found


def default_owner_for_domain(domain: str) -> str:
    dcode = normalize_domain_code(str(domain or ''), default='')
    return {
        'data': 'مدير حوكمة البيانات',
        'ai': 'رئيس حوكمة الذكاء الاصطناعي',
        'dt': 'مدير التحول الرقمي',
        'cyber': 'CISO',
        'erm': 'رئيس إدارة المخاطر',
        'global': 'مالك المبادرة',
    }.get(dcode, 'مالك المبادرة')


def allowed_frameworks_for(
        domain: str,
        selected: Optional[Iterable[Any]],
) -> List[str]:
    selected_n = normalize_selected_frameworks(selected)
    dcode = normalize_domain_code(str(domain or ''), default='')
    allowed = list(selected_n)
    inferred = {
        'cyber': ('NCA ECC', 'NCA DCC'),
        'data': ('NDMO', 'PDPL'),
        'ai': ('SDAIA',),
        'dt': ('DGA',),
    }.get(dcode, ())
    for extra in inferred:
        if extra not in allowed:
            allowed.append(extra)
    return allowed


def unexpected_frameworks(
        visible: Sequence[str],
        allowed: Sequence[str],
) -> List[str]:
    allow = {str(a) for a in allowed}
    return [v for v in visible if v not in allow]


def dga_selected(selected: Optional[Iterable[Any]]) -> bool:
    return 'DGA' in normalize_selected_frameworks(selected)


def section_has_dga_interop(text: str) -> bool:
    blob = str(text or '')
    low = blob.lower()
    if any(tok in blob for tok in DGA_INTEROP_AR):
        return True
    return any(tok in low for tok in DGA_INTEROP_EN)


def dga_interoperability_covered(sections: Optional[Dict[str, str]]) -> bool:
    secs = sections or {}
    needed = ('pillars', 'environment', 'gaps', 'roadmap', 'kpis')
    return all(section_has_dga_interop(secs.get(key, '')) for key in needed)


def _append_paragraph(text: str, paragraph: str) -> str:
    body = str(text or '').rstrip()
    extra = str(paragraph or '').strip()
    if not extra:
        return body
    if extra in body:
        return body
    if not body:
        return extra
    return body + '\n\n' + extra


def _append_md_row(text: str, header_hint: str, row: str) -> str:
    body = str(text or '').rstrip()
    if row.strip() in body:
        return body
    if '|' in body:
        return body + '\n' + row
    return _append_paragraph(body, header_hint + '\n' + row)


def repair_dga_interoperability_sections(
        sections: Optional[Dict[str, str]],
        *,
        lang: str = 'ar',
) -> Tuple[Dict[str, str], List[str]]:
    """Deterministically cover DGA interoperability in required sections."""
    out = dict(sections or {})
    repaired: List[str] = []
    inserts = {
        'pillars': (
            '### ركيزة التشغيل البيني والتكامل الحكومي\n\n'
            'ترسي هذه الركيزة تكامل الخدمات الحكومية والربط البيني بين الأنظمة '
            'وعبر واجهات API موحدة وإدارة تكامل القنوات الرقمية وتبادل البيانات '
            'بين الجهات ضمن كتالوج خدمات رقمية، مع قياس نضج التكامل وقابلية '
            'التشغيل البيني.\n\n'
            '| المبادرة | الوصف | المخرج المتوقع | المسؤول |\n'
            '|---|---|---|---|\n'
            '| تكامل الخدمات الحكومية | الربط البيني وواجهات API موحدة | '
            'كتالوج خدمات رقمية متكامل | مدير التحول الرقمي |'
        ),
        'environment': (
            'تتطلب هيئة الحكومة الرقمية (DGA) التشغيل البيني والتكامل الحكومي '
            'عبر الربط البيني بين الأنظمة وواجهات API موحدة وتبادل البيانات بين '
            'الجهات ضمن كتالوج خدمات رقمية.'
        ),
        'gaps': (
            '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
            '|---|---|---|---|---|\n'
            '| DGA-I | ضعف التشغيل البيني | فجوة في التكامل الحكومي والربط '
            'البيني وواجهات API الموحدة | عالية | مفتوحة |'
        ),
        'roadmap': (
            '| المرحلة | الفترة | المبادرة | المسؤول | المخرج المتوقع | الإطار |\n'
            '|---|---|---|---|---|---|\n'
            '| المرحلة 2 | 7-18 شهر | تكامل الخدمات الحكومية والربط البيني | '
            'مهندس تكامل | واجهات API موحدة وكتالوج خدمات رقمية | DGA |'
        ),
        'kpis': (
            '| # | وصف المؤشر | النوع | القيمة المستهدفة | صيغة الاحتساب | مصدر | التكرار | المالك |\n'
            '|---|---|---|---|---|---|---|---|\n'
            '| DGA-1 | قياس نضج التكامل وقابلية التشغيل البيني | KPI | ≥ 80% | '
            'الخدمات المترابطة / الخدمات المستهدفة × 100 | كتالوج خدمات رقمية | '
            'ربع سنوي | مدير التحول الرقمي |'
        ),
        'traceability': (
            '| الإطار | الضابط | الهدف | الفجوة | المبادرة |\n'
            '|---|---|---|---|---|\n'
            '| DGA | التشغيل البيني | التكامل الحكومي | ضعف الربط البيني | '
            'واجهات API موحدة |'
        ),
    }
    if lang != 'ar':
        inserts = {
            'pillars': (
                '### Interoperability and government integration\n\n'
                'This pillar covers government service integration, system '
                'interoperability, unified APIs, digital-channel integration, '
                'and cross-entity data exchange.'
            ),
            'environment': (
                'DGA requires interoperability and government integration '
                'through unified APIs and cross-entity data exchange.'
            ),
            'gaps': (
                '| # | Gap | Description | Priority | Status |\n'
                '|---|---|---|---|---|\n'
                '| DGA-I | Weak interoperability | Missing government '
                'integration and unified APIs | High | Open |'
            ),
            'roadmap': (
                '| Phase | Period | Initiative | Owner | Output | Framework |\n'
                '|---|---|---|---|---|---|\n'
                '| Phase 2 | 7-18 months | Government service integration | '
                'Integration engineer | Unified APIs | DGA |'
            ),
            'kpis': (
                '| # | KPI | Type | Target | Formula | Source | Frequency | Owner |\n'
                '|---|---|---|---|---|---|---|---|\n'
                '| DGA-1 | Interoperability maturity | KPI | ≥ 80% | '
                'integrated / targeted × 100 | Digital service catalog | '
                'Quarterly | DT Director |'
            ),
            'traceability': (
                '| Framework | Control | Objective | Gap | Initiative |\n'
                '|---|---|---|---|---|\n'
                '| DGA | Interoperability | Government integration | '
                'Weak interoperability | Unified APIs |'
            ),
        }
    for key, paragraph in inserts.items():
        before = out.get(key, '')
        if section_has_dga_interop(before):
            continue
        out[key] = _append_paragraph(before, paragraph)
        repaired.append(key)
    return out, repaired


def _strip_tokens(text: str, tokens: Sequence[str]) -> str:
    out = str(text or '')
    for tok in tokens:
        out = out.replace(tok, '')
    out = re.sub(r'[ \t]{2,}', ' ', out)
    return out


def _domain_default_framework(domain: str, selected: Sequence[str]) -> str:
    dcode = normalize_domain_code(str(domain or ''), default='')
    selected_n = list(selected)
    if dcode == 'data':
        if 'NDMO' in selected_n:
            return 'NDMO'
        if 'PDPL' in selected_n:
            return 'PDPL'
        return 'NDMO'
    if dcode == 'ai':
        if 'SDAIA' in selected_n:
            return 'SDAIA'
        return selected_n[0] if selected_n else 'SDAIA'
    if dcode == 'dt':
        return 'DGA' if 'DGA' in selected_n or not selected_n else selected_n[0]
    if dcode == 'cyber':
        return 'NCA ECC'
    return selected_n[0] if selected_n else ''


def roadmap_spec_for_domain(
        domain: str,
        *,
        phase: int = 1,
        selected: Optional[Iterable[Any]] = None,
) -> Dict[str, str]:
    dcode = normalize_domain_code(str(domain or ''), default='')
    selected_n = normalize_selected_frameworks(selected)
    catalog = {
        'data': DATA_ROADMAP,
        'ai': AI_ROADMAP,
        'dt': DT_ROADMAP,
    }.get(dcode, ())
    if not catalog and dcode in ('erm', 'global'):
        try:
            from release_engine_v3.rel33_domain_substance import (
                DOMAIN_ROADMAP_CATALOGS,
            )
            rows = list((DOMAIN_ROADMAP_CATALOGS.get(dcode) or {}).values())
            if rows:
                catalog = tuple(rows)
        except Exception:  # noqa: BLE001
            catalog = ()
    if catalog:
        idx = max(0, min(phase - 1, len(catalog) - 1))
        row = catalog[idx]
        return {
            'phase': row[0], 'period': row[1], 'init': row[2],
            'owner': row[3], 'output': row[4], 'fw': row[5],
        }
    fw = _domain_default_framework(dcode, selected_n)
    return {
        'phase': 'المرحلة 1: تأسيس (1-6 أشهر)',
        'period': '1-6 أشهر',
        'init': 'تأسيس الحوكمة المؤسسية',
        'owner': 'مالك المبادرة',
        'output': 'إطار معتمد',
        'fw': fw,
    }


def repair_sections_for_fidelity(
        sections: Optional[Dict[str, str]],
        *,
        domain: str = '',
        document_type: str = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        lang: str = 'ar',
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    """Repair section markdown before the selected-framework gate."""
    out = dict(sections or {})
    dcode = normalize_domain_code(str(domain or ''), default='')
    dtype = str(document_type or 'strategy').strip().lower()
    selected_n = normalize_selected_frameworks(selected_frameworks)
    allowed = allowed_frameworks_for(dcode, selected_n)
    repaired: List[str] = []
    scanned = [k for k, v in out.items() if str(v or '').strip()]

    if dga_selected(selected_n) and dtype in ('', 'strategy', 'strategy_document'):
        out, dga_repaired = repair_dga_interoperability_sections(out, lang=lang)
        repaired.extend(dga_repaired)

    strip: List[str] = []
    if dcode == 'data' and not is_cyber_strategy(dcode, dtype):
        if 'NCA ECC' not in allowed:
            strip.extend(CYBER_FRAMEWORK_TOKENS)
        if 'NCA ECC' not in allowed and 'NCA DCC' not in allowed:
            strip.extend([
                'فريق الأمن السيبراني', 'CISO', 'SIEM', 'SOAR', 'CSIRT',
                'SOC/SIEM', 'IAM/PAM/MFA',
            ])
        if 'NIST CSF' not in allowed:
            strip.extend(NIST_CSF_TOKENS)
        if 'NIST AI RMF' not in allowed:
            strip.extend(NIST_AI_TOKENS)
    if dcode == 'ai' and not is_cyber_strategy(dcode, dtype):
        if 'NCA ECC' not in allowed:
            strip.extend(CYBER_FRAMEWORK_TOKENS)
            strip.extend([
                'فريق الأمن السيبراني', 'CISO', 'SIEM', 'SOAR', 'CSIRT',
                'SOC/SIEM', 'IAM/PAM/MFA', 'SOC',
            ])
        if 'NIST AI RMF' not in allowed:
            strip.extend(NIST_AI_TOKENS)
        if 'NIST CSF' not in allowed:
            strip.extend(NIST_CSF_TOKENS)

    if strip:
        for key, val in list(out.items()):
            cleaned = apply_rel35_arabic_label_fixes(_strip_tokens(val, strip), lang)
            if cleaned != val:
                out[key] = cleaned
                if key not in repaired:
                    repaired.append(key)
    else:
        for key, val in list(out.items()):
            cleaned = apply_rel35_arabic_label_fixes(val, lang)
            if cleaned != val:
                out[key] = cleaned
                if key not in repaired:
                    repaired.append(key)

    blob = '\n'.join(str(out.get(k) or '') for k in scanned or out.keys())
    visible = detect_visible_frameworks(blob)
    unexpected = unexpected_frameworks(visible, allowed)
    forbidden = []
    if dcode in ('data', 'ai') and 'NCA ECC' not in allowed:
        forbidden = [
            t for t in detect_forbidden_domain_terms(blob)
            if t in CYBER_TERM_TOKENS or t in CYBER_FRAMEWORK_TOKENS
            or (t in NIST_AI_TOKENS and 'NIST AI RMF' not in allowed)
            or (t in NIST_CSF_TOKENS and 'NIST CSF' not in allowed)
        ]
    blocking: List[str] = []
    if unexpected and dcode in ('data', 'ai'):
        blocking.append(
            'rel35_unexpected_frameworks:' + ','.join(unexpected))
    if dga_selected(selected_n) and not dga_interoperability_covered(out):
        blocking.append('selected_framework_coverage_missing:DGA:interoperability')
    diag = {
        'domain': dcode or str(domain or ''),
        'document_type': dtype or 'strategy',
        'selected_frameworks': selected_n,
        'visible_frameworks_detected': visible,
        'unexpected_frameworks': unexpected,
        'forbidden_domain_terms_detected': forbidden,
        'sections_scanned': scanned,
        'repaired_sections': repaired,
        'dga_interoperability_covered': (
            dga_interoperability_covered(out) if dga_selected(selected_n)
            else None),
        'blocking_errors': blocking,
        'passed': not blocking,
    }
    emit_rel35_domain_framework_fidelity(diag)
    return out, diag


def _scrub_table_cells(
        tables: List[Dict[str, Any]],
        *,
        strip: Sequence[str],
        lang: str,
        replacement_fw: str = '',
        replacement_owner: str = '',
) -> List[Dict[str, Any]]:
    out = []
    for table in tables or []:
        nt = dict(table)
        rows = []
        for row in nt.get('rows') or []:
            cells = [apply_rel35_arabic_label_fixes(str(c or ''), lang) for c in row]
            blob = ' '.join(cells)
            if any(tok in blob for tok in strip):
                new_cells = []
                for c in cells:
                    had_fw = any(tok in str(c) for tok in (
                        'NCA ECC', 'NCA DCC', 'NIST AI RMF', 'NIST CSF',
                        'NIST Cybersecurity Framework'))
                    had_owner = any(
                        tok in str(c) for tok in (
                            'CISO', 'SOC', 'CSIRT', 'فريق الأمن السيبراني'))
                    cleaned = _strip_tokens(c, strip)
                    if had_fw and replacement_fw and not str(cleaned).strip():
                        cleaned = replacement_fw
                    if had_owner and replacement_owner and (
                            not str(cleaned).strip()
                            or any(tok in str(cleaned) for tok in (
                                'CISO', 'SOC', 'CSIRT',
                                'فريق الأمن السيبراني'))):
                        cleaned = replacement_owner
                    new_cells.append(cleaned)
                cells = new_cells
            rows.append(cells)
        nt['rows'] = rows
        if nt.get('title'):
            nt['title'] = apply_rel35_arabic_label_fixes(
                _strip_tokens(str(nt.get('title') or ''), strip), lang)
        out.append(nt)
    return out


def apply_fidelity_to_blocks(
        blocks: Optional[Dict[str, Any]],
        *,
        domain: str = '',
        document_type: str = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        lang: str = 'ar',
) -> Dict[str, Any]:
    """Last-mile visible block scrub for non-cyber strategy domains."""
    out = deepcopy(blocks or {})
    dcode = normalize_domain_code(str(domain or ''), default='')
    if is_cyber_strategy(dcode, document_type):
        return out
    selected_n = normalize_selected_frameworks(selected_frameworks)
    allowed = allowed_frameworks_for(dcode, selected_n)
    strip: List[str] = []
    replacement_fw = _domain_default_framework(dcode, selected_n)
    replacement_owner = ''
    if dcode == 'data' and 'NCA ECC' not in allowed:
        strip = list(CYBER_FRAMEWORK_TOKENS) + [
            'فريق الأمن السيبراني', 'CISO', 'SIEM', 'SOAR', 'CSIRT',
            'SOC/SIEM', 'IAM/PAM/MFA',
        ]
        if 'NIST CSF' not in allowed:
            strip.extend(NIST_CSF_TOKENS)
        if 'NIST AI RMF' not in allowed:
            strip.extend(NIST_AI_TOKENS)
        replacement_owner = 'مدير حوكمة البيانات'
    elif dcode == 'ai' and 'NCA ECC' not in allowed:
        strip = list(CYBER_FRAMEWORK_TOKENS) + list(NIST_AI_TOKENS) + [
            'فريق الأمن السيبراني', 'CISO', 'SIEM', 'SOAR', 'CSIRT',
            'SOC/SIEM', 'IAM/PAM/MFA',
        ]
        if 'NIST AI RMF' in allowed:
            strip = [t for t in strip if t not in NIST_AI_TOKENS]
        if 'NIST CSF' not in allowed:
            strip.extend(NIST_CSF_TOKENS)
        replacement_owner = 'رئيس حوكمة الذكاء الاصطناعي'
    elif dcode == 'dt' and 'NCA ECC' not in allowed:
        strip = [
            'مكتب CISO / نظام الحوكمة', 'CISO office / GRC',
        ]
        replacement_fw = 'DGA' if 'DGA' in allowed or not selected_n else replacement_fw
        replacement_owner = 'مدير التحول الرقمي'
    for key, blk in list(out.items()):
        if not isinstance(blk, dict):
            continue
        nb = dict(blk)
        if strip:
            nb['tables'] = _scrub_table_cells(
                list(nb.get('tables') or []),
                strip=strip, lang=lang,
                replacement_fw=replacement_fw,
                replacement_owner=replacement_owner,
            )
            nb['paragraphs'] = [
                apply_rel35_arabic_label_fixes(_strip_tokens(p, strip), lang)
                for p in (nb.get('paragraphs') or [])
            ]
            if nb.get('content'):
                nb['content'] = apply_rel35_arabic_label_fixes(
                    _strip_tokens(str(nb.get('content') or ''), strip), lang)
            if nb.get('entries'):
                cleaned_entries = []
                for entry in nb.get('entries') or []:
                    if isinstance(entry, (tuple, list)) and len(entry) >= 2:
                        orig_blob = f'{entry[0]} {entry[1]}'
                        drop_unselected = (
                            (dcode == 'ai' and 'NIST AI RMF' not in allowed
                             and any(tok in orig_blob for tok in NIST_AI_TOKENS))
                            or (dcode in ('data', 'ai')
                                and 'NIST CSF' not in allowed
                                and any(tok in orig_blob
                                        for tok in NIST_CSF_TOKENS))
                            or (dcode in ('data', 'ai')
                                and any(tok in orig_blob
                                        for tok in CYBER_FRAMEWORK_TOKENS)
                                and 'NCA ECC' not in allowed)
                        )
                        if drop_unselected:
                            continue
                        label = apply_rel35_arabic_label_fixes(
                            _strip_tokens(str(entry[0]), strip), lang)
                        body = apply_rel35_arabic_label_fixes(
                            _strip_tokens(str(entry[1]), strip), lang)
                        if not str(label).strip() and not str(body).strip():
                            continue
                        cleaned_entries.append(
                            (label, body) if isinstance(entry, tuple)
                            else [label, body] + list(entry[2:]))
                    else:
                        cleaned_entries.append(entry)
                nb['entries'] = cleaned_entries
        else:
            nb['paragraphs'] = [
                apply_rel35_arabic_label_fixes(p, lang)
                for p in (nb.get('paragraphs') or [])
            ]
        appx_tables = (nb.get('gap_action_tables') if key == 'appendices'
                       else None)
        if appx_tables and strip:
            nb['gap_action_tables'] = _scrub_table_cells(
                list(appx_tables),
                strip=strip, lang=lang,
                replacement_fw=replacement_fw,
                replacement_owner=replacement_owner,
            )
        out[key] = nb
    return out


def emit_rel35_domain_framework_fidelity(diag: Dict[str, Any]) -> Dict[str, Any]:
    payload = {
        'domain': diag.get('domain'),
        'document_type': diag.get('document_type'),
        'selected_frameworks': list(diag.get('selected_frameworks') or []),
        'visible_frameworks_detected': list(
            diag.get('visible_frameworks_detected') or []),
        'unexpected_frameworks': list(diag.get('unexpected_frameworks') or []),
        'forbidden_domain_terms_detected': list(
            diag.get('forbidden_domain_terms_detected') or []),
        'sections_scanned': list(diag.get('sections_scanned') or []),
        'repaired_sections': list(diag.get('repaired_sections') or []),
        'dga_interoperability_covered': diag.get('dga_interoperability_covered'),
        'blocking_errors': list(diag.get('blocking_errors') or []),
        'passed': bool(diag.get('passed')),
    }
    print(REL35_DIAG_TAG + ' ' + json.dumps(payload, ensure_ascii=False), flush=True)
    return payload
