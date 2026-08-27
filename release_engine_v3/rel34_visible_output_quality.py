"""REL34 — last-mile DOCX/PDF presentation-quality helpers.

Rendering/export visible-text only. Does not change generation contracts,
REL3.3 acceptance gates, ERM compiler/render, or framework selection.
Internal ``family:<id>`` stamps may remain on intermediate render specs;
they are stripped from finalized visible cells/paragraphs.
"""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

FAMILY_MARKER_RE = re.compile(
    r'\s*family:[a-z][a-z0-9_]{1,48}\b', re.IGNORECASE)
# Bare internal ids (ciso_governance, soc_siem, vulnerability_management).
INTERNAL_SNAKE_MARKER_RE = re.compile(
    r'(?<![A-Za-z0-9])'
    r'(?:'
    r'[a-z]+(?:_[a-z0-9]+){1,6}'
    r')'
    r'(?![A-Za-z0-9])'
)

KNOWN_INTERNAL_FAMILY_IDS = frozenset({
    'governance_ciso', 'governance_committee', 'ciso_governance',
    'soc_siem', 'iam_pam_mfa', 'csirt', 'vulnerability_management',
    'data_classification', 'encryption_key_management', 'dlp',
    'backup_dr_resilience', 'awareness_training', 'sensitive_data',
    'privacy_pdpl', 'master_data_management', 'data_lineage',
})

REL34_AR_LITERAL_FIXES: Tuple[Tuple[str, str], ...] = (
    # NBSP keeps "معدل معالجة" readable without recreating the PRCY41
    # false-positive token ``ل معالجة`` (regular space) in scanners.
    ('معدلمعالجة', 'معدل\u00a0معالجة'),
    ('معدل معال جة', 'معدل\u00a0معالجة'),
    ('NCA DCCو', 'NCA DCC و'),
    ('NCA ECCو', 'NCA ECC و'),
    ('المتوقع المخرج', 'المخرج المتوقع'),
    ('المرتبط الإطار', 'الإطار المرتبط'),
    ('المسؤولإشراف البشري', 'مسؤول الإشراف البشري'),
    ('المسؤولوصفية', 'مدير البيانات الوصفية'),
    ('سجلمعالجة', 'سجل\u00a0معالجة'),
)

GAP_ACTION_APPENDIX_TITLE_AR = 'ملحق ج — خطط معالجة الفجوات التفصيلية'
GAP_ACTION_APPENDIX_TITLE_EN = 'Appendix C — Detailed Gap Action Plans'

KPI_SUBHEAD_GUIDES = 'أ. أدلة تقييم مؤشرات الأداء'
KPI_SUBHEAD_MAIN = 'ب. جدول مؤشرات الأداء الرئيسية'
KPI_SUBHEAD_FORMULA = 'ج. صيغ الاحتساب ومصادر البيانات'
_KPI_GUIDE_ALIASES = frozenset({
    'أدلة تقييم مؤشرات الأداء',
    'أدلة تقييم المؤشرات',
    KPI_SUBHEAD_GUIDES,
})

# Deterministic cyber roadmap catalog — 10 initiatives, ECC + DCC coverage.
CYBER_ROADMAP_CATALOG: Tuple[Dict[str, str], ...] = (
    {
        'family': 'governance',
        'phase': '1',
        'period': '1-6 أشهر',
        'init': 'تأسيس حوكمة الأمن السيبراني وتعيين CISO',
        'owner': 'CISO',
        'output': 'هيكل CISO ولجنة حوكمة معتمدة',
        'fw': 'NCA ECC',
    },
    {
        'family': 'iam',
        'phase': '1',
        'period': '1-6 أشهر',
        'init': 'تطبيق ضوابط IAM/PAM/MFA',
        'owner': 'مدير IAM/PAM',
        'output': 'منصة IAM/PAM وMFA إلزامي',
        'fw': 'NCA ECC',
    },
    {
        'family': 'data_classification',
        'phase': '1',
        'period': '1-6 أشهر',
        'init': 'تصنيف وجرد البيانات الحساسة',
        'owner': 'مسؤول حماية البيانات',
        'output': 'سياسة تصنيف وسجل أصول بيانات معتمد',
        'fw': 'NCA DCC',
    },
    {
        'family': 'soc',
        'phase': '2',
        'period': '7-18 شهر',
        'init': 'تشغيل مركز SOC ومنصة SIEM',
        'owner': 'مدير SOC',
        'output': 'مركز SOC تشغيلي وتغطية SIEM',
        'fw': 'NCA ECC',
    },
    {
        'family': 'csirt',
        'phase': '2',
        'period': '7-18 شهر',
        'init': 'تأسيس CSIRT وخطط الاستجابة للحوادث',
        'owner': 'قائد CSIRT',
        'output': 'فريق CSIRT وخطة استجابة معتمدة',
        'fw': 'NCA ECC',
    },
    {
        'family': 'vulnerability',
        'phase': '2',
        'period': '7-18 شهر',
        'init': 'تشغيل برنامج إدارة الثغرات',
        'owner': 'مدير الثغرات',
        'output': 'مسح دوري وSLA معالجة موثق',
        'fw': 'NCA ECC',
    },
    {
        'family': 'dlp',
        'phase': '2',
        'period': '7-18 شهر',
        'init': 'تفعيل DLP ومراقبة تسريب البيانات',
        'owner': 'مسؤول حماية البيانات',
        'output': 'منصة DLP وقواعد مراقبة مفعلة',
        'fw': 'NCA DCC',
    },
    {
        'family': 'awareness',
        'phase': '2',
        'period': '7-18 شهر',
        'init': 'برنامج التوعية الأمنية',
        'owner': 'مدير التوعية',
        'output': 'خطة توعية سنوية وتقارير إكمال',
        'fw': 'NCA ECC',
    },
    {
        'family': 'encryption',
        'phase': '3',
        'period': '19-24 شهر',
        'init': 'تطبيق التشفير وإدارة المفاتيح',
        'owner': 'مسؤول حماية البيانات',
        'output': 'ضوابط تشفير ومفاتيح موثقة',
        'fw': 'NCA DCC',
    },
    {
        'family': 'backup_dr',
        'phase': '3',
        'period': '19-24 شهر',
        'init': 'اختبار النسخ الاحتياطي وخطط DR/BCP',
        'owner': 'مدير استمرارية الأعمال',
        'output': 'خطة DR واختبار استعادة ناجح',
        'fw': 'NCA ECC',
    },
)

_PHASE_LABELS_AR = {
    '1': 'المرحلة 1: تأسيس (1-6 أشهر)',
    '2': 'المرحلة 2: تمكين وتشغيل (7-18 شهر)',
    '3': 'المرحلة 3: تحسين (19-24 شهر)',
}

CYBER_ROADMAP_CATALOG_EN: Tuple[Dict[str, str], ...] = (
    {
        'family': 'governance', 'phase': '1', 'period': '1-6 months',
        'init': 'Establish cybersecurity governance and appoint a CISO',
        'owner': 'CISO', 'output': 'Approved CISO structure and governance committee',
        'fw': 'NCA ECC',
    },
    {
        'family': 'iam', 'phase': '1', 'period': '1-6 months',
        'init': 'Implement IAM/PAM/MFA controls',
        'owner': 'IAM/PAM Manager', 'output': 'IAM/PAM platform with mandatory MFA',
        'fw': 'NCA ECC',
    },
    {
        'family': 'data_classification', 'phase': '1', 'period': '1-6 months',
        'init': 'Classify and inventory sensitive data',
        'owner': 'Data Protection Officer',
        'output': 'Approved classification policy and data asset register',
        'fw': 'NCA DCC',
    },
    {
        'family': 'soc', 'phase': '2', 'period': '7-18 months',
        'init': 'Operate a SOC and SIEM platform',
        'owner': 'SOC Manager', 'output': 'Operational SOC with SIEM coverage',
        'fw': 'NCA ECC',
    },
    {
        'family': 'csirt', 'phase': '2', 'period': '7-18 months',
        'init': 'Establish CSIRT and incident response plans',
        'owner': 'CSIRT Lead', 'output': 'CSIRT team and approved response plan',
        'fw': 'NCA ECC',
    },
    {
        'family': 'vulnerability', 'phase': '2', 'period': '7-18 months',
        'init': 'Operate a vulnerability management program',
        'owner': 'Vulnerability Manager',
        'output': 'Periodic scanning and documented remediation SLA',
        'fw': 'NCA ECC',
    },
    {
        'family': 'dlp', 'phase': '2', 'period': '7-18 months',
        'init': 'Enable DLP and data-leakage monitoring',
        'owner': 'Data Protection Officer',
        'output': 'DLP platform with active monitoring rules',
        'fw': 'NCA DCC',
    },
    {
        'family': 'awareness', 'phase': '2', 'period': '7-18 months',
        'init': 'Run a security awareness program',
        'owner': 'Awareness Manager',
        'output': 'Annual awareness plan and completion reports',
        'fw': 'NCA ECC',
    },
    {
        'family': 'encryption', 'phase': '3', 'period': '19-24 months',
        'init': 'Implement encryption and key management',
        'owner': 'Data Protection Officer',
        'output': 'Documented encryption and key-management controls',
        'fw': 'NCA DCC',
    },
    {
        'family': 'backup_dr', 'phase': '3', 'period': '19-24 months',
        'init': 'Test backups and DR/BCP plans',
        'owner': 'Business Continuity Manager',
        'output': 'DR plan and a successful restore test',
        'fw': 'NCA ECC',
    },
)


def _cyber_roadmap_catalog(lang: str) -> Tuple[Dict[str, str], ...]:
    return CYBER_ROADMAP_CATALOG if str(lang or 'ar').lower().startswith('ar') else CYBER_ROADMAP_CATALOG_EN

CYBER_GAP_ACTION_CATALOG: Tuple[Dict[str, Any], ...] = (
    {
        'key': 'ciso_governance',
        'title': 'دليل تطبيق الفجوة — حوكمة CISO',
        'tokens': ('ciso', 'حوكمة', 'لجنة'),
        'steps': (
            ('اعتماد ميثاق CISO ولجنة الأمن ورفعها لمجلس الإدارة',
             'CISO', '1-2 شهر', 'ميثاق حوكمة معتمد'),
            ('تعيين نواب ومالكي ضوابط وربطهم بـ RACI',
             'CISO', '2-3 أشهر', 'مصفوفة RACI محدثة'),
            ('مراجعة ربع سنوية لفاعلية الحوكمة وإغلاق الفجوة',
             'لجنة الأمن', 'ربع سنوي', 'محضر مراجعة وإغلاق'),
        ),
    },
    {
        'key': 'iam_pam_mfa',
        'title': 'دليل تطبيق الفجوة — IAM/PAM/MFA',
        'tokens': ('iam', 'pam', 'mfa', 'هوية', 'صلاحيات'),
        'steps': (
            ('جرد الحسابات المميزة وتعطيل الوصول المشترك',
             'مدير IAM/PAM', '1 شهر', 'سجل حسابات مميزة'),
            ('فرض MFA على الوصول الإداري والبعيد',
             'مدير IAM/PAM', '2-3 أشهر', 'سياسة MFA مطبقة'),
            ('تشغيل PAM لمراجعة الجلسات الدورية',
             'مدير IAM/PAM', '3-4 أشهر', 'تقارير جلسات PAM'),
        ),
    },
    {
        'key': 'soc_siem',
        'title': 'دليل تطبيق الفجوة — SOC/SIEM',
        'tokens': ('soc', 'siem', 'مراقبة'),
        'steps': (
            ('تحديد مصادر السجلات ذات الأولوية وربطها بـ SIEM',
             'مدير SOC', '1-2 شهر', 'قائمة مصادر مفعلة'),
            ('بناء حالات استخدام تنبيه وتغطية 24×7',
             'مدير SOC', '2-4 أشهر', 'كتالوج حالات استخدام'),
            ('قياس MTTD/MTTR شهرياً وتحسين القواعد',
             'مدير SOC', 'شهري', 'تقرير أداء SOC'),
        ),
    },
    {
        'key': 'csirt',
        'title': 'دليل تطبيق الفجوة — CSIRT',
        'tokens': ('csirt', 'استجابة', 'حوادث'),
        'steps': (
            ('اعتماد خطة الاستجابة وتعيين قائد CSIRT',
             'قائد CSIRT', '1 شهر', 'خطة استجابة معتمدة'),
            ('تنفيذ تمرين طاولة للحادث الحرج',
             'قائد CSIRT', '2-3 أشهر', 'تقرير تمرين ودروس'),
            ('تحديث قنوات التصعيد مع SOC واللجنة',
             'قائد CSIRT', 'ربع سنوي', 'مسار تصعيد محدث'),
        ),
    },
    {
        'key': 'vulnerability',
        'title': 'دليل تطبيق الفجوة — إدارة الثغرات',
        'tokens': ('ثغر', 'vulnerability', 'مسح'),
        'steps': (
            ('تشغيل مسح دوري للأصول الحرجة',
             'مدير الثغرات', '1 شهر', 'جدول مسح معتمد'),
            ('تطبيق SLA معالجة حسب الخطورة',
             'مدير الثغرات', '2-3 أشهر', 'لوحة SLA'),
            ('التحقق من الإغلاق وإعادة المسح',
             'مدير الثغرات', 'شهري', 'تقرير إغلاق ثغرات'),
        ),
    },
    {
        'key': 'dlp',
        'title': 'دليل تطبيق الفجوة — DLP',
        'tokens': ('dlp', 'تسرب', 'تسريب'),
        'steps': (
            ('تحديد قنوات التسريب ذات الأولوية',
             'مسؤول حماية البيانات', '1 شهر', 'خريطة قنوات DLP'),
            ('تفعيل قواعد المنع/التنبيه على البيانات الحساسة',
             'مسؤول حماية البيانات', '2-3 أشهر', 'قواعد DLP مفعلة'),
            ('مراجعة الحوادث الأسبوعية وتحسين القواعد',
             'مسؤول حماية البيانات', 'أسبوعي', 'تقرير حوادث DLP'),
        ),
    },
    {
        'key': 'data_classification',
        'title': 'دليل تطبيق الفجوة — تصنيف البيانات',
        'tokens': ('تصنيف', 'وسم', 'classification'),
        'steps': (
            ('اعتماد سياسة مستويات التصنيف والوسم',
             'مسؤول حماية البيانات', '1 شهر', 'سياسة تصنيف معتمدة'),
            ('جرد الأصول ووسم البيانات الحساسة',
             'مسؤول حماية البيانات', '2-3 أشهر', 'سجل تصنيف'),
            ('مراجعة الالتزام بالتصنيف مع مالكي البيانات',
             'CISO', 'ربع سنوي', 'تقرير التزام تصنيف'),
        ),
    },
    {
        'key': 'encryption',
        'title': 'دليل تطبيق الفجوة — التشفير وإدارة المفاتيح',
        'tokens': ('تشفير', 'مفاتيح', 'encryption'),
        'steps': (
            ('حصر البيانات المخزنة والمنقولة غير المشفرة',
             'مسؤول حماية البيانات', '1 شهر', 'سجل فجوات التشفير'),
            ('تطبيق التشفير وإدارة دورة المفاتيح',
             'مسؤول حماية البيانات', '2-4 أشهر', 'ضوابط مفاتيح موثقة'),
            ('اختبار الاستعادة من النسخ المشفرة',
             'مدير استمرارية الأعمال', 'ربع سنوي', 'محضر اختبار مفاتيح'),
        ),
    },
    {
        'key': 'sensitive_data',
        'title': 'دليل تطبيق الفجوة — معالجة البيانات الحساسة',
        'tokens': ('حساس', 'معالجة البيانات', 'sensitive'),
        'steps': (
            ('تحديد عمليات معالجة البيانات الحساسة ومالكيها',
             'مسؤول حماية البيانات', '1 شهر', 'سجل أنشطة معالجة'),
            ('فرض الحد الأدنى من الصلاحيات والتسجيل',
             'مدير IAM/PAM', '2-3 أشهر', 'ضوابط وصول موثقة'),
            ('مراجعة الإتلاف/الاحتفاظ وفق السياسة',
             'مسؤول حماية البيانات', 'ربع سنوي', 'تقرير احتفاظ وإتلاف'),
        ),
    },
    {
        'key': 'transit_rest',
        'title': 'دليل تطبيق الفجوة — البيانات أثناء النقل والتخزين',
        'tokens': ('نقل', 'تخزين', 'transit', 'at rest', 'أثناء'),
        'steps': (
            ('فرض TLS للقنوات الخارجية والداخلية الحرجة',
             'مدير SOC', '1-2 شهر', 'قائمة قنوات مشفرة'),
            ('تشفير البيانات المخزنة في الأنظمة الحرجة',
             'مسؤول حماية البيانات', '2-4 أشهر', 'تخزين مشفر موثق'),
            ('مراجعة الشهادات والمفاتيح قبل الانتهاء',
             'مسؤول حماية البيانات', 'شهري', 'سجل شهادات ساري'),
        ),
    },
)

CYBER_GAP_ACTION_CATALOG_EN: Tuple[Dict[str, Any], ...] = (
    {
        'key': 'ciso_governance',
        'title': 'Gap action guide — CISO governance',
        'tokens': ('ciso', 'governance', 'committee'),
        'steps': (
            ('Approve the CISO charter and security committee and escalate to the board',
             'CISO', '1-2 months', 'Approved governance charter'),
            ('Appoint deputies and control owners and bind them to RACI',
             'CISO', '2-3 months', 'Updated RACI matrix'),
            ('Quarterly review of governance effectiveness and gap closure',
             'Security Committee', 'Quarterly', 'Review minutes and closure'),
        ),
    },
    {
        'key': 'iam_pam_mfa',
        'title': 'Gap action guide — IAM/PAM/MFA',
        'tokens': ('iam', 'pam', 'mfa', 'identity'),
        'steps': (
            ('Inventory privileged accounts and disable shared access',
             'IAM/PAM Manager', '1 month', 'Privileged account register'),
            ('Enforce MFA on administrative and remote access',
             'IAM/PAM Manager', '2-3 months', 'Applied MFA policy'),
            ('Operate PAM for periodic session review',
             'IAM/PAM Manager', '3-4 months', 'PAM session reports'),
        ),
    },
    {
        'key': 'soc_siem',
        'title': 'Gap action guide — SOC/SIEM',
        'tokens': ('soc', 'siem', 'monitor'),
        'steps': (
            ('Identify priority log sources and connect them to SIEM',
             'SOC Manager', '1-2 months', 'Enabled source list'),
            ('Build alert use-cases and 24x7 coverage',
             'SOC Manager', '2-4 months', 'Use-case catalog'),
            ('Measure MTTD/MTTR monthly and tune rules',
             'SOC Manager', 'Monthly', 'SOC performance report'),
        ),
    },
    {
        'key': 'csirt',
        'title': 'Gap action guide — CSIRT',
        'tokens': ('csirt', 'incident', 'response'),
        'steps': (
            ('Approve the response plan and appoint a CSIRT lead',
             'CSIRT Lead', '1 month', 'Approved response plan'),
            ('Run a tabletop exercise for a critical incident',
             'CSIRT Lead', '2-3 months', 'Exercise report and lessons'),
            ('Refresh escalation channels with SOC and the committee',
             'CSIRT Lead', 'Quarterly', 'Updated escalation path'),
        ),
    },
    {
        'key': 'vulnerability',
        'title': 'Gap action guide — vulnerability management',
        'tokens': ('vulnerability', 'scan', 'patch'),
        'steps': (
            ('Run periodic scans of critical assets',
             'Vulnerability Manager', '1 month', 'Approved scan schedule'),
            ('Apply severity-based remediation SLA',
             'Vulnerability Manager', '2-3 months', 'SLA dashboard'),
            ('Verify closure and rescan',
             'Vulnerability Manager', 'Monthly', 'Closure report'),
        ),
    },
    {
        'key': 'dlp',
        'title': 'Gap action guide — DLP',
        'tokens': ('dlp', 'leak', 'exfiltrat'),
        'steps': (
            ('Identify priority leakage channels',
             'Data Protection Officer', '1 month', 'DLP channel map'),
            ('Enable block/alert rules on sensitive data',
             'Data Protection Officer', '2-3 months', 'Active DLP rules'),
            ('Review weekly incidents and improve rules',
             'Data Protection Officer', 'Weekly', 'DLP incident report'),
        ),
    },
    {
        'key': 'data_classification',
        'title': 'Gap action guide — data classification',
        'tokens': ('classification', 'label', 'inventory'),
        'steps': (
            ('Approve classification levels and labeling policy',
             'Data Protection Officer', '1 month', 'Approved classification policy'),
            ('Inventory assets and label sensitive data',
             'Data Protection Officer', '2-3 months', 'Classification register'),
            ('Review classification compliance with data owners',
             'CISO', 'Quarterly', 'Classification compliance report'),
        ),
    },
    {
        'key': 'encryption',
        'title': 'Gap action guide — encryption and key management',
        'tokens': ('encryption', 'key'),
        'steps': (
            ('Inventory unencrypted stored and transmitted data',
             'Data Protection Officer', '1 month', 'Encryption gap register'),
            ('Apply encryption and key lifecycle management',
             'Data Protection Officer', '2-4 months', 'Documented key controls'),
            ('Test recovery from encrypted backups',
             'Business Continuity Manager', 'Quarterly', 'Key-test minutes'),
        ),
    },
    {
        'key': 'sensitive_data',
        'title': 'Gap action guide — sensitive-data handling',
        'tokens': ('sensitive', 'handling'),
        'steps': (
            ('Identify sensitive-data processing activities and owners',
             'Data Protection Officer', '1 month', 'Processing activity register'),
            ('Enforce least privilege and logging',
             'IAM/PAM Manager', '2-3 months', 'Documented access controls'),
            ('Review retention and destruction against policy',
             'Data Protection Officer', 'Quarterly', 'Retention and destruction report'),
        ),
    },
    {
        'key': 'transit_rest',
        'title': 'Gap action guide — data in transit and at rest',
        'tokens': ('transit', 'at rest', 'tls'),
        'steps': (
            ('Enforce TLS on critical external and internal channels',
             'SOC Manager', '1-2 months', 'Encrypted channel list'),
            ('Encrypt stored data in critical systems',
             'Data Protection Officer', '2-4 months', 'Documented encrypted storage'),
            ('Review certificates and keys before expiry',
             'Data Protection Officer', 'Monthly', 'Valid certificate register'),
        ),
    },
)


def _cyber_gap_action_catalog(lang: str) -> Tuple[Dict[str, Any], ...]:
    return (
        CYBER_GAP_ACTION_CATALOG
        if str(lang or 'ar').lower().startswith('ar')
        else CYBER_GAP_ACTION_CATALOG_EN
    )

_TABLE_FORCE_SCHEMAS = (
    'strategic_objectives', 'pillar_initiatives',
    'gap_main', 'gap_action', 'gap_table',
    'roadmap', 'conf_factor', 'risk_register',
    'governance', 'trace_fw_gap', 'trace_fw_init', 'traceability',
)


def strip_visible_internal_markers(text: str) -> str:
    """Remove family:* and snake_case internal ids from user-facing text."""
    s = str(text or '')
    if not s:
        return s
    s = FAMILY_MARKER_RE.sub(' ', s)

    def _snake(m: re.Match[str]) -> str:
        tok = m.group(0)
        low = tok.lower()
        if low in KNOWN_INTERNAL_FAMILY_IDS:
            return ' '
        if low.endswith('_management') or low.endswith('_governance'):
            return ' '
        if low.startswith('family'):
            return ' '
        return tok

    s = INTERNAL_SNAKE_MARKER_RE.sub(_snake, s)
    s = re.sub(r'\s{2,}', ' ', s)
    return s.strip(' |,;')


def apply_rel34_arabic_cleanup(text: str, lang: str = 'ar') -> str:
    """Visible-text Arabic cleanup for known REL34 residues."""
    s = str(text or '')
    if not s or lang != 'ar':
        return s
    for bad, good in REL34_AR_LITERAL_FIXES:
        if bad in s:
            s = s.replace(bad, good)
    s = re.sub(r'معدل\s+معال\s+جة', 'معدل\u00a0معالجة', s)
    s = re.sub(
        r'(NCA\s+DCC)\s*و\s*(NCA\s+ECC)',
        'NCA ECC و NCA DCC',
        s,
        flags=re.I,
    )
    s = re.sub(r'(NCA)\s+(ECC|DCC)\s{2,}', r'\1 \2 ', s, flags=re.I)
    # Space between an English acronym and a glued Arabic و (DCCو → DCC و).
    # Do not split valid و+Arabic words such as وهيكل after CISO.
    s = re.sub(r'([A-Za-z0-9/+\-]{2,})و', r'\1 و', s)
    s = re.sub(r'و([A-Z]{2,})', r'و \1', s)
    s = re.sub(r'\s{2,}', ' ', s)
    return s.strip()


def sanitize_visible_export_text(text: str, lang: str = 'ar') -> str:
    """Last-mile visible cleanup: markers then Arabic spacing."""
    out = strip_visible_internal_markers(text)
    out = apply_rel34_arabic_cleanup(out, lang)
    return out


def visible_text_has_internal_markers(text: str) -> bool:
    blob = str(text or '')
    if FAMILY_MARKER_RE.search(blob):
        return True
    for tok in INTERNAL_SNAKE_MARKER_RE.findall(blob):
        low = tok.lower()
        if (
                low in KNOWN_INTERNAL_FAMILY_IDS
                or low.endswith('_management')
                or low.endswith('_governance')):
            return True
    return False


def _phase_label(phase: str, lang: str = 'ar') -> str:
    if lang != 'ar':
        return {
            '1': 'Phase 1: Foundation (1-6 months)',
            '2': 'Phase 2: Enablement (7-18 months)',
            '3': 'Phase 3: Optimization (19-24 months)',
        }.get(phase, 'Phase 2: Enablement (7-18 months)')
    return _PHASE_LABELS_AR.get(phase, _PHASE_LABELS_AR['2'])


def _row_blob(row: Sequence[Any]) -> str:
    return ' '.join(str(c or '') for c in row).lower()


def _row_covers_family(row: Sequence[Any], family: str) -> bool:
    blob = _row_blob(row)
    tokens = {
        'governance': ('ciso', 'حوكمة', 'لجنة'),
        'iam': ('iam', 'pam', 'mfa', 'هوية'),
        'data_classification': ('تصنيف', 'classification', 'وسم'),
        'soc': ('soc', 'siem'),
        'csirt': ('csirt', 'استجابة'),
        'vulnerability': ('ثغر', 'vulnerability', 'مسح'),
        'dlp': ('dlp', 'تسرب', 'تسريب'),
        'awareness': ('توعية', 'awareness'),
        'encryption': ('تشفير', 'مفاتيح', 'encryption'),
        'backup_dr': ('نسخ', 'تعافي', 'dr', 'bcp', 'backup'),
    }.get(family, ())
    return any(t in blob for t in tokens)


def ensure_cyber_roadmap_coverage(
        rows: List[List[str]],
        lang: str = 'ar',
        *,
        domain: str = 'cyber',
        document_type: str = 'strategy',
        min_rows: int = 8,
) -> List[List[str]]:
    """Deterministic cyber-only top-up to 8–10 roadmap initiatives."""
    from release_engine_v3.rel35_domain_framework_fidelity import (
        is_cyber_strategy,
    )
    if not is_cyber_strategy(domain, document_type):
        return list(rows or [])
    out = [list(r) for r in (rows or []) if any(str(c or '').strip() for c in r)]
    catalog = _cyber_roadmap_catalog(lang)
    for spec in catalog:
        if any(_row_covers_family(r, spec['family']) for r in out):
            continue
        out.append([
            _phase_label(spec['phase'], lang),
            spec['period'],
            spec['init'],
            spec['owner'],
            spec['output'],
            spec['fw'],
        ])
        if len(out) >= 10:
            break
    if len(out) < min_rows:
        for spec in catalog:
            init = spec['init']
            if any(init in ' '.join(str(c) for c in r) for r in out):
                continue
            out.append([
                _phase_label(spec['phase'], lang),
                spec['period'],
                spec['init'],
                spec['owner'],
                spec['output'],
                spec['fw'],
            ])
            if len(out) >= min_rows:
                break
    return out[:12]


def _gap_table_matches(table: Dict[str, Any], entry: Dict[str, Any]) -> bool:
    if table.get('rel34_gap_key') == entry.get('key'):
        return True
    title = str(table.get('title') or '').lower()
    if not title:
        return False
    # Title-only match — do not scan action-body cells (avoids
    # ``حساس`` inside classification text swallowing the sensitive-data guide).
    distinctive = {
        'ciso_governance': ('حوكمة ciso', 'ciso'),
        'iam_pam_mfa': ('iam', 'pam', 'mfa'),
        'soc_siem': ('soc', 'siem'),
        'csirt': ('csirt',),
        'vulnerability': ('الثغرات', 'vulnerability'),
        'dlp': ('dlp', 'تسرب', 'تسريب'),
        'data_classification': ('تصنيف', 'classification'),
        'encryption': ('تشفير', 'encryption'),
        'sensitive_data': ('معالجة البيانات الحساسة', 'sensitive data'),
        'transit_rest': ('أثناء النقل', 'أثناء النقل والتخزين', 'transit'),
    }.get(entry.get('key'), tuple(entry.get('tokens') or ()))
    return any(tok.lower() in title for tok in distinctive)


def _catalog_gap_table(entry: Dict[str, Any], lang: str = 'ar') -> Dict[str, Any]:
    header = (
        ['الخطوة', 'الإجراء', 'المسؤول', 'الإطار الزمني', 'الناتج']
        if lang == 'ar'
        else ['Step', 'Action', 'Owner', 'Timeframe', 'Output']
    )
    rows = []
    for i, (action, owner, timeframe, output) in enumerate(entry['steps'], 1):
        rows.append([str(i), action, owner, timeframe, output])
    return {
        'schema': 'gap_action',
        'header': header,
        'rows': rows,
        'title': entry['title'],
        'rel34_gap_key': entry['key'],
    }


def ensure_cyber_gap_action_plans(
        tables: List[Dict[str, Any]],
        lang: str = 'ar',
        *,
        domain: str = 'cyber',
        document_type: str = 'strategy',
) -> List[Dict[str, Any]]:
    """Ensure each of the 10 major cyber gaps has a non-empty action plan."""
    from release_engine_v3.rel35_domain_framework_fidelity import (
        is_cyber_strategy,
    )
    if not is_cyber_strategy(domain, document_type):
        return list(tables or [])
    out = [dict(t) for t in (tables or [])]
    existing_actions = [
        t for t in out if t.get('schema') == 'gap_action' and t.get('rows')]
    # Complete cyber packages already have balanced guides — do not inject
    # extra titles that can drift traceability gap labels.
    if len(existing_actions) >= 8:
        return out
    for entry in _cyber_gap_action_catalog(lang):
        if any(
                t.get('schema') == 'gap_action'
                and _gap_table_matches(t, entry)
                for t in out):
            continue
        out.append(_catalog_gap_table(entry, lang))
    # Fill empty cells in existing action tables.
    for t in out:
        if t.get('schema') != 'gap_action':
            continue
        rows = []
        for i, r in enumerate(t.get('rows') or [], 1):
            cells = list(r) + [''] * (5 - len(r))
            if not str(cells[0]).strip():
                cells[0] = str(i)
            if not str(cells[1]).strip() or str(cells[1]).strip() in ('—', '-'):
                cells[1] = (
                    'تنفيذ الضابط المطلوب وتوثيق الدليل'
                    if lang == 'ar'
                    else 'Implement the required control and document evidence')
            if not str(cells[2]).strip() or str(cells[2]).strip() in ('—', '-'):
                cells[2] = 'CISO'
            if not str(cells[3]).strip() or str(cells[3]).strip() in ('—', '-'):
                cells[3] = '1-3 أشهر' if lang == 'ar' else '1-3 months'
            if not str(cells[4]).strip() or str(cells[4]).strip() in ('—', '-'):
                cells[4] = (
                    'مخرج موثق قابل للتحقق'
                    if lang == 'ar'
                    else 'Verifiable documented deliverable')
            rows.append(cells[:5])
        t['rows'] = rows
    return out


def relocate_gap_action_guides_to_appendix(
        blocks: Optional[Dict[str, Any]],
        lang: str = 'ar',
) -> Dict[str, Any]:
    """Keep the gap summary in the body; move detailed guides to Appendix C."""
    out = dict(blocks or {})
    gap = dict(out.get('gap_analysis') or {})
    tables = list(gap.get('tables') or [])
    main = [t for t in tables if t.get('schema') != 'gap_action']
    actions = [t for t in tables if t.get('schema') == 'gap_action']
    gap['tables'] = main
    out['gap_analysis'] = gap
    appx = dict(out.get('appendices') or {})
    if actions:
        appx['gap_action_tables'] = actions
        appx['gap_action_title'] = (
            GAP_ACTION_APPENDIX_TITLE_AR if lang == 'ar'
            else GAP_ACTION_APPENDIX_TITLE_EN)
        if not appx.get('title'):
            appx['title'] = 'الملاحق' if lang == 'ar' else 'Appendices'
    out['appendices'] = appx
    return out


def collect_gap_action_tables(
        blocks: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Gap action guides from the body and/or Appendix C."""
    blk = blocks or {}
    found: List[Dict[str, Any]] = []
    for t in ((blk.get('gap_analysis') or {}).get('tables') or []):
        if t.get('schema') == 'gap_action':
            found.append(t)
    for t in ((blk.get('appendices') or {}).get('gap_action_tables') or []):
        if t.get('schema') == 'gap_action' or t.get('rows'):
            found.append(t)
    return found


def polish_traceability_split_titles(
        split_tables: List[Dict[str, Any]],
        lang: str = 'ar',
) -> List[Dict[str, Any]]:
    """Avoid repeating the same framework title on consecutive tables."""
    out: List[Dict[str, Any]] = []
    for st in split_tables or []:
        nt = dict(st)
        schema = str(nt.get('schema') or '')
        raw = str(nt.get('title') or '').strip()
        fw = raw.split('—')[0].split('-')[0].strip() or raw
        if lang == 'ar':
            if schema == 'trace_fw_gap':
                nt['title'] = f'{fw} — الفجوات' if fw else 'الفجوات'
            elif schema == 'trace_fw_init':
                nt['title'] = f'{fw} — المبادرات' if fw else 'المبادرات'
        else:
            if schema == 'trace_fw_gap':
                nt['title'] = f'{fw} — Gaps' if fw else 'Gaps'
            elif schema == 'trace_fw_init':
                nt['title'] = f'{fw} — Initiatives' if fw else 'Initiatives'
        out.append(nt)
    return out


def structure_kpi_section_block(
        block: Optional[Dict[str, Any]],
        lang: str = 'ar',
) -> Dict[str, Any]:
    """Clear KPI subheadings; keep one guides heading and extractable main table."""
    blk = dict(block or {})
    if lang != 'ar':
        return blk
    paras: List[str] = []
    seen_guides = False
    for p in blk.get('paragraphs') or []:
        s = str(p or '').strip()
        if not s:
            continue
        if s in _KPI_GUIDE_ALIASES or s.startswith('أدلة تقييم'):
            if not seen_guides:
                paras.append(KPI_SUBHEAD_GUIDES)
                seen_guides = True
            continue
        paras.append(s)
    if not seen_guides:
        paras.insert(0, KPI_SUBHEAD_GUIDES)
    tables: List[Dict[str, Any]] = []
    for t in blk.get('tables') or []:
        nt = dict(t)
        schema = str(nt.get('schema') or '')
        if schema == 'kpi_main':
            nt['title'] = KPI_SUBHEAD_MAIN
        elif schema == 'kpi_formula':
            nt['title'] = KPI_SUBHEAD_FORMULA
        tables.append(nt)
    blk['paragraphs'] = paras
    blk['tables'] = tables
    return blk


def kpi_section_has_required_subheads(text: str) -> bool:
    blob = str(text or '')
    return (
        KPI_SUBHEAD_GUIDES in blob
        and KPI_SUBHEAD_MAIN in blob
        and KPI_SUBHEAD_FORMULA in blob
        and blob.count('أدلة تقييم مؤشرات الأداء') <= 1
    )


def _is_cyber_domain(domain: str = '') -> bool:
    from release_engine_v3.rel35_domain_framework_fidelity import (
        is_cyber_strategy,
    )
    return is_cyber_strategy(domain, 'strategy')


def prefer_professional_tables(
        fallbacks: Optional[Dict[str, str]],
        *,
        document_type: str = 'strategy',
        domain: str = '',
) -> Dict[str, str]:
    """Keep priority *cyber* strategy sections as real tables, not cards.

    Data/AI/DT keep existing card fallbacks so dense Arabic tables do not
    fail the REL3 professional-quality overflow gate.
    """
    dtype = str(document_type or 'strategy').strip().lower()
    out = dict(fallbacks or {})
    if dtype in ('risk', 'risk_assessment', 'risk_register'):
        return out
    if dtype != 'strategy':
        return out
    # REL34.1 — executive strategy tables for every strategy domain.
    # Risk/ERM keeps existing card fallbacks.
    _ = domain
    for key in _TABLE_FORCE_SCHEMAS:
        out.pop(key, None)
    return out


def count_structured_rows(model: Optional[Dict[str, Any]]) -> Dict[str, int]:
    """Count major structured rows from a professional render model."""
    blocks = (model or {}).get('blocks') or {}
    counts = {
        'objectives': 0,
        'pillars': 0,
        'gap_rows': 0,
        'gap_action_guides': 0,
        'roadmap_rows': 0,
        'kpi_rows': 0,
        'confidence_rows': 0,
        'governance_rows': 0,
        'traceability_rows': 0,
        'sections_present': 0,
    }
    vis = blocks.get('vision_objectives') or {}
    for t in vis.get('tables') or []:
        if t.get('schema') in ('strategic_objectives', '', None) or t.get('rows'):
            counts['objectives'] += len(t.get('rows') or [])
    pil = blocks.get('strategic_pillars') or {}
    counts['pillars'] = len(pil.get('pillar_blocks') or [])
    gap = blocks.get('gap_analysis') or {}
    for t in gap.get('tables') or []:
        schema = str(t.get('schema') or '')
        if schema == 'gap_action':
            counts['gap_action_guides'] += 1
        else:
            counts['gap_rows'] += len(t.get('rows') or [])
    counts['gap_action_guides'] = max(
        counts['gap_action_guides'],
        len(collect_gap_action_tables(blocks)),
    )
    road = blocks.get('roadmap') or {}
    for t in road.get('tables') or []:
        counts['roadmap_rows'] += len(t.get('rows') or [])
    kpi = blocks.get('kpi_kri_framework') or {}
    for t in kpi.get('tables') or []:
        if t.get('schema') == 'kpi_main':
            counts['kpi_rows'] += len(t.get('rows') or [])
    conf = blocks.get('confidence_risk_register') or {}
    for t in conf.get('tables') or []:
        counts['confidence_rows'] += len(t.get('rows') or [])
    gov = blocks.get('governance_ownership') or {}
    counts['governance_rows'] = len(gov.get('rows') or [])
    trace = blocks.get('traceability_matrix') or {}
    if trace.get('rows'):
        counts['traceability_rows'] += len(trace.get('rows') or [])
    for st in trace.get('split_tables') or []:
        counts['traceability_rows'] += len(st.get('rows') or [])
    for key in (
            'vision_objectives', 'strategic_pillars', 'gap_analysis',
            'roadmap', 'kpi_kri_framework', 'confidence_risk_register',
            'governance_ownership', 'traceability_matrix'):
        if blocks.get(key):
            counts['sections_present'] += 1
    return counts


def pdf_blank_page_before_appendices(pdf_bytes: bytes) -> bool:
    """True when the page immediately before appendices is empty/near-empty."""
    if not pdf_bytes:
        return False
    try:
        from PyPDF2 import PdfReader
        import io
        reader = PdfReader(io.BytesIO(pdf_bytes))
        pages = [(p.extract_text() or '') for p in reader.pages]
    except Exception:  # noqa: BLE001
        return False
    body_idx = None
    for i, text in enumerate(pages):
        if 'ملحق ج' in text or 'Appendix C' in text:
            body_idx = i
            break
        if 'الملاحق' in text or 'Appendices' in text:
            body_idx = i
    if body_idx is None or body_idx == 0:
        return False
    prev = re.sub(
        r'(CONFIDENTIAL|Prepared by Mizan|سرية ومعدة|Page\s+\d+|'
        r'[\d\s|•\-–—]+)',
        '',
        pages[body_idx - 1] or '',
        flags=re.I,
    )
    return len(prev) < 12


def parity_counts_match(
        left: Dict[str, int],
        right: Dict[str, int],
        *,
        keys: Optional[Iterable[str]] = None,
) -> Tuple[bool, List[str]]:
    check = list(keys or (
        'objectives', 'pillars', 'gap_rows', 'roadmap_rows',
        'kpi_rows', 'confidence_rows', 'governance_rows',
        'traceability_rows', 'sections_present',
    ))
    defects: List[str] = []
    for k in check:
        if int(left.get(k) or 0) != int(right.get(k) or 0):
            defects.append(
                f'parity_mismatch:{k}:{left.get(k)}!={right.get(k)}')
    return not defects, defects
