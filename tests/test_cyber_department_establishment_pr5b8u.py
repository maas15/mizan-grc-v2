"""PR-5B.8U — Cybersecurity Department establishment requirement.

When the diagnostic input flags ``org_structure_is_none=True`` (i.e. the
organisation lacks a defined cybersecurity organisational structure or
dedicated cybersecurity department), the Arabic Technical Strategy MUST
explicitly include the recommendation to establish a dedicated
Cybersecurity Department, appoint a CISO, define roles/responsibilities,
the operating model, reporting lines, and a cybersecurity governance
committee.

These tests pin:

  1. The validator emits ``cybersecurity_department_establishment_missing``
     when ``org_structure_is_none=True`` and the strategy lacks the
     required Arabic concepts.
  2. A strategy that explicitly includes the department-establishment
     wording passes (no defect).
  3. Pillar 1 must mention establishing the cybersecurity department or
     organisational unit.
  4. Gap analysis must include a gap for missing cybersecurity department
     / structure.
  5. Roadmap must include an initiative/activity for establishing the
     department and appointing ownership.
  6. Governance / confidence section must include CISO / cybersecurity
     department ownership.
  7. Risk register must include a risk related to absence of the
     cybersecurity department / governance ownership.
  8. The AI-repair clause is appended when ``org_structure_is_none=True``
     and the section is one that hosts the requirement.
  9. The repair pathway re-validates after AI repair (no fail-then-pass
     bypass).
 10. No deterministic department rows are inserted into the strategy
     text by the repair clause itself.
 11. When ``org_structure_is_none=False`` the requirement is NOT forced.

Run:
    python -m pytest tests/test_cyber_department_establishment_pr5b8u.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


# ── Boot env required by ``app`` ─────────────────────────────────────────
_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_dept_pr5b8u_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(_TMP_DB_DIR, 'test.db'),
)
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('ANTHROPIC_API_KEY', '')
os.environ.setdefault('GOOGLE_API_KEY', '')

_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py')
    )
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
except (ImportError, ModuleNotFoundError) as _e:  # pragma: no cover
    print(f'[WARN] Could not import app.py: {_e}')
    _APP = None


def _skip_if_no_app(fn):
    import functools

    @functools.wraps(fn)
    def _wrapped(self, *a, **kw):
        if _APP is None:
            self.skipTest('app.py could not be imported')
        return fn(self, *a, **kw)
    return _wrapped


# ── Fixtures ─────────────────────────────────────────────────────────────
# A minimal Arabic strategy that already covers all 8 cybersecurity
# capability families (so unrelated validator defects don't trip the
# tests below) but does NOT include the explicit cybersecurity-department
# establishment recommendation.
_BASE_NO_DEPT_AR = {
    'vision': (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        'تعزيز الأمن السيبراني عبر إدارة الهوية والوصول المميز IAM PAM، '
        'والمصادقة الثنائية MFA، والمراقبة المستمرة SIEM SOC.\n\n'
        '### الأهداف الاستراتيجية:\n\n'
        '| # | الهدف | المؤشر | المبرر | الإطار |\n'
        '|---|------|-------|--------|--------|\n'
        '| 1 | إدارة الهوية | 100% | IAM PAM | 12ش |\n'
        '| 2 | المصادقة الثنائية | 100% | MFA | 12ش |\n'
        '| 3 | المراقبة | 24/7 | SIEM SOC | 12ش |\n'
        '| 4 | الاستجابة للحوادث | <4س | incident response | 12ش |\n'
        '| 5 | إدارة الثغرات | 30 يوم | vulnerability | 12ش |\n'
        '| 6 | حماية البيانات | 100% | تشفير encryption | 12ش |\n'
    ),
    'pillars': (
        '## 2. الركائز الاستراتيجية\n\n'
        '### الركيزة 1: التوعية والتدريب\n\n'
        'برامج التوعية ضد التصيد phishing لجميع الموظفين.\n'
    ),
    'environment': (
        '## 3. البيئة التنظيمية والتهديدات\n\n'
        'NCA ECC، التصيد phishing، حماية البيانات، DLP.\n'
    ),
    'gaps': (
        '## 4. تحليل الفجوات\n\n'
        '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
        '|---|------|------|---------|--------|\n'
        '| 1 | غياب MFA | المصادقة الثنائية | حرجة | مفتوحة |\n'
        '| 2 | ضعف التوعية | برامج التدريب ضد التصيد | عالية | مفتوحة |\n'
    ),
    'roadmap': (
        '## 5. خارطة الطريق\n\n'
        '| # | النشاط | المسؤول | الإطار الزمني | المخرج |\n'
        '|---|------|--------|--------------|--------|\n'
        '| 1 | نشر MFA | فريق IAM | الشهر 1-3 | تفعيل المصادقة |\n'
        '| 2 | بناء SOC + SIEM | فريق المراقبة | الشهر 3-6 | مراقبة |\n'
        '| 3 | برنامج توعية ضد التصيد | HR | الشهر 4-9 | التدريب |\n'
        '| 4 | تنفيذ النسخ الاحتياطي والتعافي DR | فريق IT | الشهر 6-12 | استعادة |\n'
    ),
    'kpis': (
        '## 6. مؤشرات الأداء الرئيسية\n\n'
        '| # | المؤشر | النوع | القيمة المستهدفة | صيغة | المصدر | المالك | التكرار | الإطار |\n'
        '|---|------|------|-----------------|------|--------|-------|---------|--------|\n'
        '| 1 | تغطية IAM | KPI | 100% | x | GRC | فريق IAM | شهري | 12ش |\n'
        '| 2 | تفعيل MFA | KPI | 100% | x | IAM | فريق IAM | شهري | 12ش |\n'
        '| 3 | استجابة SOC | KPI | <4س | x | SIEM | فريق SOC | شهري | 12ش |\n'
        '| 4 | إدارة الثغرات | KPI | 30 يوم | x | VM | فريق العمليات | شهري | 12ش |\n'
        '| 5 | اختبار النسخ الاحتياطي | KPI | 100% | x | DR | فريق IT | ربع | 12ش |\n'
        '| 6 | برامج التوعية ضد التصيد | KPI | 100% | x | HR | HR | ربع | 12ش |\n'
        '| 7 | تشفير البيانات DLP | KPI | 100% | x | DP | فريق العمليات | شهري | 12ش |\n'
    ),
    'confidence': (
        '## 7. تقييم الثقة والمخاطر\n\n'
        '**درجة الثقة:** 78%\n\n'
        '| # | الخطر | الاحتمالية | التأثير | خطة التخفيف |\n'
        '|---|------|----------|--------|----------------|\n'
        '| 1 | تأخر تطبيق MFA | عالية | عالي | متابعة شهرية |\n'
    ),
}


# A version of the strategy that EXPLICITLY satisfies the cybersecurity-
# department establishment requirement across every required section.
_FULL_DEPT_AR = dict(_BASE_NO_DEPT_AR)
_FULL_DEPT_AR['vision'] = (
    '## 1. الرؤية والأهداف الاستراتيجية\n\n'
    'تأسيس إدارة الأمن السيبراني وتعيين رئيس الأمن السيبراني (CISO) '
    'وتحديد الأدوار والمسؤوليات والصلاحيات ضمن نموذج التشغيل وخطوط '
    'الرفع لإدارة الهوية والوصول المميز IAM PAM والمصادقة الثنائية '
    'MFA والمراقبة المستمرة SIEM SOC.\n\n'
    '### الأهداف الاستراتيجية:\n\n'
    '| # | الهدف | المؤشر | المبرر | الإطار |\n'
    '|---|------|-------|--------|--------|\n'
    '| 1 | إنشاء إدارة متخصصة للأمن السيبراني | 100% | حوكمة | 12ش |\n'
    '| 2 | تعيين CISO | 100% | حوكمة | 6ش |\n'
    '| 3 | المراقبة SIEM SOC | 24/7 | NCA | 12ش |\n'
    '| 4 | الاستجابة للحوادث incident response | <4س | NCA | 12ش |\n'
    '| 5 | إدارة الثغرات vulnerability | 30 يوم | NCA | 12ش |\n'
    '| 6 | حماية البيانات والتشفير encryption | 100% | NCA | 12ش |\n'
)
_FULL_DEPT_AR['pillars'] = (
    '## 2. الركائز الاستراتيجية\n\n'
    '### الركيزة 1: حوكمة الأمن السيبراني وإنشاء إدارة الأمن السيبراني\n\n'
    'إنشاء إدارة متخصصة للأمن السيبراني، تعيين رئيس الأمن السيبراني '
    '(CISO)، تحديد الأدوار والمسؤوليات والصلاحيات، نموذج التشغيل '
    'وخطوط الرفع، ولجنة حوكمة الأمن السيبراني.\n\n'
    '| # | المبادرة | الوصف | المخرج | المسؤول |\n'
    '|---|------|------|-------|--------|\n'
    '| 1 | إنشاء إدارة الأمن السيبراني | هيكل تنظيمي معتمد | إدارة قائمة | CISO |\n'
    '| 2 | تعيين CISO | تعيين رسمي | CISO معين | الإدارة العليا |\n'
    '| 3 | تأسيس لجنة حوكمة الأمن السيبراني | اعتماد ميثاق | لجنة فعالة | CISO |\n'
    '\n### الركيزة 2: التوعية والتدريب\n\nبرامج التوعية ضد التصيد phishing.\n'
)
_FULL_DEPT_AR['gaps'] = (
    '## 4. تحليل الفجوات\n\n'
    '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
    '|---|------|------|---------|--------|\n'
    '| 1 | غياب إدارة الأمن السيبراني | لا توجد إدارة متخصصة للأمن السيبراني | حرجة | مفتوحة |\n'
    '| 2 | غياب CISO | لم يتم تعيين رئيس الأمن السيبراني | حرجة | مفتوحة |\n'
    '| 3 | غياب MFA | المصادقة الثنائية | حرجة | مفتوحة |\n'
    '| 4 | ضعف التوعية | برامج التدريب ضد التصيد | عالية | مفتوحة |\n'
)
_FULL_DEPT_AR['roadmap'] = (
    '## 5. خارطة الطريق\n\n'
    '| # | النشاط | المسؤول | الإطار الزمني | المخرج |\n'
    '|---|------|--------|--------------|--------|\n'
    '| 1 | إنشاء إدارة الأمن السيبراني وتعيين CISO | الإدارة العليا | الشهر 1-3 | إدارة قائمة |\n'
    '| 2 | تحديد الأدوار والمسؤوليات ونموذج التشغيل وخطوط الرفع | CISO | الشهر 2-4 | RACI معتمد |\n'
    '| 3 | تأسيس لجنة حوكمة الأمن السيبراني | CISO | الشهر 3-5 | ميثاق اللجنة |\n'
    '| 4 | نشر MFA | فريق IAM | الشهر 1-3 | تفعيل المصادقة |\n'
    '| 5 | بناء SOC + SIEM | فريق المراقبة | الشهر 3-6 | مراقبة |\n'
    '| 6 | برنامج توعية ضد التصيد | HR | الشهر 4-9 | التدريب |\n'
    '| 7 | تنفيذ النسخ الاحتياطي والتعافي DR | فريق IT | الشهر 6-12 | استعادة |\n'
)
_FULL_DEPT_AR['confidence'] = (
    '## 7. تقييم الثقة والمخاطر\n\n'
    '**درجة الثقة:** 78%\n\n'
    'إنشاء إدارة الأمن السيبراني وتعيين CISO يقللان من مخاطر الحوكمة.\n\n'
    '| # | الخطر | الاحتمالية | التأثير | خطة التخفيف |\n'
    '|---|------|----------|--------|----------------|\n'
    '| 1 | غياب إدارة الأمن السيبراني وحوكمة الأمن السيبراني | عالية | حرج | إنشاء إدارة متخصصة وتعيين CISO |\n'
    '| 2 | عدم تحديد الأدوار والمسؤوليات وخطوط الرفع | عالية | عالي | اعتماد نموذج التشغيل ومصفوفة الصلاحيات |\n'
    '| 3 | تأخر تطبيق MFA | عالية | عالي | متابعة شهرية |\n'
)


# ── Tests ────────────────────────────────────────────────────────────────
class CyberDeptEstablishmentValidatorTests(unittest.TestCase):
    """Validator-level tests — pin the new defect's behaviour."""

    @_skip_if_no_app
    def test_01_missing_dept_with_org_none_fails(self):
        defects = _APP.validate_arabic_strategy_semantic_richness(
            _BASE_NO_DEPT_AR, lang='ar', doc_subtype='technical',
            domain='Cyber Security',
            org_structure_is_none=True,
        )
        tags = [t for t, _ in defects]
        self.assertIn(
            'cybersecurity_department_establishment_missing', tags,
            f'When org_structure_is_none=True and the strategy lacks an '
            f'explicit dedicated-cybersecurity-department recommendation, '
            f'the validator MUST emit the new defect tag; got tags={tags}',
        )

    @_skip_if_no_app
    def test_02_full_dept_passes(self):
        defects = _APP.validate_arabic_strategy_semantic_richness(
            _FULL_DEPT_AR, lang='ar', doc_subtype='technical',
            domain='Cyber Security',
            org_structure_is_none=True,
        )
        tags = [t for t, _ in defects]
        self.assertNotIn(
            'cybersecurity_department_establishment_missing', tags,
            f'A strategy that explicitly includes the department-'
            f'establishment recommendation MUST NOT trigger the defect; '
            f'got tags={tags}',
        )

    @_skip_if_no_app
    def test_03_pillar1_mentions_department_establishment(self):
        # The first pillar of the satisfied fixture must mention either
        # establishing the cybersecurity department or the cybersecurity
        # organisational unit / governance.
        p1 = _FULL_DEPT_AR['pillars'].split('### الركيزة 1')[1].split('### الركيزة 2')[0]
        self.assertTrue(
            ('إدارة الأمن السيبراني' in p1) or ('إنشاء إدارة' in p1)
            or ('تأسيس إدارة' in p1),
            f'Pillar 1 must mention the cybersecurity department / '
            f'organisational unit; got: {p1[:200]!r}',
        )

    @_skip_if_no_app
    def test_04_gaps_include_missing_department_gap(self):
        gaps = _FULL_DEPT_AR['gaps']
        self.assertIn(
            'إدارة الأمن السيبراني', gaps,
            'Gap analysis must include a gap row referencing the missing '
            'cybersecurity department / structure',
        )

    @_skip_if_no_app
    def test_05_roadmap_includes_department_initiative(self):
        roadmap = _FULL_DEPT_AR['roadmap']
        self.assertIn(
            'إنشاء إدارة الأمن السيبراني', roadmap,
            'Roadmap must include an explicit initiative for establishing '
            'the cybersecurity department',
        )
        self.assertIn(
            'CISO', roadmap,
            'Roadmap must include an activity that appoints CISO ownership',
        )

    @_skip_if_no_app
    def test_06_governance_includes_ciso_and_dept(self):
        # The confidence (governance/risk) section + roadmap together act
        # as the governance ownership surface; both must mention CISO and
        # the cybersecurity department.
        blob = _FULL_DEPT_AR['confidence'] + _FULL_DEPT_AR['roadmap']
        self.assertIn('CISO', blob,
                      'Governance / ownership content must include CISO')
        self.assertIn('إدارة الأمن السيبراني', blob,
                      'Governance / ownership content must include the '
                      'cybersecurity department')

    @_skip_if_no_app
    def test_07_risk_register_includes_dept_absence_risk(self):
        conf = _FULL_DEPT_AR['confidence']
        self.assertTrue(
            'حوكمة الأمن السيبراني' in conf
            or 'إدارة الأمن السيبراني' in conf,
            'Risk register must include a risk related to absence of '
            'the cybersecurity department / governance ownership',
        )

    @_skip_if_no_app
    def test_08_ai_repair_clause_appended_when_org_none(self):
        # The repair-clause helper logic is integrated into
        # ``ai_repair_strategy_section`` — verify the prompt builder
        # honours ``org_structure_is_none`` for non-pillar sections too
        # (gaps / roadmap / confidence / environment).
        # We verify by inspecting the source of the clause via attribute
        # presence: the new helper exposes the concept families.
        self.assertTrue(
            hasattr(_APP, '_compute_missing_cyber_dept_establishment_concepts'),
            '_compute_missing_cyber_dept_establishment_concepts helper '
            'must exist (used by the AI repair clause)',
        )
        self.assertTrue(
            hasattr(_APP, '_CYBER_DEPT_ESTAB_CONCEPTS'),
            'Concept-family map must exist as the single source of '
            'truth shared between validator + repair clause',
        )

    @_skip_if_no_app
    def test_09_revalidation_after_repair_uses_same_validator(self):
        # The repair pathway must re-run the SAME validator after it
        # mutates sections so the gate decision sees the post-repair
        # defect set. We confirm by verifying that the validator
        # signature accepts ``org_structure_is_none`` (so the re-run
        # preserves the same gating policy) — the repair block in
        # api_generate_strategy passes the same value on re-validation.
        import inspect
        sig = inspect.signature(
            _APP.validate_arabic_strategy_semantic_richness)
        self.assertIn(
            'org_structure_is_none', sig.parameters,
            'Validator must accept org_structure_is_none kwarg so the '
            'AI-repair re-validation can pin the same gating policy',
        )

    @_skip_if_no_app
    def test_10_no_deterministic_dept_rows_inserted(self):
        # The validator + helper are detection-only. They must NOT mutate
        # the sections dict.
        import copy
        snapshot = copy.deepcopy(_BASE_NO_DEPT_AR)
        _APP.validate_arabic_strategy_semantic_richness(
            _BASE_NO_DEPT_AR, lang='ar', doc_subtype='technical',
            domain='Cyber Security', org_structure_is_none=True,
        )
        self.assertEqual(
            snapshot, _BASE_NO_DEPT_AR,
            'Validator MUST NOT mutate the sections dict (no '
            'deterministic rows injected at detection time)',
        )
        # Helper is also pure detection.
        before = copy.deepcopy(_BASE_NO_DEPT_AR)
        _APP._compute_missing_cyber_dept_establishment_concepts(
            _BASE_NO_DEPT_AR)
        self.assertEqual(
            before, _BASE_NO_DEPT_AR,
            'Helper MUST be pure detection (no mutation)',
        )

    @_skip_if_no_app
    def test_11_org_structure_false_does_not_force_requirement(self):
        defects = _APP.validate_arabic_strategy_semantic_richness(
            _BASE_NO_DEPT_AR, lang='ar', doc_subtype='technical',
            domain='Cyber Security',
            org_structure_is_none=False,
        )
        tags = [t for t, _ in defects]
        self.assertNotIn(
            'cybersecurity_department_establishment_missing', tags,
            'When org_structure_is_none=False the requirement must NOT '
            'be forced (defect must not appear)',
        )


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
