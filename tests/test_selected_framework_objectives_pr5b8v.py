"""PR-5B.8V — Selected-framework compliance OBJECTIVE coverage.

Verifies that when the user explicitly selects one or more frameworks
(ECC and/or TCC), the Vision/Strategic-Objectives section MUST contain
an explicit objective row whose subject is achieving compliance with
those frameworks.  AI-first repair is routed when the objective is
missing; the post-normalization gate fails closed when the AI cannot
produce a compliant repaired vision.

These tests exercise the pure detection helper
``_compute_missing_compliance_objective`` and the
``_final_strategy_audit`` integration that emits the
``selected_framework_compliance_objective_missing:<FW,FW>`` defect.

Run:
    python -m pytest tests/test_selected_framework_objectives_pr5b8v.py -q
"""
import importlib.util
import os
import sys
import tempfile
import unittest

# ── Boot env required by ``app`` ─────────────────────────────────────────
_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_fw_objectives_pr5b8v_')
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


# ── Fixtures ──────────────────────────────────────────────────────────────
# Vision section WITH an explicit compliance objective for both ECC + TCC.
_VISION_AR_WITH_COMPLIANCE_OBJ = (
    '## 1. الرؤية والأهداف الاستراتيجية\n\n'
    '**الرؤية:** بناء قدرات أمن سيبراني رائدة.\n\n'
    '### الأهداف الاستراتيجية\n\n'
    '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
    '| 1 | تعزيز إدارة الهوية والوصول المميز IAM/PAM | تغطية 100% | حوكمة | 12 شهراً |\n'
    '| 2 | تحقيق الالتزام بضوابط NCA ECC و NCA TCC | نسبة امتثال ≥ 90% '
    'للضوابط المختارة | مواءمة برنامج الأمن السيبراني | 12 شهراً |\n'
    '| 3 | تطوير مركز العمليات الأمنية SOC والمراقبة | 24/7 | الكشف المبكر '
    '| 9 أشهر |\n'
    '| 4 | الاستجابة للحوادث وإدارة الثغرات | < 4 ساعات | تقليل الأثر '
    '| 6 أشهر |\n'
    '| 5 | تأمين الوصول عن بُعد عبر VPN و MFA | 100% MFA | حماية '
    '| 9 أشهر |\n'
    '| 6 | تعزيز التوعية والتدريب ضد التصيد | 95% إكمال | بشري | 12 شهراً |\n'
)

# Vision WITHOUT a compliance objective (only operational objectives).
_VISION_AR_WITHOUT_COMPLIANCE_OBJ = (
    '## 1. الرؤية والأهداف الاستراتيجية\n\n'
    '**الرؤية:** بناء قدرات أمن سيبراني رائدة.\n\n'
    '### الأهداف الاستراتيجية\n\n'
    '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
    '| 1 | تعزيز إدارة الهوية والوصول المميز IAM/PAM | تغطية 100% | حوكمة | 12 شهراً |\n'
    '| 2 | تطوير مركز العمليات الأمنية SOC | 24/7 | كشف | 9 أشهر |\n'
    '| 3 | إدارة الثغرات والتصحيح الدوري | شهري | تقليل الأثر | 6 أشهر |\n'
    '| 4 | الاستجابة للحوادث | < 4 ساعات | احتواء | 6 أشهر |\n'
    '| 5 | تأمين الوصول عن بُعد عبر VPN و MFA | 100% MFA | حماية | 9 أشهر |\n'
    '| 6 | تعزيز التوعية والتدريب ضد التصيد | 95% إكمال | بشري | 12 شهراً |\n'
)

# Vision with ECC compliance objective only.
_VISION_AR_ECC_ONLY = (
    '## 1. الرؤية والأهداف الاستراتيجية\n\n'
    '**الرؤية:** بناء قدرات أمن سيبراني رائدة.\n\n'
    '### الأهداف الاستراتيجية\n\n'
    '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
    '| 1 | تحقيق الامتثال لضوابط NCA ECC | نسبة ≥ 90% | تنظيمي | 12 شهراً |\n'
    '| 2 | تعزيز إدارة الهوية والوصول المميز | تغطية 100% | حوكمة | 12 شهراً |\n'
    '| 3 | الاستجابة للحوادث | < 4 ساعات | احتواء | 6 أشهر |\n'
    '| 4 | المراقبة عبر SIEM | 24/7 | كشف | 9 أشهر |\n'
    '| 5 | إدارة الثغرات | شهري | حماية | 6 أشهر |\n'
    '| 6 | التدريب والتوعية | 95% | بشري | 12 شهراً |\n'
)

# Vision with TCC / remote-work compliance objective only.
_VISION_AR_TCC_ONLY = (
    '## 1. الرؤية والأهداف الاستراتيجية\n\n'
    '**الرؤية:** بناء قدرات أمن سيبراني للعمل عن بُعد.\n\n'
    '### الأهداف الاستراتيجية\n\n'
    '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
    '| 1 | مواءمة الأمن السيبراني مع ضوابط NCA TCC للعمل عن بُعد | '
    '≥ 90% امتثال | تنظيمي | 12 شهراً |\n'
    '| 2 | نشر VPN و MFA لجميع جلسات العمل عن بُعد | 100% | حماية '
    '| 9 أشهر |\n'
    '| 3 | إدارة الأجهزة المحمولة MDM | 100% | حماية | 6 أشهر |\n'
    '| 4 | منع تسرب البيانات DLP | تغطية كاملة | حماية | 9 أشهر |\n'
    '| 5 | الاستجابة للحوادث في بيئة العمل عن بُعد | < 4 ساعات | احتواء '
    '| 6 أشهر |\n'
    '| 6 | التوعية ضد التصيد عن بُعد | 95% | بشري | 12 شهراً |\n'
)

_VISION_EN_WITH_COMPLIANCE_OBJ = (
    '## 1. Vision & Strategic Objectives\n\n'
    '**Vision:** Build leading cybersecurity capabilities.\n\n'
    '### Strategic Objectives\n\n'
    '| # | Objective | Target Metric | Justification | Timeframe |\n'
    '|---|---|---|---|---|\n'
    '| 1 | Strengthen IAM/PAM | 100% | governance | 12 months |\n'
    '| 2 | Achieve compliance with selected NCA ECC and NCA TCC '
    'controls | ≥ 90% compliance | align programme | 12 months |\n'
    '| 3 | Build SOC and SIEM monitoring | 24/7 | detection | 9 months |\n'
    '| 4 | Incident response | < 4 hours | containment | 6 months |\n'
    '| 5 | Remote access via VPN and MFA | 100% | protection | 9 months |\n'
    '| 6 | Awareness and training | 95% | human | 12 months |\n'
)


def _sections_with(vision_text):
    return {'vision': vision_text}


# ── Tests ─────────────────────────────────────────────────────────────────
class ComputeMissingComplianceObjectiveTest(unittest.TestCase):

    @_skip_if_no_app
    def test_01_no_selected_frameworks_returns_empty(self):
        # Test 10 from spec: no selected frameworks means this objective
        # is not forced.
        f = _APP._compute_missing_compliance_objective
        self.assertEqual(
            f(_sections_with(_VISION_AR_WITHOUT_COMPLIANCE_OBJ), [],
              domain='Cyber Security', lang='ar'),
            [],
        )
        self.assertEqual(
            f(_sections_with(_VISION_AR_WITHOUT_COMPLIANCE_OBJ), None,
              domain='Cyber Security', lang='ar'),
            [],
        )

    @_skip_if_no_app
    def test_02_ecc_tcc_with_compliance_obj_passes(self):
        # Test 1 from spec: ECC+TCC strategy with explicit compliance
        # objective passes (no missing).
        f = _APP._compute_missing_compliance_objective
        missing = f(_sections_with(_VISION_AR_WITH_COMPLIANCE_OBJ),
                    ['NCA ECC', 'NCA TCC'],
                    domain='Cyber Security', lang='ar')
        self.assertEqual(
            missing, [],
            f'ECC+TCC with compliance obj should be covered; missing={missing!r}'
        )

    @_skip_if_no_app
    def test_03_ecc_tcc_missing_compliance_obj_emits_both(self):
        # Test 2 from spec: ECC+TCC missing compliance obj returns both.
        f = _APP._compute_missing_compliance_objective
        missing = f(_sections_with(_VISION_AR_WITHOUT_COMPLIANCE_OBJ),
                    ['NCA ECC', 'NCA TCC'],
                    domain='Cyber Security', lang='ar')
        self.assertIn('ECC', missing)
        self.assertIn('TCC', missing)

    @_skip_if_no_app
    def test_04_ecc_only_with_ecc_compliance_obj_passes(self):
        # Test 3 from spec: ECC-only strategy requires ECC compliance.
        f = _APP._compute_missing_compliance_objective
        missing = f(_sections_with(_VISION_AR_ECC_ONLY), ['NCA ECC'],
                    domain='Cyber Security', lang='ar')
        self.assertEqual(missing, [])

    @_skip_if_no_app
    def test_05_ecc_only_strategy_misses_ecc_when_no_compliance_obj(self):
        # Test 3 from spec: ECC-only must require ECC compliance objective.
        f = _APP._compute_missing_compliance_objective
        missing = f(_sections_with(_VISION_AR_WITHOUT_COMPLIANCE_OBJ),
                    ['NCA ECC'],
                    domain='Cyber Security', lang='ar')
        self.assertEqual(missing, ['ECC'])

    @_skip_if_no_app
    def test_06_tcc_only_strategy_satisfied_by_tcc_compliance_obj(self):
        # Test 4 from spec: TCC-only requires TCC/remote-work compliance.
        f = _APP._compute_missing_compliance_objective
        missing = f(_sections_with(_VISION_AR_TCC_ONLY), ['NCA TCC'],
                    domain='Cyber Security', lang='ar')
        self.assertEqual(missing, [])

    @_skip_if_no_app
    def test_07_tcc_only_strategy_misses_tcc_when_no_compliance_obj(self):
        f = _APP._compute_missing_compliance_objective
        missing = f(_sections_with(_VISION_AR_WITHOUT_COMPLIANCE_OBJ),
                    ['NCA TCC'],
                    domain='Cyber Security', lang='ar')
        self.assertEqual(missing, ['TCC'])

    @_skip_if_no_app
    def test_08_english_strategy_with_compliance_obj_passes(self):
        f = _APP._compute_missing_compliance_objective
        missing = f(_sections_with(_VISION_EN_WITH_COMPLIANCE_OBJ),
                    ['NCA ECC', 'NCA TCC'],
                    domain='Cyber Security', lang='en')
        self.assertEqual(missing, [])

    @_skip_if_no_app
    def test_09_vision_narrative_compliance_mention_alone_does_not_pass(self):
        # Mention of compliance only in the narrative paragraph must NOT
        # satisfy the requirement; it must be in the SO table.
        narrative_only = (
            '## 1. الرؤية والأهداف الاستراتيجية\n\n'
            '**الرؤية:** نسعى إلى تحقيق الالتزام بضوابط NCA ECC و TCC '
            'وبناء حوكمة متكاملة.\n\n'
            '### الأهداف الاستراتيجية\n\n'
            '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
            '|---|---|---|---|---|\n'
            '| 1 | تعزيز IAM/PAM | 100% | حوكمة | 12 شهراً |\n'
            '| 2 | بناء SOC | 24/7 | كشف | 9 أشهر |\n'
            '| 3 | الاستجابة للحوادث | < 4 ساعات | احتواء | 6 أشهر |\n'
        )
        f = _APP._compute_missing_compliance_objective
        missing = f(_sections_with(narrative_only),
                    ['NCA ECC', 'NCA TCC'],
                    domain='Cyber Security', lang='ar')
        self.assertIn('ECC', missing)
        self.assertIn('TCC', missing)


class FinalAuditEmitsComplianceObjectiveDefectTest(unittest.TestCase):

    @_skip_if_no_app
    def test_10_final_audit_emits_defect_when_compliance_obj_missing(self):
        # Build a minimally-passing strategy that lacks the compliance
        # objective. The final audit must emit
        # ``selected_framework_compliance_objective_missing:<FWs>``.
        sections = {
            'vision':      _VISION_AR_WITHOUT_COMPLIANCE_OBJ,
            'pillars':     '## 2. الركائز الاستراتيجية\n### الركيزة 1: '
                           'الحوكمة\nإطار حوكمة الأمن السيبراني وسياسات.\n',
            'environment': '## 3. البيئة التنظيمية\nNCA ECC.\n',
            'gaps':        '## 4. تحليل الفجوات\n| # | الفجوة | الوصف '
                           '| الأولوية | الحالة |\n|---|---|---|---|---|\n'
                           '| 1 | غياب SIEM | لا يوجد | عالية | مفتوحة |\n',
            'roadmap':     '## 5. خارطة الطريق\n| # | النشاط | المسؤول '
                           '| الإطار الزمني | المخرج |\n|---|---|---|---|---|\n'
                           '| 1 | تأسيس SOC | CISO | 6 أشهر | SIEM |\n',
            'kpis':        '## 6. المؤشرات\n| # | المؤشر | النوع | المستهدف '
                           '| الصيغة | المصدر | المالك | التكرار | الإطار |\n'
                           '|---|---|---|---|---|---|---|---|---|\n'
                           '| 1 | تغطية | KPI | 95% | × | SIEM | CISO '
                           '| شهري | 12 |\n',
            'confidence':  '## 7. الثقة\n**درجة الثقة:** 70%\n',
        }
        defects = _APP._final_strategy_audit(
            sections, lang='ar', doc_subtype='strategy',
            selected_frameworks=['NCA ECC', 'NCA TCC'],
            domain='Cyber Security',
        )
        tags = [t for (_s, t, _c, _m) in defects]
        compliance_defects = [
            t for t in tags
            if t.startswith('selected_framework_compliance_objective_missing')
        ]
        self.assertTrue(
            compliance_defects,
            f'Final audit must emit compliance-objective defect; '
            f'all_tags={tags!r}'
        )
        # validation_error names selected frameworks (test 6 from spec)
        joined = '|'.join(compliance_defects)
        self.assertTrue(
            'ECC' in joined and 'TCC' in joined,
            f'Defect tag must name both ECC and TCC: {joined!r}'
        )

    @_skip_if_no_app
    def test_11_final_audit_no_defect_when_compliance_obj_present(self):
        sections = {'vision': _VISION_AR_WITH_COMPLIANCE_OBJ}
        defects = _APP._final_strategy_audit(
            sections, lang='ar', doc_subtype='strategy',
            selected_frameworks=['NCA ECC', 'NCA TCC'],
            domain='Cyber Security',
        )
        compliance_defects = [
            t for (_s, t, _c, _m) in defects
            if t.startswith('selected_framework_compliance_objective_missing')
        ]
        self.assertEqual(
            compliance_defects, [],
            'No compliance-objective defect when objective is present'
        )

    @_skip_if_no_app
    def test_12_final_audit_no_defect_when_no_frameworks(self):
        # Test 10 from spec: no selected frameworks means this objective
        # is not forced.
        sections = {'vision': _VISION_AR_WITHOUT_COMPLIANCE_OBJ}
        defects = _APP._final_strategy_audit(
            sections, lang='ar', doc_subtype='strategy',
            selected_frameworks=[],
            domain='Cyber Security',
        )
        compliance_defects = [
            t for (_s, t, _c, _m) in defects
            if t.startswith('selected_framework_compliance_objective_missing')
        ]
        self.assertEqual(compliance_defects, [])


class AiRepairPromptIncludesComplianceObjectiveClauseTest(unittest.TestCase):
    """Test 5 + 12 from spec: the vision repair prompt instructs AI to
    include a compliance objective when frameworks are selected; no
    deterministic objective row is inserted by code."""

    @_skip_if_no_app
    def test_13_no_deterministic_objective_row_inserted(self):
        # Test 9 from spec: no deterministic objective row is inserted.
        # The helper is pure detection; it must not mutate sections.
        sections = {'vision': _VISION_AR_WITHOUT_COMPLIANCE_OBJ}
        before = sections['vision']
        _APP._compute_missing_compliance_objective(
            sections, ['NCA ECC', 'NCA TCC'],
            domain='Cyber Security', lang='ar',
        )
        self.assertEqual(sections['vision'], before)


if __name__ == '__main__':
    unittest.main()
