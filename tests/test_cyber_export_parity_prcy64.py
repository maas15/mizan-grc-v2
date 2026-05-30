"""PR-CY64 — Repair missing Cyber strategic objectives section before save.

When the Strategic Objectives section or table is absent after AI
generation/repair, the pre-save path must insert a canonical
vision/objectives section, run the PR-CY39 composer, and only block
with precise tokens if repair still fails.
"""

import functools
import importlib.util
import os
import re
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_export_parity_prcy64_')
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
_APP_SOURCE = ''
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    _APP_PATH = os.path.join(os.path.dirname(__file__), '..', 'app.py')
    _spec = importlib.util.spec_from_file_location('app', _APP_PATH)
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
    with open(_APP_PATH, 'r', encoding='utf-8') as _f:
        _APP_SOURCE = _f.read()
except Exception as _e:  # pragma: no cover
    raise SystemExit(f'Cannot load app module: {_e!r}')


def _skip_if_no_app(fn):
    @functools.wraps(fn)
    def _wrapped(self, *a, **kw):
        if _APP is None:
            self.skipTest('app.py could not be imported')
        return fn(self, *a, **kw)
    return _wrapped


_PARTIAL_VISION_AR = (
    '## 1. الرؤية والأهداف الاستراتيجية\n\n'
    '**الرؤية:** رؤية الأمن السيبراني.\n\n'
    '### الأهداف الاستراتيجية\n\n'
    '| # | الهدف الاستراتيجي | المستهدف القابل للقياس |'
    ' المبرر | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
    '| 1 | إنشاء إدارة الأمن السيبراني بقيادة CISO |'
    ' تعيين CISO خلال 6 أشهر |'
    ' ضرورة وجود هيكل تنظيمي متخصص | 6 أشهر |\n'
)

_VALID_VISION_AR = (
    '## 1. الرؤية والأهداف الاستراتيجية\n\n'
    '**الرؤية:** رؤية.\n\n'
    '### الأهداف الاستراتيجية\n\n'
    '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
    '| 1 | إنشاء إدارة الأمن السيبراني بقيادة CISO |'
    ' 100% | CISO governance | 6 أشهر |\n'
    '| 2 | الامتثال لـ NCA ECC | 90% | compliance | 12 شهر |\n'
    '| 3 | الامتثال لـ NCA DCC | 90% | DCC | 18 شهر |\n'
    '| 4 | SOC و CSIRT | SLA | response | 9 أشهر |\n'
    '| 5 | IAM/PAM/MFA | 100% | access | 12 شهر |\n'
)

_PILLARS_AR = '## 2. الركائز الاستراتيجية\n\nنص الركائز.\n'
_KPI_STUB = (
    '## 6. مؤشرات الأداء\n\n| # | وصف | هدف | صيغة | مصدر | تواتر |\n'
    '|---|---|---|---|---|---|\n| 1 | x | y | z | a | b |\n'
)
_CONF_STUB = '## 7. تقييم الثقة\n\n**درجة الثقة:** 80%\n**مبررات التقييم:** x\n'


def _sections(vision, pillars=_PILLARS_AR):
    return {
        'vision': vision,
        'pillars': pillars,
        'environment': '## 3. البيئة\n\nx\n',
        'gaps': '## 4. الفجوات\n\nx\n',
        'roadmap': '## 5. خارطة الطريق\n\nx\n',
        'kpis': _KPI_STUB,
        'confidence': _CONF_STUB,
    }


def _presave(sections, content=None, lang='ar'):
    return _APP._prcy63_presave_compose_strategic_objectives(
        sections=sections,
        content=content,
        domain='cyber',
        lang=lang,
        metadata={'domain': 'cyber'},
        selected_frameworks=['nca_ecc', 'nca_dcc'],
        phase='test',
        generation_mode='consulting',
    )


class PreSaveStrategicObjectivesSectionRepairTests(unittest.TestCase):

    @_skip_if_no_app
    def test_helpers_present(self):
        self.assertTrue(hasattr(_APP, '_prcy64_presave_repair_strategic_objectives_section'))
        self.assertTrue(hasattr(_APP, '_prcy64_detect_so_presence'))

    @_skip_if_no_app
    def test_missing_table_inserted_before_presave_blocker(self):
        sections = _sections(_PARTIAL_VISION_AR.replace(
            '| # | الهدف الاستراتيجي | المستهدف القابل للقياس |'
            ' المبرر | الإطار الزمني |\n'
            '|---|---|---|---|---|\n'
            '| 1 | إنشاء إدارة الأمن السيبراني بقيادة CISO |'
            ' تعيين CISO خلال 6 أشهر |'
            ' ضرورة وجود هيكل تنظيمي متخصص | 6 أشهر |\n', ''))
        _, pre = _APP._audit_doc_quality(sections, 'technical', 'ar')
        self.assertIn('strategic_objectives_section_missing', pre)
        result = _presave(sections)
        issues = result.get('quality_issues') or []
        self.assertNotIn('strategic_objectives_section_missing', issues)
        vision = (result.get('sections') or {}).get('vision', '')
        self.assertIsNotNone(_APP._prcy39_locate_so_table(vision)[0])

    @_skip_if_no_app
    def test_missing_whole_section_inserted_before_pillars(self):
        sections = _sections('')
        content = _PILLARS_AR + '\n' + sections['environment']
        result = _presave(sections, content=content)
        out_content = result.get('content') or ''
        self.assertRegex(out_content, r'الرؤية والأهداف الاستراتيجية')
        self.assertLess(
            out_content.find('الرؤية'),
            out_content.find('الركائز'))
        diag = (_APP._prcy64_presave_repair_strategic_objectives_section(
            sections=_sections(''), content=_PILLARS_AR, domain='cyber',
            lang='ar', metadata={'domain': 'cyber'},
            selected_frameworks=['nca_ecc', 'nca_dcc']).get('diag') or {})
        self.assertTrue(diag.get('section_inserted'))

    @_skip_if_no_app
    def test_arabic_vision_and_objectives_heading_detected(self):
        text = '## 1. الرؤية والأهداف الاستراتيجية\n\n### الأهداف الاستراتيجية\n'
        det = _APP._prcy64_detect_so_presence(text, {'vision': text}, 'ar')
        self.assertTrue(det['raw_has_vision_heading'])
        self.assertTrue(det['raw_has_objectives_heading'])

    @_skip_if_no_app
    def test_arabic_objectives_subheading_detected(self):
        text = '### الأهداف الاستراتيجية\n'
        det = _APP._prcy64_detect_so_presence(text, {'vision': text}, 'ar')
        self.assertTrue(det['raw_has_objectives_heading'])

    @_skip_if_no_app
    def test_english_strategic_objectives_detected(self):
        text = '## 1. Vision & Strategic Objectives\n\n### Strategic Objectives\n'
        det = _APP._prcy64_detect_so_presence(text, {'vision': text}, 'en')
        self.assertTrue(det['raw_has_vision_heading'])
        self.assertTrue(det['raw_has_objectives_heading'])

    @_skip_if_no_app
    def test_existing_valid_table_not_duplicated(self):
        sections = _sections(_VALID_VISION_AR)
        before = sections['vision']
        result = _presave(dict(sections))
        after = (result.get('sections') or {}).get('vision', '')
        self.assertEqual(before.count('| # |'), after.count('| # |'))

    @_skip_if_no_app
    def test_partial_table_completed_not_replaced(self):
        sections = _sections(_PARTIAL_VISION_AR)
        result = _presave(dict(sections))
        vision = (result.get('sections') or {}).get('vision', '')
        self.assertIn('CISO', vision)
        self.assertIn('إنشاء إدارة الأمن السيبراني', vision)
        self.assertGreaterEqual(
            int((result.get('diag') or {}).get('rows_after', 0)), 5)

    @_skip_if_no_app
    def test_cy18_specialized_objective_preserved(self):
        sections = _sections(_PARTIAL_VISION_AR)
        result = _presave(dict(sections))
        vision = (result.get('sections') or {}).get('vision', '')
        self.assertIn('CISO', vision)
        self.assertTrue((result.get('diag') or {}).get(
            'mandatory_specialized_present'))

    @_skip_if_no_app
    def test_cy20_framework_compliance_preserved(self):
        sections = _sections(_PARTIAL_VISION_AR)
        result = _presave(dict(sections))
        vision = (result.get('sections') or {}).get('vision', '')
        self.assertTrue(
            'NCA ECC' in vision or 'ECC' in vision)
        self.assertTrue((result.get('diag') or {}).get(
            'mandatory_framework_compliance_present'))

    @_skip_if_no_app
    def test_dcc_data_protection_objective_present(self):
        sections = _sections('')
        result = _presave(sections, content=_PILLARS_AR)
        vision = (result.get('sections') or {}).get('vision', '')
        self.assertTrue(
            any(t in vision for t in (
                'DCC', 'حماية البيانات', 'تسرب البيانات', 'NCA DCC')))

    @_skip_if_no_app
    def test_presave_gate_no_section_missing_after_repair(self):
        sections = _sections('')
        result = _presave(sections, content=_PILLARS_AR)
        issues = result.get('quality_issues') or []
        self.assertNotIn('strategic_objectives_section_missing', issues)

    @_skip_if_no_app
    def test_final_export_contract_still_blocks_real_defects(self):
        bad_md = '## 1. الرؤية\n\nلا يوجد جدول.\n'
        result = _APP._cyber_final_export_contract(
            bad_md,
            metadata={'domain': 'cyber'},
            selected_frameworks=['nca_ecc'],
            lang='ar',
            domain='cyber',
            output_type='preview',
        )
        blockers = result.get('blocking_errors') or []
        # SO may be composed in-contract; other mandatory sections must
        # still fail-closed on severely incomplete input.
        self.assertTrue(
            blockers,
            f'expected final contract blockers for incomplete artifact, got {blockers!r}')

    @_skip_if_no_app
    def test_section_repair_wired_before_presave_gate_in_source(self):
        idx = _APP_SOURCE.find('_prcy64_presave_repair_strategic_objectives_section')
        gate = _APP_SOURCE.find('reason=strategic_objectives_malformed_post_normalization')
        self.assertGreater(idx, 0)
        self.assertGreater(gate, idx)


if __name__ == '__main__':
    unittest.main()
