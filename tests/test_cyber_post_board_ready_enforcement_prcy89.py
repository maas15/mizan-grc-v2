"""PR-CY89 — post board-ready artifact enforcement tests."""

import functools
import importlib.util
import io
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

_TMP = tempfile.mkdtemp(prefix='test_cyber_post_board_ready_prcy89_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(_TMP, 'test.db'),
)
os.environ.setdefault('OPENAI_API_KEY', '')

_APP = None
_P89 = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    import cyber_post_board_ready_prcy89 as _P89
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py'))
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
    sys.modules['app'] = _APP
except Exception as _e:
    raise SystemExit(f'Cannot load app module: {_e!r}')


def _skip(fn):
    @functools.wraps(fn)
    def _w(self, *a, **kw):
        if _APP is None:
            self.skipTest('app unavailable')
        return fn(self, *a, **kw)
    return _w


_SO_HEADER = (
    '| # | الهدف الاستراتيجي | المستهدف القابل للقياس |'
    ' المبرر | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
)

_SHIFTED_ROW_7 = (
    '| 7 | تعزيز القدرات الأمنية المؤسسية |'
    ' ضرورة استراتيجية لبرنامج الأمن السيبراني | خلال 24 شهراً | 12 شهراً |\n'
)

_KPI_HDR = (
    '## 6. مؤشرات الأداء\n\n'
    '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساس |'
    ' مصدر البيانات/الأداة | تواتر القياس |\n'
    '|---|---|---|---|---|\n'
)

_KPI_BROKEN_NUMBERS = (
    _KPI_HDR
    + '| 1 | نضج حوكمة | ≥ 90% | a/b | GRC | ربع |\n'
    + '| 2 | امتثال ECC | ≥ 90% | a/b | GRC | ربع |\n'
    + '| 3 | IAM | ≥ 95% | a/b | IAM | شهري |\n'
    + '| 4 | MTTD | ≤ 15 د | t | SIEM | شهري |\n'
    + '| 5 | MTTR | ≤ 4 س | t | SOAR | شهري |\n'
    + '| 6 | ثغرات | ≥ 95% | a/b | VM | شهري |\n'
    + '| 1 | نسخ احتياطي | ≥ 99% | a/b | backup | شهري |\n'
    + '| 2 | توعية | ≥ 85% | a/b | LMS | ربع |\n'
    + '| 3 | تصنيف | ≥ 90% | a/b | DCC | ربع |\n'
    + '| 4 | تشفير | ≥ 95% | a/b | enc | شهري |\n'
    + '| 9 | DLP | ≥ 90% | a/b | DLP | شهري |\n'
    + '| 11 | تصيد | < 5% | a/b | phish | ربع |\n'
)

_PILLARS = (
    '## 2. الركائز\n\n'
    '### حوكمة\n\n'
    '| المبادرة | الوصف | المخرج المتوقع |\n'
    '|---|---|---|\n'
    '| سياسات | اعتماد | ميثاق معتمد |\n'
    '### تشغيل\n\n'
    '| المبادرة | الوصف | المخرج |\n'
    '|---|---|---|\n'
    '| SOC | تشغيل | مركز SOC |\n'
    '### حماية\n\n'
    '| المبادرة | الوصف | المخرج |\n'
    '|---|---|---|\n'
    '| DLP | تفعيل | منصة DLP |\n'
)

_BASE_SECTIONS = {
    'vision': (
        '## 1. الرؤية\n\n### الأهداف الاستراتيجية\n\n'
        + _SO_HEADER
        + '| 1 | تأسيس CISO | 100% | حوكمة | 6 أشهر |\n'
        + '| 2 | امتثال ECC/DCC | ≥ 90% | تنظيمي | 12 شهر |\n'
        + '| 3 | SOC | 100% | تشغيل | 12 شهر |\n'
        + '| 4 | IAM/PAM | ≥ 95% | هوية | 12 شهر |\n'
        + '| 5 | CSIRT | 100% | استجابة | 12 شهر |\n'
        + '| 6 | ثغرات | ≥ 95% | مخاطر | 12 شهر |\n'
        + _SHIFTED_ROW_7
    ),
    'pillars': _PILLARS,
    'environment': '## 3.\n\nبيئة.\n',
    'gaps': '## 4.\n\nفجوة.\n',
    'roadmap': (
        '## 5.\n\n| المرحلة | الفترة | المبادرة | المسؤول | المخرج | الإطار |\n'
        '|---|---|---|---|---|---|\n'
        + ('| المرحلة 1 | 1-6 | حوكمة CISO | CISO | هيكل | ECC |\n' * 4)
        + ('| المرحلة 2 | 7-18 | SOC SIEM | مدير SOC | SOC | ECC |\n' * 4)
        + ('| المرحلة 3 | 19-24 | DLP | مدير | DLP | DCC |\n' * 4)
    ),
    'kpis': _KPI_BROKEN_NUMBERS,
    'confidence': (
        '## 7.\n\n**درجة الثقة:** 85%\n**مبررات التقييم:** نص.\n'
    ),
}


def _content(sections):
    if hasattr(_APP, '_prcy65_rebuild_content_from_sections'):
        return _APP._prcy65_rebuild_content_from_sections(sections, None)
    return '\n\n'.join(
        sections[k] for k in (
            'vision', 'pillars', 'environment', 'gaps',
            'roadmap', 'kpis', 'confidence')
        if sections.get(k))


def _artifact(sections, output_type='generation'):
    buf = io.StringIO()
    with redirect_stdout(buf):
        art = _APP._build_cyber_final_strategy_artifact(
            _content(sections),
            sections=dict(sections),
            metadata={'domain': 'cyber'},
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            lang='ar',
            domain='cyber',
            output_type=output_type,
            request_context={'route_name': output_type},
            generation_mode='consulting',
        )
    return art, buf.getvalue()


class Prcy89FlagTests(unittest.TestCase):

    @_skip
    def test_prcy89_flag_live(self):
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('prcy89'))


class Prcy89EnforcementTests(unittest.TestCase):

    @_skip
    def test_01_cy88_final_cannot_pass_with_shifted_so_in_saved_artifact(self):
        art, _ = _artifact(_BASE_SECTIONS)
        p89 = (art.get('diagnostics') or {}).get('prcy89') or {}
        val = p89.get('validation') or {}
        self.assertEqual(val.get('so_shifted_rows', 0), 0, val)
        self.assertTrue(p89.get('cyber_board_ready_final_passed'), p89)

    @_skip
    def test_02_cy88_final_cannot_pass_with_empty_pillars(self):
        secs = dict(_BASE_SECTIONS)
        secs['pillars'] = ''
        art, _ = _artifact(secs)
        pil = (art.get('sections') or {}).get('pillars') or ''
        self.assertTrue(_P89._pillar_present(pil), 'REL2.3 rebuilds empty pillars')
        p89 = (art.get('diagnostics') or {}).get('prcy89') or {}
        rel23 = (art.get('diagnostics') or {}).get('rel23') or {}
        parity = rel23.get('section_parity') or (
            (p89.get('pillar_parity') or {}).get('rel2_section_parity') or {})
        if parity:
            self.assertTrue(parity.get('pillars_present_docx'), parity)
            self.assertTrue(parity.get('pillars_present_pdf'), parity)

    @_skip
    def test_03_preview_pillars_docx_parity_requires_sections_pillars(self):
        secs = dict(_BASE_SECTIONS)
        secs['pillars'] = ''
        chk = _P89._pillar_export_parity_check(secs, _content(secs))
        self.assertTrue(chk.get('preview_pillars_present') or not chk.get(
            'docx_pillars_present'))
        self.assertFalse(chk.get('export_parity_valid'))

    @_skip
    def test_04_kpi_broken_numbers_canonicalized_to_sequential(self):
        secs, diag = _P89.canonicalize_kpi_final_row_model(
            _APP, dict(_BASE_SECTIONS), 'ar')
        nums = diag.get('numbers_after') or []
        self.assertEqual(nums, list(range(1, len(nums) + 1)))
        self.assertEqual(nums, list(range(1, len(nums) + 1)))

    @_skip
    def test_05_kpi_main_and_formula_same_numbers(self):
        secs, diag = _P89.canonicalize_kpi_final_row_model(
            _APP, dict(_BASE_SECTIONS), 'ar')
        main, formula = _P89._parse_kpi_numbers(secs.get('kpis', ''))
        self.assertEqual(main, formula)
        self.assertTrue(diag.get('formula_alignment_valid'))

    @_skip
    def test_06_duplicate_kpi_numbers_removed(self):
        secs, diag = _P89.canonicalize_kpi_final_row_model(
            _APP, dict(_BASE_SECTIONS), 'ar')
        self.assertEqual(diag.get('duplicate_numbers_after'), [])

    @_skip
    def test_07_kpi_number_gaps_removed(self):
        secs, diag = _P89.canonicalize_kpi_final_row_model(
            _APP, dict(_BASE_SECTIONS), 'ar')
        self.assertEqual(diag.get('gaps_after'), [])

    @_skip
    def test_08_kpi_semantics_valid_after_canonicalize(self):
        secs, diag = _P89.canonicalize_kpi_final_row_model(
            _APP, dict(_BASE_SECTIONS), 'ar')
        self.assertTrue(diag.get('kpi_metric_semantics_valid'), diag)

    @_skip
    def test_09_post_cy89_mutation_emits_detected(self):
        secs = dict(_BASE_SECTIONS)
        fp = _P89._content_fingerprint(secs)
        secs['kpis'] = (secs.get('kpis') or '') + '\n| 99 | mutated | — | — | — | — |\n'
        self.assertTrue(_P89.detect_post_board_ready_mutation(fp, secs))
        buf = io.StringIO()
        with redirect_stdout(buf):
            _P89.emit_post_board_ready_mutation_detected(
                phase='test', frozen=fp, current=_P89._content_fingerprint(secs))
        self.assertIn('POST-BOARD-READY-MUTATION-DETECTED', buf.getvalue())

    @_skip
    def test_10_full_production_fixture_passes_validation(self):
        art, log = _artifact(_BASE_SECTIONS)
        self.assertIn('CYBER-POST-BOARD-READY-ARTIFACT-VALIDATION', log)
        self.assertIn('KPI-FINAL-CANONICAL-ROW-MODEL', log)
        p89 = (art.get('diagnostics') or {}).get('prcy89') or {}
        val = p89.get('validation') or {}
        self.assertTrue(val.get('kpi_numbering_valid'), val)
        self.assertTrue(val.get('kpi_semantics_valid'), val)
        self.assertTrue(val.get('hashes_match'), val)
        self.assertTrue(p89.get('artifact_validation_passed'), p89)

    @_skip
    def test_11_validate_saved_artifact_function(self):
        art, _ = _artifact(_BASE_SECTIONS)
        v = _APP._prcy89_validate_saved_board_ready_artifact(art, 'ar')
        self.assertTrue(v.get('artifact_validation_passed'), v)


if __name__ == '__main__':
    unittest.main()
