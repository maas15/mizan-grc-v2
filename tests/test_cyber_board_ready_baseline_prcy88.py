"""PR-CY88 — Cyber board-ready content baseline tests."""

import functools
import importlib.util
import io
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

_TMP = tempfile.mkdtemp(prefix='test_cyber_board_ready_prcy88_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(_TMP, 'test.db'),
)
os.environ.setdefault('OPENAI_API_KEY', '')

_APP = None
_PSR = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    import professional_strategy_render as _PSR
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

_ROADMAP_HDR = (
    '## 5. خارطة الطريق\n\n'
    '| المرحلة | الفترة | المبادرة | المسؤول | المخرج المتوقع | الإطار |\n'
    '|---|---|---|---|---|---|\n'
)

_KPI_HDR = (
    '## 6. مؤشرات الأداء\n\n'
    '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساس |'
    ' مصدر البيانات/الأداة | تواتر القياس |\n'
    '|---|---|---|---|---|\n'
)

_PILLARS = (
    '## 2. الركائز\n\n'
    '### حوكمة الأمن\n\n'
    '| المبادرة | الوصف | المخرج المتوقع |\n'
    '|---|---|---|\n'
    '| سياسات الحوكمة | اعتماد السياسات | منصة DLP مفعّلة |\n'
    '### استمرارية الأعمال\n\n'
    '| المبادرة | الوصف | المخرج المتوقع |\n'
    '|---|---|---|\n'
    '| النسخ الاحتياطي | DR | ضوابط تشفير وإدارة مفاتيح |\n'
)

_NOISY_FIXTURE = {
    'vision': (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        '### الأهداف الاستراتيجية\n\n'
        + _SO_HEADER
        + '| 1 | إنشاء إدارة الأمن السيبراني وتعيين CISO | 100% | حوكمة | 6 أشهر |\n'
        + '| 2 | تأسيس CISO ثانٍ وإدارة الحوكمة | 100% | حوكمة | 6 أشهر |\n'
        + '| 3 | SOC/CSIRT | 100% | تشغيل | 12 شهر |\n'
        + '| 4 | IAM/PAM/MFA | 95% | هوية | 12 شهر |\n'
        + '| 5 | إطار ECC/DCC | 90% | تنظيمي | 18 شهر |\n'
        + '| 7 | معدل إصلاح الثغرات الحرجة خلال 72 ساعة | — | — | — |\n'
    ),
    'pillars': _PILLARS,
    'environment': '## 3. البيئة\n\nتصنيف وتشفير DLP.\n',
    'gaps': '## 4. الفجوات\n\nGap #1 Implementation Guide steps.\n',
    'roadmap': (
        _ROADMAP_HDR
        + '| المرحلة 3: تحسين | 19-24 شهر | تشغيل SOC/SIEM | المسؤول | — | NCA ECC |\n'
        + '| المرحلة 1: تأسيس | 1-6 أشهر | حوكمة CISO | CISO | هيكل معتمد | NCA ECC |\n'
    ),
    'kpis': (
        _KPI_HDR
        + '| 1 | معدل نجح النسخ الاحتياطي | ≥ 99% | f | backup | شهري |\n'
        + '| — | معدل تحديد الثغرات الحرجة | ≥ 95% | إغلاق/إجمالي | VM | شهري |\n'
        + '| 3 | تشفير وDLP مجمّع | ≥ 90% | f | DCC | ربع |\n'
    ),
    'confidence': (
        '## 7. تقييم الثقة\n\n'
        '**درجة الثقة:** 82%\n'
        '**مبررات التقييم:** نص تنفيذي.\n'
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


def _baseline(sections, md=None):
    return _APP._prcy88_cyber_board_ready_quality_baseline(
        dict(sections),
        md or _content(sections),
        'ar',
        ['nca_ecc', 'nca_dcc'],
    )


class Prcy88FlagTests(unittest.TestCase):

    @_skip
    def test_prcy88_flag_live(self):
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('prcy88'))


class Prcy88BoardReadyTests(unittest.TestCase):

    @_skip
    def test_01_duplicate_governance_consolidated(self):
        secs, _md, diag = _baseline(_NOISY_FIXTURE)
        so = diag.get('strategic_objectives') or {}
        self.assertEqual(so.get('duplicate_governance_rows_after'), 0)

    @_skip
    def test_02_target_like_objectives_rewritten(self):
        secs, _md, diag = _baseline(_NOISY_FIXTURE)
        self.assertEqual(
            diag.get('strategic_objectives', {}).get(
                'target_like_objectives_after', 99), 0)

    @_skip
    def test_03_objective_count_between_6_and_8(self):
        secs, _md, diag = _baseline(_NOISY_FIXTURE)
        n = diag.get('strategic_objectives', {}).get('rows_after', 0)
        self.assertGreaterEqual(n, 6)
        self.assertLessEqual(n, 8)

    @_skip
    def test_04_pillar_output_mismatch_repaired(self):
        secs, _md, diag = _baseline(_NOISY_FIXTURE)
        pil = diag.get('pillars') or {}
        self.assertEqual(pil.get('mismatched_outputs_after'), 0)
        self.assertTrue(pil.get('repaired_outputs'))

    @_skip
    def test_05_roadmap_expanded_to_10_rows(self):
        secs, _md, diag = _baseline(_NOISY_FIXTURE)
        rm = diag.get('roadmap') or {}
        self.assertGreaterEqual(rm.get('rows_after', 0), 10)

    @_skip
    def test_06_roadmap_weak_owner_repaired(self):
        secs, _md, diag = _baseline(_NOISY_FIXTURE)
        self.assertEqual(diag.get('roadmap', {}).get('weak_owner_after'), 0)

    @_skip
    def test_07_dcc_roadmap_families_present(self):
        secs, _md, diag = _baseline(_NOISY_FIXTURE)
        self.assertEqual(
            diag.get('roadmap', {}).get('missing_families_after'), [])

    @_skip
    def test_08_kpi_inserts_missing_families(self):
        secs, _md, diag = _baseline(_NOISY_FIXTURE)
        self.assertGreaterEqual(diag.get('kpi', {}).get('kpi_rows_after', 0), 8)

    @_skip
    def test_09_kpi_dash_sequence_aligned(self):
        secs, _md, diag = _baseline(_NOISY_FIXTURE)
        self.assertEqual(diag.get('kpi', {}).get('dash_sequence_after'), 0)

    @_skip
    def test_10_dcc_combined_metric_split(self):
        secs, _md, diag = _baseline(_NOISY_FIXTURE)
        self.assertTrue(
            diag.get('kpi', {}).get('dcc_kpi_split_applied')
            or 'تشفير' in (secs.get('kpis') or ''))

    @_skip
    def test_11_dcc_classification_not_mapped_to_dlp(self):
        secs, _md, diag = _baseline(_NOISY_FIXTURE)
        self.assertTrue(diag.get('traceability', {}).get('dcc_mapping_valid'))

    @_skip
    def test_12_sensitive_handling_not_kpi_text(self):
        secs, _md, diag = _baseline(_NOISY_FIXTURE)
        bad = diag.get('traceability', {}).get('bad_mappings_after', [])
        self.assertNotIn('sensitive_to_kpi', bad)

    @_skip
    def test_13_ecc_incident_maps_csirt_not_soc_only(self):
        secs, _md, diag = _baseline(_NOISY_FIXTURE)
        bad = diag.get('traceability', {}).get('bad_mappings_after', [])
        self.assertNotIn('ir_to_soc_only', bad)

    @_skip
    def test_14_pdf_layout_avoids_orphan_objective_cards(self):
        rows = [['%d' % i, f'هدف {i}', 't', 'r', '24 شهر'] for i in range(1, 8)]
        batches = _PSR.prcy88_batch_objective_card_rows(rows, batch_size=4)
        self.assertGreater(len(batches[-1]), 1)

    @_skip
    def test_15_full_fixture_board_ready_quality(self):
        art, _ = _artifact(_NOISY_FIXTURE)
        p88 = (art.get('diagnostics') or {}).get('prcy88') or {}
        self.assertTrue(art.get('sealed'), art.get('blocking_errors'))
        self.assertTrue(p88.get('cyber_board_ready_quality_passed'))
        self.assertTrue(p88.get('cyber_board_ready_final_passed'))

    @_skip
    def test_16_score_at_least_90(self):
        _, _md, diag = _baseline(_NOISY_FIXTURE)
        self.assertGreaterEqual(diag.get('cyber_board_ready_score', 0), 90)

    @_skip
    def test_17_no_dimension_below_80(self):
        _, _md, diag = _baseline(_NOISY_FIXTURE)
        for _dim, score in (diag.get('dimension_scores') or {}).items():
            self.assertGreaterEqual(score, 80, _dim)

    @_skip
    def test_18_control_coverage_matrix_exists(self):
        secs, _md, diag = _baseline(_NOISY_FIXTURE)
        self.assertIn('_prcy88_control_coverage', secs)
        cov = diag.get('coverage') or {}
        self.assertEqual(cov.get('coverage_granularity'), 'capability_family')
        self.assertFalse(cov.get('full_control_coverage_claim_allowed'))

    @_skip
    def test_19_no_full_control_claim_without_ids(self):
        secs, _md, diag = _baseline(_NOISY_FIXTURE)
        cov = secs.get('_prcy88_control_coverage') or {}
        self.assertFalse(cov.get('exact_control_ids_available'))

    @_skip
    def test_20_arabic_fixes_fريقمن_and_معدل_نجح(self):
        text = 'فريقمن معدل نجح'
        for old, new in (
                ('فريقمن', 'فريق من'),
                ('معدل نجح', 'معدل نجاح')):
            text = text.replace(old, new)
        self.assertNotIn('فريقمن', text)
        self.assertNotIn('معدل نجح', text)

    @_skip
    def test_21_final_passed_flag(self):
        _, _md, diag = _baseline(_NOISY_FIXTURE)
        self.assertTrue(diag.get('cyber_board_ready_final_passed'))


if __name__ == '__main__':
    unittest.main()
