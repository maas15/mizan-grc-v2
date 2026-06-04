"""PR-CY87 — executive-ready Cyber strategy quality + acceptance gates."""

import functools
import importlib.util
import io
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


_TMP = tempfile.mkdtemp(prefix='test_cyber_executive_quality_prcy87_')
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


def _log_has_tag(log, tag):
    return tag in (log or '')


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

_NOISY_FIXTURE = {
    'vision': (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        '### الأهداف الاستراتيجية\n\n'
        + _SO_HEADER
        + '| 1 | إنشاء إدارة الأمن السيبراني وتعيين CISO | 100% | حوكمة | 6 أشهر |\n'
        + '| 2 | SOC/CSIRT | 100% | تشغيل | 12 شهر |\n'
        + '| 3 | IAM/PAM/MFA | 95% | هوية | 12 شهر |\n'
        + '| 4 | DCC حماية البيانات | 90% | امتثال | 18 شهر |\n'
        + '| 5 | إطار ECC/DCC | 90% | تنظيمي | 18 شهر |\n'
        + '| 7 | معدل إصلاح الثغرات الحرجة خلال 72 ساعة | — | — | — |\n'
    ),
    'pillars': '## 2. الركائز\n\nنص.\n',
    'environment': '## 3. البيئة\n\nتصنيف وتشفير DLP.\n',
    'gaps': '## 4. الفجوات\n\nGap #1 Implementation Guide steps.\n',
    'roadmap': (
        _ROADMAP_HDR
        + '| المرحلة 3: تحسين | 19-24 شهر | تشغيل SOC/SIEM | المسؤول | — | NCA ECC |\n'
        + '| المرحلة 1: تأسيس | 1-6 أشهر | حوكمة CISO | CISO | هيكل معتمد | NCA ECC |\n'
        + '| المرحلة 2: تمكين | 7-18 شهر | تصنيف البيانات | مدير حماية البيانات |'
        ' جرد معتمد | NCA DCC |\n'
        + '| المرحلة 2: تمكين | 7-18 شهر | تشفير | مدير حماية البيانات |'
        ' ضوابط تشفير | NCA DCC |\n'
        + '| المرحلة 2: تمكين | 7-18 شهر | DLP | مدير حماية البيانات |'
        ' منصة DLP | NCA DCC |\n'
        + '| المرحلة 3: تحسين | 19-24 شهر | قياس وتحسين | CISO | تقرير نضج | NCA ECC |\n'
    ),
    'kpis': (
        _KPI_HDR
        + '| 1 | معدل نجح النسخ الاحتياطي | ≥ 99% | f | backup | شهري |\n'
        + '| — | معدل تحديد الثغرات الحرجة | ≥ 95% | إغلاق/إجمالي | VM | شهري |\n'
        + '| 3 | امتثال DCC | ≥ 90% | f | DCC | ربع |\n'
    ),
    'confidence': (
        '## 7. تقييم الثقة\n\n'
        '**درجة الثقة:** 82%\n'
        '**مبررات التقييم:** نص.\n'
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


class Prcy87ExecutiveQualityTests(unittest.TestCase):

    @_skip
    def test_prcy87_flag_live(self):
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('prcy87'))


class Prcy87AcceptanceTests(unittest.TestCase):
    """PR-CY87 mandatory acceptance addendum — diagnostics + gates."""

    @_skip
    def test_01_runtime_fingerprint_prcy85_86_87_rel1_absent(self):
        fp = _APP._prcy37_runtime_build_fingerprint_payload(
            route_name='test', output_type='test')
        self.assertTrue(fp.get('prcy85'))
        self.assertTrue(fp.get('prcy86'))
        self.assertTrue(fp.get('prcy87'))
        self.assertFalse(fp.get('rel1'))
        acc = _APP._prcy87_runtime_fingerprint_acceptance()
        self.assertTrue(acc['main_lineage_cy85_cy86_cy87'])
        self.assertTrue(acc['rel1_absent'])
        self.assertFalse(acc['release_hardening_required'])
        self.assertFalse(acc['domains_required'])

    @_skip
    def test_02_so_semantic_gate_target_like_after_zero(self):
        vision = (
            '## 1.\n\n### الأهداف الاستراتيجية\n\n'
            + _SO_HEADER
            + '| 7 | معدل إصلاح الثغرات الحرجة خلال 72 ساعة | — | — | — |\n'
        )
        out, diag = _APP._prcy87_polish_strategic_objectives_semantic(vision, 'ar')
        self.assertEqual(diag.get('target_like_objectives_after'), 0)
        self.assertEqual(diag.get('shifted_objective_fields_after'), 0)
        self.assertTrue(diag.get('gate_passed'))
        self.assertEqual(diag.get('blocking_error_if_any'), '')
        self.assertIn('تطوير برنامج إدارة الثغرات', out)

    @_skip
    def test_03_so_shifted_fields_repaired(self):
        vision = (
            '## 1.\n\n### الأهداف الاستراتيجية\n\n'
            + _SO_HEADER
            + '| 7 | معدل إصلاح الثغرات الحرجة خلال 72 ساعة | — | — | — |\n'
        )
        out, diag = _APP._prcy87_polish_strategic_objectives_semantic(vision, 'ar')
        self.assertEqual(diag.get('shifted_objective_fields_after'), 0)
        cells = [
            c.strip()
            for c in out.split('| 7 |')[1].split('|\n')[0].split('|')
            if c.strip()]
        self.assertIn('95%', cells[1])

    @_skip
    def test_04_roadmap_owner_almasool_replaced(self):
        rm = _ROADMAP_HDR + (
            '| المرحلة 3 | 19-24 | SOC/SIEM | المسؤول | — | ECC |\n')
        out, diag = _APP._prcy87_polish_roadmap_executive(
            rm, ['nca_ecc', 'nca_dcc'], 'ar')
        self.assertEqual(diag.get('weak_owner_after'), 0)
        self.assertIn('مدير SOC', out)

    @_skip
    def test_05_roadmap_weak_owner_after_zero(self):
        rm = _ROADMAP_HDR + (
            '| المرحلة 3 | 19-24 | SOC | المسؤول | — | ECC |\n')
        _, diag = _APP._prcy87_polish_roadmap_executive(
            rm, ['nca_ecc'], 'ar')
        self.assertEqual(diag.get('weak_owner_after'), 0)
        self.assertTrue(diag.get('gate_passed'))

    @_skip
    def test_06_kpi_typo_removed(self):
        kpi = _KPI_HDR + '| 1 | معدل نجح النسخ الاحتياطي | ≥ 99% | f | s | شهري |\n'
        out, diag = _APP._prcy87_polish_kpi_executive(kpi, 'ar')
        self.assertEqual(diag.get('typo_count_after'), 0)
        self.assertNotIn('معدل نجح', out)

    @_skip
    def test_07_kpi_dash_resequenced(self):
        kpi = _KPI_HDR + '| — | امتثال DCC | ≥ 90% | f | DCC | ربع |\n'
        out, diag = _APP._prcy87_polish_kpi_executive(kpi, 'ar')
        self.assertEqual(diag.get('kpi_dash_rows_after'), 0)
        self.assertIn('| 1 |', out)

    @_skip
    def test_08_dcc_classification_not_mapped_to_dlp(self):
        rows = [[
            'NCA DCC', 'تصنيف البيانات الحساسة',
            'ضعف ضوابط منع تسرب البيانات', 'init', 'kpi', 'risk',
        ]]
        fixed, diag = _APP._prcy87_polish_traceability_rows(rows, 'ar')
        self.assertTrue(diag.get('dcc_mapping_valid'))
        self.assertIn('تصنيف وجرد', fixed[0][2])

    @_skip
    def test_09_dcc_traceability_mapping_valid_true(self):
        rows = [[
            'NCA DCC', 'تصنيف البيانات',
            'ضعف ضوابط منع تسرب البيانات', 'x', 'y', 'z',
        ]]
        _, diag = _APP._prcy87_polish_traceability_rows(rows, 'ar')
        valid, violations = _APP._prcy87_validate_dcc_traceability_mapping(
            [[
                'NCA DCC', 'تصنيف البيانات',
                'ضعف تصنيف وجرد البيانات الحساسة',
                'تنفيذ تصنيف', 'k', 'r',
            ]], 'ar')
        self.assertTrue(valid)
        self.assertEqual(violations, [])

    @_skip
    def test_10_executive_layout_polish_applied(self):
        from tests.test_cyber_export_parity_prcy50 import _model as _m50
        model = _m50()
        model['_prcy87'] = True
        diag = _PSR.build_pdf_final_polish_diag(model, 'ar')
        self.assertTrue(diag.get('applied'))
        self.assertTrue(diag.get('objective_cards_or_tables_readable'))

    @_skip
    def test_11_pdf_vertical_stack_blocker_absent_after_fallback(self):
        from tests.test_cyber_export_parity_prcy50 import _model as _m50
        model = _m50()
        model['_prcy87'] = True
        model['blocks']['kpi_kri_framework']['tables'] = [{
            'schema': 'kpi_main',
            'header': list(_PSR.SCHEMA_KPI_MAIN_AR),
            'rows': [['1', 'KPI ' + 'x' * 120, 'KPI', '≥ 90%', 'm', 'o', '12']],
        }]
        fb = _PSR.compute_pdf_export_layout_fallbacks(model, 'ar')
        ev = _PSR.evaluate_vertical_stack_gate(model, fallbacks=fb)
        self.assertEqual(ev.get('actionable_warning_count_after'), 0)
        checks = _PSR.prcy47_docmodel_professional_checks(model, 'ar')
        self.assertTrue(checks.get('pdf_table_vertical_stack_warnings'))

    @_skip
    def test_12_no_trace_residue_in_polished_display(self):
        secs = {
            'roadmap': _ROADMAP_HDR + (
                '| 1 | 1-6 | SOC | CISO | out | ECC |'
                ' trace:section=roadmap;src=bank_fallback |\n'),
        }
        _, md, agg = _APP._prcy87_executive_strategy_quality_polish(
            secs, secs['roadmap'], 'ar', ['nca_ecc'],
            route_name='preview', output_type='preview')
        self.assertNotIn('trace:section', md)
        self.assertNotIn('bank_fallback', md)

    @_skip
    def test_13_noisy_arabic_fixture_passes_acceptance_gates(self):
        art, log = _artifact(_NOISY_FIXTURE)
        self.assertTrue(art.get('sealed'), art.get('blocking_errors'))
        p87 = (art.get('diagnostics') or {}).get('prcy87') or {}
        self.assertEqual(
            p87.get('action_taken'), 'executive_quality_polish_applied')
        secs = art.get('sections') or {}
        md = art.get('final_markdown') or _content({
            k: v for k, v in secs.items() if not str(k).startswith('_')})
        self.assertNotIn('trace:section', md)
        self.assertNotIn('معدل نجح', md)
        self.assertNotIn('trace:section=roadmap', md)
        for ln in (secs.get('roadmap') or '').splitlines():
            if ln.startswith('|') and '---' not in ln and 'المخرج' not in ln:
                self.assertNotIn('| المسؤول |', ln)
        snap = _APP._prcy87_build_acceptance_snapshot(
            secs, md, ['nca_ecc', 'nca_dcc'], 'ar',
            route_name='generation')
        self.assertEqual(snap.get('target_like_objectives_after'), 0)
        self.assertEqual(snap.get('shifted_objective_fields_after'), 0)
        self.assertEqual(snap.get('weak_owner_after'), 0)
        self.assertEqual(snap.get('typo_count_after'), 0)
        self.assertTrue(snap.get('dcc_mapping_valid'))
        self.assertTrue(snap.get('semantic_gates_passed'))
        self.assertTrue(_log_has_tag(log, 'STRATEGIC-OBJECTIVES-SEMANTIC-POLISH'))
        self.assertTrue(_log_has_tag(log, 'ROADMAP-EXECUTIVE-POLISH'))
        self.assertTrue(_log_has_tag(log, 'KPI-EXECUTIVE-POLISH'))
        self.assertTrue(_log_has_tag(log, 'TRACEABILITY-EXECUTIVE-POLISH'))
        self.assertTrue(_log_has_tag(log, 'PR-CY87-ACCEPTANCE'))

    @_skip
    def test_14_objective_orphan_batch_avoided(self):
        rows = [['%d' % i, f'هدف {i}', 't', 'r', '24 شهر'] for i in range(1, 8)]
        batches = _PSR.prcy87_batch_objective_card_rows(rows, batch_size=3)
        self.assertGreater(len(batches[-1]), 1)


if __name__ == '__main__':
    unittest.main()
