"""PR-CY38 — Eliminate user-facing repair markers and replace the
patch-loop with a schema-first final composer.

Invariants verified:

A. ``[REQUIRES_AI_*]`` may never be written into a markdown cell that
   becomes user-facing. The five legacy injection sites
   (``_prcy19_kpi_rtl_fix`` defects B/C/D, ``_prcy30_normalize_shifted_kpi_row``,
   ``_prcy23_kpi_schema_enforce``) now route through the
   ``_prcy38_compose_kpi_*`` schema-first composer.

B. ``_prcy38_assert_no_repair_markers`` raises
   :class:`InternalMarkerInjectionError` on a hit; the
   ``_prcy38_scan_repair_markers`` helper detects every English variant
   plus the Arabic mirror token.

C. ``_cyber_final_export_contract`` initialises a ``repair_flags``
   out-of-band channel and surfaces it on the returned dict /
   diagnostic.

D. ``_PRCY28_VERSION_FLAGS['prcy38']`` is ``True`` and ``'prcy38'`` is
   in ``_PRCY32_REQUIRED_RUNTIME_FLAGS`` so the runtime version gate
   refuses to release content from an image that lacks PR-CY38.

E. The contract surfaces ``final_quality_gate_failed:
   internal_marker_injection_blocked:<location>`` and
   ``final_quality_gate_failed:final_schema_compose_failed:<location>``
   when a marker survives until the final compose exit.
"""
import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(
    prefix='test_cyber_marker_ban_schema_first_prcy38_')
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
except (ImportError, ModuleNotFoundError) as _e:  # pragma: no cover
    print(f'[WARN] Could not import app.py: {_e}')
    _APP = None


def _skip_if_no_app(fn):
    @functools.wraps(fn)
    def _wrapped(self, *a, **kw):
        if _APP is None:
            self.skipTest('app.py could not be imported')
        return fn(self, *a, **kw)
    return _wrapped


# ── A. Marker scanner + assertion + composer wiring ─────────────────
class ScannerAndAssertionTests(unittest.TestCase):

    @_skip_if_no_app
    def test_scan_detects_english_target_marker(self):
        markers = _APP._prcy38_scan_repair_markers(
            'cell [REQUIRES_AI_TARGET_REPAIR] cell')
        self.assertIn('[REQUIRES_AI_TARGET_REPAIR]', markers)

    @_skip_if_no_app
    def test_scan_detects_english_formula_marker(self):
        markers = _APP._prcy38_scan_repair_markers(
            '[REQUIRES_AI_FORMULA_REPAIR]')
        self.assertIn('[REQUIRES_AI_FORMULA_REPAIR]', markers)

    @_skip_if_no_app
    def test_scan_detects_arabic_mirror_token(self):
        markers = _APP._prcy38_scan_repair_markers(
            'صيغة [يتطلب إعادة صياغة عبر مراجعة ذكية] هنا')
        self.assertIn('[يتطلب إعادة صياغة عبر مراجعة ذكية]', markers)

    @_skip_if_no_app
    def test_scan_clean_text_returns_empty(self):
        self.assertEqual(
            _APP._prcy38_scan_repair_markers('clean ≥ 95% text'), [])
        self.assertEqual(
            _APP._prcy38_scan_repair_markers(''), [])
        self.assertEqual(
            _APP._prcy38_scan_repair_markers(None), [])

    @_skip_if_no_app
    def test_assert_raises_internal_marker_injection_error(self):
        with self.assertRaises(_APP.InternalMarkerInjectionError) as ctx:
            _APP._prcy38_assert_no_repair_markers(
                'x [REQUIRES_AI_TARGET_REPAIR] y',
                location='unit_test')
        self.assertEqual(ctx.exception.location, 'unit_test')
        self.assertIn(
            'internal_marker_injection_blocked', str(ctx.exception))

    @_skip_if_no_app
    def test_assert_silent_when_clean(self):
        # Must not raise and must return [] on clean content.
        self.assertEqual(
            _APP._prcy38_assert_no_repair_markers(
                'all good', location='unit_test'), [])

    @_skip_if_no_app
    def test_assert_returns_markers_without_raise(self):
        markers = _APP._prcy38_assert_no_repair_markers(
            '[REQUIRES_AI_TARGET_REPAIR]',
            location='unit_test', raise_on_hit=False)
        self.assertIn('[REQUIRES_AI_TARGET_REPAIR]', markers)


# ── B. Schema-first composer never returns a marker ────────────────
class SchemaFirstComposerTests(unittest.TestCase):

    @_skip_if_no_app
    def test_compose_kpi_target_typed_catalogue_ecc(self):
        target, kind, conf = _APP._prcy38_compose_kpi_target(
            description='نسبة الامتثال لضوابط NCA ECC',
            lang='ar', selected_frameworks=['ECC'])
        self.assertTrue(target)
        self.assertNotIn('[REQUIRES_AI_', target)

    @_skip_if_no_app
    def test_compose_kpi_target_neutral_fallback_when_classifier_silent(
            self):
        # Description has enough context (>=12 chars) but no catalog
        # match → neutral professional fallback (never a marker).
        target, kind, conf = _APP._prcy38_compose_kpi_target(
            description='مؤشر تشغيلي عام داخل الحوكمة',
            lang='ar')
        self.assertTrue(target)
        self.assertNotIn('[REQUIRES_AI_', target)

    @_skip_if_no_app
    def test_compose_kpi_target_rebuild_required_when_no_context(self):
        target, kind, conf = _APP._prcy38_compose_kpi_target(
            description='—', lang='ar')
        # None → caller must rebuild the table; never a marker.
        self.assertIsNone(target)
        self.assertEqual(kind, 'rebuild_required')

    @_skip_if_no_app
    def test_compose_kpi_formula_never_returns_marker(self):
        for desc in ('', '—', 'نسبة الترقيع للثغرات الحرجة',
                     'incident response time'):
            formula = _APP._prcy38_compose_kpi_formula(
                description=desc, existing_formula='', lang='ar')
            self.assertIsInstance(formula, str)
            self.assertTrue(formula)
            self.assertNotIn('[REQUIRES_AI_', formula)
            self.assertNotIn('يتطلب إعادة صياغة', formula)


# ── C. The 5 legacy injection sites no longer write markers ────────
class LegacyInjectionSitesNeutralizedTests(unittest.TestCase):

    @_skip_if_no_app
    def test_prcy19_defect_d_no_marker_in_formula_cell(self):
        # Defect D: formula cell empty/dash, target non-formula.
        kpi_md = (
            '## مؤشرات الأداء الرئيسية\n\n'
            '| # | وصف المؤشر | القيمة المستهدفة |'
            ' صيغة الاحتساب | مصدر البيانات/الأداة |'
            ' تواتر القياس |\n'
            '|---|---|---|---|---|---|\n'
            '| 1 | نسبة الترقيع للثغرات الحرجة |'
            ' ≥ 95% خلال 72 ساعة | — | إدارة الثغرات |'
            ' شهري |\n'
        )
        sections = {'kpis': kpi_md}
        _APP._prcy19_kpi_rtl_fix(sections, 'ar')
        self.assertNotIn('[REQUIRES_AI_FORMULA_REPAIR]',
                         sections['kpis'])
        self.assertNotIn('[يتطلب إعادة صياغة عبر مراجعة ذكية]',
                         sections['kpis'])

    @_skip_if_no_app
    def test_prcy23_target_dash_no_marker_in_target_cell(self):
        kpi_md = (
            '## مؤشرات الأداء الرئيسية\n\n'
            '| # | وصف المؤشر | القيمة المستهدفة |'
            ' صيغة الاحتساب | مصدر البيانات/الأداة |'
            ' تواتر القياس |\n'
            '|---|---|---|---|---|---|\n'
            '| 1 | نسبة الامتثال لضوابط NCA ECC | — |'
            ' (محقق/مستهدف)*100 | إدارة الحوكمة |'
            ' ربع سنوي |\n'
        )
        sections = {'kpis': kpi_md}
        _APP._prcy23_kpi_schema_enforce(sections, 'ar')
        self.assertNotIn('[REQUIRES_AI_TARGET_REPAIR]',
                         sections['kpis'])

    @_skip_if_no_app
    def test_prcy30_column_shift_no_marker_in_target_cell(self):
        # Formula text in target cell, dash in formula cell — the
        # legacy code stamped the target column with the marker.
        kpi_md = (
            '## مؤشرات الأداء الرئيسية\n\n'
            '| # | وصف المؤشر | القيمة المستهدفة |'
            ' صيغة الاحتساب | مصدر البيانات/الأداة |'
            ' تواتر القياس |\n'
            '|---|---|---|---|---|---|\n'
            '| 1 | نسبة الامتثال لضوابط NCA ECC |'
            ' (محقق/مستهدف)*100 | — | إدارة الحوكمة |'
            ' ربع سنوي |\n'
        )
        sections = {'kpis': kpi_md}
        try:
            _APP._prcy30_normalize_shifted_kpi_row(sections, 'ar')
        except Exception as _e:  # pragma: no cover
            self.fail(f'_prcy30_normalize_shifted_kpi_row raised: {_e}')
        self.assertNotIn('[REQUIRES_AI_TARGET_REPAIR]',
                         sections['kpis'])

    @_skip_if_no_app
    def test_source_grep_no_residual_marker_assignments(self):
        # No production line may still assign ai_marker / _PRCY26_KPI_
        # TARGET_MARKER / _PRCY23_AI_TARGET_REPAIR_MARKER into a cell.
        # The legacy three lines are gone after PR-CY38.
        forbidden = (
            'c[3] = ai_marker',
            'c[2] = ai_marker',
            'cells[target_idx] = _PRCY26_KPI_TARGET_MARKER',
        )
        for needle in forbidden:
            self.assertNotIn(
                needle, _APP_SOURCE,
                f'PR-CY38 must remove legacy marker injection: {needle}')


# ── D. Version flags + runtime gate ─────────────────────────────────
class VersionFlagTests(unittest.TestCase):

    @_skip_if_no_app
    def test_prcy38_flag_present_and_true(self):
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('prcy38'),
                        'PR-CY38 must register prcy38=True in '
                        '_PRCY28_VERSION_FLAGS')

    @_skip_if_no_app
    def test_prcy38_in_required_runtime_flags(self):
        self.assertIn('prcy38', _APP._PRCY32_REQUIRED_RUNTIME_FLAGS,
                      'PR-CY38 must be required by the runtime gate')


# ── E. Contract exposes repair_flags channel ────────────────────────
class ContractRepairFlagsTests(unittest.TestCase):

    @_skip_if_no_app
    def test_contract_returns_repair_flags_list(self):
        result = _APP._cyber_final_export_contract(
            markdown='## رؤية\n\nبرنامج الأمن السيبراني.\n',
            metadata={'horizon_months': 24},
            selected_frameworks=['ECC'],
            lang='ar', domain='cyber',
            output_type='unit_test',
            read_only=True)
        self.assertIsInstance(result, dict)
        self.assertIn('repair_flags', result)
        self.assertIsInstance(result['repair_flags'], list)
        # Diagnostic surfaces the count.
        self.assertIn('repair_flags_count', result.get('diag', {}))
        self.assertIn('final_compose_marker_clean',
                      result.get('diag', {}))

    @_skip_if_no_app
    def test_contract_diagnostic_marker_clean_on_clean_input(self):
        result = _APP._cyber_final_export_contract(
            markdown='## رؤية\n\nنص نظيف.\n',
            metadata={'horizon_months': 24},
            selected_frameworks=['ECC'],
            lang='ar', domain='cyber',
            output_type='unit_test',
            read_only=True)
        self.assertTrue(
            result.get('diag', {}).get('final_compose_marker_clean'))


# ── F. Helper block source presence (defence in depth) ─────────────
class SourceMarkersPresentTests(unittest.TestCase):

    @_skip_if_no_app
    def test_helper_block_present(self):
        for needle in (
                'PR-CY38 — Schema-first final composer',
                'class InternalMarkerInjectionError',
                'def _prcy38_scan_repair_markers',
                'def _prcy38_assert_no_repair_markers',
                'def _prcy38_compose_kpi_target',
                'def _prcy38_compose_kpi_formula',
                'def _prcy38_record_repair_flag',
                '[CYBER-INTERNAL-MARKER-INJECTION-BLOCKED]',
                'final_schema_compose_failed:final_compose_exit',
        ):
            self.assertIn(needle, _APP_SOURCE,
                          f'PR-CY38 source marker missing: {needle}')


if __name__ == '__main__':
    unittest.main()
