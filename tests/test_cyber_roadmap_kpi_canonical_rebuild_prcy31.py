"""PR-CY31 — Complete roadmap and KPI canonical rebuild after PR-CY30.

Covers the three deferred PR-CY30 items (C/D/F):

C. Full roadmap rebuild when destructive-shrink guard can't restore.
D. Full 9-column KPI canonical rebuild.
F. Rebuild-and-rescan loop with fail-closed sentinel.

The tests are framework-level: they exercise the deterministic helpers
that were added without invoking any AI client.
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(
    prefix='test_cyber_roadmap_kpi_canonical_rebuild_prcy31_')
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
        'app',
        os.path.join(os.path.dirname(__file__), '..', 'app.py'),
    )
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
except Exception as e:  # noqa: BLE001
    raise SystemExit(f'Cannot load app module: {e!r}')


MARKER = _APP._PRCY26_KPI_TARGET_MARKER


def _shifted_kpi_block_ar():
    """KPI table with markers, formula-in-target and dash-only support
    cells — exactly the pathology the spec demands rebuilding."""
    lines = [
        '## مؤشرات الأداء',
        '',
        ('| # | المؤشر | النوع | القيمة المستهدفة |'
         ' صيغة الاحتساب | مصدر البيانات | المالك | التكرار |'
         ' الإطار الزمني |'),
        '|---|---|---|---|---|---|---|---|---|',
        # Row 1 — formula in target column, dash-only formula column
        ('| 1 | معدل الامتثال لضوابط الأمن السيبراني الأساسية ECC |'
         ' KPI | عدد الضوابط المطبقة / إجمالي الضوابط × 100 | — | — |'
         ' — | — | — |'),
        # Row 2 — marker survives, dash-only support cells
        (f'| 2 | متوسط زمن الاستجابة للحوادث الحرجة MTTR | KPI |'
         f' {MARKER} | متوسط زمن الاستجابة | — | — | — | — |'),
        # Row 3 — another unresolved target
        ('| 3 | معدل تطبيق المصادقة متعددة العوامل MFA للحسابات المميزة |'
         ' KPI | — | عدد الحسابات المغطاة / الإجمالي × 100 | — | — |'
         ' — | — |'),
    ]
    return '\n'.join(lines) + '\n'


class PRCY31RoadmapTests(unittest.TestCase):
    def test_phase_ranges_24_months(self):
        self.assertEqual(
            _APP._prcy31_compute_phase_ranges(24),
            ((1, 6), (7, 18), (19, 24)),
        )

    def test_phase_ranges_scales_for_36_months(self):
        ranges = _APP._prcy31_compute_phase_ranges(36)
        self.assertEqual(ranges[0][0], 1)
        self.assertEqual(ranges[2][1], 36)
        # No gap, no overlap.
        self.assertEqual(ranges[0][1] + 1, ranges[1][0])
        self.assertEqual(ranges[1][1] + 1, ranges[2][0])

    def test_phase_ranges_defaults_when_invalid(self):
        self.assertEqual(
            _APP._prcy31_compute_phase_ranges(None),
            ((1, 6), (7, 18), (19, 24)),
        )
        self.assertEqual(
            _APP._prcy31_compute_phase_ranges(0),
            ((1, 6), (7, 18), (19, 24)),
        )

    def test_roadmap_needs_rebuild_missing(self):
        self.assertEqual(
            _APP._prcy31_roadmap_needs_rebuild({'roadmap': ''}),
            (True, 'missing'),
        )

    def test_roadmap_needs_rebuild_too_short(self):
        needs, reason = _APP._prcy31_roadmap_needs_rebuild(
            {'roadmap': '## خارطة الطريق\nبدء سريع.'})
        self.assertTrue(needs)
        self.assertTrue(reason.startswith('too_short:'))

    def test_roadmap_needs_rebuild_coverage_zero(self):
        # A long enough body with zero dated rows → coverage 0.
        body = '## خارطة الطريق\n' + ('سرد عام بلا أشهر. ' * 30)
        needs, reason = _APP._prcy31_roadmap_needs_rebuild(
            {'roadmap': body})
        self.assertTrue(needs)
        self.assertEqual(reason, 'coverage_zero')

    def test_build_roadmap_text_ar_has_three_phases_and_dated_rows(self):
        text = _APP._prcy31_build_roadmap_text('ar', 24, ['nca_ecc'])
        self.assertIn('## خارطة الطريق', text)
        self.assertIn('المرحلة 1', text)
        self.assertIn('المرحلة 2', text)
        self.assertIn('المرحلة 3', text)
        # Dated ranges for the 24-month canonical horizon.
        self.assertIn('1–6', text)
        self.assertIn('7–18', text)
        self.assertIn('19–24', text)
        self.assertIn('NCA ECC', text)
        # Spec-mandated keywords per phase.
        self.assertIn('CISO', text)
        self.assertIn('SOC', text)

    def test_build_roadmap_text_en_has_three_phases(self):
        text = _APP._prcy31_build_roadmap_text(
            'en', 24, ['nca_ecc', 'nca_dcc'])
        self.assertIn('Implementation Roadmap', text)
        self.assertIn('Phase 1', text)
        self.assertIn('Phase 2', text)
        self.assertIn('Phase 3', text)
        self.assertIn('NCA ECC', text)
        self.assertIn('NCA DCC', text)

    def test_rebuild_roadmap_if_needed_triggers_and_satisfies_assertions(self):
        sections = {'roadmap': '## خارطة الطريق\nمحتوى قصير.'}
        diag = {}
        ok = _APP._prcy31_rebuild_roadmap_if_needed(
            sections, 'ar', ['nca_ecc'],
            {'horizon_months': 24}, diag)
        self.assertTrue(ok)
        # Spec assertions: coverage > 0, min_month <= 1, max_month == horizon.
        coverage = _APP._prcy25_compute_roadmap_coverage_months(sections)
        self.assertGreater(coverage, 0)
        self.assertEqual(coverage, 24,
                         'rebuilt 24-month roadmap must surface month 24')
        # Phase ranges (min_month <= 1 and max_month == horizon).
        body = sections['roadmap']
        self.assertIn('1–6', body)
        self.assertIn('19–24', body)
        self.assertIn('prcy31_roadmap_rebuilt', diag)

    def test_rebuild_roadmap_if_needed_noop_when_valid(self):
        # Pre-build a valid roadmap, then make sure the helper is a no-op.
        good = _APP._prcy31_build_roadmap_text('ar', 24, ['nca_ecc'])
        sections = {'roadmap': good}
        before = sections['roadmap']
        ok = _APP._prcy31_rebuild_roadmap_if_needed(
            sections, 'ar', ['nca_ecc'], {'horizon_months': 24}, {})
        self.assertFalse(ok)
        self.assertEqual(sections['roadmap'], before)


class PRCY31KPITests(unittest.TestCase):
    def test_kpi_needs_canonical_rebuild_detects_markers(self):
        sections = {'kpis': _shifted_kpi_block_ar()}
        needs, reasons = _APP._prcy31_kpi_needs_canonical_rebuild(
            sections, 'ar')
        self.assertTrue(needs)
        self.assertIn('markers_present', reasons)

    def test_kpi_needs_canonical_rebuild_detects_formula_in_target(self):
        sections = {'kpis': _shifted_kpi_block_ar()}
        _, reasons = _APP._prcy31_kpi_needs_canonical_rebuild(
            sections, 'ar')
        self.assertTrue(any(r.startswith('formula_in_target')
                            for r in reasons))

    def test_kpi_needs_canonical_rebuild_detects_dash_only_cells(self):
        sections = {'kpis': _shifted_kpi_block_ar()}
        _, reasons = _APP._prcy31_kpi_needs_canonical_rebuild(
            sections, 'ar')
        self.assertTrue(any(r.startswith('dash_only_support_cells')
                            for r in reasons))

    def test_rebuild_kpi_canonical_produces_9_columns(self):
        sections = {'kpis': _shifted_kpi_block_ar()}
        emitted = _APP._prcy31_rebuild_kpi_canonical(
            sections, 'ar', ['nca_ecc'],
            {'horizon_months': 24}, {})
        self.assertGreaterEqual(emitted, 3)
        body = sections['kpis']
        # Heading preserved.
        self.assertIn('## مؤشرات الأداء', body)
        # 9-column canonical header.
        self.assertIn('القيمة المستهدفة', body)
        self.assertIn('صيغة الاحتساب', body)
        self.assertIn('مصدر البيانات', body)
        self.assertIn('المالك', body)
        self.assertIn('التكرار', body)
        # No markers.
        self.assertNotIn('[REQUIRES_AI_', body)
        # No dash-only target / source / owner / frequency cells.
        for row in body.split('\n'):
            if not row.startswith('| '):
                continue
            cells = [c.strip() for c in row.strip('|').split('|')]
            if len(cells) < 9:
                continue
            if cells[0] in ('#', '---'):
                continue
            # Skip header row.
            if 'القيمة المستهدفة' in cells:
                continue
            if cells[0].startswith('---'):
                continue
            # cells = [#, desc, type, target, formula, source, owner, freq, tf]
            for idx, label in (
                    (3, 'target'),
                    (5, 'source'),
                    (6, 'owner'),
                    (7, 'frequency')):
                self.assertNotIn(cells[idx], ('', '—', '-', '–'),
                                 f'cell {label} dash-only: {cells}')

    def test_validate_kpi_canonical_passes_on_rebuilt_table(self):
        sections = {'kpis': _shifted_kpi_block_ar()}
        _APP._prcy31_rebuild_kpi_canonical(
            sections, 'ar', ['nca_ecc'], {'horizon_months': 24}, {})
        issues = _APP._prcy31_validate_kpi_canonical(sections, 'ar')
        self.assertEqual(issues, [])

    def test_kpi_canonical_rebuild_and_rescan_succeeds(self):
        sections = {'kpis': _shifted_kpi_block_ar()}
        needed, ok, actions = (
            _APP._prcy31_kpi_canonical_rebuild_and_rescan(
                sections, 'ar', ['nca_ecc'],
                {'horizon_months': 24}, {}))
        self.assertTrue(needed)
        self.assertTrue(ok)
        self.assertNotIn(_APP._PRCY31_KPI_REBUILD_FAILED_FLAG, sections)
        # Action log lists a triggered + ok terminal state.
        self.assertTrue(any(a.startswith('kpi_canonical_rebuild_triggered:')
                            for a in actions))
        self.assertTrue(any(a.startswith('kpi_canonical_validate:ok')
                            for a in actions))

    def test_kpi_canonical_rebuild_and_rescan_noop_when_clean(self):
        # A pre-rebuilt table should be a no-op.
        sections = {'kpis': _shifted_kpi_block_ar()}
        _APP._prcy31_rebuild_kpi_canonical(
            sections, 'ar', ['nca_ecc'], {'horizon_months': 24}, {})
        needed, ok, actions = (
            _APP._prcy31_kpi_canonical_rebuild_and_rescan(
                sections, 'ar', ['nca_ecc'],
                {'horizon_months': 24}, {}))
        self.assertFalse(needed)
        self.assertTrue(ok)
        self.assertEqual(actions, [])

    def test_blocking_gate_surfaces_unresolved_kpi_canonical_rebuild(self):
        # Simulate a failed rebuild by setting the sentinel directly.
        sections = {
            'kpis': '## مؤشرات الأداء\n',
            _APP._PRCY31_KPI_REBUILD_FAILED_FLAG: True,
            _APP._PRCY31_KPI_REBUILD_REASON_FLAG: 'target_empty_or_marker:row_1',
        }
        errors = _APP._cyber_final_blocking_gate(
            content='## مؤشرات الأداء\n',
            sections=sections,
            lang='ar',
            selected_frameworks=['nca_ecc'],
            domain='cyber',
        )
        joined = '\n'.join(errors)
        self.assertIn('unresolved_kpi_canonical_rebuild', joined)
        self.assertIn('target_empty_or_marker:row_1', joined)


if __name__ == '__main__':
    unittest.main()
