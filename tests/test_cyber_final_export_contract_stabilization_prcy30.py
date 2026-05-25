"""PR-CY30 — Stabilize final export contract after destructive audit
mutations.

Covers:

1. ``_prcy30_cell_looks_like_formula`` recognises Arabic / English
   formula text and ignores duration-ceiling targets.
2. ``_prcy30_detect_kpi_column_shift`` flags rows whose target carries
   formula text while formula is dash-only / marker.
3. ``_prcy30_normalize_shifted_kpi_row`` swaps the target / formula
   cells and re-stamps the canonical KPI target repair marker.
4. ``_prcy26_repair_kpi_target_markers_in_sections`` runs the shift
   pre-pass and then resolves the catalog target for the normalised
   row (no marker survives).
5. The strengthened ``_repair_kpi_target_marker.target_already_valid``
   check no longer treats a formula-looking target as valid.
6. ``_prcy30_roadmap_destructive_shrink_guard`` restores the roadmap
   and emits ``[CYBER-ROADMAP-MUTATION-REJECTED]`` when the audit
   chain shrinks roadmap below 40% of its pre-audit length.
7. ``_cyber_final_export_audit`` invokes the roadmap guard and the
   restored roadmap length matches the pre-audit length.
8. ``_cyber_final_export_contract`` surfaces
   ``selected_frameworks_canonical`` at the top level.
9. PR-CY29 framework inference still drives the canonical list when
   the caller passes ``selected_frameworks=[]``.
10. Hard gate continues to block when no catalog target can be derived
    for a normalised row (regression for the unresolvable case).
"""

import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


_TMP_DB_DIR = tempfile.mkdtemp(
    prefix='test_cyber_final_export_contract_stabilization_prcy30_')
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


def _kpi_block_with_shift(rows):
    """Build an Arabic KPI table that exhibits the column-shift
    pattern: the target column carries the formula text and the
    formula column is dash-only. ``rows`` is a list of
    ``(desc, formula_text)`` tuples."""
    lines = [
        '## مؤشرات الأداء',
        '',
        ('| # | المؤشر | النوع | القيمة المستهدفة |'
         ' صيغة الاحتساب | مصدر البيانات | المالك | التكرار |'
         ' الإطار الزمني |'),
        ('|---|---|---|---|---|---|---|---|---|'),
    ]
    for i, (desc, formula) in enumerate(rows, 1):
        lines.append(
            f'| {i} | {desc} | KPI | {formula} | — | SIEM | CISO |'
            ' ربع سنوي | 24 شهر |'
        )
    return '\n'.join(lines) + '\n'


class PRCY30Tests(unittest.TestCase):
    def test_01_cell_looks_like_formula_ar(self):
        self.assertTrue(_APP._prcy30_cell_looks_like_formula(
            'عدد الحوادث المعالجة في الوقت المحدد / إجمالي الحوادث × 100'))
        self.assertTrue(_APP._prcy30_cell_looks_like_formula(
            'متوسط الوقت للاستجابة للحوادث الحرجة'))

    def test_02_cell_looks_like_formula_en(self):
        self.assertTrue(_APP._prcy30_cell_looks_like_formula(
            'number of incidents handled on time / total incidents x 100'))
        self.assertTrue(_APP._prcy30_cell_looks_like_formula(
            'mean time to respond to critical incidents'))

    def test_03_cell_looks_like_formula_ignores_targets(self):
        # Duration ceiling — a valid target, NOT a formula.
        self.assertFalse(_APP._prcy30_cell_looks_like_formula(
            'أقل من 4 ساعات للحوادث الحرجة'))
        self.assertFalse(_APP._prcy30_cell_looks_like_formula('≥ 95%'))
        self.assertFalse(_APP._prcy30_cell_looks_like_formula('100%'))
        self.assertFalse(_APP._prcy30_cell_looks_like_formula(''))
        self.assertFalse(_APP._prcy30_cell_looks_like_formula('—'))

    def test_04_detect_kpi_column_shift_with_dash_formula(self):
        self.assertTrue(_APP._prcy30_detect_kpi_column_shift(
            'عدد الحسابات المغطاة / إجمالي الحسابات × 100',
            '—',
            marker_token=MARKER))

    def test_05_detect_kpi_column_shift_with_marker_in_formula(self):
        self.assertTrue(_APP._prcy30_detect_kpi_column_shift(
            'عدد الحسابات المغطاة / إجمالي الحسابات × 100',
            MARKER,
            marker_token=MARKER))

    def test_06_detect_kpi_column_shift_no_shift_when_both_valid(self):
        self.assertFalse(_APP._prcy30_detect_kpi_column_shift(
            '≥ 95%',
            'عدد الحسابات المغطاة / إجمالي الحسابات × 100',
            marker_token=MARKER))

    def test_07_normalize_shifted_kpi_row_swaps_cells(self):
        body = _kpi_block_with_shift([
            ('معدل تطبيق المصادقة متعددة العوامل MFA',
             'عدد الحسابات المغطاة بـ MFA / إجمالي الحسابات × 100'),
            ('معدل فعالية الاستجابة للحوادث السيبرانية',
             ('عدد الحوادث المعالجة في الوقت المحدد '
              '/ إجمالي الحوادث × 100')),
        ])
        sections = {'kpis': body}
        fixed = _APP._prcy30_normalize_shifted_kpi_row(sections, 'ar')
        self.assertEqual(fixed, 2)
        out = sections['kpis']
        # Target column now carries the marker.
        self.assertGreaterEqual(out.count(MARKER), 2)
        # Formula text moved into the formula column (dashes consumed).
        self.assertIn('عدد الحسابات المغطاة', out)
        self.assertNotIn('| — | SIEM |', out)

    def test_08_repair_pass_clears_markers_after_normalization(self):
        body = _kpi_block_with_shift([
            ('معدل تطبيق المصادقة متعددة العوامل MFA',
             'عدد الحسابات المغطاة بـ MFA / إجمالي الحسابات × 100'),
            ('متوسط زمن الاستجابة للحوادث الحرجة MTTR',
             'متوسط الوقت بين فتح الحادث وإغلاقه'),
        ])
        sections = {'kpis': body}
        buf = io.StringIO()
        with redirect_stdout(buf):
            actions = (
                _APP._prcy26_repair_kpi_target_markers_in_sections(
                    sections, 'ar',
                    metadata={'horizon_months': 24},
                    selected_frameworks=['nca_ecc']))
        # Every marker resolved.
        self.assertNotIn(MARKER, sections['kpis'])
        # Shift normalisation logged + per-row repair logged.
        joined_actions = ' '.join(actions)
        self.assertIn('kpi_column_shift_normalized:2', joined_actions)
        self.assertIn('kpi_target_repair:row_1', joined_actions)
        self.assertIn('kpi_target_repair:row_2', joined_actions)

    def test_09_target_already_valid_rejects_formula_cell(self):
        # When the marker is in column 2 (Type cell) but target is a
        # formula text, we must NOT short-circuit as misplaced strip.
        md = (
            '## مؤشرات الأداء\n\n'
            '| # | المؤشر | النوع | القيمة المستهدفة |'
            ' صيغة الاحتساب | مصدر البيانات | المالك | التكرار |'
            ' الإطار الزمني |\n'
            '|---|---|---|---|---|---|---|---|---|\n'
            '| 1 | معدل تطبيق MFA | '
            + MARKER +
            ' | عدد الحسابات المغطاة / إجمالي الحسابات × 100 |'
            ' — | SIEM | CISO | ربع سنوي | 24 شهر |\n'
        )
        new_md, diag = _APP._repair_kpi_target_marker(
            md, MARKER, 1, lang='ar',
            metadata={'horizon_months': 24},
            selected_frameworks=['nca_ecc'])
        # PR-CY30 — the formula in the target cell is no longer
        # treated as "already valid" so the catalog classifier runs.
        self.assertNotEqual(
            diag.get('action_taken'),
            'kpi_target_marker_misplaced_stripped')

    def test_10_roadmap_destructive_shrink_guard_restores(self):
        big = 'م' * 5000
        sections = {'roadmap': 'tiny remainder'}
        buf = io.StringIO()
        diag = {}
        with redirect_stdout(buf):
            restored = _APP._prcy30_roadmap_destructive_shrink_guard(
                sections, big, diag)
        self.assertTrue(restored)
        self.assertEqual(sections['roadmap'], big)
        self.assertIn('prcy30_roadmap_mutation_rejected', diag)
        info = diag['prcy30_roadmap_mutation_rejected']
        self.assertEqual(info['reason'], 'destructive_shrink')
        self.assertEqual(info['before_len'], 5000)
        self.assertIn('[CYBER-ROADMAP-MUTATION-REJECTED]', buf.getvalue())

    def test_11_roadmap_guard_no_op_for_small_roadmap(self):
        sections = {'roadmap': 'x'}
        restored = _APP._prcy30_roadmap_destructive_shrink_guard(
            sections, 'tiny', {})
        self.assertFalse(restored)
        self.assertEqual(sections['roadmap'], 'x')

    def test_12_roadmap_guard_no_op_when_after_meets_threshold(self):
        big = 'م' * 1000
        sections = {'roadmap': 'م' * 800}  # 80% of before
        restored = _APP._prcy30_roadmap_destructive_shrink_guard(
            sections, big, {})
        self.assertFalse(restored)
        self.assertEqual(len(sections['roadmap']), 800)

    def test_13_contract_surfaces_selected_frameworks_canonical(self):
        md = (
            '## الرؤية\nرؤية أمن سيبراني للمنشأة.\n\n'
            '## خارطة الطريق\n'
            'NCA ECC و NCA DCC هما الإطاران الرئيسيان.\n'
        )
        out = _APP._cyber_final_export_contract(
            md, metadata={'domain': 'cyber'},
            selected_frameworks=[], lang='ar', domain='cyber',
            output_type='unit_test',
        )
        # Top-level + inside diag both expose canonical IDs.
        self.assertIn('selected_frameworks_canonical', out)
        self.assertEqual(
            sorted(out['selected_frameworks_canonical']),
            ['nca_dcc', 'nca_ecc'])
        self.assertEqual(
            sorted(out['diag']['selected_frameworks_canonical']),
            ['nca_dcc', 'nca_ecc'])
        self.assertEqual(
            out['diag']['framework_context_source'], 'text_inference')


if __name__ == '__main__':
    unittest.main()
