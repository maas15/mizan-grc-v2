"""PR-CY59 — Final Arabic cleanup for PDF/DOCX export blockers.

Run:
    python -m pytest tests/test_cyber_export_parity_prcy59.py -v
"""
import functools
import os
import sys
import tempfile
import unittest


_TMP = tempfile.mkdtemp(prefix='test_export_parity_prcy59_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')

_P41 = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    import professional_strategy_render as _P41
except Exception as _e:
    raise SystemExit(f'Cannot load: {_e!r}')


def _skip(fn):
    @functools.wraps(fn)
    def _w(self, *a, **kw):
        if _P41 is None:
            self.skipTest('module unavailable')
        return fn(self, *a, **kw)
    return _w


class ExportParityPrcy59Tests(unittest.TestCase):

    @_skip
    def test_alalmasoul_executive_becomes_masoul_tanfithi(self):
        src = 'الالمسؤولتنفيذي'
        fixed = _P41.normalize_arabic_for_render(src)
        self.assertEqual(fixed, 'المسؤول التنفيذي')
        self.assertNotIn('الالمسؤول', fixed)

    @_skip
    def test_masoul_tanfithi_concat_fixed(self):
        src = 'المسؤولتنفيذي'
        fixed = _P41.normalize_arabic_for_render(src)
        self.assertEqual(fixed, 'المسؤول التنفيذي')

    @_skip
    def test_mutakhassas_min_concat_fixed(self):
        self.assertEqual(
            _P41.normalize_arabic_for_render('متخصصمن'),
            'متخصص من')

    @_skip
    def test_asasiya_fi_concat_fixed(self):
        self.assertEqual(
            _P41.normalize_arabic_for_render('الأساسيةفي'),
            'الأساسية في')

    @_skip
    def test_hokoma_an_concat_fixed(self):
        self.assertEqual(
            _P41.normalize_arabic_for_render('الحوكمةعن'),
            'الحوكمة عن')

    @_skip
    def test_final_table_cell_arabic_cleanup_passes_after_finalize(self):
        from tests.test_cyber_export_parity_prcy50 import _model
        model = _model()
        checks = _P41.prcy47_docmodel_professional_checks(model, 'ar')
        self.assertTrue(checks['final_table_cell_arabic_cleanup_passed'])
        self.assertTrue(checks['arabic_spacing_final_passed'])
        self.assertTrue(checks['final_arabic_spacing_pdf_passed'])

    @_skip
    def test_docx_arabic_spacing_count_zero_for_known_patterns(self):
        from tests.test_cyber_export_parity_prcy50 import _model
        model = _model()
        blocks = dict(model.get('blocks') or {})
        gov = dict(blocks.get('governance_ownership') or {})
        gov['rows'] = [['الالمسؤولتنفيذي', 'x', 'x', 'x', 'x']]
        blocks['governance_ownership'] = gov
        cleaned = _P41.apply_final_arabic_cleanup_to_blocks(blocks, 'ar')
        self.assertEqual(_P41.count_model_arabic_spacing_issues(
            {'blocks': cleaned}), 0)
        self.assertIn('المسؤول التنفيذي', str(cleaned))

    @_skip
    def test_arabic_final_cleanup_diag_shape(self):
        diag = _P41.build_arabic_final_cleanup_diag(
            {'blocks': {'x': {'paragraphs': ['الالمسؤولتنفيذي']}}},
            output_type='pdf')
        for key in (
                'output_type', 'bad_text_samples', 'replacement_candidates',
                'cleanup_applied_count', 'remaining_issue_count',
                'action_taken'):
            self.assertIn(key, diag)
        self.assertGreater(diag['remaining_issue_count'], 0)

    @_skip
    def test_organizational_goals_phrase_not_corrupted(self):
        phrase = 'أهداف المنظمة'
        fixed = _P41.prepare_final_render_text(phrase, 'ar')
        self.assertEqual(fixed, phrase)

    @_skip
    def test_prcy46_through_58_still_pass(self):
        from tests.test_cyber_export_parity_prcy50 import _model
        checks = _P41.prcy47_docmodel_professional_checks(_model(), 'ar')
        self.assertTrue(checks['docmodel_professional_passed'])


if __name__ == '__main__':
    unittest.main()
