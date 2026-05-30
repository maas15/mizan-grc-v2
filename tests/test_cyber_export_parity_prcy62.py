"""PR-CY62 — Final PDF visual polish and Arabic spacing cleanup.

Run:
    python -m pytest tests/test_cyber_export_parity_prcy62.py -v
"""
import functools
import io
import os
import sys
import tempfile
import unittest


_TMP = tempfile.mkdtemp(prefix='test_export_parity_prcy62_')
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


class ExportParityPrcy62Tests(unittest.TestCase):

    @_skip
    def test_arabic_spacing_cleanup_tawafuq_ma(self):
        self.assertEqual(
            _P41.normalize_arabic_for_render('التوافقمع'),
            'التوافق مع')

    @_skip
    def test_arabic_spacing_cleanup_tashghiliya_an(self):
        self.assertEqual(
            _P41.normalize_arabic_for_render('التشغيليةعن'),
            'التشغيلية عن')

    @_skip
    def test_arabic_spacing_cleanup_hadd_min(self):
        self.assertEqual(
            _P41.normalize_arabic_for_render('الحدمن'),
            'الحد من')

    @_skip
    def test_arabic_spacing_cleanup_ishrafiya_an(self):
        self.assertEqual(
            _P41.normalize_arabic_for_render('الإشرافيةعن'),
            'الإشرافية عن')

    @_skip
    def test_arabic_spacing_cleanup_tanfidhiya_ma(self):
        self.assertEqual(
            _P41.normalize_arabic_for_render('تنفيذيةمع'),
            'تنفيذية مع')

    @_skip
    def test_arabic_spacing_cleanup_cyber_alaa(self):
        self.assertEqual(
            _P41.normalize_arabic_for_render('السيبرانيةعلى'),
            'السيبرانية على')

    @_skip
    def test_arabic_spacing_cleanup_hokoma_faaila(self):
        self.assertEqual(
            _P41.normalize_arabic_for_render('الحوكمةالفعالة'),
            'الحوكمة الفعالة')

    @_skip
    def test_strategic_objectives_use_pdf_card_layout_for_arabic(self):
        from tests.test_cyber_export_parity_prcy50 import _model
        model = _model()
        fb = _P41.compute_pdf_export_layout_fallbacks(model, 'ar')
        self.assertEqual(fb.get('strategic_objectives'), 'objective_cards')
        checks = _P41.prcy47_docmodel_professional_checks(model, 'ar')
        self.assertTrue(checks['pdf_objectives_readable_layout_applied'])

    @_skip
    def test_pillar_initiatives_use_card_layout_not_table_plus_prose(self):
        from tests.test_cyber_export_parity_prcy50 import _model
        from copy import deepcopy
        model = deepcopy(_model())
        model['blocks']['strategic_pillars'] = {
            'title': 'الركائز',
            'pillar_blocks': [{
                'title': 'ركيزة 1',
                'paragraphs': ['مقدمة الركيزة', 'وصف مبادرة مكرر'],
                'table': {
                    'schema': 'pillar_initiatives',
                    'header': list(_P41.SCHEMA_PILLAR_INITIATIVES_AR),
                    'rows': [['1', 'مبادرة', 'وصف', 'مخرج']],
                },
            }],
        }
        fb = _P41.compute_pdf_export_layout_fallbacks(model, 'ar')
        self.assertEqual(
            fb.get('pillar_initiatives'), 'pillar_initiative_cards')
        checks = _P41.prcy47_docmodel_professional_checks(model, 'ar')
        self.assertTrue(
            checks['pdf_pillars_no_duplicate_initiative_rendering'])

    @_skip
    def test_governance_readable_via_cards_or_split(self):
        from tests.test_cyber_export_parity_prcy50 import _model
        model = _model()
        fb = _P41.compute_pdf_export_layout_fallbacks(model, 'ar')
        self.assertEqual(fb.get('governance'), 'governance_cards')
        checks = _P41.prcy47_docmodel_professional_checks(model, 'ar')
        self.assertTrue(checks['pdf_governance_split_if_wide'])

    @_skip
    def test_traceability_remains_split_by_framework(self):
        from tests.test_cyber_export_parity_prcy50 import _model
        model = _model()
        split = model['blocks']['traceability_matrix'].get(
            'split_tables') or []
        self.assertTrue(split)
        fws = {st.get('title') for st in split if st.get('title')}
        self.assertGreaterEqual(len(fws), 1)
        fb = _P41.compute_pdf_export_layout_fallbacks(model, 'ar')
        self.assertTrue(
            any(k.startswith('trace_fw') for k in fb))

    @_skip
    def test_pdf_final_polish_diag_emitted(self):
        from tests.test_cyber_export_parity_prcy50 import _model
        model = _model()
        diag = _P41.build_pdf_final_polish_diag(model, 'ar')
        for key in (
                'objectives_layout_mode', 'pillars_layout_mode',
                'duplicated_pillar_initiatives_removed',
                'arabic_spacing_cleanup_count',
                'remaining_arabic_spacing_issues',
                'dense_tables_before', 'dense_tables_after',
                'action_taken'):
            self.assertIn(key, diag, msg=key)
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            _P41.emit_pdf_final_polish_diag(model, 'ar')
        finally:
            sys.stdout = old
        self.assertIn('[PDF-FINAL-POLISH-DIAG]', buf.getvalue())

    @_skip
    def test_prcy62_polish_gates_pass_on_standard_model(self):
        from tests.test_cyber_export_parity_prcy50 import _model
        model = _model()
        checks = _P41.prcy47_docmodel_professional_checks(model, 'ar')
        self.assertTrue(checks['pdf_arabic_spacing_final_cleanup_passed'])
        self.assertTrue(checks['pdf_dense_table_polish_passed'])
        self.assertTrue(checks['docmodel_professional_passed'], checks)


if __name__ == '__main__':
    unittest.main()
