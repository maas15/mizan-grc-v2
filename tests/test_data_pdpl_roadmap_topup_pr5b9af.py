"""PR-5B.9AF — Data roadmap balance repair: AI-generated TOP-UP rows
instead of full roadmap replacement.

Runtime trace prior to PR-5B.9AF showed
``_convergence_data_roadmap_balance_repair`` rejecting every AI
candidate because each fresh full-roadmap regeneration kept SOME of
the required literal AR/EN family terms but dropped others — sometimes
``consent_management`` was present but ``breach_notification`` was
missing; sometimes ``data_subject_rights`` but not
``consent_management``; sometimes ``personal_data_classification`` was
present but ``breach_notification``/``data_subject_rights`` were
missing; etc. The candidate was rejected and the original roadmap was
restored each cycle, leaving the ``data_roadmap_balance_missing``
defect as the final blocker.

PR-5B.9AF switches the repair to AI-generated TOP-UP ROWS that the
host system splices into the EXISTING roadmap text. Previously
covered rows are preserved verbatim so satisfied families cannot
regress; the AI only has to produce one new row per still-uncovered
family. No deterministic row content is ever inserted — every
spliced row is a verbatim substring of the AI provider's response.

This module validates the PR-5B.9AF contract WITHOUT requiring an AI
provider. The three new helpers are exercised directly with stub AI
responses, and the convergence repair fail-closed plumbing (which
fires when no API key is configured) is asserted unchanged.

Run::

    python -m pytest \\
        tests/test_data_pdpl_roadmap_topup_pr5b9af.py -q
"""
import importlib.util
import inspect
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_data_pr5b9af_')
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


_FRAMEWORKS = ['NDMO', 'PDPL']


_ORIGINAL_ROADMAP = (
    '## 5. خارطة الطريق\n\n'
    '| # | النشاط | المالك | الإطار الزمني | المخرج |\n'
    '|---|------|------|------|------|\n'
    '| 1 | تأسيس مكتب إدارة البيانات وتعيين رئيس البيانات (CDO) '
    '| الإدارة العليا | Q1 | ميثاق مكتب البيانات |\n'
    '| 2 | إدارة الموافقات وسجل الموافقات والموافقة الصريحة '
    '| CDO | Q1 | سجل |\n'
    '| 3 | تفعيل حقوق صاحب البيانات: حق الوصول، حق التصحيح، حق الحذف '
    '| CDO | Q1 | آلية |\n'
    '| 4 | إطلاق برنامج إدارة جودة البيانات | CDO | Q2 | مقاييس |\n'
    '| 5 | بناء كتالوج البيانات والبيانات الوصفية | CDO | Q2 | كتالوج |\n'
    '| 6 | دورة حياة البيانات والاحتفاظ والإتلاف | CDO | Q3 | سياسة |\n'
    '| 7 | حوكمة الخصوصية | CDO | Q3 | سياسة |\n'
)


class TestTopupHelpers(unittest.TestCase):
    """The three new module-level helpers must (a) build the
    family→required-terms map from the PDPL save-guard registry,
    (b) extract at most one Markdown pipe-row per family from an AI
    response (header / separator rows skipped), and (c) splice rows
    after the LAST existing roadmap table row while preserving every
    prior line verbatim.
    """

    @_skip_if_no_app
    def test_01_required_terms_map_uses_save_guard_registry(self):
        m = _APP._data_roadmap_topup_required_terms_map(
            ['personal_data_classification', 'breach_notification',
             'consent_management', 'data_subject_rights'],
            pdpl_selected=True)
        # Sanity: the four PDPL families each have a non-empty term list
        # populated from the PR-5B.9Y exact-term registry.
        for fam in ('personal_data_classification',
                    'breach_notification',
                    'consent_management',
                    'data_subject_rights'):
            self.assertIn(fam, m)
            self.assertTrue(m[fam],
                            f'{fam} required-terms map is empty')
        # Spot-check a few canonical terms surface in the map.
        self.assertTrue(
            any('تصنيف البيانات الشخصية' in t for t in
                m['personal_data_classification']),
            'classification AR exact term missing from map')
        self.assertTrue(
            any('إخطار الخروقات' in t for t in
                m['breach_notification'])
            or any('الإبلاغ عن الانتهاكات' in t for t in
                   m['breach_notification']),
            'breach AR exact term missing from map')

    @_skip_if_no_app
    def test_02_required_terms_map_balance_topics_when_no_pdpl(self):
        # When PDPL is not selected, the map falls back to the
        # _DATA_ROADMAP_BALANCE_TOPICS vocabulary.
        m = _APP._data_roadmap_topup_required_terms_map(
            ['data_quality', 'data_catalog'], pdpl_selected=False)
        self.assertIn('data_quality', m)
        self.assertIn('data_catalog', m)
        self.assertTrue(m['data_quality'])
        self.assertTrue(m['data_catalog'])

    @_skip_if_no_app
    def test_03_extract_picks_one_row_per_family(self):
        ai_text = (
            '## 5. خارطة الطريق التنفيذية\n'
            '| # | النشاط | المسؤول | الإطار الزمني | المخرج |\n'
            '|---|--------|---------|----------------|--------|\n'
            '| 1 | تأسيس مكتب البيانات | CDO | Q1 | ميثاق |\n'
            '| 2 | تطبيق تصنيف البيانات الشخصية وربطه بضوابط PDPL '
            '| مسؤول حماية البيانات | Q2 | إطار |\n'
            '| 3 | تفعيل إخطار الخروقات والإبلاغ عن الانتهاكات '
            '| مسؤول حماية البيانات | Q2 | آلية |\n'
            '| 4 | إدارة الموافقات وسجل الموافقات | CDO | Q1 | سجل |\n'
        )
        terms_map = _APP._data_roadmap_topup_required_terms_map(
            ['personal_data_classification', 'breach_notification',
             'consent_management'],
            pdpl_selected=True)
        found = _APP._extract_data_roadmap_topup_rows(ai_text, terms_map)
        self.assertIn('personal_data_classification', found)
        self.assertIn('breach_notification', found)
        self.assertIn('consent_management', found)
        # Each picked row is a verbatim pipe-row from the AI response
        # (not a separator, not a header).
        for fam, row in found.items():
            self.assertTrue(row.startswith('|') and row.endswith('|'),
                            f'{fam} row not a pipe-row: {row!r}')
            self.assertNotIn('---', row)
            # Header tokens should not dominate the picked row.
            self.assertNotIn('النشاط | المسؤول', row)

    @_skip_if_no_app
    def test_04_extract_skips_header_and_separator_rows(self):
        ai_text = (
            '| # | النشاط | المسؤول | الإطار الزمني | المخرج |\n'
            '|---|--------|---------|----------------|--------|\n'
            '| 1 | تطبيق تصنيف البيانات الشخصية | CDO | Q2 | إطار |\n'
        )
        terms_map = _APP._data_roadmap_topup_required_terms_map(
            ['personal_data_classification'], pdpl_selected=True)
        found = _APP._extract_data_roadmap_topup_rows(ai_text, terms_map)
        self.assertEqual(list(found), ['personal_data_classification'])
        # The picked row must NOT be the header or the separator.
        row = found['personal_data_classification']
        self.assertNotIn('النشاط', row)
        self.assertNotIn('---', row)

    @_skip_if_no_app
    def test_05_extract_returns_empty_when_no_terms_match(self):
        ai_text = (
            '| # | النشاط | المسؤول | الإطار الزمني | المخرج |\n'
            '|---|--------|---------|----------------|--------|\n'
            '| 1 | حماية البيانات الشخصية | CDO | Q2 | سياسة |\n'
            '| 2 | الامتثال لـ PDPL | CDO | Q3 | تقرير |\n'
        )
        terms_map = _APP._data_roadmap_topup_required_terms_map(
            ['personal_data_classification', 'breach_notification'],
            pdpl_selected=True)
        found = _APP._extract_data_roadmap_topup_rows(ai_text, terms_map)
        # Generic "حماية البيانات الشخصية" / "PDPL compliance" must NOT
        # satisfy either family (PR-5B.9Y exact-term contract).
        self.assertNotIn('personal_data_classification', found)
        self.assertNotIn('breach_notification', found)

    @_skip_if_no_app
    def test_06_splice_preserves_every_existing_line(self):
        new_rows = [
            '| 8 | تطبيق تصنيف البيانات الشخصية | DPO | Q2 | إطار |',
            '| 9 | تفعيل إخطار الخروقات | DPO | Q3 | آلية |',
        ]
        merged = _APP._splice_data_roadmap_topup_rows(
            _ORIGINAL_ROADMAP, new_rows)
        # Every line of the original roadmap must appear in the merged
        # output verbatim.
        for ln in _ORIGINAL_ROADMAP.split('\n'):
            self.assertIn(ln, merged,
                          f'original line dropped by splice: {ln!r}')
        # Both new rows are present.
        for row in new_rows:
            self.assertIn(row, merged)
        # The new rows appear AFTER the last original table row.
        last_orig_row = (
            '| 7 | حوكمة الخصوصية | CDO | Q3 | سياسة |')
        self.assertIn(last_orig_row, merged)
        self.assertLess(
            merged.index(last_orig_row),
            merged.index(new_rows[0]),
            'splice did not place new rows after the last existing row')

    @_skip_if_no_app
    def test_07_splice_no_op_on_empty_rows(self):
        merged = _APP._splice_data_roadmap_topup_rows(
            _ORIGINAL_ROADMAP, [])
        self.assertEqual(merged, _ORIGINAL_ROADMAP)


class TestConvergenceTopupWiring(unittest.TestCase):
    """The convergence balance repair must (a) reference the three new
    top-up helpers in source, (b) emit the ``mode=topup`` diagnostic on
    every AI attempt, and (c) preserve the PR-5B.9AA / 9AD / 9AE
    contracts (acceptance gate, second-pass strict requirement,
    fail-closed via _mark_synth_failed).
    """

    @_skip_if_no_app
    def test_08_repair_source_calls_topup_helpers(self):
        src = inspect.getsource(
            _APP._convergence_data_roadmap_balance_repair)
        # PR-5B.9AF marker + the three new helper calls must all
        # appear in the repair function body.
        self.assertIn('PR-5B.9AF', src)
        self.assertIn('_data_roadmap_topup_required_terms_map(', src)
        self.assertIn('_extract_data_roadmap_topup_rows(', src)
        self.assertIn('_splice_data_roadmap_topup_rows(', src)
        # Acceptance gate, second-pass + fail-closed plumbing are
        # preserved verbatim (PR-5B.9AA/9AD/9AE contracts).
        self.assertIn('while attempt < 2 and not accepted', src)
        self.assertIn('SECOND-PASS STRICT REQUIREMENT', src)
        self.assertIn('_pdpl_save_guard_required_terms(_ufam)', src)
        self.assertIn('_mark_synth_failed', src)
        # No deterministic fallback row insertion.
        forbidden = (
            "sections['roadmap'] = (before_text + '|'",
            "sections['roadmap'] += '|",
            "sections['roadmap'] = before_text + \"| ",
        )
        for f in forbidden:
            self.assertNotIn(
                f, src,
                'deterministic fallback row insertion forbidden')

    @_skip_if_no_app
    def test_09_no_api_keys_restores_original_and_marks_failed(self):
        """Without API keys the AI call raises RepairError; the repair
        function must restore the original roadmap and mark
        ``synth_failed:roadmap`` exactly as before PR-5B.9AF."""
        sections = {
            'vision': '## 1. الرؤية\n',
            'pillars': '## 2. الركائز الاستراتيجية\n',
            'environment': '## 3. السياق التنظيمي\nNDMO and PDPL.\n',
            'gaps': '## 4. تحليل الفجوات\n',
            'roadmap': _ORIGINAL_ROADMAP,
            'kpis': '## 6. مؤشرات الأداء\n',
            'confidence': '## 7. تقييم الجاهزية\n',
        }
        before = sections['roadmap']
        log = {'synth_status': {}}
        ctx = {'frameworks': _FRAMEWORKS,
               'org_structure_is_none': False,
               'org_name': 'Test', 'sector': 'General',
               'maturity': 'initial',
               'generation_mode': 'drafting'}
        buf = io.StringIO()
        with redirect_stdout(buf):
            _APP._convergence_data_roadmap_balance_repair(
                sections, 'ar', 'Data Management', ctx, log, 1)
        out = buf.getvalue()
        # Roadmap fully restored to original (no partial residue from
        # any aborted top-up splice).
        self.assertEqual(sections['roadmap'], before)

        def _walk_status(node):
            if isinstance(node, dict):
                if node.get('roadmap') == 'failed':
                    return True
                for v in node.values():
                    if _walk_status(v):
                        return True
            return False

        self.assertTrue(
            _walk_status(log),
            f'expected roadmap synth_failed marker in log; log={log}')
        # PR-5B.9AA/AD/AE diagnostics + the legacy convergence tag are
        # still emitted (the fail-closed code path is unchanged).
        self.assertIn('[CONVERGENCE-DATA-ROADMAP-BALANCE-REPAIR]', out)
        self.assertIn('[DATA-ROADMAP-PDPL-COVERAGE]', out)


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
