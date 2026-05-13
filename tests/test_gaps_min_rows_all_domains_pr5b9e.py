"""PR-5B.9E — Gaps row floor + domain category coverage for all domains.

Pins:
  * The gap-row floor in ``synthesize_gaps_depth`` is 5 in
    consulting/assurance OR when ``org_structure_is_none=True``.
  * AI repair returning a 4-row gaps section is rejected.
  * AI repair returning a 5-row gaps section with 1:1 implementation
    guides is accepted.
  * Per-domain gap-category clauses exist in
    ``ai_repair_strategy_section`` for cyber, data, ai, dt, erm.

Run:
    python -m pytest tests/test_gaps_min_rows_all_domains_pr5b9e.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_gaps_pr5b9e_')
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


def _gaps_with_n_rows(n, domain_label='القدرات'):
    """Build a gaps section with ``n`` substantive rows AND a
    matching per-row implementation guide subsection so the
    1:1 invariant is satisfied."""
    rows = []
    guides = []
    for i in range(1, n + 1):
        rows.append(
            f'| {i} | فجوة جوهرية في {domain_label} رقم {i} '
            f'تتطلب معالجة | عالية | مفتوحة |'
        )
        guides.append(
            f'#### دليل تنفيذ الفجوة {i}\n\n'
            '1. الخطوة الأولى للمعالجة الفعلية.\n'
            '2. الخطوة الثانية لتنفيذ المعالجة.\n'
            '3. الخطوة الثالثة لمتابعة المعالجة.\n'
            '4. الخطوة الرابعة للتحقق من الإغلاق.\n'
        )
    return (
        '## 4. تحليل الفجوات الاستراتيجية\n\n'
        '| # | الفجوة | الأولوية | الحالة |\n'
        '|---|--------|---------|--------|\n'
        + '\n'.join(rows) + '\n\n'
        + '\n\n'.join(guides) + '\n'
    )


class GapsRowFloorTests(unittest.TestCase):

    @_skip_if_no_app
    def test_consulting_floor_is_five(self):
        # Stub AI to return a 4-row gaps section: must be rejected.
        sections = {'gaps': '## 4. الفجوات\n\nنص قصير.\n'}
        original = _APP.ai_repair_strategy_section

        def _stub(*a, **kw):
            return _gaps_with_n_rows(4)

        _APP.ai_repair_strategy_section = _stub
        try:
            with self.assertRaises(_APP.RepairError) as ctx:
                _APP.synthesize_gaps_depth(
                    sections, lang='ar',
                    domain='Cyber Security', fw_short='ECC',
                    generation_mode='consulting',
                )
            self.assertEqual(getattr(ctx.exception, 'section', None), 'gaps')
        finally:
            _APP.ai_repair_strategy_section = original

    @_skip_if_no_app
    def test_consulting_accepts_five_rows(self):
        sections = {'gaps': '## 4. الفجوات\n\nنص قصير.\n'}
        original = _APP.ai_repair_strategy_section

        def _stub(*a, **kw):
            return _gaps_with_n_rows(5)

        _APP.ai_repair_strategy_section = _stub
        try:
            summary = _APP.synthesize_gaps_depth(
                sections, lang='ar',
                domain='Cyber Security', fw_short='ECC',
                generation_mode='consulting',
            )
        finally:
            _APP.ai_repair_strategy_section = original

        self.assertTrue(summary.get('rebuilt'))
        self.assertGreaterEqual(summary.get('rows_after', 0), 5)

    @_skip_if_no_app
    def test_org_structure_none_in_drafting_still_requires_five(self):
        sections = {'gaps': '## 4. الفجوات\n\nنص قصير.\n'}
        original = _APP.ai_repair_strategy_section

        def _stub(*a, **kw):
            return _gaps_with_n_rows(4)

        _APP.ai_repair_strategy_section = _stub
        try:
            with self.assertRaises(_APP.RepairError):
                _APP.synthesize_gaps_depth(
                    sections, lang='ar',
                    domain='Data Management', fw_short='NDMO',
                    generation_mode='drafting',
                    org_structure_is_none=True,
                )
        finally:
            _APP.ai_repair_strategy_section = original

    @_skip_if_no_app
    def test_per_domain_floor_and_acceptance_for_all_five_domains(self):
        # Stub AI to return 5 rows; every domain must accept.
        sections_template = '## 4. الفجوات\n\nنص قصير.\n'
        original = _APP.ai_repair_strategy_section

        def _stub(*a, **kw):
            return _gaps_with_n_rows(5)

        _APP.ai_repair_strategy_section = _stub
        try:
            for domain, fw in (
                    ('Cyber Security', 'ECC'),
                    ('Data Management', 'NDMO'),
                    ('Artificial Intelligence', 'SDAIA'),
                    ('Digital Transformation', 'DGA'),
                    ('Enterprise Risk Management', 'ISO31000'),
            ):
                with self.subTest(domain=domain):
                    sections = {'gaps': sections_template}
                    summary = _APP.synthesize_gaps_depth(
                        sections, lang='ar',
                        domain=domain, fw_short=fw,
                        generation_mode='consulting',
                    )
                    self.assertTrue(summary.get('rebuilt'))
                    self.assertGreaterEqual(
                        summary.get('rows_after', 0), 5,
                    )
        finally:
            _APP.ai_repair_strategy_section = original


class GapPromptDomainCategoriesTests(unittest.TestCase):
    """The gaps repair prompt must contain a per-domain expected
    gap-categories clause for cyber, data, ai, dt, and erm."""

    @_skip_if_no_app
    def test_prompt_addendum_present_for_each_domain(self):
        # Use a dummy AI that captures the prompt and returns 5 rows.
        captured = {}

        original_provider = getattr(_APP, '_ai_complete', None)

        def _capture_then_return(prompt, **kwargs):
            captured.setdefault('prompts', []).append(prompt)
            return _gaps_with_n_rows(5)

        # We don't actually exercise the provider — just call
        # ai_repair_strategy_section with a stub that returns the
        # repaired markdown directly. The clause is added inside
        # ai_repair_strategy_section BEFORE the AI call, but it is
        # present in the function's source.  We grep the source to
        # verify the clause exists for every domain code.
        import inspect
        src = inspect.getsource(_APP.ai_repair_strategy_section)
        for code in ('cyber', 'data', 'ai', 'dt', 'erm'):
            with self.subTest(domain=code):
                # The per-domain key appears in the AR or EN map.
                self.assertIn(
                    f'"{code}"', src,
                    f'Gap-category clause missing for domain code {code!r}',
                )
        # Cyber-specific tokens that the requirement lists explicitly.
        for tok in ('SOC', 'IAM', 'CSIRT', 'DLP', 'TCC'):
            with self.subTest(token=tok):
                self.assertIn(
                    tok, src,
                    f'Cyber gap-category token missing: {tok!r}',
                )


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
