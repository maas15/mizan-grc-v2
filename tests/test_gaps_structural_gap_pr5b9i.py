"""PR-5B.9I — Domain-specific structural-gap row in the Gaps section.

When the diagnostic input flags ``org_structure_is_none=True`` the
**Gaps** section MUST contain ONE explicit row that names the missing
domain-specific specialized function (e.g. AI →
"غياب مكتب/وحدة حوكمة الذكاء الاصطناعي"). The diagnosis-grounding gate
downstream blocks the save with "gaps do not include structural gap"
when the row is absent — even if the Vision/Objectives table already
mentions establishing the function.

These tests pin:

  1. ``_compute_missing_structural_gap_for_domain`` returns ``[]`` when
     ``org_structure_is_none=False`` regardless of gaps content.
  2. The helper returns ``[]`` when the gaps text contains the
     domain-specific structural-gap wording.
  3. The helper returns the missing concept families when the gaps text
     does NOT mention any of the per-domain establishment tokens.
  4. ``_final_strategy_audit`` emits ONE
     ``missing_structural_gap-org_structure_is_none:<domain>:...`` defect
     (section=``gaps``) when the gaps section is missing the structural
     row AND ``org_structure_is_none=True``.
  5. The defect is NOT emitted when ``org_structure_is_none=False``.
  6. The defect is NOT emitted when the gaps text already mentions the
     domain's specialized function.

Run:
    python -m pytest tests/test_gaps_structural_gap_pr5b9i.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_gaps_struct_pr5b9i_')
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


# Bare gaps text — no specialized-function token for any domain.
_GAPS_BARE_AR = (
    '## 4. تحليل الفجوات\n\n'
    '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
    '|---|------|------|---------|--------|\n'
    '| 1 | فجوة في القدرات | وصف عام | عالية | مفتوحة |\n'
    '| 2 | فجوة في التدريب | وصف عام | متوسطة | مفتوحة |\n'
    '| 3 | فجوة في الأدوات | وصف عام | منخفضة | مفتوحة |\n'
    '| 4 | فجوة في العمليات | وصف عام | عالية | مفتوحة |\n'
    '| 5 | فجوة في التوثيق | وصف عام | متوسطة | مفتوحة |\n'
)


# Per-domain "good" gaps text — explicitly mentions the domain's
# specialized function so at least one concept family token matches.
_GAPS_GOOD_BY_DOMAIN = {
    'ai': _GAPS_BARE_AR + (
        '| 6 | غياب مكتب حوكمة الذكاء الاصطناعي ولجنة الحوكمة وأدوار '
        'مخاطر النماذج | لا توجد وظيفة متخصصة | عالية | مفتوحة |\n'
    ),
    'dt': _GAPS_BARE_AR + (
        '| 6 | غياب مكتب التحول الرقمي وتعيين Chief Digital Officer '
        'ولجنة التحول الرقمي ونموذج التشغيل | لا توجد وظيفة | عالية | '
        'مفتوحة |\n'
    ),
    'data': _GAPS_BARE_AR + (
        '| 6 | غياب مكتب إدارة البيانات وتعيين CDO ولجنة حوكمة '
        'البيانات وأمناء البيانات | لا توجد وظيفة | عالية | مفتوحة |\n'
    ),
    'cyber': _GAPS_BARE_AR + (
        '| 6 | غياب إدارة الأمن السيبراني وتعيين CISO ولجنة حوكمة '
        'الأمن السيبراني والأدوار والمسؤوليات | لا توجد وظيفة | '
        'عالية | مفتوحة |\n'
    ),
    'erm': _GAPS_BARE_AR + (
        '| 6 | غياب إدارة المخاطر المؤسسية وتعيين CRO ولجنة المخاطر '
        'وملاك المخاطر | لا توجد وظيفة | عالية | مفتوحة |\n'
    ),
}


_DOMAINS = ('ai', 'dt', 'data', 'cyber', 'erm')


class HelperContractTests(unittest.TestCase):
    """Direct-call tests for ``_compute_missing_structural_gap_for_domain``."""

    @_skip_if_no_app
    def test_returns_empty_when_org_structure_is_none_false(self):
        for d in _DOMAINS:
            with self.subTest(domain=d):
                missing = (
                    _APP._compute_missing_structural_gap_for_domain(
                        _GAPS_BARE_AR, d,
                        org_structure_is_none=False, lang='ar',
                    ))
                self.assertEqual(missing, [],
                                 f'expected [] for domain={d} when '
                                 f'org_structure_is_none=False')

    @_skip_if_no_app
    def test_returns_empty_for_unknown_domain(self):
        # ``normalize_domain`` defaults unknown labels to ``cyber``
        # (the legacy default for the strategy generator). Pass a
        # value that the function recognises as out-of-registry; if
        # the runtime cannot resolve a domain code at all the helper
        # must return ``[]`` (no enforcement). We simulate this by
        # monkey-patching ``normalize_domain`` to return ''.
        import unittest.mock as _mock
        with _mock.patch.object(_APP, 'normalize_domain',
                                return_value=''):
            missing = (
                _APP._compute_missing_structural_gap_for_domain(
                    _GAPS_BARE_AR, 'whatever',
                    org_structure_is_none=True, lang='ar',
                ))
        self.assertEqual(missing, [])

    @_skip_if_no_app
    def test_returns_missing_for_bare_gaps_per_domain(self):
        for d in _DOMAINS:
            with self.subTest(domain=d):
                missing = (
                    _APP._compute_missing_structural_gap_for_domain(
                        _GAPS_BARE_AR, d,
                        org_structure_is_none=True, lang='ar',
                    ))
                self.assertTrue(
                    len(missing) > 0,
                    f'expected non-empty missing list for domain={d} '
                    f'when gaps text has no SF tokens, got {missing!r}')

    @_skip_if_no_app
    def test_returns_empty_when_gaps_text_mentions_specialized_function(self):
        for d, good_gaps in _GAPS_GOOD_BY_DOMAIN.items():
            with self.subTest(domain=d):
                missing = (
                    _APP._compute_missing_structural_gap_for_domain(
                        good_gaps, d,
                        org_structure_is_none=True, lang='ar',
                    ))
                # Helper uses any-family-match semantics: as long as
                # the gaps text mentions at least one token from any
                # concept family, the structural-gap row is considered
                # present and the helper returns [].
                self.assertEqual(
                    missing, [],
                    f'expected [] for domain={d} when gaps text '
                    f'mentions SF, got {missing!r}')

    @_skip_if_no_app
    def test_empty_gaps_text_returns_full_missing_list(self):
        for d in _DOMAINS:
            with self.subTest(domain=d):
                missing = (
                    _APP._compute_missing_structural_gap_for_domain(
                        '', d,
                        org_structure_is_none=True, lang='ar',
                    ))
                expected = list(
                    _APP._DOMAIN_SPECIALIZED_FUNCTION_CONCEPTS[d].keys())
                self.assertEqual(sorted(missing), sorted(expected))


class FinalAuditDefectTests(unittest.TestCase):
    """Pin the new defect emission in ``_final_strategy_audit``."""

    def _make_sections(self, gaps_text):
        # Minimal sections that DO satisfy non-gaps thresholds well
        # enough for the gaps-specific defect to be the one we observe.
        # We don't care about other defects here — we only assert the
        # presence/absence of the structural-gap defect.
        return {
            'vision': '## 1. الرؤية\n\nرؤية.\n',
            'pillars': '## 2. الركائز\n\n### 1\n\nنص.\n',
            'environment': '## 3. البيئة\n\nنص.\n',
            'gaps': gaps_text,
            'roadmap': '## 5. خارطة\n\n',
            'kpis': '## 6. مؤشرات\n\n',
            'confidence': '## 7. الثقة\n\n',
        }

    def _has_structural_gap_defect(self, defects):
        for tup in defects:
            if not isinstance(tup, tuple) or len(tup) < 2:
                continue
            sec, tag = tup[0], tup[1]
            if (sec == 'gaps'
                    and isinstance(tag, str)
                    and tag.startswith(
                        'missing_structural_gap-org_structure_is_none')):
                return True
        return False

    @_skip_if_no_app
    def test_defect_emitted_when_gaps_lacks_structural_row(self):
        for d in _DOMAINS:
            with self.subTest(domain=d):
                sections = self._make_sections(_GAPS_BARE_AR)
                defects = _APP._final_strategy_audit(
                    sections, lang='ar', doc_subtype=None,
                    selected_frameworks=None,
                    domain=d,
                    org_structure_is_none=True,
                )
                self.assertTrue(
                    self._has_structural_gap_defect(defects),
                    f'expected missing_structural_gap defect for '
                    f'domain={d}, got defects={defects!r}')

    @_skip_if_no_app
    def test_defect_not_emitted_when_org_structure_is_none_false(self):
        for d in _DOMAINS:
            with self.subTest(domain=d):
                sections = self._make_sections(_GAPS_BARE_AR)
                defects = _APP._final_strategy_audit(
                    sections, lang='ar', doc_subtype=None,
                    selected_frameworks=None,
                    domain=d,
                    org_structure_is_none=False,
                )
                self.assertFalse(
                    self._has_structural_gap_defect(defects),
                    f'unexpected missing_structural_gap defect for '
                    f'domain={d} when org_structure_is_none=False, '
                    f'got defects={defects!r}')

    @_skip_if_no_app
    def test_defect_not_emitted_when_gaps_mentions_specialized_function(self):
        for d, good_gaps in _GAPS_GOOD_BY_DOMAIN.items():
            with self.subTest(domain=d):
                sections = self._make_sections(good_gaps)
                defects = _APP._final_strategy_audit(
                    sections, lang='ar', doc_subtype=None,
                    selected_frameworks=None,
                    domain=d,
                    org_structure_is_none=True,
                )
                self.assertFalse(
                    self._has_structural_gap_defect(defects),
                    f'unexpected missing_structural_gap defect for '
                    f'domain={d} when gaps text mentions SF, got '
                    f'defects={defects!r}')


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
