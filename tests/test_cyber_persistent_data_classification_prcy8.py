"""PR-CY8 — Persistent Cyber DCC ``data_classification`` roadmap
balance failure after PR-CY7.

Runtime evidence (cyber + ECC + DCC, AR):

    cyber_roadmap_balance_missing:data_classification (roadmap) 0/1

After PR-CY7 the canonicalization, family-level top-up extraction, and
diagnostic plumbing were already in place. The remaining failure was
caused by:

  * the DCC canonical-alias map not collapsing
    ``information_classification`` to ``data_classification``; and
  * the ``data_classification`` exact-term list missing the Arabic
    equivalent of ``information classification``
    (``تصنيف المعلومات``), so AI candidates that used the natural AR
    phrasing failed the family acceptance gate.

This module validates the PR-CY8 fix:

  1. ``data_classification`` canonicalizes from
     ``dcc_data_classification``,
  2. ``data_classification`` canonicalizes from ``classification``,
  3. ``data_classification`` canonicalizes from
     ``information_classification`` (NEW in PR-CY8),
  4. Roadmap rows that contain any of the required Arabic exact terms
     satisfy ``data_classification`` family detection,
  5. Generic ``حماية البيانات`` (data protection — different family)
     does NOT satisfy ``data_classification``,
  6. A successful ``data_classification`` top-up row is spliced into
     the original roadmap and retained verbatim,
  7. The final balance audit no longer fails
     ``cyber_roadmap_balance_missing:data_classification`` when a
     classification row is present.

Strictly Cyber-scoped — Data Management / AI / DT / ERM behaviour is
not exercised. No deterministic rows are inserted. Validators are not
weakened.

Run::

    python -m pytest \\
        tests/test_cyber_persistent_data_classification_prcy8.py -q
"""
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_dc_prcy8_')
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


def _roadmap_with_row(activity):
    return (
        '## 5. خارطة الطريق\n\n'
        '| # | النشاط | المرحلة | الإطار |\n'
        '|---|---|---|---|\n'
        f'| 1 | {activity} | Q3 | DCC |\n'
    )


class TestDataClassificationCanonicalization(unittest.TestCase):
    """Part A — all variants collapse to the canonical
    ``data_classification`` family id."""

    @_skip_if_no_app
    def test_canonicalizes_from_dcc_data_classification(self):
        self.assertEqual(
            _APP._canonicalize_cyber_roadmap_family(
                'DCC', 'dcc_data_classification'),
            'data_classification')

    @_skip_if_no_app
    def test_canonicalizes_from_classification(self):
        self.assertEqual(
            _APP._canonicalize_cyber_roadmap_family(
                'DCC', 'classification'),
            'data_classification')

    @_skip_if_no_app
    def test_canonicalizes_from_information_classification(self):
        # PR-CY8 — new alias added so the top-up family request,
        # extractor, and acceptance check all key off the same
        # canonical id when the runtime emitter uses
        # ``information_classification``.
        self.assertEqual(
            _APP._canonicalize_cyber_roadmap_family(
                'DCC', 'information_classification'),
            'data_classification')

    @_skip_if_no_app
    def test_canonical_passthrough(self):
        self.assertEqual(
            _APP._canonicalize_cyber_roadmap_family(
                'DCC', 'data_classification'),
            'data_classification')


class TestDataClassificationRowAcceptance(unittest.TestCase):
    """Roadmap rows with any required Arabic exact term satisfy the
    family detection. Generic ``حماية البيانات`` (data protection)
    does NOT satisfy ``data_classification``."""

    @_skip_if_no_app
    def test_tasnif_albayanat_satisfies(self):
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            _roadmap_with_row('تنفيذ تصنيف البيانات وفق ضوابط DCC'),
            ['DCC'], lang='ar')
        self.assertNotIn(
            'data_classification', miss,
            f'تصنيف البيانات must satisfy data_classification: {miss}')

    @_skip_if_no_app
    def test_sensitive_classification_satisfies(self):
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            _roadmap_with_row(
                'تطبيق تصنيف البيانات الحساسة عبر القطاعات'),
            ['DCC'], lang='ar')
        self.assertNotIn(
            'data_classification', miss,
            f'تصنيف البيانات الحساسة must satisfy: {miss}')

    @_skip_if_no_app
    def test_data_asset_classification_satisfies(self):
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            _roadmap_with_row(
                'تطوير إطار تصنيف الأصول البيانية'),
            ['DCC'], lang='ar')
        self.assertNotIn(
            'data_classification', miss,
            f'تصنيف الأصول البيانية must satisfy: {miss}')

    @_skip_if_no_app
    def test_information_classification_ar_satisfies(self):
        # PR-CY8 — new AR exact term ``تصنيف المعلومات`` added so
        # the family acceptance gate matches the same wording as the
        # existing EN ``information classification`` term.
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            _roadmap_with_row('تطبيق تصنيف المعلومات وفق ضوابط DCC'),
            ['DCC'], lang='ar')
        self.assertNotIn(
            'data_classification', miss,
            f'تصنيف المعلومات must satisfy data_classification: {miss}')

    @_skip_if_no_app
    def test_generic_data_protection_does_not_satisfy(self):
        # Generic data-protection wording must not satisfy the
        # data_classification family (separate DCC family).
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            _roadmap_with_row(
                'تعزيز حماية البيانات بشكل عام'),
            ['DCC'], lang='ar')
        self.assertIn(
            'data_classification', miss,
            'generic حماية البيانات must NOT satisfy '
            'data_classification family — that is a separate family')


class TestDataClassificationTopupSplice(unittest.TestCase):
    """Successful data_classification top-up row is spliced into the
    original roadmap and retained verbatim."""

    @_skip_if_no_app
    def test_topup_row_spliced_and_retained(self):
        before = (
            '## 5. خارطة الطريق\n\n'
            '| # | النشاط | المرحلة | الإطار |\n'
            '|---|---|---|---|\n'
            '| 1 | تطبيق ضوابط التشفير على البيانات | Q3 | DCC |\n'
            '| 2 | تطبيق DLP ومنع تسرب البيانات | Q3 | DCC |\n'
            '| 3 | معالجة البيانات الحساسة | Q4 | DCC |\n'
            '| 4 | ضوابط حماية البيانات أثناء النقل والتخزين | Q4 | DCC |\n'
        )
        # Family detection: data_classification is missing.
        miss_before = _APP._compute_missing_cyber_roadmap_balance_topics(
            before, ['DCC'], lang='ar')
        self.assertIn('data_classification', miss_before)

        # AI emits a single top-up row for the missing family.
        ai_text = (
            '| 5 | تنفيذ تصنيف البيانات وتصنيف البيانات الحساسة '
            '| Q3 | DCC |\n'
        )
        terms = {
            'data_classification': list(
                _APP._CYBER_ROADMAP_BALANCE_TOPICS[
                    'data_classification']),
        }
        extracted = _APP._extract_data_roadmap_topup_rows(ai_text, terms)
        self.assertIn('data_classification', extracted,
                      'AI candidate with classification wording must be '
                      'extracted under canonical family id')

        merged = _APP._splice_data_roadmap_topup_rows(
            before, [extracted['data_classification']])
        # Every original line is preserved verbatim — no deterministic
        # rewrite by the splice helper.
        for ln in before.split('\n'):
            self.assertIn(ln, merged,
                          f'splice dropped original line: {ln!r}')
        # Top-up row landed.
        self.assertIn(extracted['data_classification'], merged)
        # And the family is no longer missing after the splice.
        miss_after = _APP._compute_missing_cyber_roadmap_balance_topics(
            merged, ['DCC'], lang='ar')
        self.assertNotIn('data_classification', miss_after)

    @_skip_if_no_app
    def test_final_audit_clears_after_classification_row_present(self):
        # Roadmap covers every DCC family — final balance check is
        # empty.
        full = (
            '## 5. خارطة الطريق\n\n'
            '| # | النشاط | المرحلة | الإطار |\n'
            '|---|---|---|---|\n'
            '| 1 | تنفيذ تصنيف البيانات وتصنيف البيانات الحساسة '
            '| Q3 | DCC |\n'
            '| 2 | تطبيق ضوابط التشفير على البيانات | Q3 | DCC |\n'
            '| 3 | تطبيق DLP ومنع تسرب البيانات | Q3 | DCC |\n'
            '| 4 | معالجة البيانات الحساسة وفق الضوابط | Q4 | DCC |\n'
            '| 5 | ضوابط حماية البيانات أثناء النقل والتخزين '
            '| Q4 | DCC |\n'
        )
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            full, ['DCC'], lang='ar')
        self.assertEqual(
            miss, [],
            f'final DCC balance must be empty when classification row '
            f'is present: {miss}')


class TestRegressionScope(unittest.TestCase):
    """Strict scope: PR-CY8 must not modify Data Management /
    AI / DT / ERM behaviour."""

    @_skip_if_no_app
    def test_data_audit_unchanged(self):
        defects = _APP._final_strategy_audit(
            sections={'vision': '', 'pillars': '', 'environment': '',
                      'gaps': '', 'roadmap': 'r',
                      'kpis': '', 'confidence': ''},
            lang='en',
            selected_frameworks=['NDMO'],
            domain='Data Management')
        for _sec, tag, *_ in defects:
            self.assertFalse(
                tag.startswith('cyber_roadmap_balance_missing:'))

    @_skip_if_no_app
    def test_ai_audit_unchanged(self):
        defects = _APP._final_strategy_audit(
            sections={'vision': '', 'pillars': '', 'environment': '',
                      'gaps': '', 'roadmap': 'r',
                      'kpis': '', 'confidence': ''},
            lang='en',
            selected_frameworks=['SDAIA'],
            domain='Artificial Intelligence')
        for _sec, tag, *_ in defects:
            self.assertFalse(
                tag.startswith('cyber_roadmap_balance_missing:'))


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
