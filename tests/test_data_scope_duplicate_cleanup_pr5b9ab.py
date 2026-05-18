"""PR-5B.9AB — Scope display PDPL capability dedupe.

PDPL registers two alias families (``data_classification_pdpl`` and
``personal_data_classification``) with identical AR / EN first-keyword
labels. The scope/frameworks block must render the classification
capability label only ONCE so the published scope doesn't show
``تصنيف البيانات الشخصية`` twice under PDPL.

Run::

    python -m pytest \\
        tests/test_data_scope_duplicate_cleanup_pr5b9ab.py -q
"""
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_data_pr5b9ab_scope_')
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


class TestScopeDedupe(unittest.TestCase):

    @_skip_if_no_app
    def test_01_pdpl_scope_does_not_duplicate_classification_label_ar(self):
        out = _APP._build_scope_frameworks_block(
            {}, ['NDMO', 'PDPL'], 'ar')
        pdpl_entry = next(e for e in out if e['key'] == 'PDPL')
        desc = pdpl_entry['description']
        self.assertEqual(
            desc.count('تصنيف البيانات الشخصية'), 1,
            f'PDPL scope description duplicates the classification '
            f'label: {desc!r}')

    @_skip_if_no_app
    def test_02_pdpl_scope_does_not_duplicate_classification_label_en(self):
        out = _APP._build_scope_frameworks_block(
            {}, ['NDMO', 'PDPL'], 'en')
        pdpl_entry = next(e for e in out if e['key'] == 'PDPL')
        desc = pdpl_entry['description']
        self.assertEqual(
            desc.lower().count('personal data classification'), 1,
            f'PDPL scope description duplicates the classification '
            f'label: {desc!r}')

    @_skip_if_no_app
    def test_03_pdpl_scope_still_lists_all_distinct_capabilities_ar(self):
        out = _APP._build_scope_frameworks_block(
            {}, ['PDPL'], 'ar')
        desc = out[0]['description']
        # Every other PDPL capability label must still be present.
        for token in ('حوكمة الخصوصية', 'إدارة الموافقات',
                      'حقوق صاحب البيانات',
                      'تصنيف البيانات الشخصية',
                      'الإبلاغ عن الانتهاكات'):
            self.assertIn(
                token, desc,
                f'PDPL scope dropped capability {token!r}: {desc!r}')

    @_skip_if_no_app
    def test_04_ndmo_scope_unchanged_no_dupes(self):
        """Sanity: NDMO scope (no alias families) renders each
        capability exactly once."""
        out = _APP._build_scope_frameworks_block(
            {}, ['NDMO'], 'ar')
        desc = out[0]['description']
        # Each NDMO family label should appear at most once.
        for token in ('حوكمة البيانات', 'جودة البيانات',
                      'كتالوج البيانات', 'أمناء البيانات',
                      'دورة حياة البيانات'):
            self.assertLessEqual(
                desc.count(token), 1,
                f'NDMO scope unexpectedly duplicates {token!r}: '
                f'{desc!r}')


if __name__ == '__main__':
    unittest.main()
