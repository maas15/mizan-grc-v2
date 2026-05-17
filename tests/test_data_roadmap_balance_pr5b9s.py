"""PR-5B.9S — Data Management roadmap balance.

Scope is **Data Management only** — Cyber / AI / DT / ERM behaviour
must be preserved byte-for-byte. Validates that the Data Management
roadmap, when NDMO and/or PDPL is selected, must cover balance topics
beyond office setup: data quality, data catalog / metadata, data
lifecycle, PDPL privacy governance, consent management, data subject
rights, and breach notification.

  * Part A — ``_compute_missing_data_roadmap_balance_topics`` returns
    the missing families for thin / office-only roadmaps and ``[]``
    for balanced roadmaps.
  * Part B — When NDMO selection only, the helper requires NDMO
    families (quality / catalog / lifecycle) only; PDPL families are
    not penalised.
  * Part C — Similarly for PDPL-only selection.
  * Part D — Cross-domain regression: Cyber / AI / DT / ERM final
    audit emits no ``data_roadmap_balance_missing`` defect even when
    their roadmap text is thin, because the helper is guarded by
    ``domain == 'data'`` and the framework selection.

Run:
    python -m pytest \
        tests/test_data_roadmap_balance_pr5b9s.py -q
"""
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_data_rmap_pr5b9s_')
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


# Office-only roadmap — no balance topics covered.
_OFFICE_ONLY_ROADMAP_AR = (
    '## 5. خارطة الطريق\n\n'
    '| # | النشاط | الوصف |\n'
    '|---|------|------|\n'
    '| 1 | تأسيس مكتب إدارة البيانات وتعيين رئيس البيانات (CDO) | DMO |\n'
    '| 2 | تشكيل لجنة حوكمة البيانات | data governance committee |\n'
    '| 3 | اعتماد نموذج التشغيل وخطوط الرفع | operating model |\n'
)

# Balanced roadmap — covers office setup PLUS all 8 balance topics.
_BALANCED_ROADMAP_AR = _OFFICE_ONLY_ROADMAP_AR + (
    '| 4 | إطلاق برنامج إدارة جودة البيانات | data quality program |\n'
    '| 5 | بناء كتالوج البيانات وإدارة البيانات الوصفية | metadata |\n'
    '| 6 | حوكمة دورة حياة البيانات والاحتفاظ بالبيانات | data lifecycle |\n'
    '| 7 | تفعيل حوكمة الخصوصية وحماية البيانات الشخصية | privacy |\n'
    '| 8 | إدارة الموافقات لأصحاب البيانات | consent management |\n'
    '| 9 | تفعيل حقوق صاحب البيانات والاستجابة | data subject rights |\n'
    '| 10 | اعتماد تصنيف البيانات الشخصية | personal data classification |\n'
    '| 11 | إجراءات الإبلاغ عن الانتهاكات | breach notification |\n'
)


class TestDataRoadmapBalanceHelper(unittest.TestCase):
    @_skip_if_no_app
    def test_office_only_roadmap_missing_all_ndmo_pdpl_families(self):
        missing = _APP._compute_missing_data_roadmap_balance_topics(
            _OFFICE_ONLY_ROADMAP_AR, ['NDMO', 'PDPL'], lang='ar')
        # All 8 families are missing (PR-5B.9S fix added
        # personal_data_classification under PDPL).
        self.assertEqual(set(missing), {
            'data_quality', 'data_catalog', 'data_lifecycle',
            'privacy_governance', 'consent_management',
            'data_subject_rights', 'personal_data_classification',
            'breach_notification',
        }, f'unexpected missing set: {missing}')

    @_skip_if_no_app
    def test_balanced_roadmap_emits_no_balance_defect(self):
        missing = _APP._compute_missing_data_roadmap_balance_topics(
            _BALANCED_ROADMAP_AR, ['NDMO', 'PDPL'], lang='ar')
        self.assertEqual(missing, [],
                         f'expected no missing, got: {missing}')

    @_skip_if_no_app
    def test_ndmo_only_selection_requires_only_ndmo_families(self):
        # Office-only roadmap, NDMO only — should miss the 3 NDMO
        # families but NOT any PDPL family.
        missing = _APP._compute_missing_data_roadmap_balance_topics(
            _OFFICE_ONLY_ROADMAP_AR, ['NDMO'], lang='ar')
        self.assertEqual(set(missing), {
            'data_quality', 'data_catalog', 'data_lifecycle',
        }, f'NDMO-only missing set wrong: {missing}')

    @_skip_if_no_app
    def test_pdpl_only_selection_requires_only_pdpl_families(self):
        missing = _APP._compute_missing_data_roadmap_balance_topics(
            _OFFICE_ONLY_ROADMAP_AR, ['PDPL'], lang='ar')
        self.assertEqual(set(missing), {
            'privacy_governance', 'consent_management',
            'data_subject_rights', 'personal_data_classification',
            'breach_notification',
        }, f'PDPL-only missing set wrong: {missing}')

    @_skip_if_no_app
    def test_empty_selection_returns_no_obligations(self):
        # No NDMO / PDPL selected — helper applies no obligation.
        missing = _APP._compute_missing_data_roadmap_balance_topics(
            _OFFICE_ONLY_ROADMAP_AR, [], lang='ar')
        self.assertEqual(missing, [])

    @_skip_if_no_app
    def test_empty_roadmap_with_ndmo_misses_all_ndmo_families(self):
        missing = _APP._compute_missing_data_roadmap_balance_topics(
            '', ['NDMO'], lang='ar')
        self.assertEqual(set(missing), {
            'data_quality', 'data_catalog', 'data_lifecycle',
        })

    @_skip_if_no_app
    def test_english_keywords_satisfy_balance(self):
        en_road = (
            '## 5. Roadmap\n\n'
            '| # | Activity |\n|---|---|\n'
            '| 1 | Establish a data management office (DMO) and appoint CDO |\n'
            '| 2 | Data quality program |\n'
            '| 3 | Data catalog and metadata management |\n'
            '| 4 | Data lifecycle and retention governance |\n'
            '| 5 | Privacy governance |\n'
            '| 6 | Consent management |\n'
            '| 7 | Data subject rights program |\n'
            '| 8 | Personal data classification scheme |\n'
            '| 9 | Breach notification procedure |\n'
        )
        missing = _APP._compute_missing_data_roadmap_balance_topics(
            en_road, ['NDMO', 'PDPL'], lang='en')
        self.assertEqual(missing, [])


class TestDataRoadmapBalanceAuditWiring(unittest.TestCase):
    """The final audit must surface the balance defect for Data
    domain + NDMO/PDPL selection — and must NOT surface it for
    Cyber / AI / DT / ERM."""

    @_skip_if_no_app
    def _audit_tags(self, **kw):
        defects = _APP._final_strategy_audit(**kw)
        return [d[1] for d in defects]

    @_skip_if_no_app
    def test_audit_emits_balance_defect_for_data_ndmo_office_only(self):
        # Pad other sections to thresholds so the only defect of
        # interest is the balance one. We only care that the
        # balance tag appears — other defects are allowed.
        sections = {
            'vision': '', 'pillars': '', 'environment': '',
            'gaps': '', 'roadmap': _OFFICE_ONLY_ROADMAP_AR,
            'kpis': '', 'confidence': '',
        }
        tags = self._audit_tags(
            sections=sections, lang='ar', doc_subtype=None,
            selected_frameworks=['NDMO', 'PDPL'], domain='Data Management',
            org_structure_is_none=False,
        )
        bal = [t for t in tags if t.startswith('data_roadmap_balance_missing:')]
        self.assertEqual(len(bal), 1,
                         f'expected one balance defect, got tags={tags}')
        # The missing families must be encoded in the tag.
        self.assertIn('data_quality', bal[0])
        self.assertIn('breach_notification', bal[0])

    @_skip_if_no_app
    def test_audit_no_balance_defect_for_balanced_roadmap(self):
        sections = {
            'vision': '', 'pillars': '', 'environment': '',
            'gaps': '', 'roadmap': _BALANCED_ROADMAP_AR,
            'kpis': '', 'confidence': '',
        }
        tags = self._audit_tags(
            sections=sections, lang='ar',
            selected_frameworks=['NDMO', 'PDPL'], domain='Data Management',
        )
        bal = [t for t in tags if t.startswith('data_roadmap_balance_missing:')]
        self.assertEqual(bal, [],
                         f'unexpected balance defect on balanced roadmap: {tags}')

    @_skip_if_no_app
    def test_cyber_audit_unchanged_no_balance_defect(self):
        sections = {
            'vision': '', 'pillars': '', 'environment': '',
            'gaps': '', 'roadmap': 'short roadmap',
            'kpis': '', 'confidence': '',
        }
        tags = self._audit_tags(
            sections=sections, lang='en',
            selected_frameworks=['ECC'], domain='Cyber Security',
        )
        self.assertFalse(
            any(t.startswith('data_roadmap_balance_missing:') for t in tags),
            f'Cyber must not emit balance defect: {tags}')

    @_skip_if_no_app
    def test_ai_audit_unchanged_no_balance_defect(self):
        sections = {
            'vision': '', 'pillars': '', 'environment': '',
            'gaps': '', 'roadmap': 'short roadmap',
            'kpis': '', 'confidence': '',
        }
        tags = self._audit_tags(
            sections=sections, lang='en',
            selected_frameworks=['SDAIA'], domain='Artificial Intelligence',
        )
        self.assertFalse(
            any(t.startswith('data_roadmap_balance_missing:') for t in tags),
            f'AI must not emit balance defect: {tags}')

    @_skip_if_no_app
    def test_dt_audit_unchanged_no_balance_defect(self):
        sections = {
            'vision': '', 'pillars': '', 'environment': '',
            'gaps': '', 'roadmap': 'short roadmap',
            'kpis': '', 'confidence': '',
        }
        tags = self._audit_tags(
            sections=sections, lang='en',
            selected_frameworks=['DGA'], domain='Digital Transformation',
        )
        self.assertFalse(
            any(t.startswith('data_roadmap_balance_missing:') for t in tags),
            f'DT must not emit balance defect: {tags}')

    @_skip_if_no_app
    def test_erm_audit_unchanged_no_balance_defect(self):
        sections = {
            'vision': '', 'pillars': '', 'environment': '',
            'gaps': '', 'roadmap': 'short roadmap',
            'kpis': '', 'confidence': '',
        }
        tags = self._audit_tags(
            sections=sections, lang='en',
            selected_frameworks=['ISO22301'],
            domain='Enterprise Risk Management',
        )
        self.assertFalse(
            any(t.startswith('data_roadmap_balance_missing:') for t in tags),
            f'ERM must not emit balance defect: {tags}')


if __name__ == '__main__':
    unittest.main()
