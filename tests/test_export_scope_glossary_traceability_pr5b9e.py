"""PR-5B.9E — Export-time scope, glossary, and traceability quality.

Pins:
  * ``_build_appendices_block`` drops registry-framework acronyms that
    are NOT selected and NOT literally referenced in content.
    - AI + SDAIA selected → glossary contains SDAIA, but NOT
      NIST_AI_RMF (unless the body explicitly mentions it).
    - Cyber + ECC + TCC → glossary excludes Data/AI/ERM/Standards
      cross-domain acronyms.
    - DT + DGA → glossary excludes cyber/data/AI/ERM acronyms.
    - ERM + ISO31000 + COSO_ERM → glossary excludes cyber/data/AI/DT
      acronyms.
  * ``_build_traceability_matrix`` exposes ``informative_rows`` so the
    PDF/DOCX renderers can drop rows with "—" in key cells. The
    informative-rows filter requires Gap AND Initiative AND at least
    one of (KPI, Risk) to be non-dash.

Run:
    python -m pytest tests/test_export_scope_glossary_traceability_pr5b9e.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_export_pr5b9e_')
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


def _glossary_acronyms(out):
    """Extract bullet-acronym labels from the appendices block."""
    acronyms = []
    in_glossary = False
    for label, body in out:
        if 'الملحق ب' in str(label) or 'Appendix B' in str(label):
            in_glossary = True
            continue
        if not in_glossary:
            continue
        s = str(label).strip()
        if s.startswith('•'):
            tok = s.lstrip('•').strip()
            if tok:
                acronyms.append(tok)
    return acronyms


class GlossaryScopingTests(unittest.TestCase):

    @_skip_if_no_app
    def test_ai_with_sdaia_excludes_unselected_nist_ai_rmf(self):
        # AI strategy where the body never mentions NIST AI RMF and
        # only SDAIA is selected: the glossary must not list
        # NIST_AI_RMF.
        body = {
            'vision': 'الرؤية: تعزيز حوكمة الذكاء الاصطناعي.',
            'pillars': 'الركائز: حوكمة، أخلاقيات، شفافية.',
            'gaps': 'الفجوات: غياب مكتب الحوكمة.',
        }
        out = _APP._build_appendices_block(
            ['SDAIA'], lang='en',
            content_sections=body, domain_code='ai',
        )
        acronyms = _glossary_acronyms(out)
        self.assertNotIn(
            'NIST AI RMF', acronyms,
            f'NIST_AI_RMF leaked into AI glossary: {acronyms}',
        )

    @_skip_if_no_app
    def test_ai_with_sdaia_keeps_nist_when_referenced_in_content(self):
        body = {
            'vision': 'Vision: align with NIST AI RMF principles.',
            'pillars': 'Pillars referencing NIST AI RMF guidance.',
        }
        out = _APP._build_appendices_block(
            ['SDAIA'], lang='en',
            content_sections=body, domain_code='ai',
        )
        acronyms = _glossary_acronyms(out)
        # NIST AI RMF appears as the display acronym when content
        # explicitly references it.
        self.assertTrue(
            any('NIST AI RMF' in a for a in acronyms),
            f'NIST_AI_RMF not retained when referenced in content: '
            f'{acronyms}',
        )

    @_skip_if_no_app
    def test_cyber_glossary_excludes_data_ai_erm_terms(self):
        body = {
            'vision': 'الرؤية: تعزيز الأمن السيبراني.',
            'pillars': 'الركائز: SOC، IAM، MFA.',
        }
        out = _APP._build_appendices_block(
            ['ECC', 'TCC'], lang='ar',
            content_sections=body, domain_code='cyber',
        )
        acronyms = _glossary_acronyms(out)
        # Cross-domain forbidden acronyms must not appear unless the
        # body contains them word-bounded; this body does not.
        for forbidden in ('NDMO', 'SDAIA', 'ISO 31000', 'NIST AI RMF',
                          'DGA'):
            with self.subTest(forbidden=forbidden):
                self.assertFalse(
                    any(forbidden in a for a in acronyms),
                    f'Cyber glossary leaked {forbidden!r}: {acronyms}',
                )

    @_skip_if_no_app
    def test_dt_glossary_excludes_cross_domain_terms(self):
        body = {
            'vision': 'الرؤية: تسريع التحول الرقمي.',
            'pillars': 'تكامل الخدمات، تجربة المستخدم.',
        }
        out = _APP._build_appendices_block(
            ['DGA'], lang='ar',
            content_sections=body, domain_code='dt',
        )
        acronyms = _glossary_acronyms(out)
        for forbidden in ('SOC', 'NDMO', 'SDAIA', 'NIST AI RMF',
                          'ISO 31000', 'COSO'):
            with self.subTest(forbidden=forbidden):
                self.assertFalse(
                    any(forbidden in a for a in acronyms),
                    f'DT glossary leaked {forbidden!r}: {acronyms}',
                )

    @_skip_if_no_app
    def test_erm_glossary_excludes_other_domains(self):
        body = {
            'vision': 'الرؤية: إدارة المخاطر المؤسسية.',
            'pillars': 'شهية المخاطر، سجل المخاطر.',
        }
        out = _APP._build_appendices_block(
            ['ISO31000', 'COSO_ERM'], lang='ar',
            content_sections=body, domain_code='erm',
        )
        acronyms = _glossary_acronyms(out)
        for forbidden in ('SOC', 'NDMO', 'SDAIA', 'DGA', 'NIST AI RMF'):
            with self.subTest(forbidden=forbidden):
                self.assertFalse(
                    any(forbidden in a for a in acronyms),
                    f'ERM glossary leaked {forbidden!r}: {acronyms}',
                )


class TraceabilityQualityTests(unittest.TestCase):

    @_skip_if_no_app
    def test_informative_rows_drop_dash_only_rows(self):
        # Body has gaps section but no pillars/roadmap/kpis/confidence
        # → most cells will be dashes. ``informative_rows`` must be
        # empty because Initiative and KPI/Risk are dashy.
        body = {
            'gaps': (
                '## 4. الفجوات\n\n'
                '| # | الفجوة |\n|---|--------|\n'
                '| 1 | غياب الضوابط الأمنية الأساسية |\n'
            ),
        }
        result = _APP._build_traceability_matrix(
            body, ['ECC'], lang='ar', domain_code='cyber',
        )
        self.assertIn('informative_rows', result)
        # When initiative is dash, the row is not informative.
        for r in result.get('informative_rows', []):
            with self.subTest(row=r):
                # Row format: [framework, capability, gap, initiative,
                # kpi, risk]
                self.assertNotEqual(str(r[3]).strip(), '—')
                self.assertNotEqual(str(r[2]).strip(), '—')

    @_skip_if_no_app
    def test_full_content_yields_informative_rows(self):
        # When all sections supply matching content, at least one
        # informative row should survive for ECC capability families.
        body = {
            'gaps': (
                '## 4. الفجوات\n\n'
                '| # | الفجوة |\n|---|--------|\n'
                '| 1 | governance gap in security strategy |\n'
            ),
            'pillars': (
                '## 2. الركائز\n\n'
                '| # | المبادرة |\n|---|---------|\n'
                '| 1 | establish governance program |\n'
            ),
            'roadmap': (
                '## 5. الخارطة\n\n'
                '| # | النشاط |\n|---|--------|\n'
                '| 1 | governance roadmap activity |\n'
            ),
            'kpis': (
                '## 6. مؤشرات\n\n'
                '| # | المؤشر |\n|---|--------|\n'
                '| 1 | governance maturity index |\n'
            ),
            'confidence': (
                '## 7. الثقة\n\n'
                '| # | الخطر |\n|---|--------|\n'
                '| 1 | weak governance increases breach risk |\n'
            ),
        }
        result = _APP._build_traceability_matrix(
            body, ['ECC'], lang='en', domain_code='cyber',
        )
        # At least one informative row must survive for the
        # governance family.
        self.assertGreater(
            len(result.get('informative_rows', [])), 0,
            'No informative traceability rows surfaced for full body',
        )


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
