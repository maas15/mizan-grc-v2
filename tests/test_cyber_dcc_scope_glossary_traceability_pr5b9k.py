"""PR-5B.9K — Cyber DCC vs TCC framework leakage isolation.

Cyber strategies generated with selected_frameworks=ECC+DCC must:

  * Have Appendix B include ECC and DCC and exclude TCC/VPN/ZTNA
    (unless TCC is also selected or literally present in the body).
  * Have the traceability matrix include rows for every DCC capability
    family (data classification, encryption, DLP, data protection,
    sensitive data handling).
  * NOT auto-inject TCC/VPN/ZTNA terminology when TCC is not selected.

Cyber strategies generated with selected_frameworks=ECC+TCC must
preserve the previous behaviour (TCC/VPN/ZTNA in Appendix B; no DCC
auto-injection unless DCC is selected or literally present).

Traceability rows whose Initiative / KPI / Risk columns contain a
dash MUST NOT be rendered into the exported model — the dash-row
suppression applies to PDF and DOCX builders.

Run:
    python -m pytest tests/test_cyber_dcc_scope_glossary_traceability_pr5b9k.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_dcc_pr5b9k_')
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


# Minimal cyber strategy body that does NOT mention TCC/VPN/ZTNA
# anywhere — so any TCC/VPN/ZTNA glossary entry that appears must
# come from baseline auto-injection (which the supplement now blocks
# unless TCC is selected).
_CYBER_BODY_AR = (
    '## 1. الرؤية\n\nرؤية أمن سيبراني.\n\n'
    '## 2. الركائز الاستراتيجية\n\n'
    '### الركيزة 1: حوكمة الأمن السيبراني\n\nنص.\n\n'
    '## 3. البيئة\n\nبيئة. ECC. DCC. تصنيف البيانات. تشفير. DLP.\n\n'
    '## 4. الفجوات\n\nفجوات.\n\n'
    '## 5. خارطة الطريق\n\nخارطة.\n\n'
    '## 6. مؤشرات الأداء\n\nمؤشرات.\n\n'
    '## 7. الثقة والمخاطر\n\nثقة.\n'
)

_CYBER_SECTIONS = {
    'vision': '## 1. الرؤية\n\nرؤية.\n',
    'pillars': '## 2. الركائز\n\n### الركيزة 1\n\nنص.\n',
    'environment': ('## 3. البيئة\n\nECC. DCC. تصنيف البيانات. تشفير. '
                    'DLP. حماية البيانات.\n'),
    'gaps': '## 4. الفجوات\n\n',
    'roadmap': '## 5. خارطة\n\n',
    'kpis': '## 6. مؤشرات\n\n',
    'confidence': '## 7. الثقة\n\n',
}


class GlossaryDCCTests(unittest.TestCase):
    """Appendix-B glossary scope under different selected-framework
    combinations."""

    @_skip_if_no_app
    def test_dcc_glossary_term_registered(self):
        """A registered ``DCC`` glossary entry exists so it can surface
        in Appendix B when DCC is selected."""
        terms = _APP._GLOSSARY_TERMS
        keys = [t[0] for t in terms]
        self.assertIn('DCC', keys,
                      'Expected DCC glossary entry in _GLOSSARY_TERMS')

    @_skip_if_no_app
    def test_ecc_dcc_glossary_excludes_tcc_vpn_ztna(self):
        """ECC+DCC glossary (English) must NOT auto-inject TCC/VPN/
        ZTNA terms."""
        body = {**_CYBER_SECTIONS,
                'environment': ('## 3. Environment\n\nECC. DCC. data '
                                'classification. encryption. DLP.\n')}
        appendices = _APP._build_appendices_block(
            ['ECC', 'DCC'], 'en',
            content_sections=body,
            domain_code='cyber',
        )
        glossary_blob = ''
        for entry in (appendices or []):
            try:
                glossary_blob += '\n' + (entry[1] or '')
            except Exception:
                pass
        # Sanity: ECC and DCC are present (acronym or expansion).
        self.assertIn('Essential Cybersecurity', glossary_blob,
                      'ECC missing from ECC+DCC glossary')
        self.assertIn('Data Cybersecurity', glossary_blob,
                      'DCC missing from ECC+DCC glossary')
        # TCC/VPN/ZTNA expansions must NOT auto-inject.
        for forbidden in ('Telework Cybersecurity',
                          'Virtual Private Network',
                          'Zero-Trust Network Access'):
            self.assertNotIn(
                forbidden, glossary_blob,
                f'ECC+DCC glossary unexpectedly contains {forbidden!r}: '
                f'{glossary_blob!r}')

    @_skip_if_no_app
    def test_ecc_tcc_glossary_includes_tcc_vpn_ztna(self):
        """ECC+TCC (English glossary) must include TCC/VPN/ZTNA per
        the per-framework supplement (regression guard)."""
        # Body without DCC, so DCC must NOT auto-inject either.
        body = {**_CYBER_SECTIONS,
                'environment': ('## 3. Environment\n\nECC. TCC. VPN. '
                                'ZTNA. telework.\n')}
        appendices = _APP._build_appendices_block(
            ['ECC', 'TCC'], 'en',
            content_sections=body,
            domain_code='cyber',
        )
        glossary_blob = ''
        for entry in (appendices or []):
            try:
                glossary_blob += '\n' + (entry[1] or '')
            except Exception:
                pass
        for required in ('TCC',
                         'Virtual Private Network',
                         'Zero-Trust Network Access'):
            self.assertIn(
                required, glossary_blob,
                f'ECC+TCC glossary missing {required!r}: '
                f'{glossary_blob!r}')
        # DCC must NOT auto-inject (not selected; not literally present).
        self.assertNotIn(
            'Data Cybersecurity', glossary_blob,
            f'ECC+TCC glossary unexpectedly contains DCC: '
            f'{glossary_blob!r}')


class TraceabilityDCCTests(unittest.TestCase):
    """Traceability matrix must produce DCC rows when DCC is selected."""

    @_skip_if_no_app
    def test_ecc_dcc_traceability_includes_dcc_rows(self):
        # Build content that names DCC capability families so the
        # row's Gap/Initiative cells are not all dashes.
        sections = {
            'vision': '## 1. الرؤية\n\nرؤية.\n',
            'pillars': (
                '## 2. الركائز\n\n'
                '### الركيزة 1: حوكمة الأمن السيبراني\n\n'
                '| # | المبادرة | الوصف | المخرج |\n'
                '|---|------|------|------|\n'
                '| 1 | تطبيق تصنيف البيانات | تصنيف | تقرير |\n'
                '| 2 | نشر التشفير | تشفير | تقرير |\n'
                '| 3 | منع تسرب البيانات (DLP) | DLP | تقرير |\n'
            ),
            'environment': (
                '## 3. البيئة\n\nبيئة تتطلب تصنيف البيانات وتشفير '
                'والحماية من تسرب البيانات.\n'),
            'gaps': (
                '## 4. الفجوات\n\n'
                '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
                '|---|------|------|------|------|\n'
                '| 1 | غياب تصنيف البيانات | عام | عالية | مفتوحة |\n'
                '| 2 | غياب التشفير | عام | عالية | مفتوحة |\n'
                '| 3 | غياب DLP | عام | عالية | مفتوحة |\n'
            ),
            'roadmap': '## 5. خارطة\n\n',
            'kpis': (
                '## 6. مؤشرات\n\n'
                '| # | المؤشر | النوع | المستهدفة | الصيغة | المصدر | المالك | التكرار | الإطار |\n'
                '|---|------|------|------|------|------|------|------|------|\n'
                '| 1 | نسبة تصنيف البيانات | KPI | 100% | x | عام | الإدارة | شهري | 12ش |\n'
                '| 2 | نسبة التشفير | KPI | 100% | x | عام | الإدارة | شهري | 12ش |\n'
                '| 3 | حوادث DLP | KRI | 0 | x | عام | الإدارة | شهري | 12ش |\n'
            ),
            'confidence': (
                '## 7. الثقة\n\n'
                '| # | الخطر | الاحتمالية | التأثير | التخفيف |\n'
                '|---|------|------|------|------|\n'
                '| 1 | تسرب البيانات بسبب نقص التشفير | عالية | عالي | متابعة |\n'
                '| 2 | فشل تصنيف البيانات | عالية | عالي | متابعة |\n'
                '| 3 | فشل DLP | عالية | عالي | متابعة |\n'
            ),
        }
        trace = _APP._build_traceability_matrix(
            sections, ['ECC', 'DCC'], 'ar', domain_code='cyber',
        )
        rows = trace.get('rows') or []
        self.assertTrue(len(rows) > 0,
                        'expected non-empty traceability rows')
        # At least ONE row must come from DCC (Framework column == DCC
        # display).
        dcc_rows = [r for r in rows
                    if r and 'DCC' in str(r[0])]
        self.assertTrue(
            len(dcc_rows) > 0,
            f'expected DCC traceability rows for ECC+DCC, got '
            f'frameworks={[r[0] for r in rows]}')


class TraceabilityDashRowSuppressionTests(unittest.TestCase):
    """Rows with a dash in Initiative / KPI / Risk must not survive
    the model's dash-row suppression."""

    @_skip_if_no_app
    def test_traceability_returns_only_informative_rows_view(self):
        # Build content with DCC selected, but pillars/roadmap/etc.
        # do NOT mention any DCC keyword. The matrix produces a DCC
        # row whose Gap/Initiative/KPI/Risk are all dashes.  The
        # ``informative_rows`` view of the matrix must EXCLUDE that
        # row (the renderer further drops any row with a dash in
        # initiative/kpi/risk per PR-5B.9K).
        sections = {
            'vision': '## 1. الرؤية\n\n',
            'pillars': '## 2. الركائز\n\n### الركيزة 1\n\n',
            'environment': '## 3. البيئة\n\nنص عام.\n',
            'gaps': '## 4. الفجوات\n\n',
            'roadmap': '## 5. خارطة\n\n',
            'kpis': '## 6. مؤشرات\n\n',
            'confidence': '## 7. الثقة\n\n',
        }
        trace = _APP._build_traceability_matrix(
            sections, ['DCC'], 'ar', domain_code='cyber',
        )
        info = trace.get('informative_rows') or []
        # No row can be informative because every cell is a dash.
        for r in info:
            for c in (r[2], r[3], r[4], r[5]):
                self.assertNotIn(
                    str(c).strip(), ('—', '-', '--', '–', ''),
                    f'informative_rows contains dash cell: {r!r}')


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
