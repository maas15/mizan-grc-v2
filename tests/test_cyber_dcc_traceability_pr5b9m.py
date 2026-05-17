"""PR-5B.9M — Cyber ECC+DCC traceability quality.

Production symptom: Cyber Security strategies generated with
``selected_frameworks=['ECC','DCC']`` had Appendix B correctly showing
DCC and excluding TCC/VPN/ZTNA (PR-5B.9K), but the traceability matrix
"mostly maps ECC and does not provide meaningful DCC rows" — the DCC
keyword list in ``_FRAMEWORK_COVERAGE_REQUIREMENTS`` was too narrow, so
AI bodies using natural synonyms produced all-dash DCC rows that were
dropped by the dash-row suppression.

PR-5B.9M widens DCC capability families to:
  data_classification, encryption, dlp, sensitive_data_handling,
  data_protection — covering the spec's required concepts (classification,
  encryption, DLP, sensitive data handling, data protection).

Tests:
  1. ECC+DCC selected → traceability includes at least 3 meaningful
     (informative) DCC rows.
  2. DCC traceability includes classification / encryption / DLP / data
     protection / sensitive-data concepts.
  3. ECC+DCC selected → appendix includes DCC (regression guard).
  4. ECC+DCC selected → appendix excludes TCC/VPN/ZTNA unless selected.
  5. ECC+TCC selected → TCC rows still work (regression guard).
  6. No traceability rows surface with '—' / dash through the
     informative_rows view.

Run:
    python -m pytest tests/test_cyber_dcc_traceability_pr5b9m.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_dcc_pr5b9m_')
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


# Cyber strategy with rich DCC content in gaps/pillars/kpis/risks so
# the broader DCC keyword list produces meaningful informative rows.
_RICH_CYBER_DCC_SECTIONS_AR = {
    'vision': '## 1. الرؤية\n\nرؤية أمن سيبراني.\n',
    'pillars': (
        '## 2. الركائز\n\n'
        '### الركيزة 1: حوكمة الأمن السيبراني والبيانات\n\n'
        '| # | المبادرة | الوصف | المخرج |\n'
        '|---|------|------|------|\n'
        '| 1 | تطبيق تصنيف البيانات الحساسة وفق DCC | تصنيف '
        'وحماية البيانات | تقرير |\n'
        '| 2 | نشر التشفير عند التخزين وعند النقل | تشفير '
        'البيانات | تقرير |\n'
        '| 3 | تطبيق ضوابط منع تسرب البيانات (DLP) | DLP | '
        'تقرير |\n'
        '| 4 | اعتماد ضوابط حماية البيانات للبيانات الحساسة '
        '| ضوابط أمن البيانات | تقرير |\n'
    ),
    'environment': (
        '## 3. البيئة\n\nتتطلب البيئة تصنيف البيانات وتشفير '
        'الاتصالات والحماية من تسرب البيانات وحماية البيانات '
        'الحساسة وفق DCC.\n'),
    'gaps': (
        '## 4. الفجوات\n\n'
        '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
        '|---|------|------|------|------|\n'
        '| 1 | غياب تصنيف البيانات | تصنيف | عالية | مفتوحة |\n'
        '| 2 | غياب التشفير عند التخزين | تشفير البيانات | عالية | '
        'مفتوحة |\n'
        '| 3 | غياب منع تسرب البيانات (DLP) | DLP | عالية | '
        'مفتوحة |\n'
        '| 4 | غياب إجراءات معالجة البيانات الحساسة | تداول '
        'البيانات | عالية | مفتوحة |\n'
        '| 5 | غياب ضوابط حماية البيانات الموحدة | حماية '
        'البيانات | عالية | مفتوحة |\n'
    ),
    'roadmap': (
        '## 5. خارطة الطريق\n\n'
        '| # | النشاط | المرحلة | الإطار |\n'
        '|---|------|------|------|\n'
        '| 1 | تطبيق تصنيف البيانات | Q1 | 12ش |\n'
        '| 2 | نشر التشفير | Q2 | 12ش |\n'
        '| 3 | تشغيل ضوابط DLP | Q2 | 12ش |\n'
    ),
    'kpis': (
        '## 6. مؤشرات\n\n'
        '| # | المؤشر | النوع | المستهدفة | الصيغة | المصدر | '
        'المالك | التكرار | الإطار |\n'
        '|---|------|------|------|------|------|------|------|------|\n'
        '| 1 | نسبة تصنيف البيانات | KPI | 100% | x | عام | '
        'الإدارة | شهري | 12ش |\n'
        '| 2 | نسبة التشفير | KPI | 100% | x | عام | الإدارة | '
        'شهري | 12ش |\n'
        '| 3 | حوادث تسرب البيانات (DLP) | KRI | 0 | x | عام | '
        'الإدارة | شهري | 12ش |\n'
        '| 4 | حالة معالجة البيانات الحساسة | KPI | 100% | x | '
        'عام | الإدارة | شهري | 12ش |\n'
        '| 5 | نضج ضوابط حماية البيانات | KPI | 100% | x | عام | '
        'الإدارة | شهري | 12ش |\n'
    ),
    'confidence': (
        '## 7. الثقة\n\n'
        '| # | الخطر | الاحتمالية | التأثير | التخفيف |\n'
        '|---|------|------|------|------|\n'
        '| 1 | تسرب البيانات بسبب نقص التشفير | عالية | عالي | '
        'متابعة |\n'
        '| 2 | فشل تصنيف البيانات | عالية | عالي | متابعة |\n'
        '| 3 | فشل DLP | عالية | عالي | متابعة |\n'
        '| 4 | كشف البيانات الحساسة | عالية | عالي | متابعة |\n'
    ),
}


class DCCTraceabilityMeaningfulRowsTests(unittest.TestCase):
    """ECC+DCC must produce meaningful DCC traceability rows."""

    @_skip_if_no_app
    def test_dcc_capability_families_widened(self):
        spec = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS.get('DCC')
        self.assertIsNotNone(spec, 'DCC must be in coverage registry')
        family_ids = [c[0] for c in spec.get('capabilities', [])]
        # PR-5B.9M required families.
        for required in ('data_classification', 'encryption', 'dlp',
                         'sensitive_data_handling', 'data_protection'):
            self.assertIn(
                required, family_ids,
                f'DCC capability family {required!r} missing; '
                f'have {family_ids!r}')

    @_skip_if_no_app
    def test_ecc_dcc_traceability_has_at_least_three_dcc_rows(self):
        trace = _APP._build_traceability_matrix(
            _RICH_CYBER_DCC_SECTIONS_AR, ['ECC', 'DCC'], 'ar',
            domain_code='cyber',
        )
        rows = trace.get('rows') or []
        dcc_rows = [r for r in rows
                    if r and 'DCC' in str(r[0])]
        self.assertGreaterEqual(
            len(dcc_rows), 3,
            f'expected >=3 DCC traceability rows, got {len(dcc_rows)}: '
            f'frameworks={[r[0] for r in rows]}')

    @_skip_if_no_app
    def test_dcc_rows_cover_required_concepts(self):
        trace = _APP._build_traceability_matrix(
            _RICH_CYBER_DCC_SECTIONS_AR, ['ECC', 'DCC'], 'ar',
            domain_code='cyber',
        )
        info_rows = trace.get('informative_rows') or []
        dcc_info = [r for r in info_rows if r and 'DCC' in str(r[0])]
        # The capability column (index 1) must collectively cover the
        # spec concepts: classification, encryption, DLP, data
        # protection, sensitive data.
        blob = ' '.join(str(r[1]) for r in dcc_info).lower()
        for concept in ('تصنيف', 'تشفير', 'dlp', 'حماية',
                        'البيانات الحساسة'):
            self.assertIn(
                concept.lower(), blob,
                f'DCC capability concept {concept!r} missing from '
                f'informative rows; blob={blob!r}')

    @_skip_if_no_app
    def test_dcc_informative_rows_no_dash(self):
        trace = _APP._build_traceability_matrix(
            _RICH_CYBER_DCC_SECTIONS_AR, ['ECC', 'DCC'], 'ar',
            domain_code='cyber',
        )
        info = trace.get('informative_rows') or []
        dcc_info = [r for r in info if r and 'DCC' in str(r[0])]
        self.assertTrue(len(dcc_info) >= 3,
                        f'expected >=3 informative DCC rows, '
                        f'got {len(dcc_info)}')
        for r in dcc_info:
            # Gap and Initiative must not be dashes.
            for cell in (r[2], r[3]):
                self.assertNotIn(
                    str(cell).strip(), ('—', '-', '--', '–', ''),
                    f'informative row must not contain dash; got {r!r}')


class DCCAppendixTests(unittest.TestCase):
    """Regression guards from PR-5B.9K — appendix scope must remain."""

    @_skip_if_no_app
    def test_ecc_dcc_glossary_includes_dcc_excludes_tcc(self):
        body = {
            'vision': '## 1. Vision\n\nText.\n',
            'pillars': '## 2. Pillars\n\n### 1\nText.\n',
            'environment': ('## 3. Environment\n\nECC. DCC. data '
                            'classification. encryption. DLP.\n'),
            'gaps': '## 4. Gaps\n\n',
            'roadmap': '## 5. Roadmap\n\n',
            'kpis': '## 6. KPIs\n\n',
            'confidence': '## 7. Confidence\n\n',
        }
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
        self.assertIn('Data Cybersecurity', glossary_blob)
        for forbidden in ('Telework Cybersecurity',
                          'Virtual Private Network',
                          'Zero-Trust Network Access'):
            self.assertNotIn(forbidden, glossary_blob)

    @_skip_if_no_app
    def test_ecc_tcc_glossary_includes_tcc_excludes_dcc(self):
        body = {
            'vision': '## 1. Vision\n\nText.\n',
            'pillars': '## 2. Pillars\n\n### 1\nText.\n',
            'environment': ('## 3. Environment\n\nECC. TCC. VPN. '
                            'ZTNA. telework.\n'),
            'gaps': '## 4. Gaps\n\n',
            'roadmap': '## 5. Roadmap\n\n',
            'kpis': '## 6. KPIs\n\n',
            'confidence': '## 7. Confidence\n\n',
        }
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
        for required in ('Virtual Private Network',
                         'Zero-Trust Network Access'):
            self.assertIn(required, glossary_blob)
        # DCC must NOT auto-inject.
        self.assertNotIn('Data Cybersecurity', glossary_blob)


class TCCRegressionTests(unittest.TestCase):
    """ECC+TCC must still produce TCC traceability rows."""

    @_skip_if_no_app
    def test_ecc_tcc_traceability_has_tcc_rows(self):
        sections = {
            'vision': '## 1. الرؤية\n\n',
            'pillars': (
                '## 2. الركائز\n\n'
                '### الركيزة 1\n\n'
                '| # | المبادرة | الوصف | المخرج |\n'
                '|---|---|---|---|\n'
                '| 1 | تطبيق MFA للوصول عن بُعد | telework MFA | تقرير |\n'
                '| 2 | نشر VPN | VPN | تقرير |\n'
            ),
            'environment': '## 3. البيئة\n\nVPN. MFA. telework. ZTNA.\n',
            'gaps': (
                '## 4. الفجوات\n\n'
                '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
                '|---|---|---|---|---|\n'
                '| 1 | غياب VPN | remote work | عالية | مفتوحة |\n'
                '| 2 | غياب MFA | multi-factor | عالية | مفتوحة |\n'
            ),
            'roadmap': '## 5. خارطة\n\n',
            'kpis': (
                '## 6. مؤشرات\n\n'
                '| # | المؤشر | النوع | المستهدفة | الصيغة | '
                'المصدر | المالك | التكرار | الإطار |\n'
                '|---|---|---|---|---|---|---|---|---|\n'
                '| 1 | نسبة MFA | KPI | 100% | x | عام | '
                'الإدارة | شهري | 12ش |\n'
            ),
            'confidence': (
                '## 7. الثقة\n\n'
                '| # | الخطر | الاحتمالية | التأثير | التخفيف |\n'
                '|---|---|---|---|---|\n'
                '| 1 | اختراق الوصول عن بعد | عالية | عالي | متابعة |\n'
            ),
        }
        trace = _APP._build_traceability_matrix(
            sections, ['ECC', 'TCC'], 'ar', domain_code='cyber',
        )
        rows = trace.get('rows') or []
        tcc_rows = [r for r in rows if r and 'TCC' in str(r[0])]
        self.assertTrue(
            len(tcc_rows) > 0,
            f'expected TCC traceability rows for ECC+TCC, got '
            f'frameworks={[r[0] for r in rows]}')


class DashRowSuppressionTests(unittest.TestCase):
    """A row in ``informative_rows`` must have real Gap and real
    Initiative (PR-5B.9K guarantee, preserved). KPI / Risk may still
    be ``—`` provided the other is real.
    """

    @_skip_if_no_app
    def test_informative_rows_have_real_gap_and_initiative(self):
        trace = _APP._build_traceability_matrix(
            _RICH_CYBER_DCC_SECTIONS_AR, ['ECC', 'DCC'], 'ar',
            domain_code='cyber',
        )
        info = trace.get('informative_rows') or []
        self.assertTrue(len(info) > 0)
        for r in info:
            self.assertNotIn(str(r[2]).strip(), ('—', '-', '--', '–', ''))
            self.assertNotIn(str(r[3]).strip(), ('—', '-', '--', '–', ''))


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
