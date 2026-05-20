"""PR-CY4 — Cyber DCC traceability rendering in strategy output.

Production symptom: Cyber Security strategies generated with
``selected_frameworks=['ECC','DCC']`` correctly include DCC in scope,
vision, roadmap, KPIs and glossary — but the rendered PDF traceability
matrix Part A and Part B show ECC rows only.  Root cause: in the Cyber
``_build_traceability_matrix`` branch, DCC families used the simple
per-section ``_find_match`` lookup so the AI's natural phrasings
(``تنفيذ ضوابط تصنيف البيانات ومعالجة البيانات الحساسة``,
``نسبة تصنيف البيانات الحساسة``, ``اختراق البيانات أو سوء تصنيف
البيانات الحساسة`` etc.) left at least one of (gap / init / kpi / risk)
as a dash.  The universal no-dash gate in ``_pro_render_traceability``
then dropped every DCC row at PDF render time.

PR-CY4 mirrors the Data-scope (PDPL/NDMO) approach for (cyber, DCC):
  * augment per-family keywords with the synonyms commonly produced by
    the AI in production
    (``_TRACEABILITY_DCC_FAMILY_KEYWORD_AUGMENT``),
  * fall back across multiple sections so each row cell can be sourced
    from the section that actually contains it,
  * apply a deterministic, capability-derived soft KPI / Risk descriptor
    (``_CYBER_TRACEABILITY_SOFT_KPI_RISK``) ONLY when gap+initiative
    were already resolved from real generated content but the KPI or
    Risk lookup found no distinct phrase.

Scope is strictly (domain=cyber, framework=DCC):
  * ECC / TCC / CSCC rows keep their existing per-section ``_find_match``
    behaviour byte-for-byte;
  * Data Management (NDMO/PDPL) traceability is unchanged;
  * AI / Digital Transformation / ERM traceability is unchanged;
  * no strategy rows are inserted — only the metric / risk axis labels
    are filled for traceability rows whose capability is already covered
    by real generated content;
  * validators, scope, glossary, repair passes, auth / DB / export
    routes are untouched.

Run:
    python -m pytest tests/test_cyber_dcc_traceability_rendering_prcy4.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_dcc_prcy4_')
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


_DASH_TOKENS = ('—', '-', '--', '–')


# Realistic Cyber + ECC + DCC sections matching the production PDF
# evidence described in the PR-CY4 problem statement.  Initiatives,
# KPIs and risks use the exact AR phrasings the user observed in the
# generated PDF (e.g. ``تنفيذ ضوابط تصنيف البيانات ومعالجة البيانات
# الحساسة``).  ECC content is kept rich so the regression check has
# data to validate against.
_SECTIONS_AR_ECC_DCC = {
    'vision': (
        '## 1. الرؤية\n\n'
        'الالتزام بمتطلبات NCA ECC و NCA DCC لضمان حماية البيانات.\n'
    ),
    'pillars': (
        '## 2. الركائز\n\n'
        '### الركيزة 1: حوكمة الأمن السيبراني\n\n'
        '| # | المبادرة | الوصف | المخرج |\n'
        '|---|---|---|---|\n'
        '| 1 | تأسيس حوكمة الأمن السيبراني وفق ECC | حوكمة | تقرير |\n'
        '| 2 | تنفيذ ضوابط تصنيف البيانات ومعالجة البيانات الحساسة '
        '| DCC تصنيف | تقرير |\n'
        '| 3 | تطبيق ضوابط التشفير ومنع فقدان البيانات DLP | DCC | '
        'تقرير |\n'
        '| 4 | حماية البيانات الحساسة أثناء النقل والتخزين | DCC | '
        'تقرير |\n'
    ),
    'environment': (
        '## 3. البيئة\n\nالبيئة تتطلب الامتثال لمتطلبات ECC و DCC '
        'وتغطي تصنيف البيانات والتشفير ومنع تسرب البيانات.\n'
    ),
    'gaps': (
        '## 4. الفجوات\n\n'
        '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
        '|---|---|---|---|---|\n'
        '| 1 | غياب حوكمة الأمن السيبراني | ECC | عالية | مفتوحة |\n'
        '| 2 | غياب تصنيف البيانات الحساسة | DCC تصنيف | عالية | '
        'مفتوحة |\n'
        '| 3 | ضعف التشفير عند النقل والتخزين | DCC تشفير | عالية | '
        'مفتوحة |\n'
        '| 4 | غياب ضوابط منع فقدان البيانات DLP | DCC | عالية | '
        'مفتوحة |\n'
        '| 5 | ضعف معالجة البيانات الحساسة | DCC | عالية | مفتوحة |\n'
        '| 6 | ضعف حماية البيانات | DCC | عالية | مفتوحة |\n'
    ),
    'roadmap': (
        '## 5. خارطة الطريق\n\n'
        '| # | النشاط | المرحلة | الإطار |\n'
        '|---|---|---|---|\n'
        '| 1 | تأسيس حوكمة الأمن السيبراني وفق ECC | Q1 | ECC |\n'
        '| 2 | تنفيذ ضوابط تصنيف البيانات ومعالجة البيانات الحساسة '
        '| Q1 | DCC |\n'
        '| 3 | تطبيق ضوابط التشفير ومنع فقدان البيانات DLP | Q2 | '
        'DCC |\n'
        '| 4 | معالجة البيانات الحساسة وفق الضوابط | Q2 | DCC |\n'
        '| 5 | حماية البيانات الحساسة أثناء النقل والتخزين | Q3 | '
        'DCC |\n'
    ),
    'kpis': (
        '## 6. مؤشرات الأداء\n\n'
        '| # | المؤشر | النوع | المستهدفة | الصيغة | المصدر | '
        'المالك | التكرار | الإطار |\n'
        '|---|---|---|---|---|---|---|---|---|\n'
        '| 1 | نضج حوكمة الأمن السيبراني | KPI | عالي | x | عام | '
        'الإدارة | شهري | ECC |\n'
        '| 2 | نسبة تصنيف البيانات الحساسة | KPI | 100% | x | عام | '
        'الإدارة | شهري | DCC |\n'
        '| 3 | نسبة الامتثال لسياسات التشفير | KPI | 100% | x | عام | '
        'الإدارة | شهري | DCC |\n'
    ),
    'confidence': (
        '## 7. الثقة والمخاطر\n\n'
        '| # | الخطر | الاحتمالية | التأثير | التخفيف |\n'
        '|---|---|---|---|---|\n'
        '| 1 | اختراق الأنظمة بسبب ضعف الحوكمة | عالية | عالي | متابعة |\n'
        '| 2 | اختراق البيانات أو سوء تصنيف البيانات الحساسة | عالية | '
        'عالي | متابعة |\n'
    ),
}


class CyberDCCTraceabilityPartATests(unittest.TestCase):
    """Part A — Framework → Capability → Gap must include DCC rows
    covering classification, encryption, DLP, sensitive-data handling
    and data protection.
    """

    def _trace(self):
        return _APP._build_traceability_matrix(
            _SECTIONS_AR_ECC_DCC, ['ECC', 'DCC'], 'ar',
            domain_code='cyber',
        )

    def _render_rows(self, trace):
        """Mirror ``_pro_render_traceability``'s no-dash gate so we
        validate what the PDF will actually render, not just the
        model rows.
        """
        rows = trace.get('rows') or []
        filtered = []
        for r in rows:
            if len(r) < 6:
                continue
            if any(str(c).strip() in _DASH_TOKENS or
                   not str(c).strip()
                   for c in (r[2], r[3], r[4], r[5])):
                continue
            filtered.append(r)
        return filtered

    def _dcc_rendered(self):
        return [r for r in self._render_rows(self._trace())
                if r and 'DCC' in str(r[0])]

    @_skip_if_no_app
    def test_part_a_has_data_classification(self):
        rows = self._dcc_rendered()
        blob = ' '.join(str(r[1]) for r in rows)
        self.assertIn('تصنيف', blob,
                      f'Part A missing data classification capability; '
                      f'rendered={[r[1] for r in rows]}')

    @_skip_if_no_app
    def test_part_a_has_encryption(self):
        rows = self._dcc_rendered()
        blob = ' '.join(str(r[1]) for r in rows)
        self.assertIn('تشفير', blob,
                      f'Part A missing encryption capability; '
                      f'rendered={[r[1] for r in rows]}')

    @_skip_if_no_app
    def test_part_a_has_dlp(self):
        rows = self._dcc_rendered()
        blob = ' '.join(str(r[1]) for r in rows).lower()
        self.assertIn('dlp', blob,
                      f'Part A missing DLP capability; '
                      f'rendered={[r[1] for r in rows]}')

    @_skip_if_no_app
    def test_part_a_has_sensitive_data_handling(self):
        rows = self._dcc_rendered()
        blob = ' '.join(str(r[1]) for r in rows)
        self.assertIn('البيانات الحساسة', blob,
                      f'Part A missing sensitive-data handling capability; '
                      f'rendered={[r[1] for r in rows]}')

    @_skip_if_no_app
    def test_part_a_has_data_protection(self):
        rows = self._dcc_rendered()
        blob = ' '.join(str(r[1]) for r in rows)
        self.assertIn('حماية البيانات', blob,
                      f'Part A missing data-protection capability; '
                      f'rendered={[r[1] for r in rows]}')


class CyberDCCTraceabilityPartBTests(unittest.TestCase):
    """Part B — Framework → Initiative → KPI → Risk must include
    complete DCC rows with distinct cells (no dash placeholders, no
    duplicated phrase across init / KPI / risk).
    """

    def _dcc_rendered(self):
        trace = _APP._build_traceability_matrix(
            _SECTIONS_AR_ECC_DCC, ['ECC', 'DCC'], 'ar',
            domain_code='cyber',
        )
        out = []
        for r in (trace.get('rows') or []):
            if len(r) < 6:
                continue
            if any(str(c).strip() in _DASH_TOKENS or
                   not str(c).strip()
                   for c in (r[2], r[3], r[4], r[5])):
                continue
            if 'DCC' in str(r[0]):
                out.append(r)
        return out

    def _find_dcc_row_by_capability(self, keyword):
        for r in self._dcc_rendered():
            if keyword.lower() in str(r[1]).lower():
                return r
        return None

    @_skip_if_no_app
    def test_part_b_classification_row_complete(self):
        r = self._find_dcc_row_by_capability('تصنيف')
        self.assertIsNotNone(r, 'DCC classification row missing from Part B')
        self.assertIn('DCC', str(r[0]))
        # initiative / kpi / risk must each carry real content
        self.assertTrue(str(r[3]).strip())
        self.assertTrue(str(r[4]).strip())
        self.assertTrue(str(r[5]).strip())

    @_skip_if_no_app
    def test_part_b_encryption_row_complete(self):
        r = self._find_dcc_row_by_capability('تشفير')
        self.assertIsNotNone(r, 'DCC encryption row missing from Part B')
        self.assertIn('DCC', str(r[0]))
        self.assertTrue(str(r[3]).strip())
        self.assertTrue(str(r[4]).strip())
        self.assertTrue(str(r[5]).strip())

    @_skip_if_no_app
    def test_part_b_dlp_row_complete(self):
        r = self._find_dcc_row_by_capability('DLP')
        self.assertIsNotNone(r, 'DCC DLP row missing from Part B')
        self.assertIn('DCC', str(r[0]))
        self.assertTrue(str(r[3]).strip())
        self.assertTrue(str(r[4]).strip())
        self.assertTrue(str(r[5]).strip())

    @_skip_if_no_app
    def test_part_b_sensitive_data_row_complete(self):
        r = self._find_dcc_row_by_capability('معالجة البيانات الحساسة')
        self.assertIsNotNone(
            r, 'DCC sensitive-data-handling row missing from Part B')
        self.assertIn('DCC', str(r[0]))
        self.assertTrue(str(r[3]).strip())
        self.assertTrue(str(r[4]).strip())
        self.assertTrue(str(r[5]).strip())

    @_skip_if_no_app
    def test_part_b_data_protection_row_complete(self):
        r = self._find_dcc_row_by_capability('حماية البيانات')
        self.assertIsNotNone(
            r, 'DCC data-protection row missing from Part B')
        self.assertIn('DCC', str(r[0]))
        self.assertTrue(str(r[3]).strip())
        self.assertTrue(str(r[4]).strip())
        self.assertTrue(str(r[5]).strip())


class CyberDCCTraceabilityHygieneTests(unittest.TestCase):
    """No DCC row may contain a dash placeholder once rendered."""

    @_skip_if_no_app
    def test_no_dcc_row_contains_dash(self):
        trace = _APP._build_traceability_matrix(
            _SECTIONS_AR_ECC_DCC, ['ECC', 'DCC'], 'ar',
            domain_code='cyber',
        )
        # Apply the same render-time no-dash gate as the PDF renderer.
        for r in (trace.get('rows') or []):
            if 'DCC' not in str(r[0]):
                continue
            if len(r) < 6:
                continue
            # rendered rows = those with no dash in gap/init/kpi/risk
            cells = (r[2], r[3], r[4], r[5])
            if all(str(c).strip() and str(c).strip() not in _DASH_TOKENS
                   for c in cells):
                # rendered row — no cell may be a dash
                for c in r:
                    self.assertNotIn(
                        str(c).strip(), _DASH_TOKENS,
                        f'DCC rendered row contains dash: {r!r}')


class CyberECCRegressionTests(unittest.TestCase):
    """ECC traceability must remain unchanged by PR-CY4."""

    @_skip_if_no_app
    def test_ecc_rows_still_present(self):
        trace = _APP._build_traceability_matrix(
            _SECTIONS_AR_ECC_DCC, ['ECC', 'DCC'], 'ar',
            domain_code='cyber',
        )
        rows = trace.get('rows') or []
        ecc_rows = [r for r in rows
                    if r and 'ECC' in str(r[0]) and 'DCC' not in str(r[0])]
        self.assertGreater(
            len(ecc_rows), 0,
            f'ECC rows must remain in matrix; got '
            f'frameworks={[r[0] for r in rows]}')

    @_skip_if_no_app
    def test_ecc_only_strategy_unchanged_when_no_dcc(self):
        # ECC-only selection must not exercise the DCC-only code path.
        sections = dict(_SECTIONS_AR_ECC_DCC)
        trace = _APP._build_traceability_matrix(
            sections, ['ECC'], 'ar', domain_code='cyber',
        )
        rows = trace.get('rows') or []
        # ECC capabilities only — no DCC rows
        for r in rows:
            self.assertNotIn(
                'DCC', str(r[0]),
                'ECC-only selection must not produce DCC rows')


class DataManagementUnchangedTests(unittest.TestCase):
    """Data Management (NDMO/PDPL) traceability must remain unchanged."""

    @_skip_if_no_app
    def test_data_pdpl_unchanged(self):
        # A minimal Data PDPL section bundle exercises the data-scope
        # branch and must not be diverted into the DCC branch.
        sections = {
            'vision': '## 1\n\n',
            'pillars': (
                '## 2\n\n'
                '| # | المبادرة | الوصف | المخرج |\n'
                '|---|---|---|---|\n'
                '| 1 | تأسيس حوكمة الخصوصية وفق PDPL | privacy | تقرير |\n'
            ),
            'environment': '## 3\n\nالامتثال لـ PDPL.\n',
            'gaps': (
                '## 4\n\n'
                '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
                '|---|---|---|---|---|\n'
                '| 1 | ضعف حوكمة الخصوصية | privacy governance | عالية | '
                'مفتوحة |\n'
            ),
            'roadmap': (
                '## 5\n\n'
                '| # | النشاط | المرحلة | الإطار |\n'
                '|---|---|---|---|\n'
                '| 1 | تنفيذ حوكمة الخصوصية وفق PDPL | Q1 | PDPL |\n'
            ),
            'kpis': (
                '## 6\n\n'
                '| # | المؤشر | النوع | المستهدفة | الصيغة | المصدر | '
                'المالك | التكرار | الإطار |\n'
                '|---|---|---|---|---|---|---|---|---|\n'
                '| 1 | نسبة الالتزام بحوكمة الخصوصية | KPI | 100% | x | '
                'عام | الإدارة | شهري | PDPL |\n'
            ),
            'confidence': (
                '## 7\n\n'
                '| # | الخطر | الاحتمالية | التأثير | التخفيف |\n'
                '|---|---|---|---|---|\n'
                '| 1 | مخاطر ضعف حوكمة الخصوصية | عالية | عالي | متابعة |\n'
            ),
        }
        # Data domain should NOT enter DCC branch.
        trace = _APP._build_traceability_matrix(
            sections, ['PDPL'], 'ar', domain_code='data',
        )
        rows = trace.get('rows') or []
        # PDPL family ids must still appear (privacy_governance) — no
        # DCC capabilities should be present (PDPL not DCC).
        framework_cells = {str(r[0]) for r in rows}
        for fw in framework_cells:
            self.assertNotIn(
                'NCA DCC', fw,
                'Data PDPL traceability must not include DCC rows')


class CrossDomainUnchangedTests(unittest.TestCase):
    """AI / DT / ERM traceability must remain unchanged."""

    @_skip_if_no_app
    def test_ai_domain_no_dcc_branch(self):
        # AI scope with no DCC selected must keep its existing behaviour
        # and must not raise.  A bare-minimum section bundle is enough.
        trace = _APP._build_traceability_matrix(
            {'gaps': '', 'roadmap': '', 'kpis': '', 'confidence': '',
             'pillars': '', 'environment': ''},
            [], 'en', domain_code='ai',
        )
        self.assertIsInstance(trace, dict)
        self.assertIn('rows', trace)

    @_skip_if_no_app
    def test_dt_domain_no_dcc_branch(self):
        trace = _APP._build_traceability_matrix(
            {'gaps': '', 'roadmap': '', 'kpis': '', 'confidence': '',
             'pillars': '', 'environment': ''},
            [], 'en', domain_code='digital_transformation',
        )
        self.assertIsInstance(trace, dict)
        self.assertIn('rows', trace)

    @_skip_if_no_app
    def test_erm_domain_no_dcc_branch(self):
        trace = _APP._build_traceability_matrix(
            {'gaps': '', 'roadmap': '', 'kpis': '', 'confidence': '',
             'pillars': '', 'environment': ''},
            [], 'en', domain_code='erm',
        )
        self.assertIsInstance(trace, dict)
        self.assertIn('rows', trace)


class NoDeterministicStrategyRowsTests(unittest.TestCase):
    """PR-CY4 may only fill the metric / risk axis when the row's
    gap AND initiative are already real content.  It must NOT
    fabricate a DCC row when the strategy does not mention a DCC
    capability at all.
    """

    @_skip_if_no_app
    def test_empty_dcc_content_produces_no_complete_rows(self):
        # Sections cover ECC but never mention any DCC capability.
        sections = {
            'vision': '## 1\n\n',
            'pillars': (
                '## 2\n\n'
                '| # | المبادرة | الوصف | المخرج |\n'
                '|---|---|---|---|\n'
                '| 1 | تأسيس حوكمة الأمن السيبراني | حوكمة | تقرير |\n'
            ),
            'environment': '## 3\n\nبيئة عامة بدون أي ذكر لمواضيع DCC.\n',
            'gaps': (
                '## 4\n\n'
                '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
                '|---|---|---|---|---|\n'
                '| 1 | غياب الحوكمة | حوكمة | عالية | مفتوحة |\n'
            ),
            'roadmap': (
                '## 5\n\n'
                '| # | النشاط | المرحلة | الإطار |\n'
                '|---|---|---|---|\n'
                '| 1 | تأسيس الحوكمة | Q1 | ECC |\n'
            ),
            'kpis': (
                '## 6\n\n'
                '| # | المؤشر | النوع | المستهدفة | الصيغة | المصدر | '
                'المالك | التكرار | الإطار |\n'
                '|---|---|---|---|---|---|---|---|---|\n'
                '| 1 | نضج الحوكمة | KPI | عالي | x | عام | الإدارة | '
                'شهري | ECC |\n'
            ),
            'confidence': (
                '## 7\n\n'
                '| # | الخطر | الاحتمالية | التأثير | التخفيف |\n'
                '|---|---|---|---|---|\n'
                '| 1 | ضعف الحوكمة | عالية | عالي | متابعة |\n'
            ),
        }
        trace = _APP._build_traceability_matrix(
            sections, ['ECC', 'DCC'], 'ar', domain_code='cyber',
        )
        # Apply renderer's no-dash gate.
        for r in (trace.get('rows') or []):
            if 'DCC' not in str(r[0]):
                continue
            cells = (r[2], r[3], r[4], r[5])
            # When strategy does NOT mention a DCC capability, the
            # gap+initiative lookup must fail and the row must remain
            # dashy so the renderer drops it.  Equivalent: gap OR init
            # MUST be a dash.
            self.assertTrue(
                str(r[2]).strip() in _DASH_TOKENS
                or not str(r[2]).strip()
                or str(r[3]).strip() in _DASH_TOKENS
                or not str(r[3]).strip(),
                f'PR-CY4 must not fabricate DCC rows when strategy '
                f'has no DCC content; got row={r!r}')


class ValidatorsNotWeakenedTests(unittest.TestCase):
    """Soft KPI/Risk derivation must not bypass validators or final
    audit.  We verify by inspecting the maps: the soft derivation map
    is scoped to (cyber, DCC) only and never to PDPL/NDMO/ECC/etc.
    """

    @_skip_if_no_app
    def test_soft_map_scoped_to_dcc_only(self):
        soft = getattr(_APP, '_CYBER_TRACEABILITY_SOFT_KPI_RISK', None)
        self.assertIsInstance(soft, dict)
        # PR-CY5 — the soft map was widened from {DCC} to {DCC, ECC}
        # so the (cyber, ECC) traceability branch can fill the metric /
        # risk axis with a family-coherent phrase when the KPI / risk
        # sections are silent on a specific ECC family.  The map MUST
        # still be scoped to cyber frameworks only — never to PDPL /
        # NDMO / SDAIA / ISO 31000 / any non-cyber framework.
        self.assertTrue(set(soft.keys()).issubset({'DCC', 'ECC'}),
                        'Cyber soft KPI/Risk derivation must be scoped '
                        'to cyber frameworks (DCC, ECC) only; got '
                        f'{sorted(soft.keys())}')
        self.assertIn('DCC', soft,
                      'PR-CY4 DCC soft map must remain present')
        # Must cover all 5 DCC families described in PR-CY4 Part B.
        for fam in ('data_classification', 'encryption', 'dlp',
                    'sensitive_data_handling', 'data_protection'):
            self.assertIn(fam, soft['DCC'])

    @_skip_if_no_app
    def test_dcc_augment_map_present_and_scoped(self):
        aug = getattr(
            _APP, '_TRACEABILITY_DCC_FAMILY_KEYWORD_AUGMENT', None)
        self.assertIsInstance(aug, dict)
        for fam in ('data_classification', 'encryption', 'dlp',
                    'sensitive_data_handling', 'data_protection'):
            self.assertIn(fam, aug)
            self.assertTrue(aug[fam].get('ar'))


class AuthDBUntouchedTests(unittest.TestCase):
    """Sanity: PR-CY4 must not touch auth / DB / export / PDF / DOCX
    route handlers.  We verify the public helper signature is stable
    so callers (api_export_strategy, _strategy_doc_model assembly)
    keep working without modification.
    """

    @_skip_if_no_app
    def test_build_traceability_matrix_signature_stable(self):
        import inspect
        sig = inspect.signature(_APP._build_traceability_matrix)
        params = list(sig.parameters.keys())
        # signature: (content_sections, selected_fws_keys, lang,
        #             domain_code='cyber')
        self.assertEqual(
            params,
            ['content_sections', 'selected_fws_keys',
             'lang', 'domain_code'],
            'PR-CY4 must preserve _build_traceability_matrix signature')


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
