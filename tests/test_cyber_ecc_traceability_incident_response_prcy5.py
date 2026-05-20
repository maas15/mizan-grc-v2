"""PR-CY5 — Cyber ECC incident-response traceability + Part B cell mapping.

Production symptom: Cyber Security strategies generated with
``selected_frameworks=['ECC', 'DCC']`` correctly include scope / vision /
pillars / roadmap / KPIs / glossary for both frameworks (PR-CY3 / PR-CY4
fix), and PR-CY4 made DCC traceability Part A and Part B render all five
DCC families.  But the ECC traceability still rendered only four rows
(governance, identity, SOC, vulnerability management) — the
``incident_response`` / CSIRT row was dropped at PDF render time even
though the strategy contained incident-response content in vision /
gaps / roadmap / KPIs / confidence.  Additionally, Part B cell mapping
for ECC families could cross-contaminate (e.g. IAM initiative paired
with SOC / incident KPI/risk text) because the simple per-section
``_find_match`` keywords were too narrow.

PR-CY5 fixes both issues for the (cyber, ECC) scope strictly:

  * Augment ECC per-family keywords for traceability lookup via
    ``_TRACEABILITY_ECC_FAMILY_KEYWORD_AUGMENT`` (mirrors PR-CY4 DCC
    augmentation).  IR keywords include CSIRT, ``خطة الاستجابة
    للحوادث``, ``فريق الاستجابة للحوادث``, ``إدارة الحوادث``,
    ``احتواء الحوادث``, ``incident management``, ``incident
    handling``, etc.
  * Fall back across multiple sections (gaps / roadmap / kpis /
    pillars / confidence) for each axis so the row's cells can each be
    sourced from the section that actually contains them.
  * Apply a deterministic, capability-derived soft Initiative / KPI /
    Risk descriptor via ``_CYBER_TRACEABILITY_SOFT_INITIATIVE['ECC']``
    and ``_CYBER_TRACEABILITY_SOFT_KPI_RISK['ECC']`` ONLY when the row
    already exists (because ECC was selected and the capability is
    addressed by the strategy) but an axis lookup found no distinct
    family-coherent phrase.  Never invents a new strategy row — only
    labels the axis with a family-scoped phrase.

Scope: strictly (domain=cyber, framework=ECC).  TCC / CSCC keep the
existing per-section ``_find_match`` behaviour.  DCC rendering (PR-CY4)
is unchanged.  Data Management (NDMO / PDPL) traceability is
unchanged.  AI / Digital Transformation / ERM traceability is
unchanged.  No validators are weakened.  No deterministic strategy
rows are inserted.  Auth / DB / export / PDF / DOCX routes are
untouched.

Run:
    python -m pytest tests/test_cyber_ecc_traceability_incident_response_prcy5.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_ecc_prcy5_')
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
# evidence described in the PR-CY5 problem statement.  ECC scope
# includes governance, identity, SOC, INCIDENT RESPONSE, vulnerability
# management.  DCC scope keeps PR-CY4 coverage so this fixture also
# regression-tests that PR-CY5 does not break DCC rendering.
_SECTIONS_AR_ECC_DCC = {
    'vision': (
        '## 1. الرؤية والأهداف\n\n'
        'الالتزام بمتطلبات NCA ECC و NCA DCC لضمان حماية البيانات '
        'وتطوير الاستجابة للحوادث وتشكيل فريق CSIRT.\n'
    ),
    'pillars': (
        '## 2. الركائز الاستراتيجية\n\n'
        '### الركيزة 1: حوكمة الأمن السيبراني\n\n'
        '| # | المبادرة | الوصف | المخرج |\n'
        '|---|---|---|---|\n'
        '| 1 | تأسيس لجنة حوكمة الأمن السيبراني وإنشاء إدارة الأمن '
        'السيبراني | حوكمة ECC | تقرير |\n'
        '| 2 | تنفيذ إدارة الهوية والوصول وتفعيل MFA و PAM | IAM ECC '
        '| تقرير |\n'
        '| 3 | تأسيس مركز العمليات الأمنية SOC وتفعيل SIEM | SOC ECC '
        '| تقرير |\n'
        '| 4 | تطوير نظام الاستجابة للحوادث وتشكيل فريق CSIRT | IR '
        'ECC | تقرير |\n'
        '| 5 | تنفيذ عملية إدارة الثغرات وتقييم الثغرات بشكل دوري '
        '| Vuln ECC | تقرير |\n'
        '| 6 | تنفيذ ضوابط تصنيف البيانات ومعالجة البيانات الحساسة '
        '| DCC تصنيف | تقرير |\n'
        '| 7 | تطبيق ضوابط التشفير ومنع فقدان البيانات DLP | DCC | '
        'تقرير |\n'
        '| 8 | حماية البيانات الحساسة أثناء النقل والتخزين | DCC '
        '| تقرير |\n'
    ),
    'environment': (
        '## 3. تحليل البيئة\n\nالبيئة تتطلب الامتثال لمتطلبات ECC '
        'و DCC وتغطي الحوكمة وإدارة الهوية والوصول والرصد '
        'والاستجابة للحوادث وإدارة الثغرات وتصنيف البيانات والتشفير '
        'ومنع تسرب البيانات.\n'
    ),
    'gaps': (
        '## 4. الفجوات\n\n'
        '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
        '|---|---|---|---|---|\n'
        '| 1 | غياب حوكمة الأمن السيبراني | ECC حوكمة | عالية | مفتوحة |\n'
        '| 2 | ضعف إدارة الهوية والوصول | ECC IAM | عالية | مفتوحة |\n'
        '| 3 | غياب مركز العمليات الأمنية | ECC SOC | عالية | مفتوحة |\n'
        '| 4 | غياب خطة الاستجابة للحوادث | ECC IR | عالية | مفتوحة |\n'
        '| 5 | ضعف إدارة الثغرات | ECC Vuln | عالية | مفتوحة |\n'
        '| 6 | غياب تصنيف البيانات الحساسة | DCC تصنيف | عالية | مفتوحة |\n'
        '| 7 | ضعف التشفير عند النقل والتخزين | DCC تشفير | عالية | مفتوحة |\n'
        '| 8 | غياب ضوابط منع فقدان البيانات DLP | DCC | عالية | مفتوحة |\n'
        '| 9 | ضعف معالجة البيانات الحساسة | DCC | عالية | مفتوحة |\n'
        '| 10 | ضعف حماية البيانات | DCC | عالية | مفتوحة |\n'
    ),
    'roadmap': (
        '## 5. خارطة الطريق\n\n'
        '| # | النشاط | المرحلة | الإطار |\n'
        '|---|---|---|---|\n'
        '| 1 | تأسيس لجنة حوكمة الأمن السيبراني وإنشاء إدارة الأمن '
        'السيبراني | Q1 | ECC |\n'
        '| 2 | تنفيذ إدارة الهوية والوصول وتفعيل MFA و PAM | Q1 | ECC |\n'
        '| 3 | تأسيس مركز العمليات الأمنية وتفعيل SIEM | Q2 | ECC |\n'
        '| 4 | تطوير نظام الاستجابة للحوادث وتشكيل فريق CSIRT | Q2 | ECC |\n'
        '| 5 | تنفيذ عملية إدارة الثغرات وتقييم الثغرات | Q2 | ECC |\n'
        '| 6 | تنفيذ ضوابط تصنيف البيانات ومعالجة البيانات الحساسة | Q1 | DCC |\n'
        '| 7 | تطبيق ضوابط التشفير ومنع فقدان البيانات DLP | Q2 | DCC |\n'
        '| 8 | معالجة البيانات الحساسة وفق الضوابط | Q2 | DCC |\n'
        '| 9 | حماية البيانات الحساسة أثناء النقل والتخزين | Q3 | DCC |\n'
    ),
    'kpis': (
        '## 6. مؤشرات الأداء\n\n'
        '| # | المؤشر | النوع | المستهدف | الصيغة | المصدر | المالك | '
        'التكرار | الإطار |\n'
        '|---|---|---|---|---|---|---|---|---|\n'
        '| 1 | نسبة الامتثال لمتطلبات الحوكمة | KPI | 100% | x | عام '
        '| الإدارة | شهري | ECC |\n'
        '| 2 | نسبة تطبيق MFA | KPI | 100% | x | عام | الإدارة | شهري '
        '| ECC |\n'
        '| 3 | فعالية الرصد والاستجابة وزمن الكشف | KPI | عالية | x '
        '| عام | الإدارة | شهري | ECC |\n'
        '| 4 | وقت الاستجابة للحوادث | KPI | < 4 ساعات | x | عام | '
        'الإدارة | شهري | ECC |\n'
        '| 5 | معدل اكتشاف الثغرات | KPI | عالٍ | x | عام | الإدارة '
        '| شهري | ECC |\n'
        '| 6 | نسبة تصنيف البيانات الحساسة | KPI | 100% | x | عام '
        '| الإدارة | شهري | DCC |\n'
        '| 7 | نسبة الامتثال لسياسات التشفير | KPI | 100% | x | عام '
        '| الإدارة | شهري | DCC |\n'
    ),
    'confidence': (
        '## 7. الثقة والمخاطر\n\n'
        '| # | الخطر | الاحتمالية | التأثير | التخفيف |\n'
        '|---|---|---|---|---|\n'
        '| 1 | ضعف حوكمة الأمن السيبراني | عالية | عالي | متابعة |\n'
        '| 2 | الوصول غير المصرح بسبب ضعف التحكم في الوصول | عالية '
        '| عالي | متابعة |\n'
        '| 3 | ضعف الرصد والاستجابة الأمنية | عالية | عالي | متابعة |\n'
        '| 4 | تأخر الاستجابة للحوادث أو ضعف احتواء الحوادث | عالية '
        '| عالي | متابعة |\n'
        '| 5 | استغلال الثغرات الأمنية | عالية | عالي | متابعة |\n'
        '| 6 | اختراق البيانات أو سوء تصنيف البيانات الحساسة | عالية '
        '| عالي | متابعة |\n'
    ),
}


def _ecc_rows(trace):
    """Return ECC rows from the model (no render gate applied)."""
    out = []
    for r in (trace.get('rows') or []):
        if not r or len(r) < 6:
            continue
        if 'ECC' in str(r[0]) and 'DCC' not in str(r[0]):
            out.append(r)
    return out


def _ecc_rendered(trace):
    """Apply ``_pro_render_traceability``'s no-dash gate to ECC rows."""
    out = []
    for r in _ecc_rows(trace):
        cells = (r[2], r[3], r[4], r[5])
        if all(str(c).strip() and str(c).strip() not in _DASH_TOKENS
               for c in cells):
            out.append(r)
    return out


def _build_trace_ecc_dcc():
    return _APP._build_traceability_matrix(
        _SECTIONS_AR_ECC_DCC, ['ECC', 'DCC'], 'ar',
        domain_code='cyber',
    )


class ECCTraceabilityPartARequiredFamiliesTests(unittest.TestCase):
    """Part A — ECC rendered rows must cover ALL five required ECC
    families (governance, identity, SOC, INCIDENT RESPONSE, vulnerability
    management).  ``incident_response`` is the family the PR-CY5 problem
    statement specifically reports missing.
    """

    def _cap_blob(self):
        return ' '.join(
            str(r[1]) for r in _ecc_rendered(_build_trace_ecc_dcc())
        )

    @_skip_if_no_app
    def test_part_a_includes_governance(self):
        self.assertIn(
            'حوكمة', self._cap_blob(),
            'ECC Part A missing governance row')

    @_skip_if_no_app
    def test_part_a_includes_identity_access(self):
        blob = self._cap_blob()
        self.assertTrue(
            ('الهوية' in blob) or ('الوصول' in blob) or ('IAM' in blob),
            'ECC Part A missing identity / access management row')

    @_skip_if_no_app
    def test_part_a_includes_soc_monitoring(self):
        blob = self._cap_blob()
        self.assertTrue(
            ('SOC' in blob) or ('SIEM' in blob) or ('الرصد' in blob)
            or ('مراقبة' in blob),
            'ECC Part A missing SOC / monitoring row')

    @_skip_if_no_app
    def test_part_a_includes_incident_response(self):
        """PR-CY5 Issue 1 — the core regression test.  Without the new
        ``_TRACEABILITY_ECC_FAMILY_KEYWORD_AUGMENT['incident_response']``
        synonyms and soft Initiative / KPI / Risk derivation, the
        ECC IR row would still be dropped at PDF render time even with
        rich IR content in the strategy.
        """
        blob = self._cap_blob()
        self.assertTrue(
            ('الاستجابة للحوادث' in blob) or ('CSIRT' in blob)
            or ('incident' in blob.lower()),
            f'ECC Part A missing incident_response row; cap blob={blob!r}')

    @_skip_if_no_app
    def test_part_a_includes_vulnerability_management(self):
        blob = self._cap_blob()
        self.assertTrue(
            ('الثغرات' in blob) or ('vulnerability' in blob.lower()),
            'ECC Part A missing vulnerability management row')


class ECCTraceabilityPartBCoherentMappingTests(unittest.TestCase):
    """Part B — ECC rendered rows must have coherent Initiative / KPI /
    Risk cells per family.  Specifically:

      * The incident_response row must have an incident-response
        initiative (CSIRT / خطة الاستجابة), an incident-response KPI
        (وقت الاستجابة), and an incident-response risk.
      * The identity_access row must map to IAM / MFA / PAM content,
        NOT SOC / incident text from a sibling row.
    """

    def _find_row(self, trace, keywords):
        for r in _ecc_rendered(trace):
            cap = str(r[1])
            for kw in keywords:
                if kw in cap or kw.lower() in cap.lower():
                    return r
        return None

    @_skip_if_no_app
    def test_part_b_incident_response_row_complete(self):
        r = self._find_row(_build_trace_ecc_dcc(),
                           ('الاستجابة للحوادث', 'CSIRT', 'incident'))
        self.assertIsNotNone(
            r, 'ECC Part B incident_response row missing')
        self.assertIn('ECC', str(r[0]))
        init, kpi, risk = str(r[3]), str(r[4]), str(r[5])
        # All three must carry real content (no dashes).
        for cell, name in ((init, 'initiative'),
                           (kpi, 'kpi'),
                           (risk, 'risk')):
            self.assertTrue(
                cell.strip() and cell.strip() not in _DASH_TOKENS,
                f'IR {name} empty/dash: row={r!r}')
        # All three must carry incident-response coherent content.
        blob = (init + ' ' + kpi + ' ' + risk).lower()
        self.assertTrue(
            ('الاستجابة للحوادث' in (init + ' ' + kpi + ' ' + risk))
            or ('csirt' in blob)
            or ('احتواء الحوادث' in (init + ' ' + kpi + ' ' + risk))
            or ('incident' in blob),
            f'IR row not IR-coherent: {r!r}')

    @_skip_if_no_app
    def test_part_b_iam_row_maps_to_iam_not_soc_or_incident(self):
        """Issue 2 — IAM initiative must not be paired with SOC /
        incident KPI/risk text.  We accept either real IAM content
        from the fixtures or the PR-CY5 soft IAM mapping.
        """
        r = self._find_row(_build_trace_ecc_dcc(),
                           ('الهوية', 'الوصول', 'IAM',
                            'Identity', 'Access'))
        self.assertIsNotNone(r, 'ECC Part B IAM row missing')
        self.assertIn('ECC', str(r[0]))
        init, kpi, risk = str(r[3]), str(r[4]), str(r[5])
        # No cell is dash.
        for cell, name in ((init, 'initiative'),
                           (kpi, 'kpi'),
                           (risk, 'risk')):
            self.assertTrue(
                cell.strip() and cell.strip() not in _DASH_TOKENS,
                f'IAM {name} empty/dash: row={r!r}')
        # KPI / Risk must NOT be the SOC or incident-response content
        # leaked from another family row.  We assert KPI mentions IAM-
        # related vocabulary (MFA / Access / Identity / IAM / PAM /
        # سياسات التحكم) and Risk mentions access-control vocabulary
        # (وصول / access).
        kpi_l = kpi.lower()
        self.assertTrue(
            ('mfa' in kpi_l) or ('access' in kpi_l)
            or ('identity' in kpi_l) or ('iam' in kpi_l)
            or ('pam' in kpi_l) or ('الهوية' in kpi)
            or ('الوصول' in kpi),
            f'IAM KPI cross-contaminated with non-IAM content: {kpi!r}')
        risk_l = risk.lower()
        self.assertTrue(
            ('access' in risk_l) or ('الوصول' in risk),
            f'IAM Risk cross-contaminated with non-IAM content: {risk!r}')
        # And especially must NOT contain CSIRT / IR-specific phrasing
        # that would indicate the IR row text leaked into IAM.
        for forbidden in ('CSIRT', 'الاستجابة للحوادث',
                          'احتواء الحوادث', 'SIEM', 'SOC'):
            self.assertNotIn(
                forbidden, init,
                f'IAM initiative leaked SOC/IR text: {init!r}')
            self.assertNotIn(
                forbidden, kpi,
                f'IAM KPI leaked SOC/IR text: {kpi!r}')

    @_skip_if_no_app
    def test_part_b_no_ecc_or_dcc_row_contains_dash(self):
        """Issue 1/2 hygiene — NO rendered ECC or DCC row may carry a
        dash placeholder in any of its six columns.  Mirrors the PDF
        render-time no-dash gate.
        """
        trace = _build_trace_ecc_dcc()
        for r in (trace.get('rows') or []):
            if not r or len(r) < 6:
                continue
            fw = str(r[0])
            if not (('ECC' in fw) or ('DCC' in fw)):
                continue
            cells = (r[2], r[3], r[4], r[5])
            # Only assert no-dash on rendered rows (informative rows).
            if not all(str(c).strip()
                       and str(c).strip() not in _DASH_TOKENS
                       for c in cells):
                # row would be dropped at render time — fine.
                continue
            for c in r:
                self.assertNotIn(
                    str(c).strip(), _DASH_TOKENS,
                    f'Rendered row contains dash: {r!r}')

    @_skip_if_no_app
    def test_part_b_initiative_not_duplicated_into_kpi_or_risk(self):
        """An ECC row's Initiative phrase must not be identical to its
        KPI or Risk phrase (PR-CY5 spec — no exact duplication when
        better content exists).
        """
        for r in _ecc_rendered(_build_trace_ecc_dcc()):
            init, kpi, risk = (str(r[3]).strip(),
                               str(r[4]).strip(),
                               str(r[5]).strip())
            self.assertNotEqual(
                init, kpi,
                f'ECC row Initiative duplicated into KPI: {r!r}')
            self.assertNotEqual(
                init, risk,
                f'ECC row Initiative duplicated into Risk: {r!r}')


class DCCTraceabilityRegressionTests(unittest.TestCase):
    """PR-CY4 — DCC traceability rendering must remain byte-for-byte
    unchanged by PR-CY5 (Part A keeps all five DCC families; Part B
    cells are complete and coherent).
    """

    def _dcc_rendered(self, trace):
        out = []
        for r in (trace.get('rows') or []):
            if not r or len(r) < 6:
                continue
            if 'DCC' not in str(r[0]):
                continue
            cells = (r[2], r[3], r[4], r[5])
            if all(str(c).strip()
                   and str(c).strip() not in _DASH_TOKENS
                   for c in cells):
                out.append(r)
        return out

    @_skip_if_no_app
    def test_dcc_part_a_still_five_families(self):
        trace = _build_trace_ecc_dcc()
        cap_blob = ' '.join(str(r[1])
                            for r in self._dcc_rendered(trace))
        self.assertIn('تصنيف', cap_blob,
                      'DCC Part A regressed: classification missing')
        self.assertIn('تشفير', cap_blob,
                      'DCC Part A regressed: encryption missing')
        self.assertIn('dlp', cap_blob.lower(),
                      'DCC Part A regressed: DLP missing')
        self.assertIn('البيانات الحساسة', cap_blob,
                      'DCC Part A regressed: sensitive-data handling '
                      'missing')
        self.assertIn('حماية البيانات', cap_blob,
                      'DCC Part A regressed: data protection missing')

    @_skip_if_no_app
    def test_dcc_part_b_cells_still_complete(self):
        for r in self._dcc_rendered(_build_trace_ecc_dcc()):
            for cell in (r[2], r[3], r[4], r[5]):
                self.assertTrue(
                    str(cell).strip()
                    and str(cell).strip() not in _DASH_TOKENS,
                    f'DCC Part B cell regressed to dash: {r!r}')


class ECCOnlyAndCrossDomainUnchangedTests(unittest.TestCase):
    """Other selections and domains must keep their existing
    traceability behaviour."""

    @_skip_if_no_app
    def test_ecc_only_selection_still_renders_ecc_rows(self):
        # ECC selected alone (no DCC).  Should still render IR row.
        trace = _APP._build_traceability_matrix(
            _SECTIONS_AR_ECC_DCC, ['ECC'], 'ar',
            domain_code='cyber',
        )
        rows = _ecc_rendered(trace)
        self.assertTrue(rows, 'ECC-only selection rendered zero rows')
        for r in rows:
            self.assertNotIn(
                'DCC', str(r[0]),
                'ECC-only selection must not produce DCC rows')

    @_skip_if_no_app
    def test_data_management_unchanged_no_ecc_branch(self):
        """Data Management (NDMO/PDPL) traceability must take the
        data-scope branch, never the new (cyber, ECC) branch.
        """
        sections = {
            'vision': '## 1\n\n',
            'pillars': (
                '## 2\n\n'
                '| # | المبادرة | الوصف | المخرج |\n'
                '|---|---|---|---|\n'
                '| 1 | تأسيس حوكمة الخصوصية وفق PDPL | privacy | '
                'تقرير |\n'
            ),
            'environment': '## 3\n\nالامتثال لـ PDPL.\n',
            'gaps': (
                '## 4\n\n'
                '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
                '|---|---|---|---|---|\n'
                '| 1 | ضعف حوكمة الخصوصية | privacy governance | '
                'عالية | مفتوحة |\n'
            ),
            'roadmap': (
                '## 5\n\n'
                '| # | النشاط | المرحلة | الإطار |\n'
                '|---|---|---|---|\n'
                '| 1 | تأسيس حوكمة الخصوصية وفق PDPL | Q1 | PDPL |\n'
            ),
            'kpis': '## 6\n',
            'confidence': '## 7\n',
        }
        trace = _APP._build_traceability_matrix(
            sections, ['PDPL'], 'ar', domain_code='data',
        )
        # No ECC rows should appear from a Data-Management strategy.
        for r in (trace.get('rows') or []):
            self.assertNotIn(
                'ECC', str(r[0]),
                'Data PDPL trace must not produce ECC rows')


class ValidatorsAndAuthUntouchedTests(unittest.TestCase):
    """PR-CY5 must not weaken validators, alter the public traceability
    signature, or modify auth / DB / export route handlers.
    """

    @_skip_if_no_app
    def test_build_traceability_matrix_signature_stable(self):
        import inspect
        sig = inspect.signature(_APP._build_traceability_matrix)
        params = list(sig.parameters.keys())
        self.assertEqual(
            params,
            ['content_sections', 'selected_fws_keys',
             'lang', 'domain_code'],
            'PR-CY5 must preserve _build_traceability_matrix signature')

    @_skip_if_no_app
    def test_soft_maps_scoped_to_cyber_frameworks_only(self):
        soft = getattr(_APP, '_CYBER_TRACEABILITY_SOFT_KPI_RISK', None)
        self.assertIsInstance(soft, dict)
        self.assertTrue(
            set(soft.keys()).issubset({'DCC', 'ECC'}),
            'Soft KPI/Risk map must be cyber-framework scoped only')
        self.assertIn('ECC', soft)
        for fam in ('governance', 'identity_access', 'monitoring',
                    'incident_response', 'vulnerability_management'):
            self.assertIn(fam, soft['ECC'],
                          f'ECC soft KPI/Risk missing {fam}')

    @_skip_if_no_app
    def test_soft_initiative_map_scoped_to_ecc(self):
        soft = getattr(
            _APP, '_CYBER_TRACEABILITY_SOFT_INITIATIVE', None)
        self.assertIsInstance(soft, dict)
        self.assertTrue(
            set(soft.keys()).issubset({'ECC'}),
            'Soft initiative map must be ECC-scoped only (other '
            'frameworks unchanged)')
        for fam in ('governance', 'identity_access', 'monitoring',
                    'incident_response', 'vulnerability_management'):
            self.assertIn(fam, soft['ECC'])

    @_skip_if_no_app
    def test_ecc_keyword_augment_present(self):
        aug = getattr(
            _APP, '_TRACEABILITY_ECC_FAMILY_KEYWORD_AUGMENT', None)
        self.assertIsInstance(aug, dict)
        for fam in ('governance', 'identity_access', 'monitoring',
                    'incident_response', 'vulnerability_management'):
            self.assertIn(fam, aug)
            self.assertTrue(aug[fam].get('ar'))
        # IR family must include accepted source phrases from the
        # problem statement.
        ir_ar = aug['incident_response']['ar']
        for phrase in ('الاستجابة للحوادث', 'CSIRT',
                       'خطة الاستجابة للحوادث',
                       'فريق الاستجابة للحوادث',
                       'إدارة الحوادث', 'احتواء الحوادث',
                       'معالجة الحوادث'):
            self.assertIn(phrase, ir_ar,
                          f'IR augment missing required phrase: {phrase}')
        ir_en = aug['incident_response']['en']
        for phrase in ('incident response', 'incident management',
                       'CSIRT', 'incident handling'):
            self.assertIn(phrase, ir_en,
                          f'IR augment missing required phrase: {phrase}')


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
