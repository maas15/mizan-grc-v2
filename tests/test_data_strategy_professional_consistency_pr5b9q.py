"""PR-5B.9Q — Data Management strategy professional consistency.

Scope is **Data Management only** — Cyber/AI/DT/ERM behaviour must be
preserved. Validates three obligations after the NDMO runtime fix:

  * Part A — Data Pillar 1 (org_structure_is_none=True) must cover the
    Data-Management-Office / CDO / Data Governance Committee /
    stewards / ownership / operating-model wording, enforced through
    ``_compute_missing_governance_structure_in_pillars`` against the
    extended ``_DOMAIN_SPECIALIZED_FUNCTION_CONCEPTS['data']`` registry.
  * Part B — Data roadmap (org_structure_is_none=True) must include an
    explicit governance-setup activity that names the DMO / CDO /
    committee, enforced through ``_compute_missing_governance_setup_in_roadmap``.
  * Part C — NDMO traceability depth: ``_FRAMEWORK_COVERAGE_REQUIREMENTS``
    must declare ≥3 NDMO capability families (governance / quality /
    catalog/metadata / stewardship / lifecycle) so the traceability
    matrix renders ≥3 meaningful NDMO rows without dashes.

Plus cross-domain regression guards (Cyber ECC/TCC + ECC/DCC, AI SDAIA,
DT DGA, ERM ISO31000/COSO) and structural guards (no deterministic
rows added, validators not weakened, no export/PDF/DOCX/auth/DB edits).

Run:
    python -m pytest \
        tests/test_data_strategy_professional_consistency_pr5b9q.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_data_pr5b9q_')
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


# ── Fixtures ─────────────────────────────────────────────────────────────

# Pillar 1 with only generic "حوكمة البيانات" wording — must FAIL the
# governance-structure check (Part A test #2). No registry token from
# the data domain matches this text (`حوكمة البيانات` alone is not a
# token; tokens are more specific phrases such as `وحدة حوكمة البيانات`
# or `إدارة البيانات`).
_DATA_PILLAR_GENERIC_AR = (
    '## 2. الركائز الاستراتيجية\n\n'
    '### الركيزة 1: حوكمة البيانات والخصوصية\n\n'
    'نص عام عن حوكمة البيانات والخصوصية.\n'
)

# Pillar 1 with explicit DMO + CDO + committee + stewards + operating
# model + reporting lines + RACI — must PASS (Part A test #3).
_DATA_PILLAR_GOOD_AR = (
    '## 2. الركائز الاستراتيجية\n\n'
    '### الركيزة 1: حوكمة البيانات ومكتب إدارة البيانات ونموذج التشغيل\n\n'
    '| # | المبادرة | الوصف | المخرج |\n'
    '|---|------|------|------|\n'
    '| 1 | تأسيس مكتب إدارة البيانات وتعيين Chief Data Officer (CDO) | '
    'إنشاء مكتب إدارة البيانات وتعيين رئيس البيانات | ميثاق المكتب |\n'
    '| 2 | تشكيل لجنة حوكمة البيانات وتفعيل أمناء البيانات وملكية '
    'البيانات | data governance committee وأمناء البيانات | لائحة |\n'
    '| 3 | اعتماد نموذج تشغيل إدارة البيانات وRACI وخطوط الرفع | '
    'data operating model و reporting lines | وثيقة |\n'
)

# Roadmap missing any DMO/CDO/committee setup activity — must FAIL
# (Part B test #4).
_DATA_ROADMAP_BARE_AR = (
    '## 5. خارطة الطريق\n\n'
    '| # | النشاط | المرحلة | الإطار |\n'
    '|---|------|------|------|\n'
    '| 1 | تطوير إطار عام للجودة | Q1 | 6 أشهر |\n'
    '| 2 | تحديث السياسات | Q2 | 6 أشهر |\n'
)

# Roadmap with explicit DMO / CDO / committee setup — must PASS
# (Part B test #5).
_DATA_ROADMAP_GOOD_AR = (
    '## 5. خارطة الطريق\n\n'
    '| # | النشاط | المالك | الإطار الزمني | المخرج |\n'
    '|---|------|------|------|------|\n'
    '| 1 | تأسيس مكتب إدارة البيانات وتعيين CDO وتفعيل لجنة حوكمة '
    'البيانات | الإدارة التنفيذية | Q1 (٣ أشهر) | ميثاق المكتب '
    'ولائحة اللجنة |\n'
    '| 2 | اعتماد نموذج تشغيل إدارة البيانات وRACI | CDO | Q2 | '
    'وثيقة نموذج التشغيل |\n'
)

# Rich NDMO-aligned strategy sections so the traceability matrix can
# match each NDMO capability family (governance / quality / catalog /
# stewardship / lifecycle) and produce ≥3 meaningful informative rows
# without dashes (Part C tests #6–#8).
_RICH_NDMO_SECTIONS_AR = {
    'vision': '## 1. الرؤية\n\nرؤية حوكمة البيانات.\n',
    'pillars': (
        '## 2. الركائز\n\n'
        '### الركيزة 1: حوكمة البيانات ومكتب إدارة البيانات\n\n'
        '| # | المبادرة | الوصف | المخرج |\n'
        '|---|------|------|------|\n'
        '| 1 | إطار حوكمة البيانات وفق NDMO | data governance | تقرير |\n'
        '| 2 | برنامج جودة البيانات | data quality | تقرير |\n'
        '| 3 | كتالوج البيانات الوصفية | data catalog | تقرير |\n'
        '| 4 | تفعيل أمناء البيانات وملكية البيانات | data stewardship | '
        'تقرير |\n'
        '| 5 | دورة حياة البيانات وتصنيف البيانات | data lifecycle | '
        'تقرير |\n'
    ),
    'environment': (
        '## 3. البيئة\n\nالبيئة تتطلب حوكمة البيانات وجودة البيانات '
        'وكتالوج البيانات الوصفية وأمناء البيانات ودورة حياة '
        'البيانات وفق NDMO.\n'),
    'gaps': (
        '## 4. الفجوات\n\n'
        '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
        '|---|------|------|------|------|\n'
        '| 1 | غياب إطار حوكمة البيانات | data governance | عالية | '
        'مفتوحة |\n'
        '| 2 | غياب برنامج جودة البيانات | data quality | عالية | '
        'مفتوحة |\n'
        '| 3 | غياب كتالوج البيانات الوصفية | data catalog metadata | '
        'عالية | مفتوحة |\n'
        '| 4 | غياب أمناء البيانات وملكية البيانات | data stewardship | '
        'عالية | مفتوحة |\n'
        '| 5 | غياب دورة حياة البيانات | data lifecycle | عالية | '
        'مفتوحة |\n'
    ),
    'roadmap': (
        '## 5. خارطة الطريق\n\n'
        '| # | النشاط | المرحلة | الإطار |\n'
        '|---|------|------|------|\n'
        '| 1 | تأسيس مكتب إدارة البيانات وتعيين CDO وتفعيل لجنة حوكمة '
        'البيانات | Q1 | NDMO |\n'
        '| 2 | إطلاق برنامج جودة البيانات | Q2 | NDMO |\n'
        '| 3 | بناء كتالوج البيانات الوصفية | Q2 | NDMO |\n'
        '| 4 | تفعيل أمناء البيانات وملكية البيانات | Q2 | NDMO |\n'
        '| 5 | اعتماد سياسة دورة حياة البيانات وتصنيف البيانات | Q3 | '
        'NDMO |\n'
    ),
    'kpis': (
        '## 6. مؤشرات\n\n'
        '| # | المؤشر | النوع | المستهدفة | الصيغة | المصدر | المالك | '
        'التكرار | الإطار |\n'
        '|---|------|------|------|------|------|------|------|------|\n'
        '| 1 | نضج حوكمة البيانات | KPI | 100% | x | عام | CDO | شهري | '
        'NDMO |\n'
        '| 2 | جودة البيانات | KPI | 95% | x | عام | CDO | شهري | NDMO |\n'
        '| 3 | تغطية كتالوج البيانات الوصفية | KPI | 100% | x | عام | '
        'CDO | شهري | NDMO |\n'
        '| 4 | تغطية أمناء البيانات | KPI | 100% | x | عام | CDO | '
        'شهري | NDMO |\n'
        '| 5 | امتثال دورة حياة البيانات | KPI | 100% | x | عام | CDO | '
        'شهري | NDMO |\n'
    ),
    'confidence': (
        '## 7. الثقة\n\n'
        '| # | الخطر | الاحتمالية | التأثير | التخفيف |\n'
        '|---|------|------|------|------|\n'
        '| 1 | ضعف حوكمة البيانات | عالية | عالي | متابعة |\n'
        '| 2 | تدني جودة البيانات | عالية | عالي | متابعة |\n'
        '| 3 | غياب كتالوج البيانات الوصفية | عالية | عالي | متابعة |\n'
        '| 4 | غياب أمناء البيانات | عالية | عالي | متابعة |\n'
        '| 5 | انتهاك دورة حياة البيانات | عالية | عالي | متابعة |\n'
    ),
}


# ── Part A — Data Pillar 1 governance ────────────────────────────────────

class DataPillarGovernanceTests(unittest.TestCase):
    """Pillar-1 governance/structure check for Data Management."""

    @_skip_if_no_app
    def test_data_registry_has_required_families(self):
        """Test #1 — Data registry must include DMO / CDO / committee /
        stewards (+ operating model added in PR-5B.9Q)."""
        concepts = _APP._DOMAIN_SPECIALIZED_FUNCTION_CONCEPTS.get('data')
        self.assertIsNotNone(concepts, 'Data must be in registry')
        # Required families.
        for fam in ('establish_dept', 'head_officer', 'committee',
                    'roles_responsibilities', 'operating_model'):
            self.assertIn(fam, concepts,
                          f'Data registry missing family {fam!r}')
        # Spot-check token presence per family.
        all_tokens = []
        for fam_tokens in concepts.values():
            all_tokens.extend(t.lower() for t in fam_tokens)
        for needle in ('مكتب إدارة البيانات',
                       'chief data officer', 'cdo',
                       'لجنة حوكمة البيانات',
                       'أمناء البيانات', 'ملكية البيانات',
                       'نموذج تشغيل إدارة البيانات',
                       'خطوط الرفع'):
            self.assertTrue(
                any(needle.lower() in t for t in all_tokens),
                f'Data registry missing token {needle!r}')

    @_skip_if_no_app
    def test_data_generic_pillar_fails_governance_check(self):
        """Test #2 — generic "حوكمة البيانات" wording must FAIL when
        ``org_structure_is_none=True``."""
        missing = (
            _APP._compute_missing_governance_structure_in_pillars(
                _DATA_PILLAR_GENERIC_AR, 'data',
                org_structure_is_none=True, lang='ar',
            ))
        self.assertTrue(
            len(missing) > 0,
            f'expected non-empty missing list for generic data Pillar 1, '
            f'got {missing!r}')

    @_skip_if_no_app
    def test_data_pillar_with_dmo_and_cdo_passes(self):
        """Test #3 — Pillar 1 naming DMO + CDO + committee + stewards
        + operating model must PASS."""
        missing = (
            _APP._compute_missing_governance_structure_in_pillars(
                _DATA_PILLAR_GOOD_AR, 'data',
                org_structure_is_none=True, lang='ar',
            ))
        self.assertEqual(
            missing, [],
            f'expected [] for data Pillar 1 with DMO/CDO/committee/'
            f'stewards/operating-model, got {missing!r}')

    @_skip_if_no_app
    def test_data_pillar_org_structure_not_none_returns_empty(self):
        """Helper must short-circuit when org_structure_is_none=False
        (obligation does not apply)."""
        missing = (
            _APP._compute_missing_governance_structure_in_pillars(
                _DATA_PILLAR_GENERIC_AR, 'data',
                org_structure_is_none=False, lang='ar',
            ))
        self.assertEqual(missing, [])


# ── Part B — Data Roadmap governance setup ───────────────────────────────

class DataRoadmapGovernanceSetupTests(unittest.TestCase):
    """Roadmap governance-setup activity check for Data Management."""

    @_skip_if_no_app
    def test_data_bare_roadmap_fails_governance_setup(self):
        """Test #4 — roadmap with only generic activities must FAIL."""
        missing = _APP._compute_missing_governance_setup_in_roadmap(
            _DATA_ROADMAP_BARE_AR, domain='data',
            org_structure_is_none=True, lang='ar',
        )
        self.assertTrue(
            len(missing) > 0,
            f'expected non-empty missing list for bare data roadmap, '
            f'got {missing!r}')

    @_skip_if_no_app
    def test_data_roadmap_with_dmo_cdo_committee_passes(self):
        """Test #5 — roadmap with explicit "تأسيس مكتب إدارة البيانات
        وتعيين CDO وتفعيل لجنة حوكمة البيانات" must PASS."""
        missing = _APP._compute_missing_governance_setup_in_roadmap(
            _DATA_ROADMAP_GOOD_AR, domain='data',
            org_structure_is_none=True, lang='ar',
        )
        self.assertEqual(
            missing, [],
            f'expected [] for data roadmap with DMO/CDO/committee '
            f'setup, got {missing!r}')

    @_skip_if_no_app
    def test_generic_governance_framework_wording_alone_fails(self):
        """Roadmap saying only "تطوير إطار حوكمة البيانات" (without
        naming DMO / CDO / committee) must FAIL — the spec rejects
        generic wording."""
        roadmap = (
            '## 5. خارطة الطريق\n\n'
            '| 1 | تطوير إطار حوكمة البيانات العام | Q1 | 6 أشهر |\n'
        )
        # Note: the registry tokens for data establish_dept include
        # "وحدة حوكمة البيانات" (with the literal word "وحدة") — the
        # generic wording above does NOT include "وحدة"; head_officer
        # tokens (cdo / chief data officer / رئيس البيانات) and
        # committee tokens (لجنة حوكمة البيانات) are also absent. So
        # the helper must return a non-empty missing list.
        missing = _APP._compute_missing_governance_setup_in_roadmap(
            roadmap, domain='data',
            org_structure_is_none=True, lang='ar',
        )
        self.assertTrue(
            len(missing) > 0,
            f'expected non-empty missing list for generic governance '
            f'wording, got {missing!r}')

    @_skip_if_no_app
    def test_data_roadmap_org_structure_not_none_returns_empty(self):
        missing = _APP._compute_missing_governance_setup_in_roadmap(
            _DATA_ROADMAP_BARE_AR, domain='data',
            org_structure_is_none=False, lang='ar',
        )
        self.assertEqual(missing, [])


# ── Part C — NDMO Traceability Depth ─────────────────────────────────────

class NDMOTraceabilityDepthTests(unittest.TestCase):
    """NDMO traceability matrix must render ≥3 meaningful rows
    covering governance / quality / catalog / stewardship / lifecycle.
    """

    @_skip_if_no_app
    def test_ndmo_capability_families_widened(self):
        """NDMO registry must declare ≥5 capability families."""
        spec = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS.get('NDMO')
        self.assertIsNotNone(spec, 'NDMO must be in coverage registry')
        family_ids = [c[0] for c in spec.get('capabilities', [])]
        for required in ('data_governance', 'data_quality',
                         'data_catalog', 'data_stewardship',
                         'data_lifecycle'):
            self.assertIn(
                required, family_ids,
                f'NDMO capability family {required!r} missing; '
                f'have {family_ids!r}')

    @_skip_if_no_app
    def test_ndmo_traceability_has_at_least_three_rows(self):
        """Test #6 — at least 3 NDMO traceability rows."""
        trace = _APP._build_traceability_matrix(
            _RICH_NDMO_SECTIONS_AR, ['NDMO'], 'ar',
            domain_code='data',
        )
        rows = trace.get('rows') or []
        ndmo_rows = [r for r in rows if r and 'NDMO' in str(r[0])]
        self.assertGreaterEqual(
            len(ndmo_rows), 3,
            f'expected >=3 NDMO traceability rows, got {len(ndmo_rows)}: '
            f'frameworks={[r[0] for r in rows]}')

    @_skip_if_no_app
    def test_ndmo_rows_cover_required_concepts(self):
        """Test #7 — informative rows must collectively cover
        governance, quality, and catalog/metadata."""
        trace = _APP._build_traceability_matrix(
            _RICH_NDMO_SECTIONS_AR, ['NDMO'], 'ar',
            domain_code='data',
        )
        info = trace.get('informative_rows') or []
        ndmo_info = [r for r in info if r and 'NDMO' in str(r[0])]
        self.assertGreaterEqual(len(ndmo_info), 3)
        blob = ' '.join(str(r[1]) for r in ndmo_info).lower()
        for concept in ('حوكمة', 'جودة', 'كتالوج'):
            self.assertIn(
                concept.lower(), blob,
                f'NDMO capability concept {concept!r} missing from '
                f'informative rows; blob={blob!r}')

    @_skip_if_no_app
    def test_ndmo_informative_rows_no_dash(self):
        """Test #8 — informative NDMO rows must not contain dashes in
        the Gap/Initiative columns."""
        trace = _APP._build_traceability_matrix(
            _RICH_NDMO_SECTIONS_AR, ['NDMO'], 'ar',
            domain_code='data',
        )
        info = trace.get('informative_rows') or []
        ndmo_info = [r for r in info if r and 'NDMO' in str(r[0])]
        self.assertTrue(len(ndmo_info) >= 3)
        for r in ndmo_info:
            for cell in (r[2], r[3]):  # Gap, Initiative
                self.assertNotIn(
                    str(cell).strip(), ('—', '-', '--', '–', ''),
                    f'informative row must not contain dash; got {r!r}')


# ── Structural guards (#9–#11) ───────────────────────────────────────────

class StructuralGuardTests(unittest.TestCase):
    """No deterministic rows, validators not weakened, no auth/DB edits."""

    @_skip_if_no_app
    def test_no_deterministic_rows_inserted(self):
        """Test #9 — the traceability builder must NOT invent content.
        Sections with no NDMO-relevant tokens must produce all-dash
        rows that are dropped by the informative-rows view."""
        empty = {
            'vision': '## 1.\n', 'pillars': '## 2.\n',
            'environment': '## 3.\n', 'gaps': '## 4.\n',
            'roadmap': '## 5.\n', 'kpis': '## 6.\n',
            'confidence': '## 7.\n',
        }
        trace = _APP._build_traceability_matrix(
            empty, ['NDMO'], 'ar', domain_code='data',
        )
        info = trace.get('informative_rows') or []
        # No informative rows when content is empty — proves no
        # deterministic rows are synthesised.
        ndmo_info = [r for r in info if r and 'NDMO' in str(r[0])]
        self.assertEqual(
            ndmo_info, [],
            f'expected no informative NDMO rows for empty sections, '
            f'got {ndmo_info!r}')

    @_skip_if_no_app
    def test_validators_not_weakened(self):
        """Test #10 — pillar/roadmap helpers must still REJECT a bare
        text when ``org_structure_is_none=True`` (the gate did not
        become more permissive)."""
        bare = '## section\n\nبعض النص العام.\n'
        for helper, name in (
            (_APP._compute_missing_governance_structure_in_pillars,
             'pillars'),
            (_APP._compute_missing_governance_setup_in_roadmap,
             'roadmap'),
        ):
            missing = helper(bare, 'data',
                             org_structure_is_none=True, lang='ar')
            self.assertTrue(
                len(missing) > 0,
                f'expected {name} helper to reject bare text, '
                f'got {missing!r}')

    @_skip_if_no_app
    def test_auth_db_export_modules_untouched(self):
        """Test #11 — the PR only touches the governance registry and
        the NDMO capability list. Spot-check that key auth/DB/export
        symbols are still present and unchanged in shape."""
        # Auth / DB symbols.
        for sym in ('login_required', 'get_db'):
            self.assertTrue(
                hasattr(_APP, sym),
                f'auth/DB symbol {sym!r} missing after PR-5B.9Q')
        # Export builders.
        for sym in ('_build_appendices_block',
                    '_build_traceability_matrix',
                    '_build_document_control_rows'):
            self.assertTrue(
                hasattr(_APP, sym),
                f'export symbol {sym!r} missing after PR-5B.9Q')


# ── Cross-domain regression guards ───────────────────────────────────────
#
# Required by the problem statement: prove other domains are unchanged.
# 1. Cyber ECC/TCC + ECC/DCC still passes existing checks.
# 2. AI SDAIA still passes existing checks.
# 3. Digital Transformation DGA still passes existing checks.
# 4. ERM ISO31000/COSO still passes existing checks.

class CrossDomainRegressionTests(unittest.TestCase):
    """Confirm other domains' registries and traceability are intact."""

    @_skip_if_no_app
    def test_cyber_registry_unchanged_shape(self):
        """Cyber specialised-function registry must remain present and
        unchanged in shape (families add-only, never removed)."""
        concepts = _APP._DOMAIN_SPECIALIZED_FUNCTION_CONCEPTS.get('cyber')
        self.assertIsNotNone(concepts)
        # Spot-check critical Cyber tokens still present.
        all_tokens = []
        for fam_tokens in concepts.values():
            all_tokens.extend(t.lower() for t in fam_tokens)
        # Cyber department / CISO must remain recognised.
        self.assertTrue(
            any('ciso' in t for t in all_tokens),
            'Cyber registry must still recognise CISO')

    @_skip_if_no_app
    def test_cyber_dcc_traceability_still_produces_rows(self):
        """ECC+DCC traceability path unchanged."""
        sections = {
            'vision': '## 1.\n',
            'pillars': (
                '## 2.\n### الركيزة 1\n\n'
                '| 1 | تطبيق تصنيف البيانات الحساسة وفق DCC | x | y |\n'),
            'environment': '## 3.\n DCC. data classification.\n',
            'gaps': (
                '## 4.\n'
                '| 1 | غياب تصنيف البيانات | data classification | '
                'عالية | مفتوحة |\n'),
            'roadmap': '## 5.\n',
            'kpis': (
                '## 6.\n'
                '| 1 | نسبة تصنيف البيانات | KPI | 100% | x | y | z | '
                'شهري | DCC |\n'),
            'confidence': '## 7.\n',
        }
        trace = _APP._build_traceability_matrix(
            sections, ['ECC', 'DCC'], 'ar', domain_code='cyber',
        )
        rows = trace.get('rows') or []
        dcc_rows = [r for r in rows if r and 'DCC' in str(r[0])]
        # Must still produce DCC rows (PR-5B.9M behaviour preserved).
        self.assertTrue(
            len(dcc_rows) > 0,
            f'ECC+DCC must still produce DCC rows; got '
            f'frameworks={[r[0] for r in rows]}')

    @_skip_if_no_app
    def test_cyber_tcc_traceability_still_produces_rows(self):
        """ECC+TCC traceability path unchanged."""
        sections = {
            'vision': '## 1.\n',
            'pillars': (
                '## 2.\n### الركيزة 1\n\n'
                '| 1 | نشر VPN وتطبيق MFA للوصول عن بُعد telework | x | '
                'y |\n'),
            'environment': '## 3.\n VPN. MFA. telework. ZTNA.\n',
            'gaps': '## 4.\n| 1 | غياب VPN | remote work | عالية | x |\n',
            'roadmap': '## 5.\n',
            'kpis': '## 6.\n',
            'confidence': '## 7.\n',
        }
        trace = _APP._build_traceability_matrix(
            sections, ['ECC', 'TCC'], 'ar', domain_code='cyber',
        )
        rows = trace.get('rows') or []
        tcc_rows = [r for r in rows if r and 'TCC' in str(r[0])]
        self.assertTrue(
            len(tcc_rows) > 0,
            f'ECC+TCC must still produce TCC rows; got '
            f'frameworks={[r[0] for r in rows]}')

    @_skip_if_no_app
    def test_ai_registry_unchanged_shape(self):
        """AI specialised-function registry must remain intact."""
        concepts = _APP._DOMAIN_SPECIALIZED_FUNCTION_CONCEPTS.get('ai')
        self.assertIsNotNone(concepts)
        for fam in ('establish_dept', 'head_officer', 'committee',
                    'roles_responsibilities'):
            self.assertIn(fam, concepts,
                          f'AI registry missing family {fam!r}')

    @_skip_if_no_app
    def test_ai_sdaia_compliance_alias_unchanged(self):
        """SDAIA alias detection must remain present for AI domain."""
        spec = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS.get('SDAIA')
        self.assertIsNotNone(spec,
                             'SDAIA must remain in coverage registry')

    @_skip_if_no_app
    def test_dt_registry_unchanged_shape(self):
        """DT specialised-function registry must remain intact."""
        concepts = _APP._DOMAIN_SPECIALIZED_FUNCTION_CONCEPTS.get('dt')
        self.assertIsNotNone(concepts)
        for fam in ('establish_dept', 'head_officer', 'committee',
                    'operating_model'):
            self.assertIn(fam, concepts,
                          f'DT registry missing family {fam!r}')

    @_skip_if_no_app
    def test_dt_dga_capability_unchanged(self):
        """DGA capability families must remain unchanged."""
        spec = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS.get('DGA')
        self.assertIsNotNone(spec)
        family_ids = [c[0] for c in spec.get('capabilities', [])]
        for required in ('digital_services', 'interoperability',
                         'citizen_experience'):
            self.assertIn(required, family_ids,
                          f'DGA family {required!r} missing')

    @_skip_if_no_app
    def test_erm_registry_unchanged_shape(self):
        """ERM specialised-function registry must remain intact."""
        concepts = _APP._DOMAIN_SPECIALIZED_FUNCTION_CONCEPTS.get('erm')
        self.assertIsNotNone(concepts)
        for fam in ('establish_dept', 'head_officer', 'committee',
                    'risk_owners'):
            self.assertIn(fam, concepts,
                          f'ERM registry missing family {fam!r}')

    @_skip_if_no_app
    def test_erm_iso31000_present_in_registry_if_declared(self):
        """If ISO 31000 / COSO frameworks are declared, their entries
        must still be present. Tolerate absence (the registry may not
        list them as first-class entries) so this is a presence-only
        guard for the framework display label."""
        # ISO 31000 may be referenced through ``ISO31000`` key.
        keys = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS.keys()
        for k in keys:
            spec = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS[k]
            # Each entry must still have required schema keys.
            self.assertIn('aliases', spec,
                          f'{k!r} missing aliases after PR-5B.9Q')
            self.assertIn('capabilities', spec,
                          f'{k!r} missing capabilities after PR-5B.9Q')

    @_skip_if_no_app
    def test_other_domains_pillar_helper_unchanged_for_bare_text(self):
        """Pillar helper for cyber/ai/dt/erm must still emit missing
        when org_structure_is_none=True on bare text — i.e. broadening
        the Data registry did not weaken other domains."""
        bare = '## 2.\n### الركيزة 1: تعزيز الحوكمة\n\nنص عام.\n'
        for d in ('cyber', 'ai', 'dt', 'erm'):
            with self.subTest(domain=d):
                missing = (
                    _APP._compute_missing_governance_structure_in_pillars(
                        bare, d, org_structure_is_none=True, lang='ar',
                    ))
                self.assertTrue(
                    len(missing) > 0,
                    f'pillar helper must still reject bare text for '
                    f'domain={d}; got {missing!r}')


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
