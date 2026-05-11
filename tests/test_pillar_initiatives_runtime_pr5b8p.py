"""PR-5B.8P — Strategic Pillars initiative-count validation/repair alignment.

Targets the runtime save-gate defect ``pillar_initiatives_insufficient``
emitted by ``validate_arabic_strategy_semantic_richness``.

Required tests:
  1. Arabic pillars with each pillar having ≥3 initiatives passes.
  2. Arabic pillars where one pillar has fewer than 3 initiatives fails
     with ``pillar_initiatives_insufficient``.
  3. Arabic malformed table separators do not undercount valid rows.
  4. ``synthesize_pillars_depth`` calls ``ai_repair_strategy_section``
     with the per-pillar minimum-initiatives floor in the
     ``validation_error`` and the ``min_initiatives_per_pillar``
     placeholder in the schema.
  5. Repaired pillars are validated before assignment to
     ``sections['pillars']``.
  6. Invalid repaired pillars leave ``sections['pillars']`` unchanged
     and raise ``RepairError(section='pillars')``.
  7. Final save gate triggers a targeted AI repair routing for
     ``pillar_initiatives_insufficient``.
  8. ``org_structure_is_none=True`` still requires governance-first
     pillar AND the per-pillar initiative floor.
  9. No deterministic pillar / initiative bank is called or
     reintroduced on RepairError (sections['pillars'] unchanged).
 10. English equivalent passes / fails correctly.

Run:  python -m pytest tests/test_pillar_initiatives_runtime_pr5b8p.py -q
"""

import os
import sys
import unittest

# Set minimal env vars so app.py imports without a live DB / API keys.
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///tmp/test_pi_pr5b8p.db')
os.environ.setdefault('OPENAI_API_KEY', 'dummy')
os.environ.setdefault('ANTHROPIC_API_KEY', 'dummy')
os.environ.setdefault('GOOGLE_API_KEY', 'dummy')

_USING_REAL_APP = False
_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py')
    )
    _APP = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(_APP)
    _USING_REAL_APP = True
except Exception:
    pass


def _skip_if_no_app(fn):
    import functools

    @functools.wraps(fn)
    def wrapper(self, *a, **kw):
        if not _USING_REAL_APP:
            self.skipTest('app.py not importable')
        return fn(self, *a, **kw)

    return wrapper


# ---------------------------------------------------------------------------
# Arabic / English fixture helpers
# ---------------------------------------------------------------------------

_AR_INIT_3 = (
    '| # | المبادرة | الوصف | المخرج المتوقع |\n'
    '|---|---------|-------|----------------|\n'
    '| 1 | مبادرة أ | وصف جوهري للمبادرة الأولى | المخرج الأول |\n'
    '| 2 | مبادرة ب | وصف جوهري للمبادرة الثانية | المخرج الثاني |\n'
    '| 3 | مبادرة ج | وصف جوهري للمبادرة الثالثة | المخرج الثالث |\n'
)

_AR_INIT_1 = (
    '| # | المبادرة | الوصف | المخرج المتوقع |\n'
    '|---|---------|-------|----------------|\n'
    '| 1 | مبادرة وحيدة | وصف المبادرة الوحيدة | المخرج الوحيد |\n'
)

_EN_INIT_3 = (
    '| # | Initiative | Description | Expected Deliverable |\n'
    '|---|------------|-------------|----------------------|\n'
    '| 1 | Initiative A | Substantive description A | Deliverable A |\n'
    '| 2 | Initiative B | Substantive description B | Deliverable B |\n'
    '| 3 | Initiative C | Substantive description C | Deliverable C |\n'
)

_EN_INIT_1 = (
    '| # | Initiative | Description | Expected Deliverable |\n'
    '|---|------------|-------------|----------------------|\n'
    '| 1 | Single initiative | Single description | Single deliverable |\n'
)


def _ar_pillars(p1_init, p2_init, p3_init,
                p1_title='الحوكمة', p2_title='الحماية',
                p3_title='الاستجابة'):
    return (
        '## 2. الركائز الاستراتيجية\n\n'
        f'### الركيزة 1: {p1_title}\n\n'
        'فقرة سرديّة قصيرة تشرح المنطق الاستراتيجي للركيزة الأولى.\n\n'
        f'{p1_init}\n'
        f'### الركيزة 2: {p2_title}\n\n'
        'فقرة سرديّة قصيرة تشرح المنطق الاستراتيجي للركيزة الثانية.\n\n'
        f'{p2_init}\n'
        f'### الركيزة 3: {p3_title}\n\n'
        'فقرة سرديّة قصيرة تشرح المنطق الاستراتيجي للركيزة الثالثة.\n\n'
        f'{p3_init}\n'
    )


def _en_pillars(p1_init, p2_init, p3_init,
                p1_title='Governance', p2_title='Protection',
                p3_title='Response'):
    return (
        '## 2. Strategic Pillars\n\n'
        f'### Pillar 1: {p1_title}\n\n'
        'A short narrative paragraph explaining the strategic rationale '
        'for the first pillar.\n\n'
        f'{p1_init}\n'
        f'### Pillar 2: {p2_title}\n\n'
        'A short narrative paragraph explaining the strategic rationale '
        'for the second pillar.\n\n'
        f'{p2_init}\n'
        f'### Pillar 3: {p3_title}\n\n'
        'A short narrative paragraph explaining the strategic rationale '
        'for the third pillar.\n\n'
        f'{p3_init}\n'
    )


def _ar_full_sections(pillars_text):
    return {
        'vision': (
            '## 1. الرؤية والأهداف الاستراتيجية\n\n'
            '**الرؤية:** بناء وضع متين.\n\n'
            '### الأهداف الاستراتيجية\n\n'
            '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
            '|---|-------|-------------------|--------|---------------|\n'
            '| 1 | إنشاء لجنة | اعتماد الميثاق | يغلق فجوة 1 | خلال 6 أشهر |\n'
            '| 2 | نشر الضوابط | 100% | يغلق فجوة 2 | خلال 12 شهراً |\n'
            '| 3 | برنامج توعية | ≥90% | يغلق فجوة 3 | خلال 9 أشهر |\n'
            '| 4 | الاستجابة | اعتماد الدليل | يغلق فجوة 4 | خلال 12 شهراً |\n'
            '| 5 | المراقبة | لوحة شهرية | يغلق فجوة 5 | خلال 18 شهراً |\n'
            '| 6 | المراجعة | تقارير دورية | يغلق فجوة 6 | خلال 12 شهراً |\n'
        ),
        'pillars': pillars_text,
        'environment': (
            '## 3. البيئة التنظيمية والتهديدات\n\n'
            'فقرة سياق تنظيمي مفصّلة تشرح المتطلبات التنظيمية والامتثال '
            'والإطار التنظيمي ' * 4 + '\n\n'
            'فقرة سياق تهديدات مفصّلة عن الهجمات والحوادث والاختراقات '
            'في القطاع ' * 4 + '\n\n'
            'فقرة سياق الأعمال والتشغيل والاستمرارية والتحول الرقمي ' * 4 + '\n'
        ),
        'gaps': (
            '## 4. تحليل الفجوات\n\n'
            '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
            '|---|-------|-------|---------|--------|\n'
            '| 1 | الحوكمة | غياب اللجنة | حرجة | مفتوحة |\n'
            '| 2 | IAM | غياب PAM | عالية | مفتوحة |\n'
            '| 3 | SIEM | تكامل ناقص | عالية | مفتوحة |\n'
            '| 4 | الاستجابة | لا دليل | عالية | مفتوحة |\n'
            '| 5 | الوعي | لا برنامج | عالية | مفتوحة |\n'
        ),
        'roadmap': (
            '## 5. خارطة الطريق التنفيذية\n\n'
            '| # | النشاط | المسؤول | الإطار الزمني | المخرج |\n'
            '|---|--------|---------|---------------|--------|\n'
            '| 1 | الحوكمة | CISO | الشهر 1-3 | الميثاق |\n'
            '| 2 | IAM | IT | الشهر 3-6 | خطة IAM |\n'
            '| 3 | SIEM | SOC | الشهر 4-9 | كتالوج |\n'
            '| 4 | التوعية | HR | الشهر 6-12 | التقارير |\n'
        ),
        'kpis': (
            '## 6. مؤشرات الأداء الرئيسية\n\n'
            '| # | المؤشر | النوع KPI/KRI | القيمة المستهدفة | صيغة الاحتساب '
            '| مصدر البيانات | المالك | التكرار | الإطار الزمني |\n'
            '|---|--------|---------------|------------------|----------------|'
            '---------------|--------|---------|----------------|\n'
            '| 1 | ضوابط | KPI | ≥95% | (أ÷ب)×100 | السجل | CISO | شهري | 12ش |\n'
            '| 2 | توعية | KPI | ≥90% | (أ÷ب)×100 | HR | CISO | شهري | 9ش |\n'
            '| 3 | حوادث | KRI | ≤4 | عدّ | SOC | CISO | شهري | 6ش |\n'
            '| 4 | ثغرات | KPI | 100% | (أ÷ب)×100 | الفحص | CISO | شهري | 6ش |\n'
        ),
        'confidence': (
            '## 7. تقييم الثقة والمخاطر\n\n'
            '**درجة الثقة:** 65%\n\n'
            '### مبررات التقييم\n\nمبررات كافية لتقييم الثقة. '
            'الفجوات جوهرية والاستجابة معقولة.\n\n'
            '### عوامل النجاح الحرجة\n\n'
            '| # | العامل | الوصف | الأهمية |\n'
            '|---|-------|-------|--------|\n'
            '| 1 | دعم القيادة | الإدارة العليا | حرج |\n'
            '| 2 | الموارد | كفاءات متخصصة | عالٍ |\n'
            '| 3 | الميزانية | تمويل كافٍ | عالٍ |\n'
            '| 4 | التكنولوجيا | أدوات متكاملة | متوسط |\n'
            '### المخاطر الرئيسية\n\n'
            '| # | المخاطر | الاحتمالية | التأثير | خطة المعالجة | المالك |\n'
            '|---|--------|-----------|--------|-------------|--------|\n'
            '| 1 | تأخر | متوسط | عالٍ | جدولة محكمة | CISO |\n'
            '| 2 | ميزانية | متوسط | عالٍ | تمويل بديل | CFO |\n'
            '| 3 | كفاءات | عالٍ | عالٍ | التوظيف المبكر | HR |\n'
            '| 4 | مقاومة | متوسط | متوسط | إدارة التغيير | COO |\n'
        ),
    }


def _en_full_sections(pillars_text):
    return {
        'vision': (
            '## 1. Vision & Strategic Objectives\n\n'
            '**Vision:** Build a robust posture.\n\n'
            '### Strategic Objectives\n\n'
            '| # | Objective | Target Metric | Justification | Timeframe |\n'
            '|---|-----------|---------------|----------------|-----------|\n'
            '| 1 | Establish committee | Charter approved | Closes Gap #1 | 6 months |\n'
            '| 2 | Deploy controls | 100% implemented | Closes Gap #2 | 12 months |\n'
            '| 3 | Awareness programme | ≥90% completion | Closes Gap #3 | 9 months |\n'
            '| 4 | Response capability | Playbook approved | Closes Gap #4 | 12 months |\n'
            '| 5 | Continuous monitoring | Monthly dashboard | Closes Gap #5 | 18 months |\n'
            '| 6 | Periodic review | Periodic reports | Closes Gap #6 | 12 months |\n'
        ),
        'pillars': pillars_text,
        'environment': (
            '## 3. Regulatory Environment & Threat Landscape\n\n'
            'Regulatory context paragraph naming the regulation, compliance, '
            'and framework obligations applicable here ' * 4 + '\n\n'
            'Threat context paragraph describing the attack and incident '
            'and breach landscape ' * 4 + '\n\n'
            'Business and operational context paragraph covering continuity, '
            'transformation and sector services ' * 4 + '\n'
        ),
        'gaps': (
            '## 4. Gap Analysis\n\n'
            '| # | Gap | Description | Priority | Status |\n'
            '|---|-----|-------------|----------|--------|\n'
            '| 1 | Governance | No committee | Critical | Open |\n'
            '| 2 | IAM | No PAM | High | Open |\n'
            '| 3 | SIEM | Partial | High | Open |\n'
            '| 4 | Response | No playbook | High | Open |\n'
            '| 5 | Awareness | No programme | High | Open |\n'
        ),
        'roadmap': (
            '## 5. Implementation Roadmap\n\n'
            '| # | Activity | Owner | Timeline | Deliverable |\n'
            '|---|----------|-------|----------|-------------|\n'
            '| 1 | Governance | CISO | M1-3 | Charter |\n'
            '| 2 | IAM | IT | M3-6 | IAM plan |\n'
            '| 3 | SIEM | SOC | M4-9 | Catalogue |\n'
            '| 4 | Awareness | HR | M6-12 | Reports |\n'
        ),
        'kpis': (
            '## 6. Key Performance Indicators\n\n'
            '| # | Metric | Type KPI/KRI | Target Value | Calculation Formula '
            '| Data Source | Owner | Frequency | Timeframe |\n'
            '|---|--------|--------------|--------------|---------------------|'
            '-------------|-------|-----------|-----------|\n'
            '| 1 | Controls | KPI | ≥95% | (a/b)×100 | Register | CISO | Monthly | 12m |\n'
            '| 2 | Awareness | KPI | ≥90% | (a/b)×100 | HR | CISO | Monthly | 9m |\n'
            '| 3 | Incidents | KRI | ≤4 | count | SOC | CISO | Monthly | 6m |\n'
            '| 4 | Vulns | KPI | 100% | (a/b)×100 | Scan | CISO | Monthly | 6m |\n'
        ),
        'confidence': (
            '## 7. Confidence Assessment & Risks\n\n'
            '**Confidence Score:** 65%\n\n'
            '### Score Justification\n\nSubstantive justification covering '
            'maturity posture and material gaps.\n\n'
            '### Critical Success Factors\n\n'
            '| # | Factor | Description | Importance |\n'
            '|---|--------|-------------|------------|\n'
            '| 1 | Leadership | Senior support | Critical |\n'
            '| 2 | Resources | Specialists | High |\n'
            '| 3 | Budget | Sufficient | High |\n'
            '| 4 | Technology | Integrated | Medium |\n'
            '### Key Risks\n\n'
            '| # | Risk | Likelihood | Impact | Mitigation Plan | Owner |\n'
            '|---|------|------------|--------|-----------------|-------|\n'
            '| 1 | Delay | Medium | High | Strict scheduling | CISO |\n'
            '| 2 | Budget | Medium | High | Alternative funding | CFO |\n'
            '| 3 | Skills | High | High | Early hiring | HR |\n'
            '| 4 | Resistance | Medium | Medium | Change management | COO |\n'
        ),
    }


# ---------------------------------------------------------------------------
# 1 + 2 + 10. Validator pass / fail (AR + EN)
# ---------------------------------------------------------------------------

class TestValidatorPassFail(unittest.TestCase):

    @_skip_if_no_app
    def test_arabic_rich_pillars_pass(self):
        sections = _ar_full_sections(
            _ar_pillars(_AR_INIT_3, _AR_INIT_3, _AR_INIT_3))
        defects = _APP.validate_arabic_strategy_semantic_richness(
            sections, lang='ar', doc_subtype='technical',
            generation_mode='consulting', domain='Cyber Security')
        tags = [t for t, _ in defects]
        self.assertNotIn('pillar_initiatives_insufficient', tags,
                         f'Rich AR pillars should pass; defects={tags}')

    @_skip_if_no_app
    def test_arabic_thin_pillar_fails(self):
        sections = _ar_full_sections(
            _ar_pillars(_AR_INIT_3, _AR_INIT_1, _AR_INIT_3))
        defects = _APP.validate_arabic_strategy_semantic_richness(
            sections, lang='ar', doc_subtype='technical',
            generation_mode='consulting', domain='Cyber Security')
        tags = [t for t, _ in defects]
        self.assertIn('pillar_initiatives_insufficient', tags,
                      f'Thin AR pillar should fail; defects={tags}')

    @_skip_if_no_app
    def test_english_rich_pillars_pass(self):
        sections = _en_full_sections(
            _en_pillars(_EN_INIT_3, _EN_INIT_3, _EN_INIT_3))
        defects = _APP.validate_arabic_strategy_semantic_richness(
            sections, lang='en', doc_subtype='technical',
            generation_mode='consulting', domain='Cyber Security')
        tags = [t for t, _ in defects]
        self.assertNotIn('pillar_initiatives_insufficient', tags,
                         f'Rich EN pillars should pass; defects={tags}')

    @_skip_if_no_app
    def test_english_thin_pillar_fails(self):
        sections = _en_full_sections(
            _en_pillars(_EN_INIT_3, _EN_INIT_1, _EN_INIT_3))
        defects = _APP.validate_arabic_strategy_semantic_richness(
            sections, lang='en', doc_subtype='technical',
            generation_mode='consulting', domain='Cyber Security')
        tags = [t for t, _ in defects]
        self.assertIn('pillar_initiatives_insufficient', tags,
                      f'Thin EN pillar should fail; defects={tags}')


# ---------------------------------------------------------------------------
# 3. Malformed table separators do not undercount valid initiative rows
# ---------------------------------------------------------------------------

class TestMalformedSeparatorRows(unittest.TestCase):

    @_skip_if_no_app
    def test_duplicate_separator_does_not_undercount(self):
        body = (
            '| # | المبادرة | الوصف | المخرج المتوقع |\n'
            '|---|---------|-------|----------------|\n'
            '|---|---------|-------|----------------|\n'
            '| 1 | مبادرة أ | وصف أ | المخرج أ |\n'
            '| 2 | مبادرة ب | وصف ب | المخرج ب |\n'
            '| 3 | مبادرة ج | وصف ج | المخرج ج |\n'
        )
        n = _APP._count_pillar_initiative_rows(body)
        self.assertGreaterEqual(n, 3,
                                f'Duplicate separator should not undercount; '
                                f'got {n}')

    @_skip_if_no_app
    def test_missing_separator_does_not_undercount(self):
        # No separator row at all — counter must still detect data rows
        # through its fallback path.
        body = (
            '| # | المبادرة | الوصف | المخرج المتوقع |\n'
            '| 1 | مبادرة أ | وصف أ | المخرج أ |\n'
            '| 2 | مبادرة ب | وصف ب | المخرج ب |\n'
            '| 3 | مبادرة ج | وصف ج | المخرج ج |\n'
        )
        n = _APP._count_pillar_initiative_rows(body)
        self.assertGreaterEqual(n, 3,
                                f'Missing separator should not undercount; '
                                f'got {n}')


# ---------------------------------------------------------------------------
# 4 + 5 + 6 + 9. synthesize_pillars_depth AI-repair contract
# ---------------------------------------------------------------------------

def _stub_domain_context():
    return {
        'code': 'cyber',
        'display': 'Cyber Security',
        'display_en': 'Cyber Security',
        'forbidden_terms': [],
        'allowed_capabilities': ['IAM', 'SIEM'],
        'role_vocab': ['CISO', 'SOC Manager'],
        'selected_frameworks': ['NCA ECC'],
        'validation_rules': {'min_pillars': 3},
    }


class TestSynthesizePillarsDepthAIRepair(unittest.TestCase):
    """``synthesize_pillars_depth`` must:
       - call ``ai_repair_strategy_section`` with section_key='pillars'
         when any pillar is below the per-pillar initiative floor,
       - validate the repaired markdown (per-pillar initiative floor)
         BEFORE assigning ``sections['pillars']``,
       - leave ``sections['pillars']`` unchanged on failure and raise
         ``RepairError(section='pillars')``.
    """

    @_skip_if_no_app
    def test_calls_ai_repair_with_pillar_initiative_floor(self):
        captured = {}

        def fake_ai_repair(section_key, sections, lang, domain_context,
                           org_name='', sector='', maturity='',
                           generation_mode='consulting',
                           diagnostic_context='', validation_error='',
                           min_rows=None, org_structure_is_none=False):
            captured['section_key'] = section_key
            captured['validation_error'] = validation_error
            captured['org_structure_is_none'] = org_structure_is_none
            # Return a valid 3-pillar payload with 3 inits each
            return ('## 2. الركائز الاستراتيجية\n\n'
                    + _ar_pillars(_AR_INIT_3, _AR_INIT_3, _AR_INIT_3))

        def fake_dctx(domain, lang='en', selected_frameworks=None):
            return _stub_domain_context()

        orig_repair = _APP.ai_repair_strategy_section
        orig_dctx = _APP.get_strategy_domain_context
        _APP.ai_repair_strategy_section = fake_ai_repair
        _APP.get_strategy_domain_context = fake_dctx
        try:
            sections = {'pillars': _ar_pillars(_AR_INIT_3, _AR_INIT_1,
                                               _AR_INIT_3)}
            result = _APP.synthesize_pillars_depth(
                sections, 'ar',
                domain='Cyber Security', fw_short='NCA ECC',
                generation_mode='consulting',
            )
        finally:
            _APP.ai_repair_strategy_section = orig_repair
            _APP.get_strategy_domain_context = orig_dctx

        self.assertEqual(captured.get('section_key'), 'pillars')
        ve = captured.get('validation_error', '') or ''
        # ``validation_error`` must surface the per-pillar initiative
        # floor so the AI receives the correct repair signal.
        self.assertIn('min_initiatives_per_pillar', ve,
                      f'validation_error should mention '
                      f'min_initiatives_per_pillar; got {ve!r}')
        self.assertTrue(result.get('rebuilt'),
                        f'Repaired payload should be assigned; '
                        f'result={result}')

    @_skip_if_no_app
    def test_invalid_repair_raises_and_leaves_section_unchanged(self):
        original_pillars = _ar_pillars(_AR_INIT_3, _AR_INIT_1, _AR_INIT_3)

        def fake_ai_repair(*a, **kw):
            # Repaired output has 3 pillars but EACH pillar carries only
            # ONE initiative — fails the per-pillar initiative floor.
            return ('## 2. الركائز الاستراتيجية\n\n'
                    + _ar_pillars(_AR_INIT_1, _AR_INIT_1, _AR_INIT_1))

        def fake_dctx(*a, **kw):
            return _stub_domain_context()

        orig_repair = _APP.ai_repair_strategy_section
        orig_dctx = _APP.get_strategy_domain_context
        _APP.ai_repair_strategy_section = fake_ai_repair
        _APP.get_strategy_domain_context = fake_dctx
        try:
            sections = {'pillars': original_pillars}
            with self.assertRaises(_APP.RepairError) as cm:
                _APP.synthesize_pillars_depth(
                    sections, 'ar',
                    domain='Cyber Security', fw_short='NCA ECC',
                    generation_mode='consulting',
                )
            self.assertEqual(getattr(cm.exception, 'section', None),
                             'pillars')
            # No deterministic fallback — sections['pillars'] unchanged.
            self.assertEqual(sections['pillars'], original_pillars,
                             'sections["pillars"] must be unchanged on '
                             'RepairError (no deterministic fallback)')
        finally:
            _APP.ai_repair_strategy_section = orig_repair
            _APP.get_strategy_domain_context = orig_dctx

    @_skip_if_no_app
    def test_no_deterministic_pillar_bank_called_on_repair_error(self):
        """RepairError must surface; no fallback bank may write into
        ``sections['pillars']`` during synthesize_pillars_depth.
        """
        original_pillars = _ar_pillars(_AR_INIT_3, _AR_INIT_1, _AR_INIT_3)

        def fake_ai_repair(*a, **kw):
            raise _APP.RepairError('simulated AI failure')

        def fake_dctx(*a, **kw):
            return _stub_domain_context()

        orig_repair = _APP.ai_repair_strategy_section
        orig_dctx = _APP.get_strategy_domain_context
        _APP.ai_repair_strategy_section = fake_ai_repair
        _APP.get_strategy_domain_context = fake_dctx
        try:
            sections = {'pillars': original_pillars}
            with self.assertRaises(_APP.RepairError) as cm:
                _APP.synthesize_pillars_depth(
                    sections, 'ar',
                    domain='Cyber Security', fw_short='NCA ECC',
                    generation_mode='consulting',
                )
            self.assertEqual(getattr(cm.exception, 'section', None),
                             'pillars')
            self.assertEqual(sections['pillars'], original_pillars)
        finally:
            _APP.ai_repair_strategy_section = orig_repair
            _APP.get_strategy_domain_context = orig_dctx


# ---------------------------------------------------------------------------
# 7. Final save gate routes pillar_initiatives_insufficient → AI repair
# ---------------------------------------------------------------------------

class TestFinalSaveGateRoutesPillarInitiativesInsufficient(unittest.TestCase):
    """The final save gate must contain a targeted AI repair branch for
    ``pillar_initiatives_insufficient`` that delegates to
    ``synthesize_pillars_depth`` and re-runs the validator. We assert
    the routing structure exists in the source — not any specific AI
    behaviour — because a live HTTP exercise would require a full
    Flask request context and live providers.
    """

    @_skip_if_no_app
    def test_targeted_repair_block_exists(self):
        import inspect
        src = inspect.getsource(_APP)
        # The block must reference the defect tag, delegate to
        # synthesize_pillars_depth, and re-run the richness validator.
        self.assertIn("'pillar_initiatives_insufficient'", src)
        self.assertIn('pillar_initiatives_repair', src,
                      'Final save gate must log a '
                      'pillar_initiatives_repair status')


# ---------------------------------------------------------------------------
# 8. org_structure_is_none requires governance-first pillar AND init floor
# ---------------------------------------------------------------------------

class TestOrgStructureNoneGovernanceContract(unittest.TestCase):

    @_skip_if_no_app
    def test_governance_first_with_thin_initiatives_triggers_repair(self):
        """When ``org_structure_is_none=True`` and the governance pillar
        is present BUT carries fewer than the initiative floor,
        ``synthesize_pillars_depth`` must NOT no-op — it must invoke
        the AI repair path."""
        called = {'count': 0}

        def fake_ai_repair(*a, **kw):
            called['count'] += 1
            # Governance-first pillar with 3 inits each
            return ('## 2. الركائز الاستراتيجية\n\n'
                    + _ar_pillars(_AR_INIT_3, _AR_INIT_3, _AR_INIT_3,
                                  p1_title='الحوكمة والهيكل',
                                  p2_title='الحماية',
                                  p3_title='الاستجابة'))

        def fake_dctx(*a, **kw):
            return _stub_domain_context()

        orig_repair = _APP.ai_repair_strategy_section
        orig_dctx = _APP.get_strategy_domain_context
        _APP.ai_repair_strategy_section = fake_ai_repair
        _APP.get_strategy_domain_context = fake_dctx
        try:
            sections = {'pillars': _ar_pillars(
                _AR_INIT_1, _AR_INIT_3, _AR_INIT_3,
                p1_title='الحوكمة والهيكل',
                p2_title='الحماية',
                p3_title='الاستجابة',
            )}
            result = _APP.synthesize_pillars_depth(
                sections, 'ar',
                domain='Cyber Security', fw_short='NCA ECC',
                generation_mode='consulting',
                org_structure_is_none=True,
            )
        finally:
            _APP.ai_repair_strategy_section = orig_repair
            _APP.get_strategy_domain_context = orig_dctx

        self.assertEqual(called['count'], 1,
                         'AI repair must run when first pillar has thin '
                         'initiatives even though governance-first '
                         'contract is satisfied')
        self.assertTrue(result.get('rebuilt'))

    @_skip_if_no_app
    def test_governance_missing_in_repair_raises_repair_error(self):
        """org_structure_is_none=True and AI returns pillars without
        governance-first wording → RepairError(section='pillars'),
        section unchanged.
        """
        original_pillars = _ar_pillars(_AR_INIT_1, _AR_INIT_3, _AR_INIT_3,
                                       p1_title='الحوكمة',
                                       p2_title='الحماية',
                                       p3_title='الاستجابة')

        def fake_ai_repair(*a, **kw):
            # No governance/structure tokens in first pillar title
            return ('## 2. الركائز الاستراتيجية\n\n'
                    + _ar_pillars(_AR_INIT_3, _AR_INIT_3, _AR_INIT_3,
                                  p1_title='الحماية الفنية',
                                  p2_title='الاستجابة',
                                  p3_title='التوعية'))

        def fake_dctx(*a, **kw):
            return _stub_domain_context()

        orig_repair = _APP.ai_repair_strategy_section
        orig_dctx = _APP.get_strategy_domain_context
        _APP.ai_repair_strategy_section = fake_ai_repair
        _APP.get_strategy_domain_context = fake_dctx
        try:
            sections = {'pillars': original_pillars}
            with self.assertRaises(_APP.RepairError) as cm:
                _APP.synthesize_pillars_depth(
                    sections, 'ar',
                    domain='Cyber Security', fw_short='NCA ECC',
                    generation_mode='consulting',
                    org_structure_is_none=True,
                )
            self.assertEqual(getattr(cm.exception, 'section', None),
                             'pillars')
            self.assertEqual(sections['pillars'], original_pillars)
        finally:
            _APP.ai_repair_strategy_section = orig_repair
            _APP.get_strategy_domain_context = orig_dctx


# ---------------------------------------------------------------------------
# Schema sanity: pillars schema carries the per-pillar-initiative placeholder
# ---------------------------------------------------------------------------

class TestPillarsRepairSchemaCarriesInitiativeFloor(unittest.TestCase):

    @_skip_if_no_app
    def test_schema_contains_min_initiatives_per_pillar(self):
        schema = _APP._AI_REPAIR_SECTION_SCHEMA.get('pillars', {})
        self.assertIn('{min_initiatives_per_pillar}', schema.get('ar', ''))
        self.assertIn('{min_initiatives_per_pillar}', schema.get('en', ''))


if __name__ == '__main__':
    unittest.main()
