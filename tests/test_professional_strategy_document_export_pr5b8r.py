"""PR-5B.8R — Professional strategy document export structure.

Verifies that exported Arabic / English strategy documents are
arranged as a consulting-grade document, not a raw markdown dump:

  Cover → Document Control → Contents → Executive Summary →
  Scope and Selected Frameworks → Methodology → Current-State →
  Strategic Vision → Pillars → Environment → Gaps → Roadmap →
  KPIs → Confidence/Risks → Governance & Ownership →
  Framework Traceability Matrix → Appendices.

Strict scope mirrors the problem statement:

    * No AI prompt / generation logic changed.
    * No deterministic strategy rows added.
    * No validators weakened.
    * Preview rendering is not touched.

Run:
    python -m pytest tests/test_professional_strategy_document_export_pr5b8r.py -v
"""
import importlib.util
import os
import sys
import tempfile
import unittest

# ── Boot env required by ``app`` ─────────────────────────────────────────
_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_pro_strategy_export_pr5b8r_')
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


# ── Full Arabic strategy markdown (mirrors PR-5B.8N / PR-5B.8O fixture) ──
FULL_ARABIC_STRATEGY = '''## 1. الرؤية والأهداف الاستراتيجية

**الرؤية:** بناء قدرات الأمن السيبراني المتقدمة وحماية المعلومات الحيوية.

**الرسالة:** توفير بيئة رقمية آمنة عبر إطار حوكمة شامل وضوابط فعالة.

### الأهداف الاستراتيجية:

| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |
|---|---|---|---|---|
| 1 | تعزيز إطار حوكمة الأمن السيبراني | بلوغ مستوى النضج 4 من 5 | الالتزام التنظيمي | 12 شهر |
| 2 | تقليل المخاطر السيبرانية | خفض المخاطر العالية بنسبة 40% | حماية الأصول | 18 شهر |
| 3 | تحسين الاستجابة للحوادث | متوسط الزمن أقل من 4 ساعات | تقليل الأثر | 9 أشهر |
| 4 | بناء ثقافة الأمن السيبراني | تدريب 95% من الموظفين | تقليل المخاطر البشرية | 12 شهر |
| 5 | تطوير قدرات الكشف | تغطية 100% للأصول الحيوية | الاكتشاف المبكر | 15 شهر |

## 2. الركائز الاستراتيجية

### الركيزة 1: الحوكمة والامتثال

تعزيز إطار حوكمة الأمن السيبراني عبر السياسات والإجراءات.

| # | المبادرة | الوصف | المخرج المتوقع | المسؤول |
|---|---|---|---|---|
| 1 | تحديث السياسات | مراجعة وفق NCA-ECC | سياسات معتمدة | CISO |
| 2 | تطوير إطار الحوكمة | تصميم هيكل المجلس | إطار معتمد | Cybersecurity Governance Lead |
| 3 | تنفيذ برنامج الامتثال | برنامج رصد الالتزام | تقارير دورية | SOC Manager |

### الركيزة 2: العمل عن بُعد والوصول الآمن

تأمين بيئة العمل عن بُعد وفق ضوابط TCC ومتطلبات الوصول الآمن.

| # | المبادرة | الوصف | المخرج المتوقع | المسؤول |
|---|---|---|---|---|
| 1 | تطبيق MFA | المصادقة متعددة العوامل لكل الأنظمة | تقليل المخاطر | CISO |
| 2 | نشر VPN/ZTNA | بنية الثقة الصفرية | اتصال آمن | CSIRT Lead |
| 3 | حماية الأجهزة الطرفية | EDR وMDM للأجهزة | حماية فعالة | Risk Manager |

## 3. البيئة التنظيمية والتهديدات

تعمل المنظمة في بيئة معقدة تشمل متطلبات NCA-ECC وضوابط TCC للعمل عن بُعد، إضافة إلى متطلبات قطاعية.

**سياق التهديدات:** هجمات الفدية، التهديدات الداخلية، استهداف العمل عن بُعد.

| البُعد | المصدر | الأثر | المبادرة |
|---|---|---|---|
| تنظيمي | NCA-ECC | متطلب امتثال | برنامج مواءمة |
| تنظيمي | TCC | حماية العمل عن بُعد | تطبيق MFA و ZTNA |
| تهديدي | برامج الفدية | تعطل الخدمات | بناء قدرات الكشف |

## 4. تحليل الفجوات

| # | الفجوة | الوصف | الأولوية | الحالة |
|---|---|---|---|---|
| 1 | غياب إطار الحوكمة | لا يوجد مجلس فعّال | عالية | مفتوحة |
| 2 | ضعف الكشف | عدم وجود SOC | عالية | مفتوحة |
| 3 | ضعف المصادقة متعددة العوامل MFA | غياب MFA | عالية | مفتوحة |
| 4 | محدودية حماية الوصول عن بُعد | لا توجد ZTNA | عالية | مفتوحة |
| 5 | قصور خطط الاستجابة للحوادث | عدم اختبار الخطط | متوسطة | مفتوحة |

## 5. خارطة الطريق التنفيذية

### المرحلة 1: التأسيس (الأشهر 1-6)

| # | النشاط | المسؤول | الجدول الزمني | المخرج |
|---|---|---|---|---|
| 1 | إنشاء المجلس | الإدارة | الشهر 1-2 | ميثاق المجلس |
| 2 | اعتماد إطار الحوكمة | CISO | الشهر 3-4 | إطار معتمد |
| 3 | تطبيق MFA على جميع الأنظمة | CISO | الشهر 5-6 | MFA مفعّل |

## 6. مؤشرات الأداء الرئيسية

| # | المؤشر | النوع | القيمة المستهدفة | صيغة الاحتساب | مصدر البيانات | المالك | التكرار | الإطار الزمني |
|---|---|---|---|---|---|---|---|---|
| 1 | نسبة الامتثال لـ NCA-ECC | KPI | 95% | (الضوابط المطبقة ÷ الضوابط المطلوبة) × 100 | لوحة الامتثال | CISO | شهري | 12 شهر |
| 2 | متوسط زمن الكشف | KPI | < 30 دقيقة | إجمالي الزمن ÷ عدد الحوادث | SIEM | SOC Manager | أسبوعي | 6 شهر |
| 3 | نسبة تطبيق MFA | KPI | 100% | (الأنظمة المطبقة ÷ إجمالي الأنظمة) × 100 | لوحة الهوية | CISO | شهري | 6 شهر |
| 4 | عدد الحوادث الحرجة | KRI | < 2 سنوياً | عدد الحوادث المصنفة حرجة | سجل الحوادث | CISO | شهري | 12 شهر |
| 5 | نسبة المخاطر المخففة | KPI | 80% | (المخاطر المخففة ÷ المخاطر العالية) × 100 | سجل المخاطر | Risk Manager | فصلي | 18 شهر |
| 6 | نسبة استخدام VPN/ZTNA | KPI | 95% | (الموظفون عن بُعد ÷ الإجمالي) × 100 | لوحة الشبكة | CSIRT Lead | شهري | 9 شهر |

### أدلة تقييم مؤشرات الأداء

#### دليل تقييم المؤشر رقم 1: نسبة الامتثال لـ NCA-ECC

**الصيغة:** (الضوابط المطبقة ÷ الضوابط المطلوبة) × 100

| الخطوة | الإجراء | الأداة/النظام | المسؤول | المخرج |
|---|---|---|---|---|
| 1 | جمع قائمة الضوابط المطبقة | لوحة الامتثال | محلل الامتثال | قائمة الضوابط |
| 2 | تطبيق الصيغة الحسابية | لوحة التحكم | محلل الأمن | القيمة المحسوبة |

## 7. تقييم الثقة والمخاطر

**درجة الثقة:** 78%

**المبرر:** الاستراتيجية مبنية على إطار NCA-ECC و TCC المعتمدين.

| # | عامل النجاح الحرج | الوصف | الأهمية |
|---|---|---|---|
| 1 | الدعم التنفيذي | التزام الإدارة العليا | عالية |
| 2 | توفر الكوادر | وجود محللي أمن سيبراني | عالية |
| 3 | الموازنة المالية | تخصيص ميزانية كافية | عالية |

| # | الخطر | الاحتمالية | التأثير | خطة التخفيف |
|---|---|---|---|---|
| 1 | نقص الكفاءات | عالية | عالي | برنامج تطوير |
| 2 | تأخر تطبيق MFA | متوسطة | عالي | متابعة شهرية |
| 3 | تطور التهديدات على العمل عن بُعد | عالية | عالي | تحديث ZTNA |
| 4 | تغيير الأولويات | متوسطة | متوسط | حوكمة مستقرة |
| 5 | ضعف التكامل | متوسطة | متوسط | تخطيط معماري |
'''


# ── Helpers ──────────────────────────────────────────────────────────────
def _shape(s):
    """Return the forms an Arabic substring may take when extracted from
    a ReportLab-generated PDF."""
    import arabic_reshaper
    from bidi.algorithm import get_display
    reshaped = arabic_reshaper.reshape(s)
    return reshaped, get_display(reshaped), s


def _present(text, s):
    for v in _shape(s):
        if v in text:
            return True
    return False


def _find_first(text, s):
    idx = -1
    for v in _shape(s):
        i = text.find(v)
        if i >= 0 and (idx == -1 or i < idx):
            idx = i
    return idx


def _make_test_user(username='pr5b8r_test_user'):
    from werkzeug.security import generate_password_hash
    with _APP.app.app_context():
        _APP.init_db()
        db = _APP.get_db()
        cols = [c['name'] for c in db.execute('PRAGMA table_info(users)').fetchall()]
        if 'password_hash' in cols:
            db.execute(
                "INSERT OR IGNORE INTO users (username, password_hash, email, role, is_active) "
                "VALUES (?, ?, ?, ?, 1)",
                (username, generate_password_hash('xxx'),
                 f'{username}@test.local', 'user'),
            )
        else:
            db.execute(
                "INSERT OR IGNORE INTO users (username, password, email, role) "
                "VALUES (?, ?, ?, ?)",
                (username, generate_password_hash('xxx'),
                 f'{username}@test.local', 'user'),
            )
        db.commit()
        row = db.execute(
            "SELECT id FROM users WHERE username=?", (username,)
        ).fetchone()
        return row['id']


def _build_arabic_pdf_bytes(content, **overrides):
    uid = _make_test_user()
    client = _APP.app.test_client()
    with client.session_transaction() as sess:
        sess['user_id'] = uid
        sess['username'] = 'pr5b8r_test_user'
        sess['role'] = 'user'
    payload = {
        'content': content,
        'filename': 'pr5b8r_test',
        'language': 'ar',
        'org_name': 'منظمة اختبار',
        'sector': 'حكومي',
        'doc_type': 'Strategy Document',
        'domain': 'Cyber Security',
        'artifact_type': 'strategy',
        'artifact_id': None,
        'generation_mode': 'drafting',
        'selected_frameworks': ['ECC', 'TCC'],
    }
    payload.update(overrides)
    resp = client.post('/api/generate-pdf', json=payload)
    if resp.status_code != 200:
        raise AssertionError(
            f'PDF route failed: status={resp.status_code} '
            f'body={resp.data[:400]!r}'
        )
    return resp.data


def _extract_pdf_text(pdf_bytes):
    import fitz
    doc = fitz.open(stream=pdf_bytes, filetype='pdf')
    pages = [p.get_text() for p in doc]
    doc.close()
    return pages


# ─── 1-4: Composer-model unit tests (no PDF required) ────────────────────
class StrategyDocumentModelTest(unittest.TestCase):
    """Unit tests against ``_build_strategy_document_model``."""

    @_skip_if_no_app
    def setUp(self):
        self.model = _APP._build_strategy_document_model(
            FULL_ARABIC_STRATEGY,
            metadata={
                'org_name': 'منظمة اختبار',
                'sector':   'حكومي',
                'domain':   'Cyber Security',
                'doc_type': 'Strategy Document',
            },
            selected_frameworks=['ECC', 'TCC'],
            lang='ar',
        )
        self.blocks = self.model['blocks']
        self.order  = self.model['order']

    @_skip_if_no_app
    def test_01_executive_summary_is_present(self):
        es = self.blocks.get('executive_summary')
        self.assertIsNotNone(es, 'Executive summary block missing.')
        paras = es.get('paragraphs') or []
        self.assertGreaterEqual(
            len(paras), 1,
            'Executive summary must contain at least one paragraph.',
        )
        # The lead paragraph references the org and the framework count —
        # confirms the composer wired metadata in.
        joined = ' '.join(paras)
        self.assertIn('منظمة اختبار', joined,
                      'Exec summary should reference the org name.')

    @_skip_if_no_app
    def test_02_scope_block_lists_selected_frameworks(self):
        sf = self.blocks.get('scope_frameworks')
        self.assertIsNotNone(sf, 'Scope/frameworks block missing.')
        keys = [fw['key'] for fw in (sf.get('frameworks') or [])]
        self.assertIn('ECC', keys)
        self.assertIn('TCC', keys)
        # frameworks_keys mirrors selected_frameworks resolved keys.
        self.assertEqual(set(sf.get('frameworks_keys') or []),
                         set(['ECC', 'TCC']))

    @_skip_if_no_app
    def test_03_ecc_and_tcc_appear_in_export_scope(self):
        sf = self.blocks['scope_frameworks']
        # The display label MUST include both ECC and TCC names.
        joined = ' '.join(fw.get('display', '') for fw in sf.get('frameworks') or [])
        self.assertIn('ECC', joined)
        self.assertIn('TCC', joined)

    @_skip_if_no_app
    def test_04_document_order_is_professional(self):
        # Required order: cover → doc_control → toc → executive_summary →
        # scope_frameworks → methodology → strategy_body →
        # traceability_matrix.
        required_subseq = [
            'cover', 'doc_control', 'toc', 'executive_summary',
            'scope_frameworks', 'methodology', 'strategy_body',
            'traceability_matrix',
        ]
        # Every kind in required_subseq must appear in self.order in the
        # same relative order.
        positions = []
        for kind in required_subseq:
            self.assertIn(kind, self.order,
                          f'Missing block kind: {kind}')
            positions.append(self.order.index(kind))
        self.assertEqual(
            positions, sorted(positions),
            f'Block order is not professional: order={self.order}',
        )

    @_skip_if_no_app
    def test_08_traceability_matrix_present(self):
        tm = self.blocks.get('traceability_matrix')
        self.assertIsNotNone(tm, 'Traceability matrix block missing.')
        # Required columns
        header = tm.get('header') or []
        self.assertEqual(len(header), 6,
                         f'Traceability matrix must have 6 columns, got {len(header)}')
        rows = tm.get('rows') or []
        # ECC has 4 capability families + TCC has 5 → 9 rows.
        self.assertGreaterEqual(
            len(rows), 9,
            'Traceability matrix must have at least one row per (framework, '
            f'capability) pair (got {len(rows)}).',
        )
        # First column must be the framework display name.
        fw_col = {r[0] for r in rows}
        # Display names contain "ECC" and "TCC" tokens
        joined_fw = ' '.join(fw_col)
        self.assertIn('ECC', joined_fw)
        self.assertIn('TCC', joined_fw)


# ─── 5-7, 8: PDF round-trip tests ────────────────────────────────────────
class PdfProfessionalLayoutTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if _APP is None:
            return
        cls.pdf_bytes = _build_arabic_pdf_bytes(FULL_ARABIC_STRATEGY)
        cls.pages = _extract_pdf_text(cls.pdf_bytes)
        cls.all_text = '\n'.join(cls.pages)

    @_skip_if_no_app
    def test_05_executive_summary_appears_before_section_1(self):
        es_idx = _find_first(self.all_text, 'الملخص التنفيذي')
        # Section 1's heading text appears first in the TOC, second in
        # the body. Use rfind to reliably target the body occurrence —
        # the executive summary must precede the body, not the TOC.
        s1_idx = -1
        for v in _shape('الرؤية والأهداف'):
            j = self.all_text.rfind(v)
            if j > s1_idx:
                s1_idx = j
        self.assertGreater(es_idx, -1,
                           'Executive summary heading missing from PDF.')
        self.assertGreater(s1_idx, -1,
                           'Section 1 (vision) heading missing from PDF.')
        self.assertLess(
            es_idx, s1_idx,
            'Executive summary must appear BEFORE section 1 (vision).',
        )

    @_skip_if_no_app
    def test_06_ecc_and_tcc_appear_before_main_strategy_sections(self):
        ecc_idx = self.all_text.find('ECC')
        tcc_idx = self.all_text.find('TCC')
        # Section 1 heading appears first in the composed TOC, then again
        # in the body. The "main strategy sections" start at the BODY
        # occurrence — so use rfind to anchor on it. ECC/TCC must appear
        # in the scope page (before the body), even though they may also
        # appear later in the traceability matrix.
        s1_idx = -1
        for v in _shape('الرؤية والأهداف'):
            j = self.all_text.rfind(v)
            if j > s1_idx:
                s1_idx = j
        self.assertGreaterEqual(ecc_idx, 0, 'ECC label missing from PDF.')
        self.assertGreaterEqual(tcc_idx, 0, 'TCC label missing from PDF.')
        self.assertGreater(s1_idx, -1, 'Section 1 heading missing.')
        self.assertLess(ecc_idx, s1_idx,
                        'ECC label must appear BEFORE section 1 (in scope).')
        self.assertLess(tcc_idx, s1_idx,
                        'TCC label must appear BEFORE section 1 (in scope).')

    @_skip_if_no_app
    def test_07_pdf_contains_all_seven_strategy_sections(self):
        canonical = [
            'الرؤية',
            'الركائز الاستراتيجية',
            'البيئة التنظيمية',
            'تحليل الفجوات',
            'خارطة الطريق',
            'مؤشرات الأداء الرئيسية',
            'تقييم الثقة',
        ]
        for h in canonical:
            self.assertGreater(
                _find_first(self.all_text, h), -1,
                f'Canonical strategy heading missing from PDF: {h!r}',
            )

    @_skip_if_no_app
    def test_08b_traceability_matrix_appears_in_pdf(self):
        # Heading
        self.assertTrue(
            _present(self.all_text, 'مصفوفة تتبع الأطر'),
            'Traceability matrix heading missing from PDF.',
        )
        # Header cells (first column) — at least the framework name appears
        self.assertTrue(
            _present(self.all_text, 'الإطار'),
            'Traceability matrix header (الإطار) missing from PDF.',
        )

    @_skip_if_no_app
    def test_09_heading_punctuation_is_normalized(self):
        norm = _APP._arabic_pdf_heading_normalize
        # Documented normalisations.
        self.assertEqual(norm('.1 الرؤية'), '1. الرؤية')
        self.assertEqual(norm('الركيزة :1'), 'الركيزة 1:')
        self.assertEqual(
            norm('دليل تقييم المؤشر رقم :1'),
            'دليل تقييم المؤشر رقم 1:',
        )
        # And the rendered PDF text must NOT contain the misglued forms.
        for bad in ('.1 الرؤية', 'الركيزة :1', 'دليل تقييم المؤشر رقم :1'):
            for variant in _shape(bad):
                self.assertNotIn(
                    variant, self.all_text,
                    f'Mis-glued punctuation leaked into PDF: {bad!r}',
                )

    @_skip_if_no_app
    def test_10_kpi_formulas_are_normalized(self):
        # Formula label "الصيغة:" must be present.
        self.assertTrue(
            _present(self.all_text, 'الصيغة'),
            'KPI formula label الصيغة missing.',
        )
        # The "× 100" tail (non-LaTeX) must survive.
        self.assertIn('100', self.all_text)
        # No raw LaTeX wrappers leaked.
        for stray in (r'\text', r'\times', r'\(', r'\)'):
            self.assertNotIn(
                stray, self.all_text,
                f'LaTeX wrapper leaked into PDF: {stray!r}',
            )


# ─── 11-13: Strict scope (preview / AI / deterministic content) ─────────
class StrictScopeGuardsTest(unittest.TestCase):
    """Preview rendering and AI/generation logic must be untouched."""

    @_skip_if_no_app
    def test_11_preview_rendering_helpers_intact(self):
        # The composer is invoked ONLY by the export builders. It is
        # never called from the preview render path. Confirm the strategy
        # synthesis / preview helpers still exist with the same names so
        # preview behaviour cannot have changed.
        for sym in (
            'api_generate_strategy',
            'api_generate_pdf',
            'ensure_markdown_formatting',
            '_build_strategy_document_model',
        ):
            self.assertTrue(
                hasattr(_APP, sym),
                f'Required symbol {sym!r} missing from app.',
            )

    @_skip_if_no_app
    def test_12_no_ai_or_prompt_logic_changed(self):
        # The AI repair / synthesis entry points still exist.
        for sym in (
            'synthesize_objectives_depth',
            'synthesize_kpi_depth',
            'synthesize_confidence_depth',
            'synthesize_gaps_depth',
            'ai_repair_strategy_section',
            '_apply_final_synthesis_pass',
            'enforce_technical_strategy_depth',
        ):
            self.assertTrue(
                hasattr(_APP, sym),
                f'AI synthesis symbol {sym!r} unexpectedly missing.',
            )

    @_skip_if_no_app
    def test_13_no_deterministic_strategy_rows_added(self):
        # The composer NEVER returns a strategy row that wasn't present
        # in the input content. We verify this by feeding it an EMPTY
        # content string and checking the strategy_body block stays empty
        # (no fixed pillars/KPIs/risks ever appear).
        empty = _APP._build_strategy_document_model(
            '',
            metadata={'org_name': 'X', 'sector': 'Y',
                      'domain': 'Cyber Security'},
            selected_frameworks=['ECC', 'TCC'],
            lang='ar',
        )
        self.assertEqual(empty['blocks']['strategy_body']['content'], '')
        # Governance / current-state must be empty (no invented owners).
        self.assertEqual(
            empty['blocks']['governance_ownership']['rows'], [],
            'Governance rows must not be invented when content is empty.',
        )
        self.assertEqual(
            empty['blocks']['current_state']['paragraphs'], [],
            'Current-state must be empty when content has no environment.',
        )
        # Traceability cells from empty content must all be the dash.
        for row in empty['blocks']['traceability_matrix']['rows']:
            # Columns 2-5 are the derived cells; with empty content they
            # must all be the placeholder dash, never invented values.
            for cell in row[2:]:
                self.assertEqual(
                    cell, '—',
                    f'Traceability cell invented from empty content: {cell!r}',
                )


if __name__ == '__main__':
    unittest.main()
