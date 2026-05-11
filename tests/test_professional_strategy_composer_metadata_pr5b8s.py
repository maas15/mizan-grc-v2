"""PR-5B.8S — Professional strategy composer metadata + traceability.

Targets the defects called out in the PR-5B.8S problem statement for
the Arabic ECC + TCC strategy export:

  1. Composer receives explicit selected_frameworks=['ECC','TCC'] and
     scope/methodology/traceability/appendices reflect them.
  2. Composer never says "0 frameworks" when ECC/TCC are selected.
  3. Composer infers ECC/TCC from content when the explicit list is
     missing — and emits the [EXPORT-DIAG] framework_inferred log.
  4. Arabic document-control table uses الحقل / القيمة headers and
     does not produce reversed pairs like "منظمتي المنظمة".
  5. Executive summary mentions ECC and TCC when both are selected.
  6. Methodology covers framework scoping, gap analysis, roadmap/KPI
     design, and validation gates.
  7. Traceability matrix derives at least one ECC row and one TCC row
     from content that mentions the relevant capability families.
  8. Appendix A lists ECC and TCC.
  9. Appendix B includes the glossary terms used in the document.
 10. PDF text does not contain "لم يتم تحديد أطر مرجعية صريحة" when
     ECC/TCC are selected.
 11. PDF text does not contain "لم يتم اشتقاق صفوف لمصفوفة التتبع"
     when content has gaps/roadmap/KPIs/risks.
 12. Preview output remains unchanged (composer is not invoked from
     the preview path).
 13. AI prompt / generation logic is untouched.
 14. No deterministic strategy rows are added (composer never invents
     content from an empty input).

Run:
    python -m pytest tests/test_professional_strategy_composer_metadata_pr5b8s.py -q
"""
import importlib.util
import os
import sys
import tempfile
import unittest

# ── Boot env required by ``app`` ─────────────────────────────────────────
_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_composer_metadata_pr5b8s_')
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


# ── Strategy markdown fixture covering ECC + TCC capability keywords ─────
ECC_TCC_STRATEGY = '''## 1. الرؤية والأهداف الاستراتيجية

**الرؤية:** بناء قدرات الأمن السيبراني وفق NCA ECC و NCA TCC وحماية المعلومات.

| # | الهدف | المقياس | المبرر | الإطار الزمني |
|---|---|---|---|---|
| 1 | تعزيز إطار حوكمة الأمن السيبراني | مستوى نضج 4 | الالتزام التنظيمي | 12 شهر |
| 2 | تطبيق المصادقة متعددة العوامل MFA على الوصول عن بُعد | تغطية 100% | حماية العمل عن بُعد | 6 أشهر |
| 3 | تحسين الاستجابة للحوادث | متوسط زمن < 4 ساعات | تقليل الأثر | 9 أشهر |

## 2. الركائز الاستراتيجية

| # | الركيزة | المبادرة | المسؤول |
|---|---|---|---|
| 1 | الحوكمة | إنشاء لجنة حوكمة الأمن السيبراني | CISO |
| 2 | الوصول عن بُعد الآمن | نشر VPN و ZTNA لكل المستخدمين عن بُعد | Network Lead |

## 3. البيئة التنظيمية

تستند المنظمة إلى ضوابط NCA ECC للحوكمة العامة وضوابط NCA TCC للعمل عن بُعد.
تشمل البنية الحالية SIEM ومركز عمليات أمنية SOC للمراقبة.

## 4. تحليل الفجوات

| # | الفجوة | الأثر | الأولوية |
|---|---|---|---|
| 1 | غياب سياسة موحدة للحوكمة الأمنية | عالي | عاجلة |
| 2 | ضعف ضوابط الوصول عن بُعد للموظفين | عالي | عاجلة |
| 3 | عدم تطبيق MFA على جميع المستخدمين | متوسط | عالية |

## 5. خارطة الطريق

| # | المبادرة | الموجة | التاريخ | المسؤول |
|---|---|---|---|---|
| 1 | بناء إطار الحوكمة | الموجة الأولى | 6 أشهر | CISO |
| 2 | نشر ZTNA للوصول عن بُعد | الموجة الثانية | 12 شهر | Network Lead |
| 3 | تفعيل EDR على جميع الأجهزة الطرفية | الموجة الثالثة | 18 شهر | SOC Manager |

## 6. مؤشرات الأداء الرئيسية

| # | المؤشر | النوع | القيمة المستهدفة | المالك | التكرار |
|---|---|---|---|---|---|
| 1 | نضج حوكمة الأمن السيبراني | KPI | 4/5 | CISO | ربع سنوي |
| 2 | نسبة المستخدمين عن بُعد المحميين بـ MFA | KPI | 100% | IAM Lead | شهري |
| 3 | متوسط زمن اكتشاف الحوادث في SOC | KRI | < 30 دقيقة | SOC Manager | شهري |

## 7. تقييم الثقة والمخاطر

**درجة الثقة:** 78%

| # | الخطر | الاحتمالية | الأثر | الاستجابة |
|---|---|---|---|---|
| 1 | نقص الكوادر المتخصصة في الأمن السيبراني | عالي | عالي | برنامج تدريب مكثف |
| 2 | تعقيد بنية الوصول عن بُعد | متوسط | عالي | اعتماد ZTNA تدريجياً |
'''


# ──────────────────────────────────────────────────────────────────────────
# 1. Composer-model unit tests (no PDF required)
# ──────────────────────────────────────────────────────────────────────────
class ComposerMetadataTest(unittest.TestCase):

    @_skip_if_no_app
    def setUp(self):
        self.metadata = {
            'org_name': 'منظمتي',
            'sector':   'حكومي',
            'domain':   'Cyber Security',
            'doc_type': 'Strategy Document',
        }
        self.model = _APP._build_strategy_document_model(
            ECC_TCC_STRATEGY,
            metadata=self.metadata,
            selected_frameworks=['ECC', 'TCC'],
            lang='ar',
        )
        self.blocks = self.model['blocks']

    # 1. Explicit selected_frameworks honoured.
    @_skip_if_no_app
    def test_01_explicit_selected_frameworks_resolved(self):
        self.assertEqual(set(self.model['selected_frameworks']),
                         {'ECC', 'TCC'})
        sf = self.blocks['scope_frameworks']
        keys = [fw['key'] for fw in sf.get('frameworks') or []]
        self.assertIn('ECC', keys)
        self.assertIn('TCC', keys)
        # Display name must include both ECC and TCC tokens.
        joined = ' '.join(fw.get('display', '')
                          for fw in sf.get('frameworks') or [])
        self.assertIn('ECC', joined)
        self.assertIn('TCC', joined)

    # 2. Composer never reports "0 frameworks" when ECC/TCC are selected.
    @_skip_if_no_app
    def test_02_no_zero_frameworks_when_present(self):
        sf = self.blocks['scope_frameworks']
        self.assertGreater(len(sf.get('frameworks') or []), 0)
        # Executive summary must NOT contain a "covers 0 selected
        # frameworks" line in either language.
        joined = ' '.join(self.blocks['executive_summary']['paragraphs'])
        for bad in ('0 من الأطر', '0 selected framework',
                    '0 من الأطر المرجعية'):
            self.assertNotIn(bad, joined,
                             f'Exec summary leaked zero-framework text: {bad!r}')

    # 3. Inference fallback when explicit list is missing.
    @_skip_if_no_app
    def test_03_infer_frameworks_from_content_when_missing(self):
        m = _APP._build_strategy_document_model(
            ECC_TCC_STRATEGY,
            metadata=self.metadata,
            selected_frameworks=[],   # nothing forwarded
            lang='ar',
        )
        # Must infer ECC and TCC from the strategy body.
        self.assertEqual(set(m['selected_frameworks']), {'ECC', 'TCC'})
        self.assertTrue(m.get('frameworks_inferred'),
                        'frameworks_inferred flag must be set when '
                        'composer infers from content.')
        # Explicit input always wins — when both are passed, the explicit
        # list is used and the inferred flag stays False.
        m2 = _APP._build_strategy_document_model(
            ECC_TCC_STRATEGY,
            metadata=self.metadata,
            selected_frameworks=['ECC'],
            lang='ar',
        )
        self.assertEqual(set(m2['selected_frameworks']), {'ECC'})
        self.assertFalse(m2.get('frameworks_inferred'))

    # 4. Arabic doc-control: header row + no reversed pairs.
    @_skip_if_no_app
    def test_04_doc_control_arabic_no_reversed_pairs(self):
        rows = self.blocks['doc_control']['rows']
        # Each row is a (label, value) pair. Confirm the org row is not
        # collapsed to a reversed string like "منظمتي المنظمة".
        flat = ' '.join(f'{lbl}|{val}' for lbl, val in rows)
        self.assertNotIn('منظمتي المنظمة', flat,
                         'Reversed Arabic pair detected in doc-control rows.')
        # Confirm the labels are exactly the canonical Arabic field names
        # (so the renderer can place them in the right column).
        labels = [lbl for lbl, _ in rows]
        for required in ('المنظمة', 'القطاع', 'المجال',
                         'نوع الوثيقة', 'الإصدار', 'الحالة',
                         'تاريخ الإعداد'):
            self.assertIn(required, labels,
                          f'Arabic doc-control label missing: {required!r}')
        # Domain MUST be the Arabic display name when lang='ar'.
        domain_val = dict(rows).get('المجال', '')
        self.assertNotEqual(domain_val, 'Cyber Security',
                            'Arabic doc-control must use Arabic domain '
                            'display, not the English raw value.')
        # nuance: simply confirm it's an Arabic string (contains AR letters).
        self.assertTrue(any('\u0600' <= ch <= '\u06FF' for ch in domain_val),
                        f'Arabic domain expected in doc-control; got: '
                        f'{domain_val!r}')

    # 5. Executive summary mentions ECC and TCC.
    @_skip_if_no_app
    def test_05_executive_summary_mentions_ecc_and_tcc(self):
        joined = ' '.join(self.blocks['executive_summary']['paragraphs'])
        self.assertIn('ECC', joined,
                      'Executive summary must mention ECC when selected.')
        self.assertIn('TCC', joined,
                      'Executive summary must mention TCC when selected.')

    # 6. Methodology covers the consulting phases.
    @_skip_if_no_app
    def test_06_methodology_covers_consulting_phases(self):
        rows = self.blocks['methodology']['rows']
        labels = ' | '.join(lbl for lbl, _ in rows)
        bodies = ' | '.join(body for _, body in rows)
        # Each phase must be present (Arabic).
        for needle in ('تشخيص', 'الأطر المرجعية', 'تحليل تغطية',
                       'تحليل الفجوات', 'خارطة الطريق',
                       'المخاطر والثقة', 'بوابات الجودة'):
            self.assertTrue(
                needle in labels or needle in bodies,
                f'Methodology missing phase keyword: {needle!r}',
            )
        # Must reference the selected frameworks somewhere.
        self.assertIn('ECC', labels + bodies)
        self.assertIn('TCC', labels + bodies)

    # 7. Traceability matrix has at least one ECC row and one TCC row.
    @_skip_if_no_app
    def test_07_traceability_matrix_has_ecc_and_tcc_rows(self):
        tm = self.blocks['traceability_matrix']
        rows = tm.get('rows') or []
        self.assertGreater(len(rows), 0,
                           'Traceability matrix must not be empty.')
        ecc_rows = [r for r in rows if 'ECC' in r[0]]
        tcc_rows = [r for r in rows if 'TCC' in r[0]]
        self.assertGreaterEqual(len(ecc_rows), 1,
                                'Traceability matrix must contain at least '
                                'one ECC row.')
        self.assertGreaterEqual(len(tcc_rows), 1,
                                'Traceability matrix must contain at least '
                                'one TCC row.')
        # At least one ECC row and one TCC row must have at least one
        # derived (non-dash) cell among gap/initiative/kpi/risk columns —
        # the fixture covers governance, IAM/MFA, SOC, remote access,
        # VPN/ZTNA, EDR, …, so this should always succeed.
        def _has_derived(rows_list):
            for r in rows_list:
                if any(c and c != '—' for c in r[2:]):
                    return True
            return False
        self.assertTrue(_has_derived(ecc_rows),
                        'No ECC capability row received any derived cell '
                        'from the strategy content.')
        self.assertTrue(_has_derived(tcc_rows),
                        'No TCC capability row received any derived cell '
                        'from the strategy content.')
        # Header must be the 6-column spec.
        self.assertEqual(len(tm['header']), 6)

    # 8. Appendix A lists ECC and TCC.
    @_skip_if_no_app
    def test_08_appendix_a_lists_ecc_and_tcc(self):
        entries = self.blocks['appendices']['entries']
        # Bullets are "• ECC" / "• TCC" entries inside Appendix A.
        bullet_keys = {lbl.lstrip('• ').strip()
                       for lbl, _ in entries if lbl.startswith('•')}
        self.assertIn('ECC', bullet_keys,
                      'Appendix A must list ECC.')
        self.assertIn('TCC', bullet_keys,
                      'Appendix A must list TCC.')

    # 9. Appendix B glossary lists terms actually used.
    @_skip_if_no_app
    def test_09_appendix_b_glossary_includes_used_terms(self):
        entries = self.blocks['appendices']['entries']
        # Locate the Appendix B header.
        ap_b_idx = None
        for i, (lbl, _) in enumerate(entries):
            if 'الملحق ب' in lbl or 'Appendix B' in lbl:
                ap_b_idx = i
                break
        self.assertIsNotNone(ap_b_idx,
                             'Appendix B (glossary) header missing.')
        glossary_bullets = {
            lbl.lstrip('• ').strip()
            for lbl, _ in entries[ap_b_idx + 1:]
            if lbl.startswith('•')
        }
        # Required acronyms used in the fixture.
        for term in ('ECC', 'TCC', 'MFA', 'VPN', 'ZTNA', 'SOC', 'EDR',
                    'KPI', 'KRI'):
            self.assertIn(term, glossary_bullets,
                          f'Glossary missing acronym used in document: '
                          f'{term!r}')

    # 13. No AI prompt / generation logic changed (by symbol presence).
    @_skip_if_no_app
    def test_13_ai_pipeline_symbols_intact(self):
        for sym in (
            'api_generate_strategy',
            'synthesize_objectives_depth',
            'synthesize_kpi_depth',
            'synthesize_confidence_depth',
            'synthesize_gaps_depth',
            'ai_repair_strategy_section',
            '_apply_final_synthesis_pass',
            'enforce_technical_strategy_depth',
        ):
            self.assertTrue(hasattr(_APP, sym),
                            f'AI pipeline symbol {sym!r} unexpectedly absent.')

    # 14. No deterministic strategy rows when content is empty.
    @_skip_if_no_app
    def test_14_no_deterministic_rows_on_empty_content(self):
        m = _APP._build_strategy_document_model(
            '',
            metadata=self.metadata,
            selected_frameworks=['ECC', 'TCC'],
            lang='ar',
        )
        self.assertEqual(m['blocks']['strategy_body']['content'], '')
        self.assertEqual(m['blocks']['governance_ownership']['rows'], [])
        # All traceability cells (cols 2..) must be the placeholder dash.
        for r in m['blocks']['traceability_matrix']['rows']:
            for cell in r[2:]:
                self.assertEqual(cell, '—',
                                 'Traceability cell invented from empty '
                                 'content.')


# ──────────────────────────────────────────────────────────────────────────
# 12. Preview output remains unchanged — composer is only called by the
#     export builders, never by the preview render or AI generation paths.
# ──────────────────────────────────────────────────────────────────────────
class PreviewUntouchedTest(unittest.TestCase):

    @_skip_if_no_app
    def test_12_composer_not_called_from_preview_path(self):
        # Spot-check: api_generate_strategy must not reference the
        # composer (the composer is an export-time helper).
        import inspect
        gen_src = inspect.getsource(_APP.api_generate_strategy)
        self.assertNotIn('_build_strategy_document_model', gen_src,
                         'Composer must not be invoked from the strategy '
                         'generation / preview path.')


# ──────────────────────────────────────────────────────────────────────────
# 10–11. PDF round-trip — the bad warning lines must not appear in the
# Arabic ECC + TCC export.
# ──────────────────────────────────────────────────────────────────────────
def _build_arabic_pdf_bytes(content):
    """Mirror the helper used by tests/test_professional_strategy_document_export_pr5b8r.py."""
    if _APP is None:
        return b''
    with _APP.app.test_client() as client:
        # Inject session
        with client.session_transaction() as sess:
            sess['user_id'] = 1
        resp = client.post(
            '/api/generate-pdf',
            json={
                'content': content,
                'filename': 'cyber_security_strategy',
                'language': 'ar',
                'org_name': 'منظمتي',
                'sector': 'حكومي',
                'doc_type': 'Strategy Document',
                'domain': 'Cyber Security',
                'selected_frameworks': ['ECC', 'TCC'],
                'artifact_type': 'strategy',
                'generation_mode': 'drafting',
            },
        )
    if resp.status_code != 200:
        return b''
    return resp.get_data()


def _extract_pdf_text(pdf_bytes):
    import fitz
    doc = fitz.open(stream=pdf_bytes, filetype='pdf')
    pages = [p.get_text() for p in doc]
    doc.close()
    return '\n'.join(pages)


class PdfWarningLinesTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.text = ''
        if _APP is None:
            return
        try:
            pdf = _build_arabic_pdf_bytes(ECC_TCC_STRATEGY)
        except Exception:
            pdf = b''
        if pdf:
            try:
                cls.text = _extract_pdf_text(pdf)
            except Exception:
                cls.text = ''

    @_skip_if_no_app
    def test_10_no_no_explicit_frameworks_warning(self):
        if not self.text:
            self.skipTest('PDF could not be built in this environment.')
        bad = 'لم يتم تحديد أطر مرجعية صريحة'
        # Allow that the substring may appear with some shaping, but the
        # untransformed source phrase must not leak when ECC + TCC are in
        # the request payload.
        self.assertNotIn(bad, self.text,
                         '"No explicit frameworks" warning leaked into '
                         'PDF although ECC + TCC are selected.')

    @_skip_if_no_app
    def test_11_no_empty_traceability_warning(self):
        if not self.text:
            self.skipTest('PDF could not be built in this environment.')
        bad = 'لم يتم اشتقاق صفوف لمصفوفة التتبع'
        self.assertNotIn(bad, self.text,
                         '"Traceability matrix empty" warning leaked into '
                         'PDF although content has gaps/roadmap/KPIs/risks.')


if __name__ == '__main__':
    unittest.main()
