"""PR-5B.7C — Arabic strategy preview/export defect fixes.

Regression coverage for the bundle of defects described in the
"Diagnose and fix Arabic strategy preview/export defects" task:

  1. Trace/comment leak: internal HTML sentinel comments such as
     ``<!-- mizan-synth-env-v2 -->`` must NEVER appear in the canonical
     preview content, the PDF source, or the DOCX content.
  2. Arabic KPI guide title normalization:
     ``دليل تقييم المؤشر رقم :N``  →  ``دليل تقييم المؤشر رقم N:``
  3. Formula LaTeX-fragment normalization:
     ``\\text{Numerator}\\div\\text{Denominator}\\times 100\\%``  →
     ``Numerator ÷ Denominator × 100%`` (no remaining ``\\text`` /
     ``\\times`` / stray ``}`` artefacts).
  4. Pillar #1 sequence contract: ``synthesize_pillars_depth`` MUST
     reject AI output where the leading ``### الركيزة 1:`` /
     ``### Pillar 1:`` heading is missing or numbering is non-sequential.
  5. Export completeness gate: a fragmentary client payload that only
     contains KPI-guides + confidence sections must NOT be exported as
     a fragmentary PDF/DOCX — the ``_detect_canonical_sections_in_text``
     helper backs the route-level 422.
  6. Canonical assembly order: ``_assemble_canonical_from_sections``
     emits the 7 strategy sections in the canonical order
     (vision → pillars → environment → gaps → roadmap → KPIs → confidence).

Run:
    python -m pytest tests/test_arabic_preview_export_pr5b7c.py -v
"""
import importlib.util
import os
import sys
import tempfile
import unittest

_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_arabic_preview_export_pr5b7c_')
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
except (ImportError, ModuleNotFoundError) as _e:   # pragma: no cover
    print(f'[WARN] Could not import app.py: {_e}')
    _APP = None


def _skip_if_no_app(fn):
    import functools

    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        if _APP is None:
            self.skipTest('app.py not importable in this environment')
        return fn(self, *args, **kwargs)

    return wrapper


# ── 1. HTML comment / synthesizer-sentinel stripping ───────────────────────
class TestHtmlCommentStripping(unittest.TestCase):
    @_skip_if_no_app
    def test_strip_html_comments_removes_synth_env_marker(self):
        src = ('Some narrative.\n\n<!-- mizan-synth-env-v2 -->\n'
               'More narrative.\n')
        out = _APP._strip_html_comments(src)
        self.assertNotIn('<!--', out)
        self.assertNotIn('mizan-synth', out)
        self.assertIn('Some narrative', out)
        self.assertIn('More narrative', out)

    @_skip_if_no_app
    def test_strip_html_comments_also_removes_trace_tags(self):
        src = 'Cell <!-- trace:section=obj;src=diag --> rest.'
        out = _APP._strip_html_comments(src)
        self.assertNotIn('<!--', out)
        self.assertNotIn('trace:', out)

    @_skip_if_no_app
    def test_canonical_assembly_strips_synth_env_marker(self):
        secs = {
            'vision': '## 1. Vision\n\nbody.\n',
            'pillars': '### Pillar 1: Gov\n\nbody.\n',
            'environment': ('## 3. Environment\n\n'
                            '<!-- mizan-synth-env-v2 -->\n\n'
                            'paragraph here.\n'),
            'gaps': '## 4. Gaps\n\nbody.\n',
            'roadmap': '## 5. Roadmap\n\nbody.\n',
            'kpis': '## 6. KPIs\n\nbody.\n',
            'confidence': '## 7. Confidence\n\nbody.\n',
        }
        canonical = _APP._assemble_canonical_from_sections(secs)
        self.assertNotIn('<!--', canonical)
        self.assertNotIn('mizan-synth', canonical)


# ── 2. Arabic KPI guide title colon normalization ──────────────────────────
class TestArabicKpiGuideTitleNormalization(unittest.TestCase):
    @_skip_if_no_app
    def test_misplaced_colon_before_index_is_normalized(self):
        # The defect: "رقم :1" should become "رقم 1:".
        src = '#### دليل تقييم المؤشر رقم :1 اسم المؤشر\n'
        out = _APP.ensure_markdown_formatting(src)
        self.assertIn('رقم 1:', out)
        self.assertNotIn('رقم :1', out)

    @_skip_if_no_app
    def test_correct_form_is_preserved(self):
        src = '#### دليل تقييم المؤشر رقم 2: شيء\n'
        out = _APP.ensure_markdown_formatting(src)
        self.assertIn('رقم 2:', out)


# ── 3. LaTeX formula fragment normalization ────────────────────────────────
class TestFormulaLatexNormalization(unittest.TestCase):
    @_skip_if_no_app
    def test_text_macro_is_stripped(self):
        src = (r'**الصيغة:** \text{Numerator} \div \text{Denominator} '
               r'\times 100\%')
        out = _APP.ensure_markdown_formatting(src)
        self.assertNotIn(r'\text', out)
        self.assertNotIn(r'\times', out)
        self.assertNotIn(r'\div', out)
        # ÷, × glyphs survive
        self.assertIn('÷', out)
        self.assertIn('×', out)
        self.assertIn('100', out)

    @_skip_if_no_app
    def test_stray_closing_brace_is_dropped(self):
        # The defect: "\100 times}" — broken LaTeX-like fragment from AI.
        src = '**Formula:** \\100 times}'
        out = _APP.ensure_markdown_formatting(src)
        self.assertNotIn('}', out)
        self.assertNotIn(r'\100', out)
        self.assertIn('100', out)

    @_skip_if_no_app
    def test_frac_macro_becomes_division(self):
        src = r'\frac{a}{b}'
        out = _APP.ensure_markdown_formatting(src)
        self.assertNotIn(r'\frac', out)
        self.assertIn('(a)', out)
        self.assertIn('(b)', out)


# ── 4. Pillar #1 sequence contract ─────────────────────────────────────────
class TestPillarHeadingSequenceContract(unittest.TestCase):
    @_skip_if_no_app
    def test_repair_rejects_missing_pillar_one_arabic(self):
        """When ai_repair_strategy_section returns pillars whose first H3
        starts at "الركيزة 2" (no pillar 1), synthesize_pillars_depth
        must raise RepairError(section='pillars').
        """
        # Simulated AI output that satisfies the substantive-pillar count
        # but is MISSING the leading "### الركيزة 1:" heading.
        bad = (
            '### الركيزة 2: عمليات SOC\n\n'
            'فقرة سرد طويلة كافية الطول لتمرير عتبة المضمون لأنها تحتوي على '
            'تفاصيل كافية لتجاوز فحص المحتوى الموضوعي.\n\n'
            '| # | المبادرة | الوصف | المخرج المتوقع |\n'
            '|---|---|---|---|\n'
            '| 1 | بناء SOC | إنشاء فريق العمليات | تقرير شهري |\n\n'
            '### الركيزة 3: الاستجابة للحوادث\n\n'
            'فقرة سرد طويلة كافية الطول لتمرير عتبة المضمون لأنها تحتوي على '
            'تفاصيل كافية لتجاوز فحص المحتوى الموضوعي.\n\n'
            '| # | المبادرة | الوصف | المخرج المتوقع |\n'
            '|---|---|---|---|\n'
            '| 1 | إعداد خطة | إنشاء خطة استجابة | خطة موثقة |\n\n'
            '### الركيزة 4: الامتثال\n\n'
            'فقرة سرد طويلة كافية الطول لتمرير عتبة المضمون لأنها تحتوي على '
            'تفاصيل كافية لتجاوز فحص المحتوى الموضوعي.\n\n'
            '| # | المبادرة | الوصف | المخرج المتوقع |\n'
            '|---|---|---|---|\n'
            '| 1 | تدقيق | إعداد أدلة الامتثال | تقرير امتثال |\n'
        )
        sections = {'pillars': '## 2. الركائز\n\n(يحتاج إعادة بناء)\n'}

        # Patch ai_repair_strategy_section to return the bad output
        # without invoking any LLM.
        _orig_repair = _APP.ai_repair_strategy_section
        try:
            _APP.ai_repair_strategy_section = lambda **kw: bad
            with self.assertRaises(_APP.RepairError) as ctx:
                _APP.synthesize_pillars_depth(
                    sections,
                    lang='ar',
                    domain='Cyber Security',
                    fw_short='NCA ECC',
                    sector='General',
                    org_name='Org',
                    maturity='initial',
                    generation_mode='consulting',
                )
            self.assertEqual(getattr(ctx.exception, 'section', None),
                             'pillars')
            self.assertIn('Pillar 1', str(ctx.exception))
        finally:
            _APP.ai_repair_strategy_section = _orig_repair

    @_skip_if_no_app
    def test_repair_accepts_sequential_pillar_headings(self):
        good = (
            '### الركيزة 1: الحوكمة وإدارة المخاطر\n\n'
            'فقرة سرد طويلة كافية الطول لتمرير عتبة المضمون لأنها تحتوي على '
            'تفاصيل كافية لتجاوز فحص المحتوى الموضوعي.\n\n'
            '| # | المبادرة | الوصف | المخرج المتوقع |\n'
            '|---|---|---|---|\n'
            '| 1 | تأسيس مكتب الحوكمة | إنشاء لجنة توجيهية | ميثاق موثق |\n\n'
            '### الركيزة 2: عمليات SOC\n\n'
            'فقرة سرد طويلة كافية الطول لتمرير عتبة المضمون لأنها تحتوي على '
            'تفاصيل كافية لتجاوز فحص المحتوى الموضوعي.\n\n'
            '| # | المبادرة | الوصف | المخرج المتوقع |\n'
            '|---|---|---|---|\n'
            '| 1 | بناء SOC | إنشاء فريق العمليات | تقرير شهري |\n\n'
            '### الركيزة 3: الاستجابة للحوادث\n\n'
            'فقرة سرد طويلة كافية الطول لتمرير عتبة المضمون لأنها تحتوي على '
            'تفاصيل كافية لتجاوز فحص المحتوى الموضوعي.\n\n'
            '| # | المبادرة | الوصف | المخرج المتوقع |\n'
            '|---|---|---|---|\n'
            '| 1 | إعداد خطة | إنشاء خطة استجابة | خطة موثقة |\n\n'
            '### الركيزة 4: الامتثال\n\n'
            'فقرة سرد طويلة كافية الطول لتمرير عتبة المضمون لأنها تحتوي على '
            'تفاصيل كافية لتجاوز فحص المحتوى الموضوعي.\n\n'
            '| # | المبادرة | الوصف | المخرج المتوقع |\n'
            '|---|---|---|---|\n'
            '| 1 | تدقيق | إعداد أدلة الامتثال | تقرير امتثال |\n'
        )
        sections = {'pillars': '## 2. الركائز\n\n(يحتاج إعادة بناء)\n'}

        _orig_repair = _APP.ai_repair_strategy_section
        try:
            _APP.ai_repair_strategy_section = lambda **kw: good
            summary = _APP.synthesize_pillars_depth(
                sections,
                lang='ar',
                domain='Cyber Security',
                fw_short='NCA ECC',
                sector='General',
                org_name='Org',
                maturity='initial',
                generation_mode='consulting',
            )
            self.assertTrue(summary.get('rebuilt'))
            # Sanity: section was replaced with the AI output.
            self.assertIn('### الركيزة 1:', sections['pillars'])
            self.assertIn('### الركيزة 2:', sections['pillars'])
        finally:
            _APP.ai_repair_strategy_section = _orig_repair


# ── 5. Export completeness detector ────────────────────────────────────────
class TestExportCompletenessDetector(unittest.TestCase):
    @_skip_if_no_app
    def test_full_arabic_strategy_detects_all_seven_sections(self):
        secs = {
            'vision': '## 1. الرؤية والأهداف\n\nنص.\n',
            'pillars': '## 2. الركائز الاستراتيجية\n\n### الركيزة 1: ...\n',
            'environment': '## 3. البيئة التنظيمية\n\nنص.\n',
            'gaps': '## 4. تحليل الفجوات\n\nنص.\n',
            'roadmap': '## 5. خارطة الطريق\n\n### المرحلة 1\n',
            'kpis': '## 6. مؤشرات الأداء الرئيسية\n\nجدول.\n',
            'confidence': '## 7. تقييم الثقة والمخاطر\n\nنص.\n',
        }
        canonical = _APP._assemble_canonical_from_sections(secs)
        # All 7 canonical heading tokens detectable.
        found = _APP._detect_canonical_sections_in_text(canonical)
        for k in ('vision', 'pillars', 'environment', 'gaps',
                  'roadmap', 'kpis', 'confidence'):
            self.assertIn(k, found, f'missing {k} in {sorted(found)}')

    @_skip_if_no_app
    def test_kpi_guides_only_fragment_is_below_export_floor(self):
        """The exact failure mode the user reported: a fragmentary client
        payload that contains only KPI Assessment Guides + Confidence
        section must NOT meet the export-completeness floor.
        """
        fragment = (
            '### أدلة تقييم مؤشرات الأداء\n\n'
            '#### دليل تقييم المؤشر رقم 1: اسم\n\n'
            'تفاصيل الدليل.\n\n'
            '## 7. تقييم الثقة والمخاطر\n\n'
            '**درجة الثقة:** 78%\n'
        )
        found = _APP._detect_canonical_sections_in_text(fragment)
        # KPIs (via مؤشرات الأداء) + confidence — exactly 2 sections.
        self.assertLess(len(found), _APP._MIN_CANONICAL_SECTIONS_FOR_EXPORT,
                        f'fragment should be below floor; found={sorted(found)}')

    # ── PR-5B.7C.1 additions ───────────────────────────────────────────
    @_skip_if_no_app
    def test_detector_is_heading_anchored(self):
        """Substrings inside narrative / table cells must NOT count.

        The pre-PR-5B.7C.1 substring detector matched ``vision`` inside
        ``"This KPI supports the vision of …"`` and similar, which let
        a kpis+confidence fragment appear to carry 4-5 sections and
        sneak past the gate.
        """
        narrative_only = (
            '### أدلة تقييم مؤشرات الأداء\n\n'
            'This KPI supports the vision of the program. '
            'It maps to the first pillar of governance and feeds '
            'into phase 1 of the roadmap. The gap analysis showed '
            'a delta with the regulatory context.\n\n'
            '## 7. تقييم الثقة\n\nbody.\n'
        )
        found = _APP._detect_canonical_sections_in_text(narrative_only)
        # Only the two real headings (kpis + confidence) should match.
        self.assertEqual(found, {'kpis', 'confidence'},
                         f'expected exactly {{kpis,confidence}} from headings; '
                         f'got {sorted(found)}')

    @_skip_if_no_app
    def test_is_strategy_export_fragment_flags_kpi_only_payload(self):
        """The kpis+confidence fragment from the bug must be flagged."""
        fragment = (
            '### أدلة تقييم مؤشرات الأداء\n\n'
            '#### دليل تقييم المؤشر رقم 1: اسم\n\n'
            'detail.\n\n'
            '## 7. تقييم الثقة والمخاطر\n\nbody.\n'
        )
        is_frag, found, why = _APP._is_strategy_export_fragment(fragment)
        self.assertTrue(is_frag, f'fragment should be flagged; found={sorted(found)} why={why}')
        self.assertNotIn('vision', found)
        self.assertNotIn('pillars', found)

    @_skip_if_no_app
    def test_is_strategy_export_fragment_passes_full_strategy(self):
        secs = {
            'vision': '## 1. الرؤية\n\nنص.\n',
            'pillars': '## 2. الركائز\n\n### الركيزة 1: الحوكمة\n',
            'environment': '## 3. البيئة التنظيمية\n\nنص.\n',
            'gaps': '## 4. تحليل الفجوات\n\nنص.\n',
            'roadmap': '## 5. خارطة الطريق\n\n### المرحلة 1\n',
            'kpis': '## 6. مؤشرات الأداء\n\nجدول.\n',
            'confidence': '## 7. تقييم الثقة\n\nنص.\n',
        }
        canonical = _APP._assemble_canonical_from_sections(secs)
        is_frag, found, why = _APP._is_strategy_export_fragment(canonical)
        self.assertFalse(is_frag,
                         f'full strategy should NOT be flagged; '
                         f'found={sorted(found)} why={why}')


# ── 7. PR-5B.7C.1 — Arabic formula label normalization ─────────────────────
class TestArabicFormulaLabelNormalization(unittest.TestCase):
    @_skip_if_no_app
    def test_space_before_colon_inside_bold_is_collapsed(self):
        src = '** الصيغة :** (A÷B)×100'
        out = _APP.ensure_markdown_formatting(src)
        self.assertIn('**الصيغة:**', out)
        self.assertNotIn(' :**', out)

    @_skip_if_no_app
    def test_colon_outside_bold_is_moved_inside(self):
        src = '**الصيغة**: (A÷B)×100'
        out = _APP.ensure_markdown_formatting(src)
        self.assertIn('**الصيغة:**', out)
        self.assertNotIn('**:', out)

    @_skip_if_no_app
    def test_bare_label_with_extra_space_is_normalized(self):
        src = 'الصيغة : (A÷B)×100'
        out = _APP.ensure_markdown_formatting(src)
        self.assertIn('الصيغة:', out)
        self.assertNotIn('الصيغة :', out)


# ── 6. Canonical 7-section order ───────────────────────────────────────────
class TestCanonicalSevenSectionOrder(unittest.TestCase):
    @_skip_if_no_app
    def test_arabic_seven_sections_assembled_in_canonical_order(self):
        secs = {
            # Out of order in the dict — assembly must enforce the order.
            'kpis': '## 6. مؤشرات الأداء\n\nKPI body.\n',
            'vision': '## 1. الرؤية\n\nVision body.\n',
            'gaps': '## 4. تحليل الفجوات\n\nGap body.\n',
            'pillars': '## 2. الركائز\n\nPillar body.\n',
            'confidence': '## 7. تقييم الثقة\n\nConfidence body.\n',
            'environment': '## 3. البيئة\n\nEnv body.\n',
            'roadmap': '## 5. خارطة الطريق\n\nRoadmap body.\n',
        }
        canon = _APP._assemble_canonical_from_sections(secs)
        # Confirm STRATEGY_SECTION_ORDER is enforced by assembling order.
        order_markers = ['Vision body', 'Pillar body', 'Env body',
                         'Gap body', 'Roadmap body', 'KPI body',
                         'Confidence body']
        last = -1
        for marker in order_markers:
            idx = canon.find(marker)
            self.assertGreater(idx, last,
                               f'{marker!r} appears out of canonical order')
            last = idx


if __name__ == '__main__':
    unittest.main()
