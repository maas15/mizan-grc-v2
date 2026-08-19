"""REL34 — visible DOCX/PDF presentation-quality hardening."""

from __future__ import annotations

import unittest
from copy import deepcopy

from professional_strategy_render import (
    apply_final_arabic_cleanup_to_blocks,
    compute_pdf_export_layout_fallbacks,
    enrich_professional_blocks,
    prepare_final_render_text,
)
from release_engine_v3.rel34_visible_output_quality import (
    CYBER_GAP_ACTION_CATALOG,
    CYBER_ROADMAP_CATALOG,
    KPI_SUBHEAD_FORMULA,
    KPI_SUBHEAD_GUIDES,
    KPI_SUBHEAD_MAIN,
    apply_rel34_arabic_cleanup,
    count_structured_rows,
    ensure_cyber_gap_action_plans,
    ensure_cyber_roadmap_coverage,
    kpi_section_has_required_subheads,
    parity_counts_match,
    prefer_professional_tables,
    sanitize_visible_export_text,
    strip_visible_internal_markers,
    structure_kpi_section_block,
    visible_text_has_internal_markers,
)


def _base_model() -> dict:
    return {
        'lang': 'ar',
        'domain': 'cyber',
        'document_type': 'strategy',
        'blocks': {
            'vision_objectives': {},
            'strategic_pillars': {},
            'environment_context': {},
            'gap_analysis': {},
            'roadmap': {},
            'kpi_kri_framework': {},
            'confidence_risk_register': {},
            'governance_ownership': {},
            'traceability_matrix': {},
        },
        'selected_frameworks': [
            'NCA ECC (Essential Cybersecurity Controls)',
            'NCA DCC (Data Cybersecurity Controls)',
        ],
    }


_KPI_SECTION = """
### أدلة تقييم مؤشرات الأداء

- تغطية المؤشرات للحوكمة والمراقبة.

| # | وصف المؤشر | النوع | القيمة المستهدفة | صيغة الاحتساب | مصدر | التكرار | المالك |
|---|---|---|---|---|---|---|---|
| 1 | نسبة إغلاق الثغرات الحرجة | KPI | ≥ 95% | الثغرات المغلقة / المكتشفة × 100 | منصة الثغرات | شهري | مدير الثغرات |
| 2 | متوسط زمن الكشف | KPI | ≤ 15 دقيقة | مجموع أزمنة الكشف / عدد الحوادث | SIEM | شهري | مدير SOC |
| 3 | تغطية MFA للحسابات المميزة | KPI | 100% | الحسابات بـ MFA / المميزة × 100 | IAM | ربع سنوي | مدير IAM |
| 4 | نسبة إكمال التوعية | KPI | ≥ 95% | المكتملون / المستهدفون × 100 | نظام التعلم | ربع سنوي | مدير التوعية |
| 5 | زمن احتواء الحادث | KPI | ≤ 4 ساعات | مجموع أزمنة الاحتواء / الحوادث | CSIRT | شهري | قائد CSIRT |
| 6 | تغطية تصنيف البيانات | KPI | ≥ 90% | الأصول المصنفة / الحرجة × 100 | سجل التصنيف | ربع سنوي | مسؤول حماية البيانات |
| 7 | حوادث DLP المغلقة | KPI | ≥ 90% | المغلقة / المكتشفة × 100 | منصة DLP | شهري | مسؤول حماية البيانات |
| 8 | نجاح اختبار النسخ | KPI | 100% | الاختبارات الناجحة / المخطط × 100 | نظام النسخ | ربع سنوي | مدير استمرارية الأعمال |
| 9 | نسبة التشفير للبيانات الحساسة | KPI | 100% | المخزن المشفر / الحساس × 100 | إدارة المفاتيح | ربع سنوي | مسؤول حماية البيانات |
| 10 | اكتمال تقارير اللجنة | KPI | 100% | التقارير المقدمة / المطلوبة × 100 | أمانة اللجنة | ربع سنوي | CISO |
| 11 | معدل معالجة التنبيهات الحقيقية | KPI | ≥ 90% | المعالجة / التنبيهات × 100 | SOC | شهري | مدير SOC |

| # | المؤشر | صيغة الاحتساب | مصدر البيانات |
|---|---|---|---|
| 1 | نسبة إغلاق الثغرات الحرجة | الثغرات المغلقة / المكتشفة × 100 | منصة الثغرات |
"""

_SHORT_ROADMAP = """
| المرحلة | الفترة | المبادرة | المالك | المخرج المتوقع | الإطار |
|---|---|---|---|---|---|
| المرحلة 1 | 1-6 أشهر | تأسيس CISO family:ciso_governance | CISO | لجنة معتمدة | NCA ECC |
| المرحلة 2 | 7-18 شهر | تشغيل SOC family:soc_siem | مدير SOC | مركز SOC | NCA ECC |
"""

_GAPS = """
| # | الفجوة | الوضع الحالي | المستهدف | التوصية |
|---|---|---|---|---|
| 1 | ضعف حوكمة CISO | لجنة غير مكتملة | حوكمة معتمدة | استكمال الميثاق |
| 2 | غياب MFA | وصول مشترك | MFA إلزامي | فرض MFA |

#### دليل تطبيق الفجوة — حوكمة CISO
1. اعتماد الميثاق
"""


class TestRel34MarkerSuppression(unittest.TestCase):
    def test_strips_family_tokens_and_snake_ids(self):
        raw = (
            'مركز SOC تشغيلي family:soc_siem | NCA ECC | '
            'family:ciso_governance vulnerability_management'
        )
        cleaned = strip_visible_internal_markers(raw)
        self.assertNotIn('family:', cleaned)
        self.assertNotIn('soc_siem', cleaned)
        self.assertNotIn('ciso_governance', cleaned)
        self.assertNotIn('vulnerability_management', cleaned)
        self.assertIn('SOC', cleaned)
        self.assertFalse(visible_text_has_internal_markers(cleaned))

    def test_prepare_final_render_text_keeps_internal_markers(self):
        # Validators still see family:* on the in-memory model.
        out = prepare_final_render_text(
            'مخرج المرحلة family:awareness_training', 'ar')
        self.assertIn('family:awareness_training', out)

    def test_visible_export_helper_strips_markers(self):
        out = sanitize_visible_export_text(
            'مخرج المرحلة family:awareness_training', 'ar')
        self.assertNotIn('family:', out)
        self.assertIn('مخرج', out)

    def test_cleanup_blocks_preserve_internal_stamps(self):
        blocks = {
            'roadmap': {
                'tables': [{
                    'schema': 'roadmap',
                    'rows': [[
                        'المرحلة 2', '7-18 شهر', 'برنامج التوعية',
                        'CISO', 'خطة توعية family:awareness_training',
                        'NCA ECC',
                    ]],
                }],
            },
        }
        cleaned = apply_final_arabic_cleanup_to_blocks(blocks, 'ar')
        blob = str(cleaned)
        self.assertIn('family:awareness_training', blob)
        self.assertIn('التوعية', blob)


class TestRel34ArabicCleanup(unittest.TestCase):
    def test_known_bad_phrases(self):
        raw = 'معدلمعالجة الحوادث و NCA DCCو NCA ECC مع المتوقع المخرج'
        out = apply_rel34_arabic_cleanup(raw, 'ar')
        self.assertNotIn('معدلمعالجة', out)
        self.assertNotIn('NCA DCCو', out)
        self.assertNotIn('المتوقع المخرج', out)
        self.assertIn('معدل', out)
        self.assertIn('معالجة', out)
        self.assertIn('المخرج المتوقع', out)
        self.assertIn('NCA ECC و NCA DCC', out)

    def test_sanitize_combines_marker_and_arabic(self):
        out = sanitize_visible_export_text(
            'معدلمعالجة family:soc_siem NCA DCCو NCA ECC', 'ar')
        self.assertNotIn('معدلمعالجة', out)
        self.assertNotIn('family:', out)
        self.assertIn('معدل', out)
        self.assertIn('معالجة', out)


class TestRel34RoadmapExpansion(unittest.TestCase):
    def test_expands_to_at_least_eight_cyber_rows(self):
        rows = [
            ['المرحلة 1', '1-6 أشهر', 'تعيين CISO', 'CISO',
             'هيكل معتمد', 'NCA ECC'],
        ]
        out = ensure_cyber_roadmap_coverage(rows, 'ar', domain='cyber')
        self.assertGreaterEqual(len(out), 8)
        self.assertLessEqual(len(out), 12)
        blob = ' '.join(' '.join(r) for r in out)
        self.assertIn('NCA ECC', blob)
        self.assertIn('NCA DCC', blob)
        self.assertTrue(any('SOC' in ' '.join(r) for r in out))
        self.assertTrue(any('توعية' in ' '.join(r) for r in out))
        self.assertTrue(any('DLP' in ' '.join(r).upper() for r in out))
        self.assertFalse(any('family:' in ' '.join(r) for r in out))

    def test_does_not_expand_data_domain(self):
        rows = [['P1', '1-6', 'حوكمة البيانات', 'CDO', 'سياسة', 'PDPL']]
        out = ensure_cyber_roadmap_coverage(rows, 'ar', domain='data')
        self.assertEqual(len(out), 1)

    def test_catalog_covers_ten_families(self):
        self.assertEqual(len(CYBER_ROADMAP_CATALOG), 10)


class TestRel34GapActionBalance(unittest.TestCase):
    def test_adds_missing_major_gap_guides(self):
        tables = ensure_cyber_gap_action_plans([], 'ar', domain='cyber')
        action = [t for t in tables if t.get('schema') == 'gap_action']
        self.assertEqual(len(action), 10)
        keys = {t.get('rel34_gap_key') for t in action}
        self.assertEqual(len(keys), 10)
        for t in action:
            self.assertGreaterEqual(len(t.get('rows') or []), 3)
            for row in t['rows']:
                self.assertTrue(all(str(c).strip() for c in row[:5]))
                self.assertNotIn('—', row[1])

    def test_catalog_has_ten_gaps(self):
        self.assertEqual(len(CYBER_GAP_ACTION_CATALOG), 10)


class TestRel34KpiSectionStructure(unittest.TestCase):
    def test_subheads_and_no_duplicate_guide_title(self):
        block = structure_kpi_section_block({
            'paragraphs': [
                'أدلة تقييم مؤشرات الأداء',
                'أدلة تقييم مؤشرات الأداء',
                'شرح التقييم',
            ],
            'tables': [
                {'schema': 'kpi_main', 'header': ['#'], 'rows': [['1']]},
                {'schema': 'kpi_formula', 'header': ['#'], 'rows': [['1']]},
            ],
        }, 'ar')
        paras = block['paragraphs']
        self.assertEqual(paras.count(KPI_SUBHEAD_GUIDES), 1)
        self.assertNotIn('أدلة تقييم مؤشرات الأداء', paras)
        titles = [t.get('title') for t in block['tables']]
        self.assertIn(KPI_SUBHEAD_MAIN, titles)
        self.assertIn(KPI_SUBHEAD_FORMULA, titles)
        blob = '\n'.join(paras + titles)
        self.assertTrue(kpi_section_has_required_subheads(blob))
        self.assertEqual(blob.count('أدلة تقييم مؤشرات الأداء'), 1)


class TestRel34TablePreferenceAndParity(unittest.TestCase):
    def test_prefers_tables_for_strategy_not_risk(self):
        fb = {
            'roadmap': 'roadmap_cards',
            'gap_action': 'gap_action_cards',
            'kpi_main': 'kpi_cards',
        }
        strat = prefer_professional_tables(
            fb, document_type='strategy', domain='cyber')
        self.assertNotIn('roadmap', strat)
        self.assertNotIn('gap_action', strat)
        self.assertIn('kpi_main', strat)
        data = prefer_professional_tables(
            fb, document_type='strategy', domain='data')
        self.assertEqual(data['roadmap'], 'roadmap_cards')
        risk = prefer_professional_tables(fb, document_type='risk')
        self.assertEqual(risk['roadmap'], 'roadmap_cards')

    def test_layout_fallback_keeps_overflow_cards_for_dense_arabic(self):
        model = {
            'document_type': 'strategy',
            'domain': 'cyber',
            'lang': 'ar',
            '_prcy86': True,
            'blocks': {
                'roadmap': {
                    'tables': [{
                        'schema': 'roadmap',
                        'rows': [['1', '2', '3', '4', '5', '6']],
                    }],
                },
            },
        }
        fb = compute_pdf_export_layout_fallbacks(model, 'ar')
        self.assertEqual(fb.get('roadmap'), 'roadmap_cards')

    def test_parity_helper(self):
        left = count_structured_rows({
            'blocks': {
                'roadmap': {'tables': [{'rows': [[1], [2]]}]},
                'kpi_kri_framework': {
                    'tables': [{'schema': 'kpi_main', 'rows': [[1]]}]},
                'vision_objectives': {},
                'strategic_pillars': {},
                'gap_analysis': {},
                'confidence_risk_register': {},
                'governance_ownership': {},
                'traceability_matrix': {},
            },
        })
        ok, defects = parity_counts_match(left, deepcopy(left))
        self.assertTrue(ok, defects)


class TestRel34EnrichmentIntegration(unittest.TestCase):
    def test_enrich_cyber_visible_quality(self):
        sections = {
            'vision': (
                '| # | الهدف | المبرر | المالك |\n'
                '|---|---|---|---|\n'
                '| 1 | تعزيز الحوكمة | فجوة CISO | CISO |\n'
            ),
            'pillars': '### ركيزة الحوكمة\nنص.\n',
            'environment': 'سياق تنظيمي.',
            'gaps': _GAPS,
            'roadmap': _SHORT_ROADMAP,
            'kpis': _KPI_SECTION.replace(
                'معدل معالجة', 'معدلمعالجة'),
            'confidence': (
                '| العامل | الوزن | التقييم | المساهمة |\n'
                '|---|---|---|---|\n'
                '| اكتمال المدخلات | 20% | جيد | 16% |\n'
            ),
            'governance': 'CISO',
            'traceability': (
                '| الإطار | الضابط | الهدف | الفجوة |\n'
                '|---|---|---|---|\n'
                '| NCA ECC | 1-1 | حوكمة | CISO |\n'
            ),
        }
        model = enrich_professional_blocks(
            _base_model(), sections, {'domain': 'cyber'}, 'ar')
        model['blocks'] = apply_final_arabic_cleanup_to_blocks(
            model['blocks'], 'ar')
        blocks = model['blocks']
        visible = sanitize_visible_export_text(str(blocks), 'ar')
        self.assertNotIn('معدلمعالجة', visible)
        self.assertNotIn('family:', visible)
        road_rows = (blocks['roadmap']['tables'][0].get('rows') or [])
        self.assertGreaterEqual(len(road_rows), 8)
        road_blob = ' '.join(' '.join(str(c) for c in r) for r in road_rows)
        self.assertIn('NCA ECC', road_blob)
        self.assertIn('NCA DCC', road_blob)
        gap_actions = [
            t for t in (blocks['gap_analysis'].get('tables') or [])
            if t.get('schema') == 'gap_action']
        self.assertGreaterEqual(len(gap_actions), 10)
        kpi = blocks['kpi_kri_framework']
        self.assertIn(KPI_SUBHEAD_GUIDES, kpi.get('paragraphs') or [])
        titles = [t.get('title') for t in kpi.get('tables') or []]
        self.assertIn(KPI_SUBHEAD_MAIN, titles)
        self.assertIn(KPI_SUBHEAD_FORMULA, titles)
        main = next(
            t for t in kpi['tables'] if t.get('schema') == 'kpi_main')
        self.assertGreaterEqual(len(main.get('rows') or []), 10)


class TestRel34CyberExportVisibleQuality(unittest.TestCase):
    """Export-level REL34 checks against the cyber strategy fixture."""

    @classmethod
    def setUpClass(cls):
        import importlib.util
        import os
        import sys
        import tempfile
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        tmp = tempfile.mkdtemp(prefix='test_rel34_export_')
        os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
        os.environ.setdefault('SECRET_KEY', 'test-secret-key')
        os.environ.setdefault(
            'DATABASE_URL', 'sqlite:///' + os.path.join(tmp, 'test.db'))
        os.environ.setdefault('OPENAI_API_KEY', '')
        os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')
        if 'app' in sys.modules and hasattr(
                sys.modules['app'], '_rel31_backend_callables'):
            cls._app = sys.modules['app']
        else:
            spec = importlib.util.spec_from_file_location(
                'app', root / 'app.py')
            cls._app = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls._app)
            sys.modules['app'] = cls._app
        cls._docx_bytes = b''
        cls._pdf_bytes = b''
        cls._docx_text = ''
        cls._pdf_text = ''
        cls._docx_ev = None
        cls._pdf_ev = None
        cls._lock = None
        cls._model_counts = None
        cls._export()

    @classmethod
    def _export(cls):
        from domains._registry import get_domain_pack
        from professional_strategy_render import (
            apply_final_arabic_cleanup_to_blocks,
            enrich_professional_blocks,
        )
        from release_engine.rendered_evidence_validator import (
            extract_docx_visible_text,
            extract_pdf_visible_text,
        )
        from release_engine_v3.canonical_document import clear_artifact_registry
        from release_engine_v3.rel31_authority import rel3_export_authoritative
        from release_engine_v3.rel32_frozen_export_lock import (
            clear_rel32_frozen_export_lock,
            emit_rel32_frozen_artifact_export_lock,
        )

        clear_rel32_frozen_export_lock()
        clear_artifact_registry()
        pack = get_domain_pack('cyber')
        sections = dict(pack['fixtures_ar'].technical_sections())
        content = cls._app._assemble_canonical_from_sections(sections)
        backend = cls._app._rel31_backend_callables()
        art = {
            'sections': sections,
            'final_markdown': content,
            'domain': 'Cyber Security',
            'document_type': 'strategy',
            'strategy_id': 'rel34-cyber-quality',
            'artifact_id': 'rel34-cyber-quality',
            'contract_meta': {
                'lang': 'ar',
                'domain': 'cyber',
                'document_type': 'strategy',
            },
        }
        flags = {'rel3': True, 'rel31': True}
        kwargs = {
            'filename': 'rel34-cyber.docx',
            'lang': 'ar',
            'domain': 'Cyber Security',
            'selected_frameworks': ['NCA ECC', 'NCA DCC'],
            'doc_type': 'Strategy Document',
        }
        docx, cls._docx_ev = rel3_export_authoritative(
            'docx', art, backend=backend, flags=flags, export_kwargs=kwargs)
        pdf, cls._pdf_ev = rel3_export_authoritative(
            'pdf', art, backend=backend, flags=flags, export_kwargs=kwargs)
        cls._docx_bytes = docx.docx_bytes or b''
        cls._pdf_bytes = pdf.pdf_bytes or b''
        cls._docx_text = extract_docx_visible_text(cls._docx_bytes)
        cls._pdf_text = extract_pdf_visible_text(cls._pdf_bytes)
        cls._lock = emit_rel32_frozen_artifact_export_lock(
            'rel34-cyber-quality')
        model = enrich_professional_blocks(
            {
                'lang': 'ar',
                'domain': 'cyber',
                'document_type': 'strategy',
                'blocks': {},
            },
            sections,
            {'domain': 'cyber'},
            'ar',
        )
        model['blocks'] = apply_final_arabic_cleanup_to_blocks(
            model.get('blocks') or {}, 'ar')
        cls._model_counts = count_structured_rows(model)
        cls._model = model

    def test_exports_allowed_and_nonempty(self):
        self.assertTrue(
            self._docx_ev.export_return_allowed, self._docx_ev.blocking_errors)
        self.assertTrue(
            self._pdf_ev.export_return_allowed, self._pdf_ev.blocking_errors)
        self.assertGreater(len(self._docx_bytes), 1000)
        self.assertGreater(len(self._pdf_bytes), 1000)

    def test_no_visible_family_markers(self):
        self.assertFalse(
            visible_text_has_internal_markers(self._docx_text),
            self._docx_text[self._docx_text.find('family:'):][:80]
            if 'family:' in self._docx_text else '')
        self.assertFalse(
            visible_text_has_internal_markers(self._pdf_text),
            self._pdf_text[self._pdf_text.find('family:'):][:80]
            if 'family:' in self._pdf_text else '')
        self.assertNotIn('family:', self._docx_text)
        self.assertNotIn('family:', self._pdf_text)

    def test_roadmap_coverage_and_frameworks(self):
        rows = (
            ((self._model.get('blocks') or {}).get('roadmap') or {})
            .get('tables') or [{}]
        )[0].get('rows') or []
        self.assertGreaterEqual(len(rows), 8)
        blob = ' '.join(' '.join(str(c) for c in r) for r in rows)
        self.assertIn('NCA ECC', blob)
        self.assertIn('NCA DCC', blob)
        visible = sanitize_visible_export_text(blob, 'ar')
        self.assertNotIn('family:', visible)

    def test_gap_action_plans_for_ten_major_gaps(self):
        tables = (
            ((self._model.get('blocks') or {}).get('gap_analysis') or {})
            .get('tables') or []
        )
        actions = [t for t in tables if t.get('schema') == 'gap_action']
        self.assertGreaterEqual(len(actions), 10)
        for t in actions:
            self.assertGreaterEqual(len(t.get('rows') or []), 3)
            for row in t['rows']:
                self.assertTrue(all(str(c).strip() for c in row[:5]))

    def test_kpi_main_extractable_and_count(self):
        from io import BytesIO
        from docx import Document
        from professional_strategy_render import (
            compute_pdf_export_layout_fallbacks,
        )
        fb = compute_pdf_export_layout_fallbacks(self._model, 'ar')
        self.assertNotEqual(fb.get('kpi_main'), 'kpi_cards')
        doc = Document(BytesIO(self._docx_bytes))
        kpi_rows = 0
        for table in doc.tables:
            hdr = [(c.text or '').strip() for c in table.rows[0].cells]
            if 'وصف المؤشر' in hdr and 'صيغة الاحتساب' in hdr:
                kpi_rows = max(kpi_rows, len(table.rows) - 1)
        self.assertGreaterEqual(kpi_rows, 10)
        self.assertGreater(len(self._pdf_bytes), 1000)

    def test_kpi_subheads_present_once(self):
        blob = self._docx_text
        self.assertIn(KPI_SUBHEAD_GUIDES, blob)
        self.assertIn(KPI_SUBHEAD_MAIN, blob)
        self.assertIn(KPI_SUBHEAD_FORMULA, blob)
        self.assertLessEqual(blob.count('أدلة تقييم مؤشرات الأداء'), 1)

    def test_arabic_cleanup_residues_absent(self):
        docx = (self._docx_text or '').replace('\u00a0', ' ')
        self.assertNotIn('معدلمعالجة', docx)
        self.assertNotIn('NCA DCCو', docx)
        self.assertNotIn('المتوقع المخرج', docx)
        pdf = (self._pdf_text or '').replace('\u00a0', ' ')
        self.assertNotIn('NCA DCCو', pdf)
        self.assertNotIn('المتوقع المخرج', pdf)

    def test_docx_pdf_parity_counts(self):
        self.assertGreaterEqual(
            int(self._model_counts.get('roadmap_rows') or 0), 8)
        self.assertGreaterEqual(
            int(self._model_counts.get('gap_action_guides') or 0), 8)
        self.assertGreaterEqual(
            int(self._model_counts.get('sections_present') or 0), 6)
        for token in (
                'خارطة الطريق', 'مؤشرات الأداء', 'تحليل الفجوات',
                'الأهداف', 'الحوكمة'):
            self.assertIn(token, self._docx_text)
        self.assertGreater(len(self._pdf_text), 200)

    def test_frozen_export_lock_remains_true(self):
        lock = self._lock or {}
        self.assertTrue(
            lock.get('export_lock_passed')
            or lock.get('frozen_artifact_loaded_for_docx')
            or lock.get('frozen_artifact_loaded_for_pdf'),
            lock)


if __name__ == '__main__':
    unittest.main()
