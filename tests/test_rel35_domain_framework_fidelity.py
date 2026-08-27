"""REL35 — domain/framework fidelity and DGA interoperability."""

from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from professional_strategy_render import enrich_professional_blocks
from release_engine_v3.rel34_visible_output_quality import (
    collect_gap_action_tables,
    ensure_cyber_gap_action_plans,
    ensure_cyber_roadmap_coverage,
)
from release_engine_v3.rel35_domain_framework_fidelity import (
    apply_rel35_arabic_label_fixes,
    detect_visible_frameworks,
    dga_interoperability_covered,
    is_cyber_strategy,
    repair_dga_interoperability_sections,
    repair_sections_for_fidelity,
)


ROOT = Path(__file__).resolve().parents[1]


def _blob(obj) -> str:
    return str(obj or '')


def _table_blob(tables) -> str:
    parts = []
    for t in tables or []:
        parts.append(str(t.get('title') or ''))
        for row in t.get('rows') or []:
            parts.append(' '.join(str(c) for c in row))
    return ' '.join(parts)


def _blocks_blob(blocks: dict) -> str:
    parts = []
    for blk in (blocks or {}).values():
        if not isinstance(blk, dict):
            continue
        parts.append(' '.join(str(p) for p in (blk.get('paragraphs') or [])))
        parts.append(_table_blob(blk.get('tables') or []))
        parts.append(_table_blob(blk.get('gap_action_tables') or []))
        parts.append(_table_blob(blk.get('split_tables') or []))
        parts.append(str(blk.get('content') or ''))
        grid = blk.get('summary_grid') or {}
        parts.append(' '.join(str(x) for x in (grid.get('frameworks') or [])))
        for entry in (blk.get('entries') or []):
            if isinstance(entry, (tuple, list)):
                parts.append(' '.join(str(x) for x in entry))
            else:
                parts.append(str(entry))
    return ' '.join(parts)


def _data_sections() -> dict:
    return {
        'vision': (
            '| # | الهدف | المبرر | المالك |\n'
            '|---|---|---|---|\n'
            '| 1 | حوكمة البيانات | NDMO | CDO |\n'
        ),
        'pillars': (
            '### ركيزة حوكمة البيانات\n'
            '| المبادرة | الوصف | المخرج المتوقع | المسؤول |\n'
            '|---|---|---|---|\n'
            '| لجنة البيانات | تفعيل NDMO | إطار معتمد | CDO |\n'
        ),
        'environment': 'متطلبات NDMO وPDPL لحوكمة البيانات والخصوصية.',
        'gaps': (
            '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
            '|---|---|---|---|---|\n'
            '| 1 | ضعف حوكمة البيانات | لا لجنة بيانات | عالية | مفتوحة |\n'
        ),
        'roadmap': (
            '| المرحلة | الفترة | المبادرة | المسؤول | المخرج المتوقع | الإطار |\n'
            '|---|---|---|---|---|---|\n'
            '| المرحلة 1 | 1-6 أشهر | تأسيس حوكمة البيانات | CDO | إطار NDMO | NDMO |\n'
            '| المرحلة 2 | 7-18 شهر | تفعيل PDPL | مسؤول حماية البيانات الشخصية | سجل معالجة | PDPL |\n'
        ),
        'kpis': (
            'أ. أدلة تقييم مؤشرات الأداء\n'
            '| # | وصف المؤشر | النوع | القيمة المستهدفة | صيغة الاحتساب | مصدر | التكرار | المالك |\n'
            '|---|---|---|---|---|---|---|---|\n'
            '| 1 | اكتمال الكتالوج | KPI | ≥ 90% | الأصول في الكتالوج / الحرجة × 100 | كتالوج البيانات | ربع سنوي | مدير البيانات الوصفية والكتالوج |\n'
            '| 2 | جودة البيانات | KPI | ≥ 90% | السجلات السليمة / الكلي × 100 | منصة جودة البيانات | شهري | مدير جودة البيانات |\n'
            '| # | المؤشر | صيغة الاحتساب | مصدر البيانات |\n'
            '|---|---|---|---|\n'
            '| 1 | اكتمال الكتالوج | الأصول في الكتالوج / الحرجة × 100 | كتالوج البيانات |\n'
        ),
        'confidence': (
            '| العامل | الوزن | التقييم | المساهمة |\n'
            '|---|---|---|---|\n'
            '| اكتمال المدخلات | 20% | جيد | 16% |\n'
        ),
        'governance': 'CDO ومدير حوكمة البيانات ومسؤول حماية البيانات الشخصية.',
        'traceability': (
            '| الإطار | الضابط | الهدف | الفجوة |\n'
            '|---|---|---|---|\n'
            '| NDMO | الحوكمة | لجنة بيانات | ضعف الحوكمة |\n'
            '| PDPL | الخصوصية | سجل معالجة | فجوة RoPA |\n'
        ),
    }


def _ai_sections() -> dict:
    return {
        'vision': (
            '| # | الهدف | المبرر | المالك |\n'
            '|---|---|---|---|\n'
            '| 1 | حوكمة الذكاء الاصطناعي | SDAIA | رئيس حوكمة الذكاء الاصطناعي |\n'
        ),
        'pillars': (
            '### ركيزة حوكمة الذكاء الاصطناعي\n'
            '| المبادرة | الوصف | المخرج المتوقع | المسؤول |\n'
            '|---|---|---|---|\n'
            '| سياسة AI | حوكمة SDAIA | سياسة معتمدة | رئيس حوكمة الذكاء الاصطناعي |\n'
        ),
        'environment': 'متطلبات الهيئة السعودية للبيانات والذكاء الاصطناعي SDAIA.',
        'gaps': (
            '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
            '|---|---|---|---|---|\n'
            '| 1 | ضعف حوكمة النماذج | لا سجل نماذج | عالية | مفتوحة |\n'
        ),
        'roadmap': (
            '| المرحلة | الفترة | المبادرة | المسؤول | المخرج المتوقع | الإطار |\n'
            '|---|---|---|---|---|---|\n'
            '| المرحلة 1 | 1-6 أشهر | تأسيس حوكمة الذكاء الاصطناعي | رئيس حوكمة الذكاء الاصطناعي | سياسة SDAIA | SDAIA |\n'
            '| المرحلة 2 | 7-18 شهر | تشغيل مخاطر النماذج | مدير مخاطر النماذج | سجل نماذج | SDAIA |\n'
        ),
        'kpis': (
            'أ. أدلة تقييم مؤشرات الأداء\n'
            '| # | وصف المؤشر | النوع | القيمة المستهدفة | صيغة الاحتساب | مصدر | التكرار | المالك |\n'
            '|---|---|---|---|---|---|---|\n'
            '| 1 | تغطية سجل النماذج | KPI | 100% | النماذج المسجلة / المنتجة × 100 | سجل النماذج | ربع سنوي | مدير مخاطر النماذج |\n'
            '| # | المؤشر | صيغة الاحتساب | مصدر البيانات |\n'
            '|---|---|---|---|\n'
            '| 1 | تغطية سجل النماذج | النماذج المسجلة / المنتجة × 100 | سجل النماذج |\n'
        ),
        'confidence': (
            '| العامل | الوزن | التقييم | المساهمة |\n'
            '|---|---|---|---|\n'
            '| نضج الحوكمة | 20% | جيد | 16% |\n'
        ),
        'governance': 'رئيس حوكمة الذكاء الاصطناعي ومسؤول الإشراف البشري.',
        'traceability': (
            '| الإطار | الضابط | الهدف | الفجوة |\n'
            '|---|---|---|---|\n'
            '| SDAIA | الحوكمة | سياسة AI | ضعف الحوكمة |\n'
        ),
    }


def _dt_sections() -> dict:
    return {
        'vision': (
            '| # | الهدف | المبرر | المالك |\n'
            '|---|---|---|---|\n'
            '| 1 | رقمنة الخدمات | DGA | مدير التحول الرقمي |\n'
        ),
        'pillars': '### ركيزة القنوات الرقمية\nخدمات رقمية.',
        'environment': 'متطلبات هيئة الحكومة الرقمية.',
        'gaps': (
            '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
            '|---|---|---|---|---|\n'
            '| 1 | ضعف الرقمنة | خدمات ورقية | عالية | مفتوحة |\n'
        ),
        'roadmap': (
            '| المرحلة | الفترة | المبادرة | المسؤول | المخرج المتوقع | الإطار |\n'
            '|---|---|---|---|---|---|\n'
            '| المرحلة 1 | 1-6 أشهر | رقمنة الخدمات | مدير التحول الرقمي | خدمات إلكترونية | DGA |\n'
        ),
        'kpis': (
            '| # | وصف المؤشر | النوع | القيمة المستهدفة | صيغة الاحتساب | مصدر | التكرار | المالك |\n'
            '|---|---|---|---|---|---|---|\n'
            '| 1 | نسبة الخدمات الرقمية | KPI | ≥ 80% | الرقمية / الكلي × 100 | كتالوج الخدمات | ربع سنوي | مدير التحول الرقمي |\n'
        ),
        'confidence': '| العامل | الوزن | التقييم | المساهمة |\n|---|---|---|---|\n| الاعتماد | 20% | جيد | 16% |\n',
        'governance': 'مدير التحول الرقمي.',
        'traceability': '| الإطار | الضابط | الهدف | الفجوة |\n|---|---|---|---|\n| DGA | الخدمات | رقمنة | فجوة |\n',
    }


def _enrich(domain: str, sections: dict, selected: list) -> dict:
    model = {
        'lang': 'ar',
        'domain': domain,
        'document_type': 'strategy',
        'selected_frameworks': selected,
        'blocks': {
            'vision_objectives': {},
            'strategic_pillars': {},
            'environment_context': {},
            'gap_analysis': {},
            'roadmap': {},
            'kpi_kri_framework': {},
            'confidence_risk_register': {},
            'governance_ownership': {'rows': [['CDO', 'نطاق', 'مساءلة', 'تصعيد', 'NDMO']]},
            'traceability_matrix': {
                'rows': [
                    [selected[0] if selected else 'NDMO', 'ضابط', 'هدف',
                     'فجوة', 'مبادرة', 'مؤشر'],
                ],
            },
        },
    }
    if domain == 'data' and len(selected) > 1:
        model['blocks']['traceability_matrix']['rows'].append(
            [selected[1], 'خصوصية', 'RoPA', 'فجوة', 'مبادرة', 'مؤشر'])
    return enrich_professional_blocks(
        model, sections, {'domain': domain, 'selected_frameworks': selected}, 'ar')


class TestRel35Helpers(unittest.TestCase):
    def test_cyber_helpers_do_not_run_for_other_domains(self):
        self.assertFalse(is_cyber_strategy('data', 'strategy'))
        self.assertFalse(is_cyber_strategy('ai', 'strategy'))
        self.assertFalse(is_cyber_strategy('dt', 'strategy'))
        self.assertFalse(is_cyber_strategy('global', 'strategy'))
        self.assertFalse(is_cyber_strategy('erm', 'risk'))
        self.assertFalse(is_cyber_strategy('', 'strategy'))
        self.assertTrue(is_cyber_strategy('cyber', 'strategy'))
        self.assertTrue(is_cyber_strategy('cybersecurity', 'strategy'))
        rows = [['P1', '1-6', 'حوكمة البيانات', 'CDO', 'سياسة', 'PDPL']]
        self.assertEqual(
            ensure_cyber_roadmap_coverage(rows, 'ar', domain='data'), rows)
        self.assertEqual(
            ensure_cyber_gap_action_plans([], 'ar', domain='ai'), [])

    def test_arabic_label_fixes(self):
        self.assertEqual(
            apply_rel35_arabic_label_fixes('المسؤولإشراف البشري', 'ar'),
            'مسؤول الإشراف البشري')
        self.assertEqual(
            apply_rel35_arabic_label_fixes('المسؤولوصفية', 'ar'),
            'مدير البيانات الوصفية')
        self.assertEqual(
            apply_rel35_arabic_label_fixes('سجلمعالجة', 'ar'),
            'سجل\u00a0معالجة')


class TestRel35DataFidelity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = _enrich('data', _data_sections(), ['NDMO', 'PDPL'])
        cls.blocks = cls.model.get('blocks') or {}
        cls.visible = _blocks_blob(cls.blocks)

    def test_data_has_no_nca_in_core_sections(self):
        road = _table_blob((self.blocks.get('roadmap') or {}).get('tables'))
        kpi = _table_blob((self.blocks.get('kpi_kri_framework') or {}).get('tables'))
        gov = _blob(self.blocks.get('governance_ownership'))
        trace = _table_blob(
            (self.blocks.get('traceability_matrix') or {}).get('split_tables')
            or (self.blocks.get('traceability_matrix') or {}).get('tables'))
        appx = _table_blob(collect_gap_action_tables(self.blocks))
        for blob in (road, kpi, gov, trace, appx, self.visible):
            self.assertNotIn('NCA ECC', blob)
            self.assertNotIn('NCA DCC', blob)

    def test_data_has_ndmo_pdpl_traceability(self):
        blob = _table_blob(
            (self.blocks.get('traceability_matrix') or {}).get('split_tables')
            or []) + _data_sections()['traceability']
        self.assertIn('NDMO', blob)
        self.assertIn('PDPL', blob)

    def test_data_has_no_unselected_nist_csf(self):
        leaked = dict(_data_sections())
        leaked['environment'] += (
            '\nإطار NIST Cybersecurity Framework (NIST CSF).')
        repaired, _ = repair_sections_for_fidelity(
            leaked, domain='data', document_type='strategy',
            selected_frameworks=['NDMO', 'PDPL'], lang='ar')
        blob = '\n'.join(str(v) for v in repaired.values())
        self.assertNotIn('NIST CSF', blob)
        self.assertNotIn('NIST Cybersecurity Framework', blob)
        self.assertNotIn('NIST AI RMF', blob)

    def test_data_roadmap_is_data_privacy_only(self):
        road = _table_blob((self.blocks.get('roadmap') or {}).get('tables'))
        self.assertTrue(any(tok in road for tok in ('NDMO', 'PDPL', 'بيانات', 'CDO')))
        self.assertNotIn('SOC', road)
        self.assertNotIn('CSIRT', road)
        self.assertNotIn('CISO', road)

    def test_data_kpi_sources_are_not_cyber(self):
        kpi = _table_blob((self.blocks.get('kpi_kri_framework') or {}).get('tables'))
        self.assertNotIn('SIEM', kpi)
        self.assertNotIn('SOAR', kpi)
        self.assertNotIn('SOC', kpi)
        self.assertNotIn('CISO', kpi)

    def test_data_appendix_owners_are_not_cyber_team(self):
        appx = _table_blob(collect_gap_action_tables(self.blocks))
        self.assertNotIn('فريق الأمن السيبراني', appx)
        self.assertNotIn('CISO', appx)


class TestRel35AiFidelity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        leaked = _ai_sections()
        leaked['environment'] += (
            '\nNIST AI RMF and NIST CSF and NIST Cybersecurity Framework '
            'and NCA ECC / NCA DCC SOC/SIEM.')
        leaked['roadmap'] += (
            '\n| المرحلة 2 | 7-18 شهر | تشغيل SOC/SIEM | CISO | مركز SOC | NCA ECC |')
        repaired, cls.diag = repair_sections_for_fidelity(
            leaked, domain='ai', document_type='strategy',
            selected_frameworks=['SDAIA'], lang='ar')
        cls.model = _enrich('ai', repaired, ['SDAIA'])
        cls.blocks = cls.model.get('blocks') or {}
        cls.visible = _blocks_blob(cls.blocks) + str(repaired)

    def test_ai_sdaia_only_has_no_nca(self):
        self.assertNotIn('NCA ECC', self.visible)
        self.assertNotIn('NCA DCC', self.visible)

    def test_ai_sdaia_only_has_no_nist_unless_selected(self):
        self.assertNotIn('NIST AI RMF', self.visible)
        self.assertNotIn('NIST_AI_RMF', self.visible)
        self.assertNotIn('NIST CSF', self.visible)
        self.assertNotIn('NIST Cybersecurity Framework', self.visible)

    def test_ai_roadmap_is_ai_governance_only(self):
        road = _table_blob((self.blocks.get('roadmap') or {}).get('tables'))
        self.assertTrue(any(tok in road for tok in (
            'SDAIA', 'نماذج', 'MLOps', 'ذكاء')))
        self.assertNotIn('CSIRT', road)
        self.assertNotIn('SOC/SIEM', road)

    def test_ai_human_oversight_label_is_clean(self):
        dirty = apply_rel35_arabic_label_fixes('المسؤولإشراف البشري', 'ar')
        self.assertEqual(dirty, 'مسؤول الإشراف البشري')
        self.assertIn('مسؤول الإشراف البشري', self.visible)

    def test_ai_appendix_has_no_cyber_fallback_owners(self):
        appx = _table_blob(collect_gap_action_tables(self.blocks))
        self.assertNotIn('فريق الأمن السيبراني', appx)
        self.assertNotIn('CISO', appx)


class TestRel35CyberUnchanged(unittest.TestCase):
    def test_cyber_helpers_still_expand(self):
        rows = ensure_cyber_roadmap_coverage(
            [['المرحلة 1', '1-6 أشهر', 'تعيين CISO', 'CISO',
              'هيكل معتمد', 'NCA ECC']],
            'ar', domain='cyber', document_type='strategy')
        self.assertGreaterEqual(len(rows), 8)
        blob = ' '.join(' '.join(r) for r in rows)
        self.assertIn('NCA ECC', blob)
        self.assertIn('NCA DCC', blob)
        self.assertFalse(any('family:' in ' '.join(r) for r in rows))

    def test_cyber_enrich_keeps_nca_scope(self):
        from domains._registry import get_domain_pack
        pack = get_domain_pack('cyber')
        sections = dict(pack['fixtures_ar'].technical_sections())
        model = _enrich('cyber', sections, ['NCA ECC', 'NCA DCC'])
        visible = _blocks_blob(model.get('blocks') or {})
        self.assertIn('NCA ECC', visible)
        self.assertIn('NCA DCC', visible)
        road = ((model.get('blocks') or {}).get('roadmap') or {}).get('tables') or []
        rows = (road[0].get('rows') if road else []) or []
        self.assertGreaterEqual(len(rows), 8)


class TestRel35DgaCoverage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repaired, cls.diag = repair_sections_for_fidelity(
            _dt_sections(), domain='dt', document_type='strategy',
            selected_frameworks=['DGA'], lang='ar')

    def test_dga_interop_in_pillars(self):
        self.assertTrue(
            any(tok in (self.repaired.get('pillars') or '')
                for tok in ('التشغيل البيني', 'التكامل الحكومي')))

    def test_dga_interop_in_environment(self):
        self.assertTrue(
            any(tok in (self.repaired.get('environment') or '')
                for tok in ('التشغيل البيني', 'التكامل الحكومي')))

    def test_dga_interop_in_gaps(self):
        self.assertTrue(
            any(tok in (self.repaired.get('gaps') or '')
                for tok in ('التشغيل البيني', 'التكامل الحكومي')))

    def test_dga_interop_in_roadmap(self):
        self.assertTrue(
            any(tok in (self.repaired.get('roadmap') or '')
                for tok in ('التشغيل البيني', 'التكامل الحكومي',
                            'تكامل الخدمات الحكومية', 'الربط البيني')))

    def test_dga_interop_in_kpis(self):
        self.assertTrue(
            any(tok in (self.repaired.get('kpis') or '')
                for tok in ('التشغيل البيني', 'قابلية التشغيل البيني')))

    def test_no_dga_interop_missing_after_repair(self):
        self.assertTrue(dga_interoperability_covered(self.repaired))
        self.assertNotIn(
            'selected_framework_coverage_missing:DGA:interoperability',
            self.diag.get('blocking_errors') or [])
        buf = io.StringIO()
        with redirect_stdout(buf):
            os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
            os.environ.setdefault('SECRET_KEY', 'test-secret-key')
            os.environ.setdefault(
                'DATABASE_URL', 'sqlite:///' + os.path.join(
                    tempfile.mkdtemp(prefix='test_rel35_dga_'), 'test.db'))
            os.environ.setdefault('OPENAI_API_KEY', '')
            if 'app' in sys.modules and hasattr(
                    sys.modules['app'],
                    '_compute_missing_selected_framework_coverage'):
                app_mod = sys.modules['app']
            else:
                import importlib.util
                spec = importlib.util.spec_from_file_location(
                    'app', ROOT / 'app.py')
                app_mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(app_mod)
                sys.modules['app'] = app_mod
            missing = app_mod._compute_missing_selected_framework_coverage(
                self.repaired, ['DGA'],
                domain='Digital Transformation', lang='ar')
        interop = [
            m for m in missing
            if m[0] == 'DGA' and m[1] == 'interoperability']
        self.assertEqual(interop, [], missing)


class TestRel35CyberKpiExtractability(unittest.TestCase):
    def test_cyber_kpi_pdf_extractable(self):
        from domains._registry import get_domain_pack
        from release_engine_v3.canonical_document import clear_artifact_registry
        from release_engine_v3.rel31_authority import rel3_export_authoritative
        from release_engine_v3.rel32_frozen_export_lock import (
            clear_rel32_frozen_export_lock,
        )
        from release_engine_v3.rel32_kpi_main_schema_evidence import (
            evaluate_kpi_main_schema_from_pdf_bytes,
        )

        tmp = tempfile.mkdtemp(prefix='test_rel35_')
        os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
        os.environ.setdefault('SECRET_KEY', 'test-secret-key')
        os.environ.setdefault(
            'DATABASE_URL', 'sqlite:///' + os.path.join(tmp, 'test.db'))
        os.environ.setdefault('OPENAI_API_KEY', '')
        os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')
        if 'app' in sys.modules and hasattr(
                sys.modules['app'], '_rel31_backend_callables'):
            app_mod = sys.modules['app']
        else:
            import importlib.util
            spec = importlib.util.spec_from_file_location('app', ROOT / 'app.py')
            app_mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(app_mod)
            sys.modules['app'] = app_mod
        clear_rel32_frozen_export_lock()
        clear_artifact_registry()
        pack = get_domain_pack('cyber')
        sections = dict(pack['fixtures_ar'].technical_sections())
        content = app_mod._assemble_canonical_from_sections(sections)
        backend = app_mod._rel31_backend_callables()
        art = {
            'sections': sections,
            'final_markdown': content,
            'domain': 'Cyber Security',
            'document_type': 'strategy',
            'strategy_id': 'rel35-cyber-fidelity',
            'artifact_id': 'rel35-cyber-fidelity',
            'contract_meta': {
                'lang': 'ar',
                'domain': 'cyber',
                'document_type': 'strategy',
            },
        }
        flags = {'rel3': True, 'rel31': True}
        kwargs = {
            'filename': 'rel35-cyber.pdf',
            'lang': 'ar',
            'domain': 'Cyber Security',
            'selected_frameworks': ['NCA ECC', 'NCA DCC'],
            'doc_type': 'Strategy Document',
        }
        pdf, ev = rel3_export_authoritative(
            'pdf', art, backend=backend, flags=flags, export_kwargs=kwargs)
        self.assertTrue(ev.export_return_allowed, ev.blocking_errors)
        pdf_kpi = evaluate_kpi_main_schema_from_pdf_bytes(
            pdf.pdf_bytes or b'', route_name='pdf')
        self.assertTrue(pdf_kpi.get('kpi_main_schema_passed'), pdf_kpi)
        self.assertGreaterEqual(int(pdf_kpi.get('row_count') or 0), 8)


class TestRel35SmokeMatrix(unittest.TestCase):
    def test_p1_routes_and_smokes(self):
        from release_engine_v3.rel33_authority import REL33_P1_ROUTES
        from release_engine_v3.rel33_quality_matrix import (
            ensure_test_env,
            run_rel33_quality_case,
            run_rel33_quality_matrix,
        )
        ensure_test_env()
        accepted = {}
        for case in REL33_P1_ROUTES:
            row = run_rel33_quality_case(case)
            key = f"{case['domain']}:{case['document_type']}"
            accepted[key] = bool(row.get('accepted'))
        self.assertTrue(accepted.get('cyber:strategy'), accepted)
        self.assertTrue(accepted.get('data:strategy'), accepted)
        self.assertTrue(accepted.get('ai:strategy'), accepted)
        self.assertTrue(accepted.get('dt:strategy'), accepted)
        self.assertTrue(accepted.get('erm:risk'), accepted)
        self.assertTrue(accepted.get('global:gap_assessment'), accepted)
        matrix = run_rel33_quality_matrix()
        self.assertTrue(matrix.get('all_p1_accepted'), {
            'p1_accepted_count': matrix.get('p1_accepted_count'),
            'p1_size': matrix.get('p1_size'),
            'failed': [
                (r.get('route_key'), r.get('blockers'))
                for r in (matrix.get('rows') or [])
                if r.get('tier') == 'P1' and not r.get('accepted')
            ],
        })


if __name__ == '__main__':
    unittest.main()
