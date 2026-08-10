"""REL3.3 P0 — Domain Isolation Contract across section repairs.

Non-cyber domains must never receive Cyber-primary substance from
fallback/repairers. Blank domain fails closed. Pre-save and pre-export
guards block contamination before bytes return.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel33_isolation_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_engine.kpi_substance_model import finalize_kpi_substance
from release_engine.pillar_substance_model import finalize_pillar_substance
from release_engine.traceability_substance_model import (
    build_canonical_traceability_from_registry,
    finalize_traceability_substance,
    repair_traceability_canonical_families,
)
from release_engine_v3.contracts import RenderTree
from release_engine_v3.exporters.docx_exporter import export_docx
from release_engine_v3.exporters.pdf_exporter import export_pdf
from release_engine_v3.rel32_compiler import (
    _build_gaps_section,
    _build_governance_section,
    _build_pillars_section,
    _build_traceability_section,
    compile_canonical_strategy_document,
)
from release_engine_v3.rel33_domain_guard import (
    evaluate_domain_isolation_contract,
    evaluate_pre_export_bytes_domain_guard,
    resolve_rel33_domain_or_fail,
    resolve_rel33_export_domain,
)


_WEAK = {
    'gaps': '## تحليل الفجوات\n\nفجوة عامة.\n',
    'pillars': '## الركائز الاستراتيجية\n\nركيزة ضعيفة.\n',
    'governance': '## نموذج الحوكمة\n\nدور عام.\n',
    'traceability': '## مصفوفة التتبع\n\n',
    'kpis': (
        '## مؤشرات الأداء الرئيسية\n\n'
        '| # | وصف المؤشر | النوع | القيمة المستهدفة | '
        'صيغة الاحتساب | مصدر | التكرار | المالك |\n'
        '|---|---|---|---|---|---|---|---|\n'
        '| 1 | مؤشر عام | KPI | 90% | a ÷ b × 100 | سجل | شهري | مالك |\n'
    ),
}

_CYBER_GAP_ROW = (
    '| 1 | غياب وظيفة CISO وهيكل حوكمة الأمن السيبراني | '
    'تأسيس حوكمة | عالية | مفتوحة |'
)
_CYBER_GOV_ROW = (
    '| CISO | قيادة الأمن السيبراني | الإدارة العليا | '
    'تقرير ربع سنوي | NCA ECC |'
)
_CYBER_TRACE_SNIP = 'NCA ECC'
_CYBER_PILLAR_TITLE = 'الحماية والكشف والاستجابة'


def _rt(md: str) -> RenderTree:
    return RenderTree(
        artifact_id='iso-1',
        canonical_hash='c' * 16,
        render_tree_hash='r' * 16,
        nodes=[],
        markdown_view=md,
    )


def _docx_backend(sections):
    return {
        'build_docx_bytes': lambda content, filename, lang, **kw: b'PK-docx',
        'split_sections': lambda _c: dict(sections),
        'domain': sections.get('_domain') or 'data',
    }


class Rel33DomainIsolationContractTests(unittest.TestCase):

    # ── 1–5 Data repairs ────────────────────────────────────────────────

    def test_01_data_weak_gaps_uses_ndmo_pdpl_not_cyber(self):
        text, gaps, _ = _build_gaps_section(_WEAK['gaps'], domain='data')
        frameworks = {g.framework for g in gaps}
        blob = text + ''.join(g.gap_label for g in gaps)
        self.assertIn('NDMO', frameworks)
        self.assertIn('PDPL', frameworks)
        self.assertIn('NDMO', blob)
        self.assertNotIn('CISO', blob)
        self.assertNotIn('SOC', blob)
        self.assertNotIn('CSIRT', blob)
        self.assertNotIn('NCA ECC', blob)

    def test_02_data_weak_pillars_uses_data_not_cyber(self):
        out, diag = finalize_pillar_substance(
            dict(_WEAK), lang='ar', domain='data')
        text = out.get('pillars') or ''
        self.assertIn('حوكمة البيانات', text)
        self.assertNotIn(_CYBER_PILLAR_TITLE, text)
        self.assertNotIn('CSIRT', text)
        self.assertNotIn('NCA ECC', text)
        self.assertEqual(diag.get('selected_registry'), 'data')

    def test_03_data_governance_uses_cdo_dpo_not_ciso(self):
        text, roles = _build_governance_section(domain='data')
        roles_blob = text + ' '.join(r.role for r in roles)
        self.assertTrue(
            'CDO' in roles_blob or 'حوكمة البيانات' in roles_blob)
        self.assertIn('DPO', roles_blob)
        self.assertNotIn('CISO', roles_blob)
        self.assertNotIn('SOC', roles_blob)

    def test_04_data_traceability_uses_ndmo_pdpl_not_nca(self):
        text = build_canonical_traceability_from_registry(
            lang='ar', domain='data')
        self.assertIn('NDMO', text)
        self.assertIn('PDPL', text)
        self.assertNotIn('NCA ECC', text)
        self.assertNotIn('NCA DCC', text)
        self.assertNotIn('CISO', text)

    def test_05_data_kpi_repair_never_appends_cyber_rows(self):
        out, diag = finalize_kpi_substance(
            dict(_WEAK), lang='ar', domain='data',
            backend={'domain': 'data'})
        text = out.get('kpis') or ''
        self.assertNotIn('MTTD', text)
        self.assertNotIn('MTTR', text)
        self.assertNotIn('CISO', text)
        self.assertNotIn('SIEM', text)
        self.assertTrue(diag.get('cyber_registry_blocked'))

    # ── 6–9 Data guards ─────────────────────────────────────────────────

    def test_06_data_pre_save_guard_blocks_cyber_gaps(self):
        sections = {
            'gaps': (
                '## تحليل الفجوات\n'
                '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
                '|---|---|---|---|---|\n'
                f'{_CYBER_GAP_ROW}\n'
            ),
        }
        diag = evaluate_domain_isolation_contract(
            sections, domain='data', phase='pre_save', emit=False)
        self.assertFalse(diag['contract_passed'])
        self.assertTrue(any(
            'gaps' in e and 'cyber_primary' in e
            for e in diag['blocking_errors']))

    def test_07_data_pre_export_blocks_cyber_governance(self):
        sections = {
            'governance': (
                '## نموذج الحوكمة\n'
                '| الدور | نطاق | مساءلة | تصعيد | إطار |\n'
                '|---|---|---|---|---|\n'
                f'{_CYBER_GOV_ROW}\n'
            ),
        }
        blockers = evaluate_pre_export_bytes_domain_guard(
            sections, domain='data', route='docx')
        self.assertTrue(any(
            'governance' in e and 'cyber_primary' in e for e in blockers))

    def test_08_data_pre_export_blocks_cyber_traceability(self):
        sections = {
            'traceability': (
                '## مصفوفة التتبع\n'
                f'| {_CYBER_TRACE_SNIP} | حوكمة الأمن السيبراني | '
                f'غياب وظيفة CISO | تأسيس | مؤشر | خطر |\n'
            ),
        }
        blockers = evaluate_pre_export_bytes_domain_guard(
            sections, domain='data', route='pdf')
        self.assertTrue(any(
            'traceability' in e and 'cyber_primary' in e for e in blockers))

    def test_09_data_pre_export_blocks_cyber_pillars(self):
        sections = {
            'pillars': (
                f'## الركائز\n### {_CYBER_PILLAR_TITLE}\n'
                'تشغيل SOC/SIEM وفريق CSIRT.\n'
            ),
        }
        blockers = evaluate_pre_export_bytes_domain_guard(
            sections, domain='data', route='docx')
        self.assertTrue(any(
            'pillars' in e and 'cyber_primary' in e for e in blockers))

    # ── 10–12 AI ────────────────────────────────────────────────────────

    def test_10_ai_weak_gaps_uses_sdaia_not_cyber(self):
        text, gaps, _ = _build_gaps_section(_WEAK['gaps'], domain='ai')
        blob = text + ''.join(g.gap_label for g in gaps)
        self.assertIn('SDAIA', blob)
        self.assertNotIn('CISO', blob)
        self.assertNotIn('NCA ECC', blob)

    def test_11_ai_governance_uses_ai_roles_not_ciso(self):
        text, roles = _build_governance_section(domain='ai')
        blob = text + ' '.join(r.role for r in roles)
        self.assertIn('الذكاء الاصطناعي', blob)
        self.assertNotIn('CISO', blob)
        self.assertNotIn('SOC', blob)

    def test_12_ai_kpi_repair_never_appends_cyber_tail(self):
        out, diag = finalize_kpi_substance(
            dict(_WEAK), lang='ar', domain='ai',
            backend={'domain': 'ai'})
        text = out.get('kpis') or ''
        self.assertNotIn('MTTD', text)
        self.assertNotIn('CSIRT', text)
        self.assertTrue(diag.get('cyber_registry_blocked'))

    # ── 13–14 DT / Global ───────────────────────────────────────────────

    def test_13_dt_weak_sections_never_receive_cyber(self):
        gaps_text, _, _ = _build_gaps_section('', domain='dt')
        pillars_text, _, _ = _build_pillars_section('', lang='ar', domain='dt')
        gov_text, _ = _build_governance_section(domain='dt')
        trace_text, _, _ = _build_traceability_section(
            lang='ar', domain='dt')
        blob = gaps_text + pillars_text + gov_text + trace_text
        self.assertIn('DGA', blob)
        self.assertNotIn('CISO', blob)
        self.assertNotIn('CSIRT', blob)
        self.assertNotIn('NCA ECC', blob)

    def test_14_global_gap_assessment_never_receives_cyber_strategy(self):
        text, gaps, _ = _build_gaps_section('', domain='global')
        frameworks = {g.framework for g in gaps}
        blob = text + ''.join(g.gap_label for g in gaps)
        self.assertTrue(any('أطر' in f or 'framework' in f.lower()
                            for f in frameworks))
        self.assertTrue(any('فجوة' in g.gap_label or 'تقييم' in g.gap_label
                            or 'نطاق' in g.gap_label for g in gaps))
        self.assertNotIn('SOC', blob)
        self.assertNotIn('CISO', blob)
        self.assertNotIn('NCA ECC', blob)

    # ── 15 Cyber still works ────────────────────────────────────────────

    def test_15_cyber_still_receives_cyber_substance(self):
        text, gaps, _ = _build_gaps_section('', domain='cyber')
        frameworks = {g.framework for g in gaps}
        blob = text + ''.join(g.gap_label for g in gaps)
        self.assertTrue(any('NCA' in f for f in frameworks))
        self.assertTrue(
            'CISO' in blob or 'SOC' in blob or 'CSIRT' in blob)
        out, diag = finalize_pillar_substance(
            dict(_WEAK), lang='ar', domain='cyber')
        self.assertNotEqual(diag.get('action_taken'), 'skipped_non_cyber')
        self.assertIn('حوكمة', out.get('pillars') or '')

    # ── 16 Blank domain fails closed ────────────────────────────────────

    def test_16_blank_domain_fails_closed(self):
        with self.assertRaises(ValueError) as ctx:
            finalize_pillar_substance(dict(_WEAK), lang='ar', domain='')
        self.assertIn('rel33_substance_domain_missing', str(ctx.exception))

        with self.assertRaises(ValueError) as ctx2:
            finalize_kpi_substance(
                dict(_WEAK), lang='ar', domain='', backend={})
        self.assertIn('rel33_substance_domain_missing', str(ctx2.exception))

        with self.assertRaises(ValueError) as ctx3:
            repair_traceability_canonical_families(
                dict(_WEAK), lang='ar', domain='', backend={})
        self.assertIn('rel33_substance_domain_missing', str(ctx3.exception))

        diag = evaluate_domain_isolation_contract(
            dict(_WEAK), domain='', phase='pre_save', emit=False)
        self.assertFalse(diag['contract_passed'])
        self.assertIn(
            'rel33_substance_domain_missing', diag['blocking_errors'])

    # ── 17–18 Domain resolution / renderer parity ───────────────────────

    def test_17_export_missing_request_domain_resolves_from_db(self):
        resolved = resolve_rel33_export_domain(
            request_domain='',
            db_domain='Data Management',
            content_json_domain='',
            sections_json_domain='',
            contract_meta_domain='',
        )
        self.assertEqual(resolved['resolved_domain'], 'data')
        self.assertEqual(resolved['domain_source'], 'db')
        self.assertFalse(resolved['domain_missing'])
        self.assertFalse(resolved['fallback_domain_used'])

        code = resolve_rel33_domain_or_fail({
            'request_domain': '',
            'db_domain': '',
            'contract_meta_domain': 'ai',
            'where': 'export',
        })
        self.assertEqual(code, 'ai')

        with self.assertRaises(ValueError) as ctx:
            resolve_rel33_domain_or_fail({
                'domain': '', 'request_domain': '', 'db_domain': '',
                'where': 'export',
            })
        self.assertIn('rel33_export_domain_missing', str(ctx.exception))

    def test_18_renderer_receives_same_resolved_domain(self):
        resolved = resolve_rel33_export_domain(
            request_domain='',
            db_domain='data',
            contract_meta_domain='data',
        )
        dcode = resolved['resolved_domain']
        compiled = compile_canonical_strategy_document(
            {},
            request_context={
                'lang': 'ar',
                'domain': dcode,
                'backend': {'domain': dcode, 'lang': 'ar'},
            },
        )
        meta_domain = (compiled.document.metadata or {}).get('domain')
        self.assertEqual(meta_domain, 'data')
        secs = compiled.legacy_sections or {}
        blob = '\n'.join(str(v) for v in secs.values() if isinstance(v, str))
        self.assertIn('NDMO', blob)
        self.assertNotIn('NCA ECC', blob)

    # ── 19–20 Save / export gates ───────────────────────────────────────

    def test_19_save_gate_blocks_contaminated_non_cyber(self):
        sections = {
            'gaps': f'## فجوات\n{_CYBER_GAP_ROW}\n',
            'governance': f'## حوكمة\n{_CYBER_GOV_ROW}\n',
            'pillars': f'## ركائز\n### {_CYBER_PILLAR_TITLE}\nSOC/SIEM\n',
        }
        diag = evaluate_domain_isolation_contract(
            sections, domain='data', phase='pre_save',
            repairer_name='save_gate', emit=False)
        self.assertFalse(diag['contract_passed'])
        self.assertFalse(diag['pre_save_guard_passed'])
        self.assertTrue(diag['contaminated_sections'])

    def test_20_exporters_block_contaminated_sections_before_bytes(self):
        contaminated = {
            'roadmap': (
                '## خارطة الطريق\n'
                '| المرحلة | الإطار | المبادرة | المالك | المخرج | الإطار |\n'
                '|---|---|---|---|---|---|\n'
                '| 1 | 1-6 | تمكين SOC/SIEM | CISO | مركز SOC | NCA ECC |\n'
            ),
            'governance': f'## حوكمة\n{_CYBER_GOV_ROW}\n',
            'traceability': f'## تتبع\n| {_CYBER_TRACE_SNIP} | CISO |\n',
            '_domain': 'data',
        }
        md = '\n\n'.join(
            v for k, v in contaminated.items() if not k.startswith('_'))
        docx = export_docx(
            _rt(md), lang='ar', domain='data',
            backend=_docx_backend(contaminated))
        self.assertTrue(docx.blocking_errors)
        self.assertFalse(docx.docx_bytes or docx.bytes_data)
        self.assertTrue(any('cyber_primary' in e or 'contamination' in e
                            for e in docx.blocking_errors))

        pdf = export_pdf(
            _rt(md), lang='ar', domain='data',
            backend={
                'domain': 'data',
                'split_sections': lambda _c: dict(contaminated),
                'build_pdf_bytes': lambda *a, **k: b'%PDF-1.4',
            })
        self.assertTrue(pdf.blocking_errors)
        self.assertFalse(pdf.pdf_bytes or pdf.bytes_data)
        self.assertTrue(any('cyber_primary' in e or 'contamination' in e
                            for e in pdf.blocking_errors))


if __name__ == '__main__':
    unittest.main()
