"""REL3.3 P0 — export/render domain propagation (data roadmap purity fix).

Staging blocker: data:strategy:ar exports rendered the Cyber board-ready
roadmap (SOC/SIEM, IAM/PAM/MFA, governance CISO) plus Cyber KPIs because the
export/repair pipeline hardcoded or defaulted the domain to 'cyber' when the
domain signal was blank or ignored.

These tests pin the fix:
  1. Missing request domain resolves from DB/artifact metadata (never Cyber).
  2. The renderer receives and stamps domain=data for data artifacts.
  3. Data roadmap builds from DATA_ROADMAP_FAMILIES only.
  4. DOCX/PDF exports fail closed (rel33_export_domain_missing) on blank domain.
  5. Data DOCX/PDF exports are blocked when cyber-primary roadmap rows exist.
  6. Data DOCX/PDF exports pass with NDMO/PDPL roadmap families.
  7. Cyber exports still use Cyber roadmap families.
  8. AI KPI owners stay AI-domain; no kpi_cards fallback.
  9. DOCX export authority check still passes for the authorized pipeline.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel33_domain_prop_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_engine_v3.contracts import RenderTree
from release_engine_v3.exporters.docx_exporter import export_docx
from release_engine_v3.exporters.pdf_exporter import (
    _rel33_kpi_table_lock_flags,
    export_pdf,
)
from release_engine_v3.rel31_authority import (
    validate_rel3_roadmap_output_quality,
)
from release_engine_v3.rel32_registries import (
    DATA_ROADMAP_FAMILIES,
    resolve_roadmap_families,
)
from release_engine.roadmap_model import ROADMAP_FAMILIES
from release_engine_v3.rel33_docx_export_authority import (
    evaluate_rel33_docx_export_authority,
)
from release_engine_v3.rel33_domain_guard import (
    evaluate_pre_export_bytes_domain_guard,
    resolve_rel33_export_domain,
)


_CYBER_CONTAMINATED_ROADMAP = (
    '## خارطة الطريق التنفيذية\n'
    '| المرحلة | الإطار الزمني | المبادرة | المالك | المخرج | الإطار |\n'
    '|---|---|---|---|---|---|\n'
    '| المرحلة 1 | 1-6 أشهر | تفعيل لجنة حوكمة الأمن السيبراني | CISO | '
    'لجنة فاعلة family:governance_ciso | NCA ECC |\n'
    '| المرحلة 2 | 7-18 شهر | تشغيل SOC وSIEM | مدير SOC | '
    'مركز SOC تشغيلي family:soc_siem | NCA ECC |\n'
    '| المرحلة 2 | 7-18 شهر | تطبيق IAM/PAM/MFA | CISO | '
    'ضبط هويات family:iam_pam_mfa | NCA ECC |\n'
)

_DATA_CLEAN_ROADMAP = (
    '## خارطة الطريق التنفيذية\n'
    '| المرحلة | الإطار الزمني | المبادرة | المالك | المخرج | الإطار |\n'
    '|---|---|---|---|---|---|\n'
    '| المرحلة 1 | 1-6 أشهر | تأسيس حوكمة البيانات المؤسسية | CDO | '
    'إطار حوكمة معتمد | NDMO |\n'
    '| المرحلة 2 | 7-18 شهر | تفعيل برنامج الامتثال لنظام PDPL | '
    'مسؤول حماية البيانات | سجل معالجة وضوابط خصوصية | PDPL |\n'
    '| المرحلة 3 | 19-24 شهر | توثيق سلسلة البيانات end-to-end | '
    'مهندس بيانات | Lineage حرج موثق | NDMO |\n'
)


def _render_tree(markdown: str) -> RenderTree:
    return RenderTree(
        artifact_id='t-1',
        canonical_hash='c' * 16,
        render_tree_hash='r' * 16,
        nodes=[],
        markdown_view=markdown,
    )


def _docx_backend(sections):
    return {
        'build_docx_bytes': lambda content, filename, lang, **kw: b'PK-docx',
        'split_sections': lambda _c: dict(sections),
    }


def _pdf_backend(sections):
    return {
        'build_pdf_bytes': lambda content, **kw: b'%PDF-bytes',
        'split_sections': lambda _c: dict(sections),
    }


class Rel33DomainResolutionTests(unittest.TestCase):
    """Req 1 — DB/artifact metadata fallback; blank never becomes Cyber."""

    def test_missing_request_domain_resolves_from_db(self):
        out = resolve_rel33_export_domain(
            request_domain='', db_domain='Data Management')
        self.assertEqual(out['resolved_domain'], 'data')
        self.assertEqual(out['domain_source'], 'db')
        self.assertFalse(out['domain_missing'])
        self.assertFalse(out['fallback_domain_used'])

    def test_missing_request_domain_resolves_from_contract_meta(self):
        out = resolve_rel33_export_domain(
            request_domain='', db_domain='',
            contract_meta_domain='إدارة البيانات')
        self.assertEqual(out['resolved_domain'], 'data')
        self.assertEqual(out['domain_source'], 'contract_meta')

    def test_all_blank_is_domain_missing_not_cyber(self):
        out = resolve_rel33_export_domain()
        self.assertEqual(out['resolved_domain'], '')
        self.assertTrue(out['domain_missing'])
        self.assertNotEqual(out['resolved_domain'], 'cyber')

    def test_request_domain_wins(self):
        out = resolve_rel33_export_domain(
            request_domain='Cyber Security', db_domain='Data Management')
        self.assertEqual(out['resolved_domain'], 'cyber')
        self.assertEqual(out['domain_source'], 'request')


class Rel33RendererDomainTests(unittest.TestCase):
    """Req 2 — renderer receives and stamps domain=data."""

    def test_enrich_professional_blocks_stamps_domain(self):
        from professional_strategy_render import enrich_professional_blocks
        model = {
            'lang': 'ar',
            'blocks': {'roadmap': {'title': 'خارطة الطريق'}},
            'order': ['roadmap'],
        }
        enriched = enrich_professional_blocks(
            model, {'roadmap': _DATA_CLEAN_ROADMAP},
            {'domain': 'Data Management'}, 'ar')
        self.assertEqual(enriched.get('domain'), 'Data Management')

    def test_model_domain_takes_precedence(self):
        from professional_strategy_render import enrich_professional_blocks
        model = {
            'lang': 'ar',
            'domain': 'data',
            'blocks': {'roadmap': {'title': 'خارطة الطريق'}},
            'order': ['roadmap'],
        }
        enriched = enrich_professional_blocks(
            model, {'roadmap': _DATA_CLEAN_ROADMAP}, {}, 'ar')
        self.assertEqual(enriched.get('domain'), 'data')


class Rel33DataRoadmapFamilyTests(unittest.TestCase):
    """Req 3 + 7 — data uses DATA_ROADMAP_FAMILIES; cyber keeps cyber."""

    def test_data_families_resolved_for_data_domain(self):
        self.assertEqual(
            resolve_roadmap_families('Data Management'),
            DATA_ROADMAP_FAMILIES)
        self.assertEqual(
            resolve_roadmap_families('data'), DATA_ROADMAP_FAMILIES)

    def test_blank_domain_raises_not_cyber(self):
        with self.assertRaises(ValueError) as cm:
            resolve_roadmap_families('')
        self.assertIn('rel33_export_domain_missing', str(cm.exception))
        with self.assertRaises(ValueError):
            resolve_roadmap_families(None)

    def test_cyber_still_uses_cyber_families(self):
        self.assertEqual(resolve_roadmap_families('cyber'), ROADMAP_FAMILIES)
        self.assertEqual(
            resolve_roadmap_families('Cyber Security'), ROADMAP_FAMILIES)

    def test_compiler_data_roadmap_has_no_cyber_rows(self):
        from release_engine_v3.rel32_compiler import _build_roadmap_section
        from release_engine_v3.rel32_registries import (
            CYBER_ROADMAP_PRIMARY_MARKERS,
        )
        text, rows = _build_roadmap_section(
            '', lang='ar', domain='data',
            backend={'selected_frameworks': ['NDMO', 'PDPL']})
        self.assertGreaterEqual(len(rows), 10)
        for marker in ('تشغيل SOC وSIEM', 'تطبيق IAM/PAM/MFA',
                       'تفعيل لجنة حوكمة الأمن السيبراني'):
            self.assertNotIn(marker, text)
        hits = [m for m in CYBER_ROADMAP_PRIMARY_MARKERS if m in text]
        self.assertEqual(hits, [], f'cyber markers in data roadmap: {hits}')
        self.assertIn('NDMO', text)
        self.assertIn('PDPL', text)

    def test_roadmap_quality_validator_skips_cyber_baseline_for_data(self):
        cyber_injector_called = {'count': 0}

        def _cyber_baseline(secs, lang, fws):
            cyber_injector_called['count'] += 1
            return secs, {'gate_passed': True}

        sections = {'roadmap': _DATA_CLEAN_ROADMAP}
        out = validate_rel3_roadmap_output_quality(
            dict(sections),
            backend={
                'lang': 'ar',
                'domain': 'data',
                'baseline_roadmap': _cyber_baseline,
            })
        self.assertEqual(cyber_injector_called['count'], 0)
        blob = (out.get('sections') or {}).get('roadmap', '')
        self.assertNotIn('تشغيل SOC وSIEM', blob)
        self.assertNotIn('family:soc_siem', blob)


class Rel33FailClosedBlankDomainTests(unittest.TestCase):
    """Req 4 — blank domain fails closed for DOCX/PDF, never Cyber."""

    def test_docx_export_blocked_on_blank_domain(self):
        res = export_docx(
            _render_tree(_DATA_CLEAN_ROADMAP),
            backend=_docx_backend({'roadmap': _DATA_CLEAN_ROADMAP}),
            domain='',
        )
        self.assertEqual(res.bytes_data, b'')
        self.assertTrue(
            any('rel33_export_domain_missing' in b
                for b in res.blocking_errors),
            res.blocking_errors)

    def test_pdf_export_blocked_on_blank_domain(self):
        res = export_pdf(
            _render_tree(_DATA_CLEAN_ROADMAP),
            backend=_pdf_backend({'roadmap': _DATA_CLEAN_ROADMAP}),
            domain='',
        )
        self.assertEqual(res.bytes_data, b'')
        self.assertTrue(
            any('rel33_export_domain_missing' in b
                for b in res.blocking_errors),
            res.blocking_errors)

    def test_roadmap_quality_validator_fails_closed_on_blank_domain(self):
        out = validate_rel3_roadmap_output_quality(
            {'roadmap': _DATA_CLEAN_ROADMAP},
            backend={'lang': 'ar', 'domain': ''})
        self.assertFalse(out['valid'])
        self.assertIn('rel33_export_domain_missing', out['blocker'])

    def test_export_authority_raises_on_blank_artifact_domain(self):
        from release_engine_v3.rel31_authority import rel3_export_authoritative
        with self.assertRaises(ValueError) as cm:
            rel3_export_authoritative(
                'docx',
                {'sections': {'roadmap': _DATA_CLEAN_ROADMAP},
                 'contract_meta': {'lang': 'ar'}},
                backend={},
            )
        self.assertIn('rel33_export_domain_missing', str(cm.exception))


class Rel33DataContaminationGuardTests(unittest.TestCase):
    """Req 5 + 6 — data exports block cyber roadmap, pass NDMO/PDPL."""

    def test_pre_export_guard_blocks_cyber_primary_data_roadmap(self):
        blockers = evaluate_pre_export_bytes_domain_guard(
            {'roadmap': _CYBER_CONTAMINATED_ROADMAP},
            domain='Data Management', route='docx')
        self.assertIn('data_roadmap_cyber_contamination', blockers)

    def test_docx_export_blocked_for_contaminated_data_roadmap(self):
        res = export_docx(
            _render_tree(_CYBER_CONTAMINATED_ROADMAP),
            backend=_docx_backend({'roadmap': _CYBER_CONTAMINATED_ROADMAP}),
            domain='Data Management',
        )
        self.assertEqual(res.bytes_data, b'')
        self.assertIn('data_roadmap_cyber_contamination', res.blocking_errors)

    def test_pdf_export_blocked_for_contaminated_data_roadmap(self):
        res = export_pdf(
            _render_tree(_CYBER_CONTAMINATED_ROADMAP),
            backend=_pdf_backend({'roadmap': _CYBER_CONTAMINATED_ROADMAP}),
            domain='Data Management',
        )
        self.assertEqual(res.bytes_data, b'')
        self.assertIn('data_roadmap_cyber_contamination', res.blocking_errors)

    def test_docx_export_passes_for_clean_data_roadmap(self):
        res = export_docx(
            _render_tree(_DATA_CLEAN_ROADMAP),
            backend=_docx_backend({'roadmap': _DATA_CLEAN_ROADMAP}),
            domain='Data Management',
        )
        self.assertEqual(res.blocking_errors, [])
        self.assertEqual(res.bytes_data, b'PK-docx')

    def test_pdf_export_passes_for_clean_data_roadmap(self):
        res = export_pdf(
            _render_tree(_DATA_CLEAN_ROADMAP),
            backend=_pdf_backend({'roadmap': _DATA_CLEAN_ROADMAP}),
            domain='Data Management',
        )
        self.assertEqual(res.blocking_errors, [])
        self.assertEqual(res.bytes_data, b'%PDF-bytes')

    def test_cyber_export_with_cyber_roadmap_is_allowed(self):
        res = export_docx(
            _render_tree(_CYBER_CONTAMINATED_ROADMAP),
            backend=_docx_backend({'roadmap': _CYBER_CONTAMINATED_ROADMAP}),
            domain='Cyber Security',
        )
        self.assertEqual(res.blocking_errors, [])
        self.assertEqual(res.bytes_data, b'PK-docx')


class Rel33CyberRepairScopeTests(unittest.TestCase):
    """Req 7 — cyber repairers still run for cyber, not for data."""

    def test_kpi_canonical_registry_substitution_cyber_only(self):
        from release_engine.kpi_model import repair_kpi_canonical_families
        data_kpis = (
            '## مؤشرات الأداء الرئيسية\n'
            '| # | وصف المؤشر | النوع | القيمة المستهدفة | صيغة الاحتساب |'
            ' مصدر | التكرار | المالك |\n'
            '|---|---|---|---|---|---|---|---|\n'
            '| 1 | نضج حوكمة البيانات | KPI | ≥ 90% |'
            ' (المطبق ÷ الإجمالي) × 100 | سجل الحوكمة | ربع سنوي | CDO |\n'
        )
        sections, _ = repair_kpi_canonical_families(
            {'kpis': data_kpis},
            lang='ar',
            backend={'domain': 'data', 'lang': 'ar'})
        blob = sections.get('kpis', '')
        self.assertNotIn('CISO', blob)
        self.assertIn('CDO', blob)

    def test_roadmap_quality_validator_still_engages_cyber_baseline(self):
        called = {'count': 0}

        def _cyber_baseline(secs, lang, fws):
            called['count'] += 1
            secs = dict(secs)
            secs['roadmap'] = _CYBER_CONTAMINATED_ROADMAP
            return secs, {'gate_passed': True}

        validate_rel3_roadmap_output_quality(
            {'roadmap': ''},
            backend={
                'lang': 'ar',
                'domain': 'cyber',
                'baseline_roadmap': _cyber_baseline,
            })
        self.assertGreaterEqual(called['count'], 1)


class Rel33AiKpiOwnersTests(unittest.TestCase):
    """Req 8 — AI KPI owners stay AI-domain; kpi_main never cards."""

    def test_ai_kpi_owners_are_ai_domain_roles(self):
        from release_engine_v3.rel32_compiler import _build_kpis_section
        text, rows, _ = _build_kpis_section(
            '', lang='ar', backend={}, domain='ai')
        self.assertGreaterEqual(len(rows), 8)
        owners = {r.owner for r in rows}
        self.assertNotIn('CISO', owners)
        blob = ' '.join(owners)
        self.assertTrue(
            any(tok in blob for tok in ('AI', 'الذكاء', 'نموذج', 'بيانات')),
            owners)

    def test_ai_pdf_kpi_table_lock_no_cards_fallback(self):
        flags = _rel33_kpi_table_lock_flags('ai')
        self.assertTrue(flags['table_lock_applied'])
        self.assertTrue(flags['kpi_main_forced_table'])
        self.assertFalse(flags['used_cards_fallback'])
        flags_data = _rel33_kpi_table_lock_flags('Data Management')
        self.assertTrue(flags_data['kpi_main_forced_table'])


class Rel33DocxAuthorityStillPassesTests(unittest.TestCase):
    """Req 9 — DOCX export authority check remains green."""

    def test_authorized_pipeline_authority_passes(self):
        diag = evaluate_rel33_docx_export_authority(
            route='docx',
            domain='data',
            document_type='strategy',
            artifact_id='t-1',
            build_docx_bytes_called=True,
            called_from_authorized_export_pipeline=True,
            frozen_artifact_loaded=True,
            sections_json_loaded=True,
            export_authority='rel3_export_authoritative',
        )
        self.assertTrue(diag['docx_export_authority_passed'])
        self.assertEqual(diag['blocking_errors'], [])

    def test_unauthorized_call_still_flagged(self):
        diag = evaluate_rel33_docx_export_authority(
            route='docx',
            domain='data',
            document_type='strategy',
            artifact_id='t-1',
            build_docx_bytes_called=True,
            called_from_authorized_export_pipeline=False,
            frozen_artifact_loaded=False,
            sections_json_loaded=False,
            export_authority='legacy',
        )
        self.assertFalse(diag['docx_export_authority_passed'])
        self.assertTrue(diag['bypass_detected'])


if __name__ == '__main__':
    unittest.main()
