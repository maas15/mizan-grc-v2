"""PR-REL2.8 — route-bound actual export evidence (no preview-only DOCX/PDF pass)."""

import hashlib
import importlib.util
import os
import sys
import tempfile
import unittest

_TMP = tempfile.mkdtemp(prefix='test_rel28_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(_TMP, 'test.db'),
)
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from release_engine.export_evidence_validator import (
    block_export_if_evidence_fails,
    validate_actual_export_evidence,
)
from release_engine.final_quality_contract import evaluate_final_quality
from release_engine.pillar_model import _build_canonical_pillars
from release_engine.rel31_acceptance_checks import repair_rel31_canonical_sections
from release_engine.rel28_route_evidence import (
    apply_route_bound_verdict,
    build_returned_file_fingerprint,
    check_pillars_after_strategic_heading,
    normalize_route,
    sha256_bytes,
)
from tests.test_rel3_cyber_arabic_actual_export_quality import _GOOD_MD

_GOOD_PREVIEW = _GOOD_MD

_MIN_SECTIONS, _ = repair_rel31_canonical_sections(
    {
        'vision': '## 1. الرؤية\n\nنص.\n',
        'pillars': _build_canonical_pillars('ar'),
    },
    lang='ar',
    domain='cyber',
)
_GOOD_PREVIEW_MIN = (
    (_MIN_SECTIONS.get('vision') or '').strip() + '\n\n'
    + (_MIN_SECTIONS.get('pillars') or '').strip()
)

_BAD_KPI = (
    '## 6. مؤشرات الأداء\n\n'
    '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساس | مصدر | تواتر |\n'
    '|---|---|---|---|---|---|\n'
    '| NCA DCC | MTTR | 90% | f | src | شهري |\n'
    '| 2 | MTTR | 90% | f | src | شهري |\n'
)

_BAD_RISK = (
    '## 7. تقييم الثقة والمخاطر\n\n'
    '| المخاطرة | الاحتمال | الأثر | خطة المعالجة |\n'
    '|---|---|---|---|\n'
    '| تصيد | عالي | عالي | — |\n'
)

_BAD_TRACE = 'مصفوفة التتبع\n| ECC | الاستجابة للحوادث | CSIRT SOC |\n'

_MISSING_PILLARS = (
    '## 2. الركائز\n\n'
    '### حوكمة\n\nنص فقط بدون الأسماء الأربعة.\n'
)


def _gate(route, preview='', docx='', pdf='', **kw):
    return validate_actual_export_evidence(
        preview, docx, pdf,
        domain='cyber', lang='ar',
        route_name=route, **kw)


class Rel28RouteBoundTests(unittest.TestCase):

    def test_01_preview_only_cannot_pass_docx_route(self):
        g = _gate('docx', preview=_GOOD_PREVIEW, docx='', pdf='')
        self.assertFalse(g['route_evidence_passed'])
        self.assertFalse(g['export_return_allowed'])
        self.assertFalse(g['docx_export_evidence_passed'])
        self.assertIn('docx_bytes_not_checked', ' '.join(g['blocking_errors']))

    def test_02_preview_only_cannot_pass_pdf_route(self):
        g = _gate('pdf', preview=_GOOD_PREVIEW, docx='', pdf='')
        self.assertFalse(g['route_evidence_passed'])
        self.assertIn('pdf_bytes_not_checked', ' '.join(g['blocking_errors']))

    def test_03_docx_route_fails_without_docx_bytes(self):
        g = _gate('docx', preview=_GOOD_PREVIEW)
        self.assertFalse(g['actual_export_evidence_passed'])
        self.assertFalse(g['docx_bytes_checked'])

    def test_04_pdf_route_fails_without_pdf_bytes(self):
        g = _gate('pdf', preview=_GOOD_PREVIEW, docx=_GOOD_PREVIEW)
        self.assertFalse(g['route_evidence_passed'])
        self.assertFalse(g['pdf_bytes_checked'])

    def test_05_preview_route_passes_with_clean_preview_only(self):
        g = _gate('preview', preview=_GOOD_PREVIEW)
        self.assertTrue(g['preview_export_evidence_passed'])
        self.assertFalse(g['docx_export_evidence_passed'])
        self.assertFalse(g['pdf_export_evidence_passed'])
        self.assertTrue(g['route_evidence_passed'])

    def test_06_preview_route_does_not_set_docx_pdf_pass_true(self):
        g = _gate('preview', preview=_GOOD_PREVIEW)
        self.assertFalse(g['docx_pass_from_actual_bytes'])
        self.assertFalse(g['pdf_pass_from_actual_bytes'])

    def test_07_docx_route_passes_with_clean_docx_text(self):
        g = _gate('docx', preview=_GOOD_PREVIEW, docx=_GOOD_PREVIEW)
        self.assertTrue(g['docx_bytes_checked'])
        self.assertTrue(g['docx_pass_from_actual_bytes'])

    def test_08_missing_pillars_after_heading_fails_docx(self):
        g = _gate('docx', preview=_GOOD_PREVIEW, docx=_MISSING_PILLARS)
        self.assertFalse(g['route_evidence_passed'])
        errs = ' '.join(g['blocking_errors'])
        self.assertTrue(
            'missing_pillars_after_heading' in errs
            or 'actual_text_missing' in errs
            or 'missing_pillars' in errs)

    def test_09_kpi_nca_in_number_column_fails(self):
        blob = _GOOD_PREVIEW_MIN + '\n' + _BAD_KPI
        g = _gate('docx', preview=blob, docx=blob)
        self.assertFalse(g['route_evidence_passed'])
        self.assertIn('kpi_visible_invalid', ' '.join(g['blocking_errors']))

    def test_10_duplicate_mttr_fails(self):
        blob = _GOOD_PREVIEW_MIN + '\n' + _BAD_KPI
        defects = validate_actual_export_evidence('', blob, '', route_name='docx')
        self.assertIn('duplicate_MTTR', ' '.join(
            defects.get('docx_kpi_defects') or []))

    def test_11_risk_treatment_dash_fails(self):
        blob = _GOOD_PREVIEW_MIN + '\n' + _BAD_RISK
        g = _gate('docx', docx=blob)
        self.assertFalse(g['route_evidence_passed'])

    def test_12_traceability_mixed_csirt_soc_fails(self):
        blob = _GOOD_PREVIEW_MIN + '\n' + _BAD_TRACE
        g = _gate('docx', docx=blob)
        self.assertFalse(g['route_evidence_passed'])

    def test_13_roadmap_visible_drift_blocks(self):
        from release_engine.rel28_route_evidence import check_roadmap_visible_drift
        short = _GOOD_PREVIEW_MIN + '\n## 5. خارطة الطريق\n\n| 1 | a | b | c | d | e |\n'
        drift = check_roadmap_visible_drift(short, internal_row_count=12)
        self.assertIn('rel2_export_model_drift:roadmap_visible_row_count', drift)

    def test_14_internal_hash_match_but_missing_pillars_fails_docx(self):
        """Hash parity alone must not pass when actual DOCX text lacks pillars."""
        g = _gate(
            'docx',
            preview=_GOOD_PREVIEW,
            docx=_MISSING_PILLARS,
            canonical_sections={'pillars': _build_canonical_pillars('ar')},
        )
        self.assertFalse(g['export_return_allowed'])

    def test_15_returned_fingerprint_requires_matching_bytes(self):
        data = b'%PDF-1.4 test'
        fp = build_returned_file_fingerprint(
            route_name='pdf',
            final_hash='abc',
            returned_bytes=data,
            evidence_bytes=data,
            export_return_allowed=True,
        )
        self.assertTrue(fp['returned_equals_evidence_bytes'])
        fp_bad = build_returned_file_fingerprint(
            route_name='pdf',
            returned_bytes=data,
            evidence_bytes=b'other',
            export_return_allowed=False,
            blocking_error_if_any='mismatch',
        )
        self.assertFalse(fp_bad['returned_equals_evidence_bytes'])

    def test_16_block_export_uses_export_return_allowed(self):
        g = _gate('docx', preview=_GOOD_PREVIEW)
        allowed, errs = block_export_if_evidence_fails(g)
        self.assertFalse(allowed)
        self.assertTrue(errs)

    def test_17_finalize_requires_all_channels(self):
        g = _gate('finalize', preview=_GOOD_PREVIEW, docx='', pdf='')
        self.assertFalse(g['route_evidence_passed'])

    def test_18_arabic_residue_fails_even_if_preview_clean_flag(self):
        bad = _GOOD_PREVIEW + '\nالحاليةفي الموظفينفي\n'
        g = _gate('docx', docx=bad)
        self.assertFalse(g['route_evidence_passed'])

    def test_19_normalize_route_aliases(self):
        self.assertEqual(normalize_route('generate-docx'), 'docx')
        self.assertEqual(normalize_route('api_generate_pdf'), 'pdf')
        self.assertEqual(normalize_route('preview'), 'preview')

    def test_20_release_contract_route_flags_default_false_without_evidence(self):
        art = {
            'sections': {'vision': 'x'},
            'final_markdown': 'x',
            'blocking_errors': [],
            'sealed': True,
            'final_hash': 'h',
            'domain': 'cyber',
            'diagnostics': {'rel2': {'rel27': {'export': {
                'route_evidence_passed': False,
                'export_return_allowed': False,
                'preview_export_evidence_passed': True,
                'docx_export_evidence_passed': False,
                'pdf_export_evidence_passed': False,
                'docx_bytes_checked': False,
                'actual_export_evidence_passed': False,
                'blocking_errors': ['rel2_actual_export_evidence_failed:docx_bytes_not_checked'],
            }}}},
            'contract_meta': {},
        }
        c = evaluate_final_quality(art, lang='ar', skip_structural=True)
        self.assertFalse(c['release_ready_final_passed'])


class Rel28PillarHeadingTests(unittest.TestCase):

    def test_four_pillar_names_after_heading(self):
        blob = (
            '## 2. الركائز\n\n'
            + _build_canonical_pillars('ar')
        )
        self.assertEqual(check_pillars_after_strategic_heading(blob), [])

    def test_missing_one_pillar_name_detected(self):
        blob = (
            '## 2. الركائز\n\n'
            '### حوكمة\n\nنص.\n'
        )
        self.assertTrue(check_pillars_after_strategic_heading(blob))


class Rel28AdditionalHardeningTests(unittest.TestCase):

    def test_21_preview_pass_does_not_enable_docx_export_pass(self):
        g = _gate('preview', preview=_GOOD_PREVIEW)
        self.assertTrue(g['preview_export_evidence_passed'])
        self.assertFalse(g['docx_export_evidence_passed'])
        self.assertFalse(g['pdf_export_evidence_passed'])
        self.assertFalse(g.get('docx_pass_from_actual_bytes'))

    def test_22_docx_route_requires_docx_bytes_checked(self):
        g = _gate('docx', preview=_GOOD_PREVIEW, docx=_GOOD_PREVIEW)
        self.assertTrue(g['docx_bytes_checked'])
        self.assertTrue(g['docx_pass_from_actual_bytes'])

    def test_23_empty_risk_treatment_emits_aggregate_blocker(self):
        blob = _GOOD_PREVIEW_MIN + '\n' + _BAD_RISK
        g = _gate('docx', docx=blob)
        errs = ' '.join(g.get('blocking_errors') or [])
        self.assertIn('empty_risk_treatment', errs)

    def test_24_traceability_csirt_soc_fails(self):
        blob = _GOOD_PREVIEW_MIN + '\n' + _BAD_TRACE
        g = _gate('docx', docx=blob)
        self.assertFalse(g['exported_traceability_valid'])

    def test_25_exported_section_hashes_from_actual_docx_text(self):
        g = _gate('docx', preview=_GOOD_PREVIEW, docx=_GOOD_PREVIEW)
        hashes = g.get('exported_docx_section_hashes') or {}
        self.assertTrue(g.get('exported_text_hash_available'))
        self.assertIn('pillars', hashes)
        self.assertTrue(hashes.get('pillars'))

    def test_26_internal_canonical_pillars_do_not_pass_missing_export(self):
        g = _gate(
            'docx',
            preview=_GOOD_PREVIEW,
            docx=_MISSING_PILLARS,
            canonical_sections={'pillars': _build_canonical_pillars('ar')},
        )
        self.assertFalse(g['export_return_allowed'])

    def test_27_arabic_residue_fails_despite_clean_internal_flag(self):
        bad = _GOOD_PREVIEW + '\nالحاليةفي\n'
        g = _gate('docx', docx=bad)
        self.assertFalse(g['exported_arabic_quality_valid'])

    def test_28_build_route_diagnostics_per_channel(self):
        from release_engine.rel28_finalize import build_route_evidence_diagnostics
        art = {
            'sections': {'pillars': _build_canonical_pillars('ar'), 'vision': 'v'},
            'final_markdown': _GOOD_PREVIEW,
            'final_hash': 'abc',
            'domain': 'cyber',
        }
        backend = {'validate_export_evidence': False}
        diag = build_route_evidence_diagnostics(
            art, backend, domain='cyber', lang='ar')
        routes = diag.get('routes') or {}
        self.assertIn('preview', routes)
        self.assertIn('docx', routes)
        self.assertIn('pdf', routes)
        self.assertFalse(routes['docx'].get('docx_bytes_checked'))

    def test_29_returned_fingerprint_mismatch_blocks(self):
        fp = build_returned_file_fingerprint(
            route_name='docx',
            returned_bytes=b'docx-bytes',
            evidence_bytes=b'other-bytes',
            export_return_allowed=False,
            blocking_error_if_any='bytes_mismatch',
        )
        self.assertFalse(fp['returned_equals_evidence_bytes'])
        self.assertFalse(fp['export_return_allowed'])


if __name__ == '__main__':
    unittest.main()
