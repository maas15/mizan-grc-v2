"""PR-REL3.1 — live export authority hardening + DQS regression (37.docx)."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

_TMP = tempfile.mkdtemp(prefix='test_rel31_live_auth_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_APP = None
_APP_SOURCE = ''
try:
    _APP_SOURCE = (ROOT / 'app.py').read_text(encoding='utf-8')
    _spec = importlib.util.spec_from_file_location('app', ROOT / 'app.py')
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
    sys.modules['app'] = _APP
except Exception as _e:
    raise SystemExit(f'Cannot load app: {_e!r}')

from release_engine.rel31_content_substance_checks import evaluate_content_substance
from release_engine.rel31_acceptance_checks import repair_rel31_canonical_sections
from release_engine_v3.contracts import _sha256_bytes
from release_engine_v3.document_quality_spec import evaluate_document_quality
from release_engine_v3.evidence.docx_text_extractor import extract_docx_visible_text
from release_engine_v3.rel31_authority import (
    normalize_rel3_export_blockers,
    rel31_guard_legacy_authority,
    rel31_in_export_adapter,
    rel31_set_export_adapter,
    rel3_export_authoritative,
)
from release_engine_v3.orchestrator import clear_rel3_caches
from tests.fixtures.rel31_content_quality.latest37_live_fixtures import (
    DOCX_LATEST_37,
    LATEST_37_DOCX_SHA256,
    ensure_latest_37_fixtures,
    load_pdf_failure_log,
    verify_latest_37_byte_identical,
)
from tests.fixtures.rel31_content_quality.latest_live_fixtures import (
    DOCX_LATEST,
    LATEST_DOCX_SHA256,
    sections_from_latest_docx_text,
)


def _skip_if_no_app(fn):
    import functools
    @functools.wraps(fn)
    def _wrapped(self, *a, **kw):
        if _APP is None:
            self.skipTest('app unavailable')
        return fn(self, *a, **kw)
    return _wrapped


class Rel31StaticCallGraphTests(unittest.TestCase):

    @_skip_if_no_app
    def test_01_docx_route_calls_rel31_authoritative_export(self):
        self.assertIn('_rel31_authoritative_export_route', _APP_SOURCE)
        idx = _APP_SOURCE.find('def api_generate_docx(')
        self.assertGreater(idx, 0)
        chunk = _APP_SOURCE[idx:idx + 15000]
        self.assertIn("_rel31_authoritative_export_route(", chunk)
        self.assertIn("'docx'", chunk)

    @_skip_if_no_app
    def test_02_pdf_route_calls_rel31_authoritative_export(self):
        idx = _APP_SOURCE.find('def api_generate_pdf(')
        self.assertGreater(idx, 0)
        chunk = _APP_SOURCE[idx:idx + 15000]
        self.assertIn("_rel31_authoritative_export_route(", chunk)
        self.assertIn("'pdf'", chunk)

    @_skip_if_no_app
    def test_03_docx_blocks_legacy_build_when_rel31(self):
        with self.assertRaises(ValueError) as ctx:
            _APP._build_docx_bytes(
                '# test', 't', 'ar', domain='cyber',
                selected_frameworks=['NCA ECC'],
            )
        self.assertIn('_build_docx_bytes', str(ctx.exception))
        self.assertTrue(
            'rel32_docx_export_bypass_detected' in str(ctx.exception)
            or 'rel3_legacy_route_blocked' in str(ctx.exception),
            str(ctx.exception),
        )

    @_skip_if_no_app
    def test_04_build_docx_bytes_has_rel31_guard(self):
        self.assertIn('rel31_guard_legacy_authority', _APP_SOURCE)
        self.assertIn('guard_rel32_docx_export_bypass', _APP_SOURCE)
        self.assertIn("'_build_docx_bytes'", _APP_SOURCE)

    @_skip_if_no_app
    def test_05_cyber_final_contract_has_rel31_guard(self):
        idx = _APP_SOURCE.find('def _cyber_final_export_contract(')
        self.assertGreater(idx, 0)
        chunk = _APP_SOURCE[idx:idx + 4000]
        self.assertIn('rel31_guard_legacy_authority', chunk)

    @_skip_if_no_app
    def test_06_pdf_quality_gate_maps_to_rel3_evidence(self):
        self.assertIn('normalize_rel3_export_blockers', _APP_SOURCE)
        self.assertIn("'rel3_export_evidence_failed'", _APP_SOURCE)


class Rel31LegacyGuardTests(unittest.TestCase):

    @_skip_if_no_app
    def test_07_async_docx_uses_rel31_authoritative_export(self):
        idx = _APP_SOURCE.find('def api_generate_docx_async(')
        self.assertGreater(idx, 0)
        chunk = _APP_SOURCE[idx:idx + 16000]
        self.assertIn("_rel31_authoritative_export_route(", chunk)
        self.assertIn("'docx'", chunk)

    def test_08_build_docx_blocked_outside_adapter(self):
        rel31_set_export_adapter(False)
        blk = rel31_guard_legacy_authority(
            '_build_docx_bytes',
            domain='cyber', lang='ar',
            flags={'rel3': True, 'rel31': True},
        )
        self.assertEqual(blk, 'rel3_legacy_route_blocked:_build_docx_bytes')

    def test_09_build_docx_allowed_inside_adapter(self):
        rel31_set_export_adapter(True)
        try:
            blk = rel31_guard_legacy_authority(
                '_build_docx_bytes',
                domain='cyber', lang='ar',
                flags={'rel3': True, 'rel31': True},
            )
            self.assertIsNone(blk)
        finally:
            rel31_set_export_adapter(False)

    def test_10_vertical_stack_normalized_to_rel3_blocker(self):
        out = normalize_rel3_export_blockers(
            ['pdf_render_failed:docmodel_professional_quality:'
             'pdf_table_vertical_stack_warnings'],
            route='pdf',
        )
        self.assertTrue(any('rel3_export_evidence_failed' in b for b in out))

    def test_11_mutation_blocker_normalized(self):
        out = normalize_rel3_export_blockers(
            ['mutation_after_contract_detected'], route='docx')
        self.assertIn('rel3_post_contract_mutation_detected', out)


    def test_12_pdf_route_not_gated_by_drafting_mode(self):
        """REL3.1 PDF must run even when generation_mode defaults to drafting."""
        idx = _APP_SOURCE.find('def api_generate_pdf(')
        self.assertGreater(idx, 0)
        chunk = _APP_SOURCE[idx:idx + 15000]
        self.assertIn('_rel31_is_authoritative(domain_pdf, lang)', chunk)
        self.assertIn('not _is_internal_rel_export_request(data)', chunk)
        self.assertNotIn(
            "!= 'drafting'",
            chunk[chunk.find('_rel31_authoritative_export_route'):chunk.find('_rel31_authoritative_export_route') + 800],
        )

    def test_13_docx_route_not_gated_by_drafting_mode(self):
        idx = _APP_SOURCE.find('def api_generate_docx(')
        self.assertGreater(idx, 0)
        chunk = _APP_SOURCE[idx:idx + 15000]
        self.assertIn('_rel31_is_authoritative(domain, lang)', chunk)
        self.assertIn('not _is_internal_rel_export_request(data)', chunk)


class Rel31MonkeypatchExportTests(unittest.TestCase):

    @_skip_if_no_app
    def test_14_docx_export_does_not_call_legacy_contract(self):
        from tests.test_rel31_authoritative_generation_contract import (
            _GOOD_SECTIONS, _backend,
        )
        clear_rel3_caches()

        def _boom(*a, **kw):
            raise AssertionError('legacy contract called as authority')

        with mock.patch.object(
                _APP, '_cyber_final_export_contract', side_effect=_boom):
            export, evidence = rel3_export_authoritative(
                'docx', {
                    'sections': _GOOD_SECTIONS,
                    'domain': 'cyber',
                    'sealed': True,
                    'contract_meta': {'lang': 'ar'},
                },
                backend=_backend(),
                flags={'rel3': True, 'rel31': True},
                export_kwargs={'filename': 't.docx', 'lang': 'ar'},
            )
        self.assertTrue(
            evidence.export_return_allowed or export.docx_bytes,
            evidence.blocking_errors)

    @_skip_if_no_app
    def test_15_legacy_contract_blocked_as_authority(self):
        out = _APP._cyber_final_export_contract(
            '# test', metadata={'domain': 'cyber'},
            selected_frameworks=['ECC'], lang='ar', domain='cyber',
            output_type='docx', read_only=False,
            request_context={'rel31_contract_as_export_authority': True},
        )
        blockers = list(out.get('blocking_errors') or [])
        self.assertTrue(
            any('rel3_legacy_route_blocked:_cyber_final_export_contract' in b
                for b in blockers),
            blockers)


class Rel31SourceAuthorityDiagTests(unittest.TestCase):

    def test_16_rel3_export_emits_source_authority(self):
        from tests.test_rel31_authoritative_generation_contract import (
            _GOOD_SECTIONS, _backend,
        )
        from release_engine_v3.canonical_document import (
            build_final_document_artifact,
        )
        clear_rel3_caches()
        buf = StringIO()
        with redirect_stdout(buf):
            rel3_export_authoritative(
                'preview',
                {
                    'sections': _GOOD_SECTIONS,
                    'domain': 'cyber',
                    'sealed': True,
                    'contract_meta': {'lang': 'ar'},
                },
                backend=_backend(),
                flags={'rel3': True, 'rel31': True},
            )
        text = buf.getvalue()
        self.assertIn('[REL3-SOURCE-AUTHORITY-CHECK]', text)
        self.assertIn('[REL3-POST-CONTRACT-HASH-CHECK]', text)
        m = re.search(
            r'\[REL3-SOURCE-AUTHORITY-CHECK\] (\{.*\})', text)
        self.assertIsNotNone(m)
        payload = json.loads(m.group(1))
        self.assertEqual(payload['source_used'], 'rel3_render_tree')
        self.assertTrue(payload['sealed_artifact_used'])
        self.assertFalse(payload.get('strategies_content_direct_used'))


    def test_17_mutation_detected_blocks_export(self):
        from tests.test_rel31_authoritative_generation_contract import (
            _GOOD_SECTIONS, _backend,
        )
        from release_engine_v3.contracts import ExportResult, EvidenceResult
        clear_rel3_caches()
        with mock.patch(
                'release_engine_v3.rel31_authority.rel3_export_with_evidence') as _exp:
            _exp.return_value = (
                ExportResult(
                    route_name='docx',
                    artifact_id='a1',
                    render_tree_hash='tree1',
                    canonical_hash='mutated_hash',
                    docx_bytes=b'x',
                    returned_bytes_sha256='abc',
                ),
                EvidenceResult(
                    route_name='docx',
                    artifact_id='a1',
                    strategy_id='s1',
                    canonical_hash='mutated_hash',
                    render_tree_hash='tree1',
                    returned_bytes_sha256='abc',
                    evidence_bytes_sha256='abc',
                    returned_equals_evidence_bytes=True,
                    exact_bytes_checked=True,
                    preview_text_checked=False,
                    docx_bytes_checked=True,
                    pdf_bytes_checked=False,
                    evidence_passed=True,
                    export_return_allowed=True,
                    blocking_errors=[],
                ),
            )
            export, evidence = rel3_export_authoritative(
                'docx',
                {
                    'sections': _GOOD_SECTIONS,
                    'domain': 'cyber',
                    'sealed': True,
                    'contract_meta': {'lang': 'ar'},
                },
                backend=_backend(),
                flags={'rel3': True, 'rel31': True},
            )
        self.assertIn(
            'rel3_post_contract_mutation_detected',
            list(export.blocking_errors or []))
        self.assertFalse(evidence.export_return_allowed)


class Rel31Document37FixtureTests(unittest.TestCase):

    def test_18_byte_exact_fixture_matches_uploaded_37(self):
        ensure_latest_37_fixtures()
        proof = verify_latest_37_byte_identical()
        self.assertEqual(proof['docx_fixture_sha256'], LATEST_37_DOCX_SHA256)
        self.assertTrue(proof.get('docx_bytes_match_uploaded'))
        data = DOCX_LATEST_37.read_bytes()
        self.assertEqual(_sha256_bytes(data), LATEST_37_DOCX_SHA256)
        self.assertEqual(DOCX_LATEST, DOCX_LATEST_37)
        self.assertEqual(LATEST_DOCX_SHA256, LATEST_37_DOCX_SHA256)


class Rel31Document37BeforeRepairTests(unittest.TestCase):
    """استراتيجية الأمن السيبراني (37) must fail positive checks before repair."""

    @classmethod
    def setUpClass(cls):
        ensure_latest_37_fixtures()
        cls.docx_bytes = DOCX_LATEST_37.read_bytes()
        cls.docx_text = extract_docx_visible_text(cls.docx_bytes)
        cls.sections = sections_from_latest_docx_text(cls.docx_text)
        cls.substance = evaluate_content_substance(cls.docx_text, route='docx')
        cls.dq = evaluate_document_quality(
            canonical_artifact={'sections': cls.sections, 'domain': 'cyber'},
            legacy_sections=cls.sections,
            extracted_docx_text=cls.docx_text,
            extracted_preview_text='',
            extracted_pdf_text='',
            pdf_bytes=b'',
        )

    def test_19_fails_dqs_before_repair(self):
        self.assertFalse(self.dq.get('passed'), self.dq.get('blocking_errors'))

    def test_20_fails_roadmap_or_canonical_roadmap(self):
        road_issue = (
            self.substance.get('roadmap_visible_row_count', 99) < 10
            or 'roadmap_canonical_invalid' in ' '.join(
                self.dq.get('blocking_errors') or []))
        self.assertTrue(road_issue, self.substance)

    def test_21_fails_duplicate_dlp_incident_metric(self):
        self.assertGreater(
            self.docx_text.count('عدد حوادث تسرب البيانات الحرجة'), 1)

    def test_22_fails_duplicate_mttd_mttr(self):
        blockers = self.substance.get('blocking_errors') or []
        self.assertIn('duplicate_mttd', blockers)
        self.assertIn('duplicate_mttr', blockers)

    def test_23_fails_corrupted_cyrillic_mttr(self):
        self.assertIn('MTT\u0420', self.docx_text)

    def test_24_fails_glued_arabic_token(self):
        self.assertIn('معدلمعالجة', self.docx_text)

    def test_25_fails_dlp_encryption_metric_mix(self):
        self.assertIn(
            'dlp_encryption_classification_metric_mix',
            self.substance.get('blocking_errors') or [])

    def test_26_fails_generic_dcc_traceability(self):
        self.assertTrue(self.substance.get('traceability_bad_mappings'))

    def test_27_fails_arabic_residues_or_role_corruption(self):
        has_residue = (
            bool(self.substance.get('arabic_residues'))
            or bool(self.substance.get('arabic_role_corruption'))
            or 'ال منتظم' in self.docx_text
            or 'ال معنية' in self.docx_text
            or 'ال مراقبة المست' in self.docx_text)
        self.assertTrue(has_residue)

    def test_28_pdf_failure_log_requires_rel3_normalization(self):
        log = load_pdf_failure_log()
        raw = str(log.get('live_raw_error') or '')
        self.assertIn('pdf_render_failed:docmodel_professional_quality', raw)
        out = normalize_rel3_export_blockers([raw], route='pdf')
        self.assertTrue(
            any('rel3_export_evidence_failed:pdf:vertical_stack_warnings' in b
                for b in out),
            out)
        self.assertFalse(any('pdf_render_failed:' in b for b in out))


class Rel31Document37AfterRepairTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        ensure_latest_37_fixtures()
        text = extract_docx_visible_text(DOCX_LATEST_37.read_bytes())
        sections = sections_from_latest_docx_text(text)
        backend = _APP._rel31_backend_callables()
        cls.repaired, cls.repairs = repair_rel31_canonical_sections(
            sections, lang='ar', domain='cyber', backend=backend)
        cls.md = _APP._prcy65_rebuild_content_from_sections(cls.repaired, None)
        cls.backend = dict(backend)
        cls.backend['split_sections'] = lambda _c: dict(cls.repaired)

    def setUp(self):
        clear_rel3_caches()

    def _export_docx_with_diagnostics(self):
        buf = StringIO()
        with redirect_stdout(buf):
            export, evidence = rel3_export_authoritative(
                'docx',
                {
                    'sections': self.repaired,
                    'final_markdown': self.md,
                    'domain': 'cyber',
                    'sealed': True,
                    'contract_meta': {'lang': 'ar'},
                },
                backend=self.backend,
                flags={'rel3': True, 'rel31': True},
                export_kwargs={
                    'filename': 'cyber_strategy_37_repaired.docx',
                    'lang': 'ar',
                    'domain': 'cyber',
                    'selected_frameworks': ['NCA ECC', 'NCA DCC'],
                },
            )
        return export, evidence, buf.getvalue()

    @_skip_if_no_app
    def test_29_repaired_exports_docx_through_rel3_only(self):
        self.assertTrue(self.repairs, self.repairs)
        export, evidence, _log = self._export_docx_with_diagnostics()
        self.assertTrue(
            evidence.export_return_allowed or export.docx_bytes,
            evidence.blocking_errors)
        self.assertTrue(export.docx_bytes or export.bytes_data)

    @_skip_if_no_app
    def test_30_repaired_passes_document_quality_spec(self):
        export, evidence, _log = self._export_docx_with_diagnostics()
        docx_bytes = export.docx_bytes or export.bytes_data or b''
        self.assertTrue(docx_bytes, evidence.blocking_errors)
        dq = evaluate_document_quality(
            canonical_artifact={'sections': self.repaired, 'domain': 'cyber'},
            legacy_sections=self.repaired,
            extracted_docx_text=extract_docx_visible_text(docx_bytes),
            extracted_preview_text='',
            extracted_pdf_text='',
            pdf_bytes=b'',
        )
        self.assertTrue(dq.get('passed'), dq.get('blocking_errors'))

    @_skip_if_no_app
    def test_31_repaired_emits_rel3_source_authority(self):
        _export, _evidence, log = self._export_docx_with_diagnostics()
        self.assertIn('[REL3-SOURCE-AUTHORITY-CHECK]', log)
        m = re.search(r'\[REL3-SOURCE-AUTHORITY-CHECK\] (\{.*\})', log)
        self.assertIsNotNone(m, log[-4000:])
        payload = json.loads(m.group(1))
        self.assertEqual(payload['source_used'], 'rel3_render_tree')
        self.assertTrue(payload['sealed_artifact_used'])
        self.assertTrue(payload.get('source_authority_valid', True))
        self.assertFalse(payload.get('strategies_content_direct_used'))

    @_skip_if_no_app
    def test_32_repaired_post_contract_hash_no_mutation(self):
        _export, _evidence, log = self._export_docx_with_diagnostics()
        self.assertIn('[REL3-POST-CONTRACT-HASH-CHECK]', log)
        m = re.search(r'\[REL3-POST-CONTRACT-HASH-CHECK\] (\{.*\})', log)
        self.assertIsNotNone(m, log[-4000:])
        payload = json.loads(m.group(1))
        self.assertFalse(payload.get('mutation_after_contract_detected'))

    @_skip_if_no_app
    def test_33_repaired_emits_returned_file_evidence(self):
        _export, evidence, log = self._export_docx_with_diagnostics()
        self.assertIn('[REL3-RETURNED-FILE-EVIDENCE]', log)
        self.assertTrue(evidence.exact_bytes_checked)
        self.assertTrue(evidence.returned_equals_evidence_bytes)

    @_skip_if_no_app
    def test_34_repaired_emits_content_substance_evidence(self):
        export, _evidence, log = self._export_docx_with_diagnostics()
        self.assertIn('[REL3-CONTENT-SUBSTANCE-EVIDENCE]', log)
        docx_text = extract_docx_visible_text(export.docx_bytes or b'')
        diag = evaluate_content_substance(
            docx_text, route='docx',
            canonical_kpis=self.repaired.get('kpis') or '')
        self.assertTrue(diag['content_substance_passed'], diag)

    def test_35_raw_pdf_error_never_surfaces_to_ui_blockers(self):
        log = load_pdf_failure_log()
        raw = str(log.get('live_raw_error') or '')
        normalized = normalize_rel3_export_blockers([raw], route='pdf')
        joined = ' '.join(normalized)
        self.assertIn('rel3_export_evidence_failed:pdf:vertical_stack_warnings', joined)
        self.assertNotIn('pdf_render_failed:docmodel_professional_quality', joined)


if __name__ == '__main__':
    unittest.main()
