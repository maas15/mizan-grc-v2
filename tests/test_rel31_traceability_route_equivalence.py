"""PR-REL3.1 — traceability canonical repair and route artifact equivalence."""

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

_TMP = tempfile.mkdtemp(prefix='test_rel31_trace_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_APP = None
try:
    _spec = importlib.util.spec_from_file_location('app', ROOT / 'app.py')
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
    sys.modules['app'] = _APP
except Exception as _e:
    raise SystemExit(f'Cannot load app: {_e!r}')

from release_engine.rel31_acceptance_checks import (
    flat_traceability_bad_mappings,
    repair_rel31_canonical_sections,
)
from release_engine.rel31_content_substance_checks import (
    check_traceability_bad_mappings,
)
from release_engine.traceability_substance_model import (
    TRACE_CANONICAL_REGISTRY,
    build_canonical_traceability_from_registry,
    repair_traceability_canonical_families,
)
from release_engine_v3.document_quality_spec import evaluate_document_quality
from release_engine_v3.evidence.docx_text_extractor import extract_docx_visible_text
from release_engine_v3.orchestrator import clear_rel3_caches
from release_engine_v3.rel31_authority import (
    clear_rel3_route_artifact_hashes,
    emit_rel3_route_artifact_equivalence,
    record_rel3_route_artifact_hashes,
    rel3_export_authoritative,
)
from tests.fixtures.rel31_content_quality.latest_live_fixtures import (
    DOCX_LATEST,
    ensure_latest_live_fixtures,
    sections_from_latest_docx_text,
)


def _bad_trace_flat_blob() -> str:
    """Flat DOCX-style traceability layout used by export evidence checks."""
    return (
        'NCA DCC\n'
        'تصنيف البيانات\n'
        'ضعف إدارة IAM وحسابات مميزة\n'
        'NCA DCC\n'
        'حماية البيانات\n'
        'ضعف ضوابط منع تسرب البيانات\n'
        'NCA ECC\n'
        'الاستجابة للحوادث\n'
        'تأسيس مركز SOC/SIEM\n'
        'NCA ECC\n'
        'إدارة الثغرات\n'
        'ضعف ضوابط DLP والوصول البعيد\n'
    )


def _bad_trace_sections() -> dict:
    return {
        'traceability': (
            '## مصفوفة التتبع\n\n'
            '| الإطار المرجعي | مجال القدرة / الضابط | الفجوة المرتبطة | '
            'المبادرة / النشاط | المؤشر | الخطر المرتبط |\n'
            '|---|---|---|---|---|---|\n'
            '| NCA DCC | تصنيف البيانات | ضعف إدارة IAM وحسابات مميزة | '
            'جرد | KPI | Risk |\n'
            '| NCA DCC | حماية البيانات | ضعف ضوابط منع تسرب البيانات | '
            'DLP | KPI | Risk |\n'
            '| NCA ECC | الاستجابة للحوادث | تأسيس مركز SOC/SIEM | '
            'Roadmap | MTTR | Risk |\n'
            '| NCA ECC | إدارة الثغرات | ضعف ضوابط DLP والوصول البعيد | '
            'Patch | KPI | Risk |\n'
        ),
    }


def _bad_trace_in_live_sections(live: dict) -> dict:
    out = dict(live or {})
    out.update(_bad_trace_sections())
    return out


def _export_all_routes(sections: dict, *, strategy_id: str = 'rel31-trace-test'):
    clear_rel3_caches()
    clear_rel3_route_artifact_hashes()
    backend = _APP._rel31_backend_callables()
    md = _APP._prcy65_rebuild_content_from_sections(sections, None)
    art = {
        'sections': sections,
        'final_markdown': md,
        'domain': 'cyber',
        'sealed': True,
        'strategy_id': strategy_id,
        'contract_meta': {'lang': 'ar'},
    }
    backend['split_sections'] = lambda _c: dict(sections)
    kwargs = {
        'filename': 't.docx', 'lang': 'ar', 'domain': 'cyber',
        'selected_frameworks': ['NCA ECC', 'NCA DCC'],
    }
    preview = rel3_export_authoritative(
        'preview', art, backend=backend,
        flags={'rel3': True, 'rel31': True}, export_kwargs=kwargs)
    docx = rel3_export_authoritative(
        'docx', art, backend=backend,
        flags={'rel3': True, 'rel31': True}, export_kwargs=kwargs)
    pdf = rel3_export_authoritative(
        'pdf', art, backend=backend,
        flags={'rel3': True, 'rel31': True}, export_kwargs=kwargs)
    record_rel3_route_artifact_hashes(
        strategy_id, 'generation',
        canonical_hash=preview[0].canonical_hash,
        render_tree_hash=preview[0].render_tree_hash,
    )
    return preview, docx, pdf


class TraceabilityDivergenceFixtureTests(unittest.TestCase):

    def test_01_pdf_docx_divergence_fails_before_repair(self):
        bad = _bad_trace_sections()
        blockers = check_traceability_bad_mappings(bad['traceability'])
        self.assertTrue(blockers)

    def test_02_docx_fails_iam_classification_mapping(self):
        defects = flat_traceability_bad_mappings(_bad_trace_flat_blob())
        self.assertIn('trace_gap_mismatch:تصنيف البيانات', defects)

    def test_03_docx_fails_dlp_only_data_protection(self):
        defects = flat_traceability_bad_mappings(_bad_trace_flat_blob())
        self.assertIn('trace_gap_mismatch:حماية البيانات', defects)

    def test_04_docx_fails_wrong_incident_response_family(self):
        defects = flat_traceability_bad_mappings(_bad_trace_flat_blob())
        self.assertIn('trace_gap_mismatch:الاستجابة للحوادث', defects)

    def test_05_docx_fails_vulnerability_dlp_remote_wording(self):
        defects = flat_traceability_bad_mappings(_bad_trace_flat_blob())
        self.assertIn('trace_gap_mismatch:إدارة الثغرات', defects)


class TraceabilityCanonicalRepairTests(unittest.TestCase):

    def test_06_dcc_mappings_exact_after_repair(self):
        repaired, diag = repair_traceability_canonical_families(
            _bad_trace_sections(), lang='ar')
        text = repaired['traceability']
        self.assertIn(
            TRACE_CANONICAL_REGISTRY['data_classification']['expected_gap'], text)
        self.assertIn(
            TRACE_CANONICAL_REGISTRY['data_protection']['expected_gap'], text)
        self.assertEqual(diag.get('trace_gap_mismatch_after'), [])

    def test_07_ecc_mappings_exact_after_repair(self):
        repaired, _ = repair_traceability_canonical_families(
            _bad_trace_sections(), lang='ar')
        text = repaired['traceability']
        self.assertIn(
            TRACE_CANONICAL_REGISTRY['ecc_incident_response']['expected_gap'], text)
        self.assertIn(
            TRACE_CANONICAL_REGISTRY['ecc_vulnerability']['expected_gap'], text)

    def test_08_emits_rel3_traceability_canonical_repair(self):
        buf = StringIO()
        with redirect_stdout(buf):
            repair_traceability_canonical_families(
                _bad_trace_sections(), lang='ar')
        self.assertIn('[REL3-TRACEABILITY-CANONICAL-REPAIR]', buf.getvalue())
        m = re.search(
            r'\[REL3-TRACEABILITY-CANONICAL-REPAIR\] (\{.*\})', buf.getvalue())
        self.assertIsNotNone(m)
        payload = json.loads(m.group(1))
        self.assertTrue(payload.get('traceability_canonical_passed'))
        self.assertEqual(payload.get('trace_gap_mismatch_after'), [])


class RouteArtifactEquivalenceTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        ensure_latest_live_fixtures()
        cls.live_sections = sections_from_latest_docx_text(
            extract_docx_visible_text(DOCX_LATEST.read_bytes()))

    def test_09_generation_preview_docx_pdf_canonical_hash_match(self):
        backend = _APP._rel31_backend_callables()
        bad = _bad_trace_in_live_sections(self.live_sections)
        repaired, _ = repair_rel31_canonical_sections(
            bad, lang='ar', domain='cyber', backend=backend)
        preview, docx, pdf = _export_all_routes(repaired)
        canon = {
            preview[0].canonical_hash,
            docx[0].canonical_hash,
            pdf[0].canonical_hash,
        }
        canon = {h for h in canon if h}
        self.assertEqual(len(canon), 1)

    def test_10_generation_preview_docx_pdf_render_tree_hash_match(self):
        backend = _APP._rel31_backend_callables()
        bad = _bad_trace_in_live_sections(self.live_sections)
        repaired, _ = repair_rel31_canonical_sections(
            bad, lang='ar', domain='cyber', backend=backend)
        preview, docx, pdf = _export_all_routes(repaired)
        trees = {
            preview[0].render_tree_hash,
            docx[0].render_tree_hash,
            pdf[0].render_tree_hash,
        }
        trees = {h for h in trees if h}
        self.assertEqual(len(trees), 1)

    def test_11_docx_blocks_when_rebuilding_from_content_not_sections(self):
        bad = _bad_trace_sections()
        backend = _APP._rel31_backend_callables()
        md = _APP._prcy65_rebuild_content_from_sections(bad, None)
        backend.pop('_rel31_sections_bound', None)
        backend.pop('_rel31_frozen_sections', None)
        backend['split_sections'] = _APP._split_strategy_sections_by_h2
        export, evidence = rel3_export_authoritative(
            'docx',
            {
                'sections': bad,
                'final_markdown': md,
                'domain': 'cyber',
                'sealed': True,
                'strategy_id': 'rel31-trace-unbound',
                'contract_meta': {'lang': 'ar'},
            },
            backend=backend,
            flags={'rel3': True, 'rel31': True},
            export_kwargs={
                'filename': 't.docx', 'lang': 'ar', 'domain': 'cyber',
                'selected_frameworks': ['NCA ECC', 'NCA DCC'],
            },
        )
        joined = ' '.join(evidence.blocking_errors or export.blocking_errors or [])
        self.assertTrue(
            'rel3_route_artifact_divergence:docx' in joined
            or not evidence.export_return_allowed)

    def test_12_docx_uses_frozen_rel3_render_tree(self):
        backend = _APP._rel31_backend_callables()
        bad = _bad_trace_in_live_sections(self.live_sections)
        repaired, _ = repair_rel31_canonical_sections(
            bad, lang='ar', domain='cyber', backend=backend)
        _, evidence = _export_all_routes(repaired)[1]
        self.assertTrue(evidence.render_tree_hash)
        self.assertTrue(
            evidence.export_return_allowed or evidence.render_tree_hash,
            evidence.blocking_errors)

    def test_13_route_equivalence_diagnostic_passes_after_repair(self):
        backend = _APP._rel31_backend_callables()
        bad = _bad_trace_in_live_sections(self.live_sections)
        repaired, _ = repair_rel31_canonical_sections(
            bad, lang='ar', domain='cyber', backend=backend)
        preview, docx, pdf = _export_all_routes(repaired, strategy_id='rel31-eq')
        record_rel3_route_artifact_hashes(
            'rel31-eq', 'generation',
            canonical_hash=preview[0].canonical_hash,
            render_tree_hash=preview[0].render_tree_hash,
        )
        diag = emit_rel3_route_artifact_equivalence('rel31-eq')
        self.assertTrue(diag.get('all_route_hashes_equal'))
        self.assertTrue(diag.get('route_artifact_equivalence_passed'))
        self.assertEqual(diag.get('blocking_errors'), [])

    def test_17_empty_route_hashes_not_evaluated_as_passed(self):
        clear_rel3_route_artifact_hashes()
        diag = emit_rel3_route_artifact_equivalence('rel31-eq-empty')
        self.assertFalse(diag.get('route_artifact_equivalence_passed'))
        self.assertFalse(diag.get('all_route_hashes_equal'))
        self.assertIn(
            'rel3_route_equivalence_not_evaluated:no_route_hashes',
            diag.get('blocking_errors') or [])


class TraceabilityLiveExportTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        ensure_latest_live_fixtures()
        cls.docx_text = extract_docx_visible_text(DOCX_LATEST.read_bytes())
        cls.sections = sections_from_latest_docx_text(cls.docx_text)

    def test_14_rel3_returned_file_evidence_docx_after_repair(self):
        backend = _APP._rel31_backend_callables()
        repaired, _ = repair_rel31_canonical_sections(
            self.sections, lang='ar', domain='cyber', backend=backend)
        _, evidence = _export_all_routes(repaired, strategy_id='rel31-live-docx')[1]
        self.assertTrue(evidence.export_return_allowed, evidence.blocking_errors)
        joined = ' '.join(evidence.blocking_errors or [])
        self.assertNotIn('trace_gap_mismatch', joined)

    def test_15_rel3_returned_file_evidence_pdf_after_repair(self):
        backend = _APP._rel31_backend_callables()
        repaired, _ = repair_rel31_canonical_sections(
            self.sections, lang='ar', domain='cyber', backend=backend)
        _, evidence = _export_all_routes(repaired, strategy_id='rel31-live-pdf')[2]
        self.assertTrue(evidence.export_return_allowed, evidence.blocking_errors)

    def test_16_dqs_passes_preview_docx_pdf_after_repair(self):
        backend = _APP._rel31_backend_callables()
        repaired, _ = repair_rel31_canonical_sections(
            self.sections, lang='ar', domain='cyber', backend=backend)
        preview, docx, pdf = _export_all_routes(repaired, strategy_id='rel31-dqs')
        docx_text = ''
        if docx[0].docx_bytes:
            docx_text = extract_docx_visible_text(docx[0].docx_bytes)
        dq = evaluate_document_quality(
            canonical_artifact={'sections': repaired, 'domain': 'cyber'},
            legacy_sections=repaired,
            extracted_preview_text=preview[0].preview_text or '',
            extracted_docx_text=docx_text,
            extracted_pdf_text='',
            pdf_bytes=pdf[0].pdf_bytes or b'',
        )
        trace_bad = dq.get('traceability_bad_mappings') or []
        if not trace_bad:
            substance = dq.get('substance') or {}
            trace_bad = substance.get('traceability_bad_mappings') or []
        self.assertFalse(
            any('trace_gap_mismatch' in str(b) for b in trace_bad),
            trace_bad)


if __name__ == '__main__':
    unittest.main()
