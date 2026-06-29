"""PR-REL3.2 — frozen artifact export lock and route hash parity."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel32_lock_')
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
)
from release_engine_v3.canonical_document import clear_artifact_registry
from release_engine_v3.document_quality_spec import evaluate_document_quality
from release_engine_v3.evidence.docx_text_extractor import extract_docx_visible_text
from release_engine_v3.orchestrator import (
    clear_rel3_caches,
    rel3_build_render_tree,
    rel3_freeze_artifact,
)
from release_engine_v3.rel31_authority import (
    clear_rel3_route_artifact_hashes,
    emit_rel3_route_artifact_equivalence,
    record_rel3_route_artifact_hashes,
    rel3_export_authoritative,
    repair_canonical_before_freeze,
)
from release_engine_v3.rel32_frozen_export_lock import (
    clear_rel32_frozen_export_lock,
    emit_rel32_frozen_artifact_export_lock,
    guard_rel32_docx_export_bypass,
    prepare_rel32_export_artifact_dict,
    register_rel32_frozen_export_lock,
)
from tests.fixtures.rel31_content_quality.latest_live_fixtures import (
    ensure_latest_live_fixtures,
    sections_from_latest_docx_text,
    DOCX_LATEST,
)
from tests.test_rel31_traceability_route_equivalence import (
    _bad_trace_flat_blob,
    _bad_trace_in_live_sections,
    _bad_trace_sections,
)


def _reset_export_state() -> None:
    clear_rel3_caches()
    clear_rel3_route_artifact_hashes()
    clear_rel32_frozen_export_lock()
    clear_artifact_registry()


def _minimal_sections(trace_body: str | None = None) -> dict:
    trace = trace_body or build_canonical_traceability_from_registry(lang='ar')
    return {
        'vision': (
            '## الرؤية والأهداف الاستراتيجية\n\n'
            '| # | الهدف الاستراتيجي | المؤشر | الهدف | الإطار |\n'
            '|---|---|---|---|---|\n'
            '| 1 | حوكمة الأمن السيبراني | KPI | 90% | NCA ECC |\n'
            '| 2 | الامتثال التنظيمي | KPI | 95% | NCA DCC |\n'
            '| 3 | مراقبة الأمن | KPI | 85% | NCA ECC |\n'
            '| 4 | إدارة الهوية | KPI | 90% | NCA ECC |\n'
            '| 5 | الاستجابة للحوادث | KPI | 80% | NCA ECC |\n'
            '| 6 | إدارة الثغرات | KPI | 85% | NCA ECC |\n'
            '| 7 | حماية البيانات | KPI | 90% | NCA DCC |\n'
            '| 8 | التوعية الأمنية | KPI | 75% | NCA ECC |\n'
        ),
        'pillars': '## الركائز الاستراتيجية\n\nحوكمة ونموذج التشغيل\n',
        'environment': '## البيئة التنظيمية والتهديدات\n\nسياق تنظيمي\n',
        'gaps': '## تحليل الفجوات\n\n| الفجوة | الأولوية |\n|---|---|\n| فجوة | عالية |\n',
        'roadmap': (
            '## خارطة الطريق التنفيذية\n\n'
            '| المرحلة | المبادرة | المالك | الموعد |\n'
            '|---|---|---|---|\n'
            '| Q1 | مبادرة | CISO | 2026-Q1 |\n'
        ),
        'kpis': (
            '## مؤشرات الأداء الرئيسية\n\n'
            '| المؤشر | الهدف | التكرار |\n|---|---|---|\n'
            '| MTTD | 15 دقيقة | شهري |\n'
        ),
        'confidence': (
            '## تقييم الثقة والمخاطر\n\n'
            'درجة الثقة: 85\n\nمبررات التقييم:\nتقييم أولي\n'
        ),
        'governance': '## نموذج الحوكمة والمسؤوليات\n\n| الدور | المسؤولية |\n|---|---|\n',
        'traceability': trace,
    }


def _freeze_generation(
        sections: dict,
        *,
        strategy_id: str = 'rel32-lock-gen',
) -> tuple:
    _reset_export_state()
    backend = _APP._rel31_backend_callables()
    md = _APP._prcy65_rebuild_content_from_sections(sections, None)
    art = {
        'sections': dict(sections),
        'final_markdown': md,
        'domain': 'cyber',
        'sealed': True,
        'strategy_id': strategy_id,
        'contract_meta': {'lang': 'ar'},
    }
    art, _ = repair_canonical_before_freeze(art, backend=backend)
    frozen = rel3_freeze_artifact(art, strategy_id=strategy_id)
    tree = rel3_build_render_tree(frozen)
    frozen.render_tree_hash = tree.render_tree_hash
    register_rel32_frozen_export_lock(
        frozen, render_tree_hash=tree.render_tree_hash)
    record_rel3_route_artifact_hashes(
        strategy_id, 'generation',
        canonical_hash=frozen.canonical_hash,
        render_tree_hash=tree.render_tree_hash,
    )
    return frozen, tree, backend


def _export_route(
        route: str,
        *,
        sections: dict,
        strategy_id: str,
        backend,
        flags=None,
):
    md = _APP._prcy65_rebuild_content_from_sections(sections, None)
    art = {
        'sections': dict(sections),
        'final_markdown': md,
        'domain': 'cyber',
        'sealed': True,
        'strategy_id': strategy_id,
        'contract_meta': {'lang': 'ar'},
    }
    kwargs = {
        'filename': 't.docx', 'lang': 'ar', 'domain': 'cyber',
        'selected_frameworks': ['NCA ECC', 'NCA DCC'],
    }
    return rel3_export_authoritative(
        route, art, backend=backend,
        flags=flags or {'rel3': True, 'rel31': True},
        export_kwargs=kwargs,
    )


class Rel32DocxBypassTests(unittest.TestCase):

    def test_01_docx_bypass_blocked_outside_adapter(self):
        blk = guard_rel32_docx_export_bypass('_build_docx_bytes')
        self.assertEqual(blk, 'rel32_docx_export_bypass_detected:_build_docx_bytes')

    def test_02_docx_bypass_allowed_inside_adapter(self):
        from release_engine_v3.rel31_authority import rel31_export_adapter_context
        with rel31_export_adapter_context():
            self.assertIsNone(guard_rel32_docx_export_bypass('_build_docx_bytes'))

    def test_03_build_docx_bytes_raises_outside_adapter(self):
        with self.assertRaises(ValueError) as ctx:
            _APP._build_docx_bytes(
                'test', 't.docx', 'ar', domain='cyber',
                rel2_export_validation=False,
            )
        self.assertIn('rel32_docx_export_bypass_detected', str(ctx.exception))


class Rel32FrozenExportLockTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        ensure_latest_live_fixtures()
        cls.live_sections = sections_from_latest_docx_text(
            extract_docx_visible_text(DOCX_LATEST.read_bytes()))

    def setUp(self):
        _reset_export_state()

    def test_04_client_divergent_sections_ignored_when_frozen_loaded(self):
        good = _minimal_sections()
        frozen, _, backend = _freeze_generation(good, strategy_id='rel32-ignore-client')
        bad = dict(good)
        bad.update(_bad_trace_sections())
        export, evidence = _export_route(
            'docx', sections=bad, strategy_id='rel32-ignore-client',
            backend=backend)
        self.assertEqual(export.canonical_hash, frozen.canonical_hash)
        self.assertFalse(any(
            'rel32_export_client_markdown_divergence' in str(b)
            for b in (evidence.blocking_errors or [])))

    def test_05_docx_canonical_hash_matches_generation(self):
        good = _minimal_sections()
        frozen, _, backend = _freeze_generation(good, strategy_id='rel32-canon-docx')
        export, evidence = _export_route(
            'docx', sections=good, strategy_id='rel32-canon-docx',
            backend=backend)
        self.assertEqual(export.canonical_hash, frozen.canonical_hash)
        self.assertTrue(evidence.export_return_allowed, evidence.blocking_errors)

    def test_06_pdf_render_tree_hash_matches_generation(self):
        good = _minimal_sections()
        frozen, tree, backend = _freeze_generation(good, strategy_id='rel32-tree-pdf')
        export, evidence = _export_route(
            'pdf', sections=good, strategy_id='rel32-tree-pdf',
            backend=backend)
        self.assertEqual(export.render_tree_hash, tree.render_tree_hash)
        self.assertEqual(export.canonical_hash, frozen.canonical_hash)

    def test_07_docx_pdf_share_canonical_hash(self):
        good = _minimal_sections()
        _freeze_generation(good, strategy_id='rel32-shared-canon')
        backend = _APP._rel31_backend_callables()
        docx_export, _ = _export_route(
            'docx', sections=good, strategy_id='rel32-shared-canon',
            backend=backend)
        pdf_export, _ = _export_route(
            'pdf', sections=good, strategy_id='rel32-shared-canon',
            backend=backend)
        self.assertEqual(docx_export.canonical_hash, pdf_export.canonical_hash)

    def test_08_docx_pdf_share_render_tree_hash(self):
        good = _minimal_sections()
        _freeze_generation(good, strategy_id='rel32-shared-tree')
        backend = _APP._rel31_backend_callables()
        docx_export, _ = _export_route(
            'docx', sections=good, strategy_id='rel32-shared-tree',
            backend=backend)
        pdf_export, _ = _export_route(
            'pdf', sections=good, strategy_id='rel32-shared-tree',
            backend=backend)
        self.assertEqual(
            docx_export.render_tree_hash, pdf_export.render_tree_hash)

    def test_09_sensitive_handling_canonical_trace_in_docx(self):
        spec = TRACE_CANONICAL_REGISTRY['sensitive_handling']
        good = _minimal_sections()
        _freeze_generation(good, strategy_id='rel32-trace-canonical')
        backend = _APP._rel31_backend_callables()
        export, evidence = _export_route(
            'docx', sections=good, strategy_id='rel32-trace-canonical',
            backend=backend)
        self.assertTrue(evidence.export_return_allowed, evidence.blocking_errors)
        text = extract_docx_visible_text(export.docx_bytes or b'')
        self.assertIn(spec['capability'], text)
        self.assertIn(spec['expected_gap'], text)
        defects = flat_traceability_bad_mappings(text)
        self.assertNotIn(f'trace_gap_mismatch:{spec["capability"]}', defects)

    def test_10_bad_trace_fixture_fails_before_repair(self):
        bad = _bad_trace_sections()
        blockers = check_traceability_bad_mappings(bad['traceability'])
        self.assertTrue(blockers)
        defects = flat_traceability_bad_mappings(_bad_trace_flat_blob())
        self.assertTrue(any('معالجة البيانات' in d or 'تصنيف البيانات' in d
                            for d in defects))

    def test_11_frozen_lock_passes_after_canonical_repair(self):
        backend = _APP._rel31_backend_callables()
        bad = _bad_trace_in_live_sections(self.live_sections)
        repaired, _ = repair_rel31_canonical_sections(
            bad, lang='ar', domain='cyber', backend=backend)
        frozen, _, _ = _freeze_generation(
            repaired, strategy_id='rel32-live-lock')
        export, evidence = _export_route(
            'docx', sections=repaired, strategy_id='rel32-live-lock',
            backend=backend)
        self.assertEqual(export.canonical_hash, frozen.canonical_hash)
        self.assertTrue(evidence.export_return_allowed, evidence.blocking_errors)
        buf = io.StringIO()
        with redirect_stdout(buf):
            lock = emit_rel32_frozen_artifact_export_lock(
                'rel32-live-lock', route='docx')
        self.assertTrue(lock.get('frozen_artifact_loaded_for_docx'))
        self.assertFalse(lock.get('docx_rebuilt_from_markdown'))

    def test_12_dqs_route_count_zero_is_pre_export_phase(self):
        good = _minimal_sections()
        dq = evaluate_document_quality(
            canonical_artifact={'sections': good, 'domain': 'cyber'},
            legacy_sections=good,
        )
        self.assertEqual(dq.get('phase'), 'pre_export_model_validation')
        self.assertEqual(len(dq.get('route_evidence') or {}), 0)

    def test_13_dqs_with_routes_is_returned_file_validation(self):
        good = _minimal_sections()
        frozen, tree, backend = _freeze_generation(good, strategy_id='rel32-dqs-phase')
        preview_export, _ = _export_route(
            'preview', sections=good, strategy_id='rel32-dqs-phase',
            backend=backend)
        docx_export, _ = _export_route(
            'docx', sections=good, strategy_id='rel32-dqs-phase',
            backend=backend)
        docx_text = extract_docx_visible_text(docx_export.docx_bytes or b'')
        dq = evaluate_document_quality(
            canonical_artifact={'sections': good, 'domain': 'cyber'},
            legacy_sections=good,
            extracted_preview_text=preview_export.preview_text or '',
            extracted_docx_text=docx_text,
            render_tree=type('T', (), {'render_tree_hash': tree.render_tree_hash})(),
        )
        self.assertEqual(dq.get('phase'), 'returned_file_validation')
        self.assertGreaterEqual(len(dq.get('route_evidence') or {}), 1)

    def test_14_rel32_frozen_lock_diagnostic_fields(self):
        good = _minimal_sections()
        _freeze_generation(good, strategy_id='rel32-diag')
        backend = _APP._rel31_backend_callables()
        _export_route('preview', sections=good, strategy_id='rel32-diag', backend=backend)
        _export_route('docx', sections=good, strategy_id='rel32-diag', backend=backend)
        _export_route('pdf', sections=good, strategy_id='rel32-diag', backend=backend)
        buf = io.StringIO()
        with redirect_stdout(buf):
            lock = emit_rel32_frozen_artifact_export_lock('rel32-diag')
        out = buf.getvalue()
        self.assertIn('[REL32-FROZEN-ARTIFACT-EXPORT-LOCK]', out)
        self.assertTrue(lock.get('export_lock_passed'))
        self.assertEqual(lock.get('blocking_errors'), [])
        canon_set = {
            lock.get('generation_canonical_hash'),
            lock.get('preview_canonical_hash'),
            lock.get('docx_canonical_hash'),
            lock.get('pdf_canonical_hash'),
        }
        canon_set.discard('')
        self.assertEqual(len(canon_set), 1)

    def test_15_prepare_rel32_uses_registry_sections(self):
        good = _minimal_sections()
        _freeze_generation(good, strategy_id='rel32-prepare')
        backend = _APP._rel31_backend_callables()
        bad = dict(good)
        bad.update(_bad_trace_sections())
        prepared = prepare_rel32_export_artifact_dict(
            {
                'sections': bad,
                'final_markdown': 'stale markdown',
                'domain': 'cyber',
                'strategy_id': 'rel32-prepare',
                'contract_meta': {'lang': 'ar'},
            },
            backend=backend,
            flags={'rel3': True, 'rel31': True},
        )
        self.assertTrue(prepared.get('_rel32_frozen_loaded'))
        spec = TRACE_CANONICAL_REGISTRY['sensitive_handling']
        self.assertIn(spec['expected_gap'], prepared['sections'].get('traceability', ''))
        self.assertNotIn(
            _bad_trace_sections()['traceability'][:40],
            prepared['sections'].get('traceability', '')[:40],
        )

    def test_16_lookup_keys_resolve_hash_to_numeric_strategy_id(self):
        from release_engine_v3.rel32_frozen_export_lock import _rel32_lookup_keys

        def _resolver(key, _uid):
            return 7 if str(key).startswith('hash-') else None

        keys = _rel32_lookup_keys(
            {
                'strategy_id': 'hash-058e5a27fdb7d2d9',
                'artifact_id': 'hash-058e5a27fdb7d2d9',
            },
            backend={
                'resolve_strategy_id': _resolver,
                '_rel32_export_user_id': 1,
            },
        )
        self.assertEqual(keys[0], '7')
        self.assertIn('hash-058e5a27fdb7d2d9', keys)


class Rel32RouteEquivalenceAfterLockTests(unittest.TestCase):

    def setUp(self):
        _reset_export_state()

    def test_16_route_equivalence_after_frozen_exports(self):
        good = _minimal_sections()
        frozen, tree, backend = _freeze_generation(
            good, strategy_id='rel32-equiv')
        preview_export, _ = _export_route(
            'preview', sections=good, strategy_id='rel32-equiv', backend=backend)
        docx_export, _ = _export_route(
            'docx', sections=good, strategy_id='rel32-equiv', backend=backend)
        pdf_export, _ = _export_route(
            'pdf', sections=good, strategy_id='rel32-equiv', backend=backend)
        record_rel3_route_artifact_hashes(
            'rel32-equiv', 'generation',
            canonical_hash=frozen.canonical_hash,
            render_tree_hash=tree.render_tree_hash,
        )
        diag = emit_rel3_route_artifact_equivalence('rel32-equiv')
        self.assertTrue(diag.get('route_artifact_equivalence_passed'), diag)
        self.assertEqual(preview_export.canonical_hash, docx_export.canonical_hash)
        self.assertEqual(preview_export.canonical_hash, pdf_export.canonical_hash)


if __name__ == '__main__':
    unittest.main()
