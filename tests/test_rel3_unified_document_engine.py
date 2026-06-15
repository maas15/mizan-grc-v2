"""PR-REL3 — unified document engine core tests."""

import os
import sys
import tempfile
import unittest

_TMP = tempfile.mkdtemp(prefix='test_rel3_engine_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from release_engine.pillar_model import _build_canonical_pillars
from release_engine_v3.canonical_document import (
    build_final_document_artifact,
    clear_artifact_registry,
    freeze_artifact,
    guard_post_seal_mutation,
)
from release_engine_v3.contracts import TableRow, CanonicalSection
from release_engine_v3.orchestrator import (
    clear_rel3_caches,
    rel3_block_legacy_export_path,
    rel3_build_render_tree,
    rel3_export,
    rel3_freeze_artifact,
    rel3_guard_post_seal_mutation,
    rel3_verify_render_tree_parity_across_routes,
)
from release_engine_v3.render_tree import verify_render_tree_parity
from release_engine_v3.section_models import (
    build_strategy_document,
    section_to_markdown,
    strategy_document_to_markdown,
)

_GOOD_SECTIONS = {
    'vision': '## 1. الرؤية\n\nنص.\n',
    'pillars': _build_canonical_pillars('ar'),
    'environment': '## 3. البيئة\n\nنص.\n',
    'gaps': '## 4. الفجوات\n\nنص.\n',
    'roadmap': (
        '## 5. خارطة الطريق\n\n'
        '| المرحلة | الإطار | المبادرة | المالك | المخرج | الإطار |\n'
        '|---|---|---|---|---|---|\n'
        + '\n'.join(
            f'| p | 1-6 | مبادرة {i} CISO SOC IAM | CISO / الإدارة العليا | مخرج {i} | ECC |'
            for i in range(1, 12)
        )
    ),
    'kpis': (
        '## 6. مؤشرات\n\n'
        '| # | وصف | الهدف | صيغة | مصدر | تواتر |\n|---|---|---|---|---|---|\n'
        '| 1 | MTTD | 30 د | f1 | src | ش |\n'
        '| 2 | MTTR | 4 س | f2 | src | ش |\n'
    ),
    'confidence': (
        '## 7. المخاطر\n\n'
        '| المخاطرة | احتمال | أثر | المعالجة | المالك |\n|---|---|---|---|---|\n'
        '| تصيد | ع | ع | برنامج توعية | CISO |\n'
    ),
    'traceability': (
        '## 8. التتبع\n\n'
        '| ECC | فجوة | مبادرة |\n|---|---|---|\n'
        '| ECC | غياب CSIRT | CSIRT |\n'
    ),
}


def _artifact(**kw):
    base = {
        'sections': dict(_GOOD_SECTIONS),
        'domain': 'cyber',
        'sealed': True,
        'blocking_errors': [],
        'contract_meta': {'lang': 'ar', 'domain': 'cyber'},
    }
    base.update(kw)
    return build_final_document_artifact(base, freeze=False)


class Rel3UnifiedEngineTests(unittest.TestCase):

    def setUp(self):
        clear_artifact_registry()
        clear_rel3_caches()

    def test_01_preview_docx_pdf_same_render_tree_hash(self):
        art = freeze_artifact(_artifact())
        tree = rel3_build_render_tree(art)
        ok, errs, h = rel3_verify_render_tree_parity_across_routes(
            art, backend={})
        self.assertTrue(ok, errs)
        self.assertEqual(tree.render_tree_hash, h)
        prev = rel3_export('preview', tree, backend={})
        docx_tree = rel3_build_render_tree(art)
        self.assertEqual(tree.render_tree_hash, docx_tree.render_tree_hash)

    def test_02_post_seal_mutation_blocked(self):
        art = freeze_artifact(_artifact())
        blocker = rel3_guard_post_seal_mutation(art, 'pillars')
        self.assertTrue(blocker.startswith('rel3_post_seal_mutation_blocked'))

    def test_03_canonical_sections_are_typed_rows_not_pipe_strings(self):
        doc = build_strategy_document(_GOOD_SECTIONS)
        sec = doc.roadmap
        self.assertIsInstance(sec.table_rows[0], TableRow)
        self.assertGreater(len(sec.table_rows), 0)

    def test_04_markdown_view_derived_from_canonical_not_source(self):
        doc = build_strategy_document(_GOOD_SECTIONS)
        md = strategy_document_to_markdown(doc)
        self.assertIn('خارطة الطريق', md)
        self.assertIn('|', md)

    def test_05_render_tree_parity_mismatch_blocks(self):
        from release_engine_v3.contracts import RenderTree
        art = freeze_artifact(_artifact())
        t1 = rel3_build_render_tree(art)
        t2 = RenderTree(
            artifact_id=t1.artifact_id,
            canonical_hash=t1.canonical_hash,
            render_tree_hash='deadbeef000',
            nodes=t1.nodes,
            markdown_view=t1.markdown_view,
        )
        errs = verify_render_tree_parity({'preview': t1, 'docx': t2})
        self.assertTrue(errs)

    def test_06_legacy_export_path_blocked(self):
        ok, err = rel3_block_legacy_export_path('legacy_cyber_final_export_contract')
        self.assertFalse(ok)
        self.assertIn('rel3_legacy_export_path_blocked', err)

    def test_07_frozen_artifact_immutable_flag(self):
        frozen = rel3_freeze_artifact({
            'sections': _GOOD_SECTIONS,
            'domain': 'cyber',
            'sealed': True,
            'blocking_errors': [],
        })
        self.assertTrue(frozen.frozen)

    def test_08_canonical_hash_stable(self):
        a1 = _artifact()
        a2 = _artifact()
        self.assertEqual(a1.canonical_hash, a2.canonical_hash)

    def test_09_section_to_markdown_roundtrip_structure(self):
        doc = build_strategy_document(_GOOD_SECTIONS)
        md = section_to_markdown(doc.strategic_pillars)
        self.assertIn('حوكمة', md)

    def test_10_export_manifest_tracks_routes(self):
        art = freeze_artifact(_artifact())
        tree = rel3_build_render_tree(art)
        export = rel3_export('preview', tree, backend={})
        self.assertEqual(export.render_tree_hash, tree.render_tree_hash)


if __name__ == '__main__':
    unittest.main()
