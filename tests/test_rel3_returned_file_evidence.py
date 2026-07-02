"""PR-REL3 — returned-file evidence on exact bytes."""

import hashlib
import os
import sys
import tempfile
import unittest

_TMP = tempfile.mkdtemp(prefix='test_rel3_evidence_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from release_engine.pillar_model import _build_canonical_pillars
from release_engine_v3.canonical_document import freeze_artifact, build_final_document_artifact
from release_engine_v3.contracts import ExportResult, _sha256_bytes
from release_engine_v3.evidence.evidence_validator import validate_returned_export_bytes
from release_engine_v3.orchestrator import (
    clear_rel3_caches,
    rel3_export_with_evidence,
    rel3_invalidate_export_cache,
)

_GOOD = (
    '## 1. الرؤية\n\nنص.\n'
    + _build_canonical_pillars('ar')
    + '\n## 5. خارطة الطريق\n\n'
    + '\n'.join(
        f'| p | t | مبادرة {i} governance soc | CISO / الإدارة العليا | out | ECC |'
        for i in range(1, 12)
    )
    + '\n## 6. مؤشرات\n| # | وصف المؤشر | tgt | f | s | freq |\n|---|---|---|---|---|---|\n'
    '| 1 | MTTD | 30 | f | s | m |\n| 2 | MTTR | 4h | f | s | m |\n'
    + '\n## 7. risk\n| r | p | i | plan | o |\n|---|---|---|---|---|\n'
    '| x | h | h | action | CISO |\n'
)

_BAD_KPI = (
    '## 6. KPI\n| # | وصف | tgt | f | s | freq |\n|---|---|---|---|---|---|\n'
    '| NCA DCC | MTTR | 90% | f | s | m |\n| 2 | MTTR | 90% | f | s | m |\n'
)

_BAD_RISK = (
    '## 7. risk\n| r | p | i | plan | o |\n|---|---|---|---|---|\n| x | h | h | — | o |\n'
)

_BAD_AR = _GOOD + '\nالحاليةفي\n'

_MISSING_PILLARS = '## 2. الركائز\n\n### حوكمة\n\nنص.\n'


def _frozen(**kw):
    art = build_final_document_artifact({
        'sections': kw.get('sections') or {'vision': _GOOD, 'pillars': _build_canonical_pillars('ar')},
        'domain': 'cyber',
        'sealed': True,
        'blocking_errors': [],
        'contract_meta': {'lang': 'ar'},
    })
    return freeze_artifact(art)


class Rel3ReturnedFileEvidenceTests(unittest.TestCase):

    def setUp(self):
        clear_rel3_caches()

    def test_01_returned_equals_evidence_bytes_required(self):
        art = _frozen()
        data = b'docx-bytes-test'
        export = ExportResult(
            route_name='docx',
            artifact_id=art.artifact_id,
            render_tree_hash='abc',
            canonical_hash=art.canonical_hash,
            docx_bytes=data,
            bytes_data=data,
            returned_bytes_sha256=_sha256_bytes(data),
            evidence_bytes_sha256='different',
            returned_equals_evidence_bytes=False,
            exact_bytes_checked=True,
        )
        ev = validate_returned_export_bytes(export, art, route='docx')
        self.assertFalse(ev.export_return_allowed)
        self.assertIn('returned_bytes_mismatch', ' '.join(ev.blocking_errors))

    def test_02_exact_bytes_checked_docx(self):
        art = _frozen()
        blob = _GOOD.encode('utf-8')
        export = ExportResult(
            route_name='docx',
            artifact_id=art.artifact_id,
            render_tree_hash='h',
            canonical_hash=art.canonical_hash,
            docx_bytes=blob,
            bytes_data=blob,
            returned_bytes_sha256=_sha256_bytes(blob),
            evidence_bytes_sha256=_sha256_bytes(blob),
            returned_equals_evidence_bytes=True,
            exact_bytes_checked=True,
        )
        ev = validate_returned_export_bytes(export, art, route='docx')
        self.assertTrue(ev.exact_bytes_checked)
        self.assertTrue(ev.returned_equals_evidence_bytes)

    def test_03_missing_pillars_blocks_docx(self):
        art = _frozen()
        export = ExportResult(
            route_name='docx',
            artifact_id=art.artifact_id,
            render_tree_hash='h',
            canonical_hash=art.canonical_hash,
            docx_bytes=_MISSING_PILLARS.encode('utf-8'),
            bytes_data=_MISSING_PILLARS.encode('utf-8'),
            returned_bytes_sha256=_sha256_bytes(_MISSING_PILLARS.encode()),
            evidence_bytes_sha256=_sha256_bytes(_MISSING_PILLARS.encode()),
            returned_equals_evidence_bytes=True,
            exact_bytes_checked=True,
        )
        ev = validate_returned_export_bytes(export, art, route='docx')
        self.assertFalse(ev.export_return_allowed)

    def test_04_kpi_nca_dcc_blocks(self):
        art = _frozen()
        blob = (_GOOD + _BAD_KPI).encode('utf-8')
        export = ExportResult(
            route_name='docx', artifact_id=art.artifact_id,
            render_tree_hash='h', canonical_hash=art.canonical_hash,
            docx_bytes=blob, bytes_data=blob,
            returned_bytes_sha256=_sha256_bytes(blob),
            evidence_bytes_sha256=_sha256_bytes(blob),
            returned_equals_evidence_bytes=True, exact_bytes_checked=True,
        )
        ev = validate_returned_export_bytes(export, art, route='docx')
        self.assertFalse(ev.export_return_allowed)

    def test_05_risk_dash_blocks(self):
        art = _frozen()
        blob = (_GOOD + _BAD_RISK).encode('utf-8')
        export = ExportResult(
            route_name='docx', artifact_id=art.artifact_id,
            render_tree_hash='h', canonical_hash=art.canonical_hash,
            docx_bytes=blob, bytes_data=blob,
            returned_bytes_sha256=_sha256_bytes(blob),
            evidence_bytes_sha256=_sha256_bytes(blob),
            returned_equals_evidence_bytes=True, exact_bytes_checked=True,
        )
        ev = validate_returned_export_bytes(export, art, route='docx')
        self.assertFalse(ev.export_return_allowed)

    def test_06_arabic_residue_blocks(self):
        art = _frozen()
        blob = _BAD_AR.encode('utf-8')
        export = ExportResult(
            route_name='docx', artifact_id=art.artifact_id,
            render_tree_hash='h', canonical_hash=art.canonical_hash,
            docx_bytes=blob, bytes_data=blob,
            returned_bytes_sha256=_sha256_bytes(blob),
            evidence_bytes_sha256=_sha256_bytes(blob),
            returned_equals_evidence_bytes=True, exact_bytes_checked=True,
        )
        ev = validate_returned_export_bytes(export, art, route='docx')
        self.assertFalse(ev.export_return_allowed)

    def test_07_preview_evidence_passes_clean_text(self):
        art = _frozen()
        export = ExportResult(
            route_name='preview', artifact_id=art.artifact_id,
            render_tree_hash='h', canonical_hash=art.canonical_hash,
            preview_text=_GOOD,
            returned_bytes_sha256=hashlib.sha256(_GOOD.encode()).hexdigest(),
            evidence_bytes_sha256=hashlib.sha256(_GOOD.encode()).hexdigest(),
            returned_equals_evidence_bytes=True,
        )
        ev = validate_returned_export_bytes(export, art, route='preview')
        self.assertTrue(ev.preview_text_checked)

    def test_08_cache_invalidation_on_failure(self):
        rel3_invalidate_export_cache('aid', 'docx', 'hash1')
        rel3_invalidate_export_cache('aid', 'docx', 'hash1')  # no error

    def test_09_emit_diag_contains_required_fields(self):
        art = _frozen()
        export = ExportResult(
            route_name='preview', artifact_id=art.artifact_id,
            render_tree_hash='h', canonical_hash=art.canonical_hash,
            preview_text=_GOOD,
            returned_bytes_sha256='a', evidence_bytes_sha256='a',
            returned_equals_evidence_bytes=True,
        )
        ev = validate_returned_export_bytes(export, art, route='preview')
        diag = ev.emit_diag()
        for field in (
            'route_name', 'artifact_id', 'canonical_hash', 'render_tree_hash',
            'returned_bytes_sha256', 'evidence_bytes_sha256',
            'returned_equals_evidence_bytes', 'exact_bytes_checked',
            'evidence_passed', 'export_return_allowed', 'blocking_errors',
        ):
            self.assertIn(field, diag)

    def test_10_export_with_evidence_fails_closed(self):
        art = _frozen()
        backend = {
            'build_docx_bytes': lambda *a, **k: _MISSING_PILLARS.encode('utf-8'),
            'split_sections': lambda x: {},
        }
        export, ev = rel3_export_with_evidence(
            'docx', art, backend=backend,
            export_kwargs={'filename': 't.docx', 'lang': 'ar'})
        self.assertFalse(ev.export_return_allowed)


if __name__ == '__main__':
    unittest.main()
