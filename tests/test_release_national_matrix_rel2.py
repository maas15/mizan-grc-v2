"""PR-REL2 national release matrix — 72 strategy paths + doc types."""

import functools
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

import pytest

_TMP = tempfile.mkdtemp(prefix='test_release_national_matrix_rel2_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(_TMP, 'test.db'),
)
os.environ.setdefault('OPENAI_API_KEY', '')

_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py'))
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
    sys.modules['app'] = _APP
except Exception as _e:
    raise SystemExit(f'Cannot load app module: {_e!r}')

from domain_packs import get_domain_pack
from domains import get_domain_pack as get_legacy_pack

_MATRIX = []
for _code in ('cyber', 'data', 'ai', 'dt', 'erm', 'global'):
    for _lang in ('ar', 'en'):
        for _subtype in ('technical', 'board'):
            for _output in ('preview', 'docx', 'pdf'):
                _MATRIX.append((_code, _lang, _subtype, _output))

_DOMAIN_ALIAS = {
    'data': 'data_management',
    'ai': 'artificial_intelligence',
    'dt': 'digital_transformation',
    'erm': 'enterprise_risk_management',
    'global': 'global_standards',
}


def _require_app(fn):
    @functools.wraps(fn)
    def _w(*a, **kw):
        if _APP is None:
            raise unittest.SkipTest('app unavailable')
        return fn(*a, **kw)
    return _w


def _sections_for(domain_code, lang, doc_subtype):
    legacy = get_legacy_pack(domain_code)
    pack = get_domain_pack(_DOMAIN_ALIAS.get(domain_code, domain_code)) or legacy
    assert pack is not None
    fx = pack['fixtures_ar'] if lang == 'ar' else pack['fixtures_en']
    if doc_subtype == 'board' and hasattr(fx, 'board_sections'):
        return fx.board_sections()
    return fx.technical_sections()


def _content(sections):
    if hasattr(_APP, '_prcy65_rebuild_content_from_sections'):
        return _APP._prcy65_rebuild_content_from_sections(sections, None)
    order = ('vision', 'pillars', 'environment', 'gaps',
             'roadmap', 'kpis', 'confidence')
    return '\n\n'.join(sections[k] for k in order if sections.get(k))


@_require_app
def _build(domain, lang, doc_subtype):
    sections = _sections_for(domain, lang, doc_subtype)
    frameworks = (get_legacy_pack(domain) or {}).get('frameworks_default') or []
    buf = io.StringIO()
    with redirect_stdout(buf):
        art = _APP._build_cyber_final_strategy_artifact(
            _content(sections),
            sections=dict(sections),
            metadata={'domain': domain},
            selected_frameworks=frameworks,
            lang=lang,
            domain=domain,
            output_type='generation',
            doc_subtype=doc_subtype,
            generation_mode='consulting',
        )
    return art, buf.getvalue()


class ReleaseNationalMatrixRel2Smoke(unittest.TestCase):

    def test_rel2_flag_live(self):
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('rel2'))

    @_require_app
    def test_cyber_release_ready_ar_technical(self):
        art, _ = _build('cyber', 'ar', 'technical')
        self.assertTrue(art.get('sealed'), art.get('blocking_errors'))
        if _APP._PRCY28_VERSION_FLAGS.get('rel2'):
            self.assertTrue(
                art.get('release_ready_final_passed'),
                (art.get('blocking_errors'), art.get('failed_dimensions')))


@pytest.mark.parametrize('domain,lang,doc_subtype,output_type', _MATRIX)
class TestReleaseNationalMatrixRel2:
    """72 strategy paths: seal → rel2 contract → export hash parity."""

    @_require_app
    def test_matrix_path(self, domain, lang, doc_subtype, output_type):
        art, _ = _build(domain, lang, doc_subtype)
        blockers = art.get('blocking_errors') or []
        assert art.get('sealed'), f'{domain}/{lang}/{doc_subtype}: {blockers!r}'
        assert not blockers
        if _APP._PRCY28_VERSION_FLAGS.get('rel2'):
            assert art.get('release_ready_final_passed'), (
                f'rel2 not ready: score={art.get("board_ready_score")} '
                f'dims={art.get("failed_dimensions")!r}')
            assert (art.get('board_ready_score') or 0) >= 80
        fh = art['final_hash']
        meta = {
            'domain': domain,
            'sealed': True,
            'final_hash': fh,
            'quality_gate_passed': True,
        }
        c = _APP._prcy80_invoke_final_strategy_artifact(
            art['final_markdown'],
            metadata=meta,
            selected_frameworks=(
                (get_legacy_pack(domain) or {}).get('frameworks_default') or []),
            lang=lang,
            domain=domain,
            output_type=output_type,
            read_only=True,
            sections=art.get('sections'),
            doc_subtype=doc_subtype,
        )
        assert c.get('content_hash') == fh, output_type


@pytest.mark.parametrize('domain', ('cyber', 'data', 'ai'))
@pytest.mark.parametrize('lang', ('ar', 'en'))
class TestNoisyFixtureRepairRel2:
    """Deterministic noisy fixtures must repair or block precisely."""

    @_require_app
    def test_noisy_repair_or_block(self, domain, lang):
        from release_engine.orchestrator import process_release_artifact
        pack = get_domain_pack(_DOMAIN_ALIAS.get(domain, domain))
        clean = _sections_for(domain, lang, 'technical')
        noisy_fn = pack.get('noisy_sections')
        if not noisy_fn:
            pytest.skip('no noisy fixture')
        noisy = noisy_fn(clean)
        art = {
            'sections': noisy,
            'final_markdown': _content(noisy),
            'blocking_errors': [],
            'sealed': False,
            'rel2_force_repair': True,
            'domain': domain,
            'quality_flags': {},
        }
        out = process_release_artifact(
            art,
            domain=domain,
            lang=lang,
            backend=_APP._rel2_backend_callables() if hasattr(_APP, '_rel2_backend_callables') else {},
            domain_pack=pack,
            skip_rel1=True,
        )
        assert out.get('repair_actions') or out.get('blocking_errors')
        if out.get('sealed'):
            assert (out.get('sections') or {}).get('pillars')


_DOC_TYPES = (
    'policy', 'procedure', 'risk_register', 'audit',
    'roadmap', 'kpi_kri', 'executive_summary',
)
_DOC_MATRIX = [
    (d, lang, dt, out)
    for d in ('cyber', 'data', 'ai', 'dt', 'erm', 'global')
    for lang in ('ar', 'en')
    for dt in _DOC_TYPES
    for out in ('preview', 'docx', 'pdf')
]


@_require_app
def _build_document(domain, lang, document_type):
    from domain_packs._doc_fixtures import sections_for_document
    sections = sections_for_document(domain, lang, document_type)
    if domain == 'cyber':
        frameworks = (get_legacy_pack(domain) or {}).get('frameworks_default') or []
        buf = io.StringIO()
        with redirect_stdout(buf):
            return _APP._build_cyber_final_strategy_artifact(
                _content(sections),
                sections=dict(sections),
                metadata={'domain': domain, 'document_type': document_type},
                selected_frameworks=frameworks,
                lang=lang,
                domain=domain,
                output_type='generation',
                doc_subtype='technical',
                generation_mode='consulting',
            ), buf.getvalue()
    art = {
        'sections': dict(sections),
        'final_markdown': _content(sections),
        'blocking_errors': [],
        'sealed': False,
        'domain': domain,
        'quality_flags': {},
    }
    return _APP._rel2_apply_release_engine(
        art,
        domain=domain,
        lang=lang,
        doc_subtype='technical',
        document_type=document_type,
    ), ''


@pytest.mark.parametrize('domain,lang,document_type,output_type', _DOC_MATRIX)
class TestReleaseDocumentMatrixRel21:
    """E2E document-type matrix: repair → contract → seal → export parity."""

    @_require_app
    def test_document_matrix_path(
            self, domain, lang, document_type, output_type):
        art, _ = _build_document(domain, lang, document_type)
        blockers = art.get('blocking_errors') or []
        assert art.get('sealed'), (
            f'{domain}/{lang}/{document_type}: {blockers!r}')
        assert not blockers
        assert art.get('release_ready_final_passed'), (
            f'score={art.get("board_ready_score")} dims={art.get("failed_dimensions")}')
        fh = art['final_hash']
        meta = {
            'domain': domain,
            'sealed': True,
            'final_hash': fh,
            'quality_gate_passed': True,
        }
        c = _APP._prcy80_invoke_final_strategy_artifact(
            art['final_markdown'],
            metadata=meta,
            selected_frameworks=(
                (get_legacy_pack(domain) or {}).get('frameworks_default') or []),
            lang=lang,
            domain=domain,
            output_type=output_type,
            read_only=True,
            sections=art.get('sections'),
            doc_subtype='technical',
        )
        assert c.get('content_hash') == fh, output_type


class TestRel21Cy89Integration(unittest.TestCase):

    @_require_app
    def test_integration_diag_emitted_for_cyber(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            art, _ = _build('cyber', 'ar', 'technical')
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('prcy89'))
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('rel2'))
        self.assertTrue((art.get('diagnostics') or {}).get('prcy89'))
        self.assertTrue((art.get('diagnostics') or {}).get('rel2'))
        self.assertTrue(art.get('release_ready_final_passed'))
        out = buf.getvalue()
        if out.strip():
            self.assertIn('[REL2-CY89-INTEGRATION-CHECK]', out)
        p89 = (art.get('diagnostics') or {}).get('prcy89') or {}
        self.assertTrue(
            p89.get('artifact_validation_passed')
            or p89.get('cyber_board_ready_final_passed')
            or art.get('contract_meta', {}).get(
                'prcy89_artifact_validation_passed')
            or art.get('release_ready_final_passed'))


if __name__ == '__main__':
    unittest.main()
