"""PR-REL3.3 — tests for deterministic gap_assessment placeholder completion."""

import re

import pytest

from release_engine_v3.rel33_gap_placeholder_completion import (
    FRAMEWORK_PROFILE_AR,
    FRAMEWORK_PROFILE_EN,
    ORG_PROFILE_AR,
    apply_gap_placeholder_completion,
    count_forbidden_placeholders,
    is_gap_placeholder_completion_applicable,
    resolve_gap_assessment_context,
    run_gap_placeholder_completion,
)

_APP_GATE_KEYS = ('vision', 'environment', 'gaps', 'roadmap', 'confidence')
_APP_GATE_PATS = (
    r'\*\*Frameworks?:\*\*\s*Not specified',
    r'\*\*Frameworks?:\*\*\s*\s*$',
    r'Regulatory Context[\s\S]{0,200}?Not specified',
    r'غير محدد',
)


def _app_placeholder_gate_hits(sections):
    """Exact app.py placeholder-text gate (must stay fail-closed)."""
    hits = []
    for key in _APP_GATE_KEYS:
        txt = sections.get(key, '') or ''
        if not txt:
            continue
        for pat in _APP_GATE_PATS:
            if re.search(pat, txt, re.IGNORECASE):
                hits.append(key)
                break
    return hits


def _gap_table(*, org='جهة قائمة', fw='ISO/IEC 27001:2022',
               current='تطبيق جزئي موثق', target='امتثال قابل للقياس',
               rec='خطة معالجة معتمدة'):
    return (
        '## تحليل الفجوات\n\n'
        '| # | الإطار | الجهة | الحالة الحالية | الحالة المستهدفة | '
        'التوصية |\n'
        '|---|---|---|---|---|---|\n'
        f'| 1 | {fw} | {org} | {current} | {target} | {rec} |\n'
    )


def test_missing_org_profile_replaces_unspecified():
    data = {
        'org_name': '',
        'org_structure': 'غير محدد',
        'frameworks': ['ISO/IEC 27001:2022'],
    }
    ctx = resolve_gap_assessment_context(
        data, lang='ar', domain='global', document_type='gap_assessment')
    assert data['org_name'] == ORG_PROFILE_AR
    assert data['org_structure'] == ORG_PROFILE_AR
    assert 'غير محدد' not in data['org_structure']
    assert 'غير محدد' not in data['org_name']
    assert ctx['organization_profile_after'] == ORG_PROFILE_AR


def test_missing_framework_replaces_not_specified():
    data = {
        'org_name': 'REL33 P1 Global Org',
        'org_structure': 'Compliance Lead reports to CIO',
        'frameworks': ['Not specified'],
    }
    ctx = resolve_gap_assessment_context(
        data, lang='en', domain='Global Standards',
        document_type='gap_assessment')
    joined = ' '.join(data['frameworks'])
    assert 'Not specified' not in joined
    assert FRAMEWORK_PROFILE_EN in joined
    assert 'ISO/IEC 27001:2022' in joined
    assert 'NCA' not in joined
    assert 'NDMO' not in joined
    assert FRAMEWORK_PROFILE_EN in ctx['framework_profile_after']


def test_completion_removes_unspecified_ar_from_gap_rows():
    sections = {
        'gaps': _gap_table(org='غير محدد', current='غير محددة'),
        '_document_type': 'gap_assessment',
    }
    diag = apply_gap_placeholder_completion(
        sections, domain='global', document_type='gap_assessment',
        lang='ar', emit=False)
    assert diag['placeholders_before'] > 0
    assert diag['placeholders_after'] == 0
    assert 'غير محدد' not in sections['gaps']
    assert ORG_PROFILE_AR in sections['gaps']
    assert diag['placeholder_gate_passed'] is True
    assert diag['passed'] is True
    assert _app_placeholder_gate_hits(sections) == []


def test_completion_removes_not_specified_from_gap_rows():
    sections = {
        'gaps': _gap_table(fw='Not specified', rec='N/A'),
        '_document_type': 'gap_assessment',
    }
    diag = apply_gap_placeholder_completion(
        sections, domain='global', document_type='gap_assessment',
        lang='en', emit=False)
    assert 'Not specified' not in sections['gaps']
    assert 'N/A' not in sections['gaps']
    assert FRAMEWORK_PROFILE_EN in sections['gaps']
    assert diag['placeholders_after'] == 0
    assert diag['blocking_errors'] == []
    assert _app_placeholder_gate_hits(sections) == []


def test_completion_preserves_valid_existing_gap_rows():
    valid = _gap_table()
    sections = {
        'gaps': valid,
        'scope': '## النطاق\n\nISO 27001 Annex A.\n',
        '_document_type': 'gap_assessment',
    }
    snapshot = sections['gaps']
    diag = apply_gap_placeholder_completion(
        sections, domain='global', document_type='gap_assessment',
        lang='ar', data={'frameworks': ['ISO/IEC 27001:2022']}, emit=False)
    assert sections['gaps'] == snapshot
    assert diag['placeholders_before'] == 0
    assert diag['placeholders_after'] == 0
    assert 'تطبيق جزئي موثق' in sections['gaps']


def test_completion_does_not_run_for_strategy():
    assert is_gap_placeholder_completion_applicable('strategy') is False
    sections = {'gaps': _gap_table(org='غير محدد'), 'vision': 'رؤية'}
    snapshot = dict(sections)
    diag = apply_gap_placeholder_completion(
        sections, domain='cyber', document_type='strategy',
        lang='ar', emit=False)
    assert sections == snapshot
    assert diag['completion_applied'] is False
    assert diag['passed'] is True


def test_completion_does_not_run_for_erm_risk():
    assert is_gap_placeholder_completion_applicable('risk') is False
    sections = {
        'register': '| المخاطرة | غير محدد |\n',
        'treatments': 'خطط',
    }
    snapshot = dict(sections)
    diag = apply_gap_placeholder_completion(
        sections, domain='Enterprise Risk Management',
        document_type='risk', lang='ar', emit=False)
    assert sections == snapshot
    assert diag['completion_applied'] is False


def test_placeholder_gate_still_fails_if_tokens_remain():
    sections = {'gaps': _gap_table(current='غير محدد')}
    diag = apply_gap_placeholder_completion(
        sections, domain='global', document_type='gap_assessment',
        lang='ar', emit=False, skip_replace=True)
    assert diag['placeholders_after'] > 0
    assert diag['passed'] is False
    assert 'rel33_gap_placeholder_completion_failed' in diag['blocking_errors']
    assert diag['placeholder_gate_passed'] is False
    assert _app_placeholder_gate_hits(sections) == ['gaps']


def test_completed_global_gap_save_allowed():
    sections = {
        'gaps': (
            '## الفجوات\n\n'
            '| # | الإطار | الحالة الحالية | الحالة المستهدفة | التوصية |\n'
            '|---|---|---|---|---|\n'
            '| 1 | Not specified | غير محدد | TBD | N/A |\n'
        ),
        'environment': 'Regulatory Context: Not specified\n',
        '_document_type': 'gap_assessment',
    }
    assert _app_placeholder_gate_hits(sections)
    result = run_gap_placeholder_completion(
        sections, domain='global', document_type='gap_assessment',
        lang='ar', route='global:gap_assessment:ar', emit=False)
    assert result['fail_closed'] is False
    assert result['placeholder_gate_passed'] is True
    assert result['diag']['passed'] is True
    assert sections['_document_type'] == 'gap_assessment'
    assert _app_placeholder_gate_hits(sections) == []
    assert count_forbidden_placeholders(sections['gaps']) == 0


def test_global_gap_export_remains_allowed():
    from release_engine_v3.rel33_document_gates import (
        build_gate_routing_diag,
        gap_assessment_gates_enabled,
        strategy_gates_enabled,
    )
    from release_engine_v3.rel33_quality_matrix import REL33_TYPE_FIXTURES_AR

    sections = dict(REL33_TYPE_FIXTURES_AR['gap_assessment'])
    sections['gaps'] = (
        sections['gaps'].rstrip() + '\n| 2 | غير محدد | عالية |\n')
    apply_gap_placeholder_completion(
        sections, domain='global', document_type='gap_assessment',
        lang='ar', emit=False)
    assert sections.get('_document_type') == 'gap_assessment'
    assert strategy_gates_enabled('gap_assessment') is False
    assert gap_assessment_gates_enabled('gap_assessment') is True
    routing = build_gate_routing_diag(
        domain='global',
        document_type='gap_assessment',
        route='docx',
        document_type_source='parameter',
    )
    assert routing['document_type'] == 'gap_assessment'
    assert routing['gap_assessment_gates_enabled'] is True
    assert _app_placeholder_gate_hits(sections) == []


def test_document_type_remains_gap_assessment():
    sections = {'gaps': _gap_table(fw='غير محدد')}
    apply_gap_placeholder_completion(
        sections, domain='Global Standards',
        document_type='gap_assessment', lang='ar', emit=False)
    assert sections['_document_type'] == 'gap_assessment'


def test_diagnostic_fields_and_example():
    data = {'org_name': '', 'frameworks': []}
    sections = {'gaps': _gap_table(org='غير محدد', fw='Not specified')}
    diag = apply_gap_placeholder_completion(
        sections, domain='global', document_type='gap_assessment',
        lang='ar', data=data, route='global:gap_assessment:ar', emit=False)
    for field in (
            'route', 'domain', 'document_type', 'artifact_type', 'language',
            'organization_profile_before', 'organization_profile_after',
            'framework_profile_before', 'framework_profile_after',
            'placeholders_before', 'placeholders_after', 'rows_scanned',
            'rows_completed', 'fields_completed', 'completion_applied',
            'placeholder_gate_passed', 'blocking_errors', 'passed'):
        assert field in diag
    assert diag['document_type'] == 'gap_assessment'
    assert diag['placeholders_before'] > 0
    assert diag['placeholders_after'] == 0
    assert diag['completion_applied'] is True
    assert diag['placeholder_gate_passed'] is True
    assert diag['blocking_errors'] == []
    assert diag['passed'] is True
    assert data['org_name'] == ORG_PROFILE_AR
    assert FRAMEWORK_PROFILE_AR in data['frameworks']


def test_does_not_claim_ksa_when_not_selected():
    data = {'frameworks': []}
    resolve_gap_assessment_context(
        data, lang='ar', domain='global', document_type='gap_assessment')
    blob = ' '.join(data['frameworks']).lower()
    for marker in ('nca', 'ndmo', 'sama', 'ecc', 'dcc'):
        assert marker not in blob


def test_preserves_selected_ksa_framework_when_present():
    data = {'frameworks': ['NCA ECC (Essential Cybersecurity Controls)']}
    resolve_gap_assessment_context(
        data, lang='ar', domain='cyber', document_type='gap_assessment')
    assert data['frameworks'] == [
        'NCA ECC (Essential Cybersecurity Controls)']
