"""PR-REL2.3 — Arabic final language gate (scoped section repair)."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

REL2_ARABIC_SPECIFIC_FIXES: Tuple[Tuple[str, str], ...] = (
    ('للتعاملمع', 'للتعامل مع'),
    ('الاجتماعيةضد', 'الاجتماعية ضد'),
    ('الاستعادةفي', 'الاستعادة في'),
    ('الحاليةفي', 'الحالية في'),
    ('الموظفينفي', 'الموظفين في'),
    ('رئيسيةفي', 'رئيسية في'),
    ('ال معلومات', 'المعلومات'),
    ('ال معمول', 'المعمول'),
    ('ال منظمة', 'المنظمة'),
    ('ال معتمدة', 'المعتمدة'),
    ('ال معتمد', 'المعتمد'),
    ('لل معالجة', 'للمعالجة'),
    ('ل معالجة', 'لمعالجة'),
    # REL2.7.1 — glued solutions+prevent token before partial split rules.
    ('حلولمنع', 'حلول لمنع'),
    ('حلمنع', 'حلول لمنع'),
    ('المحددةفي', 'المحددة في'),
    ('ال معالجة', 'المعالجة'),
    ('بال منصات', 'بالمنصات'),
    # Before generic ل منع — undo false split from حلولمن inside حlولمنع.
    ('حلول منع', 'حلول لمنع'),
    ('المسؤول أمن السيبرانيe', 'مسؤول أمن السيبراني'),
    ('المسؤول أمن السيبرانيLead', 'مسؤول أمن السيبراني'),
    ('النقرفي', 'النقر في'),
    ('الناجمةعن', 'الناجمة عن'),
    ('ال مناسبة', 'المناسبة'),
    ('ال مناسب', 'المناسب'),
    ('ال معنية', 'المعنية'),
    ('ال منظمات', 'المنظمات'),
    ('ال عنصر', 'العنصر'),
    ('وال منقولة', 'والمنقولة'),
    ('ال منقولة', 'المنقولة'),
    ('segmentation-Micro', 'تقسيم Micro'),
    ('CSISO', 'CISO'),
    ('Lead e', ''),
    ('ل منع', 'لمنع'),
    ('ال معيارية', 'المعيارية'),
    ('ال منفذة', 'المنفذة'),
    ('معدلمعالجة', 'معدل معالجة'),
    ('ل منصب', 'لمنصب'),
    ('ال منتظم', 'المنتظم'),
    ('ال منظّمة', 'المنظّمة'),
    ('أعمالمع', 'أعمال مع'),
    ('حلولمن', 'حلول من'),
    ('برامجمن', 'برامج من'),
    ('خدماتمن', 'خدمات من'),
)

# Do not split حلولمن/برامجمن/خدماتمن when followed by ع (e.g. حلولمنع).
_LM_WORD_GLUE_FIX_BADS = frozenset(('حلولمن', 'برامجمن', 'خدماتمن'))
_LM_WORD_GLUE_GUARDED = tuple(
    (re.compile(re.escape(bad) + r'(?!ع)'), good)
    for bad, good in REL2_ARABIC_SPECIFIC_FIXES
    if bad in _LM_WORD_GLUE_FIX_BADS)
# Split definite-article fixes only at token boundaries — avoids false hits
# inside words like أعمال معتمدة (…+ا+ل + space + معتمدة).
_CATALOG_BOUNDARY_BADS = frozenset(
    bad for bad, _ in REL2_ARABIC_SPECIFIC_FIXES
    if bad.startswith(('ال ', 'لل ')))
_CATALOG_BOUNDARY_RES: Dict[str, re.Pattern[str]] = {
    bad: re.compile(r'(?<![\u0600-\u06FF])' + re.escape(bad))
    for bad in _CATALOG_BOUNDARY_BADS
}


_GLUE_PREPOSITIONS = ('مع', 'ضد', 'في', 'على', 'عن', 'من', 'إلى', 'لدى')
# من(?!ع) keeps valid لمنع (to prevent); other prepositions split glued tokens.
_GLUE_PREPOSITION_ALT = tuple(
    r'من(?!ع)(?![\u0600-\u06FF])' if p == 'من' else re.escape(p)
    for p in _GLUE_PREPOSITIONS)
# Only split when the letter before the preposition is a typical word ending
# (e.g. للتعاملمع, الاجتماعيةضد) — avoids breaking الزمني, التشفير, etc.
_GLUE_RE = re.compile(
    r'([\u0600-\u06FF]*[لتةاءى])('
    + '|'.join(_GLUE_PREPOSITION_ALT)
    + r')(?=[\u0600-\u06FF])')
# Live AI glue: حلولمن التهديدات (من before whitespace, not another letter).
_LM_SPACE_GLUE_RE = re.compile(
    r'([\u0600-\u06FF]{2,}ل)من(?=\s|$|[،,.؛:\)\|])')
# Split ل + منع residue (ASCII/Unicode whitespace between ل and منع).
_L_MIN_SPLIT_RE = re.compile(r'ل[\s\u00a0\u200b\u200c\u200d\u202f]+منع')
_L_LAM_MUALAJA_RE = re.compile(
    r'(?<![\u0600-\u06FF])(?<!معد)'
    r'ل[\s\u200f\u200e\u200b\u200c\u200d\u00a0\u202f]+معالجة')
# Invisible directional / zero-width chars that break substring glue detection.
_AR_INVISIBLE_RE = re.compile(r'[\u200f\u200e\u200b\u200c\u200d]')
_AR_INVISIBLE_WS = r'[\s\u200f\u200e\u200b\u200c\u200d\u00a0\u202f]+'
REL3_ARABIC_LAM_TOKENS: Tuple[str, ...] = (
    'معلومات', 'منظمة', 'بيانات', 'سيبراني', 'أمن', 'حوكمة', 'حماية',
    'تصنيف', 'معالجة', 'استجابة', 'ثغرات', 'حوادث', 'ضوابط', 'مخاطر',
    'وصول', 'هوية', 'تشفير', 'نسخ', 'مراقبة', 'امتثال', 'منتظم', 'معنية',
    'منظّمة', 'معمول', 'معتمدة', 'معتمد', 'معيارية', 'مناسبة', 'مناسب',
    'منفذة', 'منظمات', 'عنصر', 'منقولة',
)
_REL3_LAM_TOKEN_ALT = '|'.join(re.escape(t) for t in REL3_ARABIC_LAM_TOKENS)
_LAM_INVISIBLE_GLUE_RE = re.compile(
    r'(?<![\u0600-\u06FF])ال' + _AR_INVISIBLE_WS + r'(' + _REL3_LAM_TOKEN_ALT + r')',
    re.UNICODE)
_WAW_LAM_GLUE_RE = re.compile(
    r'(?<=و)ال' + _AR_INVISIBLE_WS
    + r'(منقولة|معالجة|منظمة|معلومات|معنية|بيانات|حماية|مراقبة)',
    re.UNICODE)
REL3_ARABIC_CANONICAL_LITERAL_FIXES: Tuple[Tuple[str, str], ...] = (
    ('معدلمعالجة', 'معدل معالجة'),
    ('ل منصب', 'لمنصب'),
    ('ال منتظم', 'المنتظم'),
    ('ال منظّمة', 'المنظّمة'),
)
_MURAQABA_MUST_RE = re.compile(r'المراقبة المست(?!مر)')


def _apply_glue_split(text: str) -> str:
    """Split glued prepositions but keep valid tokens like لمنع (to prevent)."""

    def _repl(m: re.Match[str]) -> str:
        g1, g2 = m.group(1), m.group(2)
        if g2 == 'من' and m.end() < len(text) and text[m.end()] == 'ع':
            if g1 == 'ل' or (g1.endswith('ل') and len(g1) <= 2):
                return m.group(0)
        return f'{g1} {g2}'

    return _GLUE_RE.sub(_repl, text)


def _normalize_lam_mualeda(text: str) -> str:
    return _L_LAM_MUALAJA_RE.sub('لمعالجة', text or '')


def _normalize_lam_mana(text: str) -> str:
    return _L_MIN_SPLIT_RE.sub('لمنع', text or '')


def _normalize_arabic_invisible_whitespace(text: str) -> str:
    """Strip invisible Unicode marks that break lam-glue substring checks."""
    if not text:
        return text or ''
    return _AR_INVISIBLE_RE.sub('', text)


def _normalize_arabic_lam_glue(text: str) -> str:
    """Repair definite-article splits including invisible-char variants."""
    if not text:
        return text or ''
    out = _normalize_arabic_invisible_whitespace(text)
    out = _WAW_LAM_GLUE_RE.sub(lambda m: 'وال' + m.group(1), out)
    out = _LAM_INVISIBLE_GLUE_RE.sub(lambda m: 'ال' + m.group(1), out)
    return out


def _apply_catalog_fixes(text: str) -> str:
    out = text or ''
    for bad, good in REL2_ARABIC_SPECIFIC_FIXES:
        if bad in _LM_WORD_GLUE_FIX_BADS:
            continue
        if bad in _CATALOG_BOUNDARY_BADS:
            out = _CATALOG_BOUNDARY_RES[bad].sub(good, out)
        else:
            out = out.replace(bad, good)
    for pat, good in _LM_WORD_GLUE_GUARDED:
        out = pat.sub(good, out)
    return out


def _catalog_residue_present(blob: str, bad: str) -> bool:
    if bad in _LM_WORD_GLUE_FIX_BADS:
        return bool(re.search(re.escape(bad) + r'(?!ع)', blob))
    if bad in _CATALOG_BOUNDARY_BADS:
        return bool(_CATALOG_BOUNDARY_RES[bad].search(blob))
    return bad in blob


def _find_residues(text: str) -> List[str]:
    residues: List[str] = []
    blob = text or ''
    for bad, _ in REL2_ARABIC_SPECIFIC_FIXES:
        if _catalog_residue_present(blob, bad):
            residues.append(bad)
    if _L_MIN_SPLIT_RE.search(blob):
        residues.append('ل منع')
    for m in _GLUE_RE.finditer(blob):
        token = m.group(0)
        if token not in residues and len(token) > 4:
            residues.append(token)
    for m in _LM_SPACE_GLUE_RE.finditer(blob):
        token = m.group(0)
        if token not in residues:
            residues.append(token)
    if _L_LAM_MUALAJA_RE.search(blob):
        residues.append('ل معالجة')
    return residues


def _repair_text(text: str) -> str:
    if not text:
        return text or ''
    out = _normalize_arabic_lam_glue(text)
    for _ in range(5):
        prev = out
        out = _normalize_lam_mana(out)
        out = _normalize_lam_mualeda(out)
        out = _normalize_arabic_lam_glue(out)
        out = _apply_catalog_fixes(out)
        out = _apply_glue_split(out)
        out = _LM_SPACE_GLUE_RE.sub(r'\1 من', out)
        out = out.replace('حلول ل منع', 'حلول لمنع')
        out = _normalize_lam_mana(out)
        out = _normalize_lam_mualeda(out)
        out = _apply_catalog_fixes(out)
        if out == prev:
            break
    return out


def apply_arabic_final_gate(
        sections: Dict[str, str],
        *,
        lang: str = 'ar',
) -> Tuple[Dict[str, str], Dict[str, object]]:
    """Repair glued Arabic tokens in legacy sections only."""
    if str(lang or '').lower() == 'en':
        return sections, {
            'arabic_quality_passed': True,
            'residues_after': [],
            'action_taken': 'skipped_en',
        }
    residues_before: List[str] = []
    out = dict(sections)
    for key, val in sections.items():
        if str(key).startswith('_') or not isinstance(val, str):
            continue
        residues_before.extend(_find_residues(val))
        out[key] = _repair_text(val)
    residues_after: List[str] = []
    for val in out.values():
        if isinstance(val, str):
            residues_after.extend(_find_residues(val))
    residues_after = list(dict.fromkeys(residues_after))
    passed = not residues_after
    blocking = ''
    if not passed:
        blocking = f'rel2_arabic_quality_failed:{residues_after[0]}'
    return out, {
        'arabic_quality_passed': passed,
        'residues_before': list(dict.fromkeys(residues_before)),
        'residues_after': residues_after,
        'action_taken': (
            'arabic_repaired' if residues_before else 'validated'),
        'blocking_error_if_any': blocking,
    }


def emit_arabic_final_language_gate(payload: Dict[str, object]) -> None:
    try:
        print(
            '[REL2-ARABIC-FINAL-LANGUAGE-GATE] '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def apply_arabic_substance_gate(
        sections: Dict[str, str],
        *,
        lang: str = 'ar',
) -> Tuple[Dict[str, str], Dict[str, object]]:
    """Extended Arabic substance gate — emits substance model tag."""
    out, diag = apply_arabic_final_gate(sections, lang=lang)
    substance_diag = {
        'residues_before': diag.get('residues_before', []),
        'residues_after': diag.get('residues_after', []),
        'arabic_quality_passed': diag.get('arabic_quality_passed', True),
        'action_taken': diag.get('action_taken', 'validated'),
        'blocking_error_if_any': diag.get('blocking_error_if_any', ''),
    }
    emit_arabic_substance_language_model(substance_diag)
    return out, substance_diag


def emit_arabic_substance_language_model(payload: Dict[str, object]) -> None:
    try:
        print(
            '[REL2-ARABIC-SUBSTANCE-LANGUAGE-MODEL] '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def _apply_rel3_conditional_repairs(text: str) -> str:
    out = text or ''
    if 'المراقبة المستمرة' not in out:
        out = _MURAQABA_MUST_RE.sub('المراقبة المستمرة', out)
    for bad, good in REL3_ARABIC_CANONICAL_LITERAL_FIXES:
        if bad in _CATALOG_BOUNDARY_BADS:
            out = _CATALOG_BOUNDARY_RES[bad].sub(good, out)
        elif bad.startswith(('ال ', 'ل ')):
            pat = re.compile(r'(?<![\u0600-\u06FF])' + re.escape(bad))
            out = pat.sub(good, out)
        else:
            out = out.replace(bad, good)
    return out


def repair_rel3_arabic_canonical_text(text: str) -> str:
    """REL3 canonical Arabic repair — controlled lam-glue + catalog fixes."""
    if not text:
        return text or ''
    out = _repair_text(text)
    for _ in range(3):
        prev = out
        out = _apply_rel3_conditional_repairs(out)
        out = _normalize_arabic_lam_glue(out)
        out = _apply_catalog_fixes(out)
        if out == prev:
            break
    return out


def _sections_blob(sections: Dict[str, str]) -> str:
    parts: List[str] = []
    for key, val in (sections or {}).items():
        if str(key).startswith('_') or not isinstance(val, str):
            continue
        parts.append(val)
    return '\n'.join(parts)


def _collect_rel3_arabic_canonical_residues(blob: str) -> List[str]:
    """Residue list aligned with REL3 DQS arabic_canonical_invalid detection."""
    try:
        from release_engine_v3.document_quality_spec import (
            check_arabic_tokenization_quality,
        )
        tok = check_arabic_tokenization_quality(blob or '')
        return list(tok.get('blocking_defects') or [])
    except Exception:  # noqa: BLE001
        return _find_residues(blob or '')


def repair_arabic_canonical_text_before_freeze(
        sections: Dict[str, str],
        *,
        lang: str = 'ar',
        backend: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    """Final REL3 Arabic canonical repair before FinalDocumentArtifact freeze."""
    _ = backend
    if str(lang or '').lower() == 'en':
        diag: Dict[str, Any] = {
            'residues_before': [],
            'repairs_applied': [],
            'residues_after': [],
            'arabic_canonical_repair_passed': True,
            'sections_repaired': [],
            'blocking_errors': [],
            'action_taken': 'skipped_en',
        }
        emit_rel3_arabic_canonical_repair(diag)
        return sections, diag

    blob_before = _sections_blob(sections)
    residues_before = _collect_rel3_arabic_canonical_residues(blob_before)
    out = dict(sections or {})
    sections_repaired: List[str] = []
    for key, val in (sections or {}).items():
        if str(key).startswith('_') or not isinstance(val, str):
            continue
        repaired = repair_rel3_arabic_canonical_text(val)
        if repaired != val:
            sections_repaired.append(str(key))
        out[key] = repaired

    blob_after = _sections_blob(out)
    residues_after = _collect_rel3_arabic_canonical_residues(blob_after)
    repairs_applied = [
        r for r in residues_before if r not in residues_after]
    blocking_errors: List[str] = []
    if residues_after:
        blocking_errors = [
            f'arabic_canonical_residue:{r}' for r in residues_after]
    passed = not residues_after
    diag = {
        'residues_before': list(dict.fromkeys(residues_before)),
        'repairs_applied': list(dict.fromkeys(repairs_applied)),
        'residues_after': list(dict.fromkeys(residues_after)),
        'arabic_canonical_repair_passed': passed,
        'sections_repaired': list(dict.fromkeys(sections_repaired)),
        'blocking_errors': blocking_errors,
        'action_taken': (
            'arabic_canonical_repaired' if sections_repaired else (
                'validated' if passed else 'blocked')),
    }
    emit_rel3_arabic_canonical_repair(diag)
    return out, diag


def emit_rel3_arabic_canonical_repair(payload: Dict[str, Any]) -> None:
    try:
        print(
            '[REL3-ARABIC-CANONICAL-REPAIR] '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass
