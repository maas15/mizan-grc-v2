"""Extract visible text from preview HTML."""

from release_engine.export_evidence_validator import extract_text_from_preview_html


def extract_preview_text(preview_html: str = '', preview_text: str = '') -> str:
    if preview_text:
        return preview_text
    return extract_text_from_preview_html(preview_html or '')
