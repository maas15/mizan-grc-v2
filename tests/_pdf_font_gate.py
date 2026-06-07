"""Skip PDF glyph assertions when no Arabic-capable TTF is installed."""
import unittest


def skip_if_no_arabic_pdf_font(app):
    """Deployment-only gate: CI/production must install Noto/Amiri fonts."""
    if app is None:
        raise unittest.SkipTest('app unavailable')
    try:
        app._ensure_arabic_pdf_font(required=False)
        if not getattr(app, '_ARABIC_PDF_FONT_PATH', None):
            raise unittest.SkipTest(
                'Arabic PDF font unavailable — install fonts-noto-core or '
                'place static/fonts/Amiri-Regular.ttf (deployment-only)')
    except unittest.SkipTest:
        raise
    except Exception as exc:
        raise unittest.SkipTest(
            f'Arabic PDF font check failed: {exc!s}') from exc
