# Supported Arabic PDF fonts

TTF files in this directory are acquired at install/CI time. They are not
committed.

`scripts/ensure_render_fonts.py` downloads:

1. Noto Sans Arabic Regular (preferred bundled face, SIL OFL 1.1)
2. Amiri Regular (bundled fallback, SIL OFL 1.1)

Each file is fetched from a pinned commit and verified against
`FONTS[].sha256` before it may be used.

Registration order in `app._ensure_arabic_pdf_font` is:

1. OS Noto Sans Arabic / Noto Naskh Arabic
2. `NotoSansArabic-Regular.ttf` from this directory
3. `Amiri-Regular.ttf` from this directory
4. DejaVu Sans (last-resort fallback; still registered if selected)
5. Liberation / glob Arabic faces

Amiri and DejaVu are not dropped. They are also not evidence exemptions.
If either face is selected as `ArabicFont`, Arabic shaping may paint extra
or corrupted glyphs while ActualText stays logical; the returned-bytes
gate still refuses that disagreement.

An untracked local font is not a clean-checkout prerequisite until the
ensure script has verified the checksum.
