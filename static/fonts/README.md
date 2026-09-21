# Supported Arabic PDF fonts

TTF files in this directory are acquired at install/CI time. They are not
committed.

`scripts/ensure_render_fonts.py` downloads Amiri Regular (SIL Open Font
License 1.1) from a pinned google/fonts commit and verifies
`AMIRI_SHA256` before the file may be used.

Registration order in `app._ensure_arabic_pdf_font` is unchanged:

1. Noto Sans Arabic / Noto Naskh Arabic (preferred OS package)
2. `Amiri-Regular.ttf` from this directory (this script)
3. DejaVu Sans (last-resort fallback; still registered if selected)
4. Liberation / glob Arabic faces

DejaVu is not dropped. It is also not an evidence exemption. If DejaVu is
the face behind `ArabicFont`, Arabic shaping may paint extra or corrupted
glyphs while ActualText stays logical; the returned-bytes gate still
refuses that disagreement.

An untracked local Amiri is not a clean-checkout prerequisite until the
ensure script has verified the checksum.
