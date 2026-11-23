"""Lay out the validated saved strategy, retaining its source table schemas."""
from __future__ import annotations

import io
import math
import re
from datetime import datetime
from itertools import groupby
from pathlib import Path
from xml.sax.saxutils import escape
from zoneinfo import ZoneInfo

import arabic_reshaper
import reportlab
from bidi.algorithm import get_display
from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import LongTable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, TableStyle

from release_engine_v3.canonical_document import parse_saved_markdown_structure

# Keep directional punctuation inside the run it delimits. Resolve other punctuation
# in context, including the Arabic comma and the sentence-final full stop.
_ISLAND = r'\([A-Za-z][A-Za-z0-9 ./+_-]*\)|\[[A-Za-z0-9][A-Za-z0-9./_-]*\]|[A-Za-z0-9]+(?:[-./_][A-Za-z0-9]+)*(?:%)?'
_WORD = re.compile(r'\([A-Za-z][A-Za-z0-9 ./+_-]*\)\S*|\S+')
_SHAPER = arabic_reshaper.ArabicReshaper(configuration={
    'delete_harakat': False, 'shift_harakat_position': True, 'support_ligatures': False})
NAVY = '#1D2B4F'
HEADER = '#214E63'
INK = '#182936'
PAD = 5


def visual_line(logical):
    # A standalone Latin fragment keeps its own direction, including terminal
    # hyphens or brackets when an over-width identifier crosses a line.
    if re.fullmatch(r'(?:[A-Za-z0-9_.]+-)+', logical):
        return logical
    shaped = _SHAPER.reshape(logical)
    directed = re.sub(_ISLAND, lambda m: '\u202a' + m[0] + '\u202c', shaped)
    return get_display(directed, base_dir='R')


def font_runs(text, font):
    primary = pdfmetrics.getFont(font).face.charToGlyph
    fallback = pdfmetrics.getFont('MizanSymbols').face.charToGlyph

    def face(char):
        if primary.get(ord(char)):
            return font
        if fallback.get(ord(char)):
            return 'MizanSymbols'
        raise ValueError(f'saved_pdf_missing_glyph:U+{ord(char):04X}')

    return [(name, ''.join(chars)) for name, chars in groupby(text, key=face)]


def measure(logical, font, size):
    return sum(pdfmetrics.stringWidth(text, name, size)
               for name, text in font_runs(visual_line(logical), font))


def cell(text, width, style):
    font, size = style.fontName, style.fontSize
    lines = []
    for paragraph in text.strip().splitlines():
        line = ''
        for word in _WORD.findall(paragraph):
            candidate = (line + ' ' + word).strip()
            if line and measure(candidate, font, size) > width:
                lines.append(line)
                line = ''
            if measure(word, font, size) > width:
                # An exceptionally long unbroken field may require character wrapping.
                for char in word:
                    if line and measure(line + char, font, size) > width:
                        lines.append(line)
                        line = ''
                    line += char
            else:
                line = (line + ' ' + word).strip()
        lines.append(line)
    formatted = []
    for line in lines:
        runs = font_runs(visual_line(line), font)
        formatted.append('<nobr>' + ''.join(
            f'<font name="{name}">{escape(value)}</font>' for name, value in runs) + '</nobr>')
    return Paragraph('<br/>'.join(formatted), style)


def column_widths(rows, width, font, size):
    columns = list(zip(*rows, strict=True))
    minimum, weights = [], []
    for col in columns:
        words = [word for value in col for word in _WORD.findall(value)]
        minimum.append(2 * PAD + max([12] + [measure(word, font, size) for word in set(words)]))
        weights.append(math.sqrt(max(1, max(len(value) for value in col))))
    remaining = width - sum(minimum)
    if remaining < 0:
        # Honor the physical frame even for unusually wide user tables.
        return [width * value / sum(minimum) for value in minimum]
    return [low + remaining * wt / sum(weights) for low, wt in zip(minimum, weights)]


def render_saved_pdf(content, cover, font):
    blocks, error = parse_saved_markdown_structure(content)
    if error or not blocks:
        raise ValueError(error or 'saved_pdf_empty')
    pdfmetrics.registerFont(TTFont('MizanSymbols', str(Path(reportlab.__file__).parent / 'fonts/Vera.ttf')))
    page = landscape(A4)
    stream = io.BytesIO()
    doc = SimpleDocTemplate(stream, pagesize=page, leftMargin=30, rightMargin=30,
                            topMargin=30, bottomMargin=32, title=cover['document_title'])
    width = doc.width - 12  # SimpleDocTemplate frame has six points of inset on each side.

    def style(name, size, color):
        return ParagraphStyle(name, fontName=font, fontSize=size, leading=size*1.55,
                              textColor=colors.HexColor(color), alignment=TA_RIGHT,
                              splitLongWords=False, spaceBefore=0, spaceAfter=0)

    body = style('SavedBody', 11, INK)
    header = style('SavedTableHeader', 11, '#FFFFFF')
    heading = style('SavedSection', 16, '#FFFFFF')
    subheading = style('SavedSubsection', 13, NAVY)
    story = []

    def table(rows, widths, styles, fills, repeat=0):
        # Source column zero is at the right-hand edge in the displayed Arabic table.
        cells = []
        cmds = [('VALIGN', (0, 0), (-1, -1), 'TOP')]
        for side in ('LEFT', 'RIGHT', 'TOP', 'BOTTOM'):
            cmds.append((side+'PADDING', (0, 0), (-1,-1), PAD))
        for r, values in enumerate(rows):
            cell_style, fill = styles(r), fills(r)
            cells.append([cell(text, colwidth - 2*PAD - 0.1, cell_style)
                          for text, colwidth in zip(values, widths, strict=True)][::-1])
            for c in range(len(values)):
                cmds.append(('BACKGROUND', (c,r), (c,r), colors.HexColor(fill)))
        if repeat:
            cmds.append(('INNERGRID', (0,0), (-1,-1), 0.35, colors.HexColor('#C7D8DF')))
        flow = LongTable(cells, colWidths=widths[::-1], style=TableStyle(cmds),
                         repeatRows=repeat, splitByRow=1, splitInRow=0, hAlign='RIGHT')
        # Prefer a complete source row on the next page. Split within a row only
        # when even a fresh frame cannot contain it and its continuation header.
        flow.wrap(width, doc.height)
        heights = flow._rowHeights
        header_height = heights[0] if repeat else 0
        flow.splitInRow = int(any(h + header_height > doc.height - 12
                                  for h in heights[repeat:]))
        return flow

    def band(text, pen, color):
        return table([[text]], [width], lambda _: pen, lambda _: color)

    story.append(band(cover['org_name'], header, HEADER))
    story.append(band(cover['document_title'], heading, NAVY))
    date = datetime.now(ZoneInfo('Asia/Riyadh')).strftime('%d %B %Y')
    story.append(band(cover['domain_display'], body, '#EDF4F6'))
    story.append(Spacer(1, 8))
    controls = [['نوع الوثيقة', 'القطاع', 'الحالة', 'تاريخ الإعداد'],
                [cover['document_type_label'], cover['sector'], cover['artifact_status'], date]]
    story.append(table(controls, [width/4]*4, lambda r: body if r else header,
                       lambda r: '#F0F5F7' if r else HEADER))
    story.append(Spacer(1, 16))
    story.append(band('محتويات الوثيقة', heading, NAVY))
    headings = [b['text'] for b in blocks if b['kind'] == 'heading' and b['level'] == 2]
    for number, title in enumerate(headings, 1):
        story.append(band(f'{number}. {title}', body, '#EDF4F6'))
    story.append(PageBreak())
    for block in blocks:
        if block['kind'] == 'table':
            rows = [block['header'], *block['rows']]
            widths = column_widths(rows, width, font, body.fontSize)
            item = table(rows, widths, lambda r: body if r else header,
                         lambda r: HEADER if not r else ('#F0F5F7' if r%2 else '#F9FBFC'), 1)
        elif block['kind'] == 'heading':
            major = block['level'] <= 2
            item = band(block['text'], heading if major else subheading,
                        NAVY if major else '#DCEAEF')
            item.keepWithNext = True
        else:
            item = band(block['text'], body, '#FFFFFF')
        story.append(item)
        if block['kind'] != 'heading':
            story.append(Spacer(1, 5))
    if isinstance(story[-1], Spacer):
        story.pop()

    def footer(canvas, document):
        canvas.saveState()
        canvas.setFillColor(colors.HexColor(NAVY))
        canvas.setFont(font, 10)
        canvas.drawCentredString(page[0]/2, 16, str(document.page))
        canvas.restoreState()
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return stream.getvalue()
