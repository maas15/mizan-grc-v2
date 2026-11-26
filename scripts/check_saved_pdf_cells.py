"""Independent physical-cell and Arabic mark checks for the reviewed numeric 702 fixture.

Use the embedded PDF glyph outlines and the painted pen positions. This module
does not call the writer's shaping, bidi or field-matching code.
"""
from __future__ import annotations

from collections import defaultdict
from io import BytesIO
import re
import unicodedata

from fontTools.ttLib import TTFont
import pymupdf

from release_engine_v3.canonical_document import parse_saved_markdown_structure


_ROLES = {'1d2b4f': 'heading', '214e63': 'header', 'dceaef': 'subheading',
          'f0f5f7': 'row', 'f9fbfc': 'row', 'ffffff': 'prose'}
# Latin technical fields are read left to right inside an Arabic line.
_TOKEN = r'\(API v2\.1\)|\[DT-POS-01\]|[A-Za-z0-9]+(?:[-./_][A-Za-z0-9]+)*(?:%)?'
_LATIN = re.compile(f'(?:{_TOKEN})(?:[.]? (?:{_TOKEN}))*')
_MIRROR = str.maketrans('()[]', ')(][')


def logical_line(visual):
    # The isolated numeric suffix of the catalogue formula is printed LTR.
    if re.fullmatch(r'\d+\) × \d+', visual):
        return visual
    units = []
    i = 0
    while i < len(visual):
        latin = _LATIN.match(visual, i)
        if latin:
            units.append(latin[0])
            i = latin.end()
        else:
            j = i + 1
            while j < len(visual) and unicodedata.combining(visual[j]):
                j += 1
            units.append(visual[i:j].translate(_MIRROR))
            i = j
    return ''.join(reversed(units))


def _font_outlines(doc, page, cache):
    fonts = {}
    for ref, _, kind, name, *_ in page.get_fonts():
        if kind != 'TrueType':
            continue
        if ref not in cache:
            cache[ref] = TTFont(BytesIO(doc.extract_font(ref)[3]))
        fonts.setdefault(name.split('+')[-1], []).append(cache[ref])
    return fonts


def _painted_cells(doc, page, font_cache):
    # The filled rectangles define the actual columns, independent of text order.
    bands = defaultdict(list)
    for drawing in page.get_drawings():
        if drawing['type'] != 'f' or not drawing['fill']:
            continue
        color = ''.join(f'{round(v * 255):02x}' for v in drawing['fill'])
        if color in _ROLES:
            rect = drawing['rect']
            bands[(round(rect.y0, 2), round(rect.y1, 2), _ROLES[color])].append(rect)
    fonts = _font_outlines(doc, page, font_cache)
    cells = [(key, rect, defaultdict(list)) for key, boxes in sorted(bands.items())
             for rect in sorted(boxes, key=lambda r: -r.x0)]
    for span in page.get_texttrace():
        for code, gid, (x, y), bbox in span['chars']:
            if y > page.rect.height - 28:
                continue
            targets = [lines for _, r, lines in cells if r.x0-.2 <= x <= r.x1+.2 and r.y0 < y <= r.y1]
            if len(targets) != 1:
                raise ValueError('Unassigned or overlapping printed glyph')
            targets[0][round(y, 2)].append((chr(code), gid, x, bbox, span['size'], span['font']))
    rows = defaultdict(list)
    for key, rect, lines in cells:
        decoded, marks, visuals = [], [], []
        for y, glyphs in sorted(lines.items()):
            bases = sorted((g for g in glyphs if not unicodedata.combining(g[0])), key=lambda g: g[2])
            attachments = defaultdict(list)
            for char, gid, x, _, size, font_name in glyphs:
                if not unicodedata.combining(char):
                    continue
                # get_texttrace gives a zero-advance origin, not the visible ink.
                # Obtain its actual outline from the embedded TrueType subset.
                bounds = set()
                for font in fonts[font_name]:
                    if gid < len(font.getGlyphOrder()):
                        glyph = font['glyf'][font.getGlyphOrder()[gid]]
                        if hasattr(glyph, 'xMin'):
                            em = font['head'].unitsPerEm
                            bounds.add(tuple(a / em for a in (glyph.xMin, glyph.xMax, glyph.yMin, glyph.yMax)))
                if len(bounds) != 1:
                    raise ValueError('Ambiguous embedded mark outline')
                left, right, low, high = bounds.pop()
                center = x + size * (left + right) / 2
                # Compare the INK centre with all physical advance intervals,
                # including spaces, not with the logical neighbour in the stream.
                hits = [i for i,g in enumerate(bases) if g[3][0] <= center < g[3][2]]
                index = hits[0] if len(hits) == 1 else None
                base = unicodedata.normalize('NFKC', bases[index][0]) if index is not None else None
                marks.append(dict(mark=char, base=base, page=page.number+1,
                                  ink_center_x=center, baseline=y, cell=list(rect),
                                  ink_box=[x+size*left,y-size*high,x+size*right,y-size*low],
                                  base_box=list(bases[index][3]) if index is not None else None))
                if index is not None:
                    attachments[index].append(char)
            visual = ''.join((unicodedata.normalize('NFKC',g[0]) if 0xfb50 <= ord(g[0]) <= 0xfeff else g[0])
                             + ''.join(attachments[i]) for i,g in enumerate(bases))
            visuals.append(visual)
            decoded.append(logical_line(visual))
        rows[key].append(dict(value=' '.join(decoded), marks=marks, painted_lines=visuals))
    return [(key[2], fields) for key,fields in sorted(rows.items())]


def inspect_saved_pdf(data, expected):
    blocks, error = parse_saved_markdown_structure(expected['full_body'])
    if error:
        raise ValueError(error)
    source = []
    section = 0
    tables = iter(expected['tables'].items())
    for block in blocks:
        if block['kind'] == 'table':
            name, table = next(tables)
            source.append(('header', name, section, table['header']))
            source.extend(('row', name, section, fields) for fields in table['rows'])
        else:
            role = ('heading' if block['level'] <= 2 else 'subheading') if block['kind'] == 'heading' else 'prose'
            section += role == 'heading'
            source.append((role, '', section, [block['text']]))
    if next(tables, None) is not None:
        raise ValueError('Unconsumed source table')
    pos, repeated = 0, 0
    last_header = None
    checked, differences = [], []
    with pymupdf.open(stream=data, filetype='pdf') as doc:
        font_cache = {}
        for page in list(doc)[1:]:  # Cover/control is checked separately by the production verifier.
            for ordinal,(role, cells) in enumerate(_painted_cells(doc, page, font_cache)):
                record = source[pos] if pos < len(source) else None
                if record and ordinal == 0 and role == 'header' and record[0] == 'row':
                    record = last_header
                    repeated += 1
                else:
                    pos += 1
                if not record or role != record[0] or len(cells) != len(record[3]):
                    raise ValueError(f'Unexpected printed row on page {page.number+1}, source position {pos}')
                if role == 'header':
                    last_header = record
                for col,(field, drawn) in enumerate(zip(record[3], cells, strict=True)):
                    item = dict(page=page.number+1, section=record[2], table=record[1], role=role,
                                block=pos, column=col+1, expected=field, **drawn)
                    checked.append(item)
                    if (drawn['value'] != ' '.join(field.split())
                            or any(not m['base'] or m['base'].isspace() for m in drawn['marks'])):
                        differences.append(item)
    if pos != len(source):
        raise ValueError('Incomplete source reconciliation')
    return dict(source_records=pos, repeated_headers=repeated, fields=checked, differences=differences)
