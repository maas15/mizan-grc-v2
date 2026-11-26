"""Compare painted PDF text to each ordered source field using the PDF's physical cell bounds."""
from __future__ import annotations

from collections import defaultdict
import hashlib
from collections import Counter
import re
import unicodedata

import pymupdf
from release_engine_v3.canonical_document import parse_saved_markdown_structure
from release_engine_v3.exporters.saved_strategy_pdf import visual_line

# The color identifies the role; association is determined by actual page geometry.
ROLES = {'1d2b4f':'heading', '214e63':'header', 'dceaef':'subheading',
         'f0f5f7':'row', 'f9fbfc':'row', 'ffffff':'prose', 'edf4f6':'metadata'}


def _normalized(value):
    # Only compatibility forms produced by Arabic shaping; preserve IDs, punctuation and digits.
    return ''.join(unicodedata.normalize('NFKC', c) if 0xfb50 <= ord(c) <= 0xfeff else c
                   for c in value).strip()


def _color(rgb):
    return ''.join(f'{round(v*255):02x}' for v in rgb)


def painted_rows(page):
    bands = defaultdict(list)
    for drawing in page.get_drawings():
        if drawing['type'] != 'f' or not drawing['fill']:
            continue
        role = ROLES.get(_color(drawing['fill']))
        if role:
            rect = drawing['rect']
            bands[(round(rect.y0, 2), round(rect.y1, 2), role)].append(rect)
    cells = [(key, rect, defaultdict(list)) for key, boxes in sorted(bands.items())
             for rect in sorted(boxes, key=lambda box: -box.x0)]
    footer = []
    for span in page.get_texttrace():
        for code, gid, origin, bounds in span['chars']:
            x, y = origin
            if y > page.rect.height-28:
                footer.append(chr(code))
                continue
            matches = [(key, rect, glyphs) for key, rect, glyphs in cells
                       if rect.x0-0.2 <= x <= rect.x1+0.2 and rect.y0 < y <= rect.y1]
            if len(matches) != 1:
                raise ValueError(f'page {page.number+1}: unassigned/overlapping glyph at {origin}')
            key, rect, glyphs = matches[0]
            if gid == 0 or code in (0, 0xfffd) or bounds[2] > rect.x1+0.8:
                raise ValueError(f'page {page.number+1}: missing or clipped glyph at {origin}')
            if key[2] in ('header','heading') and _color(span['color']) != 'ffffff':
                raise ValueError('Unreadable header foreground')
            glyphs[round(y, 2)].append(chr(code))
    if ''.join(footer) != str(page.number+1):
        raise ValueError(f'Incorrect footer on page {page.number+1}')
    rows = defaultdict(list)
    for key, _, glyphs in cells:
        rows[key].append([''.join(chars) for _, chars in sorted(glyphs.items())])
    if not rows:
        raise ValueError(f'Empty body on page {page.number+1}')
    return [(k[2], values) for k, values in sorted(rows.items())]


def match_field(source, lines):
    # Match each painted line to a consecutive prefix of the field. Line breaks
    # may change, but a token cannot move to a different line, row or column.
    remaining = ' '.join(source.split())
    for actual in map(_normalized, lines):
        if not actual:
            continue
        # Ordinary lines end between words. A token wider than a whole column
        # may end mid-word; compare its exact logical prefix without discarding
        # any character. Bidi and shaping apply independently to each line.
        ends = [m.end() for m in re.finditer(r'\S+', remaining)]
        for stop in ends:
            if _normalized(visual_line(remaining[:stop])) == actual:
                break
            if stop > len(actual)*2+8:
                break
        else:
            stop = 0
        if not stop or _normalized(visual_line(remaining[:stop])) != actual:
            first = remaining.split(' ', 1)[0]
            stop = next((n for n in range(1, min(len(first), len(actual)*2+8)+1)
                         if _normalized(visual_line(first[:n])) == actual), 0)
            if not stop:
                raise ValueError(f'Expected {remaining[:55]!r}, painted {actual!r}')
        remaining = remaining[stop:].lstrip()
    if remaining:
        raise ValueError(f'Truncated field; unpainted text starts {remaining[:55]!r}')


def verify_saved_pdf(data, content, *, cover=None, retain_cells=False):
    blocks, error = parse_saved_markdown_structure(content)
    if error:
        raise ValueError(error)
    expected = []
    section = 0
    for block in blocks:
        if block['kind'] == 'table':
            expected.append(('header', block['header'], section))
            expected.extend(('row', values, section) for values in block['rows'])
        else:
            role = 'prose'
            if block['kind'] == 'heading':
                role = 'heading' if block['level'] <= 2 else 'subheading'
                section += int(role=='heading')
            expected.append((role,[block['text']],section))
    checked = []
    pos = repeats = 0
    last_header = None
    pending = None
    missing_tokens = Counter()
    with pymupdf.open(stream=data, filetype='pdf') as document:
        for page in document:
            rows = painted_rows(page)
            if page.number == 0:
                if [r[0] for r in rows[:3]] != ['header','heading','metadata']:
                    raise ValueError('Missing saved document title/organization block')
                # The first page is the owned cover/control and the nine source headings.
                titles = [v[0] for role,v,_ in expected if role == 'heading']
                if [r[0] for r in rows[3:]] != ['header','row','heading'] + ['metadata']*len(titles):
                    raise ValueError('Incomplete document control or contents')
                for value,actual in zip(['نوع الوثيقة','القطاع','الحالة','تاريخ الإعداد'], rows[3][1], strict=True):
                    match_field(value, actual)
                if cover:
                    for field,expected_value in ((0,cover['org_name']), (1,cover['document_title']),
                                                 (2,cover['domain_display'])):
                        match_field(expected_value, rows[field][1][0])
                    for col, key in enumerate(('document_type_label','sector','artifact_status')):
                        match_field(cover[key],rows[4][1][col])
                if not re.fullmatch(r'\d{2} [A-Za-z]+ \d{4}', ' '.join(rows[4][1][-1])):
                    raise ValueError('Unreadable preparation date')
                for number,title in enumerate(titles,1):
                    match_field(f'{number}. {title}', rows[5+number][1][0])
                continue
            for index,(role,fields) in enumerate(rows):
                if pos >= len(expected):
                    raise ValueError('Unexpected additional PDF body')
                kind, source_values, section_no = expected[pos]
                repeat = index == 0 and page.number and role == 'header' and kind=='row'
                if repeat:
                    kind, source_values = 'header', last_header
                    repeats += 1
                if role!=kind or len(fields)!=len(source_values):
                    raise ValueError(f'page {page.number+1} block {pos}: expected {kind}, got {role}')
                if pending is not None and not repeat:
                    fields = [earlier + later for earlier,later in zip(pending,fields,strict=True)]
                    pending = None
                for col,(source,lines) in enumerate(zip(source_values,fields,strict=True)):
                    try:
                        match_field(source,lines)
                    except ValueError as err:
                        if (index == len(rows)-1 and page.number+1 < len(document)
                                and kind == 'row' and str(err).startswith('Truncated field')):
                            pending = fields
                            break
                        raise ValueError(f'page {page.number+1}, section {section_no}, block {pos}, column {col+1}: {err}') from err
                if pending is not None and not repeat:
                    continue
                # Independently require literal technical tokens in the painted cell,
                # rather than using the renderer's bidi helper to judge their ordering.
                if not repeat:
                    for value, painted_lines in zip(source_values, fields, strict=True):
                        tokens = re.findall(r'\(API v2\.1\)|\[DT-POS-01\]|[A-Z]+-DT-POS-\d+|\d{4}-\d{2}-\d{2}|\d+(?:\.\d+)?%', value)
                        seen = ' '.join(painted_lines)
                        for token, count in Counter(tokens).items():
                            # A physical line break is allowed inside an over-width
                            # LTR run. Full logical field matching above still enforces
                            # the exact source content and location of every space.
                            occurrences = max(seen.count(token), ''.join(painted_lines).count(token))
                            if occurrences < count:
                                missing_tokens[token] += count - occurrences
                if role=='header':
                    last_header = source_values
                checked.append(dict(page=page.number+1, section=section_no, block=pos,
                                    role=role, cells=len(fields), repeat=bool(repeat)))
                if retain_cells:
                    checked[-1]['source_cells'] = source_values
                    checked[-1]['painted_lines_by_source_column'] = fields
                pos += int(not repeat)
        pages = len(document)
    if missing_tokens:
        raise ValueError(f'Missing literal technical spans in their own cell: {dict(missing_tokens)}')
    if pending is not None or pos!=len(expected):
        raise ValueError('Missing trailing PDF content')
    return dict(sections=section, pages=pages, source_records=pos, repeated_headers=repeats,
                sha256=hashlib.sha256(data).hexdigest(), checked=checked)
