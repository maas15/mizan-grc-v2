"""Compare governance source fields with the actual native export surfaces."""

from __future__ import annotations

from html.parser import HTMLParser
from io import BytesIO
import re
import unicodedata
from xml.etree import ElementTree
from zipfile import ZipFile

from release_engine_v3.rel33_governance_artifact import (
    governance_model_blockers,
    governance_model_markdown,
    governance_model_section_order,
)


def _normal(value):
    # Expand only Arabic presentation forms produced by shaping. Preserve
    # letters, marks, digits, punctuation, cell identity and assignment codes.
    text = ''.join(
        unicodedata.normalize('NFKC', char)
        if 0xfb50 <= ord(char) <= 0xfeff else char
        for char in str(value or ''))
    text = re.sub('[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]', '', text)
    return ' '.join(text.split())


class _Preview(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tables = []
        self.text = []
        self.table = None
        self.row = None
        self.cell = None

    def handle_starttag(self, tag, attrs):
        if tag == 'table':
            self.table = []
        elif tag == 'tr' and self.table is not None:
            self.row = []
        elif tag in ('th', 'td') and self.row is not None:
            self.cell = []
        elif tag in ('br', 'p'):
            if self.cell is not None:
                self.cell.append('\n')
            self.text.append('\n')

    def handle_data(self, value):
        self.text.append(value)
        if self.cell is not None:
            self.cell.append(value)

    def handle_endtag(self, tag):
        if tag in ('th', 'td') and self.cell is not None:
            self.row.append(''.join(self.cell))
            self.cell = None
        elif tag == 'tr' and self.row is not None:
            self.table.append(self.row)
            self.row = None
        elif tag == 'table' and self.table is not None:
            self.tables.append(self.table)
            self.table = None
        self.text.append('\n')


def _source(sections):
    from release_engine_v3.canonical_document import parse_saved_markdown_structure
    tables = []
    fields = []
    for key in governance_model_section_order():
        blocks, error = parse_saved_markdown_structure(sections[key])
        if error:
            raise ValueError(f'{key}:unsupported_source_markdown')
        for block in blocks:
            if block['kind'] == 'table':
                tables.append((key, [block['header'], *block['rows']]))
            else:
                fields.append((key, block['text']))
    return tables, fields


def _docx_surface(data):
    ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
    with ZipFile(BytesIO(data)) as archive:
        body = ElementTree.fromstring(archive.read('word/document.xml'))

    def paragraph_text(paragraph):
        return ''.join(item.text or '' for item in paragraph.findall('.//w:t', ns))

    tables = []
    for table in body.findall('.//w:tbl', ns):
        tables.append([
            ['\n'.join(paragraph_text(paragraph)
                       for paragraph in cell.findall('.//w:p', ns))
             for cell in row.findall('w:tc', ns)]
            for row in table.findall('w:tr', ns)])
    text = '\n'.join(paragraph_text(paragraph)
                     for paragraph in body.findall('.//w:p', ns))
    return tables, text


def _same_row(expected, actual):
    return len(expected) == len(actual) and all(
        _normal(left) == _normal(right) for left, right in zip(expected, actual))


def _check_tables(expected, actual):
    if not expected:
        return 0
    first = expected[0][1][0]
    start = None
    for index, table in enumerate(actual):
        if table and _same_row(first, table[0]):
            start = index
            break
    if start is None:
        raise ValueError(f'{expected[0][0]}:table_header_missing')
    native = actual[start:]
    if len(native) != len(expected):
        raise ValueError('native_table_count')
    cells = 0
    for (section, wanted), table in zip(expected, native):
        if len(wanted) != len(table):
            raise ValueError(f'{section}:table_row_count')
        for row_number, (source_row, actual_row) in enumerate(zip(wanted, table)):
            if not _same_row(source_row, actual_row):
                raise ValueError(f'{section}:table_cells:{row_number}')
            cells += len(source_row)
    return cells


def evaluate_governance_export_evidence(
        *, route, sections, preview_html='', docx_bytes=b'', pdf_bytes=b''):
    """Fail closed unless every native source table cell is actually present.

    DOCX cells are read from the delivered OOXML. PDF fields are checked by
    painted physical cell bounds, including continuation headers and rows.
    No other export's text or marker counter can stand in for actual PDF cells.
    """
    prefix = f'rel33_governance_export_mismatch:{route}:'
    blockers = governance_model_blockers(sections)
    result = {'passed': False, 'blocking_errors': list(blockers), 'checked_cells': 0}
    if blockers:
        return result
    try:
        tables, fields = _source(sections)
        if route == 'preview':
            if not preview_html:
                raise ValueError('actual_html_missing')
            surface = _Preview()
            surface.feed(preview_html)
            actual_tables = surface.tables
            actual_text = '\n'.join(surface.text)
            cells = _check_tables(tables, actual_tables)
            for section, value in fields:
                if _normal(value) not in _normal(actual_text):
                    raise ValueError(f'{section}:source_text_missing')
        elif route == 'docx':
            if not docx_bytes:
                raise ValueError('actual_bytes_missing')
            actual_tables, actual_text = _docx_surface(docx_bytes)
            cells = _check_tables(tables, actual_tables)
            for section, value in fields:
                if _normal(value) not in _normal(actual_text):
                    raise ValueError(f'{section}:source_text_missing')
        elif route == 'pdf':
            if not pdf_bytes:
                raise ValueError('actual_bytes_missing')
            from release_engine_v3.exporters.saved_pdf_verification import verify_saved_pdf
            verification = verify_saved_pdf(
                pdf_bytes, governance_model_markdown(sections))
            cells = sum(
                item['cells'] for item in verification['checked']
                if item['role'] in ('header', 'row') and not item['repeat'])
            result['pdf_native_verification'] = verification
        else:
            raise ValueError('unsupported_route')
        result.update(passed=True, checked_cells=cells, checked_sections=list(governance_model_section_order()))
    except Exception as error:
        result['blocking_errors'] = [prefix + str(error)]
    return result
