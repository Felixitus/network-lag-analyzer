"""CSV and XLSX output for exports - without third-party packages.

Both are written only when a user asks for an export and are streamed to the
browser; nothing is kept on the Pi (XLSX goes through a spooled temporary file
that lives in memory up to a few MB and is deleted when the response ends).

Formula injection: spreadsheet programs evaluate cells that start with `=`, `+`,
`-` or `@` (also after a tab or carriage return). Domain names come from DNS
queries and device names are typed by users - both are attacker-controllable. So
every *text* cell that starts with one of these characters gets a leading
apostrophe (OWASP recommendation). Numbers are written as numbers and are not
touched; XLSX text cells are inline strings, which Excel never evaluates, but they
are sanitized the same way so that both formats show the same value.
"""
from __future__ import annotations

import csv
import io
import re
import zipfile
from typing import IO, Iterable, Iterator, Sequence
from xml.sax.saxutils import escape

DANGEROUS_START = ("=", "+", "-", "@", "\t", "\r")
# Characters XML 1.0 does not allow at all - a DNS name can contain anything.
_XML_INVALID = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff]")


def safe_text(v: str) -> str:
    return "'" + v if v.startswith(DANGEROUS_START) else v


class CsvFormat:
    """`de`: what a German Excel opens with a double click - semicolon, decimal comma.
    `en`: comma and decimal point. Both UTF-8 with BOM, otherwise Excel guesses
    the code page and breaks umlauts."""

    def __init__(self, locale: str = "de"):
        self.delimiter = ";" if locale == "de" else ","
        self.decimal = "," if locale == "de" else "."

    def cell(self, v) -> str:
        if v is None:
            return ""
        if isinstance(v, bool):
            return "yes" if v else "no"
        if isinstance(v, int):
            return str(v)
        if isinstance(v, float):
            s = f"{v:.4f}".rstrip("0").rstrip(".")
            return s.replace(".", self.decimal)
        return safe_text(str(v))


def csv_stream(rows: Iterable[Sequence], fmt: CsvFormat) -> Iterator[bytes]:
    """Yields the encoded CSV in chunks; the first chunk starts with the BOM."""
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=fmt.delimiter, lineterminator="\r\n", quoting=csv.QUOTE_MINIMAL)
    yield "﻿".encode("utf-8")
    for i, row in enumerate(rows, 1):
        w.writerow([fmt.cell(v) for v in row])
        if i % 500 == 0:
            yield buf.getvalue().encode("utf-8")
            buf.seek(0)
            buf.truncate()
    yield buf.getvalue().encode("utf-8")


# ---------------------------------------------------------------------- XLSX
def _col(n: int) -> str:
    s = ""
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


def sheet_name(name: str, used: set[str]) -> str:
    base = re.sub(r"[\[\]:*?/\\]", "-", name)[:31].strip() or "Sheet"
    out, i = base, 2
    while out.lower() in used:
        out = f"{base[:28]} {i}"
        i += 1
    used.add(out.lower())
    return out


def _cell_xml(ref: str, v, bold: bool) -> str:
    style = ' s="1"' if bold else ""
    if v is None or v == "":
        return ""
    if isinstance(v, bool):
        v = "yes" if v else "no"
    if isinstance(v, (int, float)):
        return f'<c r="{ref}"{style}><v>{v!r}</v></c>' if isinstance(v, float) else f'<c r="{ref}"{style}><v>{v}</v></c>'
    text = escape(_XML_INVALID.sub("", safe_text(str(v))))
    return f'<c r="{ref}"{style} t="inlineStr"><is><t xml:space="preserve">{text}</t></is></c>'


def write_xlsx(out: IO[bytes], sheets: Sequence[tuple[str, Iterable[Sequence], int]]) -> None:
    """sheets: (name, rows, number of header rows shown bold)."""
    used: set[str] = set()
    names = [sheet_name(n, used) for n, _r, _h in sheets]
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                   '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                   '<Default Extension="xml" ContentType="application/xml"/>'
                   '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
                   '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
                   + "".join(f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
                             for i in range(1, len(sheets) + 1))
                   + "</Types>")
        z.writestr("_rels/.rels",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
                   "</Relationships>")
        z.writestr("xl/workbook.xml",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                   'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
                   + "".join(f'<sheet name="{escape(n, {chr(34): "&quot;"})}" sheetId="{i}" r:id="rId{i}"/>'
                             for i, n in enumerate(names, 1))
                   + "</sheets></workbook>")
        z.writestr("xl/_rels/workbook.xml.rels",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   + "".join(f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i}.xml"/>'
                             for i in range(1, len(sheets) + 1))
                   + f'<Relationship Id="rId{len(sheets) + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
                   "</Relationships>")
        z.writestr("xl/styles.xml",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                   '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
                   '<font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
                   '<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>'
                   '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
                   '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
                   '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
                   '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>'
                   '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
                   "</styleSheet>")
        for i, (_name, rows, header) in enumerate(sheets, 1):
            # Rows are streamed into the zip entry - a large domain list never
            # has to exist as one big string.
            with z.open(f"xl/worksheets/sheet{i}.xml", "w") as f:
                f.write(b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                        b'<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                        b'<cols><col min="1" max="1" width="34" customWidth="1"/>'
                        b'<col min="2" max="30" width="16" customWidth="1"/></cols><sheetData>')
                for r, row in enumerate(rows, 1):
                    cells = "".join(_cell_xml(f"{_col(c)}{r}", v, r <= header) for c, v in enumerate(row, 1))
                    f.write(f'<row r="{r}">{cells}</row>'.encode("utf-8"))
                f.write(b"</sheetData></worksheet>")
