"""CSV/XLSX export helpers: Excel compatibility and formula injection."""
import io
import zipfile
from xml.etree import ElementTree as ET

from backend.api.dns_export import domains_table
from backend.util.tabular import CsvFormat, csv_stream, safe_text, sheet_name, write_xlsx

NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}


def csv_text(rows, locale="de"):
    return b"".join(csv_stream(rows, CsvFormat(locale))).decode("utf-8")


def test_text_that_spreadsheets_would_evaluate_gets_an_apostrophe():
    for bad in ("=HYPERLINK(\"http://x\")", "+49 phone", "-1+1", "@SUM(A1)", "\tcmd", "\rcmd"):
        assert safe_text(bad) == "'" + bad
    assert safe_text("www.example.com") == "www.example.com"


def test_csv_for_german_excel_has_bom_semicolon_and_decimal_comma():
    t = csv_text([["Gerät", "Anteil"], ["Küche", 12.5], ["=evil", 3]])
    assert t.startswith("﻿")
    assert t.split("\r\n")[:3] == ["﻿Gerät;Anteil", "Küche;12,5", "'=evil;3"]


def test_csv_international_uses_comma_and_point_and_quotes_when_needed():
    t = csv_text([["a, b", 1.25], [None, True]], "en")
    assert t.split("\r\n")[:2] == ['﻿"a, b",1.25', ",yes"]


def test_large_csv_is_streamed_in_chunks():
    chunks = list(csv_stream(([i, f"d{i}.example"] for i in range(5000)), CsvFormat()))
    assert len(chunks) > 5 and b"".join(chunks).count(b"\r\n") == 5000


def _sheet(z, i):
    root = ET.fromstring(z.read(f"xl/worksheets/sheet{i}.xml"))
    out = []
    for row in root.find("m:sheetData", NS):
        vals = []
        for c in row:
            if c.get("t") == "inlineStr":
                vals.append(c.find("m:is/m:t", NS).text)
            else:
                vals.append(float(c.find("m:v", NS).text))
        out.append(vals)
    return out


def test_xlsx_is_a_valid_workbook_with_sheets_numbers_and_safe_text():
    buf = io.BytesIO()
    write_xlsx(buf, [("About", [["Export", "Test"]], 1),
                     ("Domains", [["Domain", "Queries"], ["=cmd|' /C calc'!A0", 7], ["bad\x00name\x1f", 2.5]], 1)])
    z = zipfile.ZipFile(io.BytesIO(buf.getvalue()))
    assert z.testzip() is None
    for name in z.namelist():
        if name.endswith(".xml") or name.endswith(".rels"):
            ET.fromstring(z.read(name))                     # every part is well-formed XML
    wb = ET.fromstring(z.read("xl/workbook.xml"))
    assert [s.get("name") for s in wb.find("m:sheets", NS)] == ["About", "Domains"]
    assert _sheet(z, 2) == [["Domain", "Queries"], ["'=cmd|' /C calc'!A0", 7.0], ["badname", 2.5]]
    first = ET.fromstring(z.read("xl/worksheets/sheet2.xml")).find("m:sheetData/m:row/m:c", NS)
    assert first.get("s") == "1"                            # header bold


def test_sheet_names_are_valid_and_unique():
    used = set()
    assert sheet_name("Activity [estimated] / phases: very long name indeed", used) == \
        "Activity -estimated- - phases-"
    assert sheet_name("Domains", used) == "Domains" and sheet_name("domains", used) == "domains 2"


def test_domain_export_protects_domain_names_and_marks_folded_rows():
    rows = [{"name": "=1+1.example", "queries": 3, "blocked": 0, "first_seen": None, "last_seen": None,
             "category": "unknown", "classification": {"categories": ["unknown"]}},
            {"name": None, "queries": 2, "blocked": 0, "first_seen": None, "last_seen": None,
             "category": "not_itemized", "classification": None}]
    t = csv_text(domains_table(rows, {"unknown": "Unknown"}))
    lines = t.split("\r\n")
    assert lines[1].startswith("'=1+1.example;Unknown")
    assert lines[2].startswith("(other domains, folded);Not itemized")
