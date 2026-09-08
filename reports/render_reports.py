#!/usr/bin/env python3

from pathlib import Path
import html
import re

ROOT = Path(".")
REPORTS = ROOT / "reports"

CSS = """
@page {
  size: A4;
  margin: 18mm 16mm 18mm 16mm;
}

body {
  font-family: Arial, Helvetica, sans-serif;
  color: #111827;
  font-size: 10.5pt;
  line-height: 1.48;
  margin: 0;
}

h1 {
  font-size: 22pt;
  margin: 0 0 14pt 0;
  color: #111827;
  border-bottom: 2px solid #374151;
  padding-bottom: 8pt;
}

h2 {
  font-size: 14.5pt;
  margin: 18pt 0 7pt 0;
  color: #1f2937;
  break-after: avoid;
}

h3 {
  font-size: 11.5pt;
  margin: 13pt 0 5pt 0;
  color: #374151;
  break-after: avoid;
}

p {
  margin: 5pt 0 8pt 0;
}

ul, ol {
  margin: 5pt 0 9pt 20pt;
  padding: 0;
}

li {
  margin: 2.5pt 0;
}

code {
  font-family: "DejaVu Sans Mono", "Liberation Mono", monospace;
  font-size: 9pt;
  background: #f3f4f6;
  padding: 1pt 3pt;
  border-radius: 2pt;
  overflow-wrap: anywhere;
}

pre {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  background: #f3f4f6;
  border-left: 3px solid #6b7280;
  padding: 8pt;
}

strong {
  font-weight: 700;
}

hr {
  border: none;
  border-top: 1px solid #d1d5db;
  margin: 14pt 0;
}
"""

def inline_markup(text):
    text = html.escape(text)
    text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)
    text = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', text)
    return text

def markdown_to_html(md):
    out = []
    in_ul = False
    in_ol = False
    paragraph = []

    def flush_paragraph():
        nonlocal paragraph
        if paragraph:
            joined = " ".join(x.strip() for x in paragraph)
            out.append(f"<p>{inline_markup(joined)}</p>")
            paragraph = []

    def close_lists():
        nonlocal in_ul, in_ol
        if in_ul:
            out.append("</ul>")
            in_ul = False
        if in_ol:
            out.append("</ol>")
            in_ol = False

    for raw in md.splitlines():
        line = raw.rstrip()

        if not line.strip():
            flush_paragraph()
            close_lists()
            continue

        if line.startswith("### "):
            flush_paragraph()
            close_lists()
            out.append(f"<h3>{inline_markup(line[4:])}</h3>")
            continue

        if line.startswith("## "):
            flush_paragraph()
            close_lists()
            out.append(f"<h2>{inline_markup(line[3:])}</h2>")
            continue

        if line.startswith("# "):
            flush_paragraph()
            close_lists()
            out.append(f"<h1>{inline_markup(line[2:])}</h1>")
            continue

        if re.match(r"^\d+\.\s+", line):
            flush_paragraph()
            if in_ul:
                out.append("</ul>")
                in_ul = False
            if not in_ol:
                out.append("<ol>")
                in_ol = True
            item = re.sub(r"^\d+\.\s+", "", line)
            out.append(f"<li>{inline_markup(item)}</li>")
            continue

        if line.startswith("- "):
            flush_paragraph()
            if in_ol:
                out.append("</ol>")
                in_ol = False
            if not in_ul:
                out.append("<ul>")
                in_ul = True
            out.append(f"<li>{inline_markup(line[2:])}</li>")
            continue

        paragraph.append(line)

    flush_paragraph()
    close_lists()
    return "\n".join(out)

for stem in ("incident-report", "executive-brief"):
    md_path = REPORTS / f"{stem}.md"
    html_path = REPORTS / f"{stem}.html"

    body = markdown_to_html(md_path.read_text())
    html_doc = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>{stem}</title>
<style>{CSS}</style>
</head>
<body>
{body}
</body>
</html>
"""
    html_path.write_text(html_doc)

    print(f"created {html_path}")
