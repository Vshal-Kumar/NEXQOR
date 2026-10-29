#!/usr/bin/env python3
"""
security_lab/reporting/generate_pdf.py

Converts QRYPTONEX security evaluation report (report.md / JSON results)
into an executive, professionally styled PDF document with clean tables,
verdict badges (no emojis), and corporate cyber styling.
Uses google-chrome or libreoffice headless under the hood.
"""

import os
import sys
import re
import subprocess
import shutil

def markdown_to_styled_html(md_path, html_path):
    if not os.path.exists(md_path):
        return False

    with open(md_path, "r", encoding="utf-8") as f:
        text = f.read()

    html_parts = []
    html_parts.append("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>QRYPTONEX Security Evaluation & Multi-Suite Comparison Report</title>
<style>
    @page {
        size: A4;
        margin: 15mm 15mm 15mm 15mm;
        @bottom-right {
            content: "Page " counter(page) " of " counter(pages);
            font-size: 9px;
            color: #64748b;
        }
    }
    body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        color: #1e293b;
        line-height: 1.55;
        background: #ffffff;
        font-size: 12px;
        margin: 0;
        padding: 0;
    }
    .header-banner {
        border-bottom: 3px solid #00c853;
        padding-bottom: 12px;
        margin-bottom: 16px;
    }
    .report-title {
        font-size: 20px;
        font-weight: 800;
        color: #0f172a;
        margin: 0 0 4px 0;
        letter-spacing: -0.3px;
    }
    .report-subtitle {
        font-size: 11px;
        font-weight: 600;
        color: #00897b;
        text-transform: uppercase;
        letter-spacing: 0.8px;
        margin: 0 0 12px 0;
    }
    .meta-grid {
        display: table;
        width: 100%;
        background-color: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 6px;
        padding: 10px 14px;
        margin-bottom: 18px;
        box-sizing: border-box;
    }
    .meta-row {
        display: table-row;
    }
    .meta-cell-label {
        display: table-cell;
        font-weight: 700;
        color: #475569;
        padding: 3px 12px 3px 0;
        width: 150px;
        font-size: 11px;
    }
    .meta-cell-val {
        display: table-cell;
        color: #0f172a;
        padding: 3px 0;
        font-family: "JetBrains Mono", "Courier New", monospace;
        font-size: 11px;
    }
    h2 {
        font-size: 14px;
        font-weight: 800;
        color: #0f172a;
        border-bottom: 1.5px solid #cbd5e1;
        padding-bottom: 4px;
        margin-top: 20px;
        margin-bottom: 10px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    h3 {
        font-size: 12px;
        font-weight: 700;
        color: #334155;
        margin-top: 14px;
        margin-bottom: 6px;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        margin: 12px 0 18px 0;
        font-size: 11px;
    }
    th {
        background-color: #0f172a;
        color: #ffffff;
        padding: 7px 9px;
        text-align: left;
        font-weight: 700;
        font-size: 10.5px;
        border: 1px solid #0f172a;
    }
    td {
        padding: 6px 9px;
        border: 1px solid #e2e8f0;
        vertical-align: middle;
    }
    tr:nth-child(even) td {
        background-color: #f8fafc;
    }
    code {
        background-color: #f1f5f9;
        border: 1px solid #e2e8f0;
        padding: 1px 5px;
        border-radius: 4px;
        font-family: "JetBrains Mono", "Courier New", monospace;
        font-size: 10.5px;
        color: #0369a1;
    }
    .badge-pass {
        display: inline-block;
        background-color: #dcfce7;
        color: #166534;
        border: 1px solid #86efac;
        padding: 2px 7px;
        border-radius: 12px;
        font-weight: 800;
        font-size: 10px;
        letter-spacing: 0.4px;
    }
    .badge-fail {
        display: inline-block;
        background-color: #fee2e2;
        color: #991b1b;
        border: 1px solid #fca5a5;
        padding: 2px 7px;
        border-radius: 12px;
        font-weight: 800;
        font-size: 10px;
        letter-spacing: 0.4px;
    }
    .badge-suite {
        display: inline-block;
        background-color: #e0f2fe;
        color: #0369a1;
        border: 1px solid #bae6fd;
        padding: 2px 6px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 10px;
    }
    ul {
        margin: 6px 0 12px 0;
        padding-left: 18px;
    }
    li {
        margin-bottom: 4px;
    }
    .footer {
        margin-top: 30px;
        border-top: 1px solid #e2e8f0;
        padding-top: 8px;
        font-size: 10px;
        color: #64748b;
        text-align: center;
    }
</style>
</head>
<body>

<div class="header-banner">
    <div class="report-title">QRYPTONEX Security Evaluation & Verification Report</div>
    <div class="report-subtitle">Real-Network Attack Simulation & Multi-Suite Cryptographic Comparison</div>
</div>
""")

    meta_items = {}
    lines = text.splitlines()
    in_table = False
    i = 0

    while i < len(lines):
        line = lines[i].strip()

        # Parse metadata lines
        meta_match = re.match(r"\*\*(.*?):\*\*\s*`?(.*?)`?\s*$", line)
        if meta_match and ("Execution ID" in line or "Timestamp" in line or "Target" in line or "Environment" in line or "Architecture" in line or "Compiler" in line):
            label = meta_match.group(1).strip()
            val = meta_match.group(2).strip().strip("`")
            meta_items[label] = val
            i += 1
            continue

        # Render metadata grid once header has passed
        if line.startswith("---") and meta_items:
            html_parts.append('<div class="meta-grid">')
            for k, v in meta_items.items():
                html_parts.append(f'<div class="meta-row"><div class="meta-cell-label">{k}</div><div class="meta-cell-val">{v}</div></div>')
            html_parts.append('</div>')
            meta_items.clear()
            i += 1
            continue

        # Process markdown tables
        if line.startswith("|") and line.endswith("|"):
            cols = [c.strip() for c in line[1:-1].split("|")]
            # Skip separator line | :--- | :--- |
            if all(set(c) <= set(":- ") for c in cols):
                i += 1
                continue

            if not in_table:
                in_table = True
                html_parts.append('<table><thead><tr>')
                for c in cols:
                    c_clean = clean_text(c)
                    html_parts.append(f'<th>{c_clean}</th>')
                html_parts.append('</tr></thead><tbody>')
            else:
                html_parts.append('<tr>')
                for c in cols:
                    c_clean = clean_text(c)
                    # Verdict formatting
                    if "PASS" in c:
                        c_clean = '<span class="badge-pass">PASS</span>'
                    elif "FAIL" in c:
                        c_clean = '<span class="badge-fail">FAIL</span>'
                    elif c in ("pqc", "hybrid", "classical"):
                        c_clean = f'<span class="badge-suite">{c.upper()}</span>'
                    html_parts.append(f'<td>{c_clean}</td>')
                html_parts.append('</tr>')
            i += 1
            continue
        else:
            if in_table:
                html_parts.append('</tbody></table>')
                in_table = False

        # Headings
        if line.startswith("# "):
            pass # Title handled in banner
        elif line.startswith("## "):
            sec_title = clean_text(line[3:])
            html_parts.append(f'<h2>{sec_title}</h2>')
        elif line.startswith("### "):
            sub_title = clean_text(line[4:])
            html_parts.append(f'<h3>{sub_title}</h3>')
        elif line.startswith("- "):
            item_text = clean_text(line[2:])
            html_parts.append(f'<ul><li>{item_text}</li></ul>')
        elif re.match(r"^\d+\.\s", line):
            num_item = clean_text(re.sub(r"^\d+\.\s*", "", line))
            html_parts.append(f'<p><strong>•</strong> {num_item}</p>')
        elif line:
            p_text = clean_text(line)
            html_parts.append(f'<p>{p_text}</p>')

        i += 1

    if in_table:
        html_parts.append('</tbody></table>')

    html_parts.append("""
<div class="footer">
    QRYPTONEX Cryptographic Resilience Lab — Generated by Headless Evaluation Engine
</div>
</body>
</html>
""")

    with open(html_path, "w", encoding="utf-8") as f:
        f.write("\n".join(html_parts))

    return True

def clean_text(s):
    # Remove emojis
    s = re.sub(r'[\U00010000-\U0010ffff]', '', s)
    s = s.replace("✅", "").replace("❌", "").replace("⚠️", "").replace("🛡️", "").replace("⚡", "").replace("📉", "").strip()
    # Format bold
    s = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', s)
    # Format code
    s = re.sub(r'`(.*?)`', r'<code>\1</code>', s)
    return s

def convert_html_to_pdf(html_path, pdf_path):
    # Option 1: google-chrome headless (pixel-perfect)
    chrome_bin = shutil.which("google-chrome") or shutil.which("chromium")
    if chrome_bin:
        cmd = [
            chrome_bin,
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            f"--print-to-pdf={pdf_path}",
            html_path
        ]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if res.returncode == 0 and os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 0:
            return True

    # Option 2: libreoffice headless fallback
    libre_bin = shutil.which("libreoffice")
    if libre_bin:
        out_dir = os.path.dirname(pdf_path) or "."
        cmd = [
            libre_bin,
            "--headless",
            "--convert-to", "pdf",
            html_path,
            "--outdir", out_dir
        ]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # libreoffice names output based on input filename
        base_name = os.path.splitext(os.path.basename(html_path))[0] + ".pdf"
        lo_pdf = os.path.join(out_dir, base_name)
        if os.path.exists(lo_pdf) and lo_pdf != pdf_path:
            shutil.move(lo_pdf, pdf_path)
        if os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 0:
            return True

    return False

def main():
    workspace = sys.argv[1] if len(sys.argv) > 1 else "."
    results_dir = os.path.join(workspace, "security_lab", "results", "latest")
    md_path = os.path.join(results_dir, "report.md")
    html_path = os.path.join(results_dir, "report.html")
    pdf_path = os.path.join(results_dir, "report.pdf")

    if not os.path.exists(md_path):
        print(f"[ERROR] Markdown report not found at {md_path}")
        sys.exit(1)

    print(f"[1/2] Converting {md_path} -> {html_path}...")
    if not markdown_to_styled_html(md_path, html_path):
        print("[ERROR] Failed to compile HTML")
        sys.exit(1)

    print(f"[2/2] Rendering PDF to {pdf_path}...")
    if convert_html_to_pdf(html_path, pdf_path):
        print(f"[SUCCESS] PDF generated successfully: {pdf_path} ({os.path.getsize(pdf_path)} bytes)")
    else:
        print("[ERROR] PDF conversion failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()
