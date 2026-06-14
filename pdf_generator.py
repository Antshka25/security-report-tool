"""
pdf_generator.py — Professional security report PDF using reportlab.
Designed to look like a paid product ($50-200 price point).
"""
import io
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.graphics.shapes import Drawing, Rect, String, Circle
from reportlab.graphics import renderPDF


# ── Brand colours ─────────────────────────────────────────────────────────────
C_BG       = colors.HexColor("#0a0e1a")
C_PANEL    = colors.HexColor("#111827")
C_ACCENT   = colors.HexColor("#7c3aed")
C_ACCENT2  = colors.HexColor("#0ea5e9")
C_HIGH     = colors.HexColor("#ef4444")
C_MEDIUM   = colors.HexColor("#f59e0b")
C_LOW      = colors.HexColor("#10b981")
C_INFO     = colors.HexColor("#6b7280")
C_WHITE    = colors.HexColor("#f0f4ff")
C_MUTED    = colors.HexColor("#94a3b8")
C_BORDER   = colors.HexColor("#1e2a45")
C_ROW_ALT  = colors.HexColor("#131c2e")

SEVERITY_COLORS = {
    "HIGH":   C_HIGH,
    "MEDIUM": C_MEDIUM,
    "LOW":    C_LOW,
    "INFO":   C_INFO,
}

RISK_COLORS = {
    "CRITICAL": C_HIGH,
    "HIGH":     colors.HexColor("#f97316"),
    "MEDIUM":   C_MEDIUM,
    "LOW":      C_LOW,
}


# ── Style helpers ─────────────────────────────────────────────────────────────

def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("title", fontName="Helvetica-Bold",
                                fontSize=22, textColor=C_WHITE, spaceAfter=4),
        "subtitle": ParagraphStyle("subtitle", fontName="Helvetica",
                                   fontSize=11, textColor=C_MUTED, spaceAfter=8),
        "h2": ParagraphStyle("h2", fontName="Helvetica-Bold",
                              fontSize=14, textColor=C_WHITE, spaceBefore=18, spaceAfter=6),
        "h3": ParagraphStyle("h3", fontName="Helvetica-Bold",
                              fontSize=11, textColor=C_ACCENT2, spaceBefore=10, spaceAfter=4),
        "body": ParagraphStyle("body", fontName="Helvetica",
                               fontSize=10, textColor=C_WHITE, leading=15, spaceAfter=6),
        "body_muted": ParagraphStyle("body_muted", fontName="Helvetica",
                                     fontSize=9, textColor=C_MUTED, leading=14, spaceAfter=4),
        "label": ParagraphStyle("label", fontName="Helvetica-Bold",
                                fontSize=9, textColor=C_MUTED, spaceAfter=2),
        "small": ParagraphStyle("small", fontName="Helvetica",
                                fontSize=8, textColor=C_MUTED, leading=12),
        "center": ParagraphStyle("center", fontName="Helvetica",
                                 fontSize=10, textColor=C_WHITE, alignment=TA_CENTER),
        "bullet": ParagraphStyle("bullet", fontName="Helvetica",
                                  fontSize=10, textColor=C_WHITE, leading=15,
                                  leftIndent=14, spaceAfter=4),
    }


def _divider(color=C_BORDER):
    return HRFlowable(width="100%", thickness=1, color=color, spaceAfter=8, spaceBefore=4)


def _risk_badge(severity: str, width: float = 80) -> Drawing:
    """Draw a coloured risk badge."""
    col = SEVERITY_COLORS.get(severity, C_INFO)
    d = Drawing(width, 18)
    d.add(Rect(0, 0, width, 18, fillColor=col, strokeColor=None, rx=4, ry=4))
    d.add(String(width / 2, 4, severity, fontName="Helvetica-Bold",
                 fontSize=9, fillColor=colors.white, textAnchor="middle"))
    return d


def _score_gauge(score: int, label: str) -> Drawing:
    """Draw a circular risk score gauge."""
    size = 90
    d = Drawing(size, size)
    cx, cy, r = size / 2, size / 2, 38
    col = RISK_COLORS.get(label, C_LOW)
    # Outer ring
    d.add(Circle(cx, cy, r, fillColor=C_PANEL, strokeColor=col, strokeWidth=4))
    # Score number
    d.add(String(cx, cy + 4, str(score), fontName="Helvetica-Bold",
                 fontSize=28, fillColor=C_WHITE, textAnchor="middle"))
    d.add(String(cx, cy - 12, "/10", fontName="Helvetica",
                 fontSize=10, fillColor=C_MUTED, textAnchor="middle"))
    d.add(String(cx, cy - 26, label, fontName="Helvetica-Bold",
                 fontSize=9, fillColor=col, textAnchor="middle"))
    return d


# ── Main PDF builder ──────────────────────────────────────────────────────────

def build_pdf(report: dict) -> bytes:
    """
    Build the complete PDF report and return bytes.
    report — the dict returned by ai_reporter.generate_report()
    """
    buf = io.BytesIO()
    meta = report.get("meta", {})
    S = _styles()

    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=0.65 * inch,
        rightMargin=0.65 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    story = []
    W = doc.width

    # ── Cover header ──────────────────────────────────────────────────────────
    header_data = [[
        Paragraph(f"<font color='#7c3aed'>■</font> SECURITY REPORT", S["title"]),
        Paragraph(
            f"<font color='#94a3b8'>{meta.get('business_name', 'Your Business')}</font><br/>"
            f"<font size='9' color='#4a5568'>{meta.get('scan_date', '')} · {meta.get('scan_time', '')}</font>",
            ParagraphStyle("rh", fontName="Helvetica", fontSize=11,
                           textColor=C_MUTED, alignment=TA_RIGHT)
        )
    ]]
    header_table = Table(header_data, colWidths=[W * 0.6, W * 0.4])
    header_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "BOTTOM"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(header_table)
    story.append(_divider(C_ACCENT))
    story.append(Spacer(1, 6))

    # ── Target & score row ────────────────────────────────────────────────────
    score      = report.get("risk_score", 0)
    risk_label = report.get("risk_label", "LOW")
    risk_col   = RISK_COLORS.get(risk_label, C_LOW)

    score_section = [[
        _score_gauge(score, risk_label),
        Table([
            [Paragraph("TARGET", S["label"])],
            [Paragraph(meta.get("target", ""), S["h2"])],
            [Paragraph(f"Open ports: <b>{meta.get('total_ports', 0)}</b>", S["body_muted"])],
            [Paragraph(report.get("risk_explanation", ""), S["body_muted"])],
        ], colWidths=[W * 0.75])
    ]]
    score_table = Table(score_section, colWidths=[100, W - 100])
    score_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (1, 0), (1, 0), 16),
    ]))
    story.append(score_section[0][0])  # gauge
    story.append(Spacer(1, -90))        # overlay trick — use a two-col table instead
    story = story[:-2]  # undo the overlay hack

    meta_score_data = [[_score_gauge(score, risk_label),
                        [Paragraph("SCAN TARGET", S["label"]),
                         Paragraph(f"<b>{meta.get('target', '')}</b>",
                                   ParagraphStyle("tgt", fontName="Helvetica-Bold",
                                                  fontSize=14, textColor=C_WHITE, spaceAfter=4)),
                         Paragraph(f"Open ports detected: <b>{meta.get('total_ports', 0)}</b>",
                                   S["body_muted"]),
                         Paragraph(report.get("risk_explanation", ""), S["body_muted"])]]]
    ms_table = Table(meta_score_data, colWidths=[100, W - 108])
    ms_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (1, 0), (1, 0), 14),
        ("TOPPADDING",  (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("BACKGROUND",  (0, 0), (-1, -1), C_PANEL),
        ("ROUNDEDCORNERS", [8]),
        ("BOX", (0, 0), (-1, -1), 1, C_BORDER),
    ]))
    story.append(ms_table)
    story.append(Spacer(1, 14))

    # ── Executive Summary ─────────────────────────────────────────────────────
    story.append(Paragraph("EXECUTIVE SUMMARY", S["h2"]))
    story.append(_divider())
    story.append(Paragraph(report.get("executive_summary", ""), S["body"]))
    story.append(Spacer(1, 8))

    # Positive findings
    pos = report.get("positive_findings", "")
    if pos:
        pos_data = [[Paragraph("✓ " + pos,
                               ParagraphStyle("pos", fontName="Helvetica",
                                              fontSize=10, textColor=C_LOW, leading=14))]]
        pos_table = Table(pos_data, colWidths=[W])
        pos_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#052e16")),
            ("BOX",           (0, 0), (-1, -1), 1, C_LOW),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
            ("TOPPADDING",    (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("ROUNDEDCORNERS", [6]),
        ]))
        story.append(pos_table)
        story.append(Spacer(1, 10))

    # ── Top Recommendations ───────────────────────────────────────────────────
    recs = report.get("top_recommendations", [])
    if recs:
        story.append(Paragraph("TOP RECOMMENDATIONS", S["h2"]))
        story.append(_divider())
        for i, rec in enumerate(recs[:5], 1):
            rec_data = [[
                Paragraph(f"<b>{i}</b>",
                          ParagraphStyle("rn", fontName="Helvetica-Bold",
                                         fontSize=13, textColor=C_ACCENT, alignment=TA_CENTER)),
                Paragraph(rec, S["body"])
            ]]
            rec_table = Table(rec_data, colWidths=[28, W - 36])
            rec_table.setStyle(TableStyle([
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING",   (1, 0), (1, 0), 10),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(rec_table)
        story.append(Spacer(1, 10))

    # ── Findings ──────────────────────────────────────────────────────────────
    findings = report.get("findings", [])
    if findings:
        story.append(Paragraph("DETAILED FINDINGS", S["h2"]))
        story.append(_divider())

        for i, f in enumerate(findings):
            sev   = f.get("severity", "INFO")
            col   = SEVERITY_COLORS.get(sev, C_INFO)
            title = f.get("title", f"Port {f.get('port', '?')} Finding")

            # Finding header
            header_data = [[
                Paragraph(f"<b>{title}</b>",
                          ParagraphStyle("fh", fontName="Helvetica-Bold",
                                         fontSize=11, textColor=C_WHITE)),
                Paragraph(f"Port {f.get('port', '?')} · {f.get('service', '')}",
                          ParagraphStyle("fp", fontName="Helvetica",
                                         fontSize=9, textColor=C_MUTED, alignment=TA_RIGHT)),
                _risk_badge(sev, 72),
            ]]
            h_table = Table(header_data, colWidths=[W * 0.5, W * 0.3, 80])
            h_table.setStyle(TableStyle([
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
                ("BACKGROUND",    (0, 0), (-1, -1), C_PANEL),
                ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
                ("TOPPADDING",    (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LINEBELOW",     (0, 0), (-1, 0), 2, col),
            ]))

            # Finding body
            rows = []
            for label, key, color in [
                ("WHAT IT IS",    "what_it_is",    C_WHITE),
                ("BUSINESS RISK", "business_risk", colors.HexColor("#fcd34d")),
                ("HOW TO FIX",    "how_to_fix",    C_LOW),
            ]:
                val = f.get(key, "")
                if val:
                    rows.append([
                        Paragraph(label, S["label"]),
                        Paragraph(val, ParagraphStyle(f"fv_{key}", fontName="Helvetica",
                                                       fontSize=10, textColor=color, leading=14))
                    ])

            urgency = f.get("urgency", "")
            if urgency:
                rows.append([
                    Paragraph("URGENCY", S["label"]),
                    Paragraph(f"<b>{urgency}</b>",
                              ParagraphStyle("urg", fontName="Helvetica-Bold",
                                             fontSize=10, textColor=col))
                ])

            body_table = Table(rows, colWidths=[90, W - 100])
            body_table.setStyle(TableStyle([
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND",    (0, 0), (-1, -1), C_ROW_ALT),
                ("LEFTPADDING",   (0, 0), (0, -1), 10),
                ("RIGHTPADDING",  (1, 0), (1, -1), 10),
                ("TOPPADDING",    (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LINEBELOW",     (0, 0), (-1, -2), 0.5, C_BORDER),
            ]))

            story.append(KeepTogether([h_table, body_table]))
            story.append(Spacer(1, 10))

    # ── Port Summary Table ────────────────────────────────────────────────────
    all_ports = [f for f in findings]
    if all_ports:
        story.append(Paragraph("PORT REFERENCE TABLE", S["h2"]))
        story.append(_divider())

        tbl_data = [[
            Paragraph("PORT", S["label"]),
            Paragraph("SERVICE", S["label"]),
            Paragraph("RISK", S["label"]),
            Paragraph("DESCRIPTION", S["label"]),
        ]]
        row_styles = [
            ("BACKGROUND",   (0, 0), (-1, 0), C_PANEL),
            ("TEXTCOLOR",    (0, 0), (-1, 0), C_MUTED),
            ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",     (0, 0), (-1, -1), 9),
            ("TOPPADDING",   (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_PANEL, C_ROW_ALT]),
            ("GRID",         (0, 0), (-1, -1), 0.5, C_BORDER),
        ]
        for i, f in enumerate(all_ports):
            sev = f.get("severity", "INFO")
            col = SEVERITY_COLORS.get(sev, C_INFO)
            tbl_data.append([
                Paragraph(f.get("port", "?"),
                          ParagraphStyle("tp", fontName="Helvetica-Bold",
                                         fontSize=9, textColor=C_WHITE)),
                Paragraph(f.get("service", ""),
                          ParagraphStyle("ts", fontName="Helvetica",
                                         fontSize=9, textColor=C_WHITE)),
                Paragraph(sev, ParagraphStyle("tr", fontName="Helvetica-Bold",
                                               fontSize=9, textColor=col)),
                Paragraph(f.get("what_it_is", "")[:100],
                          ParagraphStyle("td", fontName="Helvetica",
                                         fontSize=9, textColor=C_MUTED, leading=12)),
            ])

        port_table = Table(tbl_data, colWidths=[50, 80, 60, W - 198])
        port_table.setStyle(TableStyle(row_styles))
        story.append(port_table)
        story.append(Spacer(1, 12))

    # ── Next Steps ────────────────────────────────────────────────────────────
    next_steps = report.get("next_steps", "")
    if next_steps:
        story.append(Paragraph("NEXT STEPS", S["h2"]))
        story.append(_divider())
        ns_data = [[Paragraph("→ " + next_steps,
                               ParagraphStyle("ns", fontName="Helvetica",
                                              fontSize=10, textColor=C_WHITE, leading=15))]]
        ns_table = Table(ns_data, colWidths=[W])
        ns_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#1e1150")),
            ("BOX",           (0, 0), (-1, -1), 1, C_ACCENT),
            ("LEFTPADDING",   (0, 0), (-1, -1), 14),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 14),
            ("TOPPADDING",    (0, 0), (-1, -1), 12),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ]))
        story.append(ns_table)
        story.append(Spacer(1, 12))

    # ── Disclaimer ────────────────────────────────────────────────────────────
    story.append(_divider())
    story.append(Paragraph(
        report.get("disclaimer",
                   "This report is for informational purposes only. "
                   "Consult a qualified cybersecurity professional for a complete assessment."),
        S["small"]))

    # ── Page background + footer ──────────────────────────────────────────────
    def _page(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(C_BG)
        canvas.rect(0, 0, letter[0], letter[1], fill=1, stroke=0)
        # Footer
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(C_MUTED)
        canvas.drawString(0.65 * inch, 0.4 * inch,
                          f"Generated {meta.get('scan_date', '')} · Powered by AI Security Scanner")
        canvas.drawRightString(letter[0] - 0.65 * inch, 0.4 * inch,
                               f"Page {doc.page} · CONFIDENTIAL")
        canvas.restoreState()

    doc.build(story, onFirstPage=_page, onLaterPages=_page)
    return buf.getvalue()
