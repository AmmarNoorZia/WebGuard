"""Reusable PDF export from a persisted scan snapshot; never run a scan here."""
import json
from html import escape
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_LEFT
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer


def build_report(scan):
    result = scan["result"]
    target = scan["target_snapshot"]
    stream = BytesIO()
    styles = getSampleStyleSheet()
    styles["Title"].textColor = colors.HexColor("#16734f")
    styles["Title"].alignment = TA_LEFT
    for name in ("BodyText", "Heading2"):
        styles[name].wordWrap = "CJK"
    styles["BodyText"].leading = 14
    story = [Paragraph("WebGuard Security Assessment", styles["Title"]), Spacer(1, 12)]

    def section(title, value):
        story.append(Paragraph(escape(title), styles["Heading2"]))
        text = str(value if value is not None else "Not applicable")
        for line in text.splitlines() or [""]:
            # Escape stored evidence: Paragraph otherwise interprets it as HTML.
            story.append(Paragraph(escape(line) or "&#160;", styles["BodyText"]))
        story.append(Spacer(1, 7))

    section("Assessment", f"Target: {target['name']}\nRegistered URL: {target['url']}\nTarget ID: {target['id']}\nScan ID: {scan['id']}\nScanner: {result['title']}\nStarted (UTC): {result['started_at']}\nFinished (UTC): {result['completed_at']}")
    section("Test result", f"Detection: {result['status'].replace('_', ' ')}\nSeverity: {result.get('severity') or 'Not applicable'}\nAffected endpoint: {result['affected_url']}\nHTTP status: {result.get('http_status') or 'No response'}")
    section("Tests performed", "\n".join(result['tests']) or "No test completed")
    section("Supporting evidence", json.dumps(result["evidence"], indent=2, ensure_ascii=True))
    if result.get("impact"):
        section("Impact", result["impact"])
    section("Recommended mitigation", result["remediation"])
    section("Scope and limitations", result["limitation"])

    def footer(canvas, document):
        canvas.setFont("Helvetica", 9)
        canvas.setFillColor(colors.HexColor("#52645b"))
        canvas.drawString(42, 25, "WebGuard | Authorized local laboratory assessment")
        canvas.drawRightString(document.pagesize[0] - 42, 25, f"Page {document.page}")

    SimpleDocTemplate(stream, title="WebGuard Security Assessment", author="WebGuard",
                      leftMargin=42, rightMargin=42, topMargin=38, bottomMargin=42).build(
                          story, onFirstPage=footer, onLaterPages=footer)
    stream.seek(0)
    return stream
