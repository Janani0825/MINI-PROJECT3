"""Builds the downloadable PDF report of one scan (reportlab)."""
import io
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

COL = {"Safe": colors.HexColor("#059669"), "Suspicious": colors.HexColor("#d97706"), "Fake": colors.HexColor("#dc2626")}
INK, MUTED, LINE = colors.HexColor("#0f172a"), colors.HexColor("#64748b"), colors.HexColor("#e2e8f0")


def _p(text, style):
    return Paragraph(escape(str(text)), style)


def build(scan):
    """scan = the dict returned by scan_view(). Returns PDF bytes."""
    r, f = scan.get("result") or {}, scan.get("features") or {}
    ss = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9.5, leading=13, textColor=INK)
    small = ParagraphStyle("s", parent=body, fontSize=8, textColor=MUTED)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontSize=11, textColor=colors.HexColor("#0e7490"), spaceBefore=10, spaceAfter=4)
    title = ParagraphStyle("t", parent=ss["Title"], fontSize=20, alignment=0, textColor=INK, spaceAfter=0)
    cls = r.get("classification", "Safe")
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
                            title="PhishGuard report %s" % scan.get("scan_id", ""), author="PhishGuard")
    el = [_p("PhishGuard - Website safety report", title), _p("Scan %s  |  %s" % (scan.get("scan_id", ""), scan.get("scan_date", "")), small), Spacer(1, 6)]

    verdict = Table([[_p(cls.upper(), ParagraphStyle("v", parent=body, fontSize=16, textColor=colors.white, fontName="Helvetica-Bold")),
                      _p("Risk score %s%%" % r.get("risk_score", 0), ParagraphStyle("v2", parent=body, fontSize=13, textColor=colors.white))]],
                    colWidths=[60 * mm, 114 * mm])
    verdict.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), COL.get(cls, INK)), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                 ("TOPPADDING", (0, 0), (-1, -1), 9), ("BOTTOMPADDING", (0, 0), (-1, -1), 9), ("LEFTPADDING", (0, 0), (-1, -1), 10)]))
    el += [verdict, Spacer(1, 8), _p("Address checked: " + scan.get("submitted_url", ""), body),
           _p("Decided by: %s" % r.get("decided_by", "-"), small)]

    el.append(_p("Why this result", h2))
    for x in r.get("reasons") or [r.get("detection_reason", "")]:
        el.append(_p("- " + x, body))
    el.append(Spacer(1, 3)); el.append(_p("Recommendation: " + r.get("recommendation", ""), body))

    v = r.get("verified_site")
    if v:
        el.append(_p("Verified website", h2))
        el.append(_p("%s (%s). Used for: %s. Registered owner: %s." % (v.get("org_name"), v.get("category"), v.get("purpose"), v.get("owner_name")), body))

    if r.get("pipeline"):
        el.append(_p("Detection layers", h2))
        rows = [[_p("Layer", small), _p("Result", small), _p("Note", small)]] + [[_p(l["layer"], body), _p(l["status"], body), _p(l.get("note", ""), body)] for l in r["pipeline"]]
        t = Table(rows, colWidths=[38 * mm, 22 * mm, 114 * mm])
        t.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), .4, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        el.append(t)

    if r.get("signals"):
        el.append(_p("What pushed the score (ML model)", h2))
        for s in r["signals"]:
            el.append(_p("%s%s%%  %s" % ("+" if s["share"] > 0 else "", s["share"], s["label"]), body))

    sec = r.get("security")
    if sec:
        el.append(_p("Website security checks - grade %s (%s/%s)" % (sec["grade"], sec["passed"], sec["total"]), h2))
        rows = [[_p(i["label"], body), _p({"pass": "Present", "fail": "Missing", "na": "n/a"}[i["status"]], body), _p(i["tip"], small)] for i in sec["items"]]
        t = Table(rows, colWidths=[52 * mm, 20 * mm, 102 * mm])
        t.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), .4, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        el.append(t)

    el.append(_p("Extracted features", h2))
    rows = [["Domain", scan.get("domain", "")], ["Protocol", scan.get("protocol", "")], ["URL length", f.get("url_length", "")],
            ["Hyphens / dots", "%s / %s" % (f.get("num_hyphens", ""), f.get("num_dots", ""))],
            ["Suspicious keywords", "Yes" if f.get("has_suspicious_keywords") else "No"], ["IP address in URL", "Yes" if f.get("has_ip_address") else "No"],
            ["Closest legitimate domain", r.get("matched_legit_domain") or "-"], ["ML model probability", "%s%%" % r["ml_probability"] if r.get("ml_probability") is not None else "-"]]
    t = Table([[_p(a, small), _p(b, body)] for a, b in rows], colWidths=[50 * mm, 124 * mm])
    t.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), .4, LINE)]))
    el += [t, Spacer(1, 10), _p("This report is automated guidance generated by PhishGuard. Always confirm important links through the organisation's official channels.", small)]
    doc.build(el)
    return buf.getvalue()
