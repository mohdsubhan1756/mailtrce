from __future__ import annotations

from html import escape
from html.parser import HTMLParser
from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def _text(value: Any, default: str = "—") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        text = value.strip()
        return text or default
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, (list, tuple, set)):
        return ", ".join(_text(item, default) for item in value)
    if isinstance(value, dict):
        return ", ".join(f"{k}={_text(v, default)}" for k, v in value.items())
    return str(value)


def _paragraph_text(value: Any, default: str = "—") -> str:
    return escape(_text(value, default), quote=False)


class _EmailHTMLTextParser(HTMLParser):
    _BLOCK_TAGS = {
        "address", "article", "blockquote", "dd", "div", "dl", "dt",
        "fieldset", "figcaption", "figure", "footer", "form", "h1",
        "h2", "h3", "h4", "h5", "h6", "header", "hr", "li", "main",
        "ol", "p", "section", "table", "tr", "ul",
    }
    _IGNORED_TAGS = {"head", "script", "style", "noscript", "template"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._ignored_depth = 0
        self._table_cell_open = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self._ignored_depth:
            if tag in self._IGNORED_TAGS:
                self._ignored_depth += 1
            return
        if tag in self._IGNORED_TAGS:
            self._ignored_depth = 1
        elif tag == "br":
            self.parts.append("\n")
        elif tag in {"td", "th"}:
            if self._table_cell_open:
                self.parts.append(" | ")
            self._table_cell_open = True
        elif tag in self._BLOCK_TAGS:
            self.parts.append("\n")
            if tag == "li":
                self.parts.append("- ")

    def handle_endtag(self, tag: str) -> None:
        if self._ignored_depth:
            if tag in self._IGNORED_TAGS:
                self._ignored_depth -= 1
            return
        if tag == "tr":
            self._table_cell_open = False
        if tag in self._BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._ignored_depth:
            self.parts.append(data)


def _render_email_html(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return ""

    parser = _EmailHTMLTextParser()
    parser.feed(value)
    parser.close()

    lines = [" ".join(line.split()) for line in "".join(parser.parts).splitlines()]
    rendered = "\n".join(line for line in lines if line)
    return rendered.strip()


def _normalize_data(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if value is None:
        return []
    return [value]


def _flatten_findings(findings: Any) -> list[dict[str, Any]]:
    if isinstance(findings, list):
        return [item for item in findings if isinstance(item, dict)]
    return []


def _safe_table(rows: list[list[str]], col_widths: tuple[float, ...] | None = None) -> Table:
    if not rows:
        rows = [["No data", "-"]]
    table = Table(rows, colWidths=col_widths)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.8, colors.HexColor("#cbd5e1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def _section_header(label: str, styles: dict[str, ParagraphStyle]) -> Paragraph:
    return Paragraph(label, styles["heading"])


def _table_for_section(rows: list[list[str]], widths: tuple[float, ...], styles: dict[str, ParagraphStyle]) -> tuple[Table, Spacer]:
    table = _safe_table(rows, widths)
    spacer = Spacer(1, 6)
    return table, spacer


def build_pdf_report(report: dict[str, Any]) -> bytes:
    buffer = BytesIO()
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "MailTraceTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=10,
    )
    heading_style = ParagraphStyle(
        "MailTraceHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=14,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=10,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "MailTraceBody",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#1e293b"),
    )
    label_style = ParagraphStyle(
        "MailTraceLabel",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#475569"),
    )
    verdict_style = ParagraphStyle(
        "MailTraceVerdict",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=14,
        textColor=colors.HexColor("#0f172a"),
    )

    email = report.get("email") or {}
    risk = report.get("risk") or {}
    threat = report.get("threat") or {}
    attachments = report.get("attachments") or {}
    ips = report.get("ips") or {}
    url_domain = report.get("url_domain") or {}
    intelligence = report.get("intelligence") or {}
    campaign = report.get("campaign") or {}
    privacy = report.get("privacy") or {}
    authentication = report.get("authentication") or {}
    report_version = report.get("report_version", "1.1")
    report_generated = report.get("generated_at")

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
    )

    story: list[Any] = []

    cover_rows = [
        [
            Paragraph("MailTrace", title_style),
            Paragraph(f"<b>Forensic Email Report</b><br/>Version {report_version}", verdict_style),
        ],
        [
            Paragraph(f"<b>Case:</b> {_paragraph_text(email.get('case_id'))}", body_style),
            Paragraph(f"<b>Generated:</b> {_paragraph_text(report_generated)}", body_style),
        ],
        [
            Paragraph(f"<b>Email ID:</b> {_paragraph_text(email.get('email_id'))}", body_style),
            Paragraph(f"<b>Risk score:</b> {_paragraph_text(risk.get('score'))}/100", body_style),
        ],
    ]
    cover_table = Table(cover_rows, colWidths=(90 * mm, 70 * mm))
    cover_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("GRID", (0, 0), (-1, -1), 0.8, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(Paragraph("Investigation Brief", heading_style))
    story.append(cover_table)
    story.append(Spacer(1, 10))

    summary_table = _safe_table(
        [
            ["Subject", _text(email.get("subject"))],
            ["Sender", _text((email.get("sender") or {}).get("address"))],
            ["Sender domain", _text((email.get("sender") or {}).get("domain"))],
            ["Message ID", _text(email.get("message_id"))],
            ["Risk verdict", _text(risk.get("verdict"))],
            ["Risk level", _text(risk.get("risk_level"))],
            ["Evidence SHA256", _text(email.get("sha256"))],
            ["Threat score", _text(threat.get("score"))],
        ],
        col_widths=(52 * mm, 90 * mm),
    )
    story.append(_section_header("Executive summary", {"heading": heading_style}))
    story.append(summary_table)
    story.append(Spacer(1, 8))
    story.append(Paragraph(_paragraph_text(risk.get("verdict_reason")) or "No verdict narrative was generated.", body_style))

    story.append(PageBreak())

    story.append(_section_header("1. Threat intelligence overview", {"heading": heading_style}))
    threat_findings = _flatten_findings(threat.get("findings"))
    if threat_findings:
        threat_rows = [["Severity", "Finding", "Evidence"]]
        for item in threat_findings[:20]:
            severity = _text(item.get("severity"))
            title = _text(item.get("title"))
            evidence = item.get("evidence") or {}
            matches = evidence.get("matches")
            threat_rows.append([severity, title, _text(matches or item.get("description"))])
        story.append(_safe_table(threat_rows, col_widths=(18 * mm, 38 * mm, 90 * mm)))
    else:
        story.append(Paragraph("No threat-language findings were identified.", body_style))

    experimental_model = threat.get("experimental_model") or {}
    story.append(Spacer(1, 6))
    if experimental_model.get("available"):
        story.append(Paragraph(
            "<b>Experimental corpus phishing score (uncalibrated):</b> "
            f"{_paragraph_text(round(experimental_model.get('phishing_probability', 0) * 100, 1))}%",
            body_style,
        ))
        story.append(Paragraph(
            "This score is not a calibrated probability or verdict and is excluded from risk scoring.",
            body_style,
        ))
    story.append(Paragraph(f"<b>Signal level:</b> {_paragraph_text(threat.get('signal_level'))}", body_style))

    story.append(_section_header("2. Email and message analysis", {"heading": heading_style}))
    body_data = email.get("body") or {}
    plain_text = _text(body_data.get("plain_text") if isinstance(body_data, dict) else body_data)
    html_text = _render_email_html(body_data.get("html") if isinstance(body_data, dict) else "")
    story.append(Paragraph(f"<b>Recipients:</b> {_paragraph_text(email.get('recipients'))}", body_style))
    story.append(Paragraph(f"<b>Plain text body:</b> {_paragraph_text(plain_text)}", body_style))
    story.append(Paragraph(
        f"<b>HTML body (rendered text):</b> {_paragraph_text(html_text or 'No readable HTML content.')}".replace("\n", "<br/>"),
        body_style,
    ))

    story.append(_section_header("3. URL and domain intelligence", {"heading": heading_style}))
    url_rows = [["URL", "Hostname", "Risk"]]
    for item in _normalize_data(url_domain.get("urls") or url_domain.get("results") or []):
        if isinstance(item, dict):
            url_rows.append([
                _text(item.get("url")),
                _text(item.get("hostname")),
                _text((item.get("risk") or {}).get("risk_level") or item.get("risk_level")),
            ])
    story.append(_safe_table(url_rows[:15], col_widths=(72 * mm, 40 * mm, 20 * mm)))

    story.append(_section_header("4. IP / infrastructure intelligence", {"heading": heading_style}))
    ip_rows = [["IP", "Public", "Private", "Reputation", "Country"]]
    for item in _normalize_data(ips.get("ips") or []):
        if isinstance(item, dict):
            geolocation = item.get("geolocation") or {}
            provider = item.get("provider_intelligence") or {}
            ip_rows.append([
                _text(item.get("ip")),
                _text(item.get("public")),
                _text(item.get("private")),
                _text(item.get("reputation")),
                _text(geolocation.get("country") or provider.get("country")),
            ])
    story.append(_safe_table(ip_rows[:15], col_widths=(28 * mm, 18 * mm, 18 * mm, 24 * mm, 28 * mm)))

    story.append(_section_header("5. Attachment forensics", {"heading": heading_style}))
    attachment_findings = _flatten_findings(attachments.get("findings"))
    if attachment_findings:
        attachment_rows = [["Severity", "Title", "Description"]]
        for item in attachment_findings[:15]:
            attachment_rows.append([
                _text(item.get("severity")),
                _text(item.get("title")),
                _text(item.get("description")),
            ])
        story.append(_safe_table(attachment_rows, col_widths=(20 * mm, 38 * mm, 80 * mm)))
    else:
        story.append(Paragraph("No attachment concerns were identified.", body_style))

    story.append(Spacer(1, 6))
    attachment_table_rows = [["Filename", "Type", "SHA256", "Dangerous", "Double ext"]]
    for item in _normalize_data(attachments.get("attachments") or []):
        if isinstance(item, dict):
            attachment_table_rows.append([
                _text(item.get("filename")),
                _text(item.get("content_type")),
                _text(item.get("sha256")),
                _text(item.get("dangerous_extension")),
                _text(item.get("double_extension")),
            ])
    story.append(_safe_table(attachment_table_rows[:15], col_widths=(46 * mm, 30 * mm, 52 * mm, 18 * mm, 18 * mm)))

    story.append(_section_header("6. Campaign correlation and related emails", {"heading": heading_style}))
    related = campaign.get("related_emails") or []
    if related:
        related_rows = [["Email", "Subject", "Matched indicators"]]
        for item in related[:15]:
            related_rows.append([
                _text(item.get("email_id")),
                _text(item.get("subject")),
                _text(item.get("matched_indicators")),
            ])
        story.append(_safe_table(related_rows, col_widths=(32 * mm, 52 * mm, 54 * mm)))
        story.append(Paragraph(f"<b>Correlation confidence:</b> {_paragraph_text(campaign.get('correlation_confidence'))}", body_style))
    else:
        story.append(Paragraph("No related email campaigns were identified from shared indicators.", body_style))

    story.append(_section_header("7. Risk scoring details", {"heading": heading_style}))
    components = risk.get("components") or {}
    if components:
        risk_rows = [["Component", "Value"]]
        for key, value in components.items():
            risk_rows.append([_text(key), _text(value)])
        story.append(_safe_table(risk_rows, col_widths=(48 * mm, 78 * mm)))
    else:
        story.append(Paragraph("No component breakdown was available for this email.", body_style))

    explanations = _normalize_data(risk.get("explanations") or [])
    if explanations:
        for item in explanations:
            if isinstance(item, dict):
                story.append(
                    Paragraph(
                        f"<b>{_paragraph_text(item.get('signal'))}</b> · {_paragraph_text(item.get('source'))}<br/>{_paragraph_text(item.get('effect'))}",
                        body_style,
                    )
                )

    story.append(_section_header("8. Authentication and privacy context", {"heading": heading_style}))
    if authentication:
        auth_rows = [["Check", "Result"]]
        for key in ("overall_result", "spf", "dkim", "dmarc"):
            value = authentication.get(key)
            if isinstance(value, dict):
                value = value.get("result") or value
            auth_rows.append([_text(key), _text(value)])
        story.append(_safe_table(auth_rows, col_widths=(42 * mm, 96 * mm)))
    else:
        story.append(Paragraph("Authentication analysis was not available.", body_style))

    if privacy:
        retention = privacy.get("retention_policy") or {}
        story.append(Paragraph(f"<b>Privacy mode:</b> {_paragraph_text(privacy.get('privacy_mode'))}", body_style))
        story.append(Paragraph(f"<b>Retention policy:</b> {_paragraph_text(retention.get('description'))}", body_style))

    story.append(_section_header("9. External intelligence and evidence", {"heading": heading_style}))
    external_matches = intelligence.get("external_matches") or []
    if external_matches:
        ext_rows = [["Type", "Provider", "Details"]]
        for item in external_matches[:15]:
            ext_rows.append([
                _text(item.get("type")),
                _text(item.get("provider")),
                _text(item.get("results") or item.get("usage_type") or item.get("country_code") or item),
            ])
        story.append(_safe_table(ext_rows, col_widths=(20 * mm, 24 * mm, 104 * mm)))
    else:
        story.append(Paragraph("No external provider matches were returned for this message.", body_style))

    story.append(Paragraph(f"<b>Evidence verified:</b> {_paragraph_text(email.get('sha256'))}", body_style))
    story.append(Paragraph("MailTrace report is an analyst-facing forensic summary and should be reviewed with the original evidence and chain-of-custody records.", body_style))

    doc.build(story)
    return buffer.getvalue()
