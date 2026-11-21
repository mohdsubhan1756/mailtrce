from app.services.reporting import _render_email_html, build_pdf_report


def test_html_body_is_rendered_as_readable_text():
    html = (
        "<!DOCTYPE html><html><head><title>Hidden title</title>"
        "<style>.hidden { display: none; }</style></head>"
        "<body><p>Hello &amp; welcome</p><p>Second paragraph</p>"
        "<table><tr><td>From</td><td>Analyst</td></tr></table>"
        "<script>alert('not visible')</script></body></html>"
    )

    rendered = _render_email_html(html)

    assert rendered == "Hello & welcome\nSecond paragraph\nFrom | Analyst"
    assert "Hidden title" not in rendered
    assert "alert" not in rendered


def test_pdf_report_escapes_email_content_and_analysis_text():
    report = {
        "email": {
            "email_id": "EMAIL-TEST",
            "body": {
                "plain_text": "Click <a href=",
                "html": "<html><body>Terms & conditions</body></html>",
            },
        },
        "risk": {
            "verdict_reason": "Sender <receiver@example.com> & other signals",
            "explanations": [{
                "signal": "A < B",
                "source": "email & headers",
                "effect": "Risk increased",
            }],
        },
    }

    pdf = build_pdf_report(report)

    assert pdf.startswith(b"%PDF-")
