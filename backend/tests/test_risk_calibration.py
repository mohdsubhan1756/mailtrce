from app.services.extended_analysis import (
    _campaign_header_domains,
    _calibrated_language_score,
    _combined_risk_score,
    _risk_verdict,
    analyze_threat,
)


def make_finding(code):
    return {"code": code, "evidence": {}}


def test_external_destination_is_forensic_evidence_not_risk_points():
    score = _calibrated_language_score(
        [make_finding("EXTERNAL_DESTINATION")],
    )
    assert score == 0


def test_single_lifecycle_language_cue_does_not_flag_as_suspicious():
    score = _calibrated_language_score(
        [make_finding("CREDENTIAL_REQUEST")],
    )
    assert score < 40


def test_negated_urgency_is_not_reported_as_pressure_language():
    result = analyze_threat({
        "email_id": "EMAIL-NEGATED-URGENCY",
        "subject": "Project check-in notes",
        "body": {"plain_text": "There is no urgent action required."},
    })

    assert "URGENCY" not in {item["code"] for item in result["findings"]}
    assert result["score"] == 0


def test_positive_urgency_is_still_reported():
    result = analyze_threat({
        "email_id": "EMAIL-URGENT",
        "subject": "Urgent account review",
        "body": {"plain_text": "Verify your password immediately."},
    })

    assert "URGENCY" in {item["code"] for item in result["findings"]}


def test_experimental_classifier_is_not_used_for_threat_score(monkeypatch):
    monkeypatch.setattr(
        "app.services.extended_analysis.classify_experimental_email",
        lambda email: {
            "available": True,
            "label": "phishing",
            "phishing_probability": 0.99,
        },
    )

    result = analyze_threat({
        "email_id": "EMAIL-EXPERIMENTAL-SIGNAL",
        "subject": "Routine project update",
        "body": {"plain_text": "The weekly meeting is scheduled for Friday."},
    })

    assert result["analysis_method"] == "RULE_BASED_LANGUAGE_HEURISTICS"
    assert result["score"] == 0
    assert result["experimental_model"]["phishing_probability"] == 0.99
    assert "model" not in result


def test_authentication_failure_is_weak_supporting_signal_only():
    for result in ("NONE", "PARTIAL", "NOT_ANALYZED"):
        score, contribution = _combined_risk_score(
            threat_score=0,
            attachment_score=0,
            authentication_result=result,
            url_score=0,
            external_ip_score=0,
            malicious_url=False,
        )
        assert (score, contribution) == (0, 0)

    score, contribution = _combined_risk_score(
        threat_score=0,
        attachment_score=0,
        authentication_result="FAIL",
        url_score=0,
        external_ip_score=0,
        malicious_url=False,
    )
    assert (score, contribution) == (5, 5)


def test_single_high_score_source_does_not_produce_malicious_verdict():
    _, verdict, _ = _risk_verdict(
        score=90,
        threat_score=0,
        attachment_score=90,
        url_score=0,
        external_ip_score=0,
        malicious_url=False,
    )
    assert verdict == "SUSPICIOUS"


def test_high_score_with_independent_evidence_can_produce_high_verdict():
    _, verdict, _ = _risk_verdict(
        score=75,
        threat_score=35,
        attachment_score=45,
        url_score=0,
        external_ip_score=0,
        malicious_url=False,
    )
    assert verdict == "MALICIOUS_OR_HIGHLY_SUSPICIOUS"


def test_external_malicious_url_verdict_is_explicit_high_confidence_evidence():
    _, verdict, reason = _risk_verdict(
        score=90,
        threat_score=0,
        attachment_score=0,
        url_score=0,
        external_ip_score=0,
        malicious_url=True,
    )
    assert verdict == "MALICIOUS_OR_HIGHLY_SUSPICIOUS"
    assert "external URL" in reason


def test_campaign_extracts_domains_from_forensic_identity_headers():
    domains = _campaign_header_domains({
        "return_path": "Bounce <bounce@mailer.example>",
        "reply_to": "Support <help@reply.example>",
        "message_id": "<abc123@mx.example>",
    })
    assert domains["header_return_path_domain"] == {"mailer.example"}
    assert domains["header_reply_to_domain"] == {"reply.example"}
    assert domains["header_message_id_domain"] == {"mx.example"}
