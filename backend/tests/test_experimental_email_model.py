from app.services import experimental_email_model


class _FakeClassifier:
    classes_ = [0, 1]

    def predict_proba(self, texts):
        assert len(texts) == 1
        assert "Quarterly planning" in texts[0]
        assert "Review the agenda." in texts[0]
        assert "hidden script" not in texts[0]
        return [[0.2, 0.8]]


def test_proxy_classifier_returns_experimental_signal_only(monkeypatch):
    monkeypatch.setattr(experimental_email_model, "_load_model", lambda: _FakeClassifier())

    result = experimental_email_model.classify_experimental_email({
        "subject": "Quarterly planning",
        "body": {
            "plain_text": "Review the agenda.",
            "html": "<p>Other text</p><script>hidden script</script>",
        },
    })

    assert result["available"] is True
    assert result["label"] == "phishing"
    assert result["phishing_probability"] == 0.8
    assert result["nonspam_probability"] == 0.2
    assert result["experiment"] == "phishing_vs_nonspam_proxy"
    assert result["used_for_verdict"] is False


def test_proxy_classifier_reports_missing_training_artifact(monkeypatch):
    monkeypatch.setattr(experimental_email_model, "_load_model", lambda: None)

    result = experimental_email_model.classify_experimental_email({
        "subject": "Status",
        "body": {"plain_text": "No model loaded."},
    })

    assert result["available"] is False
    assert result["used_for_verdict"] is False
    assert "model file not found" in result["reason"]
