from app.api.routes import extended_analysis as route


def test_cached_threat_analysis_with_old_version_is_recomputed(monkeypatch):
    email_id = "EMAIL-CACHED-OLD-THREAT-ANALYSIS"
    saved_failure = {
        "email_id": email_id,
        "analysis_version": "1.6.0-heuristics",
    }
    fresh_result = {
        "email_id": email_id,
        "analysis_version": route.threat_analysis_version(),
        "analysis_method": "RULE_BASED_LANGUAGE_HEURISTICS",
    }
    stored = []

    monkeypatch.setattr(route, "get_stored", lambda collection, key: saved_failure)
    monkeypatch.setattr(route, "get_email", lambda key: {"email_id": key})
    monkeypatch.setattr(route, "analyze_threat", lambda email: fresh_result)
    monkeypatch.setattr(
        route,
        "store_result",
        lambda collection, result: stored.append(result) or result,
    )

    result = route.get_threat_analysis(email_id)

    assert result["analysis_method"] == "RULE_BASED_LANGUAGE_HEURISTICS"
    assert stored == [fresh_result]
