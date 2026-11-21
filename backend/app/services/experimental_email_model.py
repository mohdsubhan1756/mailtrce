from __future__ import annotations

import logging
from functools import lru_cache
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from app.core.config import BACKEND_DIR, settings


logger = logging.getLogger(__name__)
MODEL_VERSION = "tfidf-logistic-proxy-v1"


class _HTMLTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.ignored_depth:
            if tag in {"script", "style"}:
                self.ignored_depth += 1
        elif tag in {"script", "style"}:
            self.ignored_depth = 1
        elif tag in {"br", "p", "div", "li", "tr"}:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if self.ignored_depth:
            if tag in {"script", "style"}:
                self.ignored_depth -= 1
        elif tag in {"p", "div", "li", "tr"}:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self.ignored_depth:
            self.parts.append(data)


def _strip_html(value: str) -> str:
    parser = _HTMLTextParser()
    parser.feed(value)
    parser.close()
    return " ".join(" ".join(parser.parts).split())


def _email_text(email: dict[str, Any]) -> str:
    body = email.get("body") or {}
    if isinstance(body, dict):
        plain = str(body.get("plain_text") or body.get("plain") or body.get("text") or "")
        html = str(body.get("html") or "")
        content = plain or _strip_html(html)
    else:
        content = str(body)
    return "\n".join(
        part.strip()
        for part in (str(email.get("subject") or ""), content)
        if part and part.strip()
    )[:50000]


def _model_path() -> Path:
    configured = Path(settings.EXPERIMENTAL_EMAIL_MODEL_PATH)
    return configured if configured.is_absolute() else BACKEND_DIR / configured


@lru_cache(maxsize=1)
def _load_model() -> Any | None:
    path = _model_path()
    if not path.is_file():
        return None
    try:
        import joblib

        model = joblib.load(path)
        if not callable(getattr(model, "predict_proba", None)):
            raise TypeError("Experimental email model must provide predict_proba().")
        return model
    except Exception:
        logger.exception("Could not load experimental email classifier from %s", path)
        raise


def model_status() -> dict[str, Any]:
    path = _model_path()
    return {
        "available": path.is_file(),
        "model_version": MODEL_VERSION,
        "model_path": str(path),
        "experiment": "phishing_vs_nonspam_proxy",
        "used_for_verdict": False,
    }


def classify_experimental_email(email: dict[str, Any]) -> dict[str, Any]:
    text = _email_text(email)
    common = {
        "model_version": MODEL_VERSION,
        "experiment": "phishing_vs_nonspam_proxy",
        "used_for_verdict": False,
        "classes": {"0": "nonspam", "1": "phishing"},
    }
    if not text:
        return {
            "available": False,
            "reason": "No subject or readable message body was available.",
            **common,
        }

    model = _load_model()
    if model is None:
        return {
            "available": False,
            "reason": f"Experimental model file not found: {_model_path()}",
            **common,
        }

    probabilities = model.predict_proba([text])[0]
    classes = list(model.classes_)
    class_probabilities = {
        str(label): round(float(probability), 4)
        for label, probability in zip(classes, probabilities)
    }
    phishing_probability = class_probabilities.get("1")
    nonspam_probability = class_probabilities.get("0")
    if phishing_probability is None or nonspam_probability is None:
        raise ValueError(f"Unexpected experimental model classes: {classes}")

    label = "phishing" if phishing_probability >= nonspam_probability else "nonspam"
    return {
        "available": True,
        "label": label,
        "phishing_probability": phishing_probability,
        "nonspam_probability": nonspam_probability,
        "class_probabilities": class_probabilities,
        **common,
    }
