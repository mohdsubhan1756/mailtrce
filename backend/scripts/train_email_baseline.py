from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import FeatureUnion, Pipeline


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASET_DIR = ROOT / "backend" / "data" / "datasets" / "email_classifier"
DEFAULT_OUTPUT_DIR = ROOT / "backend" / "models" / "email-classifier-proxy"
LABELS = {"nonspam": 0, "phishing": 1}


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


def _html_to_text(value: str) -> str:
    parser = _HTMLTextParser()
    parser.feed(value)
    parser.close()
    return "\n".join(
        line.strip()
        for line in "".join(parser.parts).splitlines()
        if line.strip()
    )


def _message_text(raw: bytes) -> tuple[str, str | None]:
    message = BytesParser(policy=policy.default).parsebytes(raw)
    subject = str(message.get("Subject") or "").strip()
    plain_parts: list[str] = []
    html_parts: list[str] = []

    for part in message.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        content_type = part.get_content_type()
        if content_type not in {"text/plain", "text/html"}:
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeError):
            payload = part.get_payload(decode=True) or b""
            content = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        if isinstance(content, bytes):
            content = content.decode(part.get_content_charset() or "utf-8", errors="replace")
        if content_type == "text/plain":
            plain_parts.append(str(content))
        else:
            html_parts.append(_html_to_text(str(content)))

    body = "\n".join(plain_parts or html_parts)
    text = re.sub(r"\s+", " ", f"{subject}\n{body}").strip()
    if not text:
        raise ValueError("Email has no subject or readable text body.")
    message_id = str(message.get("Message-ID") or "").strip().lower() or None
    return text, message_id


def _read_dataset(dataset_dir: Path) -> tuple[list[str], list[int], list[str], dict[str, int]]:
    texts: list[str] = []
    labels: list[int] = []
    sample_group_keys: list[str] = []
    counts: dict[str, int] = {}
    seen_hashes: dict[str, tuple[int, str]] = {}
    group_parents: dict[str, str] = {}

    def find(key: str) -> str:
        group_parents.setdefault(key, key)
        if group_parents[key] != key:
            group_parents[key] = find(group_parents[key])
        return group_parents[key]

    def union(first: str, second: str) -> None:
        first_root = find(first)
        second_root = find(second)
        if first_root != second_root:
            group_parents[second_root] = first_root

    for class_name, label in LABELS.items():
        class_dir = dataset_dir / class_name
        files = sorted(class_dir.rglob("*.eml"))
        if not files:
            raise FileNotFoundError(f"No .eml files found in {class_dir}")
        counts[class_name] = 0
        for path in files:
            raw = path.read_bytes()
            text, message_id = _message_text(raw)
            normalized_hash = hashlib.sha256(text.casefold().encode("utf-8")).hexdigest()
            previous = seen_hashes.get(normalized_hash)
            if previous and previous[0] != label:
                raise ValueError(
                    f"Conflicting class labels for identical message text in "
                    f"{previous[1]} and {path}."
                )
            seen_hashes[normalized_hash] = (label, str(path))
            texts.append(text)
            labels.append(label)
            text_key = f"text:{normalized_hash}"
            find(text_key)
            sample_group_keys.append(text_key)
            if message_id:
                union(text_key, f"id:{message_id}")
            counts[class_name] += 1

    if len(set(labels)) != 2:
        raise ValueError("Both nonspam and phishing examples are required.")
    groups = [find(key) for key in sample_group_keys]
    return texts, labels, groups, counts


def _grouped_split(
    labels: list[int],
    groups: list[str],
    test_size: float,
    random_state: int,
) -> tuple[Any, Any]:
    splitter = GroupShuffleSplit(
        n_splits=50,
        test_size=test_size,
        random_state=random_state,
    )
    overall_phishing_rate = sum(labels) / len(labels)
    best: tuple[Any, Any] | None = None
    best_score = float("inf")

    for train_indices, test_indices in splitter.split(
        [0] * len(labels),
        labels,
        groups,
    ):
        test_labels = [labels[index] for index in test_indices]
        if len(set(test_labels)) != 2:
            continue
        score = abs(sum(test_labels) / len(test_labels) - overall_phishing_rate)
        if score < best_score:
            best = train_indices, test_indices
            best_score = score

    if best is None:
        raise ValueError("Could not create a grouped train/test split containing both classes.")
    return best


def _build_pipeline() -> Pipeline:
    features = FeatureUnion(
        [
            (
                "word",
                TfidfVectorizer(
                    analyzer="word",
                    ngram_range=(1, 2),
                    min_df=2,
                    max_features=80000,
                    sublinear_tf=True,
                ),
            ),
            (
                "char",
                TfidfVectorizer(
                    analyzer="char_wb",
                    ngram_range=(3, 5),
                    min_df=2,
                    max_features=80000,
                    sublinear_tf=True,
                ),
            ),
        ]
    )
    return Pipeline(
        [
            ("features", features),
            (
                "classifier",
                LogisticRegression(
                    class_weight="balanced",
                    max_iter=1000,
                    random_state=42,
                    solver="liblinear",
                ),
            ),
        ]
    )


def train(
    dataset_dir: Path = DEFAULT_DATASET_DIR,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    test_size: float = 0.2,
    random_state: int = 42,
) -> dict[str, Any]:
    texts, labels, groups, class_counts = _read_dataset(dataset_dir)
    train_indices, test_indices = _grouped_split(labels, groups, test_size, random_state)

    train_texts = [texts[index] for index in train_indices]
    train_labels = [labels[index] for index in train_indices]
    test_texts = [texts[index] for index in test_indices]
    test_labels = [labels[index] for index in test_indices]
    if set(train_labels) != set(LABELS.values()):
        raise ValueError("Training split must contain both classes.")

    pipeline = _build_pipeline()
    pipeline.fit(train_texts, train_labels)
    predictions = pipeline.predict(test_texts)
    report = classification_report(
        test_labels,
        predictions,
        labels=[LABELS["nonspam"], LABELS["phishing"]],
        target_names=["nonspam", "phishing"],
        output_dict=True,
        zero_division=0,
    )
    metrics = {
        "experiment": "phishing_vs_nonspam_proxy",
        "not_a_genuine_email_classifier": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_counts": class_counts,
        "total_samples": len(texts),
        "train_samples": len(train_indices),
        "test_samples": len(test_indices),
        "grouped_by_message_id_or_text_hash": True,
        "accuracy": accuracy_score(test_labels, predictions),
        "balanced_accuracy": balanced_accuracy_score(test_labels, predictions),
        "confusion_matrix_labels": ["nonspam", "phishing"],
        "confusion_matrix": confusion_matrix(
            test_labels,
            predictions,
            labels=[LABELS["nonspam"], LABELS["phishing"]],
        ).tolist(),
        "classification_report": report,
        "limitations": [
            "SpamAssassin ham is non-spam, not verified legitimate email.",
            "The two classes come from different and old corpora, so source artifacts may drive results.",
            "Held-out corpus metrics do not establish performance on current real-world email.",
            "This model is an offline experiment and is not wired into MailTrace decisions.",
        ],
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, output_dir / "model.joblib")
    (output_dir / "evaluation.json").write_text(
        json.dumps(metrics, indent=2),
        encoding="utf-8",
    )
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train an experimental phishing-vs-nonspam email baseline."
    )
    parser.add_argument("--dataset-dir", type=Path, default=DEFAULT_DATASET_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()
    if not 0.1 <= args.test_size <= 0.4:
        parser.error("--test-size must be between 0.1 and 0.4")
    metrics = train(args.dataset_dir, args.output_dir, args.test_size, args.random_state)
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
