from email.message import EmailMessage

import pytest

pytest.importorskip("sklearn")

from scripts.train_email_baseline import _message_text, _read_dataset, _grouped_split


def _email_bytes(subject: str, body: str, message_id: str = "") -> bytes:
    message = EmailMessage()
    message["Subject"] = subject
    if message_id:
        message["Message-ID"] = message_id
    message.set_content(body)
    return message.as_bytes()


def test_email_text_uses_subject_body_and_message_id():
    text, message_id = _message_text(
        _email_bytes("Quarterly notes", "Please review the attached agenda.", "<one@example.org>")
    )

    assert "Quarterly notes" in text
    assert "review the attached agenda" in text
    assert message_id == "<one@example.org>"


def test_dataset_split_keeps_message_id_groups_together(tmp_path):
    nonspam = tmp_path / "nonspam"
    phishing = tmp_path / "phishing"
    nonspam.mkdir()
    phishing.mkdir()
    (nonspam / "one.eml").write_bytes(_email_bytes("One", "First text.", "<repeated@example.org>"))
    (nonspam / "two.eml").write_bytes(_email_bytes("Two", "Second text.", "<repeated@example.org>"))
    (phishing / "three.eml").write_bytes(_email_bytes("Three", "Phishing text.", "<other@example.org>"))

    _, _, groups, _ = _read_dataset(tmp_path)

    assert groups[0] == groups[1]


def test_cross_class_identical_text_is_rejected(tmp_path):
    nonspam = tmp_path / "nonspam"
    phishing = tmp_path / "phishing"
    nonspam.mkdir()
    phishing.mkdir()
    identical = _email_bytes("Same", "Same message.")
    (nonspam / "one.eml").write_bytes(identical)
    (phishing / "two.eml").write_bytes(identical)

    with pytest.raises(ValueError, match="Conflicting class labels"):
        _read_dataset(tmp_path)


def test_group_split_has_both_classes_and_no_group_leakage():
    labels = [0] * 20 + [1] * 10
    groups = [f"ham-{index}" for index in range(20)] + [f"phish-{index}" for index in range(10)]

    train_indices, test_indices = _grouped_split(labels, groups, 0.2, 42)

    assert set(labels[index] for index in train_indices) == {0, 1}
    assert set(labels[index] for index in test_indices) == {0, 1}
    assert not ({groups[index] for index in train_indices} & {groups[index] for index in test_indices})
