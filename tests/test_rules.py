import json
from pathlib import Path

import pytest

from rules import calculate_rule_score, expected_techniques, rule_findings, severity_from_score

ALERTS = {a["id"]: a for a in json.loads((Path(__file__).parents[1] / "alerts.json").read_text())}


@pytest.mark.parametrize("alert_id,score,severity,techniques", [
    ("ALERT-001", 7, "high", ["T1110"]),
    ("ALERT-002", 6, "high", ["T1078"]),
    ("ALERT-003", 7, "high", ["T1059.001", "T1027.010"]),
    ("ALERT-004", 7, "high", ["T1204.002"]),
    ("ALERT-005", 3, "medium", ["T1046"]),
])
def test_every_sample_alert_is_scored_and_mapped(alert_id, score, severity, techniques):
    alert = ALERTS[alert_id]
    assert calculate_rule_score(alert) == score
    assert severity_from_score(score) == severity
    assert expected_techniques(alert) == techniques


def test_score_is_capped_at_10():
    alert = {"type": "ransomware", "raw_log_line": "malware ransomware brute force root failed login"}
    assert calculate_rule_score(alert) == 10


def test_benign_text_scores_zero():
    assert calculate_rule_score({"type": "Info", "raw_log_line": "user opened the wiki"}) == 0
    assert rule_findings({"type": "Info", "raw_log_line": "rooted plant"}) == []


@pytest.mark.parametrize("score,expected", [(0, "low"), (3, "medium"), (6, "high"), (8, "critical"), (10, "critical")])
def test_severity_bands(score, expected):
    assert severity_from_score(score) == expected
