import json
import re
from pathlib import Path

from mitre import ATTACK_VERSION, CATALOG, validate_mapping, validate_technique
from triage import combine

ROOT = Path(__file__).parents[1]


def test_catalog_is_the_real_attack_dataset():
    assert len(CATALOG) > 500 and ATTACK_VERSION
    assert CATALOG["T1003"] == "OS Credential Dumping"
    assert CATALOG["T1059.001"] == "Command and Scripting Interpreter: PowerShell"


def test_correct_mapping_is_valid():
    v = validate_technique({"technique_id": "T1110", "technique_name": "Brute Force"})
    assert v["status"] == "valid" and v["technique_name"] == "Brute Force"


def test_real_id_with_wrong_name_is_flagged():
    """The actual failure from the sample run: T1003 labelled as Base64 encoding."""
    v = validate_technique({"technique_id": "T1003", "technique_name": "Use of Base64 Encoding"})
    assert v["status"] == "name_mismatch" and v["technique_name"] == "OS Credential Dumping"


def test_description_glued_to_id_is_split_and_checked():
    v = validate_technique({"technique_id": "T1003: Use of Port Scanning", "technique_name": ""})
    assert v["technique_id"] == "T1003" and v["model_label"] == "Use of Port Scanning" and v["status"] == "name_mismatch"


def test_invented_and_malformed_ids():
    assert validate_technique({"technique_id": "T9999"})["status"] == "unknown_id"
    assert validate_technique({"technique_id": "lateral movement"})["status"] == "malformed"


def test_agreement_with_rule_engine():
    agree = validate_mapping([{"technique_id": "T1110.001", "technique_name": "Brute Force: Password Guessing"}], ["T1110"])
    disagree = validate_mapping([{"technique_id": "T1003", "technique_name": "Use of Base64 Encoding"}], ["T1059.001"])
    assert agree["mitre_agreement"] == "agree"
    assert disagree["mitre_agreement"] == "disagree"
    assert validate_mapping([], [])["mitre_agreement"] == "no_rule_hint"


def test_every_result_still_requires_human_review():
    alert = json.loads((ROOT / "alerts.json").read_text())[0]
    out = combine(alert, {"severity_score": 5, "severity": "LOW", "mitre_attack": []})
    assert out["final_decision"] == "HUMAN_REVIEW_REQUIRED"


def test_published_sample_output_matches_current_code():
    """results.txt must stay in sync with rules.py and mitre.py."""
    alerts = {a["id"]: a for a in json.loads((ROOT / "alerts.json").read_text())}
    text = (ROOT / "results.txt").read_text()
    blocks = re.findall(r"(ALERT-\d+)\n=+\n(\{.*?\n\})", text, re.S)
    assert len(blocks) == 5
    for alert_id, body in blocks:
        published = json.loads(body)
        llm = {k: published[k] for k in ("severity_score", "severity", "summary", "recommended_next_action", "confidence", "reasoning")}
        llm["mitre_attack"] = [{"technique_id": t["technique_id"], "technique_name": t["model_label"]}
                               for t in published["llm_techniques"]]
        recomputed = combine(alerts[alert_id], llm)
        for key in ("rule_score", "rule_severity", "rule_techniques", "mitre_agreement", "final_decision"):
            assert recomputed[key] == published[key], (alert_id, key)
