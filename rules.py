"""Deterministic rule engine — the independent cross-check on the LLM.

Each rule is a keyword pattern with a score and the ATT&CK technique it indicates.
`rule_findings` explains exactly which rules fired; the technique hints are used to
check the LLM's MITRE mapping (see mitre.py).
"""
import re

# (pattern, points, technique_id, label)
RULES = [
    (r"failed (login|password)|authentication failure", 3, "T1110", "failed authentication"),
    (r"brute force|multiple failed logins", 4, "T1110", "brute-force pattern"),
    (r"accepted password|successful login", 3, "T1078", "successful logon"),
    (r"after failures", 3, "T1078", "logon following failures (possible compromise)"),
    (r"powershell(\.exe)?\s+.*-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,}", 5, "T1059.001", "PowerShell execution"),
    (r"-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,}|frombase64string", 2, "T1027.010", "encoded command"),
    (r"malware|suspicious executable", 7, "T1204.002", "suspicious executable"),
    (r"ransomware", 10, "T1486", "ransomware indicator"),
    (r"port scan|connection attempts .*ports", 3, "T1046", "network service scanning"),
    (r"\broot\b", 2, None, "privileged account"),
]
_COMPILED = [(re.compile(p, re.IGNORECASE), pts, tid, label) for p, pts, tid, label in RULES]


def _alert_text(alert):
    return " ".join(str(alert.get(k, "")) for k in ("type", "raw_log_line"))


def rule_findings(alert):
    """Return the rules that fired: [{"label", "points", "technique_id"}]."""
    text = _alert_text(alert)
    return [{"label": label, "points": pts, "technique_id": tid}
            for rx, pts, tid, label in _COMPILED if rx.search(text)]


def calculate_rule_score(alert):
    """Rule score on a 0–10 scale."""
    return min(sum(f["points"] for f in rule_findings(alert)), 10)


def expected_techniques(alert):
    """ATT&CK technique IDs the rules associate with this alert (deduplicated, in order)."""
    seen = []
    for f in rule_findings(alert):
        if f["technique_id"] and f["technique_id"] not in seen:
            seen.append(f["technique_id"])
    return seen


def severity_from_score(score):
    if score >= 8:
        return "critical"
    elif score >= 6:
        return "high"
    elif score >= 3:
        return "medium"
    else:
        return "low"
