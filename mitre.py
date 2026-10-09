"""Validate the LLM's MITRE ATT&CK mapping against the official ATT&CK catalog.

A 3B local model will sometimes return a real technique ID with the wrong name
(e.g. "T1003 — Use of Base64 Encoding"; T1003 is OS Credential Dumping) or glue a
description onto the ID. Nothing the model says about ATT&CK is shown as fact until
it has been checked here:

  * the ID is normalised and looked up in data/attack_techniques.json
    (built from mitre-attack/attack-stix-data, enterprise-attack)
  * the canonical name replaces the model's label; a label that doesn't match is flagged
  * the mapping is compared with the rule engine's technique hints
"""
import json
import re
from pathlib import Path

_CATALOG_PATH = Path(__file__).with_name("data") / "attack_techniques.json"
_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_STOP = {"of", "the", "and", "or", "a", "an", "use", "using", "via", "for", "to", "in", "on"}


def _load():
    data = json.loads(_CATALOG_PATH.read_text(encoding="utf-8"))
    return data["techniques"], data.get("version", "?")


CATALOG, ATTACK_VERSION = _load()


def _words(text):
    return {w for w in re.findall(r"[a-z0-9]+", (text or "").lower()) if w not in _STOP}


def _names_agree(model_label, canonical):
    """Loose match: the model's label shares at least half its meaningful words with the real name."""
    model = _words(model_label)
    if not model:
        return True  # no label given: nothing to contradict
    return len(model & _words(canonical)) / len(model) >= 0.5


def validate_technique(entry):
    raw_id = str(entry.get("technique_id", ""))
    label = str(entry.get("technique_name", ""))
    match = _ID.search(raw_id.upper())
    if not match:
        return {"technique_id": raw_id, "technique_name": None, "model_label": label, "status": "malformed"}
    tid = match.group(0)
    # description glued onto the ID ("T1003: Use of Fileless Malware") counts as the label
    trailing = raw_id[match.end():].strip(" :-—")
    label = label or trailing
    canonical = CATALOG.get(tid)
    if canonical is None:
        return {"technique_id": tid, "technique_name": None, "model_label": label, "status": "unknown_id"}
    status = "valid" if _names_agree(label, canonical) else "name_mismatch"
    return {"technique_id": tid, "technique_name": canonical, "model_label": label, "status": status}


def validate_mapping(llm_mapping, rule_hint_ids):
    """Return validated techniques, the rule engine's hints, and whether the two agree."""
    validated = [validate_technique(e) for e in (llm_mapping or []) if isinstance(e, dict)]
    hints = [{"technique_id": t, "technique_name": CATALOG.get(t)} for t in rule_hint_ids]
    trusted = {v["technique_id"].split(".")[0] for v in validated if v["status"] == "valid"}
    hinted = {t.split(".")[0] for t in rule_hint_ids}
    if not hinted:
        agreement = "no_rule_hint"
    elif trusted & hinted:
        agreement = "agree"
    else:
        agreement = "disagree"
    return {"llm_techniques": validated, "rule_techniques": hints, "mitre_agreement": agreement,
            "attack_version": ATTACK_VERSION}
