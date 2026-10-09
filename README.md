# 🛡️ [AI-SOC-Alert-Triage](https://github.com/CdxDebian/AI-SOC-Alert-Triage)

**AI-assisted triage for security alerts — advisory only, human decides.**

Every alert this system processes gets a structured, LLM-generated assessment *and* a deterministic rule-based cross-check. Neither one takes action. Both exist to give a human analyst a faster, more consistent starting point.

---

## 🚨 The Problem

SOC analysts don't have a detection problem — they have a **triage** problem. Hundreds of alerts a day, most of them noise, but every single one still needs eyes on it before it can be dismissed. That's what drives up Mean Time to Respond (MTTR) and burns analysts out: not the volume of threats, but the volume of *reading*.

## 🧩 The Approach

```
alerts.json → triage.py ──┬── Ollama (llama3.2:3b) → structured JSON assessment ──┐
                          │                                                      ├── mitre.py: validate ATT&CK
                          └── rules.py → deterministic score + technique hints ──┘   against the official catalog
                                                   │
                                                   ▼
                              Combined result → terminal / Streamlit dashboard
                                                   │
                                                   ▼
                                       🔒 HUMAN_REVIEW_REQUIRED
```

Each alert goes through three independent checks:

1. **LLM assessment** (Ollama, local, `llama3.2:3b`) — severity score, MITRE ATT&CK mapping, plain-English summary, recommended next action, and its own confidence/reasoning
2. **Rule-based score** (`rules.py`) — deterministic pattern scoring (failed and successful logons, encoded PowerShell, suspicious executables, port scans, ransomware), independent of the LLM. Every score lists the rules that fired and the ATT&CK technique each one indicates.
3. **ATT&CK validation** (`mitre.py`) — every technique the model names is checked against the official MITRE ATT&CK catalog (v19.2, 697 techniques, from [`mitre-attack/attack-stix-data`](https://github.com/mitre-attack/attack-stix-data)). Wrong names, invented IDs and malformed IDs are flagged, and the model's mapping is compared with the rule engine's.

Running independent signals matters: it means a prompt-injection attempt, a model hallucination, or an off day for the LLM doesn't silently become the *only* signal an analyst sees.

## 🔒 Why AI Is Advisory-Only

This is the design decision the whole project is built around, not a footnote:

- Every single alert — regardless of score — is tagged `"final_decision": "HUMAN_REVIEW_REQUIRED"`
- The system never auto-blocks, quarantines, or remediates anything
- The LLM's job is to compress analyst *read time*, not replace analyst *judgment*

In security tooling specifically, trust gets built by keeping a human in the loop — not by proving the model is right often enough to remove them.

## 📋 Sample Output

Output from `triage.py` on `ALERT-003` (a Base64-encoded PowerShell command). The LLM fields are verbatim `llama3.2:3b` output; the rule and ATT&CK-validation fields are deterministic.

```json
{
  "severity_score": 60,
  "severity": "MEDIUM",
  "summary": "A suspicious PowerShell command with Base64 encoding was detected on the system. The command appears to be encoded, but the actual payload is unclear. Further investigation is required to determine the intent behind this command.",
  "recommended_next_action": "Analyze the raw log to determine the actual payload of the Base64 encoded command and investigate the system for any signs of malicious activity.",
  "confidence": "MEDIUM",
  "reasoning": "The detection of Base64 encoding on a PowerShell command is suspicious, but it does not necessarily indicate malicious activity. However, the lack of clear context makes it difficult to determine the intent behind the command. Further analysis is required to determine the confidence in this detection.",
  "rule_score": 7,
  "rule_severity": "high",
  "rule_findings": [
    "PowerShell execution",
    "encoded command"
  ],
  "llm_techniques": [
    {
      "technique_id": "T1003",
      "technique_name": "OS Credential Dumping",
      "model_label": "Use of Base64 Encoding",
      "status": "name_mismatch"
    }
  ],
  "rule_techniques": [
    {
      "technique_id": "T1059.001",
      "technique_name": "Command and Scripting Interpreter: PowerShell"
    },
    {
      "technique_id": "T1027.010",
      "technique_name": "Obfuscated Files or Information: Command Obfuscation"
    }
  ],
  "mitre_agreement": "disagree",
  "attack_version": "19.2",
  "final_decision": "HUMAN_REVIEW_REQUIRED"
}
```

**What this shows, and why the cross-checks exist.** The model's summary is reasonable, but its ATT&CK mapping is wrong: it labelled `T1003` as "Use of Base64 Encoding", and T1003 is actually *OS Credential Dumping*. Across all five sample alerts the 3B model named a real technique ID with the wrong meaning **5 out of 5 times**, and it scored every alert 60/MEDIUM. The validator catches all five (`name_mismatch`), and the rule engine supplies the right techniques (here T1059.001 PowerShell and T1027.010 Command Obfuscation). An analyst sees the disagreement instead of a confident-looking wrong answer. Full run: [`results.txt`](results.txt).

On `ALERT-004` (a suspicious executable), the rule engine scored it **7/high** while the LLM scored it **60/MEDIUM**. That's a genuine disagreement between the two signals, and it's the point: a single-signal system would have picked one answer and moved on. This one surfaces the disagreement to the analyst instead of hiding it. 👀

## ⚙️ Tech Stack

| Layer | Choice |
|---|---|
| LLM inference | Ollama, running `llama3.2:3b` locally — no data leaves the machine |
| Rule engine | Pure Python, pattern-based scoring with ATT&CK hints (`rules.py`) |
| ATT&CK validation | Official MITRE ATT&CK catalog, v19.2 (`mitre.py`, `data/attack_techniques.json`) |
| Tests | pytest, run in GitHub Actions; no model needed |
| Dashboard | Streamlit |
| Data | Synthetic alert set (`alerts.json`), JSON schema output |

## 📁 Project Structure

```
AI-SOC-Alert-Triage/
├── triage.py                  # Pipeline: Ollama assessment + rule engine + ATT&CK validation
├── rules.py                   # Deterministic rule scoring with ATT&CK technique hints
├── mitre.py                   # Validates the model's ATT&CK mapping against the official catalog
├── app.py                     # Streamlit dashboard
├── alerts.json                # Synthetic dataset: 5 alerts, one per alert type
├── data/attack_techniques.json  # MITRE ATT&CK Enterprise v19.2 technique IDs and names
├── results.txt                # Sample run output
├── tests/                     # Rule engine and ATT&CK validation tests
└── Screenshots/               # Terminal and dashboard screenshots
```

## 🚀 Getting Started

```bash
# Clone the repo
git clone https://github.com/CdxDebian/AI-SOC-Alert-Triage.git
cd AI-SOC-Alert-Triage

# Set up a virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Pull the local model triage.py is configured for
ollama pull llama3.2:3b

# Run triage on the sample alert set
python triage.py

# Launch the dashboard
streamlit run app.py

# Run the tests (rule engine + ATT&CK validation; no model needed)
pip install -r requirements-dev.txt && pytest
```

## 🔍 Known Limitations (and why they're listed, not hidden)

Being upfront about where this stands as a prototype:

- **`final_decision` is currently static** — every alert is flagged for human review regardless of score. A natural next step is confidence/severity-based routing (e.g. auto-close only near-zero-risk alerts, always requiring review above a threshold) — but that's a deliberate future step, not a shortcut taken now.
- **The local model's ATT&CK mappings aren't reliable on their own.** In the sample run, `llama3.2:3b` paired a real technique ID with the wrong meaning on all five alerts. That's why mappings are validated against the official ATT&CK catalog and compared with the rule engine before an analyst sees them.
- **The model's severity isn't calibrated.** It returned 60/MEDIUM for every sample alert. The rule score is the more discriminating signal today; a scoring rubric in the prompt and a larger evaluation set are on the roadmap.
- **Dataset is synthetic and small** (5 alerts, one per type) — built to demonstrate the pipeline, not benchmark accuracy at scale.
- **Rule engine is intentionally simple** — pattern matching on single alerts, not correlation across time windows or entities. It's a cross-check, not a replacement for a real detection engine.

## 🗺️ Roadmap

- [x] Validate the model's ATT&CK mapping against the official MITRE ATT&CK catalog
- [ ] Confidence/severity-based review routing instead of static `HUMAN_REVIEW_REQUIRED`
- [ ] Expand the synthetic dataset and add adversarial/edge-case alerts
- [ ] Pluggable LLM backends (Claude / OpenAI as alternatives to local Ollama)
- [ ] Schema validation of the model's JSON output (pydantic), with retry on malformed responses
- [ ] Severity rubric in the prompt, measured against a labelled evaluation set
- [x] Test suite for the rule engine and ATT&CK validation, run in CI

## 👤 Why This Project

Built as a hands-on demonstration of applying LLMs inside a real SOC workflow — specifically, how to get genuine value from a model without quietly letting it become the decision-maker. A day-by-day build log is on [LinkedIn](https://www.linkedin.com/in/shriv-rahul/).

---

**AI-generated assessments in this project are advisory only. This tool does not take autonomous action on any alert.**
