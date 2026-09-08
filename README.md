# 🛡️ [AI-SOC-Alert-Triage](https://github.com/CdxDebian/AI-SOC-Alert-Triage)

**AI-assisted triage for security alerts — advisory only, human decides.**

Every alert this system processes gets a structured, LLM-generated assessment *and* a deterministic rule-based cross-check. Neither one takes action. Both exist to give a human analyst a faster, more consistent starting point.

---

## 🚨 The Problem

SOC analysts don't have a detection problem — they have a **triage** problem. Hundreds of alerts a day, most of them noise, but every single one still needs eyes on it before it can be dismissed. That's what drives up Mean Time to Respond (MTTR) and burns analysts out: not the volume of threats, but the volume of *reading*.

## 🧩 The Approach

```
alerts.json → triage.py ──┬── Ollama (llama3.2:3b) → structured JSON assessment
                            └── rules.py → deterministic rule score
                                     │
                                     ▼
                     Combined result → terminal / Streamlit dashboard
                                     │
                                     ▼
                          🔒 HUMAN_REVIEW_REQUIRED
```

Each alert is scored two independent ways:

1. **LLM assessment** (Ollama, local, `llama3.2:3b`) — severity score, MITRE ATT&CK mapping, plain-English summary, recommended next action, and its own confidence/reasoning
2. **Rule-based score** (`rules.py`) — simple deterministic keyword scoring (failed login, brute force, malware, ransomware, root), independent of the LLM

Running both matters: it means a prompt-injection attempt, a model hallucination, or an off day for the LLM doesn't silently become the *only* signal an analyst sees.

## 🔒 Why AI Is Advisory-Only

This is the design decision the whole project is built around, not a footnote:

- Every single alert — regardless of score — is tagged `"final_decision": "HUMAN_REVIEW_REQUIRED"`
- The system never auto-blocks, quarantines, or remediates anything
- The LLM's job is to compress analyst *read time*, not replace analyst *judgment*

In security tooling specifically, trust gets built by keeping a human in the loop — not by proving the model is right often enough to remove them.

## 📋 Sample Output

Real output from `triage.py` on `ALERT-003` (a Base64-encoded PowerShell command):

```json
{
  "severity_score": 60,
  "severity": "MEDIUM",
  "mitre_attack": [
    {
      "technique_id": "T1003",
      "technique_name": "Use of Base64 Encoding"
    }
  ],
  "summary": "A suspicious PowerShell command with Base64 encoding was detected on the system. The command appears to be encoded, but the actual payload is unclear. Further investigation is required to determine the intent behind this command.",
  "recommended_next_action": "Analyze the raw log to determine the actual payload of the Base64 encoded command and investigate the system for any signs of malicious activity.",
  "confidence": "MEDIUM",
  "reasoning": "The detection of Base64 encoding on a PowerShell command is suspicious, but it does not necessarily indicate malicious activity. However, the lack of clear context makes it difficult to determine the intent behind the command.",
  "rule_score": 0,
  "rule_severity": "low",
  "final_decision": "HUMAN_REVIEW_REQUIRED"
}
```

Worth noting: on `ALERT-004` (a suspicious executable), the rule engine scored it **7/high** while the LLM scored it **60/MEDIUM** — a genuine disagreement between the two signals. That's not a bug, it's the point: a single-signal system would have picked one answer and moved on. This one surfaces the disagreement to the analyst instead of hiding it. 👀

## ⚙️ Tech Stack

| Layer | Choice |
|---|---|
| LLM inference | Ollama, running `llama3.2:3b` locally — no data leaves the machine |
| Rule engine | Pure Python, keyword-based scoring (`rules.py`) |
| Dashboard | Streamlit |
| Data | Synthetic alert set (`alerts.json`), JSON schema output |

## 📁 Project Structure

```
AI-SOC-Alert-Triage/
├── triage.py          # Core pipeline: loads alerts, calls Ollama + rules, prints structured output
├── rules.py            # Deterministic rule-based scoring (independent cross-check)
├── app.py               # Streamlit dashboard
├── alerts.json            # Synthetic alert dataset (5 alert types)
├── requirements.txt         # Python dependencies
├── results.txt             # Sample triage run output
└── Screenshots/            # Terminal + dashboard screenshots
```

## 🚀 Getting Started

```bash
# Clone the repo
git clone git@github.com:CdxDebian/AI-SOC-Alert-Triage.git
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
```

## 🔍 Known Limitations (and why they're listed, not hidden)

Being upfront about where this stands as a prototype:

- **`final_decision` is currently static** — every alert is flagged for human review regardless of score. A natural next step is confidence/severity-based routing (e.g. auto-close only near-zero-risk alerts, always requiring review above a threshold) — but that's a deliberate future step, not a shortcut taken now.
- **MITRE ID formatting isn't fully consistent** — a 3B local model occasionally returns a technique ID with a description appended (e.g. `"T1003: Use of Fileless Malware"` instead of a clean ID). A validation layer against the real MITRE ATT&CK dataset is on the roadmap.
- **Dataset is synthetic and small** (5 alerts) — built to demonstrate the pipeline, not benchmark accuracy at scale.
- **Rule engine is intentionally simple** — keyword matching, not correlation across time windows or entities. It's a cross-check, not a replacement for a real detection engine.

## 🗺️ Roadmap

- [ ] Validate `mitre_attack` output against the actual MITRE ATT&CK technique list
- [ ] Confidence/severity-based review routing instead of static `HUMAN_REVIEW_REQUIRED`
- [ ] Expand the synthetic dataset and add adversarial/edge-case alerts
- [ ] Pluggable LLM backends (Claude / OpenAI as alternatives to local Ollama)
- [ ] Structured output validation via `pydantic`/`jsonschema` (already in `requirements.txt`, not yet wired in)
- [ ] Basic test suite around `rules.py` and prompt-output parsing

## 👤 Why This Project

Built as a hands-on demonstration of applying LLMs inside a real SOC workflow — specifically, how to get genuine value from a model without quietly letting it become the decision-maker. A day-by-day build log is on [LinkedIn](https://www.linkedin.com/in/shriv-rahul/).

---

**AI-generated assessments in this project are advisory only. This tool does not take autonomous action on any alert.**
