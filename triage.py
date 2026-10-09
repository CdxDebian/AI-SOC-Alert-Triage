import json
import os

from mitre import validate_mapping
from rules import calculate_rule_score, expected_techniques, rule_findings, severity_from_score

MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")


SYSTEM_PROMPT = """
You are an AI assistant supporting a Security Operations Center analyst.

Analyze security alerts and provide an advisory assessment.

Return valid JSON only.

The JSON must contain these fields:

{
  "severity_score": integer from 0 to 100,
  "severity": "LOW | MEDIUM | HIGH | CRITICAL",
  "mitre_attack": [
    {
      "technique_id": "MITRE technique ID",
      "technique_name": "MITRE technique name"
    }
  ],
  "summary": "Plain-English explanation of what happened",
  "recommended_next_action": "Recommended investigation step",
  "confidence": "LOW | MEDIUM | HIGH",
  "reasoning": "Short explanation supporting the assessment"
}

Rules:

- Do not invent evidence.
- If information is insufficient, say so.
- Treat IP addresses as indicators, not proof of malicious activity.
- Clearly distinguish observed facts from assumptions.
- The output is advisory only.
- Do not perform automatic destructive remediation.
"""


def analyze_alert(alert):

    user_prompt = f"""
Analyze this SOC alert.

Alert ID:
{alert["id"]}

Alert Type:
{alert["type"]}

Source IP:
{alert["source_ip"]}

Timestamp:
{alert["timestamp"]}

Raw Log:
{alert["raw_log_line"]}
"""

    from ollama import chat  # imported here so the deterministic checks run (and test) without Ollama

    response = chat(
        model=MODEL,
        messages=[
            {
                "role": "system",
                "content": SYSTEM_PROMPT
            },
            {
                "role": "user",
                "content": user_prompt
            }
        ],
        format="json",
        options={
            "temperature": 0
        }
    )

    result = response.message.content

    return json.loads(result)


def triage(alert):
    """Full advisory assessment: LLM + independent rule engine + validated ATT&CK mapping."""
    result = analyze_alert(alert)
    return combine(alert, result)


def combine(alert, llm_result):
    """Attach the deterministic checks to an LLM result. Pure function, so it is testable without a model."""
    result = dict(llm_result)
    rule_score = calculate_rule_score(alert)
    result["rule_score"] = rule_score
    result["rule_severity"] = severity_from_score(rule_score)
    result["rule_findings"] = [f["label"] for f in rule_findings(alert)]
    result.update(validate_mapping(result.pop("mitre_attack", []), expected_techniques(alert)))

    # AI is advisory only. Every alert goes to a human, whatever the scores say.
    result["final_decision"] = "HUMAN_REVIEW_REQUIRED"
    return result


if __name__ == "__main__":

    with open("alerts.json", "r") as file:
        alerts = json.load(file)

    for alert in alerts:

        print("\n" + "=" * 60)
        print(alert["id"])
        print("=" * 60)

        print(json.dumps(triage(alert), indent=2))
