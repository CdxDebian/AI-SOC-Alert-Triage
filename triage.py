import json

from ollama import chat
from rules import calculate_rule_score, severity_from_score


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

    response = chat(
        model="llama3.2:3b",
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


if __name__ == "__main__":

    with open("alerts.json", "r") as file:
        alerts = json.load(file)
        #alerts = alerts[2:3] #TEMP- single alert for screenshot of terminal

    for alert in alerts:

        print("\n" + "=" * 60)
        print(alert["id"])
        print("=" * 60)

        rule_score = calculate_rule_score(alert)
        rule_severity = severity_from_score(rule_score)

        result = analyze_alert(alert)

        result["rule_score"] = rule_score
        result["rule_severity"] = rule_severity

        # AI is advisory only.
        # Final decision always requires human review.
        result["final_decision"] = "HUMAN_REVIEW_REQUIRED"

        print(json.dumps(result, indent=2))