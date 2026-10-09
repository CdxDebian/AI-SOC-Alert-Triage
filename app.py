import json

import streamlit as st

from rules import calculate_rule_score, severity_from_score
from triage import triage

st.set_page_config(
    page_title="AI SOC Alert Triage",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ AI-Powered SOC Alert Triage Assistant")

st.write(
    "AI-assisted security alert analysis for SOC analysts. "
    "AI recommendations are advisory only and require human validation."
)

with open("alerts.json", "r") as file:
    alerts = json.load(file)

st.subheader("SOC Overview")

col1, col2, col3 = st.columns(3)

with col1:
    st.metric("Total Alerts", len(alerts))

with col2:
    high_alerts = sum(
        severity_from_score(calculate_rule_score(alert)) in ("high", "critical")
        for alert in alerts
    )
    st.metric("High Priority", high_alerts)

with col3:
    critical_alerts = sum(
        severity_from_score(calculate_rule_score(alert)) == "critical"
        for alert in alerts
    )
    st.metric("Critical", critical_alerts)

st.divider()

st.subheader("Security Alerts")

for alert in alerts:

    with st.expander(
        f'{alert["id"]} | {alert["type"]}'
    ):

        st.write("### Alert Information")

        st.write(f'**Source IP:** {alert["source_ip"]}')
        st.write(f'**Timestamp:** {alert["timestamp"]}')

        st.code(alert["raw_log_line"])

        if st.button(
            "🤖 Analyze Alert",
            key=alert["id"]
        ):

            with st.spinner("AI analyzing alert..."):

                ai_result = triage(alert)

                rule_score = ai_result["rule_score"]
                rule_severity = ai_result["rule_severity"]

            st.write("### AI Assessment")

            st.metric(
                "AI Severity Score",
                ai_result["severity_score"]
            )

            st.write(
                f'**Severity:** {ai_result["severity"]}'
            )

            st.write(
                f'**Confidence:** {ai_result["confidence"]}'
            )

            st.write(f'### MITRE ATT&CK (validated against ATT&CK v{ai_result["attack_version"]})')

            for t in ai_result["llm_techniques"]:
                if t["status"] == "valid":
                    st.success(f'{t["technique_id"]} - {t["technique_name"]}')
                elif t["status"] == "name_mismatch":
                    st.warning(
                        f'{t["technique_id"]} is **{t["technique_name"]}**, '
                        f'but the model labelled it "{t["model_label"]}". Treat this mapping as unreliable.'
                    )
                else:
                    st.error(f'Model returned an invalid technique: {t["technique_id"]} ({t["status"]})')

            if ai_result["rule_techniques"]:
                st.write(
                    "Rule engine indicates: " + ", ".join(
                        f'{t["technique_id"]} {t["technique_name"]}' for t in ai_result["rule_techniques"]
                    ) + f'  ·  agreement: **{ai_result["mitre_agreement"]}**'
                )

            st.write("### Plain-English Summary")
            st.write(ai_result["summary"])

            st.write("### Recommended Next Action")
            st.info(
                ai_result["recommended_next_action"]
            )

            st.write("### Rule-Based Assessment")
            st.write(f"Rule Score: **{rule_score}/10**")
            st.write(f"Rule Severity: **{rule_severity}**")
            st.write("Rules fired: " + (", ".join(ai_result["rule_findings"]) or "none"))

            st.warning(
                "Human review required. The AI does not automatically "
                "block, quarantine, or remediate anything."
            )
