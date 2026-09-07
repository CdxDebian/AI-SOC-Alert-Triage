import json
import streamlit as st

from triage import analyze_alert
from rules import calculate_rule_score, severity_from_score

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
        calculate_rule_score(alert) >= 60
        for alert in alerts
    )
    st.metric("High Priority", high_alerts)

with col3:
    critical_alerts = sum(
        calculate_rule_score(alert) >= 80
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

                ai_result = analyze_alert(alert)

                rule_score = calculate_rule_score(alert)
                rule_severity = severity_from_score(rule_score)

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

            st.write("### MITRE ATT&CK")

            for technique in ai_result["mitre_attack"]:
                st.write(
                    f'{technique["technique_id"]} - '
                    f'{technique["technique_name"]}'
                )

            st.write("### Plain-English Summary")
            st.write(ai_result["summary"])

            st.write("### Recommended Next Action")
            st.info(
                ai_result["recommended_next_action"]
            )

            st.write("### Rule-Based Assessment")
            st.write(f"Rule Score: **{rule_score}/100**")
            st.write(f"Rule Severity: **{rule_severity}**")

            st.warning(
                "Human review required. The AI does not automatically "
                "block, quarantine, or remediate anything."
            )