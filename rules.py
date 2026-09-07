def calculate_rule_score(alert):

    score = 0

    alert_text = str(alert).lower()

    if "failed login" in alert_text or "authentication failure" in alert_text:

        score += 3

    if "brute force" in alert_text:

        score += 4

    if "malware" in alert_text:

        score += 7

    if "ransomware" in alert_text:

        score += 10

    if "root" in alert_text:

        score += 2

    return min(score, 10)

def severity_from_score(score):

    if score >= 8:

        return "critical"

    elif score >= 6:

        return "high"

    elif score >= 3:

        return "medium"

    else:

        return "low"