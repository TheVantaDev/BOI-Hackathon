def classify(score: float) -> dict:
    if score < 30:
        return {
            "severity": "Safe",
            "classification": "Benign Application",
            "color": "#22c55e",
            "action": "No immediate action required.",
        }
    elif score < 55:
        return {
            "severity": "Low Risk",
            "classification": "Potentially Unwanted Application",
            "color": "#a3e635",
            "action": "Monitor for unusual behavior. Review requested permissions.",
        }
    elif score < 75:
        return {
            "severity": "Suspicious",
            "classification": "Suspicious Application",
            "color": "#f97316",
            "action": "Block distribution. Conduct deeper manual review.",
        }
    else:
        return {
            "severity": "Highly Malicious",
            "classification": "Confirmed Malware",
            "color": "#ef4444",
            "action": "Immediately block all associated IOCs. Alert affected customers.",
        }
