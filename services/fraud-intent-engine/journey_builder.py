from typing import Any, Dict, List


NODE_TYPES = {
    "infection": {"color": "#f97316", "shape": "ellipse"},
    "persistence": {"color": "#eab308", "shape": "rectangle"},
    "collection": {"color": "#3b82f6", "shape": "ellipse"},
    "exfiltration": {"color": "#ef4444", "shape": "ellipse"},
    "impact": {"color": "#dc2626", "shape": "diamond"},
}

JOURNEY_TEMPLATES = {
    "account_takeover": [
        ("install", "App Installed", "infection"),
        ("perm_grant", "Permissions Granted", "persistence"),
        ("overlay", "Overlay Phishing", "collection"),
        ("cred_theft", "Credential Theft", "collection"),
        ("sms_intercept", "OTP Intercepted", "collection"),
        ("login", "Unauthorized Login", "impact"),
        ("txn", "Fraudulent Transaction", "impact"),
    ],
    "otp_interception": [
        ("install", "App Installed", "infection"),
        ("sms_perm", "SMS Permission Granted", "persistence"),
        ("monitor", "SMS Monitoring Active", "collection"),
        ("otp_capture", "OTP Captured", "collection"),
        ("relay", "OTP Relayed to Attacker", "exfiltration"),
        ("auth_bypass", "Authentication Bypassed", "impact"),
    ],
    "credential_theft": [
        ("install", "App Installed", "infection"),
        ("accessibility", "Accessibility Service Enabled", "persistence"),
        ("keylog", "Keylogging Active", "collection"),
        ("creds", "Credentials Harvested", "collection"),
        ("c2_upload", "Data Uploaded to C2", "exfiltration"),
    ],
    "data_exfiltration": [
        ("install", "App Installed", "infection"),
        ("perms", "Device Permissions Acquired", "persistence"),
        ("contacts", "Contacts Extracted", "collection"),
        ("sms_dump", "SMS History Dumped", "collection"),
        ("files", "Device Files Accessed", "collection"),
        ("c2_upload", "Exfiltrated to C2 Server", "exfiltration"),
    ],
    "overlay_attack": [
        ("install", "App Installed", "infection"),
        ("alert_window", "Overlay Permission Obtained", "persistence"),
        ("wait", "Waiting for Banking App", "persistence"),
        ("overlay_show", "Fake Login Screen Displayed", "collection"),
        ("creds_stolen", "Credentials Entered on Fake Screen", "collection"),
        ("c2_upload", "Credentials Sent to Attacker", "exfiltration"),
    ],
}

DEFAULT_EDGES = [
    (0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 6),
]


def build_fraud_journey(intent: str, indicators: Dict[str, Any]) -> Dict[str, Any]:
    template_key = intent.lower().replace(" ", "_")
    template = JOURNEY_TEMPLATES.get(template_key, JOURNEY_TEMPLATES["credential_theft"])

    x_positions = [100 + i * 160 for i in range(len(template))]
    y_center = 200

    nodes = []
    for i, (node_id, label, node_type) in enumerate(template):
        style = NODE_TYPES.get(node_type, NODE_TYPES["collection"])
        nodes.append({
            "data": {"id": node_id, "label": label, "type": node_type},
            "position": {"x": x_positions[i], "y": y_center},
            "style": style,
        })

    edges = []
    for i in range(len(template) - 1):
        src = template[i][0]
        tgt = template[i + 1][0]
        edges.append({"data": {"source": src, "target": tgt, "id": f"{src}_{tgt}"}})

    return {
        "intent": intent,
        "nodes": nodes,
        "edges": edges,
        "step_count": len(nodes),
    }
