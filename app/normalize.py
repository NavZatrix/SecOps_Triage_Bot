from dateutil import parser

EVENT_MAP = {
    "ConsoleLogin": "console_login",
    "CreateAccessKey": "iam_access_key_created",
    "AssumeRole": "assume_role",
    "AuthorizeSecurityGroupIngress": "security_group_opened",
}

def normalize(raw: dict) -> dict:
    """Normalize a CloudTrail-ish input event into a common alert schema."""
    ts = parser.isoparse(raw["timestamp"]).isoformat()
    event = raw.get("eventName", "Unknown")
    alert_type = EVENT_MAP.get(event, event.lower())

    return {
        "timestamp": ts,
        "source": raw.get("source", "unknown"),
        "alert_type": alert_type,
        "event_name": event,
        "status": raw.get("status", "Unknown"),
        "user": raw.get("user", "unknown"),
        "src_ip": raw.get("src_ip", "0.0.0.0"),
        "region": raw.get("region"),
        "resource": raw.get("resource"),
        "asset": raw.get("asset"),  # optional
        "mfa_used": raw.get("mfaUsed"),
        "additional": raw.get("additional", {}),
        "raw": raw,
    }
