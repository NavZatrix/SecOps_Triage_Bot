import json

def build_ticket(alert: dict, incident: dict) -> dict:
    sev = alert["scoring"]["severity"]
    points = alert["scoring"]["points"]
    reasons = alert["scoring"]["reasons"]
    owner = alert["routing"]["owner"]

    title = f"[{sev}] {alert['alert_type']} for {alert.get('user')} from {alert.get('src_ip')}"

    evidence = {
        "incident_id": incident["incident_id"],
        "count": incident["count"],
        "first_seen": incident["first_seen"],
        "last_seen": incident["last_seen"],
        "event_name": alert.get("event_name"),
        "region": alert.get("region"),
        "resource": alert.get("resource"),
        "additional": alert.get("additional", {}),
        "enrichment": alert.get("enrichment", {}),
        "reasons": reasons,
        "score_points": points,
    }

    actions = []
    if alert["alert_type"] in ("console_login", "console_login_failed", "console_login_success"):
        actions += [
            "Verify user identity and source IP legitimacy",
            "Check MFA status and enforce MFA if missing",
            "Review adjacent IAM/STS activity in CloudTrail",
        ]
    if alert["alert_type"] == "iam_access_key_created":
        actions += [
            "Confirm access key creation is expected",
            "Rotate/revoke the key if suspicious and review recent IAM changes",
            "Enable alerts for key usage from new locations",
        ]
    if alert["alert_type"] == "security_group_opened":
        actions += [
            "Restrict inbound rule to specific IP ranges or VPN",
            "Verify change request and roll back if unauthorized",
            "Add guardrails via SCP/AWS Config rules",
        ]

    return {
        "title": title,
        "owner": owner,
        "severity": sev,
        "summary": f"Automated triage generated an incident with score {points}.",
        "evidence": evidence,
        "recommended_actions": actions,
    }

def write_ticket(ticket: dict, out_path: str):
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(ticket, f, indent=2)
