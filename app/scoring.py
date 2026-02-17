def score(alert: dict) -> dict:
    """Rule-based scoring: explainable and fast."""
    e = alert.get("enrichment", {})
    additional = alert.get("additional", {})

    points = 0
    reasons = []

    if e.get("is_privileged_user"):
        points += 30
        reasons.append("Privileged user activity")

    asset_info = e.get("asset_info") or {}
    if asset_info.get("env") == "prod":
        points += 25
        reasons.append("Production asset context")

    rep = e.get("ip_reputation")
    if rep == "suspicious":
        points += 25
        reasons.append("Suspicious IP reputation")
    if rep == "allowlisted":
        points -= 20
        reasons.append("Allowlisted source IP")

    if alert.get("alert_type") in ("console_login", "console_login_failed", "console_login_success"):
        mfa = (alert.get("mfa_used") or "").lower()
        if mfa in ("no", "false", "") and alert.get("status") == "Failure":
            points += 20
            reasons.append("Failed console login without MFA")
        if mfa in ("no", "false", "") and alert.get("status") == "Success":
            points += 35
            reasons.append("Successful console login without MFA")

    if alert.get("alert_type") == "iam_access_key_created":
        points += 35
        reasons.append("Access key created")

    if alert.get("alert_type") == "security_group_opened":
        cidr = str(additional.get("cidr", ""))
        port = additional.get("port")
        if cidr == "0.0.0.0/0" and port in (22, 3389):
            points += 40
            reasons.append("Security group opened to world on admin port")

    points = max(points, 0)

    if points >= 85:
        sev = "Critical"
    elif points >= 60:
        sev = "High"
    elif points >= 30:
        sev = "Medium"
    else:
        sev = "Low"

    out = dict(alert)
    out["scoring"] = {"points": points, "severity": sev, "reasons": reasons}
    return out
