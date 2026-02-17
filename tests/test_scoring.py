from app.scoring import score

def test_priv_user_increases_score():
    alert = {
        "alert_type": "iam_access_key_created",
        "status": "Success",
        "user": "admin",
        "src_ip": "45.83.12.9",
        "mfa_used": "No",
        "additional": {},
        "enrichment": {"is_privileged_user": True, "ip_reputation": "suspicious", "asset_info": None},
    }
    out = score(alert)
    assert out["scoring"]["points"] >= 60
    assert out["scoring"]["severity"] in ("High", "Critical")
