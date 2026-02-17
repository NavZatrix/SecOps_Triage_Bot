import yaml
from pathlib import Path

def _load_yaml(path: str) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))

def enrich(alert: dict) -> dict:
    """Enrich an alert with lightweight org context + placeholder reputation."""
    allow = _load_yaml("app/config/allowlist.yml")
    priv = _load_yaml("app/config/privileged_users.yml")
    inv = _load_yaml("app/config/asset_inventory.yml")

    src_ip = alert.get("src_ip")
    user = alert.get("user")
    asset = alert.get("asset")

    is_allowlisted_ip = src_ip in set(allow.get("allowed_ips", []))
    is_priv_user = user in set(priv.get("users", []))

    asset_info = None
    if asset and asset in inv.get("assets", {}):
        asset_info = inv["assets"][asset]

    # Placeholder reputation: swap this with real intel later.
    ip_reputation = "unknown"
    if src_ip and (src_ip.startswith("45.") or src_ip.startswith("185.") or src_ip.startswith("91.")):
        ip_reputation = "suspicious"
    if is_allowlisted_ip:
        ip_reputation = "allowlisted"

    out = dict(alert)
    out["enrichment"] = {
        "is_allowlisted_ip": is_allowlisted_ip,
        "is_privileged_user": is_priv_user,
        "asset_info": asset_info,
        "ip_reputation": ip_reputation,
    }
    return out
