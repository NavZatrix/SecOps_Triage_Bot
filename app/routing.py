import yaml
from pathlib import Path

def route(alert: dict) -> dict:
    cfg = yaml.safe_load(Path("app/config/routing.yml").read_text(encoding="utf-8"))
    rules = cfg.get("rules", [])
    default_owner = cfg.get("default_owner", "SOC")

    for rule in rules:
        match = rule.get("match", {})
        ok = True
        for k, v in match.items():
            if alert.get(k) != v:
                ok = False
                break
        if ok:
            out = dict(alert)
            out["routing"] = {"owner": rule.get("owner", default_owner)}
            return out

    out = dict(alert)
    out["routing"] = {"owner": default_owner}
    return out
