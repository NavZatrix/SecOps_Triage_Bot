import hashlib
from dateutil import parser
from .storage import get_conn

WINDOW_MINUTES = 30

def _make_dedupe_key(alert: dict) -> str:
    parts = [
        alert.get("alert_type", ""),
        alert.get("user", ""),
        alert.get("src_ip", ""),
        str(alert.get("resource", "")),
        str(alert.get("additional", {}).get("groupId", "")),
        str(alert.get("additional", {}).get("roleArn", "")),
    ]
    return "|".join(parts)

def _incident_id_from_key(key: str) -> str:
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]

def upsert_incident(alert: dict) -> dict:
    """Upsert an incident using a dedupe key and a time window."""
    dedupe_key = _make_dedupe_key(alert)
    incident_id = _incident_id_from_key(dedupe_key)
    ts = parser.isoparse(alert["timestamp"])

    with get_conn() as conn:
        row = conn.execute(
            "SELECT incident_id, first_seen, last_seen, count FROM incidents WHERE incident_id=?",
            (incident_id,),
        ).fetchone()

        if row:
            _, first_seen, last_seen, count = row
            last_seen_ts = parser.isoparse(last_seen)
            delta_minutes = (ts - last_seen_ts).total_seconds() / 60.0

            if delta_minutes <= WINDOW_MINUTES:
                new_count = count + 1
                conn.execute(
                    "UPDATE incidents SET last_seen=?, count=? WHERE incident_id=?",
                    (alert["timestamp"], new_count, incident_id),
                )
                return {
                    "incident_id": incident_id,
                    "dedupe_key": dedupe_key,
                    "first_seen": first_seen,
                    "last_seen": alert["timestamp"],
                    "count": new_count,
                    "is_new": False,
                }

        # new incident or outside window: reset
        conn.execute(
            "INSERT OR REPLACE INTO incidents (incident_id, dedupe_key, first_seen, last_seen, count) VALUES (?,?,?,?,?)",
            (incident_id, dedupe_key, alert["timestamp"], alert["timestamp"], 1),
        )
        return {
            "incident_id": incident_id,
            "dedupe_key": dedupe_key,
            "first_seen": alert["timestamp"],
            "last_seen": alert["timestamp"],
            "count": 1,
            "is_new": True,
        }
