from app.dedupe import upsert_incident

def test_dedupe_increments_count(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    a1 = {"timestamp":"2026-02-17T14:02:10Z","alert_type":"console_login","user":"u","src_ip":"1.2.3.4","resource":"AWS::Console","additional":{}}
    a2 = {"timestamp":"2026-02-17T14:03:10Z","alert_type":"console_login","user":"u","src_ip":"1.2.3.4","resource":"AWS::Console","additional":{}}

    i1 = upsert_incident(a1)
    i2 = upsert_incident(a2)

    assert i1["incident_id"] == i2["incident_id"]
    assert i2["count"] == 2
