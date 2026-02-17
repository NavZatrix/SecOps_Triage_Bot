import json
from pathlib import Path

from .normalize import normalize
from .dedupe import upsert_incident
from .enrich import enrich
from .scoring import score
from .routing import route
from .ticketing import build_ticket, write_ticket

def run(input_path: str, out_dir: str = "out"):
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    tickets = []
    for line in Path(input_path).read_text(encoding="utf-8").splitlines():
        raw = json.loads(line)
        alert = normalize(raw)
        incident = upsert_incident(alert)

        alert = enrich(alert)
        alert = score(alert)
        alert = route(alert)

        ticket = build_ticket(alert, incident)
        out_path = str(Path(out_dir) / f"ticket_{incident['incident_id']}.json")
        write_ticket(ticket, out_path)

        tickets.append((incident["incident_id"], ticket["severity"], ticket["owner"], ticket["title"]))

    print("\nGenerated tickets:")
    for inc_id, sev, owner, title in tickets:
        print(f"- {inc_id} | {sev} | {owner} | {title}")

if __name__ == "__main__":
    run("data/sample_cloudtrail_alerts.jsonl")
