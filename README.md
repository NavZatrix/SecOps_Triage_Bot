# SecOps_Triage_Bot
SecOps Triage Bot (AWS CloudTrail focused): a Python automation that normalizes CloudTrail-style events, deduplicates noisy alerts into incidents, enriches with org context, scores severity using explainable rules, routes ownership, and outputs ticket-ready JSON for SOC workflows.

## What it does
- Normalizes CloudTrail-ish events into a common alert schema
- Deduplicates noisy alerts into incidents (time-window based)
- Enriches with org context (allowlist, privileged users, asset inventory)
- Scores severity using explainable rules
- Routes to an owner team
- Outputs ticket JSON artifacts (`out/`)

## Quick start
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python -m app.main
```


## Run with Docker
```bash
docker build -t secops-triage-bot -f docker/Dockerfile .
docker run --rm -v "$PWD:/app" secops-triage-bot
```

## Files worth reading
- `ARCHITECTURE.md` for the system diagram
- `PROJECT_BULLETS.md` for resume-ready bullets
- `GITHUB_REPO_DESCRIPTION.md` for the GitHub “About” text

## Next upgrades (high-signal)
- Ingest real CloudTrail from S3 and parse native CloudTrail format
- Add threat intel enrichment and caching
- Auto-create GitHub Issues or Jira tickets and post to Slack
- Add correlation across event types (kill chain)
