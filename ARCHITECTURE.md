# 1-page architecture diagram

## System flow (Mermaid)

```mermaid
flowchart LR
  A[CloudTrail Events\nJSONL or S3 Export] --> B[Ingest + Parse]
  B --> C[Normalize\nCommon Alert Schema]
  C --> D[Dedupe\nSQLite Incident State\n30-min window]
  D --> E[Enrich\nAllowlist\nPrivileged Users\nAsset Inventory]
  E --> F[Score\nExplainable Rules\nSeverity + Reasons]
  F --> G[Route\nOwner Team Mapping]
  G --> H[Ticket Builder\nEvidence + Actions]
  H --> I[Outputs\nJSON Tickets in out/\n(Ready for Jira/GitHub Issues/Slack)]

  subgraph State
    D
  end

  subgraph Config
    E
    G
  end
```
