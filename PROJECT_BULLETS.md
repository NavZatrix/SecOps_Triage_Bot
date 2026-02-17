# Project bullets

- Built an AWS-focused SecOps triage bot that converts CloudTrail-style events into deduplicated incidents and ticket-ready JSON for analyst workflows  
- Implemented stateful deduplication with a 30-minute correlation window to collapse repeat alerts into a single incident while tracking occurrence counts  
- Added enrichment for allowlisted IPs, privileged identities, and asset criticality then applied explainable rule-based scoring to prioritize high-risk activity  
- Automated routing to owner teams based on alert type and embedded evidence plus remediation steps to reduce triage time and analyst back-and-forth
