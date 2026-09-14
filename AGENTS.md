# IBM BOBATHON 2026 — D2 PROJECT CONTRACT

## PROJECT

Problem Statement:
D2 — Threat Intelligence Correlation & Alert Prioritisation Assistant

Goal:

Build a working AI-powered threat intelligence system that:

1. Ingests multi-source threat feeds.
2. Correlates related alerts.
3. Separates likely genuine threats from false positives.
4. Maps attacker behavior to the MITRE ATT&CK framework.
5. Produces prioritised threat assessments.
6. Generates evidence-grounded BLUF (Bottom Line Up Front) investigation summaries.
7. Provides recommended actions.
8. Demonstrates meaningful IBM Bob integration.

The official D2 challenge specifically asks for multi-source ingestion,
alert correlation, false-positive separation, MITRE ATT&CK mapping,
and prioritised BLUF summaries for commanders.

---

# OFFICIAL REPOSITORY STRUCTURE

The official Bobathon submission template requires application source
code to live under `src/`.

Therefore the project uses:

d2-threat-copilot/
│
├── submission.yaml
├── README.md
│
├── src/
│   ├── frontend/          ← Member 3
│   ├── backend/           ← Member 2
│   ├── intelligence/     ← Member 1
│   └── data/              ← Member 2
│
├── docs/
│   ├── problem-statement.md
│   ├── solution-overview.md
│   ├── architecture.md
│   └── setup-guide.md
│
├── demo/
├── presentation/
├── CONTRIBUTING.md
├── .gitignore
└── .github/
    └── workflows/
        └── validate.yml

Do NOT move source code outside `src/`.

---

# ABSOLUTE RULES

These rules are NON-NEGOTIABLE.

1. Do NOT change the agreed architecture unless all 3 team members explicitly approve it.
2. Do NOT rename existing API endpoints.
3. Do NOT change shared schemas.
4. Do NOT move another member's files.
5. Do NOT rewrite another member's module.
6. Do NOT introduce duplicate implementations of an existing capability.
7. Do NOT change the frontend/backend contract.
8. Do NOT add dependencies unless genuinely required.
9. Do NOT commit secrets, API keys, .env files, credentials, tokens or passwords.
10. Do NOT modify `.github/workflows/validate.yml`.
11. Do NOT delete official IBM Bobathon template files.
12. Do NOT modify another member's work merely to make your own implementation easier.
13. Before changing a shared contract, STOP and ask for approval.
14. Prefer the smallest change that satisfies the task.
15. Preserve backward compatibility whenever possible.
16. Do NOT create a second implementation of the same intelligence, API, or UI capability.
17. Do NOT invent IBM Bob integration merely for documentation. The integration must be real and demonstrable.

---

# TEAM OWNERSHIP

## Member 1 — Intelligence

Owns:

src/intelligence/

Responsibilities:

- Alert correlation
- Threat scoring
- Confidence calculation
- Evidence extraction
- Controlled MITRE ATT&CK mapping
- AI reasoning/explanation
- BLUF generation
- Recommended actions
- Intelligence pipeline
- Intelligence tests

Member 1 must NOT modify frontend or backend implementation
without team approval.

---

## Member 2 — Backend & Data

Owns:

src/backend/
src/data/

Responsibilities:

- Data ingestion
- Data normalization
- Database/storage
- Backend API
- Backend integration
- Connecting backend to intelligence layer
- Synthetic demo dataset

Member 2 must NOT modify intelligence implementation
without team approval.

---

## Member 3 — Frontend

Owns:

src/frontend/

Responsibilities:

- Dashboard
- Alert explorer
- Incident investigation UI
- MITRE visualization
- BLUF presentation
- User interaction
- Visual design
- Frontend integration

Member 3 must NOT modify backend or intelligence implementation
without team approval.

---

# SHARED CONTRACT

## Canonical Alert Schema

Every normalized alert MUST contain:

id
timestamp
source
event_type
severity
source_ip
destination_ip
host
user
description

Example:

{
  "id": "ALT-1001",
  "timestamp": "2026-09-14T10:32:00Z",
  "source": "SIEM",
  "event_type": "PowerShell",
  "severity": "medium",
  "source_ip": "10.10.1.20",
  "destination_ip": "10.10.5.17",
  "host": "SERVER-17",
  "user": "admin",
  "description": "Suspicious PowerShell execution"
}

Do NOT rename these fields.

---

# Canonical Incident Schema

{
  "id": "INC-001",
  "severity": "critical",
  "confidence": 94,
  "status": "investigating",
  "affected_assets": ["SERVER-17"],
  "alert_count": 7,
  "sources": [
    "SIEM",
    "NETWORK_SENSOR",
    "THREAT_INTEL"
  ],
  "mitre_techniques": [],
  "evidence": [],
  "bluf": "",
  "recommended_actions": []
}

Do NOT rename or remove these fields.

Additional internal fields may exist internally,
but the public incident contract must remain compatible.

---

# CANONICAL API

GET  /api/alerts
GET  /api/alerts/{id}
GET  /api/incidents
GET  /api/incidents/{id}
GET  /api/dashboard/stats
POST /api/analyze

The API contract must remain stable.

---

# INTELLIGENCE ARCHITECTURE

The core pipeline is:

Multi-source alerts
        ↓
Normalization
        ↓
Correlation
        ↓
Incident grouping
        ↓
Threat scoring
        ↓
Evidence extraction
        ↓
MITRE ATT&CK mapping
        ↓
AI explanation
        ↓
BLUF generation
        ↓
Recommended actions
        ↓
Prioritised incident
        ↓
Frontend

---

# AI PRINCIPLE

Deterministic logic must remain deterministic.

Use deterministic logic for:

- validation
- normalization
- correlation
- scoring
- evidence extraction
- controlled MITRE mapping

Use AI/LLM primarily for:

- natural-language explanation
- BLUF generation
- analyst interaction

The AI must NOT invent:

- evidence
- IP addresses
- users
- hosts
- alert counts
- MITRE technique IDs
- incidents
- statistics
- actions already performed

AI-generated conclusions must be grounded in structured
evidence produced by the system.

---

# DEMO PRINCIPLE

The demo must demonstrate:

Many noisy alerts
        ↓
Correlation
        ↓
Fewer meaningful incidents
        ↓
Prioritisation
        ↓
Critical incident
        ↓
Evidence
        ↓
MITRE ATT&CK
        ↓
BLUF
        ↓
Recommended action

The golden demo scenario must be deterministic and repeatable.

Do NOT make the core demo dependent on unpredictable random output.

---

# IBM BOB PRINCIPLE

IBM Bob must be genuinely useful to the solution.

Do NOT merely mention Bob in README or presentation.

The team must identify and implement a real Bob workflow that
materially contributes to the system.

The final documentation and presentation must clearly explain:

- what Bob does
- where Bob interacts with the system
- what capability depends on Bob
- what the user gains from that integration

---

# GIT RULES

Never force-push shared branches.

Never reset another member's work.

Never use:

git reset --hard
git clean -fd
git push --force

unless the entire team explicitly approves it.

Before committing:

git status
git diff

After completing work:

git add <only-your-files>
git commit
git push

---

# BEFORE MODIFYING CODE

1. Read this file.
2. Inspect the existing implementation.
3. Determine ownership.
4. Check existing interfaces.
5. Make the smallest compatible change.
6. Run relevant tests.
7. Report exactly what changed.

If the requested change conflicts with this contract:

STOP and ask instead of modifying the architecture.