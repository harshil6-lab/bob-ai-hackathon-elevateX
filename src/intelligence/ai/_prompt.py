"""Shared grounded prompt construction for AI reasoning providers.

Both GroqProvider and GraniteProvider use the same prompt format.  This
module is the single source of truth for the grounding instruction text.

The prompt is designed to:
  - enumerate every allowed reference value explicitly,
  - instruct the model to output ONLY a JSON object,
  - prevent the model from inventing facts,
  - include pre-filled structured fields the model must preserve.

Security: alert text is embedded as data (quoted), not as instructions.
"""

from __future__ import annotations

import json
from typing import Any

from .context import AIContext


def build_grounded_prompt(context: AIContext) -> str:
    """Return the grounded prompt string for the given AIContext."""

    alert_lines = "\n".join(
        f"  - {a.alert_id} | {a.timestamp} | {a.source} | {a.event_type} "
        f"| {a.severity} | host={a.host or 'N/A'} user={a.user or 'N/A'}"
        for a in context.alerts
    )

    technique_lines = (
        "\n".join(
            f"  - {m.technique_id} ({m.technique_name}, {m.tactic})"
            for m in context.mitre_mappings
        )
        or "  (none)"
    )

    evidence_lines = (
        "\n".join(
            f"  - {e.evidence_id}: {e.evidence_type} — {e.description}"
            for e in context.evidence_records
        )
        or "  (none)"
    )

    alert_ids_csv = ", ".join(context.alert_ids)
    evidence_ids_csv = (
        ", ".join(context.evidence_ids) if context.evidence_ids else "(none)"
    )
    mitre_ids_csv = (
        ", ".join(context.mitre_technique_ids)
        if context.mitre_technique_ids
        else "(none)"
    )
    hosts_csv = (
        ", ".join(sorted({a.host for a in context.alerts if a.host})) or "(none)"
    )
    users_csv = (
        ", ".join(sorted({a.user for a in context.alerts if a.user})) or "(none)"
    )
    source_ips_csv = (
        ", ".join(sorted({a.source_ip for a in context.alerts if a.source_ip}))
        or "(none)"
    )
    destination_ips_csv = (
        ", ".join(
            sorted({a.destination_ip for a in context.alerts if a.destination_ip})
        )
        or "(none)"
    )
    assets_csv = (
        ", ".join(context.scoring.affected_assets)
        if context.scoring.affected_assets
        else "(none)"
    )

    return f"""You are a cybersecurity analyst AI assistant. You will be given structured intelligence
results from a deterministic threat intelligence engine. Your job is to write a concise,
analyst-oriented explanation (summary and reasoning) of what the intelligence means.

CRITICAL RULES:
1. You MUST output ONLY a valid JSON object. No other text before or after it.
2. Your summary and reasoning MUST be grounded ONLY in the context below.
3. You MUST NOT invent alert IDs, evidence IDs, MITRE techniques, hosts, users,
   IP addresses, risk scores, confidence values, or alert counts.
4. You MUST reference ONLY values that appear in the ALLOWED REFERENCES section.
5. The summary should be 1-3 sentences suitable for a commander's BLUF.
6. The reasoning should be 2-5 sentences explaining the key technical findings.

ALLOWED REFERENCES (use ONLY these values in referenced_* fields):
  incident_id: {context.incident_id}
  alert_ids: {alert_ids_csv}
  evidence_ids: {evidence_ids_csv}
  mitre_technique_ids: {mitre_ids_csv}
  hosts: {hosts_csv}
  users: {users_csv}
  source_ips: {source_ips_csv}
  destination_ips: {destination_ips_csv}
  assets: {assets_csv}
  alert_count (exact): {context.scoring.alert_count}
  source_count (exact): {context.scoring.source_count}
  risk_score (exact): {context.scoring.risk_score}
  confidence (exact): {context.scoring.confidence}
  evidence_count (exact): {len(context.evidence_ids)}
  mitre_technique_count (exact): {len(context.mitre_technique_ids)}

INTELLIGENCE CONTEXT:
Incident: {context.incident_id}
Assessment: {context.scoring.severity} severity, risk {context.scoring.risk_score}/100,
  confidence {context.scoring.confidence}/100, {context.scoring.false_positive_assessment}

Correlated alerts ({context.scoring.alert_count} total, {context.scoring.source_count} sources):
{alert_lines}

MITRE ATT&CK mappings:
{technique_lines}

Evidence:
{evidence_lines}

Output ONLY this JSON object (fill in summary and reasoning; keep all other fields exactly as shown):
{{
  "incident_id": "{context.incident_id}",
  "summary": "<write 1-3 sentence commander BLUF here>",
  "reasoning": "<write 2-5 sentence technical explanation here>",
  "referenced_alert_ids": [{json_str_list(context.alert_ids)}],
  "referenced_evidence_ids": [{json_str_list(context.evidence_ids)}],
  "referenced_mitre_technique_ids": [{json_str_list(context.mitre_technique_ids)}],
  "referenced_hosts": [{json_str_list(sorted({a.host for a in context.alerts if a.host}))}],
  "referenced_users": [{json_str_list(sorted({a.user for a in context.alerts if a.user}))}],
  "referenced_source_ips": [{json_str_list(sorted({a.source_ip for a in context.alerts if a.source_ip}))}],
  "referenced_destination_ips": [{json_str_list(sorted({a.destination_ip for a in context.alerts if a.destination_ip}))}],
  "referenced_assets": [{json_str_list(context.scoring.affected_assets)}],
  "numeric_claims": [
    {{"name": "alert_count", "value": {context.scoring.alert_count}}},
    {{"name": "source_count", "value": {context.scoring.source_count}}},
    {{"name": "risk_score", "value": {context.scoring.risk_score}}},
    {{"name": "confidence", "value": {context.scoring.confidence}}},
    {{"name": "evidence_count", "value": {len(context.evidence_ids)}}},
    {{"name": "mitre_technique_count", "value": {len(context.mitre_technique_ids)}}}
  ]
}}"""


def json_str_list(values: Any) -> str:
    """Render an iterable of strings as a comma-separated JSON string list."""
    return ", ".join(json.dumps(v) for v in list(values))
