# Example API payloads

These payloads were captured from the seeded backend using the real Member 1
intelligence engine and the deterministic synthetic dataset in `src/data/raw/`.
List responses are abbreviated to one item for readability; `count` shows the
full result size.

Dataset summary after `python -m app.db.seed --reset` and one
`POST /api/analyze`: **27 alerts** and **17 incidents**.

## `GET /api/alerts`

```json
{
  "alerts": [
    {
      "id": "ALT-6827BEDE38F9",
      "timestamp": "2026-09-14T00:00:00",
      "source": "INTEL_REPORT",
      "event_type": "intel_report",
      "severity": "informational",
      "source_ip": null,
      "destination_ip": null,
      "host": null,
      "user": null,
      "description": "REPORT DATE: 2026-09-14"
    }
  ],
  "count": 27
}
```

## `GET /api/alerts/ALT-6827BEDE38F9`

```json
{
  "id": "ALT-6827BEDE38F9",
  "timestamp": "2026-09-14T00:00:00",
  "source": "INTEL_REPORT",
  "event_type": "intel_report",
  "severity": "informational",
  "source_ip": null,
  "destination_ip": null,
  "host": null,
  "user": null,
  "description": "REPORT DATE: 2026-09-14"
}
```

## `GET /api/incidents`

```json
{
  "incidents": [
    {
      "id": "GRP-01FB9C0D08104CD8",
      "severity": "low",
      "confidence": 25,
      "status": "investigating",
      "affected_assets": [],
      "alert_count": 1,
      "sources": [
        "INTEL_REPORT"
      ],
      "mitre_techniques": [],
      "evidence": [
        "EV-67D7239770533447"
      ],
      "bluf": "Bottom line: low threat activity. Risk score 13/100; confidence 25/100. 1 correlated alert from 1 source has no established affected assets.",
      "recommended_actions": [
        "Review the correlated alerts and supporting evidence."
      ]
    }
  ],
  "count": 17
}
```

## `GET /api/incidents/GRP-4B1CF25CB0DC6839`

The prioritised critical incident produced by the SERVER-17 multi-source attack chain.

```json
{
  "id": "GRP-4B1CF25CB0DC6839",
  "severity": "critical",
  "confidence": 100,
  "status": "investigating",
  "affected_assets": [
    "SERVER-17"
  ],
  "alert_count": 6,
  "sources": [
    "ENDPOINT_SENSOR",
    "NETWORK_SENSOR",
    "THREAT_INTEL"
  ],
  "mitre_techniques": [
    "T1003",
    "T1021",
    "T1059.001"
  ],
  "evidence": [
    "EV-0CDEBDC4ABFECE27",
    "EV-11C5371D3CEADB4C",
    "EV-12862064A1EBAB59",
    "EV-15B1649A41D7C714",
    "EV-1665A5E697AFF5A9",
    "EV-1BE2920700F49B64",
    "EV-1D25315B02ADA1F5",
    "EV-2827FE9A81AC5BD7",
    "EV-3407057821754CA6",
    "EV-451A6868677A6259",
    "EV-45DB951FCA46A3D0",
    "EV-515C1C4FEFEEDAAF",
    "EV-531F8946E9B11209",
    "EV-53BADD03730BD36B",
    "EV-5866B95F994BDF3E",
    "EV-5B288BF72AA7B957",
    "EV-624A1D7AC790F631",
    "EV-7060027062FF1CA4",
    "EV-74EBAA4530865899",
    "EV-753BF855F55A68C1",
    "EV-829AD3F37F1D5F9A",
    "EV-865311946DE0CA32",
    "EV-897F2CF792AB75AD",
    "EV-966F690D7A8463D1",
    "EV-9D1FD931035CFDC0",
    "EV-9D7CEA089CD53A1B",
    "EV-A607501E4C0829A8",
    "EV-A9B8C591F36443EA",
    "EV-AAB646E77C2D1B08",
    "EV-C2E21DCDA76C85CA",
    "EV-C3E6E0DE4C665CA0",
    "EV-CFDEE35D3C3326D4",
    "EV-D50F2C3F59C79DCF",
    "EV-D7BA6F28C2E14D59",
    "EV-D82615B69183A69C",
    "EV-E855141F0EA20EE4",
    "EV-EC846D2C0C9A9C9A",
    "EV-F192B958EA2242B3",
    "EV-FD6D6C3FD56A267A",
    "EV-FEE78D0D38FCD3C8"
  ],
  "bluf": "Bottom line: critical threat activity. Risk score 91/100; confidence 100/100. 6 correlated alerts from 3 sources affects 1 asset.",
  "recommended_actions": [
    "Consider isolating the affected host after analyst validation.",
    "Prioritize analyst investigation of the correlated alerts and supporting evidence.",
    "Investigate possible credential exposure and review authentication activity linked to the supporting alerts.",
    "Investigate remote-service activity and review the source and destination systems linked to the supporting alerts.",
    "Review PowerShell command and script execution details, including the initiating process, user, and host where available.",
    "Cross-check the independent source observations for the correlated alerts."
  ]
}
```

## `GET /api/dashboard/stats`

```json
{
  "total_alerts": 27,
  "total_incidents": 17,
  "critical_incidents": 1,
  "high_incidents": 1,
  "severity_distribution": {
    "informational": 7,
    "low": 10,
    "medium": 1,
    "high": 7,
    "critical": 2
  },
  "source_counts": {
    "ENDPOINT_SENSOR": 8,
    "INTEL_REPORT": 3,
    "NETWORK_SENSOR": 7,
    "SIEM": 5,
    "THREAT_INTEL": 4
  },
  "status_distribution": {
    "investigating": 17
  }
}
```

## `POST /api/analyze`

Request:

```json
{}
```

Response (abbreviated to one incident):

```json
{
  "incidents": [
    {
      "id": "GRP-01FB9C0D08104CD8",
      "severity": "low",
      "confidence": 25,
      "status": "investigating",
      "affected_assets": [],
      "alert_count": 1,
      "sources": [
        "INTEL_REPORT"
      ],
      "mitre_techniques": [],
      "evidence": [
        "EV-67D7239770533447"
      ],
      "bluf": "Bottom line: low threat activity. Risk score 13/100; confidence 25/100. 1 correlated alert from 1 source has no established affected assets.",
      "recommended_actions": [
        "Review the correlated alerts and supporting evidence."
      ]
    }
  ],
  "count": 17
}
```

## `GET /api/alerts/ALT-404`

```json
{
  "error": "alert not found",
  "id": "ALT-404"
}
```

## `POST /api/analyze` with malformed JSON

Request:

```json
{invalid
```

Response:

```json
{
  "error": "validation error",
  "detail": [
    {
      "type": "json_invalid",
      "loc": [
        "body",
        1
      ],
      "msg": "JSON decode error",
      "input": {},
      "ctx": {
        "error": "Expecting property name enclosed in double quotes"
      }
    }
  ]
}
```
