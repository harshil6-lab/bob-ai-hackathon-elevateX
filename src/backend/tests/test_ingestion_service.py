import json

from app.services.ingestion_service import ingest_raw_records


def test_ingests_json_array_as_individual_records(tmp_path):
    payload = {"event_id": "SIEM-9001", "priority": "high"}
    (tmp_path / "siem_export.json").write_text(json.dumps([payload]), encoding="utf-8")

    records = ingest_raw_records(tmp_path)

    assert records == [{"source": "SIEM_EXPORT", "raw": payload}]


def test_ingests_threat_intel_indicator_list(tmp_path):
    indicator = {"type": "ipv4", "value": "203.0.113.55"}
    payload = {"indicators": [indicator]}
    (tmp_path / "threat_intel_feed.json").write_text(json.dumps(payload), encoding="utf-8")

    records = ingest_raw_records(tmp_path)

    assert records == [{"source": "THREAT_INTEL_FEED", "raw": indicator}]


def test_ingests_log_and_text_lines(tmp_path):
    (tmp_path / "network_sensor.log").write_text("first line\n\nsecond line\n", encoding="utf-8")
    (tmp_path / "intel_report.txt").write_text("report line\n", encoding="utf-8")

    records = ingest_raw_records(tmp_path)

    assert records == [
        {"source": "INTEL_REPORT", "raw": "report line"},
        {"source": "NETWORK_SENSOR", "raw": "first line"},
        {"source": "NETWORK_SENSOR", "raw": "second line"},
    ]


def test_skips_malformed_json_and_continues(tmp_path):
    (tmp_path / "bad_feed.json").write_text("{not valid json", encoding="utf-8")
    (tmp_path / "good_feed.log").write_text("valid line\n", encoding="utf-8")

    records = ingest_raw_records(tmp_path)

    assert records == [{"source": "GOOD_FEED", "raw": "valid line"}]


def test_returns_empty_list_for_missing_directory(tmp_path):
    missing_directory = tmp_path / "missing"

    assert ingest_raw_records(missing_directory) == []
