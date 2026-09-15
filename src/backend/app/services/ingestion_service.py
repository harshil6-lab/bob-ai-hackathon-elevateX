from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)

DEFAULT_RAW_DATA_DIR = Path(__file__).resolve().parents[3] / "data" / "raw"


def ingest_raw_records(raw_data_dir: Path | str = DEFAULT_RAW_DATA_DIR) -> list[dict[str, Any]]:
    """Read supported raw feed files and return source-tagged raw payloads.

    JSON arrays are expanded into one record per element. JSON objects that
    contain an ``indicators`` list are expanded into one record per indicator.
    Text and log files are expanded into one record per non-empty line.
    Malformed or unreadable files are logged and skipped.
    """

    directory = Path(raw_data_dir)
    if not directory.is_dir():
        logger.warning("Raw data directory does not exist or is not a directory: %s", directory)
        return []

    records: list[dict[str, Any]] = []
    for path in sorted(directory.iterdir()):
        if not path.is_file():
            continue

        source = path.stem.upper()
        suffix = path.suffix.lower()
        try:
            if suffix == ".json":
                payloads = _read_json_file(path)
            elif suffix in {".log", ".txt"}:
                payloads = _read_text_file(path)
            else:
                logger.warning("Skipping unsupported raw data file: %s", path)
                continue
        except (OSError, ValueError) as exc:
            logger.warning("Skipping malformed or unreadable raw data file %s: %s", path, exc)
            continue

        records.extend({"source": source, "raw": payload} for payload in payloads)

    return records


def _read_json_file(path: Path) -> list[Any]:
    """Return a list of raw JSON payloads from one file."""

    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get("indicators"), list):
        return payload["indicators"]
    return [payload]


def _read_text_file(path: Path) -> list[str]:
    """Return non-empty text lines from one raw log or report file."""

    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
