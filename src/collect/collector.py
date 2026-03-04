"""
Phase 0 – Automated CVE collection from NVD (National Vulnerability Database).

Fetches CVEs via the NVD REST API 2.0, filters by date range, and saves only
new entries (not already present in the local corpus) as JSON files compatible
with the Phase 1 RAG ingestion schema.

Usage:
    python -m src.collect.collector \
        --start-date 2024-01-01 \
        --end-date 2024-12-31 \
        [--keyword linux] \
        [--cwe CWE-79,CWE-89]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import yaml

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD rate limits: 5 req/30s without API key, 50 req/30s with key
RATE_LIMIT_DELAY_NO_KEY = 6.0   # seconds between requests (no key)
RATE_LIMIT_DELAY_WITH_KEY = 0.6  # seconds between requests (with key)
RESULTS_PER_PAGE = 100  # NVD max per request
NVD_MAX_RANGE_DAYS = 120  # NVD rejects date ranges exceeding 120 days


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _nvd_datetime(dt: datetime) -> str:
    """Format datetime for NVD API (ISO 8601 with UTC timezone offset).

    The NVD API requires timestamps in strict ISO 8601 format with an
    explicit timezone offset, e.g. ``2025-10-01T00:00:00.000+00:00``.
    Omitting the offset causes a 404 "Invalid ISO 8601 date/time format".
    """
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def _parse_date(date_str: str) -> datetime:
    """Parse a YYYY-MM-DD string into a timezone-aware datetime."""
    dt = datetime.strptime(date_str, "%Y-%m-%d")
    return dt.replace(tzinfo=timezone.utc)


def _get_existing_cve_ids(corpus_dir: Path) -> set[str]:
    """Scan corpus directory and return a set of CVE IDs already downloaded."""
    existing: set[str] = set()
    if not corpus_dir.exists():
        return existing
    for json_path in corpus_dir.glob("*.json"):
        try:
            with open(json_path) as f:
                data = json.load(f)
            cve_id = data.get("cve_id", "")
            if cve_id:
                existing.add(cve_id)
        except (json.JSONDecodeError, KeyError):
            # Also try to infer CVE ID from filename: CVE-YYYY-NNNNN.json
            name = json_path.stem
            if name.startswith("CVE-"):
                existing.add(name)
    return existing


def _extract_cve_entry(vuln: dict[str, Any]) -> dict[str, Any] | None:
    """Convert a single NVD CVE item into our corpus JSON schema.

    Returns None if the entry lacks essential data.
    """
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    # --- Description ---
    descriptions = cve.get("descriptions", [])
    desc_en = ""
    for d in descriptions:
        if d.get("lang") == "en":
            desc_en = d.get("value", "")
            break
    if not desc_en and descriptions:
        desc_en = descriptions[0].get("value", "")

    # --- CWE ---
    weaknesses = cve.get("weaknesses", [])
    cwe_ids: list[str] = []
    for w in weaknesses:
        for wd in w.get("description", []):
            val = wd.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)
    cwe_id = cwe_ids[0] if cwe_ids else "NVD-CWE-noinfo"

    # --- Vuln type (derived from CWE) ---
    vuln_type = _cwe_to_vuln_type(cwe_id)

    # --- CVSS score ---
    metrics = cve.get("metrics", {})
    cvss_score = None
    cvss_severity = None
    for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(version_key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_severity = cvss_data.get("baseSeverity")
            break

    # --- References ---
    references = cve.get("references", [])
    ref_urls = [r.get("url", "") for r in references if r.get("url")]

    # --- Dates ---
    published = cve.get("published", "")
    last_modified = cve.get("lastModified", "")

    # --- Affected configurations / CPE ---
    configurations = cve.get("configurations", [])
    affected_products: list[str] = []
    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                criteria = cpe_match.get("criteria", "")
                if criteria:
                    affected_products.append(criteria)

    return {
        "cve_id": cve_id,
        "vuln_type": vuln_type,
        "cwe_id": cwe_id,
        "cwe_ids": cwe_ids,
        "description": desc_en,
        "root_cause": desc_en,  # placeholder; enriched later by analysis
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "published": published,
        "last_modified": last_modified,
        "references": ref_urls,
        "affected_products": affected_products,
        # Fields below are populated during analysis (Phase 2+)
        "source_file": "",
        "vulnerable_code": "",
        "patched_code": "",
        "diff": "",
    }


_CWE_MAP: dict[str, str] = {
    "CWE-79": "cross-site-scripting",
    "CWE-89": "sql-injection",
    "CWE-78": "os-command-injection",
    "CWE-22": "path-traversal",
    "CWE-120": "buffer-overflow",
    "CWE-787": "out-of-bounds-write",
    "CWE-125": "out-of-bounds-read",
    "CWE-416": "use-after-free",
    "CWE-415": "double-free",
    "CWE-476": "null-pointer-dereference",
    "CWE-190": "integer-overflow",
    "CWE-191": "integer-underflow",
    "CWE-200": "information-exposure",
    "CWE-287": "improper-authentication",
    "CWE-862": "missing-authorization",
    "CWE-502": "insecure-deserialization",
    "CWE-611": "xxe-injection",
    "CWE-918": "ssrf",
    "CWE-352": "csrf",
    "CWE-434": "unrestricted-file-upload",
    "CWE-601": "open-redirect",
    "CWE-94": "code-injection",
    "CWE-327": "weak-crypto",
    "CWE-798": "hard-coded-credentials",
    "CWE-400": "resource-exhaustion",
    "CWE-367": "race-condition",
    "CWE-269": "improper-privilege-management",
    "CWE-639": "idor",
    "CWE-1333": "redos",
}


def _cwe_to_vuln_type(cwe_id: str) -> str:
    """Map a CWE ID to a human-readable vulnerability type label."""
    return _CWE_MAP.get(cwe_id, "other")


# ---------------------------------------------------------------------------
# NVD API Client
# ---------------------------------------------------------------------------

class NVDCollector:
    """Fetches CVEs from the NVD REST API 2.0 with date-range filtering
    and deduplication against the local corpus."""

    def __init__(
        self,
        corpus_dir: str | Path = "data/cve_corpus",
        api_key: str | None = None,
    ):
        self.corpus_dir = Path(corpus_dir)
        self.corpus_dir.mkdir(parents=True, exist_ok=True)
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self.delay = (
            RATE_LIMIT_DELAY_WITH_KEY if self.api_key else RATE_LIMIT_DELAY_NO_KEY
        )
        self._existing_ids: set[str] | None = None

    @property
    def existing_ids(self) -> set[str]:
        if self._existing_ids is None:
            self._existing_ids = _get_existing_cve_ids(self.corpus_dir)
            logger.info(
                "Found %d existing CVEs in %s", len(self._existing_ids), self.corpus_dir
            )
        return self._existing_ids

    def collect(
        self,
        start_date: str | datetime,
        end_date: str | datetime,
        keyword: str | None = None,
        cwe_filter: list[str] | None = None,
        cvss_min: float | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch CVEs published between *start_date* and *end_date*.

        Ranges exceeding 120 days are automatically split into consecutive
        windows (NVD API limitation).

        Args:
            start_date: Start of date range (YYYY-MM-DD or datetime).
            end_date: End of date range (YYYY-MM-DD or datetime).
            keyword: Optional keyword search (matched against description).
            cwe_filter: Optional list of CWE IDs to keep (e.g. ["CWE-79", "CWE-89"]).
            cvss_min: Optional minimum CVSS base score.

        Returns:
            List of newly saved CVE entries.
        """
        if isinstance(start_date, str):
            start_date = _parse_date(start_date)
        if isinstance(end_date, str):
            end_date = _parse_date(end_date)

        logger.info(
            "Collecting CVEs from %s to %s (keyword=%s, cwe_filter=%s, cvss_min=%s)",
            start_date.strftime("%Y-%m-%d"),
            end_date.strftime("%Y-%m-%d"),
            keyword,
            cwe_filter,
            cvss_min,
        )

        # Split into <= 120-day windows (NVD API rejects larger ranges)
        windows: list[tuple[datetime, datetime]] = []
        win_start = start_date
        while win_start < end_date:
            win_end = min(win_start + timedelta(days=NVD_MAX_RANGE_DAYS), end_date)
            windows.append((win_start, win_end))
            win_start = win_end

        if len(windows) > 1:
            logger.info(
                "Date range is %d days — splitting into %d windows of ≤%d days each",
                (end_date - start_date).days,
                len(windows),
                NVD_MAX_RANGE_DAYS,
            )

        new_entries: list[dict[str, Any]] = []

        with httpx.Client(timeout=60.0) as client:
            for win_idx, (win_start, win_end) in enumerate(windows):
                if len(windows) > 1:
                    logger.info(
                        "Window %d/%d: %s → %s",
                        win_idx + 1, len(windows),
                        win_start.strftime("%Y-%m-%d"),
                        win_end.strftime("%Y-%m-%d"),
                    )
                window_entries = self._fetch_window(
                    client, win_start, win_end,
                    keyword=keyword, cwe_filter=cwe_filter, cvss_min=cvss_min,
                )
                new_entries.extend(window_entries)

        logger.info("Collection complete: %d new CVEs saved", len(new_entries))
        return new_entries

    def _fetch_window(
        self,
        client: httpx.Client,
        start_date: datetime,
        end_date: datetime,
        keyword: str | None = None,
        cwe_filter: list[str] | None = None,
        cvss_min: float | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch a single <= 120-day window of CVEs with pagination."""
        params: dict[str, Any] = {
            "pubStartDate": _nvd_datetime(start_date),
            "pubEndDate": _nvd_datetime(end_date),
            "resultsPerPage": RESULTS_PER_PAGE,
        }
        if keyword:
            params["keywordSearch"] = keyword

        headers: dict[str, str] = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        new_entries: list[dict[str, Any]] = []
        start_index = 0
        total_results = None

        while True:
            params["startIndex"] = start_index
            logger.info("Fetching page startIndex=%d ...", start_index)

            resp = client.get(NVD_API_BASE, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()

            if total_results is None:
                total_results = data.get("totalResults", 0)
                logger.info("Total CVEs matching query: %d", total_results)

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break

            for vuln in vulnerabilities:
                entry = _extract_cve_entry(vuln)
                if entry is None:
                    continue

                cve_id = entry["cve_id"]

                # --- Dedup: skip if already exists locally ---
                if cve_id in self.existing_ids:
                    logger.debug("Skipping %s (already exists)", cve_id)
                    continue

                # --- CWE filter ---
                if cwe_filter:
                    entry_cwes = set(entry.get("cwe_ids", []))
                    if not entry_cwes.intersection(set(cwe_filter)):
                        continue

                # --- CVSS filter ---
                if cvss_min is not None:
                    score = entry.get("cvss_score")
                    if score is None or score < cvss_min:
                        continue

                # --- Save ---
                self._save_entry(entry)
                new_entries.append(entry)
                self.existing_ids.add(cve_id)

            start_index += len(vulnerabilities)
            if start_index >= total_results:
                break

            # Rate limiting
            time.sleep(self.delay)

        return new_entries

    def _save_entry(self, entry: dict[str, Any]) -> Path:
        """Write a CVE entry to the corpus directory as JSON."""
        cve_id = entry["cve_id"]
        filename = f"{cve_id}.json"
        filepath = self.corpus_dir / filename

        with open(filepath, "w") as f:
            json.dump(entry, f, indent=2, ensure_ascii=False)

        logger.info("Saved %s", filepath)
        return filepath


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect CVEs from NVD API and save to local corpus."
    )
    parser.add_argument(
        "--start-date",
        required=True,
        help="Start date for CVE collection (YYYY-MM-DD)",
    )
    parser.add_argument(
        "--end-date",
        required=True,
        help="End date for CVE collection (YYYY-MM-DD)",
    )
    parser.add_argument(
        "--keyword",
        default=None,
        help="Optional keyword to filter CVEs (matched against description)",
    )
    parser.add_argument(
        "--cwe",
        default=None,
        help="Comma-separated CWE IDs to filter (e.g. CWE-79,CWE-89)",
    )
    parser.add_argument(
        "--cvss-min",
        type=float,
        default=None,
        help="Minimum CVSS base score (e.g. 7.0)",
    )
    parser.add_argument(
        "--config",
        default="config/settings.yaml",
        help="Path to settings.yaml (default: config/settings.yaml)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Load config
    config_path = Path(args.config)
    if config_path.exists():
        with open(config_path) as f:
            cfg = yaml.safe_load(f).get("collector", {})
    else:
        cfg = {}

    corpus_dir = cfg.get("corpus_path", "data/cve_corpus")
    api_key = cfg.get("api_key") or os.environ.get("NVD_API_KEY")

    cwe_filter = None
    if args.cwe:
        cwe_filter = [c.strip() for c in args.cwe.split(",")]

    collector = NVDCollector(corpus_dir=corpus_dir, api_key=api_key)
    new_entries = collector.collect(
        start_date=args.start_date,
        end_date=args.end_date,
        keyword=args.keyword,
        cwe_filter=cwe_filter,
        cvss_min=args.cvss_min,
    )

    print(f"\nDone. {len(new_entries)} new CVEs collected.")
    if new_entries:
        print("New CVE IDs:")
        for entry in new_entries[:20]:
            score = entry.get("cvss_score", "N/A")
            print(f"  {entry['cve_id']}  [{entry['cwe_id']}]  CVSS={score}")
        if len(new_entries) > 20:
            print(f"  ... and {len(new_entries) - 20} more")


if __name__ == "__main__":
    main()
