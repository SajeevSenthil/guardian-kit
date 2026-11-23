# EPSS and CISA KEV (probed 2026-11-23)

## EPSS (FIRST.org)

- Request: `GET https://api.first.org/data/v1/epss?cve=CVE-2019-10744,CVE-2018-16487` (comma list).
- Response: `{"status":"OK","total":N,"limit":100,"data":[{"cve","epss","percentile","date"}]}`.
  `epss` and `percentile` are **strings** ("0.050060000"); parse to float.
- At most 100 CVEs per request (`limit: 100`); batch accordingly.
- A CVE with no score is simply absent from `data`: treat as unknown, never 0.
- Observed: CVE-2019-10744 (lodash) epss 0.05006, percentile 0.92447; CVE-2018-16487 epss 0.01491.
- Fixture: `tests/fixtures/epss/sample.json`.

## CISA Known Exploited Vulnerabilities

- Request: `GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
  (one file, ~1.5 MB).
- Top-level keys: `title`, `catalogVersion`, `dateReleased`, `count`, `vulnerabilities[]`.
- Each entry: `cveID`, `vendorProject`, `product`, `vulnerabilityName`, `dateAdded`,
  `shortDescription`, `requiredAction`, `dueDate`, `knownRansomwareCampaignUse`, `notes`, `cwes`.
- Observed: catalogVersion 2026.11.23, 1,790 entries. **CVE-2025-30066 (tj-actions/changed-files)
  is listed**; CVE-2019-10744 (lodash) is not.
- Fixture: `tests/fixtures/kev/sample.trimmed.json` (header + two entries).

## How Guardian uses them

`guardian/enrich.py` caches both under `.cache/enrich/` with the fetch time. Offline with no
cache: EPSS and KEV are `None` (unknown), and scoring uses the stated prior.
