"""Lookups against official / authoritative sources.

Every function returns plain data (or {"error": ...}) and never raises, so one
unreachable source does not break the whole check. Version numbers and CVEs in
this app ONLY come from here - never from the LLM.

Sources:
  - endoflife.date            release cycles + latest patch, links to vendor release notes
  - GitHub Releases API       latest release of the project's official repository
  - PyPI / npm registries     official package registries
  - Homebrew cask API         tracks the vendor's download for macOS apps
  - NIST NVD CPE + CVE API 2.0
  - CISA Known Exploited Vulnerabilities (KEV) catalog
  - OSV.dev                   vulnerabilities for PyPI / npm packages
"""
import time

import requests
import streamlit as st

from utils.utility import get_secret

TIMEOUT = 20
HEADERS = {"User-Agent": "software-request-checker/1.0"}

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _get(url, params=None, headers=None):
    """GET JSON. Returns (data, error)."""
    try:
        r = requests.get(url, params=params, headers={**HEADERS, **(headers or {})}, timeout=TIMEOUT)
        if r.status_code == 404:
            return None, "not found"
        r.raise_for_status()
        return r.json(), None
    except requests.RequestException as e:
        return None, str(e)
    except ValueError:
        return None, "invalid JSON response"


# ---------------------------------------------------------------- latest version sources

@st.cache_data(ttl=3600, show_spinner=False)
def fetch_endoflife(slug):
    """Release cycles for a product on endoflife.date (v1 API)."""
    if not slug:
        return None
    data, err = _get(f"https://endoflife.date/api/v1/products/{slug}/")
    if err:
        return {"error": err}
    result = data.get("result", {})
    releases = []
    for r in result.get("releases", []):
        latest = r.get("latest") or {}
        releases.append({
            "cycle": r.get("name"),
            "release_date": r.get("releaseDate"),
            "is_eol": r.get("isEol"),
            "eol_date": r.get("eolFrom"),
            "is_maintained": r.get("isMaintained"),
            "latest": latest.get("name"),
            "latest_date": latest.get("date"),
            "latest_link": latest.get("link"),
        })
    return {
        "source": "endoflife.date",
        "url": f"https://endoflife.date/{slug}",
        "label": result.get("label"),
        "release_policy": (result.get("links") or {}).get("releasePolicy"),
        "releases": releases,  # newest cycle first
    }


@st.cache_data(ttl=3600, show_spinner=False)
def fetch_github_latest(repo):
    """Latest (non-prerelease) release of an official GitHub repo, e.g. 'notepad-plus-plus/notepad-plus-plus'."""
    if not repo or "/" not in repo:
        return None
    token = get_secret("GITHUB_TOKEN")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data, err = _get(f"https://api.github.com/repos/{repo}/releases/latest", headers=headers)
    if err:
        return {"error": err}
    return {
        "source": "GitHub Releases",
        "url": data.get("html_url") or f"https://github.com/{repo}/releases",
        "version": (data.get("tag_name") or "").lstrip("vV"),
        "release_date": (data.get("published_at") or "")[:10],
    }


@st.cache_data(ttl=3600, show_spinner=False)
def fetch_pypi(package):
    if not package:
        return None
    data, err = _get(f"https://pypi.org/pypi/{package}/json")
    if err:
        return {"error": err}
    info = data.get("info", {})
    version = info.get("version")
    files = data.get("releases", {}).get(version) or []
    return {
        "source": "PyPI",
        "url": f"https://pypi.org/project/{package}/",
        "version": version,
        "release_date": files[0]["upload_time"][:10] if files else None,
    }


@st.cache_data(ttl=3600, show_spinner=False)
def fetch_npm(package):
    if not package:
        return None
    data, err = _get(f"https://registry.npmjs.org/{package}")
    if err:
        return {"error": err}
    version = (data.get("dist-tags") or {}).get("latest")
    return {
        "source": "npm registry",
        "url": f"https://www.npmjs.com/package/{package}",
        "version": version,
        "release_date": ((data.get("time") or {}).get(version) or "")[:10] or None,
    }


@st.cache_data(ttl=3600, show_spinner=False)
def fetch_homebrew_cask(token):
    if not token:
        return None
    data, err = _get(f"https://formulae.brew.sh/api/cask/{token}.json")
    if err:
        return {"error": err}
    return {
        "source": "Homebrew cask (vendor download)",
        "url": data.get("homepage") or f"https://formulae.brew.sh/cask/{token}",
        "version": (data.get("version") or "").split(",")[0],
        "release_date": None,
    }


# ---------------------------------------------------------------- NVD (NIST)

_last_nvd_call = [0.0]


def _nvd_get(url, params):
    """NVD allows 5 requests / 30 s without an API key (50 with one) - throttle accordingly."""
    api_key = get_secret("NVD_API_KEY")
    gap = 0.7 if api_key else 6.5
    wait = _last_nvd_call[0] + gap - time.time()
    if wait > 0:
        time.sleep(wait)
    headers = {"apiKey": api_key} if api_key else None
    data, err = _get(url, params=params, headers=headers)
    if err and ("403" in err or "429" in err or "503" in err):  # rate limited - one retry
        time.sleep(10)
        data, err = _get(url, params=params, headers=headers)
    _last_nvd_call[0] = time.time()
    return data, err


@st.cache_data(ttl=86400, show_spinner=False)
def resolve_cpe(vendor, product, keyword):
    """Confirm the NVD CPE vendor:product for the software.

    Tries the exact vendor:product first (as suggested by the LLM), then falls
    back to a keyword search of the official CPE dictionary.
    Returns {"vendor", "product", "title", "method"} or {"error"}.
    """
    attempts = []
    if vendor and product:
        attempts.append(("exact", {"cpeMatchString": f"cpe:2.3:a:{vendor}:{product}", "resultsPerPage": 5}))
    if keyword:
        attempts.append(("keyword", {"keywordSearch": keyword, "resultsPerPage": 20}))

    last_err = "no identifiers to search"
    for method, params in attempts:
        data, err = _nvd_get(NVD_CPE_URL, params)
        if err:
            last_err = err
            continue
        for p in data.get("products", []):
            cpe = p.get("cpe", {})
            if cpe.get("deprecated"):
                continue
            parts = cpe.get("cpeName", "").split(":")
            if len(parts) < 6 or parts[2] != "a":  # applications only
                continue
            titles = cpe.get("titles") or [{}]
            title = next((t["title"] for t in titles if t.get("lang") == "en"), titles[0].get("title"))
            return {"vendor": parts[3], "product": parts[4], "title": title, "method": method}
        last_err = "no matching CPE in the NVD dictionary"
    return {"error": last_err}


def _parse_cve(item):
    cve = item.get("cve", {})
    metrics = cve.get("metrics", {})
    score, severity, cvss_version = None, None, None
    for key, ver in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
                     ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        if metrics.get(key):
            m = metrics[key][0]
            data = m.get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or m.get("baseSeverity")
            cvss_version = ver
            break
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    return {
        "id": cve.get("id"),
        "published": (cve.get("published") or "")[:10],
        "score": score,
        "severity": severity,
        "cvss_version": cvss_version,
        "status": cve.get("vulnStatus"),
        "description": desc,
        "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}",
    }


@st.cache_data(ttl=21600, show_spinner=False)
def fetch_nvd_cves(vendor, product, version=None, max_results=2000):
    """CVEs whose NVD configuration matches vendor:product[:version] (version ranges included)."""
    match = f"cpe:2.3:a:{vendor}:{product}"
    if version:
        match += f":{version}"
    params = {"virtualMatchString": match, "resultsPerPage": max_results}
    data, err = _nvd_get(NVD_CVE_URL, params)
    if err:
        return {"error": err, "match": match}
    total = data.get("totalResults", 0)
    items = data.get("vulnerabilities", [])
    if total > max_results:  # results are oldest-first; fetch the newest page instead
        data, err = _nvd_get(NVD_CVE_URL, {**params, "startIndex": total - max_results})
        if not err:
            items = data.get("vulnerabilities", [])
    cves = [c for c in (_parse_cve(i) for i in items) if c["status"] != "Rejected"]
    cves.sort(key=lambda c: (c["score"] or 0, c["published"]), reverse=True)
    return {
        "source": "NIST NVD",
        "match": match,
        "url": requests.Request("GET", NVD_CVE_URL, params=params).prepare().url,  # reproducible query
        "total": total,
        "cves": cves,
    }


# ---------------------------------------------------------------- CISA KEV

@st.cache_data(ttl=43200, show_spinner=False)
def load_kev():
    """CISA Known Exploited Vulnerabilities catalog as {cveID: entry}."""
    data, err = _get(KEV_URL)
    if err:
        return {"error": err}
    return {v["cveID"]: v for v in data.get("vulnerabilities", [])}


# ---------------------------------------------------------------- OSV (packages)

@st.cache_data(ttl=21600, show_spinner=False)
def fetch_osv(ecosystem, package, version):
    """Known vulnerabilities for a package version (ecosystem: 'PyPI' or 'npm')."""
    if not (ecosystem and package and version):
        return None
    try:
        r = requests.post("https://api.osv.dev/v1/query", headers=HEADERS, timeout=TIMEOUT,
                          json={"package": {"name": package, "ecosystem": ecosystem}, "version": version})
        r.raise_for_status()
        vulns = r.json().get("vulns", [])
    except (requests.RequestException, ValueError) as e:
        return {"error": str(e)}
    return {
        "source": "OSV.dev",
        "url": f"https://osv.dev/list?ecosystem={ecosystem}&q={package}",
        "vulns": [{"id": v.get("id"), "aliases": v.get("aliases", []),
                   "summary": v.get("summary") or (v.get("details") or "")[:200],
                   "url": f"https://osv.dev/vulnerability/{v.get('id')}"} for v in vulns],
    }
