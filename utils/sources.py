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
import re
import time
import xml.etree.ElementTree as ET
from urllib.parse import quote

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


def norm(text):
    """'Notepad++' -> 'notepad', 'Adobe Acrobat Reader' -> 'adobeacrobatreader'."""
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


def _words(text):
    return set(re.findall(r"[a-z0-9]+", (text or "").lower()))


@st.cache_data(ttl=86400, show_spinner=False)
def load_homebrew_index():
    """All Homebrew casks (~7k desktop apps) as {token: {names, version, homepage}}."""
    data, err = _get("https://formulae.brew.sh/api/cask.json")
    if err:
        return {"error": err}
    return {c["token"]: {"names": c.get("name") or [], "version": c.get("version"),
                         "homepage": c.get("homepage")} for c in data if c.get("token")}


def find_homebrew_cask(token, name):
    """Look up a cask by token, else by product name. Returns (token, entry, method) or None."""
    index = load_homebrew_index()
    if index.get("error"):
        return {"error": index["error"]}
    if token and token in index:
        return token, index[token], "token"
    wanted, wanted_words = norm(name), _words(name)
    if not wanted:
        return None
    exact = [t for t, c in index.items() if wanted in {norm(t), *map(norm, c["names"])}]
    if exact:
        return exact[0], index[exact[0]], "name"
    # every word typed appears in the cask name, e.g. "adobe reader" -> "Adobe Acrobat Reader"
    subset = [(len(n), t) for t, c in index.items() for n in c["names"] if wanted_words <= _words(n)]
    if subset:
        t = min(subset)[1]
        return t, index[t], "partial name"
    return None


def fetch_homebrew_cask(token, name=None):
    found = find_homebrew_cask(token, name)
    if not found or isinstance(found, dict):
        return found
    token, cask, method = found
    return {
        "source": f"Homebrew cask '{token}' (macOS vendor download, matched by {method})",
        "url": cask.get("homepage") or f"https://formulae.brew.sh/cask/{token}",
        "version": (cask.get("version") or "").split(",")[0],
        "release_date": None,
    }


@st.cache_data(ttl=3600, show_spinner=False)
def fetch_chocolatey(package_id):
    """Latest approved version of a Windows package on the Chocolatey community repository."""
    if not package_id:
        return None
    # OData query built by hand so spaces become %20 (not '+')
    odata_filter = quote(f"Id eq '{package_id}' and IsLatestVersion", safe="'")
    url = f"https://community.chocolatey.org/api/v2/Packages()?$filter={odata_filter}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        r.raise_for_status()
        root = ET.fromstring(r.content)
    except (requests.RequestException, ET.ParseError) as e:
        return {"error": str(e)}
    props = {el.tag.split("}")[-1]: el.text for el in root.iter() if el.tag.endswith(("}Version", "}Published"))}
    if not props.get("Version"):
        return {"error": "not found"}
    return {
        "source": "Chocolatey (Windows package)",
        "url": f"https://community.chocolatey.org/packages/{package_id}",
        "version": props["Version"],
        "release_date": (props.get("Published") or "")[:10] or None,
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


def cpe_escape(value):
    """CPE 2.3 formatted strings escape everything except letters, digits, '_', '-' and '.'."""
    return re.sub(r"([^A-Za-z0-9_.\-])", r"\\\1", value)


@st.cache_data(ttl=86400, show_spinner=False)
def resolve_cpe(vendor, product, keyword):
    """Confirm the NVD CPE vendor:product for the software.

    1. exact vendor:product (as suggested by the LLM)
    2. keyword search of the official CPE dictionary, choosing the product whose
       name matches what was asked for ("keyword-confirmed"), else the best partial match.
    Returns {"vendor", "product", "title", "method"} or {"error"}.
    """
    last_err = "no identifiers to search"
    if vendor and product:
        v, p = cpe_escape(vendor.replace("\\", "")), cpe_escape(product.replace("\\", ""))
        data, err = _nvd_get(NVD_CPE_URL, {"cpeMatchString": f"cpe:2.3:a:{v}:{p}", "resultsPerPage": 5})
        last_err = err or last_err
        for c in _cpe_candidates(data):
            return {**c, "method": "exact"}
    if keyword:
        data, err = _nvd_get(NVD_CPE_URL, {"keywordSearch": keyword, "resultsPerPage": 200})
        last_err = err or "no matching CPE in the NVD dictionary"
        targets = {norm(keyword), norm(product)} - {""}
        words = _words(keyword)
        best, best_score = None, 0
        for c in _cpe_candidates(data):
            name = c["product"].replace("\\", "")
            score = 3 if norm(name) in targets else 1 if words <= _words(name.replace("_", " ") + " " + c["vendor"]) else 0
            if score > best_score:
                best, best_score = c, score
        if best:
            return {**best, "method": "keyword-confirmed" if best_score == 3 else "keyword"}
    return {"error": last_err}


def _cpe_candidates(data):
    """Distinct non-deprecated application vendor:product pairs from a CPE API response."""
    seen = set()
    for p in (data or {}).get("products", []):
        cpe = p.get("cpe", {})
        if cpe.get("deprecated"):
            continue
        parts = re.split(r"(?<!\\):", cpe.get("cpeName", ""))  # ':' not preceded by '\'
        if len(parts) < 6 or parts[2] != "a" or (parts[3], parts[4]) in seen:
            continue
        seen.add((parts[3], parts[4]))
        titles = cpe.get("titles") or [{}]
        title = next((t["title"] for t in titles if t.get("lang") == "en"), titles[0].get("title"))
        yield {"vendor": parts[3], "product": parts[4], "title": title}


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
