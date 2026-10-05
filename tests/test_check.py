"""Offline tests: mocked official-source responses (no network, no OpenAI key needed)."""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import pytest
from utils import sources, assess

EOL = {"result": {"label": "Python", "links": {"releasePolicy": "x"}, "releases": [
    {"name": "3.13", "releaseDate": "2024-10-07", "isEol": False, "eolFrom": "2029-10-31", "isMaintained": True,
     "latest": {"name": "3.13.7", "date": "2025-08-14", "link": "https://www.python.org/downloads/release/python-3137/"}},
    {"name": "3.8", "releaseDate": "2019-10-14", "isEol": True, "eolFrom": "2024-10-07", "isMaintained": False,
     "latest": {"name": "3.8.20", "date": "2024-09-06", "link": None}}]}}
CPE = {"products": [{"cpe": {"cpeName": "cpe:2.3:a:python:python:3.8.0:*:*:*:*:*:*:*", "deprecated": False,
                             "titles": [{"title": "Python 3.8.0", "lang": "en"}]}}]}
def cve(i, score, v="cvssMetricV31"):
    return {"cve": {"id": i, "published": "2024-01-01T00:00:00", "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "en", "value": "desc " + i}],
                    "metrics": {v: [{"cvssData": {"baseScore": score, "baseSeverity": "CRITICAL" if score >= 9 else "HIGH"}}]}}}
CVES_OLD = {"totalResults": 2, "vulnerabilities": [cve("CVE-2023-0001", 9.8), cve("CVE-2023-0002", 7.5)]}
CVES_NEW = {"totalResults": 0, "vulnerabilities": []}
KEV = {"vulnerabilities": [{"cveID": "CVE-2023-0001", "dateAdded": "2024-02-01", "vendorProject": "Python"}]}
calls = []

def fake_get(url, params=None, headers=None):
    calls.append((url, params))
    if "endoflife" in url: return EOL, None
    if "cpes/2.0" in url: return CPE, None
    if "cves/2.0" in url:
        return (CVES_OLD if params["virtualMatchString"].endswith(":3.8.10") else CVES_NEW), None
    if "known_exploited" in url: return KEV, None
    return None, "not found"

@pytest.fixture(autouse=True)
def mock(monkeypatch):
    calls.clear()
    monkeypatch.setattr(sources, "_get", fake_get)
    monkeypatch.setattr(sources.time, "sleep", lambda s: None)
    def no_network(*a, **k): raise sources.requests.ConnectionError("offline test")
    monkeypatch.setattr(sources.requests, "get", no_network)   # chocolatey
    monkeypatch.setattr(sources.requests, "post", no_network)  # osv
    for f in ("fetch_endoflife","fetch_github_latest","fetch_pypi","fetch_npm",
              "resolve_cpe","fetch_nvd_cves","load_kev","fetch_osv","load_homebrew_index","fetch_chocolatey"):
        getattr(sources, f).clear()

REQ = {"software_name": "Python", "requested_version": "3.8.10", "platform": "Windows", "purpose": "scripts"}
OV = {"cpe_vendor": "python", "cpe_product": "python", "endoflife_slug": "python"}

def test_old_version_is_high_risk():
    f = assess.run_check(REQ, overrides=OV, progress=lambda m: None)
    assert f["latest"]["version"] == "3.13.7" and f["latest"]["source"] == "endoflife.date"
    assert f["outdated"] is True
    assert f["eol_cycle"]["cycle"] == "3.8" and f["eol_cycle"]["is_eol"]
    assert [k["cveID"] for k in f["kev_hits"]] == ["CVE-2023-0001"]
    assert f["cves_requested"]["cves"][0]["score"] == 9.8
    assert f["cves_latest"]["total"] == 0
    assert f["risk"]["level"] == "High"
    assert f["summary"] is None  # no OpenAI key -> no AI summary
    assert f["cpe"]["method"] == "exact"

def test_latest_version_is_low_risk():
    f = assess.run_check({**REQ, "requested_version": ""}, overrides=OV, progress=lambda m: None)
    assert f["target_version"] == "3.13.7" and f["outdated"] is None
    assert f["risk"]["level"] == "Low", f["risk"]
    assert f["cves_latest"] is None

def test_unknown_product_is_unverified(monkeypatch):
    monkeypatch.setattr(sources, "_get", lambda *a, **k: (None, "not found") if "known" not in a[0] else (KEV, None))
    f = assess.run_check({**REQ, "software_name": "ObscureTool"}, progress=lambda m: None)
    assert f["risk"]["level"] == "Unverified" and len(f["risk"]["caveats"]) == 2

def test_version_helpers():
    assert assess.is_outdated("1.9", "1.10") is True
    assert assess.is_outdated("v2.0", "2.0") is False
    assert assess.find_cycle([{"cycle": "3.1"}, {"cycle": "3.12"}], "3.12.4")["cycle"] == "3.12"
    assert sources._parse_cve({"cve": {"id": "X", "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}]}}})["severity"] == "MEDIUM"

def test_llm_path(monkeypatch):
    from utils import llm
    import json
    monkeypatch.setattr(llm, "llm_available", lambda: True)
    prompts = []
    def fake_completion(prompt, system=None, json_mode=False):
        prompts.append(prompt)
        if json_mode:
            return json.dumps({"display_name": "Python", "cpe_vendor": "python", "cpe_product": "python",
                               "endoflife_slug": "python", "extra": "ignored"})
        return "**Recommendation**: Reject"
    monkeypatch.setattr(llm, "get_completion", fake_completion)
    f = assess.run_check(REQ, progress=lambda m: None)
    assert f["identity"]["cpe_vendor"] == "python" and "extra" not in f["identity"]
    assert f["summary"].startswith("**Recommendation")
    assert "CVE-2023-0001" in prompts[1] and "<findings>" in prompts[1]


# ---- standard closed-source apps (Adobe Reader style) -------------------------------
BREW = [{"token": "adobe-acrobat-reader", "name": ["Adobe Acrobat Reader"], "version": "25.001.20756",
         "homepage": "https://www.adobe.com/acrobat/pdf-reader.html"},
        {"token": "adobe-acrobat-pro", "name": ["Adobe Acrobat Pro DC"], "version": "25.001.20756", "homepage": None},
        {"token": "notepadnext", "name": ["NotepadNext"], "version": "0.8", "homepage": None}]
CPE_KW = {"products": [
    {"cpe": {"cpeName": "cpe:2.3:a:adobe:acrobat_reader_dc:15.006.30033:*:*:*:classic:*:*:*", "deprecated": False,
             "titles": [{"title": "Adobe Acrobat Reader DC 15.006.30033", "lang": "en"}]}},
    {"cpe": {"cpeName": "cpe:2.3:a:notepad-plus-plus:notepad\\+\\+:8.6:*:*:*:*:*:*:*", "deprecated": False,
             "titles": [{"title": "Notepad++ 8.6", "lang": "en"}]}}]}

def fake_get2(url, params=None, headers=None):
    calls.append((url, params))
    if url.endswith("cask.json"): return BREW, None
    if "cpes/2.0" in url:
        return (CPE_KW, None) if "keywordSearch" in params else ({"products": []}, None)
    if "cves/2.0" in url:
        if params["virtualMatchString"].endswith(":25.001.20756"):
            return {"totalResults": 1, "vulnerabilities": [cve("CVE-2025-1111", 7.8)]}, None
        return CVES_OLD, None  # product-wide history
    if "known_exploited" in url: return KEV, None
    return None, "not found"

def test_closed_source_app_found_via_homebrew_name(monkeypatch):
    monkeypatch.setattr(sources, "_get", fake_get2)
    monkeypatch.setattr(sources, "fetch_chocolatey", lambda i: {"error": "not found"})
    f = assess.run_check({"software_name": "Adobe Reader", "requested_version": "", "platform": "Windows",
                          "purpose": "pdf"}, progress=lambda m: None)
    assert f["latest"]["version"] == "25.001.20756" and "adobe-acrobat-reader" in f["latest"]["source"]
    assert f["cpe"]["product"] == "acrobat_reader_dc" and f["cpe"]["method"] == "keyword"
    assert f["target_version"] == "25.001.20756"
    assert f["risk"]["level"] == "Medium"            # one high CVE on the latest build
    assert any("macOS build" in c for c in f["risk"]["caveats"])

def test_no_version_known_is_not_high(monkeypatch):
    monkeypatch.setattr(sources, "_get", lambda u, params=None, headers=None:
                        fake_get2(u, params) if "nist" in u or "known_exploited" in u else (None, "not found"))
    monkeypatch.setattr(sources, "fetch_chocolatey", lambda i: None)
    f = assess.run_check({"software_name": "Adobe Reader", "requested_version": "", "platform": "Windows",
                          "purpose": "pdf"}, progress=lambda m: None)
    assert f["target_version"] is None
    assert f["risk"]["level"] == "Unverified" and not f["risk"]["reasons"]
    assert any("ALL historical versions" in c for c in f["risk"]["caveats"])

def test_cpe_special_chars(monkeypatch):
    monkeypatch.setattr(sources, "_get", fake_get2)
    r = sources.resolve_cpe("notepad-plus-plus", "notepad++", "Notepad++")
    assert r == {"vendor": "notepad-plus-plus", "product": "notepad\\+\\+", "title": "Notepad++ 8.6",
                 "method": "keyword-confirmed"}
    exact_query = [p for u, p in calls if p and "cpeMatchString" in p][0]["cpeMatchString"]
    assert exact_query == "cpe:2.3:a:notepad-plus-plus:notepad\\+\\+"

def test_chocolatey_xml(monkeypatch):
    xml = b'''<feed xmlns="http://www.w3.org/2005/Atom" xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices"
      xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata"><entry><m:properties>
      <d:Version>2025.001.20756</d:Version><d:Published>2025-09-10T12:00:00</d:Published></m:properties></entry></feed>'''
    class R:
        content = xml
        def raise_for_status(self): pass
    monkeypatch.setattr(sources.requests, "get", lambda *a, **k: R())
    r = sources.fetch_chocolatey("adobereader")
    assert r["version"] == "2025.001.20756" and r["release_date"] == "2025-09-10"
