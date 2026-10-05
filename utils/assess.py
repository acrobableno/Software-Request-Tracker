"""Orchestrates the check for one request (prompt chaining: identify -> fetch -> rules -> summarise)."""
from datetime import datetime

from packaging.version import InvalidVersion, Version

from utils import llm, sources


def _parse(v):
    try:
        return Version(str(v).lstrip("vV"))
    except (InvalidVersion, TypeError):
        return None


def is_outdated(requested, latest):
    """True / False, or None if the versions can't be compared."""
    a, b = _parse(requested), _parse(latest)
    if a is None or b is None:
        return None if str(requested).lstrip("vV") != str(latest).lstrip("vV") else False
    return a < b


def find_cycle(releases, version):
    """The endoflife.date release cycle a version belongs to, e.g. '3.12' for '3.12.4'."""
    if not version:
        return None
    v = str(version).lstrip("vV")
    matches = [r for r in releases if r["cycle"] and (v == r["cycle"] or v.startswith(r["cycle"] + "."))]
    return max(matches, key=lambda r: len(r["cycle"]), default=None)


def pick_latest(latest_sources):
    """First successful source in priority order wins; others are kept for cross-checking."""
    for s in latest_sources:
        if s and not s.get("error") and s.get("version"):
            return s
    return None


def rate_risk(findings):
    """Deterministic, explainable rules - the LLM does not decide the risk level."""
    reasons_high, reasons_med = [], []
    target = findings["target_version"]
    cves = (findings.get("cves_requested") or {}).get("cves") or []

    if findings.get("kev_hits"):
        reasons_high.append(f"{len(findings['kev_hits'])} CVE(s) are in the CISA Known Exploited Vulnerabilities catalog")
    critical = [c for c in cves if (c["score"] or 0) >= 9.0]
    high = [c for c in cves if 7.0 <= (c["score"] or 0) < 9.0]
    if critical:
        reasons_high.append(f"{len(critical)} critical CVE(s) (CVSS ≥ 9.0) affect version {target or '(any)'}")
    if high:
        reasons_med.append(f"{len(high)} high CVE(s) (CVSS 7.0–8.9) affect version {target or '(any)'}")
    osv = (findings.get("osv") or {}).get("vulns") or []
    if osv:
        reasons_med.append(f"{len(osv)} known vulnerability(ies) in OSV.dev for this package version")

    cycle = findings.get("eol_cycle")
    if cycle and cycle.get("is_eol"):
        reasons_high.append(f"Release cycle {cycle['cycle']} is end-of-life (since {cycle.get('eol_date')})")

    if findings.get("outdated"):
        reasons_med.append(f"Requested version {target} is older than latest {findings['latest']['version']}")

    unverified = []
    if not findings.get("latest"):
        unverified.append("latest version could not be confirmed from an official source")
    if (findings.get("cpe") or {}).get("error"):
        unverified.append("product not found in the NVD CPE dictionary - vulnerability check incomplete")
    if (findings.get("cpe") or {}).get("method") == "keyword":
        unverified.append("NVD product was matched by keyword - confirm it is the right product")

    if reasons_high:
        level = "High"
    elif reasons_med:
        level = "Medium"
    elif unverified:
        level = "Unverified"
    else:
        level = "Low"
    return {"level": level, "reasons": reasons_high + reasons_med, "caveats": unverified}


def run_check(request, overrides=None, progress=print):
    """Run all lookups for a request dict (from the DB). `overrides` lets a reviewer fix identifiers."""
    name = request["software_name"]
    requested = (request.get("requested_version") or "").strip().lstrip("vV") or None

    progress("Identifying software…")
    identity = llm.identify_software(name, request.get("platform"))
    identity.update({k: v for k, v in (overrides or {}).items() if v})

    progress("Checking official sources for the latest version…")
    eol = sources.fetch_endoflife(identity.get("endoflife_slug"))
    eol_latest = None
    if eol and not eol.get("error") and eol["releases"]:
        newest = eol["releases"][0]
        eol_latest = {"source": eol["source"], "url": newest.get("latest_link") or eol["url"],
                      "version": newest["latest"], "release_date": newest.get("latest_date")}
    eco, pkg = identity.get("package_ecosystem"), identity.get("package_name")
    latest_sources = [
        eol_latest,
        sources.fetch_github_latest(identity.get("github_repo")),
        sources.fetch_pypi(pkg) if eco == "PyPI" else None,
        sources.fetch_npm(pkg) if eco == "npm" else None,
        sources.fetch_homebrew_cask(identity.get("homebrew_cask")),
    ]
    latest = pick_latest(latest_sources)
    target = requested or (latest or {}).get("version")

    progress("Resolving product in the NIST NVD…")
    cpe = sources.resolve_cpe(identity.get("cpe_vendor"), identity.get("cpe_product"),
                              identity.get("display_name") or name)

    cves_requested = cves_latest = None
    if not cpe.get("error"):
        progress(f"Fetching CVEs for version {target or '(all versions)'}…")
        cves_requested = sources.fetch_nvd_cves(cpe["vendor"], cpe["product"], target)
        if latest and requested and latest["version"] != requested:
            progress(f"Fetching CVEs for latest version {latest['version']}…")
            cves_latest = sources.fetch_nvd_cves(cpe["vendor"], cpe["product"], latest["version"])

    progress("Cross-checking CISA Known Exploited Vulnerabilities…")
    kev = sources.load_kev()
    kev_hits = []
    if cves_requested and not cves_requested.get("error") and not kev.get("error"):
        kev_hits = [{**kev[c["id"]], "url": c["url"]} for c in cves_requested["cves"] if c["id"] in kev]

    osv = sources.fetch_osv(eco, pkg, target) if eco in ("PyPI", "npm") else None

    findings = {
        "checked_at": datetime.now().isoformat(timespec="seconds"),
        "identity": identity,
        "requested_version": requested,
        "target_version": target,
        "latest": latest,
        "latest_sources": [s for s in latest_sources if s],
        "outdated": is_outdated(requested, latest["version"]) if requested and latest else None,
        "eol_cycle": find_cycle(eol["releases"], target) if eol and not eol.get("error") else None,
        "cpe": cpe,
        "cves_requested": cves_requested,
        "cves_latest": cves_latest,
        "kev_hits": kev_hits,
        "kev_error": kev.get("error"),
        "osv": osv,
    }
    findings["risk"] = rate_risk(findings)

    progress("Writing AI summary…")
    findings["summary"] = llm.write_assessment(request, findings)
    return findings
