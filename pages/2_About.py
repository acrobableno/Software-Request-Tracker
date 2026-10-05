import streamlit as st

from utils.utility import check_password

st.set_page_config(layout="centered", page_title="About")
if not check_password():
    st.stop()

st.title("ℹ️ About this app")
st.markdown("""
**Purpose** — record end-user software requests and give the approver an evidence-based view of
(1) whether the requested version is the latest official release and (2) its known vulnerabilities.

### How a check works
1. **Identify** — an LLM maps the free-text name to lookup identifiers (NVD CPE, endoflife.date slug,
   GitHub repo, package name). These are *guesses* that are then verified against each source.
2. **Latest version** — first successful source wins, in this order:
   endoflife.date → official GitHub releases → PyPI / npm → Chocolatey (Windows apps) / Homebrew (macOS apps).
   Chocolatey and Homebrew track each vendor's own download, so they cover standard closed-source apps
   (Adobe Reader, Chrome, Zoom…). If no AI identifier works, Homebrew is searched by product name.
3. **Vulnerabilities** — NIST NVD CVE API (matched by CPE and version),
   CISA Known Exploited Vulnerabilities catalog, and OSV.dev for PyPI/npm packages.
4. **Risk level** — fixed, explainable rules (not the LLM):
   - 🔴 **High**: any CISA KEV hit, any CVSS ≥ 9.0, or the release cycle is end-of-life
   - 🟠 **Medium**: CVSS 7.0–8.9, OSV advisories, or an outdated version
   - ⚪ **Unverified**: the product, its version or its latest release could not be confirmed.
     If no version is known, CVEs across all historical versions are shown as context only.
   - 🟢 **Low**: none of the above
5. **AI summary** — the LLM summarises only the fetched data.

### Limitations
- Not every product is in NVD / endoflife.date; closed-source desktop apps may need a manual check
  on the vendor site. The reviewer can correct identifiers and re-run the check.
- NVD matching depends on the CPE data NIST has recorded; missing CPEs mean missing CVEs.
- Without an NVD API key, lookups are throttled (5 requests / 30 s), so a check takes ~20–30 s.
- This is a decision aid — the approver remains responsible for the decision.
""")
