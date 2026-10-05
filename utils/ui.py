"""Shared Streamlit rendering of a check result."""
import pandas as pd
import streamlit as st

RISK_BADGE = {"High": "🔴 High", "Medium": "🟠 Medium", "Low": "🟢 Low", "Unverified": "⚪ Unverified"}


def _cve_table(result):
    if not result:
        return
    if result.get("error"):
        st.warning(f"NVD lookup failed: {result['error']}")
        return
    st.caption(f"{result['total']} CVE(s) match `{result['match']}` — [NVD query]({result['url']})")
    if result["cves"]:
        df = pd.DataFrame(result["cves"])[["id", "score", "severity", "published", "description", "url"]]
        st.dataframe(df, hide_index=True, use_container_width=True,
                     column_config={"url": st.column_config.LinkColumn("link", display_text="open")})


def render_findings(f):
    risk = f["risk"]
    identity = f["identity"]
    latest = f.get("latest")

    for e in f.get("approval") or []:
        notes = f" — notes: {e['notes']}" if e["notes"] else ""
        if e["status"] in ("Approved", "Approved with Conditions"):
            st.success(f"✅ **{e['software']}** is already approved for everyone "
                       f"({e['status']}, Request #{e['request_id']}, {e['date']}){notes}")
        else:
            st.error(f"⛔ **{e['software']}** was previously rejected (Request #{e['request_id']}, {e['date']}){notes}")

    c1, c2, c3 = st.columns(3)
    c1.metric("Risk (rule-based)", RISK_BADGE.get(risk["level"], risk["level"]))
    c2.metric("Requested", f.get("requested_version") or "latest")
    c3.metric("Latest official", latest["version"] if latest else "unknown")
    for r in risk["reasons"]:
        st.markdown(f"- {r}")
    for c in risk["caveats"]:
        st.markdown(f"- ⚠️ {c}")

    if f.get("summary"):
        with st.container(border=True):
            st.markdown("**AI summary** (generated only from the data below — verify before acting)")
            st.markdown(f["summary"])

    with st.expander("Latest version — sources", expanded=True):
        rows = [{"source": s.get("source", "?"), "version": s.get("version"), "released": s.get("release_date"),
                 "url": s.get("url"), "error": s.get("error")} for s in f["latest_sources"]]
        if rows:
            st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True,
                         column_config={"url": st.column_config.LinkColumn("link", display_text="open")})
        else:
            st.info("No official source identified for this product. Check the vendor website manually.")
        if identity.get("official_website"):
            st.caption(f"Vendor site suggested by AI (verify): {identity['official_website']}")
        cycle = f.get("eol_cycle")
        if cycle:
            st.markdown(f"Release cycle **{cycle['cycle']}** — latest patch {cycle['latest']}, "
                        f"{'**END OF LIFE** since ' + str(cycle['eol_date']) if cycle['is_eol'] else 'supported'}"
                        f"{' until ' + str(cycle['eol_date']) if cycle['eol_date'] and not cycle['is_eol'] else ''}.")

    vuln_title = (f"Vulnerabilities — version {f['target_version']}" if f.get("target_version")
                  else "Vulnerabilities — all historical versions (no version determined, context only)")
    with st.expander(vuln_title, expanded=bool(f.get("target_version"))):
        cpe = f.get("cpe") or {}
        if cpe.get("error"):
            st.warning(f"NVD product lookup: {cpe['error']}")
        else:
            st.caption(f"NVD product: **{cpe['title']}** (`{cpe['vendor']}:{cpe['product']}`, matched by {cpe['method']})")
        if f.get("kev_hits"):
            st.error("**CISA Known Exploited Vulnerabilities:** " + ", ".join(
                f"[{k['cveID']}]({k['url']}) (added {k['dateAdded']})" for k in f["kev_hits"]))
        elif f.get("kev_error"):
            st.warning(f"CISA KEV catalog unavailable: {f['kev_error']}")
        _cve_table(f.get("cves_requested"))
        osv = f.get("osv")
        if osv and osv.get("error"):
            st.warning(f"OSV lookup failed: {osv['error']}")
        elif osv and osv["vulns"]:
            st.markdown("**OSV.dev package advisories**")
            st.dataframe(pd.DataFrame(osv["vulns"]), hide_index=True, use_container_width=True)

    if f.get("cves_latest"):
        with st.expander(f"Vulnerabilities — latest version {latest['version']} (for comparison)"):
            _cve_table(f["cves_latest"])

    if "policy_context" in f or f.get("rag_error"):
        with st.expander("Policy & past decisions used by the AI (RAG)"):
            if f.get("rag_error"):
                st.warning(f"Policy/precedent retrieval failed: {f['rag_error']}")
            render_chunks(f.get("policy_context") or [], f.get("precedents") or [])

    with st.expander("Identifiers used"):
        st.json(identity)
    st.caption(f"Checked {f['checked_at']}")


def render_chunks(policy, precedents):
    """Show retrieved RAG context so the reviewer can check what the AI was given."""
    st.markdown("**Policy excerpts**" if policy else "_No policy excerpts retrieved._")
    for c in policy:
        page = f", p.{c['page']}" if c.get("page") else ""
        with st.container(border=True):
            st.caption(f"{c['source']}{page} · relevance {c['score']}")
            st.text(c["text"])
    if precedents is None:
        return
    st.markdown("**Similar past decisions**" if precedents else "_No similar past decisions._")
    for h in precedents:
        with st.container(border=True):
            st.caption(f"Request #{h['request_id']} · {h['date']} · {h['decision']} · relevance {h['score']}")
            st.text(h["text"])
