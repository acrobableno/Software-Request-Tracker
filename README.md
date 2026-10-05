# Software Request Checker (Streamlit)

Records end-user software requests, checks the **latest official version** and **known vulnerabilities**,
and gives the IT approver a review queue. Built with the AI Bootcamp patterns: Streamlit multipage app,
`st.secrets`, password protection (8.2), thin `app.py` + `utils/` (7.2), prompt chaining (2.6),
and grounding the LLM to avoid hallucinations (1.9).

```
software-request-app/
├── app.py                     # Submit a request (UI only)
├── pages/1_Review_Requests.py # Approver queue: decide, add notes, re-run check, CSV export
├── pages/2_About.py           # Method, risk rules, limitations
├── utils/
│   ├── sources.py             # Official-source lookups (NVD, CISA KEV, endoflife.date, GitHub, PyPI, npm, Homebrew, OSV)
│   ├── llm.py                 # OpenAI: identify product → identifiers; summarise findings
│   ├── assess.py              # Orchestration + rule-based risk rating
│   ├── db.py                  # SQLite storage (data/requests.db)
│   ├── ui.py                  # Shared results view
│   └── utility.py             # check_password(), get_secret()
├── tests/                     # Offline tests with mocked API responses
└── .streamlit/secrets.toml.example
```

## Run locally
```bash
cd software-request-app
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .streamlit/secrets.toml.example .streamlit/secrets.toml   # then edit it
streamlit run app.py
```
Tests: `pip install pytest && pytest -q tests`

## How the check works
1. **LLM identifies** the product (NVD CPE vendor/product, endoflife.date slug, GitHub repo, package name).
   These are only lookup keys — each is verified against the real source; a wrong guess returns "not found".
2. **Latest version** from the first source that answers: endoflife.date → official GitHub releases → PyPI/npm → Homebrew cask.
3. **Vulnerabilities**: NIST NVD CVE API 2.0 for the requested version (and latest, for comparison),
   CISA KEV catalog cross-check, OSV.dev for PyPI/npm packages.
4. **Risk** is rule-based (High / Medium / Unverified / Low) — see the About page. The LLM only writes the summary.

Without `OPENAI_API_KEY` the app still works: it uses NVD keyword search to find the product.

## Notes
- NVD without an API key is throttled to 5 requests / 30 s, so a check takes ~20–30 s. Get a free key for speed.
- On Streamlit Community Cloud the SQLite file is wiped on redeploy; use a hosted DB for real use.
- Everyone with `APP_PASSWORD` can see the review page. Split into separate apps/passwords if requesters shouldn't approve.
