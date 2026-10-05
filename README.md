# Software Request Checker (Streamlit)

Records end-user software requests, checks the **latest official version** and **known vulnerabilities**,
and gives the IT approver a review queue. Built with the AI Bootcamp patterns: Streamlit multipage app,
`st.secrets`, password protection (8.2), thin `app.py` + `utils/` (7.2), prompt chaining (2.6),
and grounding the LLM to avoid hallucinations (1.9).

```
software-request-app/
├── app.py                     # Login + role-based navigation (user / admin)
├── pages/0_Submit_Request.py  # Submit a request (all accounts)
├── pages/5_My_Requests.py     # Status of your own requests (all accounts)
├── pages/6_Approved_Software.py # Approved-software register (all accounts)
├── pages/1_Review_Requests.py # ADMIN: decide, add notes, re-run check, CSV export
├── pages/2_About.py           # Method, risk rules, limitations
├── pages/3_Ask_IT.py          # RAG chatbot over policies + past decisions
├── pages/4_Knowledge_Base.py  # ADMIN: upload / edit / remove policy documents, test retrieval
├── policies/                  # SAMPLE policy documents (replace with your own .pdf/.md/.txt)
├── utils/
│   ├── sources.py             # Official-source lookups (NVD, CISA KEV, endoflife.date, GitHub, PyPI, npm, Homebrew, OSV)
│   ├── llm.py                 # OpenAI: identify product → identifiers; summarise findings; chat
│   ├── rag.py                 # RAG: chunk → embed → Chroma → retrieve (policies + past decisions)
│   ├── approvals.py           # Approved-software register (latest admin decision per product)
│   ├── assess.py              # Orchestration + rule-based risk rating
│   ├── db.py                  # SQLite storage (data/requests.db)
│   ├── ui.py                  # Shared results view
│   └── utility.py             # login_form(), require_role(), get_secret()
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
2. **Latest version** from the first source that answers: endoflife.date → official GitHub releases → PyPI/npm → Chocolatey (Windows) / Homebrew cask (macOS, also searched by name).
3. **Vulnerabilities**: NIST NVD CVE API 2.0 for the requested version (and latest, for comparison),
   CISA KEV catalog cross-check, OSV.dev for PyPI/npm packages.
4. **Risk** is rule-based (High / Medium / Unverified / Low) — see the About page. The LLM only writes the summary.
5. **RAG**: relevant policy clauses and similar past decisions are retrieved from Chroma and added to the
   summary prompt, so the recommendation cites policy ([file]) and precedents ([Request #id]).

## RAG features (Topics 3, 4, 7.4)
| Feature | Where | Index |
|---|---|---|
| Policy check in every assessment | Request + Review pages | `policies/` files → Markdown split by heading, one chunk per table row (prefixed with its section); PDFs 800-char chunks |
| Past-decision precedents | Request + Review pages | one document per decided request (no requester names) |
| Ask IT chatbot | `pages/3_Ask_IT.py` | policy index + the full approved-software register |

Retrieval is hybrid: product-name matches first, then semantic search. Indexes are in-memory Chroma collections built with `text-embedding-3-small`, cached with `@st.cache_resource`
and rebuilt automatically when the policy files or decisions change. RAG needs `OPENAI_API_KEY`.
Uploads on the Knowledge Base page are temporary on Streamlit Cloud — commit policy files to `policies/` to keep them.

Without `OPENAI_API_KEY` the app still works: it uses NVD keyword search to find the product.

## Notes
- NVD without an API key is throttled to 5 requests / 30 s, so a check takes ~20–30 s. Get a free key for speed.
- On Streamlit Community Cloud the SQLite file is wiped on redeploy; use a hosted DB for real use.
- Two roles from `secrets.toml` (`[users.user]`, `[users.admin]`): users submit and track requests; admins also approve and edit policies.
  Pages are hidden by role (`st.navigation`) and each admin page re-checks the role.
- Policies are **default deny with no pre-approved software**: an admin approval makes the software allowed for everyone
  (latest decision per product wins). The register comes straight from the database, not from RAG.
- ⚠️ On Streamlit Community Cloud the SQLite database — and therefore the approved list — is wiped on restart/redeploy.
  Use a hosted database before relying on it.
- Policy edits/uploads made in the app are lost when Streamlit Cloud restarts — commit lasting changes to `policies/`.
