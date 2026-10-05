"""RAG over (1) policy documents and (2) past review decisions.

Follows AI Bootcamp Topics 3, 4 and 7.4:
  load -> split (800 chars, 100 overlap) -> embed (text-embedding-3-small) -> Chroma (in memory) -> retrieve top-k

Indexes are rebuilt automatically when the policy files or the decided requests change
(@st.cache_resource keyed on a fingerprint of the content).
"""
import hashlib
import json
from pathlib import Path

import streamlit as st
from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_openai import OpenAIEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter
from pypdf import PdfReader

from utils import db
from utils.utility import get_secret

POLICY_DIR = Path(__file__).resolve().parent.parent / "policies"
SUPPORTED_TYPES = (".pdf", ".md", ".txt")
EMBEDDING_MODEL = "text-embedding-3-small"


def rag_available():
    return bool(get_secret("OPENAI_API_KEY"))


def get_embeddings():
    return OpenAIEmbeddings(model=EMBEDDING_MODEL, api_key=get_secret("OPENAI_API_KEY"))


def _fresh_store(name, docs):
    """Chroma's in-memory client is shared by the whole process, so drop any
    collection with the same name before rebuilding (otherwise chunks duplicate)."""
    embeddings = get_embeddings()
    Chroma(collection_name=name, embedding_function=embeddings).delete_collection()
    if not docs:
        return None
    return Chroma.from_documents(docs, embeddings, collection_name=name,
                                 collection_metadata={"hnsw:space": "cosine"})  # relevance = cosine similarity


def _fingerprint(items):
    return hashlib.sha256(json.dumps(items, default=str).encode()).hexdigest()[:16]


def _search(store, query, k):
    if store is None:
        return []
    results = store.similarity_search_with_relevance_scores(query, k=k)
    return [{**doc.metadata, "text": doc.page_content, "score": round(score, 3)} for doc, score in results]


# ---------------------------------------------------------------- 1. policy documents

def policy_files():
    POLICY_DIR.mkdir(exist_ok=True)
    return sorted(p for p in POLICY_DIR.iterdir() if p.suffix.lower() in SUPPORTED_TYPES)


def load_policy_chunks():
    pages = []
    for path in policy_files():
        if path.suffix.lower() == ".pdf":
            for number, page in enumerate(PdfReader(path).pages, start=1):
                text = page.extract_text() or ""
                if text.strip():
                    pages.append(Document(page_content=text, metadata={"source": path.name, "page": number}))
        else:
            pages.append(Document(page_content=path.read_text(encoding="utf-8", errors="ignore"),
                                  metadata={"source": path.name}))
    splitter = RecursiveCharacterTextSplitter(chunk_size=800, chunk_overlap=100)
    return splitter.split_documents(pages)


@st.cache_resource(show_spinner="Indexing policy documents…", max_entries=2)
def _policy_store(fingerprint):
    return _fresh_store(f"policies-{fingerprint}", load_policy_chunks())


def policy_store():
    if not rag_available():
        return None
    files = [(p.name, p.stat().st_size, p.stat().st_mtime) for p in policy_files()]
    return _policy_store(_fingerprint(files))


def retrieve_policy(software, category=None, purpose=None, k=5):
    """Two queries - one about the product itself (catalogue entries), one about the
    situation (rules) - merged and de-duplicated."""
    store = policy_store()
    queries = [f"{software} {category or ''}".strip(),
               f"Rules for installing {software} ({category or 'software'}). Purpose: {purpose or '-'}. "
               "Version, end-of-life, vulnerabilities, prohibited or restricted software, licensing."]
    seen, chunks = set(), []
    for q in queries:
        for c in _search(store, q, k):
            if c["text"] not in seen:
                seen.add(c["text"])
                chunks.append(c)
    return sorted(chunks, key=lambda c: c["score"], reverse=True)[:k]


# ---------------------------------------------------------------- 2. past decisions

def decision_documents(rows):
    """One document per decided request. Requester names are left out on purpose."""
    docs = []
    for r in rows:
        if r["status"] == "Pending Review":
            continue
        text = (f"Software: {r['software_name']} {r['requested_version'] or '(latest)'} on {r['platform']}\n"
                f"Department: {r['department'] or '-'}\nPurpose: {r['purpose']}\n"
                f"Risk level at review: {r['risk_level'] or '-'} (latest version then: {r['latest_version'] or '-'})\n"
                f"Decision: {r['status']}\nReviewer notes: {r['reviewer_notes'] or '-'}")
        docs.append(Document(page_content=text, metadata={
            "request_id": r["id"], "software": r["software_name"], "decision": r["status"],
            "date": (r["created_at"] or "")[:10]}))
    return docs


@st.cache_resource(show_spinner="Indexing past decisions…", max_entries=2)
def _decision_store(fingerprint, _docs):
    return _fresh_store(f"decisions-{fingerprint}", _docs)


def decision_store():
    if not rag_available():
        return None
    docs = decision_documents(db.list_requests())
    return _decision_store(_fingerprint([d.page_content for d in docs]), docs)


def retrieve_precedents(software, category=None, exclude_id=None, k=3):
    hits = _search(decision_store(), f"Software: {software} {category or ''}", k + 1)
    return [h for h in hits if h.get("request_id") != exclude_id][:k]


# ---------------------------------------------------------------- formatting for prompts

def format_policy(chunks):
    return "\n\n---\n\n".join(
        f"[{c['source']}{', p.' + str(c['page']) if c.get('page') else ''}]\n{c['text']}" for c in chunks
    ) or "(no policy documents indexed)"


def format_precedents(hits):
    return "\n\n---\n\n".join(f"[Request #{h['request_id']}, {h['date']}]\n{h['text']}" for h in hits) \
        or "(no past decisions yet)"
