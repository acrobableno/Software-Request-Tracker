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
from langchain_text_splitters import MarkdownHeaderTextSplitter, RecursiveCharacterTextSplitter
from pypdf import PdfReader

from utils import db
from utils.approvals import names_match
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


def _markdown_chunks(text, source):
    """Structure-aware chunking for Markdown policies (Topic 4.2 - improving pre-retrieval):
    - every chunk is prefixed with its heading path, e.g. [Software Catalogue > Restricted ...],
      so a chunk never loses the section that gives it meaning;
    - every table row becomes its own chunk (with the table header), so one product = one chunk."""
    sections = MarkdownHeaderTextSplitter(
        headers_to_split_on=[("#", "h1"), ("##", "h2"), ("###", "h3")]).split_text(text)
    prose_splitter = RecursiveCharacterTextSplitter(chunk_size=800, chunk_overlap=100)
    chunks = []
    for section in sections:
        path = " > ".join(section.metadata.values()) or source
        lines = section.page_content.splitlines()
        table = [line for line in lines if line.strip().startswith("|")]
        prose = "\n".join(line for line in lines if not line.strip().startswith("|")).strip()
        if len(table) < 3:  # not a real table (header + separator + rows): keep it with the prose
            prose, table = section.page_content.strip(), []
        for piece in prose_splitter.split_text(prose) if prose else []:
            chunks.append(Document(page_content=f"[{path}]\n{piece}", metadata={"source": source, "section": path}))
        header = table[0] if table else ""
        for row in table[2:]:  # skip header and |---| separator
            item = row.strip().strip("|").split("|")[0].strip()
            chunks.append(Document(page_content=f"[{path}]\n{header}\n{row}",
                                   metadata={"source": source, "section": path, "item": item}))
    return chunks


def load_policy_chunks():
    chunks, pdf_pages = [], []
    for path in policy_files():
        if path.suffix.lower() == ".pdf":
            for number, page in enumerate(PdfReader(path).pages, start=1):
                text = page.extract_text() or ""
                if text.strip():
                    pdf_pages.append(Document(page_content=text, metadata={"source": path.name, "page": number}))
        else:
            chunks += _markdown_chunks(path.read_text(encoding="utf-8", errors="ignore"), path.name)
    splitter = RecursiveCharacterTextSplitter(chunk_size=800, chunk_overlap=100)
    return chunks + splitter.split_documents(pdf_pages)


def _name_search(store, query, field, limit=4):
    """Keyword half of hybrid retrieval (Topic 4.3): chunks whose product name matches the query.
    Embeddings alone can rank a one-line table row below long policy paragraphs."""
    if store is None:
        return []
    data = store.get(include=["documents", "metadatas"])
    hits = [{**meta, "text": doc, "score": 1.0, "match": "name"}
            for doc, meta in zip(data["documents"], data["metadatas"])
            if meta and meta.get(field) and names_match(meta[field], query)]
    return hits[:limit]


@st.cache_resource(show_spinner="Indexing policy documents…", max_entries=2)
def _policy_store(fingerprint):
    return _fresh_store(f"policies-{fingerprint}", load_policy_chunks())


def policy_store():
    if not rag_available():
        return None
    files = [(p.name, p.stat().st_size, p.stat().st_mtime) for p in policy_files()]
    return _policy_store(_fingerprint(files))


def retrieve_policy(software, category=None, purpose=None, k=5):
    """Hybrid retrieval: catalogue rows naming the product first, then semantic search with two
    queries - one about the product, one about the situation (rules) - de-duplicated."""
    store = policy_store()
    chunks = _name_search(store, software, "item")
    seen = {c["text"] for c in chunks}
    queries = [f"{software} {category or ''}".strip(),
               f"Rules for installing {software} ({category or 'software'}). Purpose: {purpose or '-'}. "
               "Version, end-of-life, vulnerabilities, prohibited or restricted software, licensing."]
    semantic = []
    for q in queries:
        for c in _search(store, q, k):
            if c["text"] not in seen:
                seen.add(c["text"])
                semantic.append(c)
    return chunks + sorted(semantic, key=lambda c: c["score"], reverse=True)[:k]


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
    """Past decisions for the same product (by name) first, then semantically similar ones."""
    store = decision_store()
    hits = _name_search(store, software, "software", limit=k)
    seen = {h["request_id"] for h in hits}
    hits += [h for h in _search(store, f"Software: {software} {category or ''}", k + 1) if h["request_id"] not in seen]
    return [h for h in hits if h.get("request_id") != exclude_id][:k]


# ---------------------------------------------------------------- formatting for prompts

def format_policy(chunks):
    return "\n\n---\n\n".join(
        f"[{c['source']}{', p.' + str(c['page']) if c.get('page') else ''}]\n{c['text']}" for c in chunks
    ) or "(no policy documents indexed)"


def format_precedents(hits):
    return "\n\n---\n\n".join(f"[Request #{h['request_id']}, {h['date']}]\n{h['text']}" for h in hits) \
        or "(no past decisions yet)"
