"""RAG tests with a local bag-of-words embedding (no OpenAI calls)."""
import sys, pathlib, re, zlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import math
import pytest
from langchain_core.embeddings import Embeddings
from utils import rag, db, llm


class WordEmbeddings(Embeddings):
    """Lexical stand-in for text-embedding-3-small: hashed bag of words, L2-normalised."""
    def _vec(self, text):
        v = [0.0] * 512
        for w in re.findall(r"[a-z0-9]+", text.lower()):
            v[zlib.crc32(w.encode()) % 512] += 1
        n = math.sqrt(sum(x * x for x in v)) or 1
        return [x / n for x in v]
    def embed_documents(self, texts): return [self._vec(t) for t in texts]
    def embed_query(self, text): return self._vec(text)


@pytest.fixture(autouse=True)
def setup(monkeypatch, tmp_path):
    monkeypatch.setattr(rag, "get_embeddings", lambda: WordEmbeddings())
    monkeypatch.setattr(rag, "rag_available", lambda: True)
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "t.db")
    rag._policy_store.clear(); rag._decision_store.clear()
    db.init_db()


def test_policy_retrieval_finds_catalogue_entry():
    chunks = rag.retrieve_policy("TeamViewer", "Remote access tool", "support customers")
    assert chunks and any("TeamViewer" in c["text"] and "CISO" in c["text"] for c in chunks)
    assert all(c["source"].endswith(".md") for c in chunks)
    assert len({c["text"] for c in chunks}) == len(chunks)  # de-duplicated


def test_index_not_duplicated_on_rebuild():
    n1 = rag.policy_store()._collection.count()
    rag._policy_store.clear()
    assert rag.policy_store()._collection.count() == n1


def test_precedents_only_decided_and_exclude_self():
    a = db.add_request("Ann", "", "Finance", "Notepad++", "8.1", "Windows", "edit csv")
    b = db.add_request("Bob", "", "IT", "Notepad++", "", "Windows", "scripts")
    c = db.add_request("Cat", "", "HR", "uTorrent", "", "Windows", "downloads")
    db.update_status(a, "Approved with Conditions", "install latest 8.9 instead")
    db.update_status(c, "Rejected", "P2P prohibited")
    hits = rag.retrieve_precedents("Notepad++", "Text editor", exclude_id=b)
    assert hits[0]["request_id"] == a and hits[0]["decision"] == "Approved with Conditions"
    assert b not in [h["request_id"] for h in hits]            # pending -> not indexed
    assert "Ann" not in hits[0]["text"]                         # requester name not indexed
    assert rag.retrieve_precedents("Notepad++", exclude_id=a)[0]["request_id"] == c  # self excluded
    # decisions index refreshes when a decision changes
    db.update_status(b, "Approved", "ok")
    assert b in [h["request_id"] for h in rag.retrieve_precedents("Notepad++ scripts", k=3)]


def test_assessment_prompt_includes_rag_context(monkeypatch):
    seen = {}
    monkeypatch.setattr(llm, "llm_available", lambda: True)
    monkeypatch.setattr(llm, "get_completion", lambda prompt, system=None, json_mode=False: seen.setdefault("p", prompt) and "ok")
    findings = {"risk": {"level": "Low"}, "policy_context": rag.retrieve_policy("uTorrent", "P2P"),
                "precedents": [{"request_id": 7, "date": "2026-10-01", "text": "Decision: Rejected"}]}
    llm.write_assessment({"software_name": "uTorrent"}, findings)
    assert "<policy>" in seen["p"] and "approved_software_catalogue.md" in seen["p"]
    assert "[Request #7, 2026-10-01]" in seen["p"]
    assert '"policy_context"' not in seen["p"]   # not duplicated inside findings JSON


def test_chat_and_knowledge_base_pages(monkeypatch):
    from streamlit.testing.v1 import AppTest
    root = pathlib.Path(__file__).resolve().parent.parent
    captured = {}
    def fake_stream(messages, policy_text, precedents_text):
        captured.update(messages=messages, policy=policy_text)
        yield "TeamViewer needs CISO approval [approved_software_catalogue.md]."
    monkeypatch.setattr(llm, "chat_stream", fake_stream)

    at = AppTest.from_file(str(root / "pages/3_Ask_IT.py"), default_timeout=30)
    at.session_state["user"] = {"username": "user", "role": "user"}
    at.run()
    at.chat_input[0].set_value("Can I install TeamViewer?").run()
    assert not at.exception, at.exception
    assert "CISO approval" in at.chat_message[1].markdown[0].value
    assert "TeamViewer" in captured["policy"] and captured["messages"][-1]["content"] == "Can I install TeamViewer?"

    kb = AppTest.from_file(str(root / "pages/4_Knowledge_Base.py"), default_timeout=30)
    kb.session_state["user"] = {"username": "admin", "role": "admin"}
    kb.run()
    assert not kb.exception, kb.exception
    assert int(kb.metric[0].value) > 5
    kb.text_input[0].input("prohibited peer-to-peer").run()
    assert not kb.exception


def test_admin_can_edit_policy(monkeypatch, tmp_path):
    import shutil
    from streamlit.testing.v1 import AppTest
    root = pathlib.Path(__file__).resolve().parent.parent
    pol = tmp_path / "policies"; shutil.copytree(rag.POLICY_DIR, pol)
    monkeypatch.setattr(rag, "POLICY_DIR", pol)
    kb = AppTest.from_file(str(root / "pages/4_Knowledge_Base.py"), default_timeout=30)
    kb.session_state["user"] = {"username": "admin", "role": "admin"}
    kb.run()
    doc = kb.selectbox[0].value
    kb.text_area[0].input("# New rule\nZoom is prohibited.")
    next(b for b in kb.button if b.label == "Save changes").click().run()
    assert not kb.exception, kb.exception
    assert (pol / doc.name).read_text() == "# New rule\nZoom is prohibited."
    assert any("Zoom is prohibited" in c["text"] for c in rag.retrieve_policy("Zoom", k=8))  # re-indexed
