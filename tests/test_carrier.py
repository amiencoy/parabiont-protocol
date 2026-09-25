import copy
import os
from pathlib import Path
import pytest
from starlette.testclient import TestClient
from axionorm import Engine
from axionorm.engine import digest
from parabiont.carrier import pack, verify, keygen
from parabiont.store import Store
from parabiont.server import build_app


@pytest.fixture
def setup(tmp_path):
    sibling = Path(__file__).resolve().parents[2] / "axionorm"
    engine = Engine(os.environ.get("AXIONORM_POLICY", sibling / "examples/technical-review.yaml"),
                    os.environ.get("OPA_BINARY", sibling / ".runtime/opa/opa"))
    keygen(tmp_path / "keys")
    item = {"id": "p1", "kind": "task", "topic": "parabiont", "labels": ["technical"], "text": "Continue the project design."}
    packet, _ = pack(engine, {"version": "parabiont-candidate/v0.1", "items": [item]},
        {"version": "axionorm-review/v0.1", "approved": {"p1": digest(item)}}, tmp_path / "keys/issuer.pem")
    return engine, packet, tmp_path / "keys/issuer.pub.pem", Store(tmp_path / "state.sqlite")


def test_signature_and_expiry(setup):
    e, p, public, _ = setup
    assert verify(p, public, e)["audience"] == "gemini-local"
    changed = copy.deepcopy(p); changed["capsule"]["state"][0]["text"] = "tampered"
    with pytest.raises(Exception): verify(changed, public, e)
    with pytest.raises(ValueError): verify(p, public, e, now=p["capsule"]["expires_at"])


def test_replay_and_revocation(setup):
    e, p, public, store = setup
    c = verify(p, public, e); store.accept(c)
    with pytest.raises(ValueError): store.accept(c)
    store.revoke(c["bond_id"])
    with pytest.raises(ValueError): store.read(c["bond_id"])
    with pytest.raises(ValueError): store.accept(c)


def test_real_a2a_dispatch(setup):
    e, p, public, store = setup
    with TestClient(build_app(e, public, store)) as client:
        card = client.get("/.well-known/agent-card.json")
        assert card.status_code == 200
        assert card.json()["protocolVersion"] == "0.3.0"
        request = {"jsonrpc": "2.0", "id": "req-1", "method": "message/send", "params": {"message": {
            "role": "user", "messageId": "message-1", "parts": [{"kind": "data", "data": p}]}}}
        response = client.post("/", json=request)
        assert response.status_code == 200, response.text
        assert '"accepted": true' in response.json()["result"]["parts"][0]["text"], response.text
        assert store.read(p["capsule"]["bond_id"])["state"] == p["capsule"]["state"]
        replay = client.post("/", json=request)
        assert '"accepted": false' in replay.json()["result"]["parts"][0]["text"]
        assert client.post("/", json=request, headers={"origin": "https://example.com"}).status_code == 403
