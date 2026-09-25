import base64
import json
import time
import uuid
from pathlib import Path
from typing import Literal
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption, load_pem_private_key, load_pem_public_key
from pydantic import Field
from axionorm.models import Strict
from axionorm.engine import canonical


class StateItem(Strict):
    id: str = Field(pattern=r"^[a-zA-Z0-9-]{1,64}$")
    kind: Literal["fact", "decision", "task", "constraint"]
    topic: str = Field(pattern=r"^[a-z0-9-]{1,64}$")
    text: str = Field(min_length=1, max_length=10000)


class Capsule(Strict):
    version: Literal["parabiont-context/v0.1"]
    bond_id: str = Field(pattern=r"^[a-f0-9-]{36}$")
    audience: str = Field(pattern=r"^[a-z0-9-]{1,64}$")
    purpose: str = Field(pattern=r"^[a-z0-9-]{1,64}$")
    issued_at: int
    expires_at: int
    policy_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    state: list[StateItem] = Field(min_length=1, max_length=500)


def keygen(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    private = Ed25519PrivateKey.generate()
    # Exclusive creates avoid replacing a trust root accidentally.
    for name, data in (("issuer.pem", private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())),
                       ("issuer.pub.pem", private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))):
        path = directory / name
        with path.open("xb") as stream:
            path.chmod(0o600)
            stream.write(data)


def pack(engine, candidate, review, private_path, now=None):
    state, receipt = engine.filter_context(candidate, review)
    now = int(time.time()) if now is None else now
    capsule = Capsule(version="parabiont-context/v0.1", bond_id=str(uuid.uuid4()),
        audience=engine.policy["audience"], purpose=engine.policy["purpose"], issued_at=now,
        expires_at=now + engine.policy["lease_seconds"], policy_digest=engine.policy_digest, state=state).model_dump()
    private = load_pem_private_key(Path(private_path).read_bytes(), password=None)
    signature = base64.b64encode(private.sign(canonical(capsule))).decode()
    return {"capsule": capsule, "signature": signature}, receipt


def verify(envelope, public_path, engine, now=None):
    if not isinstance(envelope, dict) or set(envelope) != {"capsule", "signature"}:
        raise ValueError("Invalid envelope")
    capsule = Capsule.model_validate(envelope["capsule"]).model_dump()
    public = load_pem_public_key(Path(public_path).read_bytes())
    public.verify(base64.b64decode(envelope["signature"], validate=True), canonical(capsule))
    now = int(time.time()) if now is None else now
    if not capsule["issued_at"] <= now < capsule["expires_at"] or capsule["expires_at"] - capsule["issued_at"] > engine.policy["lease_seconds"]:
        raise ValueError("Invalid or expired lease")
    if any(capsule[k] != engine.policy[k] for k in ("audience", "purpose")) or capsule["policy_digest"] != engine.policy_digest:
        raise ValueError("Policy, audience or purpose mismatch")
    # Re-evaluate content under the current policy; signature authenticates the operator review.
    from axionorm.engine import digest
    items = [{**item, "labels": ["technical"]} for item in capsule["state"]]
    state, _ = engine.filter_context({"version": "parabiont-candidate/v0.1", "items": items},
        {"version": "axionorm-review/v0.1", "approved": {i["id"]: digest(i) for i in items}})
    if state != capsule["state"]:
        raise ValueError("Receiver policy rejected part of capsule")
    return capsule
