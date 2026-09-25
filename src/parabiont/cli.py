import argparse
import json
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4
from axionorm import Engine
from .carrier import keygen, pack
from .store import Store


def main():
    p = argparse.ArgumentParser(description="Parabiont signed context carrier")
    sub = p.add_subparsers(dest="command", required=True)
    q = sub.add_parser("keygen"); q.add_argument("directory")
    q = sub.add_parser("pack")
    for name in ("candidate", "review", "policy", "opa", "private-key", "out"):
        q.add_argument("--" + name, required=True)
    q = sub.add_parser("serve")
    for name in ("policy", "opa", "public-key", "store"):
        q.add_argument("--" + name, required=True)
    q.add_argument("--port", type=int, default=8787)
    q = sub.add_parser("send"); q.add_argument("envelope"); q.add_argument("--url", default="http://127.0.0.1:8787/")
    q = sub.add_parser("revoke"); q.add_argument("bond_id"); q.add_argument("--store", required=True)
    q = sub.add_parser("schema")
    a = p.parse_args()
    if a.command == "keygen": keygen(a.directory)
    elif a.command == "schema":
        from .carrier import Capsule
        print(json.dumps(Capsule.model_json_schema(), indent=2))
    elif a.command == "pack":
        envelope, audit = pack(Engine(a.policy, a.opa), json.loads(Path(a.candidate).read_text()),
            json.loads(Path(a.review).read_text()), a.private_key)
        with open(a.out, "x") as f: json.dump(envelope, f, indent=2)
        Path(a.out).chmod(0o600)
        print(json.dumps({"bond_id": envelope["capsule"]["bond_id"], "audit": audit}))
    elif a.command == "serve":
        import uvicorn
        from .server import build_app
        uvicorn.run(build_app(Engine(a.policy, a.opa), a.public_key, Store(a.store), a.port), host="127.0.0.1", port=a.port, access_log=False)
    elif a.command == "revoke": Store(a.store).revoke(a.bond_id)
    else:
        import httpx
        parsed = urlparse(a.url)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"} or parsed.username or parsed.password:
            p.error("This profile only sends to a local receiver; remote TLS/auth is not implemented")
        request = {"jsonrpc": "2.0", "id": str(uuid4()), "method": "message/send", "params": {
            "message": {"role": "user", "messageId": str(uuid4()), "parts": [{"kind": "data", "data": json.loads(Path(a.envelope).read_text())}]}}}
        response = httpx.post(a.url, json=request, headers={"X-A2A-Extensions": "https://github.com/amiencoy/parabiont-protocol/context-carrier/v0.1"}, timeout=20, follow_redirects=False)
        response.raise_for_status()
        print(response.text)
