# Parabiont Protocol

An open-protocol initiative for persistent, governed agent attachment. Formerly **AIPP (AI Parabiosis Protocol)**.

## Status

v0.1.0 adds an experimental **context-carrier profile** over an official A2A SDK transport. It includes Ed25519 signatures, purpose/audience binding, expiry, replay protection and local revocation. This is one profile within the wider attachment initiative, not a complete persistent-agent SDK.

## Mechanism

1. Prepare and review a project context candidate locally.
2. Axionorm invokes OPA per item; rejected content never enters the outgoing capsule.
3. Parabiont signs the filtered capsule and sends one A2A DataPart.
4. The receiver authenticates the issuer, checks current policy and lease, and records the bond in SQLite.
5. A governed MCP gateway exposes that state to the destination agent.

The sender and receiver are A2A agents around the source/destination workflows. Neither ChatGPT nor the Gemini consumer app is claimed to expose a native A2A endpoint. This profile pins **A2A 0.3.0**, `a2a-sdk==0.3.26`; it does not claim A2A 1.0 conformance. Parabiont is an extension, not a fork of the wire protocol.

## Install and run

Install [Axionorm](https://github.com/amiencoy/axionorm) first in the same Python 3.11+ environment, or use the [combined installer](https://github.com/amiencoy/paralax-mcp).

```bash
git clone --branch v0.1.0 https://github.com/amiencoy/parabiont-protocol.git
cd parabiont-protocol
python -m pip install .
parabiont keygen .runtime/keys
parabiont pack --candidate candidate.json --review review.local.json --policy ../axionorm/examples/technical-review.yaml --opa ../axionorm/.runtime/opa/opa --private-key .runtime/keys/issuer.pem --out .runtime/envelope.json
parabiont serve --policy ../axionorm/examples/technical-review.yaml --opa ../axionorm/.runtime/opa/opa --public-key .runtime/keys/issuer.pub.pem --store .runtime/state.sqlite
```

Another terminal: `parabiont send .runtime/envelope.json`. Discovery: `http://127.0.0.1:8787/.well-known/agent-card.json`. This loopback receiver never invokes a cloud provider. `parabiont revoke BOND_ID --store .runtime/state.sqlite` blocks future reads and re-delivery of that bond.

Expiry/revocation cannot erase context already delivered to a model. Start a fresh model session after revocation. Keep keys, policies, reviews and state outside model-writable paths. Remote TLS/auth, distributed revocation, persistent A2A tasks and round-trip reconciliation remain future work.

## Tests and schemas

`parabiont schema` emits the capsule JSON Schema. Tests use a sibling Axionorm checkout; override through `AXIONORM_POLICY` and `OPA_BINARY`. Install pytest and run `python -m pytest tests -q`. The MCP repo includes an A2A HTTP to MCP stdio demo.

## Related projects and licensing

[Lophiont](https://github.com/amiencoy/lophiont) is a planned parabiotic carrier for [Lophiarch](https://github.com/amiencoy/lophiarch); those integrations are not implemented here. Licensing remains to be selected. No standards-body endorsement or certification is implied. Dependencies retain upstream licenses.

---

<p align="center"><sub>Built with code, coffee, and a healthy dislike of repetitive work.</sub></p>
