import json
from a2a.server.agent_execution import AgentExecutor
from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import AgentCard, AgentCapabilities, AgentSkill, AgentExtension, DataPart
from a2a.utils import new_agent_text_message
from .carrier import verify

EXTENSION = "https://github.com/amiencoy/parabiont-protocol/context-carrier/v0.1"


class Receiver(AgentExecutor):
    def __init__(self, engine, public_key, store):
        self.engine, self.public_key, self.store = engine, public_key, store

    async def execute(self, context, event_queue):
        try:
            parts = context.message.parts
            if len(parts) != 1 or not isinstance(parts[0].root, DataPart):
                raise ValueError("Expected a single signed DataPart")
            capsule = verify(parts[0].root.data, self.public_key, self.engine)
            self.store.accept(capsule)
            reply = {"accepted": True, "bond_id": capsule["bond_id"], "items": len(capsule["state"])}
        except Exception:
            # Never return raw policy input, errors containing context, or signatures.
            reply = {"accepted": False, "reason": "invalid_or_denied_carrier"}
        await event_queue.enqueue_event(new_agent_text_message(json.dumps(reply), context_id=context.context_id))

    async def cancel(self, context, event_queue):
        raise NotImplementedError("Synchronous receipt only; revoke bonds through the local operator CLI")


def build_app(engine, public_key, store, port=8787):
    card = AgentCard(name="Parabiont context receiver", description="Receives signed Axionorm-approved context for a local agent.",
        url=f"http://127.0.0.1:{port}/", version="0.1.0", protocol_version="0.3.0",
        capabilities=AgentCapabilities(streaming=False, push_notifications=False, extensions=[AgentExtension(uri=EXTENSION, required=True,
            description="Signed, purpose-bound context carrier profile v0.1")]),
        default_input_modes=["application/json"], default_output_modes=["text/plain"],
        skills=[AgentSkill(id="context-receive", name="Receive context", description="Validate and store an approved context capsule", tags=["context", "handoff"])])
    app = A2AStarletteApplication(agent_card=card, http_handler=DefaultRequestHandler(
        agent_executor=Receiver(engine, public_key, store), task_store=InMemoryTaskStore()), max_content_length=1048576).build()
    # Local-only receiver. Host/Origin checks prevent browser-based DNS rebinding.
    @app.middleware("http")
    async def local_boundary(request, call_next):
        from starlette.responses import JSONResponse
        if request.headers.get("origin") or request.url.hostname not in {"127.0.0.1", "localhost", "testserver"}:
            return JSONResponse({"error": "local_boundary"}, status_code=403)
        return await call_next(request)
    return app
