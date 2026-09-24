# sec310-sample — one agent, five patches

Companion code for the re:Invent code talk **SEC310 · Building Production-Ready Agents Securely**.

This repository evolves through tagged commits. You are looking at an early tag; `v5-telemetry`
(the `main` branch) carries the full README, the presenter walkthrough, and the demo runner.

```bash
uv sync && uv run pytest
```

Everything here is synthetic and offline: fake tenants, fake accounts, an in-memory evidence
store, and a deliberately gullible scripted model. No credentials, no network, no real service.

License: MIT-0 (see `LICENSE`).
