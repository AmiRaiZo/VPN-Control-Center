from fastapi import FastAPI

from vpn_manager import __version__

app = FastAPI(
    title="VPN Control Center API",
    version=__version__,
    description="Multi-panel vpn-ui control plane",
)


@app.get("/health/live", tags=["health"])
async def liveness() -> dict[str, str]:
    return {"status": "ok", "version": __version__}

