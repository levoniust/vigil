"""HTTP server: the dashboard page and a small JSON API."""
import json
from pathlib import Path

from aiohttp import web

STATIC = Path(__file__).with_name("static")


def make_app(engine):
    app = web.Application()

    async def index(request):
        return web.FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})

    async def state(request):
        return web.json_response(engine.state(), dumps=lambda o: json.dumps(o, default=str))

    async def briefing(request):
        return web.json_response(await engine.make_briefing())

    async def refresh(request):
        what = request.match_info["what"]
        jobs = {"checks": engine.run_checks, "power": engine.run_power, "disks": engine.run_disks, "games": engine.run_games,
                "exposure": engine.run_exposure, "certs": engine.run_certs, "ct": engine.run_ct}
        if what not in jobs:
            raise web.HTTPNotFound()
        await jobs[what]()
        return web.json_response({"ok": True})

    async def test_alert(request):
        await engine.notify("info", "Vigil test notification", "If you can read this, Vigil alerts reach you.")
        return web.json_response({"ok": True, "targets": [k for k, v in engine.c["notify"].items() if v]})

    async def health(request):
        return web.Response(text="ok")

    app.router.add_get("/", index)
    app.router.add_get("/api/state", state)
    app.router.add_post("/api/briefing", briefing)
    app.router.add_post("/api/refresh/{what}", refresh)
    app.router.add_post("/api/test-alert", test_alert)
    app.router.add_get("/healthz", health)
    app.router.add_static("/static", STATIC)
    return app
