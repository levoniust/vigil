"""python -m vigil [--demo]  (env: VIGIL_DATA=/data, VIGIL_PORT=8080, VIGIL_DEMO=1)"""
import asyncio
import logging
import os
import sys
import tempfile

from aiohttp import web

from . import __version__
from .config import Config
from .engine import Engine
from .web import make_app


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    demo_mode = "--demo" in sys.argv[1:] or os.environ.get("VIGIL_DEMO", "") not in ("", "0")
    if demo_mode:  # a throwaway data folder, so the demo never touches a real config or history
        from . import demo
        data = tempfile.mkdtemp(prefix="vigil-demo-")
        demo.write_config(data)
    else:
        data = os.environ.get("VIGIL_DATA", "./data")
        os.makedirs(data, exist_ok=True)
    engine = Engine(Config(data), data)
    if demo_mode:
        demo.install(engine, data)
    runner = web.AppRunner(make_app(engine), access_log=None)
    await runner.setup()
    port = int(os.environ.get("VIGIL_PORT", "8080"))
    await web.TCPSite(runner, "0.0.0.0", port).start()
    logging.getLogger("vigil").info("Vigil %s on port %s, data in %s%s", __version__, port, data, " (DEMO: simulated lab)" if demo_mode else "")
    await engine.run()


if __name__ == "__main__":
    asyncio.run(main())
