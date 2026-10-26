import asyncio
import time

import pytest
from aiohttp import web

from vigil import probes
from vigil.config import DEFAULTS, Config, merge, validate
from vigil.engine import Engine, battery_age_years
from vigil.store import Store


def test_summarize_ups_and_pdu():
    ups = probes.summarize_ups("ups-rack", {"ups.status": "OB DISCHRG", "battery.charge": "87", "battery.runtime": "3000",
                                             "ups.load": "10", "device.model": "Smart-UPS"}, watts=1980)
    assert ups["on_battery"] and ups["charge"] == 87 and ups["runtime_min"] == 50 and ups["load_w"] == 198 and not ups["pdu"]
    pdu = probes.summarize_ups("pdu1", {"ups.status": "OL", "ups.realpower": "168", "device.model": "AP7901"})
    assert pdu["pdu"] and pdu["load_w"] == 168 and not pdu["on_battery"]


def test_battery_age():
    assert 2.9 < battery_age_years("2023/07/15") < 99
    assert battery_age_years("garbage") is None and battery_age_years(None) is None


def test_validate():
    validate(merge(DEFAULTS, {"checks": [{"id": "a", "type": "tcp", "host": "x", "port": 1}]}))
    with pytest.raises(ValueError):
        validate(merge(DEFAULTS, {"checks": [{"id": "a", "type": "http"}]}))
    with pytest.raises(ValueError):
        validate(merge(DEFAULTS, {"checks": [{"id": "a", "type": "tcp", "host": "x", "port": 1}] * 2}))


def test_store_buckets(tmp_path):
    st = Store(tmp_path)
    now = time.time()
    st.add_results([(now - 60, "a", 1, 5.0, ""), (now - 30, "a", 0, None, "x"), (now - 7200, "a", 1, 3.0, "")])
    assert st.uptime("a", 24) == pytest.approx(66.67, 0.01)
    bars = st.buckets("a", 24, 48)
    assert len(bars) == 48 and bars[-1]["up"] == 0.5 and bars[0]["up"] is None


def test_config_written_and_bad_file_kept(tmp_path):
    cfg = Config(tmp_path)
    assert (tmp_path / "config.yaml").exists() and cfg.get()["title"] == "Vigil"
    (tmp_path / "config.yaml").write_text("checks: [{id: a}]")
    cfg.mtime = None
    assert cfg.get()["title"] == "Vigil" and cfg.error


def test_checks_down_alert_and_recovery(tmp_path):
    """A check that fails twice goes down (incident + alert), then recovers (incident closed + alert)."""
    async def run():
        hits = {"ok": False}

        async def handler(request):
            return web.Response(status=200 if hits["ok"] else 503)
        app = web.Application()
        app.router.add_get("/", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        (tmp_path / "config.yaml").write_text(f"checks: [{{id: svc, name: Svc, type: http, url: 'http://127.0.0.1:{port}/'}}]\nexposure: {{enabled: false}}\n")
        eng = Engine(Config(tmp_path), tmp_path)
        import aiohttp
        eng.session = aiohttp.ClientSession()
        try:
            await eng.run_checks()
            assert eng.checks["svc"]["status"] == "pending"
            await eng.run_checks()
            assert eng.checks["svc"]["status"] == "down" and eng.issues()[0]["title"] == "Svc is down"
            hits["ok"] = True
            await eng.run_checks()
            assert eng.checks["svc"]["status"] == "up" and not eng.issues()
            titles = [e["title"] for e in eng.store.events()]
            assert titles == ["Svc is back up", "Svc is DOWN"]
            assert eng.store.incidents()[0]["end"] is not None
            st = eng.state()
            assert st["summary"]["up"] == 1 and st["groups"][0]["checks"][0]["id"] == "svc"
        finally:
            await eng.session.close()
            await runner.cleanup()
    asyncio.run(run())


def test_briefing_never_catches_up(tmp_path, monkeypatch):
    """Started at night with no briefing yet: the clock must not send one (only 07:00-07:30)."""
    import datetime as dt
    from vigil import engine as em
    sent = []

    class Night(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 10, 16, 23, 35)
    monkeypatch.setattr(em, "datetime", Night)
    (tmp_path / "config.yaml").write_text("briefing: {enabled: true, url: 'http://x', time: '07:00'}\nexposure: {enabled: false}\n")
    eng = Engine(Config(tmp_path), tmp_path)
    eng.started -= 1000

    async def fake_brief():
        sent.append(1)
    eng.make_briefing = fake_brief

    async def run():
        task = asyncio.create_task(eng._briefing_clock())
        await asyncio.sleep(0.2)
        task.cancel()
    asyncio.run(run())
    assert not sent


def test_demo_mode_fills_every_panel(tmp_path, monkeypatch):
    """--demo: the real engine on simulated probes fills every panel and makes no network requests."""
    from vigil import demo
    for name in dir(probes):  # demo.install swaps probe functions; put the real ones back after the test
        if not name.startswith("_") and callable(getattr(probes, name)):
            monkeypatch.setattr(probes, name, getattr(probes, name))

    async def run():
        demo.write_config(tmp_path)
        eng = Engine(Config(tmp_path), tmp_path)
        demo.install(eng, tmp_path)
        import aiohttp
        eng.session = aiohttp.ClientSession()
        try:
            for job in (eng.run_checks, eng.run_checks, eng.run_power, eng.run_disks, eng.run_games, eng.run_exposure, eng.run_certs, eng.run_ct):
                await job()
            await eng.make_briefing()
            return eng.state()
        finally:
            await eng.session.close()
    s = asyncio.run(run())
    assert s["summary"]["total"] == 15 and s["summary"]["up"] >= 13
    assert s["power"]["devices"] and len(s["disks"]["devices"]) == 5 and len(s["games"]) == 2
    assert s["exposure"]["ip"] == "203.0.113.7" and s["exposure"]["certs"] and s["exposure"]["ct"]
    assert s["briefing"]["text"] and s["incidents"] and s["uptime"]["immich"]["d7"] < 100
    assert any("8443" in i["title"] for i in s["issues"])
