"""AMP discovery: port parsing, probe choice, the API flow against a fake AMP, and the game alert rules."""
import asyncio

import aiohttp
from aiohttp import web

from vigil import probes
from vigil.config import Config
from vigil.engine import Engine

# App.Ports rows as AMP stores them (Valheim template: query port is a child at offset 1)
VALHEIM_PORTS = [{"Protocol": 1, "Port": 2456, "Ref": "ApplicationPort1", "Name": "Game Port",
                  "ChildPorts": [{"Protocol": 1, "Offset": 1, "Ref": "ApplicationPort2", "Name": "Steam Query Port", "ChildPorts": None}]}]
PALWORLD_PORTS = [{"Protocol": 1, "Port": 8213, "Ref": "GamePort", "Name": "Game Port"},
                  {"Protocol": 0, "Port": 8213, "Ref": "RESTAPIPort", "Name": "REST API Port"},
                  {"Protocol": 1, "Port": 27016, "Ref": "QueryPort", "Name": "Query Port"},
                  {"Protocol": 0, "Port": 25576, "Ref": "RCONPort", "Name": "RCON Port"}]


def test_amp_ports_and_probe_choice():
    v = probes.amp_ports(VALHEIM_PORTS)
    assert [(p["port"], p["protocol"], p["player"]) for p in v] == [(2456, "udp", True), (2457, "udp", True)]
    assert probes.game_probe("Valheim", v) == ("a2s", 2457)
    pal = probes.amp_ports(PALWORLD_PORTS)
    assert [p["port"] for p in pal if p["player"]] == [8213, 27016]  # not REST API or RCON
    assert probes.game_probe("Palworld (Modded)", pal) == ("a2s", 27016)
    mc = probes.amp_ports([{"Name": "Minecraft Server Port", "PortNumber": 25565, "Protocol": 0}, {"Name": "RCON Port", "PortNumber": 25575, "Protocol": 0}])
    assert probes.game_probe("Minecraft", mc) == ("minecraft", 25565)
    assert probes.game_probe("Some Game", probes.amp_ports([{"Name": "Game Port", "PortNumber": 7777, "Protocol": 0}])) == ("tcp", 7777)
    assert probes.game_probe("Nothing", []) == (None, None)


def fake_amp(state):
    """A tiny AMP: Core/Login, ADSModule/GetInstances, GetInstanceNetworkInfo, Core/Logout."""
    async def api(request):
        body = await request.json()
        method = request.match_info["m"]
        if method == "Core/Login":
            ok = body.get("username") == "vigil" and body.get("password") == "pw"
            return web.json_response({"success": ok, "sessionID": "s1" if ok else "", "resultReason": "" if ok else "Bad login"})
        if body.get("SESSIONID") != "s1":
            return web.json_response({"Title": "Unauthorized Access"})
        if method == "Core/Logout":
            state["logouts"] += 1
            return web.json_response(None)
        if method == "ADSModule/GetInstances":
            return web.json_response([{"AvailableInstances": [
                {"InstanceID": "a", "InstanceName": "ADS01", "FriendlyName": "ADS01", "Module": "ADS", "Running": True, "AppState": 20},
                *state["instances"]]}])
        if method == "ADSModule/GetInstanceNetworkInfo":
            return web.json_response({"result": state["ports"].get(body["InstanceName"], [])})
        return web.json_response({}, status=404)
    app = web.Application()
    app.router.add_post("/API/{m:.+}", api)
    return app


async def start(app):
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    return runner, site._server.sockets[0].getsockname()[1]


VALHEIM = {"InstanceID": "v", "InstanceName": "Valheim01", "FriendlyName": "Viking world", "Module": "GenericModule",
           "ModuleDisplayName": "Valheim", "Running": True, "AppState": 20, "IP": "0.0.0.0"}
PAL = {"InstanceID": "p", "InstanceName": "Pal01", "FriendlyName": "Pal server", "Module": "GenericModule",
       "ModuleDisplayName": "Palworld (Modded)", "Running": False, "AppState": 0, "IP": "0.0.0.0"}
NET = {"Valheim01": [{"Name": "Game Port", "PortNumber": 2456, "Protocol": 1}, {"Name": "Steam Query Port", "PortNumber": 2457, "Protocol": 1}],
       "Pal01": [{"Name": "Game Port", "PortNumber": 8213, "Protocol": 1}, {"Name": "Query Port", "PortNumber": 27016, "Protocol": 1},
                 {"Name": "RCON Port", "PortNumber": 25576, "Protocol": 0}]}


def test_amp_instances_api_flow():
    state = {"instances": [VALHEIM, PAL], "ports": NET, "logouts": 0}

    async def run():
        runner, port = await start(fake_amp(state))
        async with aiohttp.ClientSession() as s:
            try:
                found = await probes.amp_instances(s, f"http://127.0.0.1:{port}", "vigil", "pw")
                bad = None
                try:
                    await probes.amp_instances(s, f"http://127.0.0.1:{port}", "vigil", "nope")
                except PermissionError as ex:
                    bad = str(ex)
                return found, bad
            finally:
                await runner.cleanup()
    found, bad = asyncio.run(run())
    assert [(i["name"], i["game"], i["state"], i["running"]) for i in found] == [
        ("Viking world", "Valheim", "running", True), ("Pal server", "Palworld (Modded)", "stopped", False)]
    assert [p["port"] for p in found[0]["ports"]] == [2456, 2457] and state["logouts"] == 1
    assert "Bad login" in bad


def test_engine_amp_games_and_alerts(tmp_path, monkeypatch):
    """First start asks AMP; stopped = grey, no alert. A game that stops answering makes Vigil ask AMP again:
    still running -> one more try -> alert; stopped or deleted in AMP -> no alert. AMP down alerts once."""
    state = {"instances": [VALHEIM, PAL], "ports": NET, "logouts": 0, "logins": 0}
    answers = {"up": True}
    a2s_calls = []

    async def fake_a2s(host, port, timeout=3):
        a2s_calls.append((host, port))
        if not answers["up"]:
            raise TimeoutError("timed out")
        return {"name": "My Valheim Server", "map": "w", "players": 1, "max_players": 10}
    monkeypatch.setattr(probes, "a2s_info", fake_a2s)
    real = probes.amp_instances
    asks = []

    async def counting(*a, **kw):
        asks.append(1)
        return await real(*a, **kw)
    monkeypatch.setattr(probes, "amp_instances", counting)

    async def run():
        runner, port = await start(fake_amp(state))
        cfg = (f"amp: {{url: 'http://127.0.0.1:{port}', username: vigil, password: pw, addresses: {{Viking world: valheim.example.com}}}}\n"
               "exposure: {enabled: false, expected_ports: [443]}\n")
        (tmp_path / "config.yaml").write_text(cfg)
        eng = Engine(Config(tmp_path), tmp_path)
        eng.session = aiohttp.ClientSession()
        alerts = []

        async def alert(level, title, body=""):
            alerts.append((level, title))
        eng.alert = alert
        try:
            await eng.run_games()  # first start: no saved list, so AMP is asked once
            assert len(asks) == 1
            g = {x["name"]: x for x in eng.games}
            assert g["Viking world"]["online"] and g["Viking world"]["players"] == 1 and g["Viking world"]["address"] == "valheim.example.com"
            assert g["Pal server"]["online"] is False and not g["Pal server"]["expected"] and g["Pal server"]["detail"] == "stopped in AMP"
            assert a2s_calls == [("127.0.0.1", 2457)]  # only the running game is queried, on its query port
            assert eng.expected_ports() == [443, 2456, 2457, 8213, 27016]  # RCON 25576 is not a player port
            assert not eng.issues() and not alerts

            await eng.run_games()  # healthy check: AMP is not asked
            assert len(asks) == 1

            answers["up"] = False  # stops answering while AMP still says running: ask AMP, retry, alert
            await eng.run_games()
            assert len(asks) == 2 and len(a2s_calls) == 4
            assert alerts == [("bad", "Viking world is not answering")]
            assert eng.issues()[0]["title"] == "Viking world is not answering"
            await eng.run_games()
            assert alerts == [("bad", "Viking world is not answering")]  # no repeat while down
            answers["up"] = True
            await eng.run_games()
            assert alerts[-1] == ("ok", "Viking world is answering again")

            # stopped in AMP on purpose: the failed check asks AMP, sees "stopped" -> grey card, no alert
            answers["up"] = False
            state["instances"] = [{**VALHEIM, "Running": False, "AppState": 0}, PAL]
            n = len(alerts)
            await eng.run_games()
            assert len(alerts) == n and eng.games[0]["state"] == "stopped" and not eng.games[0]["expected"]

            # deleted from AMP: the card goes away (found at the next morning list or failed check)
            state["instances"] = [PAL]
            await eng.run_amp()
            assert [x["name"] for x in eng.games] == ["Pal server"] and eng.expected_ports() == [443, 8213, 27016]
            assert any("removed from AMP: Viking world" in e["title"] for e in eng.store.events())

            await runner.cleanup()  # AMP goes away
            await eng.run_amp()
            await eng.run_amp()
            assert [a for a in alerts if "AMP" in a[1]] == [("warn", "AMP unreachable")]
            assert len(eng.games) == 1 and any(i["title"] == "AMP unreachable" for i in eng.issues())
        finally:
            await eng.session.close()
    asyncio.run(run())


def test_amp_daily_time(tmp_path):
    (tmp_path / "config.yaml").write_text("briefing: {time: '07:00'}\nexposure: {enabled: false}\n")
    eng = Engine(Config(tmp_path), tmp_path)
    assert eng.amp_daily_time() == "06:50"
    (tmp_path / "config.yaml").write_text("briefing: {time: '00:05'}\namp: {daily_time: ''}\nexposure: {enabled: false}\n")
    eng.config.mtime = None
    assert eng.amp_daily_time() == "23:55"
    (tmp_path / "config.yaml").write_text("amp: {daily_time: '05:30'}\nexposure: {enabled: false}\n")
    eng.config.mtime = None
    assert eng.amp_daily_time() == "05:30"


def test_steam_game_without_query_trusts_amp(tmp_path, monkeypatch):
    """A running AMP game that has never answered A2S shows online (AMP's word) and never alerts."""
    async def no_answer(host, port, timeout=3):
        raise TimeoutError("timed out")
    monkeypatch.setattr(probes, "a2s_info", no_answer)
    (tmp_path / "config.yaml").write_text("amp: {url: 'http://127.0.0.1:1', username: vigil}\nexposure: {enabled: false}\n")
    eng = Engine(Config(tmp_path), tmp_path)
    eng.amp = {"instances": [probes.amp_instance(VALHEIM, probes.amp_ports(NET["Valheim01"]))], "error": "", "ts": 1, "ok": True}
    alerts = []

    async def alert(level, title, body=""):
        alerts.append(title)
    eng.alert = alert

    async def run():
        for _ in range(3):
            await eng.run_games()
    asyncio.run(run())
    assert eng.games[0]["online"] is True and "no answer to the Steam query" in eng.games[0]["detail"] and not alerts
