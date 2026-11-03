"""The watch loops: checks, power, disks, games, internet exposure, daily briefing; alerts on changes."""
import asyncio
import json
import logging
import re
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse

import aiohttp

from . import probes
from .store import Store

log = logging.getLogger("vigil")


class Engine:
    def __init__(self, config, data_dir):
        self.config = config
        self.store = Store(data_dir)
        self.checks = {}  # id -> live state
        self.power = {"devices": [], "errors": [], "ts": None}
        self.disks = {"devices": [], "error": "", "ts": None}
        self.games = []
        self.game_state = {}  # target id -> {fails, status}
        self.amp = self.store.get("amp", {"instances": [], "error": "", "ts": None, "ok": None})
        self.a2s_seen = set(self.store.get("a2s_seen", []))  # games that answered the Steam query at least once
        self.exposure = self.store.get("exposure", {"ip": None, "shodan": None, "certs": [], "ct": [], "errors": [], "ts": None})
        self.briefing = self.store.get("briefing", {"ts": None, "text": "", "error": ""})
        self.started = time.time()
        self.session = None
        self._briefing_lock = asyncio.Lock()
        self._games_lock = asyncio.Lock()

    @property
    def c(self):
        return self.config.get()

    # ---------- main ----------

    async def run(self):
        self.session = aiohttp.ClientSession()
        loops = [self._every(self.c["interval_seconds"], self.run_checks), self._every(60, self.run_power),
                 self._every(lambda: max(60, int(self.c["games_interval_seconds"])), self.run_games), self._amp_clock(), self._every(600, self.run_disks), self._every(3600, self.run_certs),
                 self._every(6 * 3600, self.run_exposure), self._every(24 * 3600, self.run_ct),
                 self._every(3600, lambda: asyncio.to_thread(self.store.prune, self.c["keep_days"])), self._briefing_clock()]
        await asyncio.gather(*loops)

    async def _every(self, seconds, fn):
        while True:
            try:
                await fn()
            except Exception:
                log.exception("loop %s failed", getattr(fn, "__name__", fn))
            await asyncio.sleep(seconds if not callable(seconds) else seconds())

    # ---------- service checks ----------

    async def run_checks(self):
        c = self.c
        timeout = float(c["timeout_seconds"])
        wanted = {chk["id"]: chk for chk in c["checks"]}
        for gone in set(self.checks) - set(wanted):
            del self.checks[gone]
        open_inc = self.store.open_incidents()

        async def one(chk):
            if chk["type"] == "http":
                return await probes.http_check(self.session, chk, timeout)
            return await probes.tcp_check(chk, timeout)
        results = await asyncio.gather(*(one(chk) for chk in wanted.values()))
        now = time.time()
        rows = []
        for chk, (ok, ms, detail) in zip(wanted.values(), results):
            st = self.checks.setdefault(chk["id"], {"fails": 0, "status": "unknown", "since": now})
            st.update(id=chk["id"], name=chk.get("name", chk["id"]), group=chk.get("group", "Other"), icon=chk.get("icon", ""),
                      optional=bool(chk.get("optional")), link=chk.get("link") or (chk.get("url") if chk["type"] == "http" else ""),
                      target=chk.get("url") or f"{chk['host']}:{chk['port']}", ok=ok, ms=round(ms, 1) if ms is not None else None,
                      detail=detail, checked=now)
            st["fails"] = 0 if ok else st["fails"] + 1
            old = st["status"]
            new = "up" if ok else ("down" if st["fails"] >= int(c["fail_after"]) else old if old != "unknown" else "pending")
            if new != old and new in ("up", "down"):
                st["since"] = now
                if new == "down":
                    if chk["id"] not in open_inc:
                        self.store.open_incident(chk["id"], st["name"], now, detail)
                    if not st["optional"]:
                        await self.alert("bad", f"{st['name']} is DOWN", f"{st['target']}: {detail}")
                elif old == "down":
                    self.store.close_incident(chk["id"], now)
                    if not st["optional"]:
                        await self.alert("ok", f"{st['name']} is back up", f"after {fmt_duration(now - open_inc.get(chk['id'], st['since']))}")
                elif chk["id"] in open_inc:  # was down before a restart
                    self.store.close_incident(chk["id"], now)
            st["status"] = new
            rows.append((now, chk["id"], int(ok), ms, detail))
        await asyncio.to_thread(self.store.add_results, rows)

    # ---------- power ----------

    async def run_power(self):
        devices, errors = [], []
        for srv in self.c["nut"]:
            try:
                found = await probes.nut_query(srv["host"], int(srv.get("port", 3493)))
                for name, v in found.items():
                    d = probes.summarize_ups(name, v, (srv.get("watts") or {}).get(name))
                    d["server"] = srv.get("name", srv["host"])
                    devices.append(d)
            except Exception as ex:
                errors.append(f"{srv.get('name', srv['host'])}: {probes.short_error(ex)}")
        before = {d["name"]: d for d in self.power["devices"]}
        for d in devices:
            was = before.get(d["name"])
            if was and d["on_battery"] and not was["on_battery"]:
                await self.alert("bad", f"{d['name']} is ON BATTERY", f"charge {d['charge']}%, about {d['runtime_min']} min left")
            if was and was["on_battery"] and not d["on_battery"]:
                await self.alert("ok", f"{d['name']} is back on mains power", f"charge {d['charge']}%")
        self.power = {"devices": devices, "errors": errors, "ts": time.time()}

    # ---------- disks ----------

    async def run_disks(self):
        url = self.c["scrutiny_url"]
        if not url:
            return
        try:
            devices = await probes.scrutiny_summary(self.session, url, 20)
            before = {d["serial"]: d for d in self.disks["devices"]}
            for d in devices:
                if not d["ok"] and before.get(d["serial"], {}).get("ok", True):
                    await self.alert("bad", f"Drive {d['name']} {d['status']}", f"{d['model']} {d['serial']} - check Scrutiny")
            self.disks = {"devices": devices, "error": "", "ts": time.time()}
        except Exception as ex:
            self.disks["error"] = probes.short_error(ex)

    # ---------- games: AMP discovery + manual entries ----------

    async def run_amp(self):
        """Ask AMP for its server list now, then check the games (the API refresh button and the daily clock)."""
        async with self._games_lock:
            await self._discover()
            await self._run_games()

    async def _amp_clock(self):
        """Ask AMP for the server list once a day, shortly before the morning briefing (amp.daily_time, default
        10 minutes before briefing.time). Between those, AMP is only asked when a game check fails."""
        while True:
            try:
                if self.c["amp"].get("url"):
                    hh, mm = map(int, self.amp_daily_time().split(":"))
                    now = datetime.now()
                    due = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
                    if due <= now < due + timedelta(minutes=30) and (self.amp.get("ts") or 0) < due.timestamp():
                        await self.run_amp()
            except Exception:
                log.exception("AMP clock")
            await asyncio.sleep(60)

    def amp_daily_time(self):
        t = str(self.c["amp"].get("daily_time") or "")
        if t:
            return t
        hh, mm = map(int, str(self.c["briefing"].get("time", "07:00")).split(":"))
        before = datetime(2000, 1, 2, hh, mm) - timedelta(minutes=10)
        return before.strftime("%H:%M")

    async def _discover(self):
        """Ask AMP which game servers exist (and their ports and state). Keeps the last list when AMP can't be reached."""
        amp = self.c["amp"]
        if not amp.get("url"):
            self.amp = {"instances": [], "error": "", "ts": None, "ok": None}
            return False
        try:
            found = await probes.amp_instances(self.session, amp["url"], amp.get("username", ""), amp.get("password", ""))
        except Exception as ex:
            err = probes.short_error(ex)
            if self.amp.get("ok") is not False:
                await self.alert("warn", "AMP unreachable", f"{err} - game servers show their last known state")
            self.amp.update(error=err, ok=False)
            return False
        if self.amp.get("ok") is False:
            await self.alert("ok", "AMP reachable again", f"{len(found)} game server(s)")
        before = {i["id"]: i for i in self.amp.get("instances", [])}
        if self.amp.get("ts"):  # not on the very first discovery
            for inst in found:
                was = before.get(inst["id"])
                if not was:
                    await asyncio.to_thread(self.store.add_event, "info", f"New game server in AMP: {inst['name']}", f"{inst['game']}, {inst['state']}")
                elif was["state"] != inst["state"]:
                    if inst["state"] == "failed":
                        await self.alert("bad", f"{inst['name']} failed in AMP", f"{inst['game']} was {was['state']}")
                    else:
                        await asyncio.to_thread(self.store.add_event, "info", f"{inst['name']} is {inst['state']} in AMP", inst["game"])
            for gone in set(before) - {i["id"] for i in found}:
                await asyncio.to_thread(self.store.add_event, "info", f"Game server removed from AMP: {before[gone]['name']}", before[gone]["game"])
        self.amp = {"instances": found, "error": "", "ts": time.time(), "ok": True}
        self.store.put("amp", self.amp)
        return True

    def amp_host(self, inst):
        """Where to reach an AMP game: amp.host, else the instance's own IP, else the AMP server's host."""
        amp = self.c["amp"]
        if amp.get("host"):
            return amp["host"]
        if inst.get("ip") and inst["ip"] not in ("0.0.0.0", "::", "127.0.0.1", "localhost"):
            return inst["ip"]
        return urlparse(amp["url"]).hostname

    def game_targets(self):
        """Every game server to show: AMP instances first, then manual `games:` entries (for servers not in AMP)."""
        out = []
        addresses = self.c["amp"].get("addresses") or {}
        for inst in self.amp.get("instances", []):
            kind, port = probes.game_probe(inst["game"], inst["ports"])
            host = self.amp_host(inst)
            connect = next((p["port"] for p in inst["ports"] if p["player"] and "query" not in p["name"].lower()), port)
            out.append({"id": f"amp:{inst['id']}", "name": inst["name"], "game": inst["game"], "source": "amp", "state": inst["state"],
                        "kind": kind, "host": host, "port": port,
                        "address": addresses.get(inst["name"]) or addresses.get(inst["instance"]) or (f"{host}:{connect}" if connect else host)})
        for g in self.c["games"]:
            kind = {"valheim": "a2s", "steam": "a2s", "a2s": "a2s"}.get(g["type"], g["type"])
            port = int(g.get("query_port", int(g.get("port", 2456)) + 1)) if g["type"] == "valheim" else int(g.get("port", 25565 if kind == "minecraft" else 27015))
            out.append({"id": f"cfg:{g.get('name', g['type'])}", "name": g.get("name", g["type"]), "game": g["type"].title(), "source": "config",
                        "state": "running", "kind": kind, "host": g["host"], "port": port, "address": g.get("address", "")})
        return out

    async def run_games(self):
        async with self._games_lock:
            if self.c["amp"].get("url") and not self.amp.get("ts"):  # first start: no saved list yet
                await self._discover()
            await self._run_games()

    async def _probe_game(self, t):
        """(ok, card fields) for one running game server."""
        try:
            if t["kind"] == "a2s":
                info = await probes.a2s_info(t["host"], t["port"])
                self.a2s_seen.add(t["id"])
            elif t["kind"] == "minecraft":
                info = await probes.minecraft_info(t["host"], t["port"])
            elif t["kind"] == "tcp":
                ok, ms, detail = await probes.tcp_check({"host": t["host"], "port": t["port"]}, float(self.c["timeout_seconds"]))
                if not ok:
                    raise ConnectionError(detail)
                info = {"detail": f"port {t['port']} open"}
            else:
                info = {"detail": "running in AMP (no query for this game)"}
            return True, {"online": True, "title": info.get("name"), "players": info.get("players"), "max_players": info.get("max_players"),
                          "map": info.get("map"), "version": info.get("version"), "detail": info.get("detail", "")}
        except Exception as ex:
            if t["kind"] == "a2s" and t["source"] == "amp" and t["id"] not in self.a2s_seen:
                # never answered A2S: probably a game without Steam query; trust AMP's "running"
                return True, {"online": True, "detail": "running in AMP (no answer to the Steam query)"}
            return False, {"online": False, "detail": probes.short_error(ex)}

    async def _run_games(self):
        """Check every running game server (every games_interval_seconds, default 15 min). A server that doesn't answer:
        ask AMP whether it still exists and still runs, then check it once more before alerting."""
        targets = self.game_targets()
        results = {t["id"]: await self._probe_game(t) for t in targets if t["state"] == "running"}
        failed = [t for t in targets if t["id"] in results and not results[t["id"]][0]]
        if failed and any(t["source"] == "amp" for t in failed) and self.c["amp"].get("url"):
            if await self._discover():
                targets = self.game_targets()
        for t in targets:
            if t["id"] in {f["id"] for f in failed} and t["state"] == "running":
                results[t["id"]] = await self._probe_game(t)  # still there and running: one more try (UDP can drop a packet)
        for gone in set(self.game_state) - {t["id"] for t in targets}:
            del self.game_state[gone]
        out = []
        for t in targets:
            st = self.game_state.setdefault(t["id"], {"status": "unknown"})
            item = {k: t[k] for k in ("name", "game", "source", "state", "address")}
            item.update(type=t["kind"] or "amp", online=False, players=None, max_players=None, detail="", expected=t["state"] == "running",
                        checked=time.time())
            if t["state"] != "running":  # stopped/sleeping/updating in AMP: nothing to check, never an alert
                st["status"] = "off"
                item["detail"] = f"{t['state']} in AMP"
                out.append(item)
                continue
            ok, fields = results[t["id"]]
            item.update(fields)
            new = "up" if ok else "down"
            if new != st["status"]:
                if new == "down":
                    why = "AMP says it is running, but it" if t["source"] == "amp" and self.amp.get("ok") else "it"
                    await self.alert("bad", f"{t['name']} is not answering", f"{why} does not answer on {t['host']}:{t['port']}: {item['detail']}")
                elif st["status"] == "down":
                    await self.alert("ok", f"{t['name']} is answering again", item.get("title") or t["game"])
                st["status"] = new
            out.append(item)
        self.games = out
        self.store.put("a2s_seen", sorted(self.a2s_seen))

    def expected_ports(self):
        """Public ports that are fine: exposure.expected_ports + the player ports of every AMP game server."""
        ports = set(self.c["exposure"].get("expected_ports", []))
        for inst in self.amp.get("instances", []):
            ports |= {p["port"] for p in inst["ports"] if p["player"]}
        return sorted(ports)

    # ---------- internet exposure ----------

    async def run_exposure(self):
        ex = self.c["exposure"]
        if not ex.get("enabled", True):
            return
        errors = []
        ip = await probes.public_ip(self.session)
        shodan = self.exposure.get("shodan")
        if ip:
            try:
                shodan = await probes.shodan_internetdb(self.session, ip)
            except Exception as e:
                errors.append(f"Shodan InternetDB: {probes.short_error(e)}")
        else:
            errors.append("could not find the public IP")
        old = self.exposure.get("shodan") or {}
        if self.exposure.get("ip") and ip and ip != self.exposure["ip"]:
            await self.alert("info", "Public IP changed", f"{self.exposure['ip']} -> {ip}")
        if shodan and old:
            new_ports = set(shodan.get("ports", [])) - set(old.get("ports", []))
            new_vulns = set(shodan.get("vulns", [])) - set(old.get("vulns", []))
            if new_ports:
                await self.alert("warn", "New port visible from the internet", f"Shodan now sees {sorted(new_ports)} open on {ip}")
            if new_vulns:
                await self.alert("bad", "Shodan lists new vulnerabilities", ", ".join(sorted(new_vulns)))
        self.exposure.update(ip=ip, shodan=shodan, errors=errors + [e for e in self.exposure.get("errors", []) if not e.startswith(("Shodan", "could not"))], ts=time.time())
        self.store.put("exposure", self.exposure)

    async def run_certs(self):
        ex = self.c["exposure"]
        certs = []
        warn = int(ex.get("cert_warn_days", 14))
        before = {x["name"]: x for x in self.exposure.get("certs", [])}
        for h in ex.get("public_hosts", []):
            item = {"name": h.get("name", h["url"]), "url": h["url"], "planned": bool(h.get("planned"))}
            try:
                item.update(await probes.cert_info(h["url"]))
                ok, ms, detail = await probes.http_check(self.session, {"url": h["url"], "insecure": False}, 10)
                item.update(reachable=ok, http=detail, ms=round(ms) if ms else None)
            except Exception as e:
                item.update(valid=False, reachable=False, error=probes.short_error(e))
            was = before.get(item["name"], {})
            if item.get("days_left") is not None and item["days_left"] <= warn and (was.get("days_left") or 999) > warn:
                await self.alert("warn", f"Certificate for {item['name']} expires in {item['days_left']} days", item["url"])
            if was.get("reachable") and not item.get("reachable") and not item["planned"]:
                await self.alert("bad", f"{item['name']} is not reachable from outside", item.get("error") or item.get("http", ""))
            certs.append(item)
        self.exposure["certs"] = certs
        self.store.put("exposure", self.exposure)

    async def run_ct(self):
        domain = self.c["exposure"].get("domain")
        if not domain:
            return
        try:
            ct = await probes.crtsh(self.session, domain)
        except Exception as e:
            self.exposure["errors"] = [x for x in self.exposure.get("errors", []) if not x.startswith("crt.sh")] + [f"crt.sh: {probes.short_error(e)}"]
            return
        seen = set(self.store.get("ct_seen", []))
        if seen:
            for cert in ct:
                if cert["id"] not in seen:
                    await self.alert("warn", "New certificate issued", f"{', '.join(cert['names'])} by {cert['issuer'][:80]} - expected if you just added or renewed a site; otherwise investigate")
        self.store.put("ct_seen", [x["id"] for x in ct])
        self.exposure["ct"] = ct[:25]
        self.exposure["errors"] = [x for x in self.exposure.get("errors", []) if not x.startswith("crt.sh")]
        self.store.put("exposure", self.exposure)

    # ---------- issues + briefing ----------

    def issues(self):
        """Everything that needs attention right now, most serious first: [{level, title, detail}]."""
        out = []
        if self.config.error:
            out.append({"level": "bad", "title": "config.yaml has an error", "detail": self.config.error})
        for st in self.checks.values():
            if st["status"] == "down" and not st["optional"]:
                out.append({"level": "bad", "title": f"{st['name']} is down", "detail": f"{st['target']}: {st['detail']}, since {fmt_ago(st['since'])}"})
        for d in self.power["devices"]:
            if d["on_battery"]:
                out.append({"level": "bad", "title": f"{d['name']} on battery", "detail": f"{d['charge']}% charge, ~{d['runtime_min']} min"})
            elif d["charge"] is not None and d["charge"] < 90:
                out.append({"level": "warn", "title": f"{d['name']} battery at {d['charge']:.0f}%", "detail": "charging or worn battery"})
            age = battery_age_years(d.get("battery_date"))
            if age is not None and age >= 3.5:
                out.append({"level": "warn", "title": f"{d['name']} battery is {age:.1f} years old", "detail": "APC batteries last 3-5 years; plan a replacement"})
        out += [{"level": "warn", "title": "NUT server unreachable", "detail": e} for e in self.power["errors"]]
        if self.c["amp"].get("url") and self.amp.get("error"):
            out.append({"level": "warn", "title": "AMP unreachable", "detail": f"{self.amp['error']}; game servers show their last known state"})
        for g in self.games:
            if g["online"] is False and g.get("expected"):
                out.append({"level": "bad", "title": f"{g['name']} is not answering", "detail": g["detail"]})
        for d in self.disks["devices"]:
            if not d["ok"]:
                out.append({"level": "bad", "title": f"Drive {d['name']}: {d['status']}", "detail": f"{d['model']} {d['serial']}"})
            elif d["temp"] and d["temp"] >= 60:
                out.append({"level": "warn", "title": f"Drive {d['name']} is hot ({d['temp']} °C)", "detail": d["model"]})
        ex = self.c["exposure"]
        sh = self.exposure.get("shodan") or {}
        unexpected = sorted(set(sh.get("ports", [])) - set(self.expected_ports()))
        if unexpected:
            out.append({"level": "warn", "title": f"Unexpected public port(s): {', '.join(map(str, unexpected))}",
                        "detail": "Shodan sees these open on your public IP; close them, or add them to exposure.expected_ports if intended (AMP game ports count automatically)"})
        if sh.get("vulns"):
            out.append({"level": "bad", "title": f"{len(sh['vulns'])} known vulnerabilities on your public IP", "detail": ", ".join(sh["vulns"][:6])})
        for cert in self.exposure.get("certs", []):
            if cert.get("planned"):
                continue
            if cert.get("valid") is False:
                out.append({"level": "bad", "title": f"{cert['name']}: certificate problem", "detail": cert.get("error", "")})
            elif cert.get("days_left") is not None and cert["days_left"] <= int(ex.get("cert_warn_days", 14)):
                out.append({"level": "warn", "title": f"{cert['name']} certificate expires in {cert['days_left']} days", "detail": cert.get("issuer", "")})
            elif cert.get("reachable") is False:
                out.append({"level": "bad", "title": f"{cert['name']} unreachable from the internet side", "detail": cert.get("http") or cert.get("error", "")})
        out += [{"level": "info", "title": "Exposure check incomplete", "detail": e} for e in self.exposure.get("errors", [])]
        order = {"bad": 0, "warn": 1, "info": 2}
        return sorted(out, key=lambda i: order[i["level"]])

    async def _briefing_clock(self):
        while True:
            try:
                b = self.c["briefing"]
                hh, mm = map(int, str(b.get("time", "07:00")).split(":"))
                now = datetime.now()
                last = self.briefing.get("ts") or 0
                due = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
                # Only in the 30 minutes after the set time: never a catch-up briefing (e.g. at night after a restart).
                in_window = due <= now < due + timedelta(minutes=30)
                if b.get("enabled") and in_window and last < due.timestamp() and time.time() - self.started > 120:
                    await self.make_briefing()
                    text = self.briefing.get("text")
                    if text:
                        await asyncio.to_thread(self.store.add_event, "info", "Morning briefing sent", text[:300])
                        await self.notify("info", "Vigil morning briefing", text)
            except Exception:
                log.exception("briefing clock")
            await asyncio.sleep(60)

    def snapshot_for_briefing(self):
        checks = list(self.checks.values())
        return {
            "now": datetime.now().strftime("%A %Y-%m-%d %H:%M"),
            "services": {"total": len(checks), "up": sum(1 for x in checks if x["status"] == "up"),
                         "down": [x["name"] for x in checks if x["status"] == "down" and not x["optional"]],
                         "optional_off": [x["name"] for x in checks if x["status"] == "down" and x["optional"]],
                         "slowest": sorted(((x["name"], x["ms"]) for x in checks if x.get("ms")), key=lambda t: -t[1])[:3]},
            "incidents_last_24h": [{"name": i["name"], "start": fmt_time(i["start"]), "end": fmt_time(i["end"]) if i["end"] else "still down"}
                                   for i in self.store.incidents(50) if i["start"] > time.time() - 86400],
            "power": {"note": "PDUs are plugged into the UPSes, so never add PDU watts to UPS watts. Total draw = ups_total_w.",
                      "ups_total_w": sum(d["load_w"] or 0 for d in self.power["devices"] if not d["pdu"]),
                      "ups": [{k: d[k] for k in ("name", "status", "charge", "runtime_min", "load_pct", "load_w", "battery_date")} for d in self.power["devices"] if not d["pdu"]],
                      "pdus": [{k: d[k] for k in ("name", "load_w")} for d in self.power["devices"] if d["pdu"]]},
            "disks": [{k: d[k] for k in ("name", "model", "temp", "status")} for d in self.disks["devices"]],
            "games": [{k: g.get(k) for k in ("name", "game", "state", "online", "players", "max_players")} for g in self.games],
            "internet": {"public_ip": self.exposure.get("ip"), "shodan_ports": (self.exposure.get("shodan") or {}).get("ports"),
                         "expected_ports": self.expected_ports(),
                         "certs": [{k: x.get(k) for k in ("name", "days_left", "reachable", "planned")} for x in self.exposure.get("certs", [])]},
            "issues": self.issues(),
        }

    async def make_briefing(self):
        b = self.c["briefing"]
        if not b.get("url"):
            self.briefing = {"ts": time.time(), "text": "", "error": "No LLM configured (briefing.url in config.yaml)."}
            return self.briefing
        async with self._briefing_lock:
            facts = json.dumps(self.snapshot_for_briefing(), indent=1, default=str)
            body = {"model": b.get("model", ""), "max_tokens": 3000, "temperature": 0.6, "messages": [
                {"role": "system", "content": (
                    "You are Vigil, the watch officer of a home lab. Write a short morning briefing for its owner from the JSON facts. "
                    "Start with one line verdict (all good / needs attention). Then 3-7 short bullet points: problems first with a concrete "
                    "next step, then notable facts (power draw, UPS runtime, drive temperatures, games with players, certificates expiring "
                    "within 30 days, anything visible from the internet). Never invent facts that are not in the JSON. Plain text with '- ' bullets, "
                    "no markdown headings, under 150 words.")},
                {"role": "user", "content": facts}]}
            body.update(b.get("extra_body") or {})
            headers = {"Content-Type": "application/json", **(b.get("headers") or {})}
            if b.get("api_key"):
                headers["Authorization"] = f"Bearer {b['api_key']}"
            try:
                async with self.session.post(b["url"], json=body, headers=headers, timeout=aiohttp.ClientTimeout(total=180)) as r:
                    data = await r.json(content_type=None)
                text = data["choices"][0]["message"].get("content") or ""
                text = re.sub(r"(?s)<think>.*?</think>", "", text).strip()
                self.briefing = {"ts": time.time(), "text": text, "error": "" if text else "the LLM returned nothing"}
            except Exception as ex:
                self.briefing = {"ts": time.time(), "text": self.briefing.get("text", ""), "error": f"LLM failed: {probes.short_error(ex)}"}
            self.store.put("briefing", self.briefing)
            return self.briefing

    # ---------- alerts ----------

    async def alert(self, level, title, body=""):
        log.info("ALERT [%s] %s - %s", level, title, body)
        await asyncio.to_thread(self.store.add_event, level, title, body)
        await self.notify(level, title, body)

    async def notify(self, level, title, body):
        n = self.c["notify"]
        icon = {"bad": "🔴", "warn": "🟠", "ok": "🟢", "info": "🔵"}.get(level, "")
        jobs = []
        if n.get("discord_webhook"):
            jobs.append(self._post(n["discord_webhook"], json={"username": "Vigil", "content": f"{icon} **{title}**\n{body}"[:1900]}))
        if n.get("ntfy_url"):
            jobs.append(self._post(n["ntfy_url"], data=body.encode(), headers={"Title": title.encode("ascii", "ignore").decode(),
                                                                                 "Priority": "high" if level == "bad" else "default",
                                                                                 "Tags": {"bad": "rotating_light", "warn": "warning", "ok": "white_check_mark"}.get(level, "information_source")}))
        if n.get("ha_webhook"):
            jobs.append(self._post(n["ha_webhook"], json={"level": level, "title": title, "body": body}))
        for res in await asyncio.gather(*jobs, return_exceptions=True):
            if isinstance(res, Exception):
                log.warning("notification failed: %s", res)

    async def _post(self, url, **kw):
        async with self.session.post(url, timeout=aiohttp.ClientTimeout(total=15), **kw) as r:
            if r.status >= 400:
                raise RuntimeError(f"{url.split('/')[2]} answered HTTP {r.status}")

    # ---------- state for the web page ----------

    def state(self):
        groups = {}
        for st in self.checks.values():
            groups.setdefault(st["group"], []).append(st)
        order = self.c.get("groups") or []
        group_list = sorted(groups.items(), key=lambda kv: order.index(kv[0]) if kv[0] in order else 999)
        uptime = {st["id"]: {"h24": self.store.uptime(st["id"], 24), "d7": self.store.uptime(st["id"], 168),
                             "bars": self.store.buckets(st["id"], 24, 48)} for st in self.checks.values()}
        checks = list(self.checks.values())
        return {
            "title": self.c["title"], "now": time.time(), "started": self.started,
            "summary": {"total": len(checks), "up": sum(1 for x in checks if x["status"] == "up"),
                        "down": sum(1 for x in checks if x["status"] == "down" and not x["optional"]),
                        "optional_off": sum(1 for x in checks if x["status"] == "down" and x["optional"]),
                        "avg_ms": round(sum(x["ms"] for x in checks if x.get("ms")) / max(1, sum(1 for x in checks if x.get("ms"))), 1)},
            "issues": self.issues(),
            "groups": [{"name": g, "checks": sorted(items, key=lambda x: x["name"].lower())} for g, items in group_list],
            "uptime": uptime, "power": self.power, "disks": self.disks, "games": self.games,
            "amp": {"configured": bool(self.c["amp"].get("url")), "error": self.amp.get("error", ""), "ts": self.amp.get("ts"),
                    "daily_time": self.amp_daily_time(), "games_interval": int(self.c["games_interval_seconds"]),
                    "count": len(self.amp.get("instances", []))},
            "exposure": {**self.exposure, "expected_ports": self.expected_ports(), "domain": self.c["exposure"].get("domain", "")},
            "briefing": {**self.briefing, "enabled": bool(self.c["briefing"].get("url")), "time": self.c["briefing"].get("time")},
            "incidents": self.store.incidents(20), "events": self.store.events(30),
            "notify": {k: bool(v) for k, v in self.c["notify"].items()},
        }


def fmt_duration(sec):
    sec = int(sec)
    if sec < 90:
        return f"{sec} s"
    if sec < 5400:
        return f"{sec // 60} min"
    if sec < 172800:
        return f"{sec / 3600:.1f} h"
    return f"{sec / 86400:.1f} days"


def fmt_ago(ts):
    return fmt_duration(time.time() - ts) + " ago"


def fmt_time(ts):
    return datetime.fromtimestamp(ts).strftime("%a %H:%M")


def battery_age_years(date):
    if not date:
        return None
    m = re.match(r"(\d{4})[/-](\d{1,2})", date) or re.match(r"(\d{1,2})/\d{1,2}/(\d{2,4})", date)
    if not m:
        return None
    try:
        if len(m.group(1)) == 4:
            y, mo = int(m.group(1)), int(m.group(2))
        else:
            mo, y = int(m.group(1)), int(m.group(2))
            y += 2000 if y < 100 else 0
        return (datetime.now() - datetime(y, mo, 1)).days / 365.25
    except ValueError:
        return None
