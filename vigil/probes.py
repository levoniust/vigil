"""Network probes: HTTP/TCP checks, NUT (UPS/PDU), Scrutiny, game servers (AMP discovery, A2S, Minecraft), TLS certificates, internet exposure."""
import asyncio
import json
import socket
import ssl
import struct
import time
from datetime import datetime, timezone

import aiohttp

UA = {"User-Agent": "Vigil homelab monitor"}


async def http_check(session, chk, timeout):
    """ok if the status is below 500 (or in chk['expect'])."""
    start = time.monotonic()
    try:
        async with session.get(chk["url"], ssl=False if chk.get("insecure", True) else None, allow_redirects=False,
                               timeout=aiohttp.ClientTimeout(total=timeout), headers=UA) as r:
            await r.read()
            ms = (time.monotonic() - start) * 1000
            expect = chk.get("expect")
            ok = r.status in expect if isinstance(expect, list) else r.status < 500
            return ok, ms, f"HTTP {r.status}"
    except asyncio.TimeoutError:
        return False, None, "timeout"
    except Exception as ex:
        return False, None, short_error(ex)


async def tcp_check(chk, timeout):
    start = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(chk["host"], int(chk["port"])), timeout)
        ms = (time.monotonic() - start) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True, ms, "open"
    except asyncio.TimeoutError:
        return False, None, "timeout"
    except Exception as ex:
        return False, None, short_error(ex)


def short_error(ex):
    text = str(ex) or type(ex).__name__
    for key, nice in (("Connection refused", "connection refused"), ("Connect call failed", "connection refused"), ("No route", "no route to host"),
                      ("Name or service not known", "unknown host"), ("certificate", "certificate error")):
        if key in text:
            return nice
    return text[:120]


# ---------- NUT (Network UPS Tools), plain text protocol on port 3493 ----------

async def nut_query(host, port=3493, timeout=5):
    """{ups_name: {var: value}} for every device on a NUT server (no login needed for reading)."""
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    try:
        async def ask(cmd, end):
            writer.write((cmd + "\n").encode())
            await writer.drain()
            lines = []
            while True:
                line = (await asyncio.wait_for(reader.readline(), timeout)).decode(errors="replace").strip()
                if not line or line.startswith("ERR"):
                    raise ConnectionError(line or "connection closed")
                if line.startswith(end):
                    return lines
                if not line.startswith("BEGIN"):
                    lines.append(line)
        devices = {}
        for line in await ask("LIST UPS", "END LIST UPS"):
            name = line.split()[1]
            devices[name] = {}
        for name in devices:
            for line in await ask(f"LIST VAR {name}", f"END LIST VAR {name}"):
                # VAR <ups> <var> "<value>"
                _, _, var, value = line.split(" ", 3)
                devices[name][var] = value.strip('"')
        writer.write(b"LOGOUT\n")
        return devices
    finally:
        writer.close()


def summarize_ups(name, v, watts=None):
    """watts: the UPS's rated real power, for UPSes that only report load in % (e.g. 1980 for an SMT2200)."""
    num = lambda k: float(v[k]) if k in v and v[k].replace(".", "", 1).lstrip("-").isdigit() else None  # noqa: E731
    status = v.get("ups.status", "")
    model = v.get("device.model") or v.get("ups.model") or ""
    is_pdu = "PDU" in (v.get("device.type", "") + model).upper() or model.upper().startswith("AP79")
    load_w = num("ups.realpower")
    nominal = num("ups.realpower.nominal") or watts
    if load_w is None and num("ups.load") is not None and nominal:
        load_w = num("ups.load") / 100 * float(nominal)
    return {
        "name": name, "model": model, "pdu": is_pdu, "status": status,
        "on_battery": "OB" in status.split(), "low_battery": "LB" in status.split(),
        "charge": num("battery.charge"), "runtime_min": round(num("battery.runtime") / 60) if num("battery.runtime") else None,
        "load_pct": num("ups.load"), "load_w": round(load_w) if load_w is not None else None,
        "input_v": num("input.voltage"), "battery_date": v.get("battery.date") or v.get("battery.mfr.date"),
    }


# ---------- Scrutiny (SMART) ----------

async def scrutiny_summary(session, base, timeout):
    async with session.get(base.rstrip("/") + "/api/summary", timeout=aiohttp.ClientTimeout(total=timeout), headers=UA) as r:
        data = await r.json(content_type=None)
    out = []
    for wwn, d in (data.get("data", {}).get("summary") or {}).items():
        dev = d.get("device", {})
        smart = d.get("smart") or {}
        status = dev.get("device_status", 0)  # 0 passed, bit 1 failed SMART, bit 2 failed Scrutiny thresholds
        out.append({
            "name": dev.get("device_name", wwn), "model": dev.get("model_name", ""), "serial": dev.get("serial_number", ""),
            "capacity_tb": round((dev.get("capacity") or 0) / 1e12, 2), "temp": smart.get("temp"),
            "power_on_hours": smart.get("power_on_hours"), "ok": status == 0,
            "status": "passed" if status == 0 else ("SMART failed" if status & 1 else "warning"),
        })
    return sorted(out, key=lambda x: x["name"])


# ---------- game servers ----------

async def a2s_info(host, port, timeout=3):
    """Steam A2S_INFO on the query port (Valheim: game port + 1). Returns {name, map, players, max_players}."""
    loop = asyncio.get_running_loop()
    req = b"\xFF\xFF\xFF\xFFTSource Engine Query\x00"

    def query():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            addr = (host, int(port))
            s.sendto(req, addr)
            data, _ = s.recvfrom(4096)
            if data[4:5] == b"A":  # challenge: repeat with it appended
                s.sendto(req + data[5:9], addr)
                data, _ = s.recvfrom(4096)
            return data
    data = await loop.run_in_executor(None, query)
    if data[4:5] != b"I":
        raise ValueError("unexpected A2S answer")
    pos = 6
    fields = []
    for _ in range(4):  # name, map, folder, game
        end = data.index(b"\x00", pos)
        fields.append(data[pos:end].decode(errors="replace"))
        pos = end + 1
    pos += 2  # app id
    players, max_players = data[pos], data[pos + 1]
    return {"name": fields[0], "map": fields[1], "players": players, "max_players": max_players}


async def valheim_info(host, port, timeout=3):  # name used before 1.1
    return await a2s_info(host, port, timeout)


def _varint(n):
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out


async def minecraft_info(host, port=25565, timeout=4):
    """Minecraft Server List Ping. Returns {name (motd), version, players, max_players}."""
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, int(port)), timeout)
    try:
        hb = host.encode()
        handshake = b"\x00" + _varint(767) + _varint(len(hb)) + hb + struct.pack(">H", int(port)) + b"\x01"
        writer.write(_varint(len(handshake)) + handshake + b"\x01\x00")
        await writer.drain()

        async def read_varint():
            num = shift = 0
            while True:
                b = (await asyncio.wait_for(reader.readexactly(1), timeout))[0]
                num |= (b & 0x7F) << shift
                if not b & 0x80:
                    return num
                shift += 7
        await read_varint()  # packet length
        await read_varint()  # packet id
        length = await read_varint()
        data = json.loads((await asyncio.wait_for(reader.readexactly(length), timeout)).decode())
        motd = data.get("description")
        if isinstance(motd, dict):
            motd = motd.get("text", "") + "".join(x.get("text", "") for x in motd.get("extra", []) if isinstance(x, dict))
        return {"name": str(motd or "")[:80], "version": data.get("version", {}).get("name", ""),
                "players": data.get("players", {}).get("online", 0), "max_players": data.get("players", {}).get("max", 0)}
    finally:
        writer.close()


# ---------- AMP (CubeCoders) game server discovery ----------

# AMP's AppState numbers (ApplicationState enum) -> what Vigil shows.
AMP_STATES = {0: "stopped", 5: "starting", 7: "starting", 10: "starting", 20: "running", 30: "restarting", 40: "stopping",
              45: "stopping", 50: "sleeping", 60: "waiting", 70: "installing", 75: "updating", 80: "waiting", 100: "failed",
              200: "suspended", 250: "maintenance"}
# Ports players need (and that may be open to the internet). Not RCON, REST, web or SFTP ports.
_PLAYER_PORT = ("game", "query", "application", "server", "client", "voice", "steam", "beacon")
_ADMIN_PORT = ("rcon", "rest", "api", "web", "sftp", "http", "telnet", "console", "rpc", "metrics")


async def amp_call(session, base, method, sid="", timeout=15, **params):
    """One AMP API call (POST /API/<Module>/<Method>, JSON). Returns the decoded answer."""
    body = {"SESSIONID": sid, **params} if sid else params
    async with session.post(f"{base.rstrip('/')}/API/{method}", json=body, headers={"Accept": "application/json", **UA},
                            timeout=aiohttp.ClientTimeout(total=timeout)) as r:
        if r.status >= 400:
            raise RuntimeError(f"AMP answered HTTP {r.status}")
        data = await r.json(content_type=None)
    if isinstance(data, dict) and data.get("Title") == "Unauthorized Access":
        raise PermissionError("AMP refused: this user lacks the permission for that call")
    return data


def amp_ports(raw):
    """AMP port rows (GetInstanceNetworkInfo, or App.Ports with ChildPorts) -> [{name, port, protocol, player}]."""
    out = []

    def add(p, base_port=None):
        port = p.get("PortNumber") or p.get("Port") or (base_port + int(p.get("Offset") or 0) if base_port else None)
        if not port:
            return
        proto = {0: "tcp", 1: "udp", 2: "both"}.get(p.get("Protocol"), str(p.get("Protocol", "")).lower() or "tcp")
        name = str(p.get("Name") or p.get("Description") or p.get("Ref") or "")
        low = name.lower() + " " + str(p.get("Ref") or p.get("ProvisionNodeName") or "").lower()
        player = any(k in low for k in _PLAYER_PORT) and not any(k in low for k in _ADMIN_PORT)
        out.append({"name": name, "port": int(port), "protocol": proto, "player": player})
        for child in p.get("ChildPorts") or []:
            add(child, int(port))
    for p in raw or []:
        add(p)
    return out


def amp_instance(inst, ports):
    """One AMP instance -> {id, name, game, state, running, ports, ip}."""
    running = bool(inst.get("Running"))
    state = AMP_STATES.get(inst.get("AppState"), "unknown") if running else "stopped"
    return {"id": inst.get("InstanceID") or inst.get("InstanceName"), "instance": inst.get("InstanceName", ""),
            "name": inst.get("FriendlyName") or inst.get("InstanceName", ""),
            "game": inst.get("ModuleDisplayName") or inst.get("Module", ""),
            "state": state, "running": state == "running", "suspended": bool(inst.get("Suspended")),
            "ip": inst.get("IP") or "", "ports": ports}


async def amp_instances(session, base, username, password, timeout=15):
    """Every game instance AMP manages: log in, list instances, read each one's ports, log out.

    The ADS controller itself (module ADS) is skipped. Needs a user whose role may view instances."""
    login = await amp_call(session, base, "Core/Login", timeout=timeout, username=username, password=password, token="", rememberMe=False)
    if not login.get("success") or not login.get("sessionID"):
        raise PermissionError(f"AMP login failed: {login.get('resultReason') or 'wrong user or password'}")
    sid = login["sessionID"]
    try:
        targets = await amp_call(session, base, "ADSModule/GetInstances", sid, timeout, ForceIncludeSelf=False)
        if isinstance(targets, dict):
            targets = targets.get("result", targets.get("Result", []))
        out = []
        for target in targets or []:
            for inst in target.get("AvailableInstances") or []:
                if inst.get("Module") == "ADS":
                    continue
                try:
                    net = await amp_call(session, base, "ADSModule/GetInstanceNetworkInfo", sid, timeout, InstanceName=inst.get("InstanceName"))
                    if isinstance(net, dict):
                        net = net.get("result", net.get("Result", []))
                except Exception:  # not allowed for this user, or an older AMP: use the endpoints from GetInstances
                    net = []
                ports = amp_ports(net) or amp_ports([{"Name": e.get("DisplayName"), "Port": int(e["Endpoint"].rsplit(":", 1)[1])}
                                                     for e in inst.get("ApplicationEndpoints") or []
                                                     if str(e.get("Endpoint", "")).rsplit(":", 1)[-1].isdigit()])
                out.append(amp_instance(inst, ports))
        return out
    finally:
        try:
            await amp_call(session, base, "Core/Logout", sid, timeout)
        except Exception:
            pass


def game_probe(game, ports):
    """How to check a game: ("minecraft", port) | ("a2s", port) | ("tcp", port) | (None, None) = AMP's word only."""
    g = game.lower()
    player = [p for p in ports if p["player"]] or ports
    if "minecraft" in g and "bedrock" not in g:
        tcp = [p for p in player if p["protocol"] in ("tcp", "both")]
        return ("minecraft", tcp[0]["port"]) if tcp else (None, None)
    query = [p for p in player if "query" in p["name"].lower() and p["protocol"] in ("udp", "both")]
    if query:
        return "a2s", query[0]["port"]
    tcp = [p for p in player if p["protocol"] in ("tcp", "both")]
    if tcp:
        return "tcp", tcp[0]["port"]
    udp = [p for p in player if p["protocol"] == "udp"]
    if udp:  # Steam games without a separate query port usually answer A2S on the game port
        return "a2s", udp[0]["port"]
    return None, None


# ---------- TLS certificates and internet exposure ----------

async def cert_info(url, timeout=8):
    """Days until the certificate of an https URL expires, its issuer, and whether it is valid for the host."""
    from urllib.parse import urlparse
    u = urlparse(url)
    host, port = u.hostname, u.port or 443
    loop = asyncio.get_running_loop()

    def fetch():
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock, ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
            valid = True
        except ssl.SSLCertVerificationError as ex:
            return {"valid": False, "error": ex.verify_message or str(ex)}
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
        issuer = dict(x[0] for x in cert.get("issuer", []))
        return {"valid": valid, "expires": expires.isoformat(), "days_left": (expires - datetime.now(timezone.utc)).days,
                "issuer": issuer.get("organizationName", "") + (" " + issuer.get("commonName", "") if issuer.get("commonName") else "")}
    return await loop.run_in_executor(None, fetch)


async def public_ip(session):
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=8), headers=UA) as r:
                ip = (await r.text()).strip()
                if ip.count(".") == 3:
                    return ip
        except Exception:
            continue
    return None


async def shodan_internetdb(session, ip):
    """What Shodan has seen open on an IP (free, no key; updated about weekly)."""
    async with session.get(f"https://internetdb.shodan.io/{ip}", timeout=aiohttp.ClientTimeout(total=15), headers=UA) as r:
        if r.status == 404:
            return {"ports": [], "vulns": [], "cpes": [], "hostnames": [], "tags": []}
        return await r.json(content_type=None)


async def crtsh(session, domain):
    """Certificates issued for a domain and its subdomains (certificate transparency logs)."""
    rows = None
    for attempt in range(3):  # crt.sh is often slow or busy
        try:
            async with session.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=aiohttp.ClientTimeout(total=150), headers=UA) as r:
                rows = await r.json(content_type=None)
            break
        except (asyncio.TimeoutError, aiohttp.ClientError, ValueError):
            if attempt == 2:
                raise
            await asyncio.sleep(20)
    certs = {}
    for row in rows:
        certs[row["id"]] = {"id": row["id"], "names": sorted(set(row["name_value"].split("\n"))), "issuer": row.get("issuer_name", ""),
                            "not_before": row.get("not_before"), "not_after": row.get("not_after")}
    return sorted(certs.values(), key=lambda c: c["not_before"] or "", reverse=True)
