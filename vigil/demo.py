"""Demo mode (python -m vigil --demo, or VIGIL_DEMO=1): a made-up lab, no network requests at all.

The real engine runs; only the probes are swapped for simulated ones, so alerts, incidents and uptime bars behave
as they would in a real lab. Addresses are from the documentation ranges (192.0.2.0/24, 203.0.113.0/24, example.com).
"""
import random
import time
from pathlib import Path

from . import probes

CONFIG = """# Vigil demo: a made-up lab. Nothing here is contacted; every result is simulated.
title: Vigil demo
interval_seconds: 15
fail_after: 2
groups: [Core, Media, Home, Apps, PCs]
checks:
  - {id: router, name: Router, group: Core, type: tcp, host: 192.0.2.1, port: 443, icon: router}
  - {id: nas, name: NAS, group: Core, type: http, url: "https://192.0.2.10/", icon: dns}
  - {id: dns, name: Pi-hole DNS, group: Core, type: tcp, host: 192.0.2.2, port: 53, icon: shield}
  - {id: proxy, name: Reverse proxy, group: Core, type: http, url: "http://192.0.2.10:81/", icon: swap}
  - {id: jellyfin, name: Jellyfin, group: Media, type: http, url: "http://192.0.2.10:8096/health", icon: play}
  - {id: immich, name: Immich, group: Media, type: http, url: "http://192.0.2.10:2283/api/server/ping", icon: photo}
  - {id: sonarr, name: Sonarr, group: Media, type: http, url: "http://192.0.2.10:8989/ping", icon: tv}
  - {id: radarr, name: Radarr, group: Media, type: http, url: "http://192.0.2.10:7878/ping", icon: movie}
  - {id: ha, name: Home Assistant, group: Home, type: http, url: "http://192.0.2.20:8123/manifest.json", icon: home}
  - {id: mqtt, name: MQTT broker, group: Home, type: tcp, host: 192.0.2.20, port: 1883, icon: bolt}
  - {id: nextcloud, name: Nextcloud, group: Apps, type: http, url: "http://192.0.2.10:8080/status.php", icon: apps}
  - {id: grafana, name: Grafana, group: Apps, type: http, url: "http://192.0.2.10:3000/api/health", icon: monitor}
  - {id: llm, name: Local LLM, group: Apps, type: http, url: "http://192.0.2.30:8080/health", icon: brain}
  - {id: flaky, name: Old Raspberry Pi, group: Apps, type: http, url: "http://192.0.2.40/", icon: apps}
  - {id: desktop, name: Desktop (SSH), group: PCs, type: tcp, host: 192.0.2.50, port: 22, icon: pc, optional: true}
nut:
  - {name: NAS, host: 192.0.2.10, port: 3493, watts: {ups-rack: 900}}
scrutiny_url: "http://192.0.2.10:8090"
games:
  - {name: Minecraft, type: minecraft, host: 192.0.2.60, port: 25565, address: mc.example.com}
  - {name: Valheim, type: valheim, host: 192.0.2.60, port: 2456, address: valheim.example.com}
exposure:
  enabled: true
  expected_ports: [443]
  domain: example.com
  public_hosts:
    - {name: Photos, url: "https://photos.example.com/"}
    - {name: Cloud, url: "https://cloud.example.com/"}
briefing:
  enabled: true
  url: "demo"
  time: "07:00"
"""

BASE_MS = {"router": 2, "nas": 9, "dns": 1, "proxy": 6, "jellyfin": 14, "immich": 22, "sonarr": 11, "radarr": 12, "ha": 18,
           "mqtt": 2, "nextcloud": 48, "grafana": 16, "llm": 7, "flaky": 35, "desktop": 3}

BRIEFING = """Needs attention: an unexpected public port and a flaky Raspberry Pi; everything else is healthy.
- Old Raspberry Pi has been dropping off every few hours; check its power supply or SD card.
- Shodan sees port 8443 open on your public IP; close it on the router or add it to expected_ports if you meant to open it.
- The rack UPS is on mains at 96%, about 41 min runtime at 212 W.
- Drives are healthy; the warmest is sdc at 44 °C.
- Minecraft has 3 players online; the Photos certificate renews in 9 days."""


def _flaky_down(now):
    """The Raspberry Pi is down for 4 minutes in every 10 minutes, so the demo shows an outage and a recovery."""
    return (now // 60) % 10 < 4


async def http_check(session, chk, timeout):
    now = time.time()
    if chk.get("id") == "flaky" and _flaky_down(now):
        return False, None, "timeout"
    ms = BASE_MS.get(chk.get("id"), 10) * random.uniform(0.7, 1.6)
    return True, ms, "HTTP 200"


async def tcp_check(chk, timeout):
    if chk.get("id") == "desktop":
        return False, None, "connection refused"
    return True, BASE_MS.get(chk.get("id"), 3) * random.uniform(0.7, 1.5), "open"


async def nut_query(host, port):
    load = random.uniform(22, 25)
    return {"ups-rack": {"ups.status": "OL", "battery.charge": "96", "battery.runtime": str(int(2460 + random.uniform(-60, 60))),
                         "ups.load": f"{load:.0f}", "device.model": "Smart-UPS 1500", "input.voltage": "121.0",
                         "battery.date": "2024/03/12"}}


async def scrutiny_summary(session, base, timeout):
    disks = [("sda", "WDC WD120EFBX", 12.0, 38), ("sdb", "WDC WD120EFBX", 12.0, 39), ("sdc", "ST16000NM001G", 16.0, 44),
             ("sdd", "ST16000NM001G", 16.0, 42), ("nvme0", "Samsung 990 PRO 2TB", 2.0, 41)]
    return [{"name": n, "model": m, "serial": f"DEMO{i:04d}", "capacity_tb": tb, "temp": t, "power_on_hours": 9000 + i * 1234,
             "ok": True, "status": "passed"} for i, (n, m, tb, t) in enumerate(disks)]


async def valheim_info(host, port, timeout=3):
    return {"name": "Demo Valheim", "map": "Demo", "players": 0, "max_players": 10}


async def minecraft_info(host, port=25565, timeout=4):
    return {"name": "A Minecraft Server", "version": "1.21.4", "players": 3, "max_players": 20}


async def cert_info(url, timeout=8):
    days = 9 if "photos" in url else 61
    return {"valid": True, "expires": "", "days_left": days, "issuer": "Let's Encrypt R11"}


async def public_ip(session):
    return "203.0.113.7"


async def shodan_internetdb(session, ip):
    return {"ip": ip, "ports": [443, 8443], "vulns": [], "cpes": ["cpe:/a:nginx:nginx"], "hostnames": [], "tags": []}


async def crtsh(session, domain):
    day = 86400
    now = time.time()
    rows = [(9001, ["photos.example.com"], 81), (9002, ["cloud.example.com"], 29), (9003, ["*.example.com", "example.com"], 140)]
    return [{"id": i, "names": names, "issuer": "C=US, O=Let's Encrypt, CN=R11",
             "not_before": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now - age * day)),
             "not_after": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now + (90 - age) * day))} for i, names, age in rows]


def install(engine, data_dir):
    """Swap the probes for the simulated ones, give the engine a canned briefing and seed a week of history."""
    for name in ("http_check", "tcp_check", "nut_query", "scrutiny_summary", "valheim_info", "minecraft_info", "cert_info",
                 "public_ip", "shodan_internetdb", "crtsh"):
        setattr(probes, name, globals()[name])

    async def make_briefing():
        engine.briefing = {"ts": time.time(), "text": BRIEFING, "error": ""}
        return engine.briefing
    engine.make_briefing = make_briefing
    engine.briefing = {"ts": time.time() - 3 * 3600, "text": BRIEFING, "error": ""}
    seed_history(engine.store)


def seed_history(store, days=7, step=300):
    """A week of results every 5 minutes, with a few short outages, so the uptime bars and percentages have something to show."""
    if store.db.execute("select count(*) from results").fetchone()[0]:
        return
    rnd = random.Random(7)
    now = time.time()
    outages = {"immich": [(now - 2 * 86400, 1500)], "nextcloud": [(now - 5 * 86400, 2400)], "flaky": [(now - 3600 * h, 900) for h in (5, 13, 30, 70)]}
    rows = []
    for cid, base in BASE_MS.items():
        if cid == "desktop":
            continue
        for ts in range(int(now - days * 86400), int(now - 60), step):
            down = any(s <= ts < s + d for s, d in outages.get(cid, []))
            rows.append((ts, cid, 0 if down else 1, None if down else base * rnd.uniform(0.7, 1.6), "timeout" if down else "HTTP 200"))
    store.add_results(rows)
    names = {"immich": "Immich", "nextcloud": "Nextcloud", "flaky": "Old Raspberry Pi"}
    for cid, spans in outages.items():
        for s, d in spans:
            store.db.execute("insert into incidents (check_id, name, start, end, detail) values (?,?,?,?,?)", (cid, names[cid], s, s + d, "timeout"))
            store.add_event("bad", f"{names[cid]} is DOWN", "timeout")
            store.db.execute("update events set ts=? where id=(select max(id) from events)", (s,))
            store.add_event("ok", f"{names[cid]} is back up", f"after {d // 60} min")
            store.db.execute("update events set ts=? where id=(select max(id) from events)", (s + d,))
    store.add_event("info", "Morning briefing sent", BRIEFING[:300])
    store.db.execute("update events set ts=? where id=(select max(id) from events)", (now - 3 * 3600,))
    store.db.commit()


def write_config(data_dir):
    Path(data_dir, "config.yaml").write_text(CONFIG, encoding="utf-8")
