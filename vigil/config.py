"""Settings: /data/config.yaml (created from the example on first start), reloaded when the file changes."""
import logging
import os
import shutil
from pathlib import Path

import yaml

log = logging.getLogger("vigil")

EXAMPLE = Path(__file__).with_name("config.example.yaml")

DEFAULTS = {
    "title": "Vigil",
    "interval_seconds": 60,
    "timeout_seconds": 6,
    "fail_after": 2,  # consecutive failures before a check counts as down (and alerts)
    "keep_days": 30,
    "checks": [],
    "groups": [],
    "nut": [],  # [{name, host, port}] NUT servers; every UPS/PDU on them is shown
    "scrutiny_url": "",
    "games": [],  # [{name, type: valheim|minecraft, host, port}]
    "exposure": {
        "enabled": True,
        "expected_ports": [443],  # public ports you meant to open; anything else Shodan sees is flagged
        "domain": "",  # crt.sh watch: certificates issued for *.domain
        "public_hosts": [],  # [{name, url}] HTTPS endpoints whose certificate expiry is watched
        "cert_warn_days": 14,
    },
    "briefing": {
        "enabled": False,
        "url": "",  # OpenAI-compatible /v1/chat/completions
        "model": "",
        "api_key": "",
        "headers": {},
        "extra_body": {},
        "time": "07:00",
    },
    "notify": {
        "discord_webhook": "",
        "ntfy_url": "",  # e.g. https://ntfy.sh/your-secret-topic
        "ha_webhook": "",  # Home Assistant webhook URL (automation trigger)
    },
}


def merge(base, override):
    out = dict(base)
    for k, v in (override or {}).items():
        out[k] = merge(base[k], v) if isinstance(base.get(k), dict) and isinstance(v, dict) else v
    return out


def validate(c):
    if int(c["interval_seconds"]) < 15:
        raise ValueError("interval_seconds must be 15 or more")
    ids = set()
    for chk in c["checks"]:
        if not chk.get("id") or not chk.get("type") in ("http", "tcp"):
            raise ValueError(f"check needs an id and type http|tcp: {chk}")
        if chk["id"] in ids:
            raise ValueError(f"duplicate check id {chk['id']}")
        ids.add(chk["id"])
        if chk["type"] == "http" and not chk.get("url"):
            raise ValueError(f"http check {chk['id']} needs url")
        if chk["type"] == "tcp" and not (chk.get("host") and chk.get("port")):
            raise ValueError(f"tcp check {chk['id']} needs host and port")
    for g in c["games"]:
        if g.get("type") not in ("valheim", "minecraft"):
            raise ValueError(f"game type must be valheim or minecraft: {g}")


class Config:
    def __init__(self, data_dir):
        self.path = Path(data_dir) / "config.yaml"
        if not self.path.exists():
            shutil.copy(EXAMPLE, self.path)
            os.chmod(self.path, 0o664)
            log.info("Wrote %s from the example; edit it to match your lab", self.path)
        self.mtime = None
        self.data = merge(DEFAULTS, {})
        self.error = ""
        self.get()

    def get(self):
        try:
            mtime = self.path.stat().st_mtime
            if mtime != self.mtime:
                self.mtime = mtime
                data = merge(DEFAULTS, yaml.safe_load(self.path.read_text(encoding="utf-8")) or {})
                validate(data)
                self.data, self.error = data, ""
                log.info("Config loaded (%d checks)", len(data["checks"]))
        except Exception as ex:  # keep the last good config
            self.error = f"{type(ex).__name__}: {ex}"
            log.error("config.yaml not loaded: %s", self.error)
        return self.data
