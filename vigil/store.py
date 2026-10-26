"""SQLite history: one row per check result, incidents (down periods), events (alerts, exposure changes), key/value state."""
import json
import sqlite3
import time
from pathlib import Path

SCHEMA = """
create table if not exists results (ts real, check_id text, ok integer, ms real, detail text);
create index if not exists results_check_ts on results (check_id, ts);
create table if not exists incidents (id integer primary key, check_id text, name text, start real, end real, detail text);
create table if not exists events (id integer primary key, ts real, level text, title text, body text);
create table if not exists kv (key text primary key, value text);
"""


class Store:
    def __init__(self, data_dir):
        self.db = sqlite3.connect(Path(data_dir) / "vigil.db", check_same_thread=False)
        self.db.executescript(SCHEMA)
        self.db.commit()

    # ---------- results ----------

    def add_results(self, rows):
        self.db.executemany("insert into results values (?,?,?,?,?)", rows)
        self.db.commit()

    def uptime(self, check_id, hours):
        since = time.time() - hours * 3600
        total, good = self.db.execute("select count(*), sum(ok) from results where check_id=? and ts>=?", (check_id, since)).fetchone()
        return round(100 * (good or 0) / total, 2) if total else None

    def buckets(self, check_id, hours=24, count=48):
        """Uptime per time slice (None = no data) plus average latency, oldest first."""
        now = time.time()
        size = hours * 3600 / count
        rows = self.db.execute(
            "select cast((ts-?)/? as integer) b, count(*), sum(ok), avg(ms) from results where check_id=? and ts>=? group by b",
            (now - hours * 3600, size, check_id, now - hours * 3600)).fetchall()
        by = {b: (n, g, ms) for b, n, g, ms in rows}
        out = []
        for i in range(count):
            n, g, ms = by.get(i, (0, 0, None))
            out.append({"up": round(g / n, 3) if n else None, "ms": round(ms, 1) if ms is not None else None})
        return out

    def prune(self, keep_days):
        cutoff = time.time() - keep_days * 86400
        self.db.execute("delete from results where ts<?", (cutoff,))
        self.db.execute("delete from events where ts<?", (cutoff,))
        self.db.execute("delete from incidents where end is not null and end<?", (cutoff,))
        self.db.commit()

    # ---------- incidents ----------

    def open_incident(self, check_id, name, start, detail):
        self.db.execute("insert into incidents (check_id, name, start, end, detail) values (?,?,?,null,?)", (check_id, name, start, detail))
        self.db.commit()

    def close_incident(self, check_id, end):
        self.db.execute("update incidents set end=? where check_id=? and end is null", (end, check_id))
        self.db.commit()

    def open_incidents(self):
        return {r[0]: r[1] for r in self.db.execute("select check_id, start from incidents where end is null")}

    def incidents(self, limit=30):
        rows = self.db.execute("select check_id, name, start, end, detail from incidents order by start desc limit ?", (limit,)).fetchall()
        return [{"check_id": c, "name": n, "start": s, "end": e, "detail": d} for c, n, s, e, d in rows]

    # ---------- events ----------

    def add_event(self, level, title, body=""):
        self.db.execute("insert into events (ts, level, title, body) values (?,?,?,?)", (time.time(), level, title, body))
        self.db.commit()

    def events(self, limit=40):
        rows = self.db.execute("select ts, level, title, body from events order by ts desc limit ?", (limit,)).fetchall()
        return [{"ts": t, "level": lv, "title": ti, "body": b} for t, lv, ti, b in rows]

    # ---------- key/value ----------

    def get(self, key, default=None):
        row = self.db.execute("select value from kv where key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def put(self, key, value):
        self.db.execute("insert into kv values (?,?) on conflict(key) do update set value=excluded.value", (key, json.dumps(value)))
        self.db.commit()
