"""Synthetic Pi-hole FTL databases for tests.

The schema mirrors the installed FTL v6.8 (checked with `.schema` on the Pi) and
the older v5 layout with a plain `queries` table.
"""
import sqlite3

from backend.collectors.ftl_queries import FtlQueryLog

T0 = 1_760_000_000.0
MAC_A = "02:00:00:00:00:0a"
MAC_B = "02:00:00:00:00:0b"

V6_SCHEMA = """
CREATE TABLE query_storage (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL,
  type INTEGER NOT NULL, status INTEGER NOT NULL, domain INTEGER NOT NULL, client INTEGER NOT NULL,
  forward INTEGER, additional_info INTEGER, reply_type INTEGER, reply_time REAL, dnssec INTEGER,
  list_id INTEGER, ede INTEGER);
CREATE INDEX idx_queries_timestamp ON query_storage (timestamp);
CREATE TABLE domain_by_id (id INTEGER PRIMARY KEY, domain TEXT NOT NULL);
CREATE UNIQUE INDEX domain_by_id_domain_idx ON domain_by_id(domain);
CREATE TABLE client_by_id (id INTEGER PRIMARY KEY, ip TEXT NOT NULL, name TEXT);
CREATE UNIQUE INDEX client_by_id_client_idx ON client_by_id(ip,name);
CREATE VIEW queries AS SELECT q.id, q.timestamp, q.status, d.domain, c.ip AS client
  FROM query_storage q LEFT JOIN domain_by_id d ON q.domain = d.id LEFT JOIN client_by_id c ON q.client = c.id;
"""
V5_SCHEMA = """
CREATE TABLE queries (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, type INTEGER NOT NULL,
  status INTEGER NOT NULL, domain TEXT NOT NULL, client TEXT NOT NULL, forward TEXT, additional_info TEXT);
CREATE INDEX idx_queries_timestamps ON queries (timestamp);
"""
NETWORK_SCHEMA = """
CREATE TABLE network (id INTEGER PRIMARY KEY NOT NULL, hwaddr TEXT UNIQUE NOT NULL, interface TEXT NOT NULL,
  firstSeen INTEGER NOT NULL, lastQuery INTEGER NOT NULL, numQueries INTEGER NOT NULL, macVendor TEXT,
  aliasclient_id INTEGER);
CREATE TABLE network_addresses (network_id INTEGER NOT NULL, ip TEXT UNIQUE NOT NULL,
  lastSeen INTEGER NOT NULL, name TEXT, nameUpdated INTEGER);
"""


class FakeFtl:
    """Builds an FTL database. `add` takes (ts, client_ip, domain, status[, client_name])."""

    def __init__(self, path, legacy=False):
        self.path = str(path)
        self.legacy = legacy
        self.c = sqlite3.connect(self.path)
        self.c.executescript((V5_SCHEMA if legacy else V6_SCHEMA) + NETWORK_SCHEMA)

    def add(self, rows):
        for ts, ip, domain, status, *rest in rows:
            name = rest[0] if rest else None
            if self.legacy:
                self.c.execute("INSERT INTO queries (timestamp, type, status, domain, client) VALUES (?,1,?,?,?)",
                               (int(ts), status, domain, ip))
                continue
            self.c.execute("INSERT OR IGNORE INTO domain_by_id (domain) VALUES (?)", (domain,))
            did = self.c.execute("SELECT id FROM domain_by_id WHERE domain=?", (domain,)).fetchone()[0]
            self.c.execute("INSERT OR IGNORE INTO client_by_id (ip, name) VALUES (?,?)", (ip, name))
            cid = self.c.execute("SELECT id FROM client_by_id WHERE ip=? AND name IS ?", (ip, name)).fetchone()[0]
            self.c.execute("INSERT INTO query_storage (timestamp, type, status, domain, client) VALUES (?,1,?,?,?)",
                           (int(ts), status, did, cid))
        self.c.commit()
        return self

    def device(self, hwaddr, ips, first_seen=T0 - 86400, name=None, vendor=None, last_seen=T0):
        cur = self.c.execute("INSERT INTO network (hwaddr, interface, firstSeen, lastQuery, numQueries, macVendor) "
                             "VALUES (?, 'eth0', ?, 0, 0, ?)", (hwaddr, int(first_seen), vendor))
        for ip in ips:
            self.c.execute("INSERT INTO network_addresses (network_id, ip, lastSeen, name) VALUES (?,?,?,?)",
                           (cur.lastrowid, ip, int(last_seen), name))
        self.c.commit()
        return self

    def move_ip(self, ip, hwaddr, last_seen):
        """The IP now belongs to another (existing) device - as FTL records it: one row per IP."""
        nid = self.c.execute("SELECT id FROM network WHERE hwaddr=?", (hwaddr,)).fetchone()[0]
        self.c.execute("UPDATE network_addresses SET network_id=?, lastSeen=? WHERE ip=?", (nid, int(last_seen), ip))
        self.c.commit()
        return self

    def log(self):
        """Commit and hand out a reader, but keep the fake open for more rows."""
        self.c.commit()
        return FtlQueryLog(self.path)

    def close(self):
        self.c.close()
        return FtlQueryLog(self.path)
