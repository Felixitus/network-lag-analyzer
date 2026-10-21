"""SQLite schema.

Timestamps are Unix seconds (REAL, or INTEGER for per-second buckets).
Column `res` = resolution in seconds (1, 10, 60) for aggregated tables.
Values that cannot be measured are stored as NULL - never as 0.

**Storage format (from version 3).** Measurements are stored as INTEGER in fixed
units instead of REAL, because SQLite uses eight bytes for every REAL,
but only two to four for small INTEGERs. That halves the measurement tables.
Conversion happens exclusively in `repository.py`
(`encode_measurement` / `decode_measurement`); the rest of the code keeps
milliseconds and percent as floats.

    times (ms)     → 1/100 ms   (18.34 ms  → 1834)
    shares (%)     → 1/100 %    (2.90 %    → 290)
    rates (bit/s)  → bit/s as an integer

This was not changed for tidiness: on a Raspberry Pi every write saved
goes straight into the lifetime of the SD card.
"""

SCHEMA_VERSION = 4

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,            -- JSON
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS targets (
    id      INTEGER PRIMARY KEY,
    address TEXT NOT NULL UNIQUE,
    name    TEXT,
    kind    TEXT NOT NULL                -- gateway | internet | game
);

-- Individual ICMP probes (raw data retention only, 24 h by default)
CREATE TABLE IF NOT EXISTS ping_samples (
    ts        REAL NOT NULL,
    target_id INTEGER NOT NULL,
    rtt_ms    REAL,                      -- NULL = lost
    lost      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_ping_samples_ts ON ping_samples(ts);

-- Network state per time bucket. Units see module header.
CREATE TABLE IF NOT EXISTS measurements (
    res        INTEGER NOT NULL,
    ts         INTEGER NOT NULL,
    rtt_avg    INTEGER,                  -- internet RTT (median of the targets), 1/100 ms
    rtt_min    INTEGER,
    rtt_max    INTEGER,
    gw_rtt     INTEGER,
    jitter     INTEGER,
    loss_pct   INTEGER,                  -- 1/100 %
    probes     INTEGER,
    lost       INTEGER,
    down_bps   INTEGER,                  -- bit/s
    up_bps     INTEGER,
    traffic_src TEXT,                    -- capture | tr064 | NULL
    retrans    INTEGER,
    tcp_segs   INTEGER,
    retrans_down INTEGER,
    retrans_up INTEGER,
    dns_ms     INTEGER,
    dns_fail   INTEGER,
    game_rtt   INTEGER,
    game_pps   INTEGER,                  -- 1/100 packets/s
    game_gap_ms INTEGER,
    PRIMARY KEY (res, ts)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS target_measurements (
    res       INTEGER NOT NULL,
    ts        INTEGER NOT NULL,
    target_id INTEGER NOT NULL,
    rtt_avg   INTEGER,                   -- 1/100 ms
    rtt_max   INTEGER,
    probes    INTEGER,
    lost      INTEGER,
    PRIMARY KEY (res, target_id, ts)
) WITHOUT ROWID;

-- id instead of MAC is the key for device_traffic: a small integer per row
-- instead of 17 characters of text saves more than half the space there.
CREATE TABLE IF NOT EXISTS devices (
    id          INTEGER PRIMARY KEY,
    mac         TEXT NOT NULL UNIQUE,    -- aa:bb:cc:dd:ee:ff
    ip          TEXT,
    hostname    TEXT,
    custom_name TEXT,
    vendor      TEXT,
    sources     TEXT,                    -- JSON list of data sources
    interface   TEXT,                    -- LAN/Wi-Fi according to the FRITZ!Box
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    active      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_devices_ip ON devices(ip);

-- WAN traffic per device (rx = download to the device, tx = upload from the device).
-- Deliberately only the two byte counters: packets, UDP and LAN share used to be
-- stored, but were read by no evaluation and no view.
-- Live (in the ring buffer) they are still fully available.
CREATE TABLE IF NOT EXISTS device_traffic (
    res       INTEGER NOT NULL,
    ts        INTEGER NOT NULL,
    dev       INTEGER NOT NULL,          -- devices.id
    rx_bytes  INTEGER NOT NULL,
    tx_bytes  INTEGER NOT NULL,
    PRIMARY KEY (res, ts, dev)
) WITHOUT ROWID;

-- Daily summary: tiny (about 200 bytes per day) and therefore exempt from
-- retention. This keeps "has it gotten better since the change?" answerable
-- for years, even when the detail data is long gone.
CREATE TABLE IF NOT EXISTS daily_stats (
    day         TEXT PRIMARY KEY,        -- YYYY-MM-DD, local time
    seconds     INTEGER NOT NULL,        -- seconds with measurements
    rtt_p50     INTEGER, rtt_p95 INTEGER, rtt_max INTEGER,   -- 1/100 ms
    gw_p50      INTEGER,
    jitter_p50  INTEGER, jitter_p95 INTEGER,
    loss_pct    INTEGER,                 -- 1/100 %
    probes      INTEGER, lost INTEGER,
    down_peak   INTEGER, up_peak INTEGER,                    -- bit/s
    down_bytes  INTEGER, up_bytes INTEGER,
    bloat_up    INTEGER, bloat_down INTEGER,                 -- 1/100 ms increase under load
    outage_secs INTEGER,
    incidents   TEXT                     -- JSON {category: count}
) WITHOUT ROWID;

-- Latency under load (bufferbloat) per 10-minute window.
-- Computed continuously because 1 s values are only kept for one day;
-- this keeps the long-term history visible over weeks.
CREATE TABLE IF NOT EXISTS bufferbloat (
    ts            INTEGER PRIMARY KEY,   -- start of the window
    idle_ms       REAL NOT NULL,         -- median RTT on a quiet line
    idle_secs     INTEGER NOT NULL,
    up_ms         REAL,                  -- median RTT under upload load
    up_worst_ms   REAL,
    up_secs       INTEGER NOT NULL DEFAULT 0,
    down_ms       REAL,                  -- median RTT under download load
    down_worst_ms REAL,
    down_secs     INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS network_flows (
    id          INTEGER PRIMARY KEY,
    ts_start    REAL NOT NULL,
    ts_end      REAL NOT NULL,
    proto       TEXT NOT NULL,
    mac         TEXT,
    local_ip    TEXT NOT NULL,
    local_port  INTEGER,
    remote_ip   TEXT NOT NULL,
    remote_port INTEGER,
    bytes_up    INTEGER NOT NULL,
    bytes_down  INTEGER NOT NULL,
    pkts_up     INTEGER NOT NULL,
    pkts_down   INTEGER NOT NULL,
    retrans     INTEGER NOT NULL,
    resets      INTEGER NOT NULL,
    max_gap_ms  REAL,
    dns_name    TEXT
);
CREATE INDEX IF NOT EXISTS ix_flows_time ON network_flows(ts_end, ts_start);
CREATE INDEX IF NOT EXISTS ix_flows_mac ON network_flows(mac, ts_end);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    type        TEXT NOT NULL,
    severity    TEXT NOT NULL,           -- info | warning | critical
    ts_start    REAL NOT NULL,
    ts_end      REAL,                    -- NULL = still open
    peak        REAL,
    baseline    REAL,
    target      TEXT,
    mac         TEXT,
    details     TEXT,                    -- JSON
    incident_id INTEGER
);
CREATE INDEX IF NOT EXISTS ix_events_time ON events(ts_start);
CREATE INDEX IF NOT EXISTS ix_events_incident ON events(incident_id);

CREATE TABLE IF NOT EXISTS incidents (
    id           INTEGER PRIMARY KEY,
    source       TEXT NOT NULL,          -- auto | user
    ts_start     REAL NOT NULL,
    ts_end       REAL,
    reported_at  REAL,
    title        TEXT,
    cause        TEXT,
    category     TEXT,
    confidence   TEXT,
    analysis     TEXT,                   -- JSON: evidence, top talkers, metrics
    session_id   INTEGER,
    pcap_protected INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_incidents_time ON incidents(ts_start);

-- DNS activity per client and minute (from Pi-hole). NOT a traffic measure!
CREATE TABLE IF NOT EXISTS dns_queries (
    ts          INTEGER NOT NULL,        -- minute bucket
    client_ip   TEXT NOT NULL,
    queries     INTEGER NOT NULL,
    blocked     INTEGER NOT NULL,
    top_domains TEXT,                    -- JSON
    PRIMARY KEY (ts, client_ip)
) WITHOUT ROWID;

-- ---- DNS usage module (version 4) ------------------------------------------------
-- Pi-hole stays the source of the individual queries (91 days there). These tables
-- hold only what Pi-hole does not have: who held an IP when, and compact counters
-- that make 7/30-day views affordable (a 30-day scan of the FTL log takes minutes
-- on the Pi). Counts only - DNS queries are NOT a measure of usage or bandwidth.

-- One row per attribution key. A MAC client and an "IP only" client are different
-- rows on purpose: merging them would claim knowledge the data does not have.
CREATE TABLE IF NOT EXISTS dns_clients (
    id          INTEGER PRIMARY KEY,
    key         TEXT NOT NULL UNIQUE,    -- mac:<mac> | ip:<ip> | local
    basis       TEXT NOT NULL,           -- mac | ip | local
    mac         TEXT,
    ip          TEXT,                    -- most recent IP
    name        TEXT,                    -- host name according to Pi-hole
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS dns_domains (
    id   INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS dns_client_hourly (
    ts         INTEGER NOT NULL,         -- start of the hour
    client     INTEGER NOT NULL,         -- dns_clients.id
    queries    INTEGER NOT NULL,         -- without retries/duplicates
    blocked    INTEGER NOT NULL,
    duplicates INTEGER NOT NULL,
    PRIMARY KEY (client, ts)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS ix_dns_client_hourly_ts ON dns_client_hourly(ts);

-- Per client, local day and domain. Completed days keep only the top N domains;
-- the rest is folded into domain 0 so that the day's totals stay exact.
CREATE TABLE IF NOT EXISTS dns_domain_daily (
    day       INTEGER NOT NULL,          -- local midnight
    client    INTEGER NOT NULL,
    domain    INTEGER NOT NULL,          -- dns_domains.id, 0 = all other domains
    queries   INTEGER NOT NULL,
    blocked   INTEGER NOT NULL,
    first_ts  INTEGER NOT NULL,
    last_ts   INTEGER NOT NULL,
    PRIMARY KEY (client, day, domain)
) WITHOUT ROWID;
-- No index on `day`: on the Pi it was half the size of the table and only served
-- the hourly retention DELETE, for which a scan is cheap.

-- Recorded by us, because FTL's network table only knows the current owner of an IP.
CREATE TABLE IF NOT EXISTS dns_ip_history (
    ip         TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    mac        TEXT NOT NULL,
    last_seen  INTEGER NOT NULL,
    PRIMARY KEY (ip, first_seen)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS gaming_sessions (
    id            INTEGER PRIMARY KEY,
    ts_start      REAL NOT NULL,
    ts_end        REAL,
    mac           TEXT,
    device_ip     TEXT,
    server_ip     TEXT,
    server_port   INTEGER,
    auto_detected INTEGER NOT NULL DEFAULT 0,
    summary       TEXT                   -- JSON
);

CREATE TABLE IF NOT EXISTS pcap_files (
    id          INTEGER PRIMARY KEY,
    path        TEXT NOT NULL UNIQUE,
    ts_start    REAL NOT NULL,
    ts_end      REAL,
    size        INTEGER NOT NULL DEFAULT 0,
    protected   INTEGER NOT NULL DEFAULT 0,
    incident_id INTEGER
);
"""
