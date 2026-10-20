"""SQLite-Schema.

Zeitstempel sind Unix-Sekunden (REAL bzw. INTEGER für Sekunden-Buckets).
Spalte `res` = Auflösung in Sekunden (1, 10, 60) für aggregierte Tabellen.
Nicht messbare Werte werden als NULL gespeichert – niemals als 0.

**Speicherformat (ab Version 3).** Messwerte liegen als INTEGER in festen
Einheiten statt als REAL, weil SQLite für jedes REAL acht Bytes belegt,
für kleine INTEGER aber nur zwei bis vier. Das halbiert die Messtabellen.
Die Umrechnung passiert ausschließlich in `repository.py`
(`encode_measurement` / `decode_measurement`); im übrigen Code bleiben es
Millisekunden und Prozent als Fließkommazahlen.

    Zeiten (ms)    → 1/100 ms   (18,34 ms  → 1834)
    Anteile (%)    → 1/100 %    (2,90 %    → 290)
    Raten (bit/s)  → bit/s als ganze Zahl

Geändert wurde das nicht aus Ordnungsliebe: Auf einem Raspberry Pi landet
jeder gesparte Schreibvorgang direkt in der Lebensdauer der SD-Karte.
"""

SCHEMA_VERSION = 3

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

-- Einzelne ICMP-Probes (nur Rohdaten-Retention, standardmäßig 24 h)
CREATE TABLE IF NOT EXISTS ping_samples (
    ts        REAL NOT NULL,
    target_id INTEGER NOT NULL,
    rtt_ms    REAL,                      -- NULL = verloren
    lost      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_ping_samples_ts ON ping_samples(ts);

-- Netzwerkzustand pro Zeit-Bucket. Einheiten siehe Modulkopf.
CREATE TABLE IF NOT EXISTS measurements (
    res        INTEGER NOT NULL,
    ts         INTEGER NOT NULL,
    rtt_avg    INTEGER,                  -- Internet-RTT (Median der Ziele), 1/100 ms
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
    game_pps   INTEGER,                  -- 1/100 Pakete/s
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

-- id statt MAC ist der Schlüssel für device_traffic: eine kleine Ganzzahl je Zeile
-- statt 17 Zeichen Text spart dort über die Hälfte des Platzes.
CREATE TABLE IF NOT EXISTS devices (
    id          INTEGER PRIMARY KEY,
    mac         TEXT NOT NULL UNIQUE,    -- aa:bb:cc:dd:ee:ff
    ip          TEXT,
    hostname    TEXT,
    custom_name TEXT,
    vendor      TEXT,
    sources     TEXT,                    -- JSON-Liste der Datenquellen
    interface   TEXT,                    -- LAN/WLAN laut FRITZ!Box
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    active      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_devices_ip ON devices(ip);

-- WAN-Traffic pro Gerät (rx = Download zum Gerät, tx = Upload vom Gerät).
-- Bewusst nur die beiden Byte-Zähler: Pakete, UDP- und LAN-Anteil wurden zwar
-- gespeichert, aber von keiner Auswertung und keiner Ansicht gelesen.
-- Live (im Ringpuffer) stehen sie weiterhin vollständig zur Verfügung.
CREATE TABLE IF NOT EXISTS device_traffic (
    res       INTEGER NOT NULL,
    ts        INTEGER NOT NULL,
    dev       INTEGER NOT NULL,          -- devices.id
    rx_bytes  INTEGER NOT NULL,
    tx_bytes  INTEGER NOT NULL,
    PRIMARY KEY (res, ts, dev)
) WITHOUT ROWID;

-- Tages-Zusammenfassung: winzig (rund 200 Byte je Tag) und deshalb von der
-- Retention ausgenommen. Damit bleibt "ist es seit dem Umbau besser geworden?"
-- über Jahre beantwortbar, auch wenn die Detaildaten längst gelöscht sind.
CREATE TABLE IF NOT EXISTS daily_stats (
    day         TEXT PRIMARY KEY,        -- YYYY-MM-DD, lokale Zeit
    seconds     INTEGER NOT NULL,        -- Sekunden mit Messwerten
    rtt_p50     INTEGER, rtt_p95 INTEGER, rtt_max INTEGER,   -- 1/100 ms
    gw_p50      INTEGER,
    jitter_p50  INTEGER, jitter_p95 INTEGER,
    loss_pct    INTEGER,                 -- 1/100 %
    probes      INTEGER, lost INTEGER,
    down_peak   INTEGER, up_peak INTEGER,                    -- bit/s
    down_bytes  INTEGER, up_bytes INTEGER,
    bloat_up    INTEGER, bloat_down INTEGER,                 -- 1/100 ms Aufschlag unter Last
    outage_secs INTEGER,
    incidents   TEXT                     -- JSON {kategorie: anzahl}
) WITHOUT ROWID;

-- Latenz unter Last (Bufferbloat) je 10-Minuten-Fenster.
-- Wird laufend berechnet, weil die 1-s-Werte nur einen Tag aufbewahrt werden;
-- so bleibt der Langzeitverlauf über Wochen sichtbar.
CREATE TABLE IF NOT EXISTS bufferbloat (
    ts            INTEGER PRIMARY KEY,   -- Beginn des Fensters
    idle_ms       REAL NOT NULL,         -- Median-RTT bei ruhiger Leitung
    idle_secs     INTEGER NOT NULL,
    up_ms         REAL,                  -- Median-RTT unter Upload-Last
    up_worst_ms   REAL,
    up_secs       INTEGER NOT NULL DEFAULT 0,
    down_ms       REAL,                  -- Median-RTT unter Download-Last
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
    ts_end      REAL,                    -- NULL = noch offen
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
    analysis     TEXT,                   -- JSON: Evidenz, Top Talker, Kennzahlen
    session_id   INTEGER,
    pcap_protected INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_incidents_time ON incidents(ts_start);

-- DNS-Aktivität pro Client und Minute (aus Pi-hole). KEIN Traffic-Maß!
CREATE TABLE IF NOT EXISTS dns_queries (
    ts          INTEGER NOT NULL,        -- Minuten-Bucket
    client_ip   TEXT NOT NULL,
    queries     INTEGER NOT NULL,
    blocked     INTEGER NOT NULL,
    top_domains TEXT,                    -- JSON
    PRIMARY KEY (ts, client_ip)
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
