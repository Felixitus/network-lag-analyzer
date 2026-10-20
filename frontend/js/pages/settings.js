// Setup-Wizard und Einstellungen.
import { api, clear, fmtBytes, fmtDateTime, h, statusIcon, toast } from '../lib.js';
import { segmented } from './common.js';

function get(obj, path) { return path.split('.').reduce((o, k) => (o == null ? undefined : o[k]), obj); }
function setPath(obj, path, v) {
  const ks = path.split('.'); let o = obj;
  ks.slice(0, -1).forEach(k => { o[k] = o[k] || {}; o = o[k]; });
  o[ks[ks.length - 1]] = v;
}

/** Formular aus Felddefinitionen; liefert {el, patch()} */
function form(cfg, fields) {
  const inputs = [];
  const grid = h('div', { class: 'form-grid' });
  for (const f of fields) {
    const val = get(cfg, f.path);
    let input;
    if (f.type === 'bool') {
      input = h('input', { type: 'checkbox', checked: !!val, id: `f-${f.path}` });
      grid.append(h('div', { class: 'field' }, h('label', { class: 'check', for: `f-${f.path}` }, input, f.label), f.help ? h('div', { class: 'help' }, f.help) : null));
    } else if (f.type === 'select') {
      input = h('select', { id: `f-${f.path}` }, f.options.map(([v, l]) => h('option', { value: v, selected: String(val) === String(v) }, l)));
      grid.append(h('div', { class: 'field' }, h('label', { for: `f-${f.path}` }, f.label), input, f.help ? h('div', { class: 'help' }, f.help) : null));
    } else {
      const v = f.type === 'list' ? (val || []).map(x => (typeof x === 'object' ? x.address : x)).join(', ') : (val ?? '');
      input = h('input', { type: f.type === 'password' ? 'password' : f.type === 'number' ? 'number' : 'text', value: String(v), id: `f-${f.path}`,
        step: f.step || 'any', placeholder: f.placeholder || '', autocomplete: 'off' });
      grid.append(h('div', { class: 'field' }, h('label', { for: `f-${f.path}` }, f.label), input, f.help ? h('div', { class: 'help' }, f.help) : null));
    }
    inputs.push([f, input]);
  }
  return {
    el: grid,
    patch() {
      const p = {};
      for (const [f, input] of inputs) {
        let v;
        if (f.type === 'bool') v = input.checked;
        else if (f.type === 'number') v = input.value === '' ? null : Number(input.value);
        else if (f.type === 'numauto') v = input.value.trim() === '' || input.value.trim() === 'auto' ? 'auto' : Number(input.value);
        else if (f.type === 'list') v = input.value.split(/[,\s]+/).filter(Boolean).map(a => ({ address: a }));
        else if (f.type === 'nullable') v = input.value.trim() || null;
        else v = input.value;
        if (f.type === 'password' && v === '********') continue;
        setPath(p, f.path, v);
      }
      return p;
    },
  };
}

function section(title, sub, fieldsForm, extra) {
  const save = h('button', { class: 'btn primary', type: 'button' }, 'Speichern');
  save.addEventListener('click', async () => {
    save.disabled = true;
    try {
      const r = await api('api/settings', { method: 'PUT', body: fieldsForm.patch() });
      toast(r.restarted ? 'Gespeichert – Datenquellen neu gestartet' : 'Gespeichert');
    } catch (e) { toast(`Fehler: ${e.message}`, 6000); }
    save.disabled = false;
  });
  return h('div', { class: 'card stack' }, h('div', null, h('h3', null, title), sub ? h('p', { class: 'small muted', style: { margin: '4px 0 0' } }, sub) : null),
    fieldsForm.el, h('div', { class: 'row' }, save, extra || null));
}

// ---------------------------------------------------------------- Datenbank
// Kleine Tabellen, die man selten löschen will, sind vorab abgewählt: Events,
// Incidents und die Bufferbloat-Fenster kosten fast keinen Platz, sind aber das
// Gedächtnis der Software.
const SMALL_TABLES = new Set(['events', 'incidents', 'bufferbloat', 'gaming_sessions']);
const DAY = 86400;

function isoDay(tsSeconds) {
  const d = new Date(tsSeconds * 1000);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}
function dayStart(iso) { return new Date(`${iso}T00:00:00`).getTime() / 1000; }

function databaseCard() {
  const card = h('div', { class: 'card stack' });
  const body = h('div', null, h('div', { class: 'skeleton' }, 'Lese Größe der Datenbank …'));
  card.append(h('div', null, h('h3', null, 'Datenbank'),
    h('p', { class: 'small muted', style: { margin: '4px 0 0' } },
      'Platzverbrauch und gezieltes Löschen nach Datum – falls die Speicherkarte eng wird.')), body);
  load();

  async function load() {
    let d;
    try { d = await api('api/database'); } catch (e) { clear(body).append(h('div', { class: 'empty' }, e.message)); return; }
    clear(body);
    body.append(sizeRow(d), pcapRow(d), tableList(d), deleteForm(d), maintenanceRow(d));
  }

  // PCAP-Dateien liegen neben der Datenbank und waren bisher nirgends sichtbar –
  // genau deshalb konnten sie unbemerkt auf zweistellige Gigabyte wachsen.
  function pcapRow(d) {
    const p = d.pcap || {};
    const limit = p.limit_bytes || 0;
    const pct = limit ? Math.min(100, Math.round(p.bytes / limit * 100)) : 0;
    const clean = h('button', { class: 'btn small', type: 'button' }, 'Jetzt aufräumen');
    clean.addEventListener('click', async () => {
      clean.disabled = true; const t = clean.textContent; clean.textContent = 'Räumt auf …';
      try {
        const r = await api('api/database/pcap-cleanup', { method: 'POST' });
        toast(r.freed_bytes > 0 ? `${fmtBytes(r.freed_bytes)} freigegeben` : 'Nichts aufzuräumen', 5000);
        load();
      } catch (e) { toast(e.message, 6000); }
      clean.textContent = t; clean.disabled = false;
    });
    return h('div', { class: 'stack', style: { marginTop: '16px' } },
      h('div', { class: 'row' }, h('h4', { style: { margin: 0 } }, 'Deep Capture (PCAP-Dateien)'),
        h('span', { class: `badge ${p.enabled ? 'warning' : ''}` }, p.enabled ? 'aktiv' : 'aus'),
        h('span', { class: 'spacer' }), clean),
      h('div', { class: 'row small' },
        h('b', null, fmtBytes(p.bytes || 0)),
        h('span', { class: 'muted' }, `in ${p.files || 0} Datei(en) · Grenze ${fmtBytes(limit)}`)),
      limit ? h('div', { class: 'meter' }, h('div', {
        class: `meter-fill ${pct >= 90 ? 'critical' : pct >= 70 ? 'warning' : ''}`,
        style: { width: `${pct}%` },
      })) : null,
      h('div', { class: 'small muted' },
        'Die Mitschnitte zählen NICHT zur Datenbankgröße oben. Incident-Mitschnitte werden '
        + `${d.deep_capture ? d.deep_capture.protected_days : 7} Tage aufgehoben; `
        + 'darüber hinaus gilt die Gesamtgrenze, die älteste Mitschnitte verdrängt.'));
  }

  function sizeRow(d) {
    const pct = d.limit_mb ? Math.min(100, Math.round(d.size.used / (d.limit_mb * 1e6) * 100)) : null;
    return h('div', { class: 'stack', style: { marginTop: '12px' } },
      h('div', { class: 'facts' },
        fact('Datei', fmtBytes(d.size.file)),
        fact('Belegt', fmtBytes(d.size.used)),
        fact('Frei in der Datei', fmtBytes(d.size.free)),
        fact('Frei auf dem Datenträger', d.free_disk == null ? 'Not available' : fmtBytes(d.free_disk)),
        fact('Ältester Datenpunkt', d.oldest ? fmtDateTime(d.oldest) : 'Not available')),
      pct == null ? h('div', { class: 'small muted' }, 'Keine Größengrenze gesetzt.')
        : h('div', null,
          h('div', { class: 'meter' }, h('div', {
            class: `meter-fill ${pct >= 90 ? 'critical' : pct >= 70 ? 'warning' : ''}`,
            style: { width: `${pct}%` },
          })),
          h('div', { class: 'small muted' }, `${pct} % der Grenze von ${d.limit_mb} MB`)),
      d.guard && d.guard.acted
        ? h('div', { class: 'banner warn' }, h('b', null, 'Automatisch aufgeräumt'),
          h('span', null, `Die Grenze war überschritten; gelöscht wurden ${
            Object.entries(d.guard.deleted).map(([k, v]) => `${k}: ${v}`).join(', ')}.`))
        : null);
  }

  function fact(k, v) {
    return h('div', { class: 'fact' }, h('div', { class: 'k' }, k), h('div', { class: 'v small-v' }, v));
  }

  function tableList(d) {
    const rows = d.tables.map(t => h('tr', null,
      h('td', null, h('div', null, t.label), h('div', { class: 'small mono muted' }, t.table)),
      h('td', { class: 'num' }, t.rows.toLocaleString('de-DE')),
      h('td', { class: 'num' }, t.bytes == null ? '–' : fmtBytes(t.bytes))));
    return h('details', { style: { marginTop: '12px' } },
      h('summary', { style: { cursor: 'pointer', fontWeight: 600 } }, 'Platz je Tabelle'),
      h('div', { class: 'table-wrap' }, h('table', { class: 'tbl small' },
        h('thead', null, h('tr', null, h('th', null, 'Tabelle'), h('th', { class: 'num' }, 'Zeilen'),
          h('th', { class: 'num' }, 'Platz'))),
        h('tbody', null, ...rows))),
      h('div', { class: 'small muted', style: { marginTop: '6px' } },
        `Nie gelöscht werden: ${d.protected.join(', ')} – darin stehen Gerätenamen, Ziele, `
        + 'Einstellungen und die Tages-Zusammenfassung.'));
  }

  function deleteForm(d) {
    const today = isoDay(Date.now() / 1000);
    const oldest = d.oldest ? isoDay(d.oldest) : today;
    let mode = 'before';
    const before = h('input', { type: 'date', value: isoDay(Date.now() / 1000 - 30 * DAY), min: oldest, max: today });
    const from = h('input', { type: 'date', value: oldest, min: oldest, max: today });
    const to = h('input', { type: 'date', value: today, min: oldest, max: today });
    // Das Datumsfeld zeigt je nach Browser-Sprache ein anderes Format. Die Zeile
    // darunter sagt deshalb im Klartext, welcher Zeitpunkt gemeint ist.
    const resolved = h('div', { class: 'small muted' });
    const updateResolved = () => {
      const b = bounds();
      resolved.textContent = mode === 'before'
        ? `Gelöscht wird alles vor ${fmtDateTime(b.end)}.`
        : (b.start >= b.end ? 'Das Startdatum muss vor dem Enddatum liegen.'
          : `Gelöscht wird von ${fmtDateTime(b.start)} bis ${fmtDateTime(b.end)}.`);
    };
    const beforeBox = h('div', { class: 'row' }, h('label', null, 'Alles vor dem'), before);
    const rangeBox = h('div', { class: 'row', style: { display: 'none' } },
      h('label', null, 'Von'), from, h('label', null, 'bis (ausschließlich)'), to);
    // Nach Namen sortiert, damit die Kästchen nach jedem Neuladen an derselben
    // Stelle stehen – die Tabellenliste oben ist dagegen nach Größe sortiert.
    const boxes = [...d.tables].sort((a, b) => a.label.localeCompare(b.label, 'de')).map(t => {
      const cb = h('input', { type: 'checkbox', checked: !SMALL_TABLES.has(t.table) });
      return { table: t.table, cb, el: h('label', { class: 'check' }, cb, t.label) };
    });

    const out = h('div', { class: 'small' });
    const preview = h('button', { class: 'btn', type: 'button' }, 'Vorschau');
    const del = h('button', { class: 'btn danger', type: 'button', disabled: true }, 'Löschen');
    let pending = null;

    function bounds() {
      if (mode === 'before') return { start: null, end: dayStart(before.value) };
      return { start: dayStart(from.value), end: dayStart(to.value) };
    }
    function selected() { return boxes.filter(b => b.cb.checked).map(b => b.table); }

    preview.addEventListener('click', async () => {
      const tables = selected();
      if (!tables.length) { out.textContent = 'Keine Tabelle ausgewählt.'; return; }
      const b = bounds();
      if (b.start != null && b.start >= b.end) { out.textContent = 'Das Startdatum liegt nicht vor dem Enddatum.'; return; }
      preview.disabled = true;
      try {
        const r = await api('api/database/preview', { method: 'POST', body: { ...b, tables, confirm: 'VORSCHAU' } });
        const lines = Object.entries(r.counts).filter(([, n]) => n > 0)
          .map(([t, n]) => `${t}: ${n.toLocaleString('de-DE')}`);
        clear(out).append(
          h('div', null, h('b', null, `${r.total.toLocaleString('de-DE')} Zeilen`),
            ' würden gelöscht', lines.length ? ` (${lines.join(', ')})` : ''),
          r.total ? h('div', { class: 'muted' }, 'Das lässt sich nicht rückgängig machen.') : null);
        pending = r.total ? { ...b, tables } : null;
        del.disabled = !pending;
      } catch (e) { out.textContent = e.message; }
      preview.disabled = false;
    });

    del.addEventListener('click', async () => {
      if (!pending) return;
      if (del.textContent !== 'Wirklich löschen?') { del.textContent = 'Wirklich löschen?'; return; }
      del.disabled = true; del.textContent = 'Löscht …';
      try {
        const r = await api('api/database/delete', { method: 'POST', body: { ...pending, confirm: 'DELETE' } });
        toast(`${r.total.toLocaleString('de-DE')} Zeilen gelöscht, ${fmtBytes(r.freed_bytes)} freigegeben`, 6000);
        pending = null;
        load();
      } catch (e) { toast(e.message, 6000); del.disabled = false; }
      del.textContent = 'Löschen';
    });

    const invalidate = () => {
      pending = null; del.disabled = true; del.textContent = 'Löschen'; clear(out); updateResolved();
    };
    [before, from, to].forEach(i => i.addEventListener('change', invalidate));
    boxes.forEach(b => b.cb.addEventListener('change', invalidate));

    updateResolved();
    return h('div', { class: 'stack', style: { marginTop: '16px' } },
      h('h4', { style: { margin: 0 } }, 'Daten nach Datum löschen'),
      segmented([['before', 'Alles vor einem Datum'], ['range', 'Zeitraum']], 'before', v => {
        mode = v;
        beforeBox.style.display = v === 'before' ? '' : 'none';
        rangeBox.style.display = v === 'range' ? '' : 'none';
        invalidate();
      }),
      beforeBox, rangeBox, resolved,
      h('div', { class: 'check-grid' }, ...boxes.map(b => b.el)),
      h('div', { class: 'row' }, preview, del), out);
  }

  function maintenanceRow(d) {
    const vac = h('button', { class: 'btn', type: 'button' }, 'Datei verkleinern (VACUUM)');
    vac.addEventListener('click', async () => {
      vac.disabled = true;
      const txt = vac.textContent;
      vac.textContent = 'Läuft … (kann dauern)';
      try {
        const r = await api('api/database/vacuum', { method: 'POST' });
        toast(r.freed > 0 ? `${fmtBytes(r.freed)} freigegeben` : 'Nichts zu verkleinern');
        load();
      } catch (e) { toast(e.message, 6000); }
      vac.textContent = txt; vac.disabled = false;
    });
    return h('div', { class: 'stack', style: { marginTop: '16px' } },
      h('div', { class: 'row' }, vac),
      h('div', { class: 'small muted' },
        'Gelöschte Seiten bleiben zunächst in der Datei liegen und werden wiederverwendet. '
        + 'Erst VACUUM gibt den Platz an das Dateisystem zurück – dafür wird kurzzeitig noch '
        + 'einmal so viel Platz gebraucht, wie die Datenbank belegt.'));
  }

  return card;
}


export async function mount(main, { refreshStatus }) {
  const s = await api('api/settings');
  const cfg = s.config;
  main.append(h('div', { class: 'page-head' }, h('div', null, h('h1', null, 'Setup & Einstellungen'),
    h('p', null, `Werte aus ${s.yaml_path || 'Standardwerten'}; Änderungen hier werden in der Datenbank gespeichert und überschreiben die Datei.`))));

  // ---------------------------------------------------------------- Wizard
  const wiz = h('div', { class: 'card stack' });
  main.append(wiz);
  async function runWizard() {
    clear(wiz).append(h('h3', null, 'Diagnose der Netzwerkarchitektur'), h('div', { class: 'skeleton' }, 'Prüfe Interfaces, Router, Pi-hole und Sichtbarkeit von Client-Traffic … (ca. 5 s)'));
    let r;
    try { r = await api('api/setup/check'); } catch (e) { clear(wiz).append(h('div', { class: 'empty' }, e.message)); return; }
    clear(wiz);
    wiz.append(h('div', { class: 'row' }, h('h3', null, 'Diagnose der Netzwerkarchitektur'), h('span', { class: 'spacer' }),
      h('button', { class: 'btn', onclick: runWizard }, 'Erneut prüfen'),
      h('button', { class: 'btn primary', onclick: async () => { await api('api/setup/complete', { method: 'POST' }); toast('Setup abgeschlossen'); refreshStatus(); } }, 'Setup abschließen')));
    const caps = h('div', { class: 'cap-grid' }, r.capabilities.map(c => h('div', null, statusIcon(c.ok), h('span', null, c.name),
      c.detail ? h('span', { class: 'small muted' }, `(${c.detail})`) : null)));
    wiz.append(h('div', null, h('h2', { style: { marginBottom: '8px' } }, 'Monitoring Capability'), caps));
    if (r.hint) wiz.append(h('div', { class: 'banner warn', style: { marginTop: 0 } }, h('b', null, 'Hinweis'), h('span', null, r.hint)));
    wiz.append(h('details', null, h('summary', { style: { cursor: 'pointer', fontWeight: 600 } }, 'Einzelprüfungen anzeigen'),
      h('ul', { class: 'checks' }, r.checks.map(c => h('li', null, statusIcon(c.ok),
        h('div', null, h('b', null, c.name), h('div', { class: 'small secondary' }, c.detail), c.hint ? h('div', { class: 'small', style: { color: 'var(--warning-ink)' } }, c.hint) : null))))));
  }
  runWizard();

  // ---------------------------------------------------------------- FRITZ!Box
  const fb = form(cfg, [
    { path: 'fritzbox.enabled', label: 'FRITZ!Box-Integration aktiv', type: 'bool' },
    { path: 'fritzbox.host', label: 'Adresse', help: '"auto" = Default-Gateway' },
    { path: 'fritzbox.username', label: 'Benutzername', help: 'Eigener Benutzer empfohlen, Recht „FRITZ!Box Einstellungen"' },
    { path: 'fritzbox.password', label: 'Passwort', type: 'password' },
    { path: 'fritzbox.capture_enabled', label: 'Paketmitschnitt für Traffic pro Gerät nutzen', type: 'bool', help: 'Nur Header (snaplen), keine Inhalte' },
    { path: 'fritzbox.capture_interface', label: 'Mitschnitt-Interface', help: 'Standard „1-lan" (LAN-Bridge)' },
    { path: 'fritzbox.snaplen', label: 'Snaplen (Bytes je Paket)', type: 'number' },
    { path: 'capture.source', label: 'Traffic-Quelle', type: 'select', options: [['auto', 'Automatisch'], ['fritzbox', 'FRITZ!Box-Mitschnitt'], ['local', 'Lokales Interface (Mirror/Gateway)'], ['none', 'Keine']] },
    { path: 'capture.local_interface', label: 'Lokales Interface', help: 'Nur für Port-Mirroring oder Pi als Gateway' },
  ]);
  const testOut = h('div', { class: 'small' });
  const testBtn = h('button', { class: 'btn', type: 'button' }, 'Verbindung & Mitschnitt testen');
  testBtn.addEventListener('click', async () => {
    const p = fb.patch().fritzbox;
    testBtn.disabled = true; testOut.textContent = 'Teste Login, TR-064 und 3 s Mitschnitt …';
    try {
      const r = await api('api/setup/fritzbox-test', { method: 'POST', body: { host: p.host, username: p.username, password: p.password || '', capture_interface: p.capture_interface, snaplen: p.snaplen } });
      clear(testOut).append(h('div', null, statusIcon(r.login.ok), ' Login: ', r.login.detail),
        r.login.hint ? h('div', { style: { color: 'var(--warning-ink)' } }, r.login.hint) : null,
        r.capture ? h('div', null, statusIcon(r.capture.ok), ` Mitschnitt: ${r.capture.ok
          ? `${r.capture.packets} Pakete, ${r.capture.macs} MAC-Adressen, Format ${r.capture.format}, ${r.capture.linktype_name}`
          : (r.capture.error || 'fehlgeschlagen')}`) : null,
        r.interfaces && r.interfaces.length ? h('div', { class: 'muted' }, `Gefundene Interfaces: ${r.interfaces.join(', ')}`) : null);
    } catch (e) { testOut.textContent = e.message; }
    testBtn.disabled = false;
  });
  main.append(h('div', { style: { height: '16px' } }), section('FRITZ!Box & Traffic-Quelle',
    'Voraussetzung: Heimnetz → Netzwerk → Netzwerkeinstellungen → „Zugriff für Anwendungen zulassen". Der Pi sieht fremden Traffic nur über diesen Weg (oder Port-Mirroring).',
    fb, h('div', { class: 'row' }, testBtn)), testOut);

  // ---------------------------------------------------------------- Messung
  const meas = form(cfg, [
    { path: 'targets', label: 'Internet-Ziele', type: 'list', help: 'IPs oder Hostnamen, kommagetrennt' },
    { path: 'gateway', label: 'Gateway', help: '"auto" oder IPv4' },
    { path: 'probe.interval', label: 'Ping-Intervall (s)', type: 'number' },
    { path: 'probe.gaming_interval', label: 'Intervall im Gaming Mode (s)', type: 'number' },
    { path: 'probe.timeout', label: 'Timeout (s)', type: 'number', help: 'Antwort später = verloren' },
    { path: 'capacity.down_mbit', label: 'Download-Kapazität (Mbit/s)', type: 'numauto', help: '"auto" = FRITZ!Box-Linkrate. Gebuchte Rate eintragen ist genauer.' },
    { path: 'capacity.up_mbit', label: 'Upload-Kapazität (Mbit/s)', type: 'numauto' },
    { path: 'dns_probe.enabled', label: 'DNS-Überwachung', type: 'bool' },
  ]);
  main.append(h('div', { style: { height: '16px' } }), section('Messung', null, meas));

  const thr = form(cfg, [
    { path: 'thresholds.ping_warning', label: 'Ping Warnung (ms)', type: 'number' },
    { path: 'thresholds.ping_critical', label: 'Ping kritisch (ms)', type: 'number' },
    { path: 'thresholds.spike_min_delta', label: 'Spike: min. über Baseline (ms)', type: 'number' },
    { path: 'thresholds.jitter_warning', label: 'Jitter Warnung (ms)', type: 'number' },
    { path: 'thresholds.packet_loss_warning', label: 'Packet Loss Warnung (% / 10 s)', type: 'number' },
    { path: 'thresholds.gateway_warning', label: 'Router Warnung (ms)', type: 'number' },
    { path: 'thresholds.high_upload_pct', label: 'Hoher Upload (% Kapazität)', type: 'number' },
    { path: 'thresholds.high_download_pct', label: 'Hoher Download (% Kapazität)', type: 'number' },
    { path: 'thresholds.retrans_warning_pct', label: 'Retransmissions Warnung (%)', type: 'number' },
    { path: 'thresholds.game_gap_ms', label: 'Game-Paketlücke (ms)', type: 'number' },
  ]);
  main.append(h('div', { style: { height: '16px' } }), section('Schwellwerte', 'Wirken sofort, ohne Neustart.', thr));

  const gm = form(cfg, [
    { path: 'gaming_pc.ip', label: 'IP des Gaming-PCs', type: 'nullable', placeholder: '192.168.178.20' },
    { path: 'gaming.auto_detect', label: 'Sessions automatisch erkennen', type: 'bool' },
    { path: 'gaming.min_pps', label: 'Min. UDP-Pakete/s je Richtung', type: 'number' },
    { path: 'gaming.stop_after_idle', label: 'Auto-Stopp nach Inaktivität (s)', type: 'number' },
  ]);
  main.append(h('div', { style: { height: '16px' } }), section('Gaming Mode', null, gm));

  const ret = form(cfg, [
    { path: 'retention.raw_days', label: '1-s-Werte (Tage)', type: 'number' },
    { path: 'retention.detailed_days', label: '10-s-Aggregate (Tage)', type: 'number' },
    { path: 'retention.aggregate_days', label: '1-min-Aggregate (Tage)', type: 'number' },
    { path: 'retention.flow_days', label: 'Flows (Tage)', type: 'number' },
    { path: 'retention.event_days', label: 'Events & Incidents (Tage)', type: 'number' },
    { path: 'retention.max_db_mb', label: 'Größengrenze der Datenbank (MB)', type: 'number',
      help: 'Notbremse: Wird sie überschritten, werden zuerst Rohdaten und 1-s-Werte gelöscht. 0 = keine Grenze.' },
    { path: 'retention.ping_samples', label: 'Einzelne Pings speichern', type: 'bool',
      help: 'Rund 14 MB je Tag, die keine Auswertung liest. Nur für die Fehlersuche einschalten.' },
    { path: 'deep_capture.enabled', label: 'Deep Capture (PCAP-Ringpuffer)', type: 'bool', help: 'Nur Header; bei Incidents geschützt' },
    { path: 'deep_capture.max_files', label: 'PCAP-Dateien im Ring', type: 'number' },
    { path: 'deep_capture.file_size_mb', label: 'Größe je Datei (MB)', type: 'number' },
    { path: 'deep_capture.max_total_mb', label: 'PCAP gesamt höchstens (MB)', type: 'number',
      help: 'Harte Grenze für ALLE Mitschnitte zusammen, auch die zu Incidents gehörenden. Die einzige Zahl, die wirklich begrenzt.' },
    { path: 'deep_capture.protected_days', label: 'Incident-Mitschnitte aufheben (Tage)', type: 'number' },
    { path: 'deep_capture.protect_auto', label: 'Mitschnitt festhalten bei', type: 'select',
      options: [['critical', 'kritischen Incidents'], ['all', 'allen Incidents'], ['none', 'nur gemeldetem Lag']],
      help: 'Gemeldete Lags werden immer festgehalten. „Alle" kann je nach Incident-Häufigkeit viel Platz kosten.' },
  ]);
  main.append(h('div', { style: { height: '16px' } }),
    section('Speicher & Deep Capture', 'Die Tages-Zusammenfassung ist von der Aufbewahrung ausgenommen – '
      + 'sie ist winzig und hält den Langzeitvergleich am Leben.', ret));

  main.append(h('div', { style: { height: '16px' } }), databaseCard());

  // ---------------------------------------------------------------- Login
  const en = h('input', { type: 'checkbox', checked: cfg.security.login_enabled && cfg.security.password_set });
  const pw = h('input', { type: 'password', placeholder: 'Neues Passwort (min. 8 Zeichen)', autocomplete: 'new-password' });
  const curPw = h('input', { type: 'password', placeholder: 'Aktuelles Passwort', autocomplete: 'current-password' });
  const saveLogin = h('button', { class: 'btn primary', type: 'button' }, 'Speichern');
  saveLogin.addEventListener('click', async () => {
    try {
      await api('api/auth/setup', { method: 'POST', body: { enabled: en.checked, password: pw.value || null, current_password: curPw.value || null } });
      toast('Login-Einstellung gespeichert'); pw.value = ''; curPw.value = '';
    } catch (e) { toast(e.message, 5000); }
  });
  main.append(h('div', { style: { height: '16px' } }), h('div', { class: 'card stack' }, h('h3', null, 'Zugriffsschutz'),
    h('p', { class: 'small muted' }, 'Optional. Die Oberfläche ist nur im LAN erreichbar; ein Login verhindert, dass andere Geräte im Netz Einstellungen ändern.'),
    h('div', { class: 'form-grid' }, h('label', { class: 'check' }, en, 'Login aktivieren'), pw, cfg.security.password_set ? curPw : null), h('div', { class: 'row' }, saveLogin)));
}
