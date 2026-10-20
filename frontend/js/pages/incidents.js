// Incident-Liste und Detailansicht.
import { api, clear, CONF_LABEL, confBadge, deviceColor, EVENT_LABEL, fmtBytes, fmtDateTime, fmtDuration, fmtMbit, fmtMs, fmtRate, fmtTime, h, SERIES, ago } from '../lib.js';
import { chartCard, fmt, timeChart } from '../charts.js';
import { buildMarkers, latencyUnderLoad, segmented } from './common.js';

export async function mount(main, ctx) {
  if (ctx.route === 'incident' || ctx.args[0]) return detail(main, parseInt(ctx.args[0] || ctx.args[1], 10));
  return list(main);
}

async function list(main) {
  let source = null;
  const body = h('div', { class: 'card' });
  main.append(h('div', { class: 'page-head' },
    h('div', null, h('h1', null, 'Incidents'), h('p', null, 'Automatisch erkannte Lag-Ereignisse und deine „Ich hatte gerade Lag"-Meldungen.')),
    segmented([[null, 'Alle'], ['auto', 'Automatisch'], ['user', 'Gemeldet']], null, v => { source = v; load(); })), body);
  async function load() {
    const r = await api(`api/incidents?limit=200${source ? `&source=${source}` : ''}`);
    clear(body);
    if (!r.incidents.length) { body.append(h('div', { class: 'empty' }, 'Keine Incidents vorhanden.')); return; }
    const tbody = h('tbody');
    for (const i of r.incidents) {
      const m = i.metrics || {};
      const tr = h('tr', { class: 'click', tabindex: '0' },
        h('td', { class: 'num' }, `#${i.id}`),
        h('td', null, h('div', null, fmtDateTime(i.ts_start)), h('div', { class: 'small muted' }, ago(i.ts_start))),
        h('td', null, i.source === 'user' ? h('span', { class: 'badge warning' }, 'gemeldet') : h('span', { class: 'badge' }, 'auto')),
        h('td', null, h('div', null, i.title || '–'), h('div', { class: 'small secondary' }, i.cause || 'läuft…')),
        h('td', null, confBadge(i.confidence)),
        h('td', { class: 'num' }, m.ping_peak != null ? `${fmtMs(m.ping_before)} → ${fmtMs(m.ping_peak)} ms` : '–'),
        h('td', { class: 'num' }, m.loss_pct != null ? `${m.loss_pct} %` : '–'),
        h('td', { class: 'num' }, m.duration != null ? fmtDuration(m.duration) : '–'));
      const go = () => { location.hash = `#/incident/${i.id}`; };
      tr.addEventListener('click', go);
      tr.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
      tbody.append(tr);
    }
    body.append(h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' },
      h('thead', null, h('tr', null, ...['ID', 'Zeit', 'Quelle', 'Ereignis / Ursache', 'Confidence'].map(t => h('th', null, t)),
        h('th', { class: 'num' }, 'Ping'), h('th', { class: 'num' }, 'Loss'), h('th', { class: 'num' }, 'Dauer'))), tbody)));
  }
  await load();
}

function fact(k, before, after, unit) {
  const v = h('div', { class: 'v' });
  if (after === null || after === undefined) v.append(h('span', { class: 'muted', style: { fontSize: '14px' } }, 'Not available'));
  else if (before !== null && before !== undefined) v.append(before, h('span', { class: 'arrow' }, '→'), after, unit ? ` ${unit}` : '');
  else v.append(after, unit ? ` ${unit}` : '');
  return h('div', { class: 'fact' }, h('div', { class: 'k' }, k), v);
}

const KIND_ICON = { ping: '⏱', loss: '✕', jitter: '≈', gateway: '⌂', game_gap: '◆', dns: '◌', traffic_start: '↑', traffic_range: '⇅' };

// Wer kann das überhaupt beheben? Ehrlich benennen, statt Maßnahmen vorzuschlagen, die nichts bringen.
const SCOPE_LABEL = {
  self: ['Selbst behebbar', 'good'],
  provider: ['Liegt beim Anbieter', 'warning'],
  remote: ['Liegt beim Ziel/Routing', 'warning'],
  none: ['Keine Maßnahme ableitbar', ''],
};

function recommendation(r) {
  if (!r || !(r.steps || []).length) return null;
  const [label, cls] = SCOPE_LABEL[r.scope] || SCOPE_LABEL.none;
  return h('div', { class: 'reco' },
    h('div', { class: 'row' }, h('h3', null, 'Was jetzt hilft'), h('span', { class: `badge ${cls}` }, label)),
    h('div', { class: 'reco-head' }, r.headline || ''),
    h('ol', { class: 'reco-steps' }, r.steps.map(s => h('li', null, s))));
}

async function detail(main, id) {
  const d = await api(`api/incidents/${id}`);
  const a = d.analysis || {};
  const m = a.metrics || {};
  const when = d.reported_at || d.ts_start;

  main.append(h('p', null, h('a', { href: '#/incidents' }, '← alle Incidents')));
  const head = h('div', { class: 'card stack' },
    h('div', { class: 'inc-head' },
      h('div', null, h('div', { class: 'inc-id' }, `INCIDENT #${d.id}`),
        h('h1', null, d.source === 'user' ? `Lag gemeldet: ${fmtDateTime(d.reported_at)}` : fmtDateTime(d.ts_start)),
        h('div', { class: 'secondary' }, d.title || '',
          a.analysis_window ? ` · Analyse ${fmtTime(a.analysis_window.start)}–${fmtTime(a.analysis_window.end)}` : '')),
      h('div', { class: 'row' },
        d.session_id ? h('a', { class: 'btn', href: `#/gaming/${d.session_id}` }, 'Gaming Session') : null,
        h('a', { class: 'btn', href: `#/timeline/${pickRange(when)}` }, 'In Timeline zeigen'),
        pcapButton(d))),
    h('div', { class: 'facts' },
      fact('Dauer', null, m.duration != null ? fmtDuration(m.duration) : null),
      fact('Ping', fmtMs(m.ping_before), fmtMs(m.ping_peak), 'ms'),
      fact('Jitter', fmtMs(m.jitter_before), fmtMs(m.jitter_peak), 'ms'),
      fact('Packet Loss', null, m.loss_pct != null ? `${m.loss_pct} %` : null),
      fact('Gateway', fmtMs(m.gw_before), fmtMs(m.gw_peak), 'ms'),
      fact('Upload (Spitze)', null, m.up_peak != null ? fmtMbit(m.up_peak) : null, 'Mbit/s'),
      fact('Download (Spitze)', null, m.down_peak != null ? fmtMbit(m.down_peak) : null, 'Mbit/s')));
  main.append(head);

  // ---------------------------------------------------------------- Ursache
  const cause = h('div', { class: 'card stack' },
    h('h2', null, 'Possible Cause'),
    h('div', { class: 'cause' },
      h('div', { class: 'c' }, a.cause || d.cause || '–'),
      h('div', { class: 'row' }, confBadge(a.confidence || d.confidence),
        h('span', { class: 'secondary' }, CONF_LABEL[a.confidence || d.confidence] || ''),
        a.category_label ? h('span', { class: 'badge' }, a.category_label) : null),
      a.device ? h('div', { class: 'row', style: { marginTop: '8px' } },
        h('span', { class: 'dot', style: { background: deviceColor(a.device.mac) } }), h('b', null, a.device.name),
        h('span', { class: 'mono muted' }, a.device.ip || a.device.mac)) : null),
    h('div', null, h('h3', null, 'Evidence'), h('ul', { class: 'evidence' }, (a.evidence || []).map(e => h('li', null, e)))),
    recommendation(a.recommendation),
    (a.notes || []).length ? h('div', { class: 'small muted' }, h('b', null, 'Hinweise: '), h('ul', { class: 'evidence' }, a.notes.map(n => h('li', null, n)))) : null);

  // ---------------------------------------------------------------- Top Traffic
  const tt = h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', null, 'Top Traffic'), h('span', { class: 'sub' }, 'Ø / Spitze im Incident')));
  if (!(a.top_talkers || []).length) {
    tt.append(h('div', { class: 'empty' }, m.traffic_source ? 'Kein nennenswerter Traffic pro Gerät.' : 'Not available – kein Traffic pro Gerät gemessen.'));
  } else {
    const ul = h('ul', { class: 'list' });
    for (const t of a.top_talkers) {
      const up = t.up_peak_bps >= t.down_peak_bps;
      ul.append(h('li', { class: 'row' }, h('span', { class: 'dot', style: { background: deviceColor(t.mac) } }),
        h('div', null, h('b', null, t.name), h('div', { class: 'small mono muted' }, t.ip || t.mac)), h('span', { class: 'spacer' }),
        h('div', { class: 'num', style: { textAlign: 'right' } },
          h('div', null, `${up ? 'Upload' : 'Download'} ${fmtMbit(up ? t.up_peak_bps : t.down_peak_bps)} Mbit/s`),
          h('div', { class: 'small muted' }, `Ø ↑ ${fmtMbit(t.up_bps)} · ↓ ${fmtMbit(t.down_bps)}`))));
    }
    tt.append(ul);
  }
  if ((a.correlated_devices || []).length) {
    tt.append(h('div', { class: 'small muted', style: { marginTop: '8px' } },
      'Zeitlich korreliert (keine Ursache belegt): ', a.correlated_devices.map(c => c.name).join(', ')));
  }
  main.append(h('div', { class: 'grid grid-2', style: { marginTop: '16px' } }, cause, tt));

  if (m.latency_under_load) {
    main.append(h('div', { class: 'card stack', style: { marginTop: '16px' } },
      h('div', { class: 'card-head' }, h('h2', null, 'Latenz unter Last'),
        h('span', { class: 'sub' }, 'Zusatz-Ping gegenüber ruhiger Leitung, im Analysefenster')),
      latencyUnderLoad(m.latency_under_load, { showAdvice: true })));
  }

  // ---------------------------------------------------------------- Chart des Zeitfensters
  const t0 = Math.floor(d.ts_start) - 30, t1 = Math.ceil(d.ts_end || d.ts_start) + 10;
  const chartWrap = h('div', { class: 'stack', style: { marginTop: '16px' } });
  main.append(chartWrap);
  try {
    const span = t1 - t0;
    const rng = span <= 300 ? '5m' : span <= 900 ? '15m' : '1h';
    const end = t1 + Math.max(0, (rng === '5m' ? 300 : rng === '15m' ? 900 : 3600) - span) / 2;
    const [hist, dev] = await Promise.all([api(`api/history?range=${rng}&end=${Math.round(end)}`), api(`api/history/devices?range=${rng}&end=${Math.round(end)}&top=4`)]);
    const mk = () => buildMarkers(hist.events.filter(e => e.incident_id === d.id || (e.ts_start >= t0 && e.ts_start <= t1)), [d]);
    const c1 = chartCard('Ping & Router rund um den Incident', [
      { label: 'Internet (Median)', color: SERIES(1), fmt: fmt.ms }, { label: 'Internet (Max)', color: SERIES(1), dash: [4, 4], width: 1, fmt: fmt.ms },
      { label: 'Router', color: SERIES(3), fmt: fmt.ms }], { sync: 'inc', height: 170, yFmt: fmt.msAxis, yLabel: 'ms', markers: mk, yMinMax: 30 });
    const devSpecs = dev.devices.map(x => ({ label: `${x.name} ↑`, color: deviceColor(x.mac), fmt: fmt.mbit }));
    const c2 = chartCard('Upload pro Gerät', devSpecs.length ? devSpecs : [{ label: 'Upload', color: SERIES(2), fmt: fmt.mbit }],
      { sync: 'inc', height: 140, yFmt: fmt.mbitAxis, yLabel: 'Mbit/s', markers: mk, naText: 'Not available – kein Traffic pro Gerät', forceLegend: true });
    const c3 = chartCard('Download pro Gerät', dev.devices.map(x => ({ label: `${x.name} ↓`, color: deviceColor(x.mac), fmt: fmt.mbit })).concat(devSpecs.length ? [] : [{ label: 'Download', color: SERIES(1), fmt: fmt.mbit }]),
      { sync: 'inc', height: 140, yFmt: fmt.mbitAxis, yLabel: 'Mbit/s', markers: mk, naText: 'Not available – kein Traffic pro Gerät', forceLegend: true });
    chartWrap.append(c1.card, h('div', { class: 'grid grid-2' }, c2.card, c3.card));
    const s = hist.series;
    c1.mount().setData([s.ts, s.rtt_avg, s.rtt_max, s.gw_rtt]);
    const x2 = c2.mount(), x3 = c3.mount();
    if (dev.devices.length) {
      x2.setData([dev.ts, ...dev.devices.map(x => x.up)]);
      x3.setData([dev.ts, ...dev.devices.map(x => x.down)]);
    } else { x2.setData([s.ts, s.up_bps]); x3.setData([s.ts, s.down_bps]); }
  } catch (e) { chartWrap.append(h('div', { class: 'card muted' }, `Verlauf nicht verfügbar: ${e.message}`)); }

  // ---------------------------------------------------------------- Zeitleiste (Lag-Report)
  const lower = h('div', { class: 'grid grid-2', style: { marginTop: '16px' } });
  if (a.timeline) {
    const ul = h('ul', { class: 'timeline-list' });
    if (!a.timeline.length) ul.append(h('li', { class: 'empty' }, 'Keine Auffälligkeiten im Zeitraum.'));
    for (const x of a.timeline) {
      ul.append(h('li', null, h('span', { class: 'tl-t' }, x.ts_end && x.ts_end !== x.ts ? `${fmtTime(x.ts)}–${fmtTime(x.ts_end)}` : fmtTime(x.ts)),
        h('span', { class: 'muted' }, KIND_ICON[x.kind] || '•'), h('span', null, x.text)));
    }
    const win = a.windows || {};
    const wt = h('table', { class: 'tbl small' }, h('thead', null, h('tr', null, ...['Fenster', 'Ping max', 'Loss', 'Jitter max', 'Upload max'].map(t => h('th', null, t)))),
      h('tbody', null, Object.entries(win).map(([k, v]) => h('tr', null, h('td', null, k), h('td', { class: 'num' }, v.ping_max != null ? `${fmtMs(v.ping_max)} ms` : '–'),
        h('td', { class: 'num' }, v.loss_pct != null ? `${v.loss_pct} %` : '–'), h('td', { class: 'num' }, v.jitter_max != null ? `${fmtMs(v.jitter_max)} ms` : '–'),
        h('td', { class: 'num' }, v.up_max != null ? fmtRate(v.up_max) : '–')))));
    lower.append(h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', null, 'Gefunden'),
      h('span', { class: 'sub' }, a.analysis_window ? `Analyse ${fmtTime(a.analysis_window.start)}–${fmtTime(a.analysis_window.end)}` : '')), ul),
    h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', null, 'Analysefenster')), h('div', { class: 'table-wrap' }, wt)));
  }
  // Events
  const evs = d.events.length ? d.events : (a.events || []);
  const evList = h('ul', { class: 'list' });
  if (!evs.length) evList.append(h('li', { class: 'empty' }, 'Keine Events verknüpft.'));
  for (const e of evs) {
    evList.append(h('li', { class: 'row' }, h('span', { class: `badge ${e.severity === 'critical' ? 'critical' : 'warning'}` }, EVENT_LABEL[e.type] || e.type),
      h('span', { class: 'small muted num' }, `${fmtTime(e.ts_start)}–${e.ts_end ? fmtTime(e.ts_end) : 'offen'}`), h('span', { class: 'spacer' }),
      h('span', { class: 'small num' }, e.peak != null ? (e.type.includes('UPLOAD') || e.type.includes('DOWNLOAD') ? fmtRate(e.peak) : `${(+e.peak).toFixed(1)}`) : '')));
  }
  // Alle Regeln
  const rules = h('table', { class: 'tbl small' }, h('thead', null, h('tr', null, h('th', null, 'Regel'), h('th', null, 'Erklärung'), h('th', { class: 'num' }, 'Punkte'))),
    h('tbody', null, (a.rules || []).map(r => h('tr', null, h('td', { class: 'mono' }, r.rule.replace('rule_', '')), h('td', null, r.cause), h('td', { class: 'num' }, r.score)))));
  lower.append(h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', null, 'Events')), evList),
    h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', null, 'Geprüfte Erklärungen'), h('span', { class: 'sub' }, '≥80 High · ≥55 Medium')),
      (a.rules || []).length ? h('div', { class: 'table-wrap' }, rules) : h('div', { class: 'empty' }, 'Keine Regel traf zu.')));
  main.append(lower);

  // ---------------------------------------------------------------- Flows
  const flows = (d.active_flows || []).length ? d.active_flows : d.flows;
  const fc = h('div', { class: 'card', style: { marginTop: '16px' } }, h('div', { class: 'card-head' }, h('h2', null, 'Verbindungen im Zeitraum'),
    h('span', { class: 'sub' }, 'nur Metadaten, keine Inhalte')));
  if (!flows.length) fc.append(h('div', { class: 'empty' }, 'Keine Flow-Daten (benötigt den Traffic-Mitschnitt).'));
  else {
    fc.append(h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' },
      h('thead', null, h('tr', null, ...['Gerät', 'Protokoll', 'Gegenstelle', '↑', '↓', 'Retrans.'].map(t => h('th', null, t)))),
      h('tbody', null, flows.map(f => h('tr', null, h('td', null, f.device || f.local_ip), h('td', { class: 'mono' }, `${f.proto.toUpperCase()} :${f.local_port}`),
        h('td', { class: 'mono' }, `${f.dns_name ? f.dns_name + ' ' : ''}${f.remote_ip}:${f.remote_port}`),
        h('td', { class: 'num' }, fmtBytes(f.bytes_up)), h('td', { class: 'num' }, fmtBytes(f.bytes_down)), h('td', { class: 'num' }, f.retrans)))))));
  }
  main.append(fc);
}

function pcapButton(d) {
  if (!d.deep_capture_enabled) return h('span', { class: 'small muted', title: 'Deep Capture ist in den Einstellungen deaktiviert' }, 'PCAP: Deep Capture aus');
  if (!(d.pcap_files || []).length) return h('span', { class: 'small muted' }, 'PCAP: keine Datei für diesen Zeitraum');
  return h('a', { class: 'btn primary', href: `api/incidents/${d.id}/pcap` }, 'PCAP herunterladen');
}

function pickRange(ts) {
  const age = Date.now() / 1000 - ts;
  return age < 800 ? '15m' : age < 3000 ? '1h' : age < 20000 ? '6h' : age < 80000 ? '24h' : '7d';
}
