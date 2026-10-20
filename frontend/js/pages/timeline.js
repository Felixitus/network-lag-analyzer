// Gemeinsame Zeitachse: Netzwerkwerte und Traffic jedes Geräts übereinander,
// ein Cursor für alles, eine Ableseleiste für alle Werte gleichzeitig.
//
// Aufbau bewusst als EIN Block gestapelter Panels statt sechs Einzelkarten:
// Nur das unterste Panel trägt die Zeitachse, alles andere liegt exakt darüber.
// Das spart Höhe und macht "was war zur selben Zeit los?" ablesbar statt schätzbar.
import { api, clear, cssVar, deviceColor, fmtBytes, fmtDateTime, fmtTime, h, SERIES } from '../lib.js';
import { fmt, legend, timeChart } from '../charts.js';
import { buildMarkers, RANGES, segmented } from './common.js';

let timer = null;
export function unmount() { clearInterval(timer); }

// Panels der oberen Gruppe. `compact` = Standardhöhe; per Klick aufklappbar.
const PANELS = [
  { key: 'ping', title: 'Ping', unit: 'ms', height: 150, expand: 240,
    specs: () => [
      { label: 'Internet (Median)', color: SERIES(1), fmt: fmt.ms },
      { label: 'Internet (Max)', color: SERIES(1), dash: [4, 4], width: 1, fmt: fmt.ms },
      { label: 'Router', color: SERIES(3), fmt: fmt.ms },
      { label: 'Game-Server', color: SERIES(2), fmt: fmt.ms }],
    cols: s => [s.rtt_avg, s.rtt_max, s.gw_rtt, s.game_rtt],
    opts: { yFmt: fmt.msAxis, yMinMax: 30 } },
  { key: 'loss', title: 'Packet Loss', unit: '%', height: 78, expand: 150,
    specs: () => [{ label: 'Packet Loss', color: SERIES(8), fmt: fmt.pct, bars: true, fill: 0.85 }],
    cols: s => [s.loss_pct], opts: { yFmt: v => `${v}`, yMinMax: 5 } },
  { key: 'jitter', title: 'Jitter', unit: 'ms', height: 78, expand: 150,
    specs: () => [{ label: 'Jitter', color: SERIES(7), fmt: fmt.ms }],
    cols: s => [s.jitter], opts: { yFmt: fmt.msAxis, yMinMax: 5 } },
  { key: 'down', title: 'Download gesamt', unit: 'Mbit/s', height: 88, expand: 170,
    specs: () => [{ label: 'Download', color: SERIES(1), fmt: fmt.mbit, fill: 0.12 }],
    cols: s => [s.down_bps], opts: { yFmt: fmt.mbitAxis, yMinMax: 1e6, naText: 'Not available' } },
  { key: 'up', title: 'Upload gesamt', unit: 'Mbit/s', height: 88, expand: 170,
    specs: () => [{ label: 'Upload', color: SERIES(2), fmt: fmt.mbit, fill: 0.12 }],
    cols: s => [s.up_bps], opts: { yFmt: fmt.mbitAxis, yMinMax: 1e6, naText: 'Not available' } },
  { key: 'retrans', title: 'TCP-Retransmissions', unit: '%', height: 78, expand: 150,
    specs: () => [{ label: 'Retransmissions', color: SERIES(5), fmt: fmt.pct }],
    cols: s => [s.retrans_pct],
    opts: { yFmt: v => `${v}`, yMinMax: 2, naText: 'Not available – benötigt Traffic-Mitschnitt' } },
];

/** Aus dem `covered`-Feld zusammenhängende Lücken bauen (für die Schraffur). */
function gapsFrom(ts, covered, res) {
  if (!covered) return [];
  const out = [];
  let start = null;
  for (let i = 0; i < ts.length; i++) {
    if (!covered[i] && start === null) start = ts[i];
    if ((covered[i] || i === ts.length - 1) && start !== null) {
      const end = covered[i] ? ts[i] : ts[i] + res;
      if (end - start >= res) out.push([start, end]);
      start = null;
    }
  }
  return out;
}

export async function mount(main, { args }) {
  let range = args[0] && RANGES.some(r => r[0] === args[0]) ? args[0] : '15m';
  let zoom = null;          // {start, end} bei Zoom per Ziehen
  let res = 1;

  const zoomInfo = h('span', { class: 'sub' });
  const zoomOut = h('button', { class: 'btn small', type: 'button', style: { display: 'none' } }, '← Zoom aufheben');
  zoomOut.addEventListener('click', () => { zoom = null; zoomOut.style.display = 'none'; load(true); });
  const rangePicker = segmented(RANGES, range, v => {
    range = v; zoom = null; zoomOut.style.display = 'none';
    history.replaceState(null, '', `#/timeline/${v}`);
    load(true);
  });

  main.append(h('div', { class: 'page-head' },
    h('div', null, h('h1', null, 'Timeline'),
      h('p', null, 'Alle Messwerte auf einer Zeitachse. Rote Bänder = Incidents, orange = gemeldeter Lag, '
        + 'Striche oben = Events. Klick auf ein Band öffnet den Incident, Ziehen zoomt in den Zeitraum.')),
    h('div', { class: 'row' }, zoomOut, rangePicker)));

  // ---------------------------------------------------------------- Ableseleiste
  const readTime = h('span', { class: 'read-time' }, '–');
  const readCells = new Map();
  const readout = h('div', { class: 'readout' },
    h('span', { class: 'read-label' }, 'Werte am Cursor'), readTime);
  for (const p of PANELS) {
    const v = h('b', null, '–');
    readCells.set(p.key, v);
    readout.append(h('span', { class: 'read-cell' }, h('span', { class: 'k' }, p.title), v));
  }

  const stack = h('div', { class: 'panel-stack' });
  const lanesCard = h('div', { class: 'card chart-card' });
  const heatCard = h('div', { class: 'card' });
  const netCard = h('div', { class: 'card chart-card' },
    h('div', { class: 'card-head' }, h('h2', null, 'Netzwerk'),
      h('span', { class: 'sub' }, zoomInfo)), readout, stack);
  main.append(netCard, h('div', { style: { height: '16px' } }), lanesCard,
    h('div', { style: { height: '16px' } }), heatCard);

  // ---------------------------------------------------------------- Charts
  const sync = 'timeline';
  let markers = { bands: [], ticks: [], gaps: [] };
  const mk = () => markers;
  let incidents = [];
  const onClick = t => {
    const inc = incidents.find(i => t >= i.ts_start - 1 && t <= (i.ts_end || i.ts_start) + 1);
    if (inc) location.hash = `#/incident/${inc.id}`;
  };
  const onSelect = (a, b) => {
    if (b - a < 10) return;
    zoom = { start: Math.floor(a), end: Math.ceil(b) };
    zoomOut.style.display = '';
    load(true);
  };
  const common = { sync, markers: mk, onClick, onSelect };

  const panels = PANELS.map((p, idx) => {
    const last = idx === PANELS.length - 1;
    const specs = p.specs();
    const value = h('span', { class: 'p-val' });
    const head = h('div', { class: 'panel-head' },
      h('button', { class: 'p-toggle', type: 'button', title: 'Panel vergrößern' }, '▸'),
      h('span', { class: 'p-title' }, p.title),
      h('span', { class: 'p-unit' }, p.unit),
      specs.length > 1 ? legend(specs) : null,
      h('span', { class: 'spacer' }), value);
    const body = h('div');
    const el = h('div', { class: 'panel' }, head, body);
    stack.append(el);
    const chart = timeChart(body, specs, {
      ...common, height: p.height, xAxis: last, tooltip: false,
      onCursor: info => updateReadout(p.key, specs, info),
      ...p.opts,
    });
    let open = false;
    head.querySelector('.p-toggle').addEventListener('click', () => {
      open = !open;
      chart.setHeight(open ? p.expand : p.height);
      head.querySelector('.p-toggle').textContent = open ? '▾' : '▸';
    });
    return { def: p, chart, specs, value };
  });

  // Der Tooltip ist abgeschaltet: Sechs Tooltips gleichzeitig wären Rauschen.
  // Stattdessen schreibt jedes Panel seinen Wert in die gemeinsame Leiste.
  function updateReadout(key, specs, info) {
    const cell = readCells.get(key);
    if (!info) { readTime.textContent = '–'; readCells.forEach(c => { c.textContent = '–'; }); return; }
    readTime.textContent = fmtDateTime(info.ts);
    const parts = info.values.map((v, i) => (v === null || v === undefined ? null : specs[i].fmt(v)))
      .filter(Boolean);
    cell.textContent = parts.length ? parts.join(' · ') : 'n/a';
  }

  let laneCharts = [];
  let laneShared = false;

  async function load(full) {
    const q = zoom ? `start=${zoom.start}&end=${zoom.end}` : `range=${range}`;
    const [hist, dev, heat] = await Promise.all([
      api(`api/history?${q}`),
      api(`api/history/devices?${q}&top=8`),
      full || (!zoom && ['live', '5m', '15m'].includes(range))
        ? api(`api/heatmap?range=${range === 'live' ? '5m' : range}&cols=120`) : null,
    ]);
    res = hist.res;
    incidents = hist.incidents;
    const s = hist.series;
    markers = { ...buildMarkers(hist.events, hist.incidents), gaps: gapsFrom(s.ts, s.covered, hist.res) };
    zoomInfo.textContent = `${fmtTime(hist.start)} – ${fmtTime(hist.end)} · Auflösung ${hist.res} s`
      + (markers.gaps.length ? ` · ${markers.gaps.length} Lücke(n) ohne Messdaten` : '');
    panels.forEach(p => {
      p.chart.setData([s.ts, ...p.def.cols(s)]);
      p.chart.setMarkers(mk);
      p.value.textContent = peakLabel(p.def, s);
    });
    renderLanes(dev, full);
    if (heat) renderHeat(heat);
  }

  /** Spitzenwert im sichtbaren Zeitraum – damit ein flaches Panel trotzdem etwas sagt. */
  function peakLabel(def, s) {
    const cols = def.cols(s);
    const vals = cols.flat().filter(v => v !== null && v !== undefined);
    if (!vals.length) return '';
    return `max ${def.specs()[0].fmt(Math.max(...vals))}`;
  }

  function renderLanes(dev, full) {
    const key = dev.devices.map(d => d.mac).join(',');
    if (full || key !== renderLanes.key) {
      laneCharts.forEach(c => c.destroy()); laneCharts = [];
      clear(lanesCard);
      const scaleBtn = h('button', { class: 'btn small', type: 'button' },
        laneShared ? 'Eigene Skala je Gerät' : 'Gleiche Skala für alle');
      scaleBtn.addEventListener('click', () => {
        laneShared = !laneShared;
        renderLanes.key = null;
        renderLanes(dev, true);
        laneCharts.forEach((c, i) => { c.setData([dev.ts, dev.devices[i].up, dev.devices[i].down]); c.setMarkers(mk); });
      });
      lanesCard.append(h('div', { class: 'card-head' }, h('h2', null, 'Traffic pro Gerät'),
        h('div', { class: 'row' }, h('span', { class: 'sub' },
          `Top ${dev.devices.length} nach Datenmenge · Auflösung ${dev.res} s`), scaleBtn)));
      if (!dev.devices.length) {
        lanesCard.append(h('div', { class: 'empty' }, dev.available ? 'Kein Traffic im Zeitraum.'
          : `Not available – ${dev.reason || 'keine Traffic-Quelle'}. Der Pi sieht fremden Traffic nur über den `
            + 'FRITZ!Box-Mitschnitt, Port-Mirroring oder als Gateway.'));
        renderLanes.key = key;
        return;
      }
      lanesCard.append(h('div', { class: 'legend', style: { marginBottom: '6px' } },
        h('span', null, h('span', { class: 'swatch', style: { background: cssVar('--text-secondary') } }), 'Upload (durchgezogen)'),
        h('span', null, h('span', { class: 'swatch dash', style: { borderColor: cssVar('--text-secondary') } }), 'Download (gestrichelt)'),
        laneShared ? h('span', { class: 'muted' }, 'gleiche Skala – Lanes sind direkt vergleichbar')
          : h('span', { class: 'muted' }, 'eigene Skala je Gerät – Höhen NICHT vergleichbar')));
      // Bei gemeinsamer Skala ist die Obergrenze der größte Wert aller Geräte.
      const allMax = Math.max(1e6, ...dev.devices.flatMap(d => [...d.up, ...d.down])
        .filter(v => v !== null && v !== undefined));
      const lanes = h('div', { class: 'lanes' });
      lanesCard.append(lanes);
      dev.devices.forEach((d, idx) => {
        const c = deviceColor(d.mac);
        const body = h('div');
        const peak = Math.max(0, ...[...d.up, ...d.down].filter(v => v !== null && v !== undefined));
        lanes.append(h('div', { class: 'lane' },
          h('div', { class: 'lane-label' },
            h('span', { class: 'dot', style: { background: c, marginRight: '6px' } }), h('b', null, d.name),
            h('span', { class: 'muted mono' }, d.ip && d.ip !== d.name ? d.ip : (d.ip ? '' : d.mac)),
            h('span', { class: 'muted' }, fmtBytes(d.total_bytes)),
            h('span', { class: 'spacer' }),
            h('span', { class: 'muted num' }, peak > 0 ? `Spitze ${fmt.mbit(peak)}` : '')),
          body));
        laneCharts.push(timeChart(body, [
          { label: `${d.name} ↑`, color: c, fmt: fmt.mbit, fill: 0.14 },
          { label: `${d.name} ↓`, color: c, dash: [5, 4], width: 1.5, fmt: fmt.mbit },
        ], { ...common, height: idx === dev.devices.length - 1 ? 104 : 74, yFmt: fmt.mbitAxis,
          yMinMax: laneShared ? allMax : 1e6,
          yRange: laneShared ? (() => [0, allMax * 1.08]) : undefined,
          xAxis: idx === dev.devices.length - 1 }));
      });
      renderLanes.key = key;
    }
    dev.devices.forEach((d, i) => { laneCharts[i].setData([dev.ts, d.up, d.down]); laneCharts[i].setMarkers(mk); });
  }

  function renderHeat(hm) {
    clear(heatCard);
    heatCard.append(h('div', { class: 'card-head' }, h('h2', null, 'Heatmap: Aktivität je Gerät'),
      h('span', { class: 'sub' }, `Zeit → horizontal · Intensität = Datenmenge (${Math.round(hm.bucket_seconds)} s je Zelle)`)));
    if (!hm.rows.length) { heatCard.append(h('div', { class: 'empty' }, 'Not available – keine Traffic-Daten im Zeitraum.')); return; }
    const max = Math.max(...hm.rows.flatMap(r => r.values), 1);
    // Sequenzielle Skala (ein Farbton, hell → dunkel), logarithmisch, damit kleine Aktivität sichtbar bleibt
    const ramp = ['#cde2fb', '#9ec5f4', '#6da7ec', '#3987e5', '#256abf', '#184f95', '#0d366b'];
    const colorFor = v => v <= 0 ? 'var(--surface-2)' : ramp[Math.min(ramp.length - 1, Math.floor(Math.log1p(v) / Math.log1p(max) * ramp.length))];
    const wrap = h('div', { class: 'heatmap' });
    for (const r of hm.rows) {
      const cells = h('div', { class: 'hm-cells', style: { gridTemplateColumns: `repeat(${hm.cols}, 1fr)` } });
      r.values.forEach((v, i) => {
        const t0 = new Date((hm.start + i * hm.bucket_seconds) * 1000);
        cells.append(h('i', { style: { background: colorFor(v) }, title: `${r.name} · ${t0.toLocaleTimeString()} · ${fmtBytes(v)}` }));
      });
      wrap.append(h('div', { class: 'hm-row' }, h('span', { class: 'n' }, r.name), cells));
    }
    const scale = h('div', { class: 'row small muted', style: { marginTop: '8px' } }, 'wenig',
      ...ramp.map(c => h('i', { style: { display: 'inline-block', width: '18px', height: '10px', background: c, borderRadius: '2px' } })), 'viel');
    heatCard.append(wrap, scale);
  }

  await load(true);
  timer = setInterval(() => {
    if (!zoom && ['live', '5m', '15m', '1h'].includes(range)) load(false);
  }, 5000);
}
