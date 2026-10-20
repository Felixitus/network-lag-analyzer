// Dashboard: network status, LAG button, live charts, top devices, latest incidents.
import { api, ago, confBadge, deviceColor, EVENT_LABEL, fmtMbit, fmtMs, fmtRate, h, levelFor, NA, SERIES, clear, toast, fmtTime } from '../lib.js';
import { chartCard, fmt } from '../charts.js';
import { BLOAT_RANGES, buildMarkers, latencyUnderLoad, RANGES, segmented } from './common.js';

let off = null;
let timer = null;

export function unmount() { if (off) off(); off = null; clearInterval(timer); }

export async function mount(main, { store }) {
  const settings = await api('api/settings');
  const th = settings.config.thresholds;
  let range = 'live';

  // ---------------------------------------------------------------- header
  const st0 = store.status || {};
  main.append(h('div', { class: 'page-head' },
    h('div', null, h('h1', null, 'Network Status'),
      h('p', null, 'Live measurement from the Raspberry Pi - every value measured, nothing estimated.'),
      st0.capture_delay >= 4 ? h('p', { class: 'small muted', style: { margin: '4px 0 0' } },
        `Note: your router delivers the capture buffered by ~${Math.round(st0.capture_delay)} s. `
        + 'Ping, jitter and packet loss are live; traffic values are filled in later, '
        + `the root cause analysis waits ${Math.round(st0.analysis_delay || 0)} s for complete data.`) : null)));

  // ---------------------------------------------------------------- tiles + LAG button
  const tiles = h('div', { class: 'tiles', role: 'list' });
  const T = {};
  for (const [key, label] of [['internet', 'Internet'], ['ping', 'Ping'], ['jitter', 'Jitter'], ['loss', 'Packet Loss'],
    ['gw', 'Gateway'], ['down', 'Download'], ['up', 'Upload']]) {
    const v = h('div', { class: 'value' }, '…'), f = h('div', { class: 'foot' }, '');
    const el = h('div', { class: 'tile', role: 'listitem' }, h('div', { class: 'label' }, label), v, f);
    T[key] = { el, v, f }; tiles.append(el);
  }
  let lagWindow = 30;
  const lagBtn = h('button', { class: 'lag-btn', type: 'button' }, 'I JUST HAD LAG', h('small', null, 'analyzes the last seconds right away'));
  lagBtn.addEventListener('click', async () => {
    lagBtn.disabled = true;
    lagBtn.firstChild.textContent = 'Analyzing…';
    try {
      const inc = await api('api/lag-report', { method: 'POST', body: { window: lagWindow } });
      location.hash = `#/incident/${inc.id}`;
    } catch (e) { toast(`Analysis failed: ${e.message}`); lagBtn.disabled = false; lagBtn.firstChild.textContent = 'I JUST HAD LAG'; }
  });
  const gamingBox = h('div', { class: 'row small' });
  const lagCard = h('div', { class: 'card lag-card' }, lagBtn,
    h('div', { class: 'row small' }, h('span', { class: 'muted' }, 'Time span:'),
      segmented([[10, '10 s'], [30, '30 s'], [60, '60 s'], [300, '5 min']], 30, v => { lagWindow = v; })),
    gamingBox);
  main.append(h('div', { class: 'status-wrap' }, tiles, lagCard));

  // ---------------------------------------------------------------- charts
  const sync = 'dash';
  const markers = { events: [], incidents: [] };
  const mk = () => buildMarkers(markers.events, markers.incidents);
  const pingSpecs = [
    { label: 'Internet (median)', color: SERIES(1), fmt: fmt.ms },
    { label: 'Internet (max)', color: SERIES(1), width: 1, dash: [4, 4], fmt: fmt.ms },
    { label: 'Router', color: SERIES(3), fmt: fmt.ms },
    { label: 'Game server', color: SERIES(2), fmt: fmt.ms },
  ];
  const c1 = chartCard('Ping', pingSpecs, { sync, yFmt: fmt.msAxis, yLabel: 'ms', markers: mk, height: 200, yMinMax: 30 });
  const c2 = chartCard('Jitter', [{ label: 'Jitter', color: SERIES(7), fmt: fmt.ms }], { sync, yFmt: fmt.msAxis, yLabel: 'ms', markers: mk, height: 130, yMinMax: 5 });
  const c3 = chartCard('Packet Loss', [{ label: 'Packet Loss', color: SERIES(8), fmt: fmt.pct, bars: true, fill: 0.85 }], { sync, yFmt: v => `${v}`, yLabel: '%', markers: mk, height: 130, yMinMax: 5 });
  const tputSpecs = [
    { label: 'Download', color: SERIES(1), fmt: fmt.mbit, fill: 0.10 },
    { label: 'Upload', color: SERIES(2), fmt: fmt.mbit, fill: 0.10 },
  ];
  const c4 = chartCard('Throughput (WAN total)', tputSpecs, { sync, yFmt: fmt.mbitAxis, yLabel: 'Mbit/s', markers: mk, height: 160, yMinMax: 1e6,
    naText: 'Not available - no traffic source (enter FRITZ!Box access in Setup)' });
  const rangeSeg = segmented(RANGES, range, v => { range = v; loadHistory(); });
  const chartsCard = h('section', { class: 'stack', style: { marginTop: '16px' } },
    h('div', { class: 'row' }, h('h2', null, 'History'), h('span', { class: 'spacer' }), rangeSeg),
    h('div', { class: 'grid grid-2' }, c1.card, c4.card), h('div', { class: 'grid grid-2' }, c2.card, c3.card));
  main.append(chartsCard);
  const ch = [c1.mount(), c2.mount(), c3.mount(), c4.mount()];

  // ---------------------------------------------------------------- latency under load (bufferbloat)
  const bloatBody = h('div', null, h('div', { class: 'empty' }, 'loading…'));
  const bloatFoot = h('div', { class: 'small muted' });
  let bloatRange = '24h';
  main.append(h('div', { class: 'card stack', style: { marginTop: '16px' } },
    h('div', { class: 'card-head' },
      h('div', null, h('h2', null, 'Latency under load'),
        h('div', { class: 'sub' }, 'How much ping is added when the line is full')),
      segmented(BLOAT_RANGES, bloatRange, v => { bloatRange = v; loadBloat(); })),
    bloatBody, bloatFoot));

  async function loadBloat() {
    try {
      const r = await api(`api/bufferbloat?range=${bloatRange}`);
      clear(bloatBody);
      bloatBody.append(latencyUnderLoad(r.summary, { showAdvice: true }));
      bloatFoot.textContent = r.source === 'live'
        ? `From ${r.seconds_covered} per-second values${bloatRange === '1h' ? ' of the time span' : ' of the last hour - no evaluated windows exist yet for longer spans'}.`
        : `From ${r.summary.windows || 0} evaluated ${Math.round(r.window_seconds / 60)}-minute windows `
          + '(per-second values are only kept for one day).';
    } catch (e) {
      clear(bloatBody);
      bloatBody.append(h('div', { class: 'empty' }, `Not available - ${e.message}`));
      bloatFoot.textContent = '';
    }
  }
  await loadBloat();

  // ---------------------------------------------------------------- bottom row
  const talkers = h('ul', { class: 'list' });
  const incList = h('ul', { class: 'list' });
  const openEv = h('ul', { class: 'list' });
  const talkerNote = h('span', { class: 'sub' });
  main.append(h('div', { class: 'grid grid-3', style: { marginTop: '16px' } },
    h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', null, 'Top Devices right now'), talkerNote), talkers,
      h('a', { href: '#/devices', class: 'small' }, 'Historical view →')),
    h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', null, 'Latest Incidents'), h('a', { href: '#/incidents', class: 'small' }, 'all →')), incList),
    h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', null, 'Active Events')), openEv)));

  // ---------------------------------------------------------------- data
  let data = null;   // column arrays for LIVE
  function toCols(s) {
    return {
      ts: s.ts, ping: [s.rtt_avg, s.rtt_max, s.gw_rtt, s.game_rtt], jit: [s.jitter], loss: [s.loss_pct], tput: [s.down_bps, s.up_bps],
    };
  }
  function draw() {
    ch[0].setData([data.ts, ...data.ping]);
    ch[1].setData([data.ts, ...data.jit]);
    ch[2].setData([data.ts, ...data.loss]);
    ch[3].setData([data.ts, ...data.tput]);
  }
  async function loadHistory() {
    const r = await api(`api/history?range=${range}`);
    data = toCols(r.series);
    markers.events = r.events; markers.incidents = r.incidents;
    draw();
    ch.forEach(c => c.setMarkers(mk));
  }
  await loadHistory();

  function renderIncidents(items) {
    clear(incList);
    if (!items.length) { incList.append(h('li', { class: 'empty' }, 'No incidents yet - good.')); return; }
    for (const i of items) {
      incList.append(h('li', { class: 'inc-row' }, h('a', { href: `#/incident/${i.id}` },
        h('div', { class: 'row' }, h('span', { class: 'title' }, i.source === 'user' ? 'Lag reported' : (i.title || `Incident #${i.id}`)),
          h('span', { class: 'spacer' }), h('span', { class: 'when' }, ago(i.ts_start)))),
        h('div', { class: 'row small secondary' }, i.cause || 'running…', confBadge(i.confidence))));
    }
  }
  async function loadIncidents() {
    const r = await api('api/incidents?limit=6');
    renderIncidents(r.incidents);
  }
  await loadIncidents();

  function renderTiles(f) {
    const m = f ? f.m : {};
    const set = (k, val, unit, foot, lvl) => {
      const t = T[k];
      t.el.className = `tile${val === null ? ' na' : ''}${lvl && lvl !== 'good' ? ` lvl-${lvl}` : ''}`;
      clear(t.v);
      if (val === null) t.v.append(NA); else t.v.append(val, unit ? h('span', { class: 'unit' }, unit) : null);
      t.f.textContent = foot || '';
    };
    const online = f ? f.online : null;
    clear(T.internet.v);
    T.internet.el.className = 'tile';
    T.internet.v.append(h('span', { class: 'state' }, h('span', { class: `dot ${online === true ? 'good' : online === false ? 'critical' : 'muted'}` }),
      online === true ? 'Online' : online === false ? 'Offline' : NA));
    T.internet.f.textContent = f ? `As of ${fmtTime(f.ts)}` : '';
    set('ping', fmtMs(m.rtt_avg), 'ms', m.rtt_min !== null && m.rtt_min !== undefined ? `${fmtMs(m.rtt_min)}–${fmtMs(m.rtt_max)} ms` : '',
      levelFor(m.rtt_avg, th.ping_warning, th.ping_critical));
    set('jitter', fmtMs(m.jitter), 'ms', '10 s window', levelFor(m.jitter, th.jitter_warning));
    const l = f ? f.loss : {};
    const l10 = l['10s'];
    set('loss', l10 === null || l10 === undefined ? null : l10.toFixed(l10 === 0 ? 0 : 1), '%',
      l['60s'] !== null && l['60s'] !== undefined ? `60 s: ${l['60s'].toFixed(1)} % · 5 min: ${(l['300s'] || 0).toFixed(1)} %` : '',
      levelFor(l10, th.packet_loss_warning, 5));
    set('gw', fmtMs(m.gw_rtt), 'ms', 'Router latency', levelFor(m.gw_rtt, th.gateway_warning));
    const sticky = stickyTraffic(f);
    const tm = sticky ? { down_bps: sticky.down, up_bps: sticky.up, traffic_src: sticky.src } : m;
    const src = tm.traffic_src === 'tr064' ? 'FRITZ!Box total (sum)'
      : tm.traffic_src?.startsWith('capture') ? (sticky ? `Capture ${fmtTime(sticky.ts)}`
        : `Capture${tm.traffic_src.endsWith('~') ? ' (estimated)' : ''}`) : '';
    set('down', fmtMbit(tm.down_bps), 'Mbit/s', src);
    set('up', fmtMbit(tm.up_bps), 'Mbit/s', src);
  }

  // Last second WITH traffic data. The router delivers the capture buffered,
  // so in the meantime we show the last measured state - with its timestamp.
  let lastTraffic = null;
  function updateSticky(f) {
    if (f && f.m.traffic_src && f.m.traffic_src.startsWith('capture')) {
      lastTraffic = { ts: f.ts, devices: f.devices, down: f.m.down_bps, up: f.m.up_bps, src: f.m.traffic_src };
    }
  }
  function stickyTraffic(f) {
    const live = f && f.m.traffic_src && f.m.traffic_src.startsWith('capture');
    if (live) return null;
    return lastTraffic && f && f.ts - lastTraffic.ts <= 15 ? lastTraffic : null;
  }
  function renderTalkers(f) {
    clear(talkers);
    const traffic = f && f.m.traffic_src && f.m.traffic_src.startsWith('capture');
    const sticky = stickyTraffic(f);
    const devs = traffic ? f.devices : sticky ? sticky.devices : [];
    talkerNote.textContent = traffic ? 'last second' : sticky ? `As of ${fmtTime(sticky.ts)}` : '';
    if (!traffic && !sticky) {
      talkers.append(h('li', { class: 'empty' }, 'Not available - traffic per device needs the FRITZ!Box capture, port mirroring or the Pi as gateway.'));
      return;
    }
    if (!devs.length) { talkers.append(h('li', { class: 'empty' }, 'No significant traffic.')); return; }
    const max = Math.max(1, ...devs.map(d => Math.max(d.up_bps, d.down_bps)));
    for (const d of devs.slice(0, 6)) {
      const c = deviceColor(d.mac);
      talkers.append(h('li', { class: 'talker' },
        h('div', null, h('div', { class: 'name' }, h('span', { class: 'dot', style: { background: c, marginRight: '8px' } }), d.name),
          h('div', { class: 'small muted mono' }, d.ip || d.mac)),
        h('div', { class: 'bars' },
          h('div', { class: 'bar-row' }, h('span', { title: 'Upload' }, '↑'), h('div', { class: 'bar-track' }, h('div', { class: 'bar-fill', style: { width: `${100 * d.up_bps / max}%`, background: c } })), h('b', null, `${fmtMbit(d.up_bps)}`)),
          h('div', { class: 'bar-row' }, h('span', { title: 'Download' }, '↓'), h('div', { class: 'bar-track' }, h('div', { class: 'bar-fill', style: { width: `${100 * d.down_bps / max}%`, background: c, opacity: 0.55 } })), h('b', null, `${fmtMbit(d.down_bps)}`)))));
    }
    talkers.append(h('li', { class: 'small muted' }, 'Values in Mbit/s · ↑ upload · ↓ download'));
  }

  function renderOpenEvents(evs) {
    clear(openEv);
    if (!evs.length) { openEv.append(h('li', { class: 'empty' }, 'No active anomalies.')); return; }
    for (const e of evs) {
      openEv.append(h('li', null, h('div', { class: 'row' },
        h('span', { class: `badge ${e.severity === 'critical' ? 'critical' : 'warning'}` }, e.severity === 'critical' ? '⚠ critical' : '▲ warning'),
        h('b', null, EVENT_LABEL[e.type] || e.type), h('span', { class: 'spacer' }), h('span', { class: 'small muted' }, `since ${fmtTime(e.ts_start)}`)),
        h('div', { class: 'small secondary' }, e.peak !== null && e.peak !== undefined ? `Peak: ${e.type.includes('UPLOAD') || e.type.includes('DOWNLOAD') ? fmtRate(e.peak) : e.peak.toFixed(1)}` : '')));
    }
  }

  function renderGaming(sess) {
    clear(gamingBox);
    if (sess) {
      gamingBox.append(h('span', { class: 'dot good' }), h('b', null, 'Gaming session running'),
        h('span', { class: 'muted' }, `since ${fmtTime(sess.ts_start)}`), h('span', { class: 'spacer' }),
        h('button', { class: 'btn', onclick: async () => { const r = await api('api/gaming/stop', { method: 'POST' }); location.hash = `#/gaming/${r.id}`; } }, 'Stop'));
    } else {
      gamingBox.append(h('span', { class: 'muted' }, 'Gaming Mode: off'), h('span', { class: 'spacer' }),
        h('button', { class: 'btn', onclick: async () => { await api('api/gaming/start', { method: 'POST', body: {} }); toast('Gaming session started - detailed monitoring active'); } }, 'Start gaming session'));
    }
  }

  // On load, fetch the last measured traffic state from the history (buffered stream)
  try {
    const tt = await api('api/top-talkers?seconds=12');
    if (tt.devices.length) {
      lastTraffic = {
        ts: tt.end, devices: tt.devices, src: 'capture',
        down: tt.devices.reduce((a, d) => a + d.down_bps, 0), up: tt.devices.reduce((a, d) => a + d.up_bps, 0),
      };
    }
  } catch { /* irrelevant without a traffic source */ }

  const st = store.status;
  if (st && st.last) { updateSticky(st.last); renderTiles(st.last); renderTalkers(st.last); renderOpenEvents(st.last.open_events || []); }
  else renderTiles(null);
  renderGaming(st ? st.gaming : null);

  // ---------------------------------------------------------------- live updates
  let lastGaming = st ? st.gaming : null;
  let lastFrame = st ? st.last : null;
  off = store.on((kind, d) => {
    if (kind === 'tick_patch') {
      // Fill in late traffic data (buffered router stream)
      if (data) {
        const i = data.ts.lastIndexOf(d.ts);
        if (i >= 0) { data.tput[0][i] = d.m.down_bps; data.tput[1][i] = d.m.up_bps; draw(); }
      }
      if (lastFrame && d.ts >= lastFrame.ts - 30) {
        if (d.ts >= lastFrame.ts) lastFrame = { ...lastFrame, m: { ...lastFrame.m, ...d.m }, devices: d.devices };
        updateSticky(d);
        renderTiles(lastFrame); renderTalkers(lastFrame);
      }
      return;
    }
    if (kind === 'tick') {
      lastFrame = d;
      updateSticky(d);
      renderTiles(d); renderTalkers(d); renderOpenEvents(d.open_events || []);
      if (JSON.stringify(d.gaming) !== JSON.stringify(lastGaming)) { lastGaming = d.gaming; renderGaming(d.gaming); }
      if (range === 'live' && data) {
        data.ts.push(d.ts);
        const m = d.m;
        [[data.ping, [m.rtt_avg, m.rtt_max, m.gw_rtt, m.game_rtt]], [data.jit, [m.jitter]], [data.loss, [m.loss_pct]], [data.tput, [m.down_bps, m.up_bps]]]
          .forEach(([arr, vals]) => arr.forEach((a, i) => a.push(vals[i] ?? null)));
        while (data.ts.length && data.ts[0] < d.ts - 300) {
          data.ts.shift(); [...data.ping, ...data.jit, ...data.loss, ...data.tput].forEach(a => a.shift());
        }
        draw();
      }
    } else if (kind === 'event') {
      const i = markers.events.findIndex(e => e.id === d.id);
      if (i >= 0) markers.events[i] = d; else markers.events.push(d);
    } else if (kind === 'incident') {
      const i = markers.incidents.findIndex(e => e.id === d.id);
      if (i >= 0) markers.incidents[i] = d; else markers.incidents.push(d);
      loadIncidents();
    } else if (kind === 'gaming') {
      lastGaming = d; renderGaming(d);
    }
  });
  timer = setInterval(() => { if (range !== 'live') loadHistory(); }, 30000);
}
