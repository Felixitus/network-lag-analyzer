// Shared building blocks of the pages.
import { cssVar, fmtDateTime, fmtMs, h } from '../lib.js';

export const BLOAT_RANGES = [['1h', '1 H'], ['24h', '24 H'], ['7d', '7 D'], ['30d', '30 D']];

export const RANGES = [['live', 'LIVE'], ['5m', '5 MIN'], ['15m', '15 MIN'], ['1h', '1 H'], ['6h', '6 H'], ['24h', '24 H'], ['7d', '7 D']];

export function segmented(options, value, onChange) {
  const wrap = h('div', { class: 'seg', role: 'group' });
  const btns = options.map(([v, label]) => {
    const b = h('button', { type: 'button', class: v === value ? 'on' : '', 'aria-pressed': v === value ? 'true' : 'false' }, label);
    b.addEventListener('click', () => {
      btns.forEach(x => { x.classList.remove('on'); x.setAttribute('aria-pressed', 'false'); });
      b.classList.add('on'); b.setAttribute('aria-pressed', 'true');
      onChange(v);
    });
    return b;
  });
  wrap.append(...btns);
  return wrap;
}

const LAG_TYPES = new Set(['PING_SPIKE', 'PACKET_LOSS', 'HIGH_JITTER', 'CONNECTION_DROP', 'GATEWAY_LATENCY',
  'INTERNET_LATENCY', 'TCP_RETRANSMISSION_SPIKE', 'GAME_FLOW_GAP', 'DNS_FAILURE']);

/** Incidents as bands, events as ticks (critical/warning/context). */
export function buildMarkers(events = [], incidents = [], now = Date.now() / 1000) {
  const crit = cssVar('--critical'), warn = cssVar('--warning'), ctx = cssVar('--series-2');
  return {
    bands: incidents.map(i => ({ t0: i.ts_start, t1: i.ts_end || now, color: i.source === 'user' ? warn : crit,
      alpha: i.source === 'user' ? 0.18 : 0.12 })),
    ticks: events.map(e => ({ t: e.ts_start, color: LAG_TYPES.has(e.type) ? (e.severity === 'critical' ? crit : warn) : ctx })),
  };
}

export function naBox(text) { return h('div', { class: 'empty' }, text); }

// ---------------------------------------------------------------- latency under load (bufferbloat)
export const BLOAT_DIRS = [['down', 'Under download load'], ['up', 'Under upload load']];
const badge = lvl => `badge ${lvl === 'good' ? 'good' : lvl === 'warning' ? 'warning' : 'critical'}`;

/** Compact rendering of /api/bufferbloat or metrics.latency_under_load. */
export function latencyUnderLoad(bb, { showAdvice = false } = {}) {
  if (!bb) return naBox('Not available');
  const rows = [];
  for (const [key, title] of BLOAT_DIRS) {
    const v = bb[key];
    if (!v) continue;
    rows.push(h('li', { class: 'row' },
      h('div', null, h('b', null, title),
        h('div', { class: 'small muted' }, `${v.seconds} s measured · peak ${fmtMs(v.worst_ms)} ms`),
        showAdvice ? h('div', { class: 'bloat-advice' }, v.advice) : null),
      h('span', { class: 'spacer' }),
      h('div', { style: { textAlign: 'right' } },
        h('div', { class: 'num big' }, `+${fmtMs(v.delta_ms)} ms`),
        h('span', { class: badge(v.level) }, v.grade || ''))));
  }
  if (!rows.length) return naBox(bb.note || 'Not available - no comparable measurement phases yet.');
  return h('div', { class: 'stack' },
    h('div', { class: 'bloat-idle' },
      `Quiet line: ${fmtMs(bb.idle_ms)} ms (baseline from ${bb.samples?.idle ?? 0} seconds)`),
    h('ul', { class: 'list' }, ...rows),
    rows.length < 2
      ? h('div', { class: 'small muted' }, 'The other direction was never heavily utilized in this time span.')
      : null);
}

// ------------------------------------------------------------------ path measurement (traceroute)
const PATH_BADGE = { clean: ['good', 'path clean'], loss: ['critical', 'loss on the path'], delay: ['warning', 'delay on the path'],
  unreached: ['warning', 'target not reached'], error: ['', 'not available'] };
const REASON = { incident: 'at the start of an incident', report: 'after a lag report', manual: 'started by hand' };

export function pathView(t) {
  const [cls, label] = PATH_BADGE[t.verdict] || ['', t.verdict];
  const head = h('div', { class: 'row' }, h('b', null, t.name || t.address), t.name ? h('span', { class: 'mono muted small' }, t.address) : null,
    h('span', { class: 'spacer' }), h('span', { class: `badge ${cls}` }, label));
  const sub = h('div', { class: 'small muted' }, `${fmtDateTime(t.ts)} · ${REASON[t.reason] || t.reason || ''}`,
    t.duration != null || t.duration_s != null ? ` · ${Math.round(t.duration ?? t.duration_s)} s` : '');
  const findings = h('ul', { class: 'evidence' }, (t.findings || []).map(f => h('li', null, f)));
  if (!(t.hops || []).length) return h('div', { class: 'stack' }, head, sub, findings);
  const ms = v => (v === null || v === undefined ? '–' : fmtMs(v, 1));
  const table = h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' },
    h('thead', null, h('tr', null, h('th', { class: 'num' }, 'Hop'), h('th', null, 'Address'), h('th', null, 'Segment'),
      h('th', { class: 'num' }, 'Loss'), h('th', { class: 'num' }, 'Avg ms'), h('th', { class: 'num' }, 'Best'), h('th', { class: 'num' }, 'Worst'))),
    h('tbody', null, t.hops.map(x => h('tr', null,
      h('td', { class: 'num' }, x.ttl),
      h('td', { class: 'mono' }, x.ip || h('span', { class: 'muted' }, 'no answer')),
      h('td', { class: 'small secondary' }, x.segment_label || ''),
      h('td', { class: 'num' }, x.received ? `${x.loss_pct} %` : '–'),
      h('td', { class: 'num' }, ms(x.rtt_avg)), h('td', { class: 'num' }, ms(x.rtt_min)), h('td', { class: 'num' }, ms(x.rtt_max)))))));
  return h('div', { class: 'stack' }, head, sub, findings, table);
}

// ------------------------------------------------------------------ upstream DNS servers
export function upstreamTable(servers) {
  const ms = v => (v === null || v === undefined ? '–' : fmtMs(v, 1));
  return h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' },
    h('thead', null, h('tr', null, h('th', null, 'Server'), h('th', { class: 'num' }, 'Forwarded'), h('th', { class: 'num' }, 'Median ms'),
      h('th', { class: 'num' }, '95 % within'), h('th', { class: 'num' }, 'Slowest'), h('th', { class: 'num' }, 'No reply recorded'))),
    h('tbody', null, servers.map(s => h('tr', null,
      h('td', null, h('span', { class: 'mono' }, s.upstream), s.name ? h('div', { class: 'small muted' }, s.name) : null),
      h('td', { class: 'num' }, s.forwarded.toLocaleString()),
      h('td', { class: 'num' }, ms(s.median_ms)), h('td', { class: 'num' }, ms(s.p95_ms)), h('td', { class: 'num' }, ms(s.max_ms)),
      h('td', { class: 'num' }, s.no_reply_pct === null ? '–' : `${s.no_reply_pct} %`))))));
}
