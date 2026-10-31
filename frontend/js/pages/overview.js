// Overview: one light per area, the last 24 h / 7 d as a timeline, incidents and restarts in it.
import { api, clear, fmtDate, fmtTime, h } from '../lib.js';
import { piholeCard, segmented } from './common.js';

let timer = null;
export function unmount() { clearInterval(timer); }

const LEVEL_TEXT = { good: 'OK', warning: 'Warning', critical: 'Problem', unknown: 'Not available' };

function lightCard(l) {
  const lvl = l.level === 'unknown' ? 'muted' : l.level;
  const body = [
    h('div', { class: 'light-head' }, h('span', { class: `dot ${lvl} light-dot`, 'aria-hidden': 'true' }),
      h('span', { class: 'label' }, l.label)),
    h('div', { class: 'light-value' }, l.value),
    h('div', { class: 'small muted light-detail' }, l.detail || ' '),
  ];
  const attrs = { class: `light lvl-${l.level}`, role: 'listitem', 'aria-label': `${l.label}: ${LEVEL_TEXT[l.level] || l.level}, ${l.value}` };
  return l.href ? h('a', { ...attrs, href: l.href }, ...body) : h('div', attrs, ...body);
}

function cellTitle(t0, bucket, cell) {
  const span = `${fmtDate(t0)} ${fmtTime(t0, false)}–${fmtTime(t0 + bucket, false)}`;
  return cell ? `${span}: ${cell.text}` : `${span}: not measured`;
}

/** One lane per kind of event: in a single row they sat on top of each other. */
function eventLanes(data) {
  const lanes = [
    { label: 'Incidents', many: '#/incidents', items: data.incidents.map(i => ({ ts: i.ts_start, href: `#/incident/${i.id}`,
      cls: i.source === 'user' ? 'user' : 'inc', sym: '!',
      text: `${i.source === 'user' ? 'Lag reported' : (i.title || 'Incident')}${i.cause ? ' - ' + i.cause : ''}` })) },
    { label: 'FRITZ!Box', many: '#/line', items: (data.line_events || []).map(e => ({ ts: e.ts, href: '#/line', cls: 'line', sym: '◆',
      text: `FRITZ!Box - ${e.label}` })) },
    { label: 'New devices', many: '#/devices', items: (data.new_devices || []).map(d => ({ ts: d.ts, href: '#/devices', cls: 'newdev',
      sym: '+', text: `new device ${d.name}` })) },
    { label: 'Restarts', many: null, items: data.restarts.map(r => ({ ts: r.ts, href: null, cls: 'restart',
      sym: r.kind === 'boot' ? '⏻' : '↻', text: r.label })) },
  ];
  return lanes.filter(l => l.items.length);
}

/** Events closer than `gap` seconds become one marker with their count. */
export function clusters(items, gap) {
  const out = [];
  for (const e of [...items].sort((a, b) => a.ts - b.ts)) {
    const last = out[out.length - 1];
    if (last && e.ts - last[0].ts < gap) last.push(e);
    else out.push([e]);
  }
  return out;
}

function timelineView(data) {
  const tl = data.timeline;
  const total = tl.end - tl.start;
  const pos = ts => `${Math.min(100, Math.max(0, 100 * (ts - tl.start) / total))}%`;
  const wrap = h('div', { class: 'otl' });
  for (const row of tl.rows) {
    const strip = h('div', { class: 'otl-strip', role: 'img', 'aria-label': `${row.label}, ${tl.starts.length} periods` });
    row.cells.forEach((c, i) => strip.append(h('span', {
      class: `otl-cell ${c ? `lvl-${c.level || 'unknown'}` : 'na'}`, title: cellTitle(tl.starts[i], tl.bucket, c) })));
    wrap.append(h('div', { class: 'otl-row' }, h('div', { class: 'otl-label' }, row.label), strip));
  }
  // Markers are 20 px wide whatever the screen: on a phone the strip is a fifth as wide, so
  // "close together" is measured in pixels of the strip, not in a share of the time span.
  const stripPx = Math.max(200, Math.min(window.innerWidth, 1440) - 230);
  const gap = total * 24 / stripPx;
  for (const lane of eventLanes(data)) {
    const strip = h('div', { class: 'otl-strip otl-lane' });
    for (const c of clusters(lane.items, gap)) {
      const first = c[0];
      const when = e => `${fmtDate(e.ts)} ${fmtTime(e.ts, false)}`;
      const title = c.slice(0, 8).map(e => `${when(e)}: ${e.text}`).join('\n') + (c.length > 8 ? `\n… and ${c.length - 8} more` : '');
      const attrs = { class: `otl-mark ${first.cls}${c.length > 1 ? ' many' : ''}`, title,
        style: { left: `clamp(10px, ${pos(first.ts)}, calc(100% - 10px))` }, 'aria-label': title };
      const href = c.length > 1 ? lane.many : first.href;
      strip.append(href ? h('a', { ...attrs, href }, c.length > 1 ? String(c.length) : first.sym)
        : h('span', attrs, c.length > 1 ? String(c.length) : first.sym));
    }
    wrap.append(h('div', { class: 'otl-row' }, h('div', { class: 'otl-label' }, lane.label), strip));
  }
  // axis: 6 labels
  const axis = h('div', { class: 'otl-strip otl-axis' });
  for (let k = 0; k <= 6; k++) {
    const ts = tl.start + total * k / 6;
    axis.append(h('span', { style: { left: `${100 * k / 6}%` } }, total > 2 * 86400 ? fmtDate(ts).slice(5) : fmtTime(ts, false)));
  }
  wrap.append(h('div', { class: 'otl-row' }, h('div', { class: 'otl-label' }), axis));
  return wrap;
}

function legend() {
  const item = (cls, text) => h('span', { class: 'row small' }, h('span', { class: `otl-cell legend ${cls}` }), text);
  const mark = (cls, sym, text) => h('span', { class: 'row small' }, h('span', { class: `otl-mark legend ${cls}` }, sym), text);
  return h('div', { class: 'row small muted', style: { flexWrap: 'wrap', gap: '14px' } },
    item('lvl-good', 'OK'), item('lvl-warning', 'Warning'), item('lvl-critical', 'Problem'), item('na', 'Not measured'),
    mark('inc', '!', 'Incident'), mark('user', '!', 'Lag reported'), mark('line', '◆', 'FRITZ!Box event'),
    mark('newdev', '+', 'New device'), mark('restart', '↻', 'Restart'));
}

function happenings(data) {
  const items = [
    ...data.incidents.map(i => ({ ts: i.ts_start, el: h('a', { href: `#/incident/${i.id}` },
      i.source === 'user' ? 'Lag reported' : (i.title || `Incident #${i.id}`)), sub: i.cause })),
    ...data.restarts.map(r => ({ ts: r.ts, el: h('span', null, r.label), sub: null })),
    ...(data.new_devices || []).map(d => ({ ts: d.ts, el: h('a', { href: '#/devices' }, `New device: ${d.name}`), sub: d.mac })),
  ].sort((a, b) => b.ts - a.ts).slice(0, 5);
  if (!items.length) return h('div', { class: 'empty' }, 'No incidents and no restarts in this time span.');
  return h('ul', { class: 'list' }, ...items.map(it => h('li', null,
    h('div', { class: 'row' }, it.el, h('span', { class: 'spacer' }), h('span', { class: 'small muted' }, `${fmtDate(it.ts)} ${fmtTime(it.ts, false)}`)),
    it.sub ? h('div', { class: 'small secondary' }, it.sub) : null)));
}

export async function mount(main) {
  let range = '24h';
  const lightsBox = h('div', { class: 'lights', role: 'list' });
  const tlBox = h('div', null, h('div', { class: 'empty' }, 'loading…'));
  const listBox = h('div');
  main.append(
    h('div', { class: 'page-head' }, h('h1', null, 'Overview')),
    lightsBox,
    h('div', { style: { marginTop: '16px' } }, piholeCard({ compact: true })),
    h('div', { class: 'card stack', style: { marginTop: '16px' } },
      h('div', { class: 'card-head' }, h('div', null, h('h2', null, 'Timeline'),
        h('div', { class: 'sub' }, 'Hover a cell or a marker for the measured values; hatched: nothing was measured')),
      segmented([['24h', '24 H'], ['7d', '7 D']], range, v => { range = v; load(); })),
      tlBox, legend()),
    h('div', { class: 'card', style: { marginTop: '16px' } },
      h('div', { class: 'card-head' }, h('h2', null, 'What happened'), h('a', { href: '#/incidents', class: 'small' }, 'all incidents →')), listBox));

  async function load() {
    const d = await api(`api/overview?range=${range}`);
    clear(lightsBox).append(...d.lights.map(lightCard));
    clear(tlBox).append(timelineView(d));
    clear(listBox).append(happenings(d));
  }
  await load();
  timer = setInterval(() => load().catch(() => null), 30000);
}
