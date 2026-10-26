// Overview: one light per area, the last 24 h / 7 d as a timeline, incidents and restarts in it.
import { api, clear, fmtDate, fmtTime, h } from '../lib.js';
import { segmented } from './common.js';

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
  // markers: incidents (click → incident), restarts
  const marks = h('div', { class: 'otl-strip otl-marks' });
  for (const i of data.incidents) {
    marks.append(h('a', { class: `otl-mark inc ${i.source === 'user' ? 'user' : ''}`, href: `#/incident/${i.id}`,
      style: { left: pos(i.ts_start) }, title: `${fmtDate(i.ts_start)} ${fmtTime(i.ts_start, false)}: ${i.source === 'user' ? 'Lag reported' : (i.title || 'Incident')}${i.cause ? ' - ' + i.cause : ''}` }, '▲'));
  }
  for (const r of data.restarts) {
    marks.append(h('span', { class: `otl-mark restart ${r.kind}`, style: { left: pos(r.ts) },
      title: `${fmtDate(r.ts)} ${fmtTime(r.ts, false)}: ${r.label}` }, r.kind === 'boot' ? '⏻' : '↻'));
  }
  for (const e of data.line_events || []) {
    marks.append(h('a', { class: 'otl-mark line', href: '#/line', style: { left: pos(e.ts) },
      title: `${fmtDate(e.ts)} ${fmtTime(e.ts, false)}: FRITZ!Box - ${e.label}` }, '◆'));
  }
  for (const d of data.new_devices || []) {
    marks.append(h('a', { class: 'otl-mark newdev', href: '#/devices', style: { left: pos(d.ts) },
      title: `${fmtDate(d.ts)} ${fmtTime(d.ts, false)}: new device ${d.name}` }, '＋'));
  }
  wrap.append(h('div', { class: 'otl-row' }, h('div', { class: 'otl-label' }, 'Events'), marks));
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
  return h('div', { class: 'row small muted', style: { flexWrap: 'wrap', gap: '14px' } },
    item('lvl-good', 'OK'), item('lvl-warning', 'Warning'), item('lvl-critical', 'Problem'), item('na', 'Not measured'),
    h('span', null, '▲ Incident'), h('span', null, '◆ FRITZ!Box event'), h('span', null, '＋ New device'), h('span', null, '↻ Service started'), h('span', null, '⏻ Pi started'));
}

function happenings(data) {
  const items = [
    ...data.incidents.map(i => ({ ts: i.ts_start, el: h('a', { href: `#/incident/${i.id}` },
      i.source === 'user' ? 'Lag reported' : (i.title || `Incident #${i.id}`)), sub: i.cause })),
    ...data.restarts.map(r => ({ ts: r.ts, el: h('span', null, r.label), sub: null })),
    ...(data.new_devices || []).map(d => ({ ts: d.ts, el: h('a', { href: '#/devices' }, `New device: ${d.name}`), sub: d.mac })),
  ].sort((a, b) => b.ts - a.ts).slice(0, 12);
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
  const note = h('div', { class: 'small muted' });
  main.append(
    h('div', { class: 'page-head' }, h('div', null, h('h1', null, 'Overview'),
      h('p', null, 'Everything at a glance - each light from the current measurements, the timeline from the stored ones.'))),
    lightsBox,
    h('div', { class: 'card stack', style: { marginTop: '16px' } },
      h('div', { class: 'card-head' }, h('div', null, h('h2', null, 'Timeline'),
        h('div', { class: 'sub' }, 'Hover a cell for the measured values')),
      segmented([['24h', '24 H'], ['7d', '7 D']], range, v => { range = v; load(); })),
      tlBox, legend(), note),
    h('div', { class: 'card', style: { marginTop: '16px' } },
      h('div', { class: 'card-head' }, h('h2', null, 'What happened'), h('a', { href: '#/incidents', class: 'small' }, 'all incidents →')), listBox));

  async function load() {
    const d = await api(`api/overview?range=${range}`);
    clear(lightsBox).append(...d.lights.map(lightCard));
    clear(tlBox).append(timelineView(d));
    clear(listBox).append(happenings(d));
    note.textContent = d.note;
  }
  await load();
  timer = setInterval(() => load().catch(() => null), 30000);
}
