// Devices page, part 2: new and unnamed devices, and when which device was in the network.
import { api, clear, deviceColor, fmtDate, fmtDateTime, fmtDuration, fmtTime, h, toast } from '../lib.js';
import { segmented } from './common.js';

function newCard(r, reload) {
  const items = [...r.new.map(d => ({ ...d, why: `new since ${fmtDateTime(d.first_seen)}` })),
    ...r.unknown.filter(u => !r.new.some(n => n.mac === u.mac)).map(d => ({ ...d, why: 'no name from any source' }))];
  const allBtn = h('button', { class: 'btn', type: 'button', disabled: !items.length || null }, 'Mark all as known');
  allBtn.addEventListener('click', async () => {
    await api('api/devices/known', { method: 'POST', body: { all_new: true } });
    toast('All marked as known'); reload();
  });
  const card = h('div', { class: 'card stack' }, h('div', { class: 'card-head' }, h('div', null, h('h2', null, 'New and unnamed devices'),
    h('div', { class: 'sub' }, items.length ? `${items.length} to check` : 'Nothing to check')), allBtn));
  if (!items.length) {
    card.append(h('div', { class: 'empty' }, 'No new or unnamed devices. A device that joins the network for the first time appears here.'));
    return card;
  }
  card.append(h('ul', { class: 'list' }, ...items.map(d => {
    const btn = h('button', { class: 'btn', type: 'button' }, 'Known');
    btn.addEventListener('click', async () => {
      await api('api/devices/known', { method: 'POST', body: { macs: [d.mac] } }); reload();
    });
    return h('li', { class: 'row' },
      h('span', { class: `dot ${d.active ? 'good' : 'muted'}`, title: d.active ? 'Online' : 'Offline' }),
      h('div', null, h('b', null, d.name), h('div', { class: 'small muted mono' }, `${d.ip || '–'} · ${d.mac}`),
        h('div', { class: 'small secondary' }, [d.vendor, d.why].filter(Boolean).join(' · '))),
      h('span', { class: 'spacer' }), btn);
  })));
  card.append(h('div', { class: 'small muted' }, 'Give a device a name in the list below, or mark it as known if you recognize it.'));
  return card;
}

function lanesCard(r, rangeSeg) {
  const total = r.end - r.start;
  const pct = ts => `${100 * (ts - r.start) / total}%`;
  const card = h('div', { class: 'card stack' }, h('div', { class: 'card-head' }, h('div', null, h('h2', null, 'Presence'),
    h('div', { class: 'sub' }, 'When which device was in the network')), rangeSeg));
  if (!r.lanes.length) { card.append(h('div', { class: 'empty' }, 'No presence recorded yet - it is collected once a minute from now on.')); return card; }
  for (const l of r.lanes.slice(0, 40)) {
    const track = h('div', { class: 'phase-track' });
    for (const [a, b, src] of l.periods) {
      const dns = src === 'dns';
      const bar = h('div', { class: `phase-bar${dns ? ' from-dns' : ''}`,
        title: `${fmtDateTime(a)} – ${fmtTime(b, false)} (${fmtDuration(b - a)})${dns ? ' · from DNS lookups, whole hours' : ''}`,
        style: { left: pct(a), width: `max(2px, ${100 * (b - a) / total}%)` } });
      // custom properties only via setProperty; Object.assign on style ignores them
      if (dns) bar.style.setProperty('--bar', deviceColor(l.mac)); else bar.style.background = deviceColor(l.mac);
      track.append(bar);
    }
    card.append(h('div', { class: 'phase-lane' }, h('div', { class: 'phase-label small', title: l.mac },
      h('span', { class: `dot ${l.active ? 'good' : 'muted'}`, style: { marginRight: '6px' } }), l.name), track));
  }
  const fmtAxis = ts => (total > 2 * 86400 ? fmtDate(ts).slice(5) : fmtTime(ts, false));
  card.append(h('div', { class: 'phase-lane' }, h('div'), h('div', { class: 'phase-axis small muted' },
    ...[0, 1, 2, 3, 4].map(k => h('span', null, fmtAxis(r.start + total * k / 4))))));
  if (r.lanes.length > 40) card.append(h('div', { class: 'small muted' }, `${r.lanes.length - 40} more devices not shown.`));
  card.append(h('div', { class: 'small muted' }, r.note));
  return card;
}

export function presenceSection() {
  let range = '24h';
  const wrap = h('div', { class: 'stack', style: { marginBottom: '16px' } });
  const rangeSeg = segmented([['24h', '24 H'], ['7d', '7 D']], range, v => { range = v; load(); });
  async function load() {
    try {
      const r = await api(`api/devices/presence?range=${range}`);
      clear(wrap).append(newCard(r, load), lanesCard(r, rangeSeg));
    } catch (e) {
      clear(wrap).append(h('div', { class: 'card' }, h('div', { class: 'empty' }, `Not available - ${e.message}`)));
    }
  }
  load();
  return wrap;
}
