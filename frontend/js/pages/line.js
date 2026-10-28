// Internet line: DSL values and errors from the FRITZ!Box, its event log, and outages measured by the Pi.
import { api, clear, fmtDate, fmtDuration, fmtTime, h, SERIES, toast } from '../lib.js';
import { chartCard, fmt } from '../charts.js';
import { naBox, pathView, segmented } from './common.js';

let timer = null;
export function unmount() { clearInterval(timer); }

const kbit = v => (v === null || v === undefined ? null : v * 1000);
const dt = ts => `${fmtDate(ts)} ${fmtTime(ts, false)}`;
const dbFmt = v => `${v.toFixed(1)} dB`;

function valueRow(label, value, sub) {
  return h('li', { class: 'row' }, h('span', { class: 'secondary' }, label), h('span', { class: 'spacer' }),
    h('b', null, value ?? 'Not available'), sub ? h('span', { class: 'small muted', style: { marginLeft: '6px' } }, sub) : null);
}

function currentCard(st) {
  const box = h('div', { class: 'card stack' }, h('div', { class: 'card-head' }, h('h2', null, 'Line right now'),
    st.ts ? h('span', { class: 'sub' }, `As of ${fmtTime(st.ts)}`) : null));
  if (!st.enabled) {
    box.append(h('div', { class: 'empty' }, 'Not available - no FRITZ!Box access configured (Setup).'));
    return box;
  }
  if (st.ok === null || st.ok === undefined) { box.append(h('div', { class: 'empty' }, 'Waiting for the first values…')); return box; }
  const d = st.dsl, w = st.wan;
  const ul = h('ul', { class: 'list' });
  if (w) {
    ul.append(valueRow('Internet connection', w.status || null, w.uptime_s !== null && w.uptime_s !== undefined
      ? `since ${fmtDuration(w.uptime_s)}` : null));
  }
  if (d) {
    const rate = (cur, max) => (cur === null ? null : `${(cur / 1000).toFixed(1)} Mbit/s`) + (max ? ` of ${(max / 1000).toFixed(1)} possible` : '');
    ul.append(valueRow('DSL', d.status),
      valueRow('Sync download', rate(d.down_kbit, d.down_max_kbit)),
      valueRow('Sync upload', rate(d.up_kbit, d.up_max_kbit)),
      valueRow('Noise margin ↓ / ↑', d.down_snr_db === null ? null : `${d.down_snr_db.toFixed(1)} / ${d.up_snr_db?.toFixed(1) ?? '–'} dB`),
      valueRow('Attenuation ↓ / ↑', d.down_atten_db === null ? null : `${d.down_atten_db.toFixed(1)} / ${d.up_atten_db?.toFixed(1) ?? '–'} dB`),
      valueRow('Errors since sync', d.crc === null ? null : `${d.crc} CRC · ${d.errored_secs ?? '–'} errored s · ${d.severe_secs ?? '–'} severely errored s`),
      valueRow('Resyncs (counter)', d.retrains));
  } else if (st.has_dsl === false) {
    ul.append(h('li', { class: 'small muted' }, 'This FRITZ!Box reports no DSL values (cable, fibre or mobile access).'));
  }
  box.append(ul);
  for (const n of st.notes || []) box.append(h('div', { class: `badge ${st.level === 'critical' ? 'critical' : 'warning'}` }, n));
  if (st.error) box.append(h('div', { class: 'small muted' }, `Partly not available: ${st.error}`));
  return box;
}

function outagesCard(d, range) {
  const card = h('div', { class: 'card stack' },
    h('div', { class: 'card-head' }, h('div', null, h('h2', null, 'Outages'),
      h('div', { class: 'sub' }, `${d.outages.length} outages, ${d.outage_minutes} min in total`)),
    h('a', { class: 'btn', href: `api/line/outages.csv?days=${range === '24h' ? 1 : range === '7d' ? 7 : 30}`, download: '' }, 'Outage report (CSV)')));
  if (!d.outages.length) { card.append(h('div', { class: 'empty' }, 'No outage in this time span.')); return card; }
  card.append(h('ul', { class: 'list' }, ...d.outages.slice().reverse().map(o => h('li', null,
    h('div', { class: 'row' }, h('b', null, `${dt(o.start)} – ${fmtTime(o.end, false)}`), h('span', { class: 'spacer' }),
      h('span', { class: 'badge critical' }, `${o.minutes} min`)),
    o.events.length ? h('div', { class: 'small secondary' }, 'FRITZ!Box: ', o.events.map(e => `${fmtTime(e.ts, false)} ${e.label}`).join(' · '))
      : h('div', { class: 'small muted' }, 'No matching FRITZ!Box event - the line itself stayed up, the cause lies elsewhere.')))));
  return card;
}

function eventsCard(d, showAll, onToggle) {
  const toggle = h('label', { class: 'row small' }, h('input', { type: 'checkbox', checked: showAll || null, onchange: e => onToggle(e.target.checked) }),
    'all entries');
  const card = h('div', { class: 'card stack' }, h('div', { class: 'card-head' }, h('h2', null, 'FRITZ!Box events'), toggle));
  if (!d.events.length) { card.append(h('div', { class: 'empty' }, 'No events in this time span.')); return card; }
  card.append(h('ul', { class: 'list' }, ...d.events.slice(0, 60).map(e => h('li', null,
    h('div', { class: 'row' }, h('b', null, e.label), h('span', { class: 'spacer' }), h('span', { class: 'small muted' }, dt(e.ts))),
    h('div', { class: 'small secondary' }, e.msg)))));
  return card;
}

function pathCard() {
  const list = h('div', { class: 'stack' }, h('div', { class: 'skeleton' }, 'Loading…'));
  const select = h('select', { 'aria-label': 'Target' });
  const btn = h('button', { class: 'btn', type: 'button' }, 'Measure path now');
  const card = h('div', { class: 'card stack', style: { marginTop: '16px' } },
    h('div', { class: 'card-head' }, h('div', null, h('h2', null, 'Path to the targets'),
      h('div', { class: 'sub' }, 'Traceroute: from which hop on are packets lost? Measured automatically when an incident starts.')),
    h('div', { class: 'row' }, select, btn)), list);
  const show = r => {
    clear(list);
    if (!r.traceroutes.length) list.append(naBox(r.enabled ? 'No path measured yet - it runs with the next incident, or start one here.'
      : 'Automatic path measurement is switched off in the settings.'));
    r.traceroutes.slice(0, 3).forEach(t => list.append(pathView(t)));
  };
  const load = () => api('api/traceroutes?limit=3').then(r => {
    if (!select.options.length) r.targets.forEach(t => select.append(h('option', { value: t.target_id }, t.name)));
    btn.disabled = !r.targets.length;
    show(r);
  }).catch(e => { clear(list).append(naBox(`Not available - ${e.message}`)); });
  btn.onclick = async () => {
    btn.disabled = true; btn.textContent = 'Measuring… (about 15 s)';
    try { await api('api/traceroutes', { method: 'POST', body: { target_id: Number(select.value) } }); await load(); }
    catch (e) { toast(e.message, 5000); }
    finally { btn.disabled = false; btn.textContent = 'Measure path now'; }
  };
  load();
  return card;
}

export async function mount(main) {
  let range = '24h', showAll = false;
  const top = h('div', { class: 'grid grid-2' });
  const rate = chartCard('Sync rate', [
    { label: 'Download', color: SERIES(1), fmt: fmt.mbit }, { label: 'Download possible', color: SERIES(1), width: 1, dash: [4, 4], fmt: fmt.mbit },
    { label: 'Upload', color: SERIES(2), fmt: fmt.mbit }, { label: 'Upload possible', color: SERIES(2), width: 1, dash: [4, 4], fmt: fmt.mbit },
  ], { yFmt: fmt.mbitAxis, yLabel: 'Mbit/s', height: 170, naText: 'Not available - no DSL values' });
  const snr = chartCard('Noise margin', [
    { label: 'Download', color: SERIES(1), fmt: dbFmt }, { label: 'Upload', color: SERIES(2), fmt: dbFmt },
  ], { yFmt: v => `${v}`, yLabel: 'dB', height: 170, naText: 'Not available - no DSL values' });
  const errs = chartCard('Line errors per 5 minutes', [
    { label: 'CRC errors', color: SERIES(8), fmt: v => `${v}`, bars: true, fill: 0.85 },
    { label: 'Errored seconds', color: SERIES(4), fmt: v => `${v} s` },
  ], { yFmt: v => `${v}`, height: 150, naText: 'Not available - no error counters' });
  const bottom = h('div', { class: 'grid grid-2', style: { marginTop: '16px' } });
  const note = h('p', { class: 'small muted' });
  main.append(
    h('div', { class: 'page-head' }, h('div', null, h('h1', null, 'Internet line'),
      h('p', null, 'Is the line the problem, or the home network? Line values from the FRITZ!Box, outages from the Pi\'s own pings.')),
    segmented([['24h', '24 H'], ['7d', '7 D'], ['30d', '30 D']], range, v => { range = v; load(); })),
    top,
    h('div', { class: 'grid grid-2', style: { marginTop: '16px' } }, rate.card, snr.card),
    h('div', { style: { marginTop: '16px' } }, errs.card),
    bottom, pathCard(), note);
  const ch = [rate.mount(), snr.mount(), errs.mount()];

  async function load() {
    const d = await api(`api/line?range=${range}${showAll ? '&all_events=true' : ''}`);
    clear(top).append(currentCard(d.status), outagesCard(d, range));
    clear(bottom).append(eventsCard(d, showAll, v => { showAll = v; load(); }));
    const s = d.series;
    ch[0].setData([s.ts, s.down_kbit.map(kbit), s.down_max_kbit.map(kbit), s.up_kbit.map(kbit), s.up_max_kbit.map(kbit)]);
    ch[1].setData([s.ts, s.down_snr_db, s.up_snr_db]);
    ch[2].setData([s.ts, s.crc, s.errored_secs]);
    note.textContent = d.note;
  }
  await load();
  timer = setInterval(() => load().catch(() => null), 60000);
}
