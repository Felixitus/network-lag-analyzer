// Raspberry Pi: its own health, its network port, and where losses in the home network lie.
import { api, clear, fmtBytes, fmtDateTime, fmtDuration, h, SERIES } from '../lib.js';
import { chartCard } from '../charts.js';
import { segmented } from './common.js';

let timer = null;
export function unmount() { clearInterval(timer); }

const NA = 'Not available';
const row = (label, value, sub) => h('li', { class: 'row' }, h('span', { class: 'secondary' }, label), h('span', { class: 'spacer' }),
  h('b', null, value ?? NA), sub ? h('span', { class: 'small muted', style: { marginLeft: '6px' } }, sub) : null);
const gb = mb => (mb === null || mb === undefined ? null : `${(mb / 1024).toFixed(1)} GB`);

function healthCard(d) {
  const x = d.health || {};
  const card = h('div', { class: 'card stack' }, h('div', { class: 'card-head' }, h('h2', null, 'Health'),
    x.ts ? h('span', { class: 'sub' }, `As of ${fmtDateTime(x.ts)}`) : null));
  if (!x.ts) { card.append(h('div', { class: 'empty' }, 'Waiting for the first values (once a minute)…')); return card; }
  const lvl = x.level === 'critical' ? 'critical' : x.level === 'warning' ? 'warning' : 'good';
  card.append(h('div', { class: `badge ${lvl}` }, x.level === 'good' ? 'Everything OK' : `${x.notes.length} finding(s)`));
  for (const n of x.notes || []) card.append(h('div', { class: 'small' }, `• ${n}`));
  card.append(h('ul', { class: 'list' },
    row('Temperature', x.temp_c === null ? null : `${x.temp_c.toFixed(1)} °C`),
    row('Power supply', x.undervoltage === null ? null : x.undervoltage ? 'Under-voltage!' : 'OK', x.undervoltage === null ? null : 'firmware alarm'),
    row('CPU', x.cpu_pct === null || x.cpu_pct === undefined ? null : `${x.cpu_pct.toFixed(0)} %`, x.load1 !== null && x.load1 !== undefined ? `load ${x.load1.toFixed(2)} / ${x.cpu_count} cores` : null),
    row('Memory available', x.mem_available_mb === null ? null : `${x.mem_available_mb} MB`, x.mem_total_mb ? `of ${x.mem_total_mb} MB` : null),
    row('Swap in use', x.swap_used_mb === null ? null : `${x.swap_used_mb} MB`),
    row('Free storage', gb(x.disk_free_mb), x.disk_total_mb ? `of ${gb(x.disk_total_mb)}` : null),
    row('Written to the SD card', x.sd_written_bytes === null ? null : fmtBytes(x.sd_written_bytes), 'since boot'),
    row('Pi-hole service', x.pihole_active === null ? null : x.pihole_active ? 'running' : 'NOT running'),
    row('Pi running for', x.boot_ts ? fmtDuration(x.ts - x.boot_ts) : null),
    row('Service running for', fmtDuration(d.service.uptime_s), `version ${d.service.version}`)));
  return card;
}

function linkCard(d) {
  const lk = (d.health || {}).link;
  const rec = (d.health || {}).recent || {};
  const card = h('div', { class: 'card stack' }, h('div', { class: 'card-head' }, h('h2', null, 'Network port and path'),
    h('a', { class: 'small', href: '#/settings' }, 'LAN reference →')));
  const ul = h('ul', { class: 'list' });
  if (lk) {
    ul.append(row('Port', lk.iface),
      row('Link', lk.carrier === null ? null : lk.carrier ? 'up' : 'DOWN', lk.speed_mbit > 0 ? `${lk.speed_mbit} Mbit/s ${lk.duplex || ''}` : null),
      row('Link drops', lk.carrier_changes, `since boot · last hour: ${rec.carrier_changes || 0}`),
      row('Receive errors', lk.rx_errors, `since boot · last hour: ${rec.rx_errors || 0}`),
      row('Send errors', lk.tx_errors, 'since boot'));
  } else ul.append(h('li', { class: 'small muted' }, 'Port counters not available on this system.'));
  for (const t of d.link_targets) {
    ul.append(row(t.kind === 'gateway' ? `Router ${t.address}` : `LAN reference ${t.address}`,
      t.probes ? `${(t.loss_pct ?? 0).toFixed(1)} % loss` : null, t.rtt_avg !== null ? `${t.rtt_avg.toFixed(1)} ms · ${t.window_seconds} s` : null));
  }
  card.append(ul);
  const v = d.verdict;
  if (v && v.text) card.append(h('div', { class: `badge ${v.where === 'pi_link' ? 'critical' : 'warning'}` }, v.text));
  else if (v && v.where === 'ok') card.append(h('div', { class: 'small muted' }, 'No packet loss inside the home network right now.'));
  if (!d.lan_reference) {
    card.append(h('div', { class: 'small muted' }, 'Tip: set a second always-on device (access point, switch, NAS) as LAN reference in Setup. '
      + 'If router and reference lose packets at the same time, the problem is the Pi\'s own cable or port.'));
  }
  return card;
}

export async function mount(main) {
  let range = '24h';
  const top = h('div', { class: 'grid grid-2' });
  const temp = chartCard('Temperature', [{ label: 'CPU', color: SERIES(2), fmt: v => `${v.toFixed(1)} °C` }],
    { yFmt: v => `${v}`, yLabel: '°C', height: 150, naText: 'Not available on this system' });
  const cpu = chartCard('CPU and memory', [
    { label: 'CPU', color: SERIES(1), fmt: v => `${v.toFixed(0)} %` },
  ], { yFmt: v => `${v}`, yLabel: '%', height: 150 });
  const mem = chartCard('Memory available', [{ label: 'Available', color: SERIES(3), fmt: v => `${v} MB` }],
    { yFmt: v => `${v}`, yLabel: 'MB', height: 150 });
  const port = chartCard('Network port: drops and errors per minute', [
    { label: 'Link drops', color: SERIES(8), fmt: v => `${v}`, bars: true, fill: 0.85 },
    { label: 'Receive errors', color: SERIES(4), fmt: v => `${v}`, bars: true, fill: 0.6 },
  ], { yFmt: v => `${v}`, height: 150, naText: 'Not available on this system' });
  const note = h('p', { class: 'small muted' });
  main.append(
    h('div', { class: 'page-head' }, h('div', null, h('h1', null, 'Raspberry Pi'),
      h('p', null, 'The measuring device itself - if it is unwell, every other number is in doubt.')),
    segmented([['24h', '24 H'], ['7d', '7 D']], range, v => { range = v; load(); })),
    top,
    h('div', { class: 'grid grid-2', style: { marginTop: '16px' } }, temp.card, port.card),
    h('div', { class: 'grid grid-2', style: { marginTop: '16px' } }, cpu.card, mem.card), note);
  const ch = [temp.mount(), port.mount(), cpu.mount(), mem.mount()];

  async function load() {
    const d = await api(`api/pi?range=${range}`);
    clear(top).append(healthCard(d), linkCard(d));
    const s = d.series;
    ch[0].setData([s.ts, s.temp_c]);
    ch[1].setData([s.ts, s.carrier_changes, s.rx_errors]);
    ch[2].setData([s.ts, s.cpu_pct]);
    ch[3].setData([s.ts, s.mem_avail_mb]);
    note.textContent = d.note;
  }
  await load();
  timer = setInterval(() => load().catch(() => null), 60000);
}
