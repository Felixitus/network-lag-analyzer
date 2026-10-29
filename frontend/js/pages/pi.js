// Raspberry Pi: its own health, its network port, and where losses in the home network lie.
import { ago, api, clear, fmtBytes, fmtDateTime, fmtDuration, h, SERIES, toast } from '../lib.js';
import { chartCard } from '../charts.js';
import { segmented, updateCommand } from './common.js';

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

/** Installed version, the last update check and the command to update. */
const pct = (part, total) => (total ? `${Math.round((100 * part) / total)} %` : null);

/** The packet capture: how hard it works, where its ring lives, how often a server name is readable. */
function captureCard(d, range) {
  const c = d.capture;
  const card = h('div', { class: 'card stack', style: { marginTop: '16px' } },
    h('div', { class: 'card-head' }, h('h2', null, 'Packet capture'),
      c && c.ts ? h('span', { class: 'sub' }, `As of ${fmtDateTime(c.ts)}`) : null));
  if (!c) {
    card.append(h('div', { class: 'empty' }, 'Not available - the capture is not running (no FRITZ!Box access or capture off).'));
    return card;
  }
  const ring = c.ring;
  const ringText = !c.buffer ? 'off' : c.buffer === 'memory'
    // MiB like the setting (memory_mb), not the 1000s of fmtBytes: "64 MB" should read 64
    ? (ring ? `in RAM, ${Math.round(ring.memory_bytes / 1048576)} of ${Math.round(ring.memory_limit / 1048576)} MB` : 'in RAM')
    : 'on the SD card';
  const busy = c.busy_pct === null || c.busy_pct === undefined ? null : `${c.busy_pct.toFixed(0)} %`;
  const sni = c.sni || {};
  const n = d.names || {};
  const share = x => (x && x.flows ? `${pct(x.named, x.flows)}` : null);
  const sub = x => (x && x.flows ? `${x.named} of ${x.flows} connections` : null);
  card.append(h('div', { class: 'grid grid-2' },
    h('ul', { class: 'list' },
      row('Data from the FRITZ!Box', c.stream_kbps === null || c.stream_kbps === undefined ? null : `${(c.stream_kbps / 8).toFixed(0)} KB/s`,
        c.pps ? `${c.pps.toFixed(0)} packets/s` : null),
      row('Time spent parsing', busy, 'the rest is waiting for the stream'),
      row('Delay of the stream', c.lag_s === null || c.lag_s === undefined ? null : `${c.lag_s.toFixed(1)} s`,
        'the FRITZ!Box sends in bursts'),
      row('Load guard', `level ${c.guard_level}`, c.guard_level ? 'throttling the analysis' : 'full analysis'),
      row('Running PCAP ring', ringText)),
    h('ul', { class: 'list' },
      row(`Server names, TCP (${range})`, share(n.tcp), sub(n.tcp)),
      row(`Server names, QUIC (${range})`, share(n.quic), sub(n.quic)),
      row('QUIC hellos cut off', sni.quic ? pct(sni.quic_truncated, sni.quic) : null,
        sni.quic ? `${sni.quic_truncated} of ${sni.quic} since the capture started` : null),
      row('QUIC joined mid-connection', sni.quic_midway ?? null, 'started before the capture'),
      row('QUIC of another version', sni.quic_unreadable ?? null, "e.g. Google's own gQUIC"))));
  if (sni.quic && sni.quic_truncated / sni.quic > 0.25) {
    card.append(h('div', { class: 'small muted' }, 'Many QUIC hellos are cut off: browsers now send them over two packets of '
      + '1200+ bytes, and the capture keeps the first fritzbox.snaplen bytes of each. A larger snaplen reads more names '
      + 'but brings more data from the FRITZ!Box.'));
  }
  return card;
}

function softwareCard(store, refreshStatus) {
  const card = h('div', { class: 'card stack', style: { marginTop: '16px' } });
  const check = h('button', { class: 'btn', type: 'button' }, 'Check for updates now');
  check.addEventListener('click', async () => {
    check.disabled = true;
    try { await api('api/update/check', { method: 'POST', body: {} }); await refreshStatus(); render(); }
    catch (e) { toast(`Check failed: ${e.message}`, 5000); }
    check.disabled = false;
  });
  function render() {
    const s = store.status || {};
    const u = s.update;
    const state = !u ? (s.update_check ? 'not checked yet' : 'automatic check switched off')
      : u.error ? `GitHub not reachable (${u.error})`
        : u.newer ? `version ${u.latest} is available` : `up to date (latest release ${u.latest})`;
    // DOM append() would print a null as the text "null"
    clear(card).append(...[
      h('div', { class: 'card-head' }, h('h2', null, 'Software'),
        h('span', { class: `badge ${u && u.newer ? 'warning' : u && !u.error ? 'good' : ''}` }, u && u.newer ? 'update available' : `v${s.version}`)),
      h('ul', { class: 'list' },
        row('Installed version', s.version),
        row('Update check', state, u ? `checked ${ago(u.checked)}` : (s.update_check ? 'once a day' : null))),
      u && u.newer ? h('div', { class: 'stack-sm' },
        h('div', { class: 'small' }, 'Run this on the Pi (over SSH). Settings and data are kept, the service restarts by itself. ',
          u.url ? h('a', { href: u.url, target: '_blank', rel: 'noopener noreferrer' }, 'What is new →') : null),
        updateCommand(s)) : null,
      h('div', { class: 'row' }, check, h('span', { class: 'small muted' },
        'Asks GitHub for the latest release - nothing about this installation is sent. Nothing is installed automatically.')),
    ].filter(Boolean));
  }
  render();
  return card;
}

export async function mount(main, { store, refreshStatus }) {
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
  const capture = h('div');
  main.append(
    h('div', { class: 'page-head' }, h('div', null, h('h1', null, 'Raspberry Pi'),
      h('p', null, 'The measuring device itself - if it is unwell, every other number is in doubt.')),
    segmented([['24h', '24 H'], ['7d', '7 D']], range, v => { range = v; load(); })),
    top,
    capture,
    softwareCard(store, refreshStatus),
    h('div', { class: 'grid grid-2', style: { marginTop: '16px' } }, temp.card, port.card),
    h('div', { class: 'grid grid-2', style: { marginTop: '16px' } }, cpu.card, mem.card), note);
  const ch = [temp.mount(), port.mount(), cpu.mount(), mem.mount()];

  async function load() {
    const d = await api(`api/pi?range=${range}`);
    clear(top).append(healthCard(d), linkCard(d));
    clear(capture).append(captureCard(d, range));
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
