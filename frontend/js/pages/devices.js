// Devices: list, renaming, marking the gaming PC, DNS activity, historical top talkers.
import { api, clear, deviceColor, fmtBytes, fmtMbit, h, ago, toast } from '../lib.js';
import { segmented } from './common.js';
import { presenceSection } from './presence.js';

export async function mount(main) {
  main.append(h('div', { class: 'page-head' }, h('div', null, h('h1', null, 'Devices'),
    h('p', null, 'Detected automatically via the FRITZ!Box host list, Pi-hole, ARP and the traffic capture. Names can be chosen freely.')),
  h('span', { class: 'spacer' }), refreshNamesButton(() => loadList())));
  const listCard = h('div', { class: 'card' });
  const histCard = h('div', { class: 'card' });
  const dnsCard = h('div', { class: 'card', style: { display: 'none' } });
  main.append(presenceSection(), listCard, h('div', { style: { height: '16px' } }), dnsCard, h('div', { class: 'grid', style: { marginTop: '16px' } }, histCard));

  async function loadList() {
    const r = await api('api/devices');
    clear(listCard);
    listCard.append(h('div', { class: 'card-head' }, h('h2', null, `${r.devices.length} devices`),
      h('span', { class: 'sub' }, r.traffic_available ? 'Rates: avg of the last 10 s' : 'Traffic per device: Not available')));
    if (!r.devices.length) { listCard.append(h('div', { class: 'empty' }, 'No devices detected yet.')); return; }
    const tbody = h('tbody');
    for (const d of r.devices) {
      const nameInput = h('input', { type: 'text', value: d.custom_name || '', placeholder: d.hostname || d.name, maxlength: '64',
        'aria-label': `Name for ${d.mac}`, style: { width: '100%' } });
      nameInput.addEventListener('change', async () => {
        try { await api(`api/devices/${encodeURIComponent(d.mac)}`, { method: 'PATCH', body: { custom_name: nameInput.value } }); toast('Name saved'); }
        catch (e) { toast(e.message); }
      });
      const gp = h('input', { type: 'checkbox', checked: d.gaming_pc, 'aria-label': 'Gaming PC', disabled: !d.ip });
      gp.addEventListener('change', async () => {
        try { await api(`api/devices/${encodeURIComponent(d.mac)}`, { method: 'PATCH', body: { gaming_pc: gp.checked } }); toast(gp.checked ? 'Set as gaming PC' : 'Gaming PC removed'); loadList(); }
        catch (e) { toast(e.message); gp.checked = !gp.checked; }
      });
      const dnsBtn = h('button', { class: 'btn', type: 'button', disabled: !d.ip }, 'DNS');
      dnsBtn.addEventListener('click', () => showDns(d));
      tbody.append(h('tr', null,
        h('td', null, h('span', { class: `dot ${d.active ? 'good' : 'muted'}`, title: d.active ? 'Online' : 'Offline' })),
        h('td', { style: { minWidth: '180px' } }, nameInput, h('div', { class: 'small muted' }, d.hostname && d.custom_name ? `Hostname: ${d.hostname}` : '')),
        h('td', { class: 'mono' }, d.ip || '–'),
        h('td', { class: 'mono' }, d.mac),
        h('td', { class: 'small' }, d.vendor || '–', d.interface ? h('div', { class: 'muted' }, d.interface) : null),
        h('td', { class: 'num' }, d.down_bps == null ? 'n/a' : fmtMbit(d.down_bps)),
        h('td', { class: 'num' }, d.up_bps == null ? 'n/a' : fmtMbit(d.up_bps)),
        h('td', { class: 'small muted' }, d.active ? 'Online' : ago(d.last_seen), h('div', null, d.sources.join(', '))),
        h('td', null, h('label', { class: 'check small' }, gp, 'Gaming PC')),
        h('td', null, dnsBtn)));
    }
    listCard.append(h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' },
      h('thead', null, h('tr', null, h('th', null, ''), h('th', null, 'Name'), h('th', null, 'IP'), h('th', null, 'MAC'), h('th', null, 'Vendor'),
        h('th', { class: 'num' }, '↓ Mbit/s'), h('th', { class: 'num' }, '↑ Mbit/s'), h('th', null, 'Status / sources'), h('th', null, ''), h('th', null, ''))),
      tbody)));
  }

  async function showDns(d) {
    dnsCard.style.display = '';
    clear(dnsCard).append(h('div', { class: 'skeleton' }, 'Loading DNS activity…'));
    try {
      const r = await api(`api/devices/${encodeURIComponent(d.mac)}/dns?minutes=60`);
      clear(dnsCard);
      dnsCard.append(h('div', { class: 'card-head' }, h('h2', null, `DNS activity: ${d.name}`),
        h('button', { class: 'btn', onclick: () => { dnsCard.style.display = 'none'; } }, 'Close')),
      h('p', { class: 'small muted' }, `${r.note} Source: Pi-hole (delayed by up to ~60 s).`));
      if (!r.available) { dnsCard.append(h('div', { class: 'empty' }, 'Not available - Pi-hole database not readable.')); return; }
      const total = r.minutes.reduce((a, x) => a + x.queries, 0), blocked = r.minutes.reduce((a, x) => a + x.blocked, 0);
      dnsCard.append(h('div', { class: 'row' }, h('b', null, `${total} queries`), h('span', { class: 'muted' }, `in 60 min, ${blocked} blocked`)),
        h('ul', { class: 'list' }, r.top_domains.map(([dom, n]) => h('li', { class: 'row' }, h('span', { class: 'mono' }, dom), h('span', { class: 'spacer' }), h('span', { class: 'num' }, n)))));
    } catch (e) { clear(dnsCard).append(h('div', { class: 'empty' }, e.message)); }
  }

  // ---------------------------------------------------------------- historical top talkers
  let hr = 3600;
  const histBody = h('div');
  histCard.append(h('div', { class: 'card-head' }, h('h2', null, 'Top talkers (historical)'),
    segmented([[600, '10 min'], [3600, '1 h'], [21600, '6 h'], [86400, '24 h'], [604800, '7 days']], hr, v => { hr = v; loadHist(); })), histBody);
  async function loadHist() {
    const end = Math.floor(Date.now() / 1000);
    const r = await api(`api/top-talkers?start=${end - hr}&end=${end}&n=15`);
    clear(histBody);
    if (!r.devices.length) { histBody.append(h('div', { class: 'empty' }, r.reason ? `Not available - ${r.reason}` : 'No data in this time span.')); return; }
    const max = Math.max(...r.devices.map(d => d.bytes), 1);
    histBody.append(h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' },
      h('thead', null, h('tr', null, h('th', null, 'Device'), h('th', null, 'Data volume'), h('th', { class: 'num' }, 'avg ↓'), h('th', { class: 'num' }, 'avg ↑'),
        h('th', { class: 'num' }, 'peak ↓'), h('th', { class: 'num' }, 'peak ↑'))),
      h('tbody', null, r.devices.map(d => h('tr', null,
        h('td', null, h('span', { class: 'dot', style: { background: deviceColor(d.mac), marginRight: '8px' } }), d.name, h('div', { class: 'small mono muted' }, d.ip || d.mac)),
        h('td', { style: { minWidth: '160px' } }, h('div', { class: 'bar-track', style: { height: '8px' } }, h('div', { class: 'bar-fill', style: { width: `${100 * d.bytes / max}%`, background: deviceColor(d.mac) } })),
          h('div', { class: 'small muted' }, fmtBytes(d.bytes))),
        h('td', { class: 'num' }, `${fmtMbit(d.down_bps)}`), h('td', { class: 'num' }, `${fmtMbit(d.up_bps)}`),
        h('td', { class: 'num' }, `${fmtMbit(d.down_peak_bps)}`), h('td', { class: 'num' }, `${fmtMbit(d.up_peak_bps)}`))))),
    h('div', { class: 'small muted' }, 'Rates in Mbit/s.')));
  }
  await Promise.all([loadList(), loadHist()]);
}

/** Re-read host names and IPs from all sources. Shared with the DNS page. */
export function refreshNamesButton(after) {
  const btn = h('button', { class: 'btn', type: 'button', title: 'Forget learned host names and IPs and ask Pi-hole (incl. DHCP leases) and the FRITZ!Box again. Your own names stay.' }, 'Refresh host names');
  btn.addEventListener('click', async () => {
    btn.disabled = true;
    btn.textContent = 'Refreshing…';
    try {
      const r = await api('api/devices/refresh-names', { method: 'POST', body: {} });
      const n = r.changed.length;
      toast(n ? n + ' device(s) changed (sources: ' + r.sources.join(', ') + ')' : 'All host names were already current', 5000);
      if (after) await after(r);
    } catch (e) { toast(e.message, 5000); }
    btn.disabled = false;
    btn.textContent = 'Refresh host names';
  });
  return btn;
}
