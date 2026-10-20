// Geräte: Liste, Umbenennen, Gaming-PC markieren, DNS-Aktivität, historische Top Talker.
import { api, clear, deviceColor, fmtBytes, fmtMbit, h, ago, toast } from '../lib.js';
import { segmented } from './common.js';

export async function mount(main) {
  main.append(h('div', { class: 'page-head' }, h('div', null, h('h1', null, 'Geräte'),
    h('p', null, 'Automatisch erkannt über FRITZ!Box-Hostliste, Pi-hole, ARP und Traffic-Mitschnitt. Namen sind frei vergebbar.'))));
  const listCard = h('div', { class: 'card' });
  const histCard = h('div', { class: 'card' });
  const dnsCard = h('div', { class: 'card', style: { display: 'none' } });
  main.append(listCard, h('div', { style: { height: '16px' } }), dnsCard, h('div', { class: 'grid', style: { marginTop: '16px' } }, histCard));

  async function loadList() {
    const r = await api('api/devices');
    clear(listCard);
    listCard.append(h('div', { class: 'card-head' }, h('h2', null, `${r.devices.length} Geräte`),
      h('span', { class: 'sub' }, r.traffic_available ? 'Raten: Ø der letzten 10 s' : 'Traffic pro Gerät: Not available')));
    if (!r.devices.length) { listCard.append(h('div', { class: 'empty' }, 'Noch keine Geräte erkannt.')); return; }
    const tbody = h('tbody');
    for (const d of r.devices) {
      const nameInput = h('input', { type: 'text', value: d.custom_name || '', placeholder: d.hostname || d.name, maxlength: '64',
        'aria-label': `Name für ${d.mac}`, style: { width: '100%' } });
      nameInput.addEventListener('change', async () => {
        try { await api(`api/devices/${encodeURIComponent(d.mac)}`, { method: 'PATCH', body: { custom_name: nameInput.value } }); toast('Name gespeichert'); }
        catch (e) { toast(e.message); }
      });
      const gp = h('input', { type: 'checkbox', checked: d.gaming_pc, 'aria-label': 'Gaming-PC', disabled: !d.ip });
      gp.addEventListener('change', async () => {
        try { await api(`api/devices/${encodeURIComponent(d.mac)}`, { method: 'PATCH', body: { gaming_pc: gp.checked } }); toast(gp.checked ? 'Als Gaming-PC gesetzt' : 'Gaming-PC entfernt'); loadList(); }
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
        h('td', null, h('label', { class: 'check small' }, gp, 'Gaming-PC')),
        h('td', null, dnsBtn)));
    }
    listCard.append(h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' },
      h('thead', null, h('tr', null, h('th', null, ''), h('th', null, 'Name'), h('th', null, 'IP'), h('th', null, 'MAC'), h('th', null, 'Hersteller'),
        h('th', { class: 'num' }, '↓ Mbit/s'), h('th', { class: 'num' }, '↑ Mbit/s'), h('th', null, 'Status / Quellen'), h('th', null, ''), h('th', null, ''))),
      tbody)));
  }

  async function showDns(d) {
    dnsCard.style.display = '';
    clear(dnsCard).append(h('div', { class: 'skeleton' }, 'Lade DNS-Aktivität…'));
    try {
      const r = await api(`api/devices/${encodeURIComponent(d.mac)}/dns?minutes=60`);
      clear(dnsCard);
      dnsCard.append(h('div', { class: 'card-head' }, h('h2', null, `DNS-Aktivität: ${d.name}`),
        h('button', { class: 'btn', onclick: () => { dnsCard.style.display = 'none'; } }, 'Schließen')),
      h('p', { class: 'small muted' }, `${r.note} Quelle: Pi-hole (bis ~60 s verzögert).`));
      if (!r.available) { dnsCard.append(h('div', { class: 'empty' }, 'Not available – Pi-hole-Datenbank nicht lesbar.')); return; }
      const total = r.minutes.reduce((a, x) => a + x.queries, 0), blocked = r.minutes.reduce((a, x) => a + x.blocked, 0);
      dnsCard.append(h('div', { class: 'row' }, h('b', null, `${total} Anfragen`), h('span', { class: 'muted' }, `in 60 min, ${blocked} blockiert`)),
        h('ul', { class: 'list' }, r.top_domains.map(([dom, n]) => h('li', { class: 'row' }, h('span', { class: 'mono' }, dom), h('span', { class: 'spacer' }), h('span', { class: 'num' }, n)))));
    } catch (e) { clear(dnsCard).append(h('div', { class: 'empty' }, e.message)); }
  }

  // ---------------------------------------------------------------- Historische Top Talker
  let hr = 3600;
  const histBody = h('div');
  histCard.append(h('div', { class: 'card-head' }, h('h2', null, 'Top Talker (historisch)'),
    segmented([[600, '10 min'], [3600, '1 h'], [21600, '6 h'], [86400, '24 h'], [604800, '7 Tage']], hr, v => { hr = v; loadHist(); })), histBody);
  async function loadHist() {
    const end = Math.floor(Date.now() / 1000);
    const r = await api(`api/top-talkers?start=${end - hr}&end=${end}&n=15`);
    clear(histBody);
    if (!r.devices.length) { histBody.append(h('div', { class: 'empty' }, r.reason ? `Not available – ${r.reason}` : 'Keine Daten im Zeitraum.')); return; }
    const max = Math.max(...r.devices.map(d => d.bytes), 1);
    histBody.append(h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' },
      h('thead', null, h('tr', null, h('th', null, 'Gerät'), h('th', null, 'Datenmenge'), h('th', { class: 'num' }, 'Ø ↓'), h('th', { class: 'num' }, 'Ø ↑'),
        h('th', { class: 'num' }, 'Spitze ↓'), h('th', { class: 'num' }, 'Spitze ↑'))),
      h('tbody', null, r.devices.map(d => h('tr', null,
        h('td', null, h('span', { class: 'dot', style: { background: deviceColor(d.mac), marginRight: '8px' } }), d.name, h('div', { class: 'small mono muted' }, d.ip || d.mac)),
        h('td', { style: { minWidth: '160px' } }, h('div', { class: 'bar-track', style: { height: '8px' } }, h('div', { class: 'bar-fill', style: { width: `${100 * d.bytes / max}%`, background: deviceColor(d.mac) } })),
          h('div', { class: 'small muted' }, fmtBytes(d.bytes))),
        h('td', { class: 'num' }, `${fmtMbit(d.down_bps)}`), h('td', { class: 'num' }, `${fmtMbit(d.up_bps)}`),
        h('td', { class: 'num' }, `${fmtMbit(d.down_peak_bps)}`), h('td', { class: 'num' }, `${fmtMbit(d.up_peak_bps)}`))))),
    h('div', { class: 'small muted' }, 'Raten in Mbit/s.')));
  }
  await Promise.all([loadList(), loadHist()]);
}
