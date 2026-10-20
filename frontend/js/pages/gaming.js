// Gaming Mode: Session starten/stoppen, Live-Werte des Game-Flows, vergangene Sessions.
import { api, clear, fmtDateTime, fmtDuration, fmtMs, fmtTime, h, SERIES, toast, confBadge } from '../lib.js';
import { chartCard, fmt } from '../charts.js';

let off = null;
export function unmount() { if (off) off(); off = null; }

export async function mount(main, { args, store }) {
  if (args[0]) return sessionDetail(main, parseInt(args[0], 10));
  const settings = await api('api/settings');
  main.append(h('div', { class: 'page-head' }, h('div', null, h('h1', null, 'Gaming Mode'),
    h('p', null, 'Während einer Session: 4 Pings/s, Überwachung des Game-Flows deines Gaming-PCs, Erkennung des Game-Servers.'))));
  const cur = h('div', { class: 'card stack' });
  const list = h('div', { class: 'card' });
  main.append(cur, h('div', { style: { height: '16px' } }), list);
  let chart = null;
  let data = { ts: [], rtt: [], game: [], gap: [] };

  async function renderCurrent() {
    const r = await api('api/gaming/current');
    clear(cur);
    const pcIp = settings.config.gaming_pc.ip;
    if (!r.session) {
      cur.append(h('div', { class: 'row' }, h('h3', null, 'Keine Session aktiv'), h('span', { class: 'spacer' }),
        h('button', { class: 'btn primary', onclick: start }, 'Gaming Session starten')),
      h('p', { class: 'secondary' }, pcIp ? `Gaming-PC: ${pcIp}. ` : 'Kein Gaming-PC festgelegt – unter „Geräte" markieren, damit der Game-Flow erkannt wird. ',
        settings.config.gaming.auto_detect ? 'Automatische Erkennung ist aktiv: Sessions starten von selbst, sobald der Gaming-PC anhaltenden UDP-Traffic zu einem Server hat.' : ''));
      if (r.candidates.length) {
        cur.append(h('div', { class: 'small' }, h('b', null, 'Aktuelle bidirektionale UDP-Flows: '),
          r.candidates.slice(0, 5).map(c => `${c.device} → ${c.remote_ip}:${c.remote_port} (${c.pps_up}/${c.pps_down} pps)`).join(' · ')));
      }
      return;
    }
    const s = r.session;
    cur.append(h('div', { class: 'row' }, h('span', { class: 'dot good' }), h('h3', null, `Gaming Session #${s.id} läuft`),
      h('span', { class: 'muted' }, `seit ${fmtTime(s.ts_start)}${s.auto_detected ? ' · automatisch erkannt' : ''}`), h('span', { class: 'spacer' }),
      h('button', { class: 'btn', onclick: stop }, 'Session beenden')),
    h('div', { class: 'facts' },
      h('div', { class: 'fact' }, h('div', { class: 'k' }, 'Gerät'), h('div', { class: 'v', style: { fontSize: '16px' } }, s.device_ip || 'nicht festgelegt')),
      h('div', { class: 'fact' }, h('div', { class: 'k' }, 'Game-Server'), h('div', { class: 'v', style: { fontSize: '16px' } },
        s.server_ip ? `${s.server_ip}:${s.server_port}` : 'wird erkannt…')),
      h('div', { class: 'fact' }, h('div', { class: 'k' }, 'Ping zum Server'), h('div', { class: 'v', style: { fontSize: '16px' } },
        s.server_icmp === 'blocked' ? 'Not available (Server antwortet nicht auf ICMP)' : s.server_icmp === 'ok' ? 'wird gemessen' : '–'))));
    const c = chartCard('Live: Ping & Game-Flow', [
      { label: 'Internet (Median)', color: SERIES(1), fmt: fmt.ms },
      { label: 'Game-Server Ping', color: SERIES(2), fmt: fmt.ms },
      { label: 'Game-Paketlücke', color: SERIES(7), fmt: fmt.ms, dash: [4, 3] },
    ], { height: 200, yFmt: fmt.msAxis, yLabel: 'ms', yMinMax: 50 });
    cur.append(c.card);
    chart = c.mount();
    const hist = await api('api/history?range=5m');
    const ss = hist.series;
    data = { ts: ss.ts.slice(), rtt: ss.rtt_avg.slice(), game: ss.game_rtt.slice(), gap: ss.game_gap_ms.slice() };
    chart.setData([data.ts, data.rtt, data.game, data.gap]);
    cur.append(h('p', { class: 'small muted' }, 'Game-Paketlücke = längste Zeit ohne Paket vom Server pro Sekunde (bei ~60–128 Tickrate normal: 8–35 ms).'));
  }
  async function start() { await api('api/gaming/start', { method: 'POST', body: {} }); toast('Gaming Session gestartet'); renderCurrent(); }
  async function stop() { const r = await api('api/gaming/stop', { method: 'POST' }); location.hash = `#/gaming/${r.id}`; }

  async function renderList() {
    const r = await api('api/gaming/sessions');
    clear(list).append(h('div', { class: 'card-head' }, h('h2', null, 'Vergangene Sessions')));
    const done = r.sessions.filter(s => s.ts_end);
    if (!done.length) { list.append(h('div', { class: 'empty' }, 'Noch keine abgeschlossenen Sessions.')); return; }
    list.append(h('div', { class: 'grid grid-3' }, done.map(sessionCard)));
  }
  await Promise.all([renderCurrent(), renderList()]);
  let active = !!(store.status && store.status.gaming);
  off = store.on((kind, d) => {
    if (kind === 'gaming') { renderCurrent(); renderList(); }
    if (kind === 'tick') {
      if (!!d.gaming !== active) { active = !!d.gaming; renderCurrent(); }
      if (chart && d.gaming) {
        data.ts.push(d.ts); data.rtt.push(d.m.rtt_avg); data.game.push(d.m.game_rtt); data.gap.push(d.m.game_gap_ms);
        while (data.ts.length > 300) { data.ts.shift(); data.rtt.shift(); data.game.shift(); data.gap.shift(); }
        chart.setData([data.ts, data.rtt, data.game, data.gap]);
      }
    }
  });
}

function sessionCard(s) {
  const m = s.summary || {};
  return h('a', { class: 'card', href: `#/gaming/${s.id}`, style: { color: 'inherit', textDecoration: 'none' } },
    h('div', { class: 'secondary small' }, 'Gaming Session'),
    h('h3', null, `${fmtTime(s.ts_start, false)}–${fmtTime(s.ts_end, false)}`),
    h('div', { class: 'small muted' }, `${fmtDateTime(s.ts_start).slice(0, 10)} · ${fmtDuration(s.ts_end - s.ts_start)}`),
    h('hr', { class: 'sep' }),
    summaryTable(m));
}

function summaryTable(m) {
  const rows = [
    ['Ping Durchschnitt', m.ping_avg != null ? `${fmtMs(m.ping_avg)} ms` : 'Not available'],
    ['Maximum', m.ping_max != null ? `${fmtMs(m.ping_max)} ms` : 'Not available'],
    ['Jitter Durchschnitt', m.jitter_avg != null ? `${m.jitter_avg} ms` : 'Not available'],
    ['Packet-Loss-Events', m.packet_loss_events ?? '–'],
    ['Lag Events', m.lag_events ?? '–'],
  ];
  if (m.game_gap_max != null) rows.push(['Größte Game-Paketlücke', `${Math.round(m.game_gap_max)} ms`]);
  const causes = Object.entries(m.causes || {});
  return h('div', null, h('table', { class: 'tbl small' }, h('tbody', null, rows.map(([k, v]) => h('tr', null, h('td', null, k), h('td', { class: 'num' }, String(v)))))),
    causes.length ? h('div', { style: { marginTop: '8px' } }, h('div', { class: 'small secondary', style: { fontWeight: 600 } }, 'Mögliche Ursachen:'),
      h('ul', { class: 'evidence small' }, causes.map(([k, n]) => h('li', null, `${n}× ${k}`)))) : null);
}

async function sessionDetail(main, id) {
  const s = await api(`api/gaming/sessions/${id}`);
  main.append(h('p', null, h('a', { href: '#/gaming' }, '← Gaming Mode')));
  main.append(h('div', { class: 'card stack' },
    h('div', { class: 'secondary' }, `Gaming Session #${s.id}${s.auto_detected ? ' · automatisch erkannt' : ''}`),
    h('h1', null, `${fmtTime(s.ts_start, false)}–${s.ts_end ? fmtTime(s.ts_end, false) : 'läuft'}`),
    h('div', { class: 'muted' }, `${fmtDateTime(s.ts_start)} · Gerät ${s.device_ip || '–'} · Server ${s.server_ip ? `${s.server_ip}:${s.server_port}` : 'nicht erkannt'}`),
    s.summary ? summaryTable(s.summary) : h('div', { class: 'empty' }, 'Zusammenfassung wird nach Ende der Session erstellt.')));
  const inc = h('div', { class: 'card', style: { marginTop: '16px' } }, h('div', { class: 'card-head' }, h('h2', null, 'Incidents während der Session')));
  if (!s.incidents.length) inc.append(h('div', { class: 'empty' }, 'Keine Lag-Events – saubere Session.'));
  else inc.append(h('ul', { class: 'list' }, s.incidents.map(i => h('li', null, h('a', { href: `#/incident/${i.id}` },
    h('div', { class: 'row' }, h('b', null, fmtTime(i.ts_start)), h('span', null, i.title || ''), h('span', { class: 'spacer' }), confBadge(i.confidence)),
    h('div', { class: 'small secondary' }, i.cause || ''))))));
  main.append(inc);
}
