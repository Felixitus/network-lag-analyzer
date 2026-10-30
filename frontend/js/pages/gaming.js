// Gaming Mode: start/stop a session, live values of the game flow, past sessions.
import { api, clear, fmtDateTime, fmtDuration, fmtMs, fmtTime, h, SERIES, toast, confBadge } from '../lib.js';
import { chartCard, fmt } from '../charts.js';

let off = null;
export function unmount() { if (off) off(); off = null; }

export async function mount(main, { args, store }) {
  if (args[0]) return sessionDetail(main, parseInt(args[0], 10));
  const settings = await api('api/settings');
  main.append(h('div', { class: 'page-head' }, h('div', null, h('h1', null, 'Gaming Mode'),
    h('p', null, 'During a session: 4 pings/s, your gaming PC\'s game flow and its game server.'))));
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
      cur.append(h('div', { class: 'row' }, h('h3', null, 'No session active'), h('span', { class: 'spacer' }),
        h('button', { class: 'btn primary', onclick: start }, 'Start gaming session')),
      h('p', { class: 'secondary' }, pcIp ? `Gaming PC: ${pcIp}. ` : 'No gaming PC set - mark one under "Devices" so that the game flow is detected. ',
        settings.config.gaming.auto_detect ? 'Automatic detection is active: sessions start by themselves as soon as the gaming PC has sustained UDP traffic to a server.' : ''));
      if (r.candidates.length) {
        cur.append(h('div', { class: 'small' }, h('b', null, 'Current bidirectional UDP flows: '),
          r.candidates.slice(0, 5).map(c => `${c.device} → ${c.remote_ip}:${c.remote_port} (${c.pps_up}/${c.pps_down} pps)`).join(' · ')));
      }
      return;
    }
    const s = r.session;
    cur.append(h('div', { class: 'row' }, h('span', { class: 'dot good' }), h('h3', null, `Gaming session #${s.id} running`),
      h('span', { class: 'muted' }, `since ${fmtTime(s.ts_start)}${s.auto_detected ? ' · detected automatically' : ''}`), h('span', { class: 'spacer' }),
      h('button', { class: 'btn', onclick: stop }, 'Stop session')),
    h('div', { class: 'facts' },
      h('div', { class: 'fact' }, h('div', { class: 'k' }, 'Device'), h('div', { class: 'v', style: { fontSize: '16px' } }, s.device_ip || 'not set')),
      h('div', { class: 'fact' }, h('div', { class: 'k' }, 'Game server'), h('div', { class: 'v', style: { fontSize: '16px' } },
        s.server_ip ? `${s.server_ip}:${s.server_port}` : 'detecting…')),
      h('div', { class: 'fact' }, h('div', { class: 'k' }, 'Ping to the server'), h('div', { class: 'v', style: { fontSize: '16px' } },
        s.server_icmp === 'blocked' ? 'Not available (server does not answer ICMP)' : s.server_icmp === 'ok' ? 'being measured' : '–'))));
    const c = chartCard('Live: ping & game flow', [
      { label: 'Internet (median)', color: SERIES(1), fmt: fmt.ms },
      { label: 'Game server ping', color: SERIES(2), fmt: fmt.ms },
      { label: 'Game packet gap', color: SERIES(7), fmt: fmt.ms, dash: [4, 3] },
    ], { height: 200, yFmt: fmt.msAxis, yLabel: 'ms', yMinMax: 50 });
    cur.append(c.card);
    chart = c.mount();
    const hist = await api('api/history?range=5m');
    const ss = hist.series;
    data = { ts: ss.ts.slice(), rtt: ss.rtt_avg.slice(), game: ss.game_rtt.slice(), gap: ss.game_gap_ms.slice() };
    chart.setData([data.ts, data.rtt, data.game, data.gap]);
    cur.append(h('p', { class: 'small muted' }, 'Game packet gap = longest time without a packet from the server per second (normal at ~60–128 tick rate: 8–35 ms).'));
  }
  async function start() { await api('api/gaming/start', { method: 'POST', body: {} }); toast('Gaming session started'); renderCurrent(); }
  async function stop() { const r = await api('api/gaming/stop', { method: 'POST' }); location.hash = `#/gaming/${r.id}`; }

  async function renderList() {
    const r = await api('api/gaming/sessions');
    clear(list).append(h('div', { class: 'card-head' }, h('h2', null, 'Past sessions')));
    const done = r.sessions.filter(s => s.ts_end);
    if (!done.length) { list.append(h('div', { class: 'empty' }, 'No completed sessions yet.')); return; }
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
    h('div', { class: 'secondary small' }, 'Gaming session'),
    h('h3', null, `${fmtTime(s.ts_start, false)}–${fmtTime(s.ts_end, false)}`),
    h('div', { class: 'small muted' }, `${fmtDateTime(s.ts_start).slice(0, 10)} · ${fmtDuration(s.ts_end - s.ts_start)}`),
    h('hr', { class: 'sep' }),
    summaryTable(m));
}

function summaryTable(m) {
  const rows = [
    ['Ping average', m.ping_avg != null ? `${fmtMs(m.ping_avg)} ms` : 'Not available'],
    ['Maximum', m.ping_max != null ? `${fmtMs(m.ping_max)} ms` : 'Not available'],
    ['Jitter average', m.jitter_avg != null ? `${m.jitter_avg} ms` : 'Not available'],
    ['Packet loss events', m.packet_loss_events ?? '–'],
    ['Lag events', m.lag_events ?? '–'],
  ];
  if (m.game_gap_max != null) rows.push(['Largest game packet gap', `${Math.round(m.game_gap_max)} ms`]);
  const causes = Object.entries(m.causes || {});
  return h('div', null, h('table', { class: 'tbl small' }, h('tbody', null, rows.map(([k, v]) => h('tr', null, h('td', null, k), h('td', { class: 'num' }, String(v)))))),
    causes.length ? h('div', { style: { marginTop: '8px' } }, h('div', { class: 'small secondary', style: { fontWeight: 600 } }, 'Possible causes:'),
      h('ul', { class: 'evidence small' }, causes.map(([k, n]) => h('li', null, `${n}× ${k}`)))) : null);
}

async function sessionDetail(main, id) {
  const s = await api(`api/gaming/sessions/${id}`);
  main.append(h('p', null, h('a', { href: '#/gaming' }, '← Gaming Mode')));
  main.append(h('div', { class: 'card stack' },
    h('div', { class: 'secondary' }, `Gaming session #${s.id}${s.auto_detected ? ' · detected automatically' : ''}`),
    h('h1', null, `${fmtTime(s.ts_start, false)}–${s.ts_end ? fmtTime(s.ts_end, false) : 'running'}`),
    h('div', { class: 'muted' }, `${fmtDateTime(s.ts_start)} · device ${s.device_ip || '–'} · server ${s.server_ip ? `${s.server_ip}:${s.server_port}` : 'not detected'}`),
    s.summary ? summaryTable(s.summary) : h('div', { class: 'empty' }, 'The summary is created after the session ends.')));
  const inc = h('div', { class: 'card', style: { marginTop: '16px' } }, h('div', { class: 'card-head' }, h('h2', null, 'Incidents during the session')));
  if (!s.incidents.length) inc.append(h('div', { class: 'empty' }, 'No lag events - clean session.'));
  else inc.append(h('ul', { class: 'list' }, s.incidents.map(i => h('li', null, h('a', { href: `#/incident/${i.id}` },
    h('div', { class: 'row' }, h('b', null, fmtTime(i.ts_start)), h('span', null, i.title || ''), h('span', { class: 'spacer' }), confBadge(i.confidence)),
    h('div', { class: 'small secondary' }, i.cause || ''))))));
  main.append(inc);
}
