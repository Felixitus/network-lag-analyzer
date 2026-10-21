// DNS usage: network overview, client detail, category rules.
// Everything shown here are counts of DNS queries as Pi-hole logged them - not usage time, not traffic.
import { api, clear, fmtDate, fmtDateTime, h, ago, toast, cssVar, NA } from '../lib.js';
import { timeChart } from '../charts.js';
import { naBox, segmented } from './common.js';

const RANGES = [['1h', '1 H'], ['24h', '24 H'], ['7d', '7 D'], ['30d', '30 D'], ['custom', 'Custom']];
const SPAN = { '1h': 3600, '24h': 86400, '7d': 7 * 86400, '30d': 30 * 86400 };
const BASIS_LABEL = {
  mac: ['Device (MAC)', 'Queries attributed by the MAC address Pi-hole knows for this IP.'],
  ip: ['IP only', 'No MAC address known for this IP at the time of the queries - the device behind it cannot be named.'],
  local: ['This Pi', "The Raspberry Pi's own lookups. Not counted in network totals."],
};
const CONF_TEXT = { high: 'high', medium: 'medium', low: 'low' };

// ------------------------------------------------------------------ shared state
const state = { range: '24h', start: null, end: null };
try { Object.assign(state, JSON.parse(sessionStorage.getItem('nla-dns-range') || '{}')); } catch { /* */ }
function saveRange() { try { sessionStorage.setItem('nla-dns-range', JSON.stringify(state)); } catch { /* */ } }

function currentRange() {
  if (state.range === 'custom' && state.start && state.end) return [state.start, state.end];
  const end = Math.floor(Date.now() / 1000);
  return [end - SPAN[state.range === 'custom' ? '24h' : state.range], end];
}
const qs = () => { const [s, e] = currentRange(); return `start=${s}&end=${e}`; };
const nf = new Intl.NumberFormat('en-US');
const n = v => (v === null || v === undefined ? NA : nf.format(v));
const pct = (a, b) => (b ? `${(100 * a / b).toFixed(1)} %` : '–');

function toLocalInput(ts) {
  const d = new Date(ts * 1000), p = x => String(x).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

/** Range picker: segmented presets + custom from/to. Calls onChange after every change. */
function rangePicker(onChange) {
  const from = h('input', { type: 'datetime-local', 'aria-label': 'From' });
  const to = h('input', { type: 'datetime-local', 'aria-label': 'To' });
  const apply = h('button', { class: 'btn', type: 'button' }, 'Apply');
  const custom = h('div', { class: 'row small', style: { display: state.range === 'custom' ? '' : 'none' } }, from, '–', to, apply);
  const [s, e] = currentRange();
  from.value = toLocalInput(s); to.value = toLocalInput(e);
  apply.addEventListener('click', () => {
    const a = Date.parse(from.value) / 1000, b = Date.parse(to.value) / 1000;
    if (!a || !b || b <= a) { toast('Invalid time range'); return; }
    state.start = Math.floor(a); state.end = Math.floor(b); saveRange(); onChange();
  });
  const seg = segmented(RANGES, state.range, v => {
    state.range = v; custom.style.display = v === 'custom' ? '' : 'none'; saveRange();
    if (v !== 'custom') onChange();
  });
  return h('div', { class: 'row' }, seg, custom);
}

// ------------------------------------------------------------------ small building blocks
const CAT_SLOTS = ['social', 'gaming', 'streaming', 'communication', 'productivity', 'shopping', 'news', 'music',
  'cloud', 'ads_tracking', 'os_updates', 'smart_home'];
function catColor(cat) {
  const i = CAT_SLOTS.indexOf(cat);
  return i < 0 ? cssVar('--axis') : cssVar(`--series-${(i % 8) + 1}`);
}
let LABELS = {};
const catLabel = c => (c === 'not_itemized' ? 'Not itemized' : LABELS[c] || c);

function catBadge(cat, cls) {
  const title = cls
    ? `Rule: ${cls.rule || '–'} · source: ${cls.source || 'none'} · confidence: ${CONF_TEXT[cls.confidence] || 'none'}`
      + (cls.service_name ? ` · service: ${cls.service_name}` : '')
      + (cls.categories && cls.categories.length > 1 ? ` · also: ${cls.categories.slice(1).map(catLabel).join(', ')}` : '')
    : 'Folded on completed days - cannot be classified any more';
  return h('span', { class: `badge cat${cls && cls.confidence === 'low' ? ' cat-low' : ''}`, title },
    h('span', { class: 'dot', style: { background: catColor(cat) } }), catLabel(cat),
    cls && cls.confidence === 'low' ? h('span', { class: 'muted' }, '?') : null);
}

function basisBadge(basis) {
  const [label, title] = BASIS_LABEL[basis] || [basis, ''];
  return h('span', { class: `badge${basis === 'ip' ? ' warning' : ''}`, title }, label);
}

function tile(label, value, foot) {
  return h('div', { class: `tile${value === null ? ' na' : ''}`, role: 'listitem' },
    h('div', { class: 'label' }, label), h('div', { class: 'value' }, value === null ? NA : value),
    h('div', { class: 'foot' }, foot || ''));
}

function sourceLine(name, st) {
  st = st || {};
  const ok = st.ok === true ? 'good' : st.ok === false ? 'critical' : 'muted';
  const msg = st.message || st.note || (st.enabled === false ? 'disabled' : st.ok ? 'connected' : 'unknown');
  return h('div', { class: 'row small' }, h('span', { class: `dot ${ok}` }), h('b', null, name), h('span', { class: 'muted' }, msg));
}

function categoryBars(cats) {
  if (!cats.length) return naBox('No queries in this range.');
  const max = Math.max(...cats.map(c => c.queries), 1);
  return h('div', { class: 'stack-sm' }, cats.map(c => h('div', { class: 'bar-row cat-row', title: `${n(c.queries)} queries, ${n(c.blocked)} blocked, ${c.domains} domains` },
    h('span', { class: 'dot', style: { background: catColor(c.category) } }),
    h('div', null, h('div', { class: 'small' }, c.label), h('div', { class: 'bar-track' },
      h('div', { class: 'bar-fill', style: { width: `${100 * c.queries / max}%`, background: catColor(c.category) } }))),
    h('b', null, `${(100 * c.share).toFixed(1)} %`))));
}

/** Hourly bars. Hours before recording started are hatched - not drawn as zero. */
function hourlyChart(container, rows, t0, t1, coverageFrom) {
  const by = new Map(rows.map(r => [r.ts, r]));
  const xs = [], q = [], b = [];
  for (let t = t0; t < t1; t += 3600) {
    const r = by.get(t);
    const covered = coverageFrom !== null && coverageFrom !== undefined && t >= coverageFrom && t <= Date.now() / 1000;
    xs.push(t); q.push(r ? r.queries - r.blocked : covered ? 0 : null); b.push(r ? r.blocked : covered ? 0 : null);
  }
  const gaps = [];
  if (coverageFrom === null || coverageFrom === undefined) gaps.push([t0, t1]);
  else if (coverageFrom > t0) gaps.push([t0, Math.min(coverageFrom, t1)]);
  const chart = timeChart(container, [
    { label: 'Allowed', color: cssVar('--series-1'), bars: true, fill: 0.85, width: 0, fmt: v => nf.format(v) },
    { label: 'Blocked', color: cssVar('--series-8'), bars: true, fill: 0.85, width: 0, fmt: v => nf.format(v) },
  ], { height: 170, yFmt: v => nf.format(v), markers: () => ({ gaps }), naText: 'Not available - no recorded hours in this range' });
  chart.setData([xs, q, b]);
  return chart;
}

function rangeNote(res, meta, note) {
  if (!meta) return null;
  return h('div', { class: 'small muted' }, res === 'hour'
    ? `Domains for ${fmtDateTime(meta.from)} – ${fmtDateTime(meta.to)}. `
    : `Domains for whole days ${fmtDate(meta.from)} – ${fmtDate(meta.to - 1)}. `, note || '');
}

// ------------------------------------------------------------------ router
export async function mount(main, ctx) {
  const [sub, id] = ctx.args;
  try { LABELS = (await api('api/dns/rules')).categories || {}; } catch { LABELS = {}; }
  if (sub === 'client' && id) return mountClient(main, Number(id));
  if (sub === 'rules') return mountRules(main);
  return mountOverview(main);
}

function pageHead(title, sub, ...right) {
  return h('div', { class: 'page-head' },
    h('div', null, h('h1', null, title), h('p', null, sub)), h('span', { class: 'spacer' }), ...right);
}

// ------------------------------------------------------------------ overview
async function mountOverview(main) {
  const body = h('div', { class: 'stack' });
  main.append(pageHead('DNS usage',
    'Which device looked up which names, counted from the Pi-hole query log. DNS lookups show activity - not usage time and not data volume.',
    h('a', { class: 'btn', href: '#/dns/rules' }, 'Category rules')),
  h('div', { class: 'card' }, rangePicker(load)), h('div', { style: { height: '16px' } }), body);

  async function load() {
    clear(body).append(h('div', { class: 'skeleton' }, 'Loading…'));
    let o, cl;
    try { [o, cl] = await Promise.all([api(`api/dns/overview?${qs()}`), api(`api/dns/clients?${qs()}`)]); }
    catch (e) { clear(body).append(naBox(`Not available - ${e.message}`)); return; }
    clear(body);
    const t = o.totals;
    const src = o.sources || {};
    body.append(h('div', { class: 'card' },
      h('div', { class: 'card-head' }, h('h2', null, 'Data sources'),
        h('span', { class: 'sub' }, o.coverage.from ? `Recorded: ${fmtDateTime(o.coverage.from)} – ${fmtDateTime(o.coverage.to)}` : 'Nothing recorded yet')),
      h('div', { class: 'grid grid-3' }, sourceLine('Pi-hole', src.pihole), sourceLine('DNS usage', src.dns_usage), sourceLine('FRITZ!Box', src.fritzbox)),
      src.dns_usage && src.dns_usage.backlog ? h('div', { class: 'small muted', style: { marginTop: '8px' } },
        `Still reading the Pi-hole log: ${n(src.dns_usage.backlog)} queries to go. Older ranges fill in over the next minutes.`) : null));

    const tiles = h('div', { class: 'tiles tiles-4', role: 'list' },
      tile('Known clients', n(t.known_clients), 'seen by Pi-hole since recording started'),
      tile('Active clients', n(t.active_clients), 'with queries in this range'),
      tile('DNS queries', n(t.queries), `${n(t.duplicates)} retries not counted${t.local_queries ? ` · Pi itself: ${n(t.local_queries)}` : ''}`),
      tile('Blocked', n(t.blocked), pct(t.blocked, t.queries)));
    body.append(tiles);

    const chartBox = h('div');
    body.append(h('div', { class: 'card chart-card' },
      h('div', { class: 'chart-title' }, h('h3', null, 'DNS queries per hour'), h('span', { class: 'muted small' }, 'all devices, without the Pi itself')),
      chartBox));
    hourlyChart(chartBox, o.timeline, o.start, o.end, o.coverage.from);

    const domTable = o.top_domains.length ? h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' },
      h('thead', null, h('tr', null, h('th', null, 'Domain'), h('th', null, 'Category'), h('th', { class: 'num' }, 'Queries'), h('th', { class: 'num' }, 'Blocked'))),
      h('tbody', null, o.top_domains.map(d => h('tr', null, h('td', { class: 'mono' }, d.domain), h('td', null, catBadge(d.category, d.classification)),
        h('td', { class: 'num' }, n(d.queries)), h('td', { class: 'num' }, n(d.blocked))))))) : naBox('No domains in this range.');
    body.append(h('div', { class: 'grid grid-2' },
      h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', null, 'Top domains')), domTable, rangeNote(o.domains_resolution, o.domains_range)),
      h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', null, 'Categories'), h('span', { class: 'sub' }, 'share of queries, rule based')),
        categoryBars(o.categories))));

    body.append(h('div', { class: 'grid grid-2' }, clientsCard(cl), recentCard(o)));
  }
  await load();
}

function clientsCard(cl) {
  const search = h('input', { type: 'search', placeholder: 'Search name, IP or MAC…', 'aria-label': 'Search clients', style: { minWidth: '220px' } });
  const tbody = h('tbody');
  const card = h('div', { class: 'card' },
    h('div', { class: 'card-head' }, h('h2', null, `Clients (${cl.clients.length})`), search),
    h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' },
      h('thead', null, h('tr', null, h('th', null, ''), h('th', null, 'Client'), h('th', { class: 'num' }, 'Queries'),
        h('th', { class: 'num' }, 'Blocked'), h('th', { class: 'num' }, 'Domains'))), tbody)),
    h('div', { class: 'small muted' }, cl.domains_note));
  function render() {
    const needle = search.value.trim().toLowerCase();
    clear(tbody);
    const rows = cl.clients.filter(c => !needle || [c.name, c.hostname, c.alias, c.ip, c.mac, c.vendor]
      .some(v => v && String(v).toLowerCase().includes(needle)));
    if (!rows.length) { tbody.append(h('tr', null, h('td', { colspan: '5', class: 'muted' }, 'No matching client.'))); return; }
    for (const c of rows) {
      const tr = h('tr', { class: 'click', tabindex: '0' },
        h('td', null, h('span', { class: `dot ${c.online === true ? 'good' : 'muted'}`, title: c.online === null ? 'Online status: Not available' : c.online ? 'Online' : 'Offline' })),
        h('td', null, h('div', null, c.name, ' ', c.basis !== 'mac' ? basisBadge(c.basis) : null),
          h('div', { class: 'small mono muted' }, [c.ip, c.mac].filter(Boolean).join(' · '), c.vendor ? ` · ${c.vendor}` : '')),
        h('td', { class: 'num' }, n(c.queries)), h('td', { class: 'num' }, n(c.blocked)),
        h('td', { class: 'num' }, n(c.domains)));
      const go = () => { location.hash = `#/dns/client/${c.id}`; };
      tr.addEventListener('click', go);
      tr.addEventListener('keydown', ev => { if (ev.key === 'Enter') go(); });
      tbody.append(tr);
    }
  }
  search.addEventListener('input', render);
  render();
  return card;
}

function recentCard(o) {
  const card = h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', null, 'Latest queries'),
    h('span', { class: 'sub' }, 'from Pi-hole, up to ~60 s delayed')));
  if (o.recent === null || o.recent === undefined) {
    card.append(naBox(`Not available${o.recent_error ? ` - ${o.recent_error}` : ' - Pi-hole query log not connected.'}`));
    return card;
  }
  if (!o.recent.length) { card.append(naBox('No queries yet.')); return card; }
  card.append(h('ul', { class: 'list' }, o.recent.map(r => h('li', { class: 'row' },
    h('span', { class: 'small muted', style: { minWidth: '64px' } }, ago(r.ts)),
    h('div', { style: { minWidth: 0, flex: 1 } }, h('div', { class: 'mono', style: { overflowWrap: 'anywhere' } }, r.domain),
      h('div', { class: 'small muted' }, r.client || '–')),
    r.outcome === 'blocked' ? h('span', { class: 'badge critical' }, 'blocked') : null))));
  return card;
}

// ------------------------------------------------------------------ client detail
async function mountClient(main, cid) {
  const head = h('div');
  const body = h('div', { class: 'stack' });
  main.append(h('div', { class: 'row small' }, h('a', { href: '#/dns' }, '← DNS usage')), head,
    h('div', { class: 'card' }, rangePicker(load)), h('div', { style: { height: '16px' } }), body);

  const filt = { category: '', q: '', status: 'all', sort: 'queries', offset: 0 };
  const LIMIT = 50;

  async function load() {
    clear(body).append(h('div', { class: 'skeleton' }, 'Loading…'));
    let s, hr;
    try { [s, hr] = await Promise.all([api(`api/dns/clients/${cid}/summary?${qs()}`), api(`api/dns/clients/${cid}/hourly?${qs()}`)]); }
    catch (e) { clear(body).append(naBox(e.status === 404 ? 'Client not found.' : `Not available - ${e.message}`)); return; }
    const st = await api('api/dns/status').catch(() => ({}));
    renderHead(s.client);
    clear(body);
    const t = s.totals, cmp = s.comparison;
    const change = k => {
      if (!cmp || !cmp[k] || cmp[k].change === null) return 'previous period: Not available';
      const c = cmp[k].change;
      return `${c >= 0 ? '+' : ''}${(100 * c).toFixed(0)} % vs. previous period (${n(cmp[k].previous)})`;
    };
    body.append(h('div', { class: 'tiles tiles-4', role: 'list' },
      tile('DNS queries', n(t.queries), change('queries')),
      tile('Blocked', n(t.blocked), `${pct(t.blocked, t.queries)} · ${change('blocked')}`),
      tile('Distinct domains', n(t.domains), change('domains')),
      tile('Retries', n(t.duplicates), 'repeated lookups, not counted')));
    if (!cmp) body.append(h('div', { class: 'small muted' }, s.comparison_note));

    const chartBox = h('div');
    body.append(h('div', { class: 'card chart-card' },
      h('div', { class: 'chart-title' }, h('h3', null, 'DNS activity per hour'), h('span', { class: 'muted small' }, 'hatched = not recorded')),
      chartBox));
    hourlyChart(chartBox, hr.hours, hr.start, hr.end, st.data_from ?? null);

    const top = s.top_domains.length ? h('ul', { class: 'list' }, s.top_domains.map(d => h('li', { class: 'row' },
      h('span', { class: 'mono', style: { overflowWrap: 'anywhere' } }, d.domain), h('span', { class: 'spacer' }),
      catBadge(d.category, d.classification), h('span', { class: 'num' }, n(d.queries))))) : naBox('No domains in this range.');
    body.append(h('div', { class: 'grid grid-2' },
      h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', null, 'Categories'), h('span', { class: 'sub' }, 'share of queries, rule based')),
        categoryBars(s.categories),
        cmp ? comparisonList(cmp.categories) : null),
      h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', null, 'Top domains')), top,
        rangeNote(s.domains_resolution, s.domains_range))));

    const domCard = h('div', { class: 'card' });
    body.append(domCard);
    filt.offset = 0;
    renderDomains(domCard, s.categories);
  }

  function renderHead(c) {
    clear(head);
    const aliasInput = h('input', { type: 'text', value: c.alias || '', placeholder: c.hostname || 'Alias, e.g. Gaming-PC', maxlength: '64', 'aria-label': 'Alias' });
    const save = h('button', { class: 'btn', type: 'button' }, 'Save alias');
    save.addEventListener('click', async () => {
      try { await api(`api/devices/${encodeURIComponent(c.mac)}`, { method: 'PATCH', body: { custom_name: aliasInput.value } }); toast('Alias saved'); load(); }
      catch (e) { toast(e.message); }
    });
    const [blabel, btitle] = BASIS_LABEL[c.basis] || [c.basis, ''];
    head.append(h('div', { class: 'page-head' },
      h('div', null, h('h1', null, c.name),
        h('p', null, [c.ip ? `IP ${c.ip}` : null, c.mac ? `MAC ${c.mac}` : null, c.vendor, c.hostname && c.alias ? `host name ${c.hostname}` : null].filter(Boolean).join(' · ')),
        h('div', { class: 'row small' }, basisBadge(c.basis), h('span', { class: 'muted' }, btitle),
          c.online === null ? h('span', { class: 'muted' }, 'Online status: Not available') : h('span', { class: `badge${c.online ? ' good' : ''}` }, c.online ? 'Online' : 'Offline'),
          h('span', { class: 'muted' }, `First query ${fmtDateTime(c.first_seen)} · last ${ago(c.last_seen)}`))),
      h('span', { class: 'spacer' }),
      c.mac ? h('div', { class: 'row' }, aliasInput, save)
        : h('div', { class: 'small muted', style: { maxWidth: '260px' } }, `${blabel}: an alias needs a MAC address - an IP alone can belong to different devices over time.`)));
  }

  async function renderDomains(card, cats) {
    const catSel = h('select', { 'aria-label': 'Category' }, h('option', { value: '' }, 'All categories'),
      cats.map(c => h('option', { value: c.category, selected: filt.category === c.category }, c.label)));
    const search = h('input', { type: 'search', placeholder: 'Filter domains…', value: filt.q, 'aria-label': 'Filter domains' });
    const sortSel = h('select', { 'aria-label': 'Sort' }, [['queries', 'Most queries'], ['last_seen', 'Last seen'], ['domain', 'Name']]
      .map(([v, l]) => h('option', { value: v, selected: filt.sort === v }, l)));
    const tableBox = h('div');
    clear(card).append(h('div', { class: 'card-head' }, h('h2', null, 'Domains'),
      h('div', { class: 'row' }, segmented([['all', 'All'], ['allowed', 'Allowed'], ['blocked', 'Blocked']], filt.status, v => { filt.status = v; filt.offset = 0; fetchPage(); }),
        catSel, search, sortSel)), tableBox);
    catSel.addEventListener('change', () => { filt.category = catSel.value; filt.offset = 0; fetchPage(); });
    sortSel.addEventListener('change', () => { filt.sort = sortSel.value; fetchPage(); });
    let tmr;
    search.addEventListener('input', () => { clearTimeout(tmr); tmr = setTimeout(() => { filt.q = search.value.trim(); filt.offset = 0; fetchPage(); }, 300); });

    async function fetchPage() {
      const p = new URLSearchParams({ limit: LIMIT, offset: filt.offset, status: filt.status, sort: filt.sort });
      if (filt.category) p.set('category', filt.category);
      if (filt.q) p.set('q', filt.q);
      let r;
      try { r = await api(`api/dns/clients/${cid}/domains?${qs()}&${p}`); }
      catch (e) { clear(tableBox).append(naBox(e.message)); return; }
      clear(tableBox);
      if (!r.domains.length) { tableBox.append(naBox('No domains match these filters.')); return; }
      tableBox.append(h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' },
        h('thead', null, h('tr', null, h('th', null, 'Domain'), h('th', null, 'Category'), h('th', { class: 'num' }, 'Queries'),
          h('th', { class: 'num' }, 'Blocked'), h('th', null, 'Last seen'))),
        h('tbody', null, r.domains.map(d => h('tr', null,
          h('td', { class: 'mono', style: { overflowWrap: 'anywhere' } }, d.other ? h('i', null, 'other domains (folded)') : d.domain),
          h('td', null, catBadge(d.category, d.classification)),
          h('td', { class: 'num' }, n(d.queries)), h('td', { class: 'num' }, n(d.blocked)),
          h('td', { class: 'small muted' }, d.last_seen ? fmtDateTime(d.last_seen) : '–')))))));
      const prev = h('button', { class: 'btn', type: 'button', disabled: filt.offset === 0 }, '← Previous');
      const next = h('button', { class: 'btn', type: 'button', disabled: filt.offset + LIMIT >= r.total }, 'Next →');
      prev.addEventListener('click', () => { filt.offset = Math.max(0, filt.offset - LIMIT); fetchPage(); });
      next.addEventListener('click', () => { filt.offset += LIMIT; fetchPage(); });
      tableBox.append(h('div', { class: 'row pager' }, prev,
        h('span', { class: 'small muted' }, `${filt.offset + 1}–${Math.min(filt.offset + LIMIT, r.total)} of ${n(r.total)}`), next,
        h('span', { class: 'spacer' }), h('span', { class: 'small muted' }, r.resolution_note)));
    }
    fetchPage();
  }
  await load();
}

function comparisonList(cats) {
  const rows = Object.entries(cats || {}).filter(([, v]) => v.current || v.previous);
  if (!rows.length) return null;
  return h('div', { style: { marginTop: '12px' } }, h('div', { class: 'small muted' }, 'Compared with the previous period of the same length:'),
    h('ul', { class: 'list' }, rows.map(([cat, v]) => h('li', { class: 'row small' },
      h('span', { class: 'dot', style: { background: catColor(cat) } }), catLabel(cat), h('span', { class: 'spacer' }),
      h('span', { class: 'num' }, `${n(v.previous)} → ${n(v.current)}`)))));
}

// ------------------------------------------------------------------ category rules
async function mountRules(main) {
  main.append(h('div', { class: 'row small' }, h('a', { href: '#/dns' }, '← DNS usage')),
    pageHead('Category rules', 'Local, rule based classification. The most specific rule wins; manual rules win over the built-in list for the same name.'));
  const testCard = h('div', { class: 'card' });
  const listCard = h('div', { class: 'card' });
  main.append(h('div', { class: 'grid grid-2' }, testCard, listCard));

  const input = h('input', { type: 'text', placeholder: 'e.g. scontent.cdninstagram.com', 'aria-label': 'Domain', style: { flex: 1 } });
  const out = h('div');
  const btn = h('button', { class: 'btn', type: 'submit' }, 'Check');
  const form = h('form', { class: 'row' }, input, btn);
  form.addEventListener('submit', async ev => {
    ev.preventDefault();
    try { showResult(await api(`api/dns/classify?domain=${encodeURIComponent(input.value)}`)); }
    catch (e) { clear(out).append(naBox(e.message)); }
  });
  testCard.append(h('div', { class: 'card-head' }, h('h2', null, 'Check a domain')), form, out);

  function showResult(r) {
    const boxes = Object.entries(LABELS).filter(([k]) => k !== 'unknown').map(([k, l]) => h('label', { class: 'check small' },
      h('input', { type: 'checkbox', value: k, checked: r.source === 'manual' && r.categories.includes(k) }), l));
    const exact = h('input', { type: 'checkbox' });
    const svc = h('input', { type: 'text', placeholder: 'Service name (optional)', maxlength: '64', value: r.source === 'manual' ? (r.service_name || '') : '' });
    const save = h('button', { class: 'btn primary', type: 'button' }, 'Save manual rule');
    save.addEventListener('click', async () => {
      const cats = boxes.map(b => b.firstChild).filter(x => x.checked).map(x => x.value);
      if (!cats.length) { toast('Choose at least one category'); return; }
      try {
        const res = await api(`api/dns/rules/${encodeURIComponent(r.domain)}`, { method: 'PUT', body: { categories: cats, exact: exact.checked, service_name: svc.value } });
        toast('Rule saved'); showResult(res); loadList();
      } catch (e) { toast(e.message); }
    });
    clear(out).append(h('div', { class: 'stack' },
      h('div', { class: 'row' }, h('b', { class: 'mono' }, r.domain), catBadge(r.primary, r)),
      h('div', { class: 'small muted' }, r.source
        ? `Rule "${r.rule}" from the ${r.source} rules, confidence ${r.confidence}${r.service_name ? `, service ${r.service_name}` : ''}.`
        : 'No rule matches - Unknown.'),
      h('div', null, h('div', { class: 'small', style: { fontWeight: 600, marginBottom: '6px' } }, 'Manual rule (applies to this name and its subdomains)'),
        h('div', { class: 'check-grid' }, boxes),
        h('div', { class: 'row', style: { marginTop: '8px' } }, h('label', { class: 'check small' }, exact, 'Only this exact name'), svc, save))));
  }

  async function loadList() {
    const r = await api('api/dns/rules');
    LABELS = r.categories || LABELS;
    const entries = Object.entries(r.overrides || {});
    clear(listCard).append(h('div', { class: 'card-head' }, h('h2', null, `Manual rules (${entries.length})`),
      h('span', { class: 'sub' }, r.layers.map(l => `${l.source}: ${l.rules}`).join(' · '))));
    for (const e of r.errors || []) listCard.append(h('div', { class: 'banner warn' }, h('b', null, 'Rule file ignored'), h('span', null, e)));
    if (!entries.length) { listCard.append(naBox('No manual rules yet. Check a domain on the left to add one.')); return; }
    listCard.append(h('ul', { class: 'list' }, entries.map(([dom, o]) => {
      const del = h('button', { class: 'btn', type: 'button' }, 'Remove');
      del.addEventListener('click', async () => {
        try { await api(`api/dns/rules/${encodeURIComponent(dom)}`, { method: 'DELETE' }); toast('Rule removed'); loadList(); }
        catch (e) { toast(e.message); }
      });
      return h('li', { class: 'row' }, h('span', { class: 'mono' }, o.exact ? `=${dom}` : dom),
        o.categories.map(c => catBadge(c, { rule: dom, source: 'manual', confidence: 'high', categories: o.categories, service_name: o.service_name })),
        h('span', { class: 'spacer' }), del);
    })));
  }
  await loadList();
}
