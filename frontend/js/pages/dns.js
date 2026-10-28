// DNS usage: network overview, client detail, category rules.
// Everything shown here are counts of DNS queries as Pi-hole logged them - not usage time, not traffic.
import { api, clear, fmtDate, fmtDateTime, fmtTime, h, ago, toast, cssVar, NA } from '../lib.js';
import { timeChart } from '../charts.js';
import { naBox, piholeCard, segmented, upstreamTable } from './common.js';
import { refreshNamesButton } from './devices.js';
import { domainLink } from './dns_domain.js';

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
  'cloud', 'ads_tracking', 'os_updates', 'smart_home', 'adult', 'gambling', 'dating', 'vpn'];
// Not chosen by anybody: drawn in neutral grey so they never look like a kind of use.
const NEUTRAL = new Set(['network', 'infrastructure', 'other', 'unknown', 'not_itemized']);
function catColor(cat) {
  if (cat === 'threat') return cssVar('--critical');
  const i = CAT_SLOTS.indexOf(cat);
  return i < 0 || NEUTRAL.has(cat) ? cssVar('--axis') : cssVar(`--series-${(i % 8) + 1}`);
}
let LABELS = {};
let INFO = {};
const domCtx = () => ({ labels: LABELS, info: INFO, qs, badge: catBadge });
const catLabel = c => (c === 'not_itemized' ? 'Not itemized' : LABELS[c] || c);

function catBadge(cat, cls) {
  const title = cls === undefined ? `${catLabel(cat)}${INFO[cat] ? ` - ${INFO[cat]}` : ''}` : cls
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
  return h('div', { class: 'stack-sm' }, cats.map(c => h('div', { class: 'bar-row cat-row', title: `${n(c.queries)} queries, ${n(c.blocked)} blocked, ${c.domains} domains${INFO[c.category] ? `\n${INFO[c.category]}` : ''}` },
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
  try { const r = await api('api/dns/rules'); LABELS = r.categories || {}; INFO = r.category_info || {}; } catch { LABELS = {}; INFO = {}; }
  if (sub === 'client' && id) return mountClient(main, Number(id));
  if (sub === 'rules') return mountRules(main);
  if (sub === 'categories') return mountCategories(main, id ? Number(id) : null);
  return mountOverview(main);
}

// ------------------------------------------------------------------ export
let csvLocale = 'de';
try { csvLocale = localStorage.getItem('nla-csv-locale') || 'de'; } catch { /* */ }

/** Export menu. `items`: [label, format, kind, extraParams()] - params are read at click time,
 *  so the file always has the range and filters that are on screen right now. */
function exportMenu(items) {
  const loc = h('select', { 'aria-label': 'CSV format' },
    h('option', { value: 'de', selected: csvLocale === 'de' }, 'CSV for German Excel (;)'),
    h('option', { value: 'en', selected: csvLocale === 'en' }, 'CSV international (,)'));
  loc.addEventListener('change', () => { csvLocale = loc.value; try { localStorage.setItem('nla-csv-locale', csvLocale); } catch { /* */ } });
  const menu = h('details', { class: 'export-menu' }, h('summary', { class: 'btn' }, 'Export ▾'),
    h('div', { class: 'export-list' },
      items.map(([label, format, kind, extra]) => {
        const b = h('button', { type: 'button', class: 'export-item' }, h('span', { class: 'badge' }, format.toUpperCase()), label);
        b.addEventListener('click', () => {
          const p = new URLSearchParams({ kind, format, locale: csvLocale });
          for (const [k, v] of Object.entries(extra ? extra() : {})) if (v !== null && v !== undefined && v !== '' && v !== 0) p.set(k, v);
          menu.open = false;
          toast('Preparing the export…');
          window.location.href = `api/dns/export?${qs()}&${p}`;
        });
        return b;
      }),
      loc,
      h('div', { class: 'small muted' }, 'Uses the selected range and filters. Each file states the export time, range and method.')));
  return menu;
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
    h('div', { class: 'row' }, exportMenu([
      ['Whole network (all tables)', 'xlsx', 'network'],
      ['Clients', 'csv', 'clients'],
      ['Domain list', 'csv', 'domains'],
      ['Category statistics', 'csv', 'categories'],
      ['Blocked domains', 'csv', 'blocked'],
      ['Time series (per hour)', 'csv', 'timeseries'],
    ]), h('a', { class: 'btn', href: '#/dns/categories' }, 'Categories per device'),
    h('a', { class: 'btn', href: '#/dns/rules' }, 'Category rules'))),
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

    body.append(identificationCard());

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
      h('tbody', null, o.top_domains.map(d => h('tr', null, h('td', null, domainLink(d.domain, domCtx())), h('td', null, catBadge(d.category, d.classification)),
        h('td', { class: 'num' }, n(d.queries)), h('td', { class: 'num' }, n(d.blocked))))))) : naBox('No domains in this range.');
    body.append(h('div', { class: 'grid grid-2' },
      h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', null, 'Top domains')), domTable, rangeNote(o.domains_resolution, o.domains_range)),
      h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', null, 'Categories'), h('span', { class: 'sub' }, 'share of queries, rule based')),
        categoryBars(o.categories))));

    body.append(h('div', { class: 'grid grid-2' }, clientsCard(cl), recentCard(o)));
    body.append(bypassCard());
    body.append(upstreamCard());
    body.append(piholeCard());
    body.append(h('div', { class: 'grid grid-2' }, uncategorizedCard(load), glossaryCard()));
  }
  await load();
}

// ------------------------------------------------------------------ categories per device
function fmtEstimate(s) {
  if (!s) return null;
  const m = Math.round(s / 60);
  return m < 60 ? `~${m} min` : `~${Math.floor(m / 60)} h ${m % 60} min`;
}

function stackedBar(cats, showBackground) {
  const bar = h('div', { class: 'stack-bar', role: 'img', 'aria-label': cats.filter(c => !c.background).slice(0, 4)
    .map(c => `${c.label} ${(100 * c.share).toFixed(0)} %`).join(', ') || 'background only' });
  let bg = 0;
  for (const c of cats) {
    if (c.background && !showBackground) { bg += c.share; continue; }
    bar.append(h('span', { style: { width: `${100 * c.share}%`, background: catColor(c.category) },
      title: `${c.label}: ${(100 * c.share).toFixed(1)} % of the lookups${c.background ? ' (background)' : ''}` }));
  }
  if (bg > 0) bar.append(h('span', { class: 'bg', style: { width: `${100 * bg}%` }, title: `Background (not use): ${(100 * bg).toFixed(1)} %` }));
  return bar;
}

async function mountCategories(main, selected) {
  let showBackground = false;
  const listBox = h('div');
  const detailBox = h('div');
  const bgToggle = h('label', { class: 'check small' }, h('input', { type: 'checkbox', onchange: e => { showBackground = e.target.checked; load(); } }),
    'show background categories one by one');
  main.append(h('div', { class: 'row small' }, h('a', { href: '#/dns' }, '← DNS usage')),
    pageHead('Categories per device', 'How the lookups of each device split into categories. Pick a device for lookups, active hours and - where possible - an estimate per category.'),
    h('div', { class: 'card' }, h('div', { class: 'row' }, rangePicker(load), h('span', { class: 'spacer' }), bgToggle)),
    h('div', { class: 'banner info', style: { margin: '12px 0' } }, h('b', null, 'Not usage time'),
      h('span', null, 'DNS lookups show that a device asked for names - also in the background, also without anyone watching. '
        + 'Grey parts are background (infrastructure, network checks, telemetry, updates).')),
    h('div', { class: 'grid grid-2' }, h('div', { class: 'card' }, listBox), h('div', { class: 'card' }, detailBox)));

  async function load() {
    clear(listBox).append(h('div', { class: 'skeleton' }, 'Loading…'));
    let r;
    try { r = await api(`api/dns/categories?${qs()}`); } catch (e) { clear(listBox).append(naBox(`Not available - ${e.message}`)); return; }
    clear(listBox).append(h('div', { class: 'card-head' }, h('h2', null, `Devices (${r.clients.length})`),
      h('span', { class: 'sub' }, r.resolution === 'hour' ? 'exact hours' : 'whole days')));
    if (!r.clients.length) { listBox.append(naBox('No lookups in this range.')); return; }
    const ul = h('ul', { class: 'list device-cats' });
    for (const d of r.clients) {
      const top = d.categories.filter(c => !c.background).slice(0, 3);
      const li = h('li', { class: `click${d.client.id === selected ? ' selected' : ''}`, tabindex: '0' },
        h('div', { class: 'row' }, h('b', null, d.client.name), d.client.basis === 'ip' ? basisBadge('ip') : null,
          h('span', { class: 'spacer' }), h('span', { class: 'small muted' }, `${n(d.queries)} lookups`)),
        stackedBar(d.categories, showBackground),
        h('div', { class: 'small secondary' }, top.length
          ? top.map(c => `${c.label} ${(100 * c.share).toFixed(1)} %`).join(' · ')
          : 'only background lookups'));
      const pick = () => { selected = d.client.id; history.replaceState(null, '', `#/dns/categories/${selected}`); load(); };
      li.addEventListener('click', pick);
      li.addEventListener('keydown', ev => { if (ev.key === 'Enter') pick(); });
      ul.append(li);
    }
    listBox.append(ul, h('div', { class: 'small muted' }, r.note));
    if (selected === null || !r.clients.some(d => d.client.id === selected)) selected = r.clients[0].client.id;
    loadDetail();
  }

  async function loadDetail() {
    clear(detailBox).append(h('div', { class: 'skeleton' }, 'Loading…'));
    let r;
    try { r = await api(`api/dns/clients/${selected}/categories?${qs()}`); } catch (e) { clear(detailBox).append(naBox(`Not available - ${e.message}`)); return; }
    const fg = r.categories.filter(c => !c.background), bg = r.categories.filter(c => c.background);
    const row = c => h('tr', { title: c.description || '' },
      h('td', null, catBadge(c.category)),
      h('td', { class: 'num' }, n(c.queries)), h('td', { class: 'num' }, `${(100 * c.share).toFixed(1)} %`),
      h('td', { class: 'num' }, c.active_hours === null || c.active_hours === undefined ? NA : n(c.active_hours)),
      h('td', { class: 'num' }, c.background ? h('span', { class: 'muted' }, 'background')
        : c.estimate_seconds ? h('span', { title: `from: ${c.estimated_services.join(', ')}` }, fmtEstimate(c.estimate_seconds),
          h('span', { class: 'small muted' }, ` (${c.estimate_confidence})`))
          : h('span', { class: 'muted', title: c.services_without_estimate.length
            ? `not reliably determinable for: ${c.services_without_estimate.join(', ')}` : 'lookups of this category belong to no single service' }, 'no estimate')));
    const head = h('thead', null, h('tr', null, h('th', null, 'Category'), h('th', { class: 'num' }, 'Lookups'), h('th', { class: 'num' }, 'Share'),
      h('th', { class: 'num', title: 'Clock hours with at least one allowed lookup' }, 'Active hours'),
      h('th', { class: 'num', title: 'Sum of the per-service DNS estimates' }, 'Est. activity')));
    // native append() would print a null as the text "null" - h() skips it
    clear(detailBox).append(...[
      h('div', { class: 'card-head' }, h('h2', null, r.client.name), h('a', { class: 'small', href: `#/dns/client/${r.client.id}` }, 'all details →')),
      h('div', { class: 'small muted' }, `${n(r.queries)} lookups, ${n(r.blocked)} of them blocked`),
      fg.length ? h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' }, head, h('tbody', null, fg.map(row))))
        : naBox('Only background lookups in this range.'),
      bg.length ? h('details', { class: 'glossary' }, h('summary', null, `Background, not use (${(100 * bg.reduce((a, c) => a + c.share, 0)).toFixed(1)} % of the lookups)`),
        h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' }, h('tbody', null, bg.map(row))))) : null,
      r.minutes_note ? h('div', { class: 'small muted' }, r.minutes_note) : null,
      h('div', { class: 'small muted' }, 'Active hours: clock hours with at least one allowed lookup of the category. '
        + 'Est. activity: only where single services allow a DNS-based estimate (see the activity phases on the device page); '
        + 'categories from the UT1 lists (adult, gambling, dating, ...) never get one.')].filter(Boolean));
  }
  await load();
}

// ------------------------------------------------------------------ DNS past Pi-hole
const BYPASS_BADGE = { bypassing: 'critical', partial: 'warning', complete: 'good' };

function bypassCard() {
  const card = h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', null, 'DNS past Pi-hole'),
    h('span', { class: 'sub' }, 'devices whose numbers are probably incomplete (7 days)')), h('div', { class: 'skeleton' }, 'Loading…'));
  api('api/dns/bypass').then(r => {
    card.lastChild.remove();
    const flagged = r.devices.filter(d => d.level !== 'complete');
    if (!flagged.length) {
      card.append(naBox(`No sign of DNS past Pi-hole for ${r.devices.length} devices.`));
    } else {
      card.append(h('ul', { class: 'list' }, flagged.map(d => h('li', null,
        h('div', { class: 'row' }, d.client.id ? h('a', { href: `#/dns/client/${d.client.id}` }, d.client.name) : h('b', null, d.client.name),
          h('span', { class: 'spacer' }), h('span', { class: `badge ${BYPASS_BADGE[d.level]}` }, d.level === 'bypassing' ? 'largely missing' : 'probably incomplete')),
        d.reasons.map(x => h('div', { class: 'small secondary' }, `• ${x}`))))));
    }
    if (r.presence_note) card.append(h('div', { class: 'small muted' }, r.presence_note));
    card.append(h('div', { class: 'small muted' }, r.note));
  }).catch(e => { card.lastChild.replaceWith(naBox(`Not available - ${e.message}`)); });
  return card;
}

function upstreamCard() {
  const card = h('div', { class: 'card stack' }, h('div', { class: 'card-head' }, h('h2', null, 'Upstream DNS servers'),
    h('span', { class: 'sub' }, 'how fast the servers behind Pi-hole answer - from its log, nothing extra is sent')),
  h('div', { class: 'skeleton' }, 'Loading…'));
  api(`api/dns/upstreams?${qs()}`).then(r => {
    card.lastChild.remove();
    if (!r.available) { card.append(naBox(r.error)); return; }
    (r.notes || []).forEach(x => card.append(h('div', { class: 'small secondary' }, `• ${x}`)));
    if (!r.servers.length) return;
    card.append(upstreamTable(r.servers));
    const box = h('div');
    card.append(h('div', { class: 'chart-title' }, h('h3', null, 'Median reply time'),
      h('span', { class: 'muted small' }, `per ${r.bucket >= 3600 ? `${r.bucket / 3600} h` : `${r.bucket / 60} min`}, gaps = nothing forwarded`)), box);
    const xs = [];
    for (let t = Math.floor(r.start / r.bucket) * r.bucket; t < r.end; t += r.bucket) xs.push(t);
    const shown = r.servers.slice(0, 6);
    const chart = timeChart(box, shown.map((s, i) => ({ label: s.name ? `${s.upstream} (${s.name})` : s.upstream,
      color: cssVar(`--series-${i + 1}`), fmt: v => `${v.toFixed(1)} ms` })), { height: 170, yFmt: v => `${v}`, yLabel: 'ms' });
    chart.setData([xs, ...shown.map(s => { const by = new Map(s.series.map(p => [p.ts, p.median_ms])); return xs.map(t => by.get(t) ?? null); })]);
    card.append(h('div', { class: 'small muted' }, '"No reply recorded": the server did not answer, or Pi-hole asked again and another server answered first. Answers from the cache never reach these servers.'));
  }).catch(e => { card.lastChild.replaceWith(naBox(`Not available - ${e.message}`)); });
  return card;
}

// ------------------------------------------------------------------ not categorized yet
function uncategorizedCard(reload) {
  const card = h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', null, 'Not categorized yet'),
    h('span', { class: 'sub' }, 'names no rule knows - busiest first')), h('div', { class: 'skeleton' }, 'Loading…'));
  api(`api/dns/uncategorized?${qs()}&limit=25`).then(r => {
    card.lastChild.remove();
    card.append(h('div', { class: 'small muted' }, r.queries
      ? `${pct(r.unknown_queries, r.queries)} of the lookups in this range match no rule, from ${n(r.group_count)} owners. `
        + 'Click a name to see who asked for it and to give it a category.' : 'No lookups in this range.'));
    if (!r.groups.length) { card.append(naBox('Every looked-up name matches a rule.')); return; }
    card.append(h('ul', { class: 'list' }, r.groups.map(g => h('li', null,
      h('div', { class: 'row' }, domainLink(g.names[0], { ...domCtx(), suggestion: g.group, onChange: reload }),
        g.name_count > 1 ? h('span', { class: 'small muted' }, `+${g.name_count - 1} more under ${g.group}`) : null,
        h('span', { class: 'spacer' }), h('b', { class: 'num' }, pct(g.queries, r.queries)))))));
  }).catch(e => { card.lastChild.replaceWith(naBox(`Not available - ${e.message}`)); });
  return card;
}

// ------------------------------------------------------------------ what the numbers mean
function glossaryCard() {
  const item = (term, text) => h('li', null, h('b', null, term), h('div', { class: 'small secondary' }, text));
  return h('div', { class: 'card' }, h('details', { class: 'glossary' }, h('summary', null, h('h2', { style: { display: 'inline' } }, 'What these numbers mean')),
    h('ul', { class: 'list' },
      item('Lookup (DNS query)', 'A device asked Pi-hole for the address of a name. Apps do this on their own - for updates, ads, sync, push messages. A lookup is not a visit, not usage time and not data volume.'),
      item('Blocked', 'Pi-hole answered with "does not exist" because the name is on a blocklist or your denylist. The device got nothing from it.'),
      item('Retries', 'The same question again while the first one was still open. Counted separately, not as lookups.'),
      item('Device vs. "IP only"', 'Lookups are assigned to a device through the MAC address Pi-hole knows for the IP. Without it the IP is shown - it can belong to different devices over time.'),
      item('Category', 'Comes from rules: the shipped list, the UT1 list (if imported) or your own rules. Each one shows its source and confidence. "Not categorized yet" means no rule matched - not that it is harmless.'),
      item('Shared infrastructure', 'CDNs and cloud platforms (CloudFront, Akamai, Google, Apple, Microsoft) deliver for countless services. The provider is known, the service behind it is not.'),
      item('Network & connectivity', 'Devices checking whether the internet works, asking for the time or for names inside the home. Background, never use.'),
      item('What DNS cannot see', 'Lookups that bypass Pi-hole: DNS over HTTPS in browsers, iCloud Private Relay, VPNs, devices with a fixed foreign DNS server. They are missing here completely.'))));
}

const ID_STATUS = {
  consistent: ['Consistent', 'good', 'Same device and IP in FRITZ!Box and Pi-hole.'],
  ip_mismatch: ['IP differs', 'warning', 'Same device, different IP - usually a stale entry on one side.'],
  ip_conflict: ['IP conflict', 'critical', 'This IP belongs to different devices in the two sources.'],
  not_using_pihole: ['Not using Pi-hole', 'critical', 'Active in the FRITZ!Box, but never asked Pi-hole - resolves names elsewhere.'],
  fritz_only_inactive: ['FRITZ!Box only', '', 'Known to the FRITZ!Box, currently inactive, never seen by Pi-hole.'],
  pihole_only: ['Pi-hole only', '', 'Known to Pi-hole only (older device, or no longer listed by the FRITZ!Box).'],
};

/** FRITZ!Box vs Pi-hole: can the per-device numbers be trusted? */
function identificationCard() {
  const card = h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', null, 'Client identification'),
    h('span', { class: 'sub' }, 'FRITZ!Box host list compared with Pi-hole')), h('div', { class: 'skeleton' }, 'Comparing…'));
  api('api/dns/identification').then(r => {
    clear(card).append(h('div', { class: 'card-head' }, h('h2', null, 'Client identification'),
      h('span', { class: 'sub' }, r.fritz_hosts_at ? 'FRITZ!Box list from ' + ago(r.fritz_hosts_at) : 'FRITZ!Box host list compared with Pi-hole')));
    if (r.fritz_note) card.append(h('div', { class: 'small muted' }, r.fritz_note));
    if (r.fritz_available) {
      card.append(h('div', { class: 'row small' },
        h('b', null, r.consistent_share === null ? NA : (100 * r.consistent_share).toFixed(0) + ' % consistent'),
        h('span', { class: 'muted' }, 'of ' + r.in_both + ' devices known to both · FRITZ!Box ' + r.fritz_devices + ' · Pi-hole ' + r.pihole_devices)));
    }
    for (const f of r.findings) card.append(h('div', { class: 'banner warn', style: { marginTop: '8px' } }, h('span', null, f)));
    if (!r.rows.length) return;
    const order = ['not_using_pihole', 'ip_conflict', 'ip_mismatch', 'consistent', 'fritz_only_inactive', 'pihole_only'];
    const rows = [...r.rows].sort((a, b) => order.indexOf(a.status) - order.indexOf(b.status));
    card.append(h('details', { style: { marginTop: '10px' } }, h('summary', { class: 'small' }, 'Show all ' + rows.length + ' devices'),
      h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' },
        h('thead', null, h('tr', null, h('th', null, 'Status'), h('th', null, 'Name (FRITZ!Box / Pi-hole)'), h('th', null, 'MAC'),
          h('th', null, 'IP FRITZ!Box'), h('th', null, 'IPs Pi-hole'), h('th', null, 'Connection'))),
        h('tbody', null, rows.map(x => {
          const [label, cls, title] = ID_STATUS[x.status] || [x.status, '', ''];
          return h('tr', null,
            h('td', null, h('span', { class: 'badge ' + cls, title }, label)),
            h('td', null, x.fritz_name || '–', h('div', { class: 'small muted' }, x.pihole_name || '–')),
            h('td', { class: 'mono' }, x.mac, x.randomized ? h('div', { class: 'small muted' }, 'randomized') : null),
            h('td', { class: 'mono' }, x.fritz_ip || '–'),
            h('td', { class: 'mono' }, x.pihole_ips.join(', ') || '–'),
            h('td', { class: 'small' }, x.interface || '–', x.active === false ? h('div', { class: 'muted' }, 'inactive') : null));
        }))))));
  }).catch(e => { clear(card).append(naBox('Not available - ' + e.message)); });
  return card;
}

function clientsCard(cl) {
  const search = h('input', { type: 'search', placeholder: 'Search name, IP or MAC…', 'aria-label': 'Search clients', style: { minWidth: '220px' } });
  const tbody = h('tbody');
  const card = h('div', { class: 'card' },
    h('div', { class: 'card-head' }, h('h2', null, `Clients (${cl.clients.length})`),
      h('div', { class: 'row' }, search, refreshNamesButton(() => window.dispatchEvent(new HashChangeEvent('hashchange'))))),
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
          h('div', { class: 'small mono muted' }, [c.ip, c.mac].filter(Boolean).join(' · '), c.vendor ? ` · ${c.vendor}` : '',
            c.connection ? ' · ' + c.connection : '')),
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
    h('div', { style: { minWidth: 0, flex: 1 } }, h('div', { style: { overflowWrap: 'anywhere' } }, domainLink(r.domain, domCtx())),
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
    api('api/dns/bypass').then(r => {
      const me = r.devices.find(d => d.client.id === cid);
      if (me && me.level !== 'complete') {
        body.prepend(h('div', { class: `banner ${me.level === 'bypassing' ? 'warn' : 'info'}` }, h('b', null, me.text),
          h('span', null, me.reasons.join(' '))));
      }
    }).catch(() => null);

    const chartBox = h('div');
    body.append(h('div', { class: 'card chart-card' },
      h('div', { class: 'chart-title' }, h('h3', null, 'DNS activity per hour'), h('span', { class: 'muted small' }, 'hatched = not recorded')),
      chartBox));
    hourlyChart(chartBox, hr.hours, hr.start, hr.end, st.data_from ?? null);

    const top = s.top_domains.length ? h('ul', { class: 'list' }, s.top_domains.map(d => h('li', { class: 'row' },
      h('span', { style: { overflowWrap: 'anywhere' } }, domainLink(d.domain, domCtx())), h('span', { class: 'spacer' }),
      catBadge(d.category, d.classification), h('span', { class: 'num' }, n(d.queries))))) : naBox('No domains in this range.');
    body.append(h('div', { class: 'grid grid-2' },
      h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', null, 'Categories'), h('span', { class: 'sub' }, 'share of queries, rule based')),
        categoryBars(s.categories),
        cmp ? comparisonList(cmp.categories) : null),
      h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', null, 'Top domains')), top,
        rangeNote(s.domains_resolution, s.domains_range))));

    body.append(activityCard(cid));
    if (s.client.mac) body.append(connectionsCard(s.client.mac));
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
      exportMenu([
        ['This client (all tables)', 'xlsx', 'client', () => ({ client: cid, gap: phaseGap })],
        ['Domain list (current filters)', 'csv', 'domains', () => ({ client: cid, status: filt.status, category: filt.category, q: filt.q, sort: filt.sort })],
        ['Category statistics', 'csv', 'categories', () => ({ client: cid })],
        ['Blocked domains', 'csv', 'blocked', () => ({ client: cid })],
        ['Time series (per hour)', 'csv', 'timeseries', () => ({ client: cid })],
        ['Activity phases', 'csv', 'phases', () => ({ client: cid, gap: phaseGap })],
      ]),
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
          h('td', { style: { overflowWrap: 'anywhere' } }, domainLink(d.other ? null : d.domain, domCtx())),
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

// ------------------------------------------------------------------ measured connections (TLS server names)
function connectionsCard(mac) {
  const card = h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('div', null, h('h2', null, 'Measured connections'),
    h('div', { class: 'sub' }, 'from the TLS server names in the FRITZ!Box capture - measured, not estimated')), h('div', { class: 'skeleton' }, 'Loading…')));
  const [s, e] = currentRange();
  api(`api/devices/${encodeURIComponent(mac)}/connections?start=${s}&end=${e}`).then(r => {
    card.lastChild.remove();
    if (r.hint) card.append(h('div', { class: 'banner info', style: { margin: '0 0 10px' } }, h('b', null, 'Note'), h('span', null, r.hint)));
    const cv = r.coverage;
    card.append(h('div', { class: 'small muted' }, cv.bytes
      ? `${fmtBytesShort(cv.named_bytes)} of ${fmtBytesShort(cv.bytes)} (${(100 * cv.named_share).toFixed(0)} %) of this device's traffic have a server name`
        + (cv.quic_unnamed_bytes ? `; ${(100 * cv.quic_unnamed_share).toFixed(0)} % is QUIC (HTTP/3) without a readable name.` : '.')
      : `No connections recorded in this range (kept ${r.retention_days} days).`));
    if (!r.services.length) { card.append(naBox('No connection with a server name in this range.')); card.append(h('div', { class: 'small muted' }, r.note)); return; }
    card.append(h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' },
      h('thead', null, h('tr', null, h('th', null, 'Service'), h('th', null, 'Category'), h('th', { class: 'num' }, 'Sessions'),
        h('th', { class: 'num' }, 'Connected'), h('th', { class: 'num' }, 'Data'), h('th', null, 'Last'))),
      h('tbody', null, r.services.slice(0, 30).map(x => h('tr', { title: x.servers.join(', ') },
        h('td', null, x.name), h('td', null, catBadge(x.category)), h('td', { class: 'num' }, n(x.session_count)),
        h('td', { class: 'num' }, fmtEstimate(x.seconds) ? fmtEstimate(x.seconds).replace('~', '') : '< 1 min'),
        h('td', { class: 'num' }, fmtBytesShort(x.bytes)),
        h('td', { class: 'small muted' }, fmtDateTime(x.sessions[x.sessions.length - 1].end))))))));
    card.append(h('div', { class: 'small muted' }, r.note));
  }).catch(err => { card.lastChild.replaceWith(naBox(`Not available - ${err.message}`)); });
  return card;
}
function fmtBytesShort(b) {
  if (!b) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB']; let i = 0;
  while (b >= 1000 && i < u.length - 1) { b /= 1000; i++; }
  return `${b.toFixed(b >= 100 || i === 0 ? 0 : 1)} ${u[i]}`;
}

// ------------------------------------------------------------------ activity phases (estimated)
const GAPS = [[0, 'Default'], [2, '2 min'], [5, '5 min'], [10, '10 min'], [15, '15 min'], [30, '30 min']];
let phaseGap = 0;

function fmtMinutes(s) {
  if (s < 3600) return `${Math.round(s / 60)} min`;
  return `${Math.floor(s / 3600)} h ${Math.round((s % 3600) / 60)} min`;
}

function activityCard(cid) {
  const body = h('div');
  const card = h('div', { class: 'card' },
    h('div', { class: 'card-head' }, h('h2', null, 'Activity phases (estimated)'),
      h('div', { class: 'row small' }, h('span', { class: 'muted' }, 'Pause that ends a phase:'),
        segmented(GAPS, phaseGap, v => { phaseGap = v; load(); }))),
    h('p', { class: 'small muted' }, 'Estimated from DNS lookups - not verified screen or app usage time. ',
      'A phase runs from the first to the last lookup of a service; pauses longer than the chosen gap end it and are not counted.'),
    body);
  async function load() {
    clear(body).append(h('div', { class: 'skeleton' }, 'Computing phases from the Pi-hole log…'));
    let r;
    try { r = await api(`api/dns/clients/${cid}/activity?${qs()}${phaseGap ? `&gap=${phaseGap}` : ''}`); }
    catch (e) { clear(body).append(naBox(`Not available - ${e.message}`)); return; }
    clear(body);
    if (r.rebuild_note) body.append(h('div', { class: 'banner warn' }, h('b', null, 'Rebuilding'), h('span', null, r.rebuild_note)));
    if (r.coverage_note) body.append(h('div', { class: 'small muted' }, r.coverage_note));
    if (!r.services.length) { body.append(naBox('No lookups that can be attributed to a service in this range.')); return; }
    body.append(h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' },
      h('thead', null, h('tr', null, h('th', null, 'Service'), h('th', { class: 'num' }, 'DNS queries'),
        h('th', { class: 'num' }, 'Phases'), h('th', null, 'Estimated activity'), h('th', null, 'Confidence'))),
      h('tbody', null, r.services.map(s => h('tr', null,
        h('td', null, h('div', null, s.name), h('div', { class: 'small' }, catBadge(s.category)),
          s.gap_minutes !== (r.gap_minutes || r.default_gap_minutes) ? h('div', { class: 'small muted' }, `gap ${s.gap_minutes} min`) : null),
        h('td', { class: 'num' }, n(s.queries), s.blocked ? h('div', { class: 'small muted' }, `${n(s.blocked)} blocked`) : null),
        h('td', { class: 'num' }, n(s.phase_count)),
        h('td', null, s.estimate_seconds === null
          ? h('span', { class: 'muted' }, 'Not reliably determinable')
          : h('b', null, `≈ ${fmtMinutes(s.estimate_seconds)}`)),
        h('td', { class: 'small' }, s.confidence ? h('span', { class: `badge conf-${s.confidence === 'medium' ? 'medium' : 'low'}` }, s.confidence) : null,
          h('div', { class: 'muted', style: { maxWidth: '360px' } }, s.reason))))))));
    body.append(phaseLanes(r));
    const un = Object.entries(r.unattributed || {});
    if (un.length) {
      body.append(h('div', { class: 'small muted', style: { marginTop: '8px' } },
        `${n(un.reduce((a, [, v]) => a + v, 0))} lookups could not be attributed to a service: `,
        un.map(([c, v]) => `${catLabel(c)} ${n(v)}`).join(', '), '.'));
    }
    body.append(h('details', { class: 'small', style: { marginTop: '12px' } },
      h('summary', null, 'Why this is only an estimate'),
      h('ul', null, r.explanation.map(e => h('li', null, e)))));
  }
  load();
  return card;
}

/** One lane per service with phases, plus "all services" on top. Bars are positioned in % of the range. */
function phaseLanes(r) {
  const span = r.end - r.start;
  const pos = t => `${Math.max(0, Math.min(100, 100 * (t - r.start) / span))}%`;
  const width = p => `max(2px, ${100 * Math.max(0, Math.min(p.end, r.end) - Math.max(p.start, r.start)) / span}%)`;
  const lane = (label, phases, color, title) => h('div', { class: 'phase-lane' },
    h('div', { class: 'phase-label small', title: title || label }, label),
    h('div', { class: 'phase-track' }, phases.map(p => h('span', {
      class: 'phase-bar', style: { left: pos(p.start), width: width(p), background: color },
      title: `${fmtDateTime(p.start)} – ${fmtTime(p.end)} · ${fmtMinutes(p.seconds)} · ${p.queries} lookups`,
    }))));
  const services = r.services.filter(s => s.phases.length && s.estimate_seconds !== null).slice(0, 10);
  if (!services.length && !r.overall.length) return h('div');
  return h('div', { class: 'phase-lanes', style: { marginTop: '14px' } },
    lane('All services', r.overall, cssVar('--text-secondary'), 'Phases of any foreground service (at least 3 lookups)'),
    services.map(s => lane(s.name, s.phases, catColor(s.category))),
    h('div', { class: 'phase-lane' }, h('div'), h('div', { class: 'phase-axis small muted' },
      h('span', null, fmtDateTime(r.start)), h('span', null, fmtDateTime(r.end)))));
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
    const ut1 = (r.layers || []).find(l => l.source === 'ut1');
    listCard.append(h('div', { class: 'small muted' }, ut1
      ? `UT1 lists: ${n(ut1.rules)} names, list of ${ut1.list_date ? fmtDate(ut1.list_date) : 'unknown date'}, imported ${ut1.imported ? fmtDate(ut1.imported) : '–'}. `
        + (r.ut1_auto_update ? `Checked for updates every ${r.ut1_update_days} days at night.` : 'Automatic update is off.')
        + (r.ut1_refresh && !r.ut1_refresh.ok ? ` Last update failed: ${r.ut1_refresh.error}` : '')
      : 'UT1 lists not imported (optional, see docs/dns-usage.md).'));
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
