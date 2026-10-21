// Helpers: DOM (XSS-safe), formatting, API, colors.

/** Create an element. Children: strings are ALWAYS inserted as text (host names are not trustworthy). */
export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
      else if (k === 'dataset') Object.assign(el.dataset, v);
      else el.setAttribute(k, v === true ? '' : String(v));
    }
  }
  append(el, children);
  return el;
}
function append(el, children) {
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    if (Array.isArray(c)) append(el, c);
    else if (c instanceof Node) el.appendChild(c);
    else el.appendChild(document.createTextNode(String(c)));
  }
}
export function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }

// ------------------------------------------------------------------ formatting
export const NA = 'Not available';
export function fmtMs(v, d = 0) { return v === null || v === undefined ? null : (v >= 100 ? v.toFixed(0) : v.toFixed(d || (v < 10 ? 1 : 0))); }
export function fmtMbit(bps) {
  if (bps === null || bps === undefined) return null;
  const m = bps / 1e6;
  return m >= 100 ? m.toFixed(0) : m >= 10 ? m.toFixed(1) : m.toFixed(2);
}
export function fmtRate(bps) { const v = fmtMbit(bps); return v === null ? NA : `${v} Mbit/s`; }
export function fmtPct(v, d = 1) { return v === null || v === undefined ? null : `${v.toFixed(v === 0 ? 0 : d)}`; }
export function fmtBytes(b) {
  if (b === null || b === undefined) return NA;
  const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0;
  while (b >= 1000 && i < u.length - 1) { b /= 1000; i++; }
  return `${b.toFixed(b >= 100 || i === 0 ? 0 : 1)} ${u[i]}`;
}
const pad = n => String(n).padStart(2, '0');
export function fmtTime(ts, sec = true) {
  if (!ts) return '–';
  const d = new Date(ts * 1000);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}${sec ? ':' + pad(d.getSeconds()) : ''}`;
}
export function fmtDate(ts) {
  if (!ts) return '–';
  const d = new Date(ts * 1000);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}
export function fmtDateTime(ts) { return `${fmtDate(ts)} ${fmtTime(ts)}`; }
export function fmtDuration(s) {
  if (s === null || s === undefined) return '–';
  if (s < 60) return `${s < 10 ? s.toFixed(1) : Math.round(s)} s`;
  if (s < 3600) return `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`;
  return `${Math.floor(s / 3600)} h ${Math.round((s % 3600) / 60)} min`;
}
export function ago(ts) {
  const s = Date.now() / 1000 - ts;
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return fmtDateTime(ts);
}

// ------------------------------------------------------------------ API
function csrf() {
  const m = document.cookie.match(/(?:^|; )nla_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : '';
}
export class ApiError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
export async function api(path, { method = 'GET', body, signal } = {}) {
  const opts = { method, headers: {}, signal, credentials: 'same-origin' };
  if (method !== 'GET') opts.headers['X-CSRF-Token'] = csrf();
  if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  const r = await fetch(path, opts);
  if (!r.ok) {
    let msg = `${r.status}`;
    try { const j = await r.json(); msg = typeof j.detail === 'string' ? j.detail : JSON.stringify(j.detail); } catch { /* */ }
    // Not for the login call itself: re-rendering the form would wipe its error message.
    if (r.status === 401 && !path.startsWith('api/auth/')) window.dispatchEvent(new CustomEvent('nla-login'));
    if (r.status === 403 && msg.includes('No account set up')) window.dispatchEvent(new CustomEvent('nla-setup'));
    throw new ApiError(r.status, msg);
  }
  return r.json();
}

export function toast(msg, ms = 3000) {
  const t = document.getElementById('toast');
  t.textContent = msg; t.style.display = 'block';
  clearTimeout(toast._t); toast._t = setTimeout(() => { t.style.display = 'none'; }, ms);
}

// ------------------------------------------------------------------ colors
export function cssVar(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
export const SERIES = n => cssVar(`--series-${n}`);

/** Color follows the device (not the rank): stable slot assignment per MAC, remembered in the browser. */
const SLOT_KEY = 'nla-device-slots';
let slots = {};
try { slots = JSON.parse(localStorage.getItem(SLOT_KEY) || '{}'); } catch { slots = {}; }
export function deviceSlot(mac) {
  if (!(mac in slots)) {
    const used = new Set(Object.values(slots));
    let s = 1; while (used.has(s) && s < 8) s++;
    if (used.has(s)) s = (Object.keys(slots).length % 8) + 1;
    slots[mac] = s;
    try { localStorage.setItem(SLOT_KEY, JSON.stringify(slots)); } catch { /* private mode */ }
  }
  return slots[mac];
}
export const deviceColor = mac => SERIES(deviceSlot(mac));

export function levelFor(value, warn, crit) {
  if (value === null || value === undefined) return null;
  if (crit !== undefined && value >= crit) return 'critical';
  if (value >= warn) return 'warning';
  return 'good';
}

export const EVENT_LABEL = {
  PING_SPIKE: 'Ping spike', PACKET_LOSS: 'Packet loss', HIGH_JITTER: 'High jitter', HIGH_UPLOAD: 'High upload',
  HIGH_DOWNLOAD: 'High download', TCP_RETRANSMISSION_SPIKE: 'TCP retransmissions', CONNECTION_DROP: 'Connection drop',
  DNS_FAILURE: 'DNS failure', GATEWAY_LATENCY: 'Router latency', INTERNET_LATENCY: 'Internet latency', GAME_FLOW_GAP: 'Game packet gap',
};
export const CONF_LABEL = { high: 'likely cause', medium: 'possible cause', low: 'temporally correlated' };
export const CONF_SHORT = { high: 'High', medium: 'Medium', low: 'Low' };

export function confBadge(conf) {
  if (!conf) return null;
  return h('span', { class: `badge conf-${conf}`, title: CONF_LABEL[conf] }, `Confidence: ${CONF_SHORT[conf] || conf}`);
}
export function statusIcon(ok) {
  return ok === true ? h('span', { class: 'ic ok', 'aria-label': 'ok' }, '✓')
    : ok === false ? h('span', { class: 'ic bad', 'aria-label': 'not available' }, '✗')
      : h('span', { class: 'ic unk', 'aria-label': 'unknown' }, '?');
}
