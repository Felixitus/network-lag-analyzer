// Entry point: routing, live stream (SSE), banners, theme, login.
import { api, clear, h, toast } from './lib.js';
import { destroyAll } from './charts.js';
import * as dashboard from './pages/dashboard.js';
import * as timeline from './pages/timeline.js';
import * as incidents from './pages/incidents.js';
import * as devices from './pages/devices.js';
import * as dns from './pages/dns.js';
import * as gaming from './pages/gaming.js';
import * as settings from './pages/settings.js';

export const store = {
  status: null,
  listeners: new Set(),
  on(fn) { this.listeners.add(fn); return () => this.listeners.delete(fn); },
  emit(kind, data) { for (const fn of this.listeners) { try { fn(kind, data); } catch (e) { console.error(e); } } },
};

const routes = { dashboard, timeline, incidents, incident: incidents, devices, dns, gaming, settings };
let current = null;

function parseHash() {
  const parts = location.hash.replace(/^#\/?/, '').split('/').filter(Boolean);
  const name = parts[0] || 'dashboard';
  return { name: routes[name] ? name : 'dashboard', args: parts.slice(1) };
}

async function render() {
  const { name, args } = parseHash();
  if (current && current.unmount) current.unmount();
  destroyAll();
  const main = clear(document.getElementById('main'));
  document.querySelectorAll('#nav a').forEach(a => a.classList.toggle('active',
    a.dataset.route === name || (name === 'incident' && a.dataset.route === 'incidents')));
  const mod = routes[name];
  current = mod;
  try {
    await mod.mount(main, { args, route: name, store, refreshStatus });
  } catch (e) {
    console.error(e);
    if (e.status !== 401) main.append(h('div', { class: 'card' }, h('h3', null, 'Error while loading'), h('p', { class: 'muted' }, String(e.message || e))));
  }
  window.scrollTo(0, 0);
}

// ------------------------------------------------------------------ Live-Stream
let es = null;
function connect() {
  const pill = document.getElementById('live-pill');
  es = new EventSource('api/stream');
  es.addEventListener('hello', () => { pill.textContent = '● Live'; pill.className = 'pill pill-good'; });
  for (const kind of ['tick', 'tick_patch', 'event', 'incident', 'gaming']) {
    es.addEventListener(kind, ev => store.emit(kind, JSON.parse(ev.data)));
  }
  es.onerror = () => { pill.textContent = '● Disconnected - reconnecting…'; pill.className = 'pill pill-bad'; };
}

// ------------------------------------------------------------------ Banner
export async function refreshStatus() {
  try {
    store.status = await api('api/status');
  } catch (e) { return; }
  const s = store.status;
  const b = clear(document.getElementById('banners'));
  if (s.dev_mode) {
    b.append(h('div', { class: 'banner demo' }, h('b', null, 'DEMO MODE'),
      h('span', null, 'All values shown are simulated (dev_mode). For real measurements disable dev_mode in config.yaml.')));
  }
  if (!s.setup_done && !s.dev_mode) {
    b.append(h('div', { class: 'banner info' }, h('b', null, 'First-time setup'),
      h('span', null, 'The setup wizard checks which data can actually be measured in your network. '),
      h('a', { href: '#/settings' }, 'Open setup →')));
  }
  if (s.icmp && s.icmp.error) {
    b.append(h('div', { class: 'banner warn' }, h('b', null, 'Ping measurement not possible'), h('span', null, s.icmp.error)));
  }
  const cap = s.capture || {};
  if (!s.dev_mode && cap.state !== 'running') {
    b.append(h('div', { class: 'banner info' }, h('b', null, 'Traffic per device: Not available'),
      h('span', null, cap.error || (cap.state === 'paused' ? 'Capture paused because of high CPU load.' : `Status: ${cap.state || 'off'}`)),
      h('a', { href: '#/settings' }, 'Details')));
  }
  const tot = (s.targets || []).filter(t => t.unreachable);
  if (tot.length) {
    b.append(h('div', { class: 'banner warn' }, h('b', null, tot.length > 1 ? 'Targets not answering' : 'Target not answering'),
      h('span', null, `${tot.map(t => t.name ? `${t.name} (${t.address})` : t.address).join(', ')} `
        + 'no longer answers pings. The target is excluded from packet loss and latency '
        + 'so that it does not fake a permanent loss. '),
      h('a', { href: '#/settings' }, 'Replace target →')));
  }
  if (s.system && s.system.level > 0) {
    b.append(h('div', { class: 'banner warn' }, h('b', null, `Load Guard level ${s.system.level}`),
      h('span', null, s.system.level === 1 ? 'Flow analysis reduced to spare Pi-hole.'
        : s.system.level === 2 ? 'Traffic values are estimated by sampling (CPU load).' : 'Capture paused (overload).')));
  }
}

// ------------------------------------------------------------------ theme
function initTheme() {
  let t = null;
  try { t = localStorage.getItem('nla-theme'); } catch { /* */ }
  if (t) document.documentElement.dataset.theme = t;
  document.getElementById('theme-toggle').addEventListener('click', () => {
    const cur = document.documentElement.dataset.theme
      || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    const next = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem('nla-theme', next); } catch { /* */ }
    render();   // rebuild charts with the new colors
  });
}

// ------------------------------------------------------------------ login
function showLogin() {
  const main = clear(document.getElementById('main'));
  const pw = h('input', { type: 'password', placeholder: 'Password', autocomplete: 'current-password' });
  const form = h('form', { class: 'card', style: { maxWidth: '360px', margin: '60px auto' } },
    h('h3', null, 'Sign in'), h('p', { class: 'muted' }, 'Access to the Network Lag Analyzer is protected.'),
    h('div', { class: 'stack' }, pw, h('button', { class: 'btn primary', type: 'submit' }, 'Sign in')));
  form.addEventListener('submit', async ev => {
    ev.preventDefault();
    try { await api('api/auth/login', { method: 'POST', body: { password: pw.value } }); location.reload(); }
    catch (e) { toast(e.message); }
  });
  main.append(form);
  pw.focus();
}
window.addEventListener('nla-login', showLogin);

async function boot() {
  initTheme();
  try {
    const st = await api('api/auth/state');
    if (st.login_enabled && !st.logged_in) { showLogin(); return; }
  } catch { /* */ }
  await refreshStatus();
  connect();
  setInterval(refreshStatus, 15000);
  window.addEventListener('hashchange', render);
  render();
}
boot();
