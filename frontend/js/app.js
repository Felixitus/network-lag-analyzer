// Einstieg: Routing, Live-Stream (SSE), Banner, Theme, Login.
import { api, clear, h, toast } from './lib.js';
import { destroyAll } from './charts.js';
import * as dashboard from './pages/dashboard.js';
import * as timeline from './pages/timeline.js';
import * as incidents from './pages/incidents.js';
import * as devices from './pages/devices.js';
import * as gaming from './pages/gaming.js';
import * as settings from './pages/settings.js';

export const store = {
  status: null,
  listeners: new Set(),
  on(fn) { this.listeners.add(fn); return () => this.listeners.delete(fn); },
  emit(kind, data) { for (const fn of this.listeners) { try { fn(kind, data); } catch (e) { console.error(e); } } },
};

const routes = { dashboard, timeline, incidents, incident: incidents, devices, gaming, settings };
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
    if (e.status !== 401) main.append(h('div', { class: 'card' }, h('h3', null, 'Fehler beim Laden'), h('p', { class: 'muted' }, String(e.message || e))));
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
  es.onerror = () => { pill.textContent = '● Getrennt – verbinde neu…'; pill.className = 'pill pill-bad'; };
}

// ------------------------------------------------------------------ Banner
export async function refreshStatus() {
  try {
    store.status = await api('api/status');
  } catch (e) { return; }
  const s = store.status;
  const b = clear(document.getElementById('banners'));
  if (s.dev_mode) {
    b.append(h('div', { class: 'banner demo' }, h('b', null, 'DEMO-MODUS'),
      h('span', null, 'Alle angezeigten Werte sind simuliert (dev_mode). Für echte Messungen dev_mode in der config.yaml deaktivieren.')));
  }
  if (!s.setup_done && !s.dev_mode) {
    b.append(h('div', { class: 'banner info' }, h('b', null, 'Ersteinrichtung'),
      h('span', null, 'Der Setup-Wizard prüft, welche Daten in deinem Netzwerk tatsächlich messbar sind. '),
      h('a', { href: '#/settings' }, 'Setup öffnen →')));
  }
  if (s.icmp && s.icmp.error) {
    b.append(h('div', { class: 'banner warn' }, h('b', null, 'Ping-Messung nicht möglich'), h('span', null, s.icmp.error)));
  }
  const cap = s.capture || {};
  if (!s.dev_mode && cap.state !== 'running') {
    b.append(h('div', { class: 'banner info' }, h('b', null, 'Traffic pro Gerät: Not available'),
      h('span', null, cap.error || (cap.state === 'paused' ? 'Mitschnitt wegen hoher CPU-Last pausiert.' : `Status: ${cap.state || 'aus'}`)),
      h('a', { href: '#/settings' }, 'Details')));
  }
  const tot = (s.targets || []).filter(t => t.unreachable);
  if (tot.length) {
    b.append(h('div', { class: 'banner warn' }, h('b', null, tot.length > 1 ? 'Ziele antworten nicht' : 'Ziel antwortet nicht'),
      h('span', null, `${tot.map(t => t.name ? `${t.name} (${t.address})` : t.address).join(', ')} `
        + 'beantwortet keine Pings mehr. Das Ziel wird aus Paketverlust und Latenz herausgerechnet, '
        + 'damit es keinen Dauerverlust vortäuscht. '),
      h('a', { href: '#/settings' }, 'Ziel ersetzen →')));
  }
  if (s.system && s.system.level > 0) {
    b.append(h('div', { class: 'banner warn' }, h('b', null, `Load Guard Stufe ${s.system.level}`),
      h('span', null, s.system.level === 1 ? 'Flow-Analyse reduziert, um Pi-hole zu schonen.'
        : s.system.level === 2 ? 'Traffic-Werte werden per Sampling geschätzt (CPU-Last).' : 'Mitschnitt pausiert (Überlast).')));
  }
}

// ------------------------------------------------------------------ Theme
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
    render();   // Charts mit neuen Farben neu aufbauen
  });
}

// ------------------------------------------------------------------ Login
function showLogin() {
  const main = clear(document.getElementById('main'));
  const pw = h('input', { type: 'password', placeholder: 'Passwort', autocomplete: 'current-password' });
  const form = h('form', { class: 'card', style: { maxWidth: '360px', margin: '60px auto' } },
    h('h3', null, 'Anmeldung'), h('p', { class: 'muted' }, 'Der Zugriff auf den Network Lag Analyzer ist geschützt.'),
    h('div', { class: 'stack' }, pw, h('button', { class: 'btn primary', type: 'submit' }, 'Anmelden')));
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
