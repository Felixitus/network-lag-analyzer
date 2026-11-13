// Helpers of the web UI. Run: node --test tests/frontend/*.test.mjs (the CI writes frontend/package.json first)
import assert from 'node:assert/strict';
import { beforeEach, test } from 'node:test';

import { install } from './fake_dom.mjs';

install();
const lib = await import('../../frontend/js/lib.js');
const { buildMarkers } = await import('../../frontend/js/pages/common.js');

beforeEach(() => { install(); });

test('what was not measured stays not available instead of becoming zero', () => {
  assert.equal(lib.fmtMs(null), null);
  assert.equal(lib.fmtMbit(undefined), null);
  assert.equal(lib.fmtPct(null), null);
  assert.equal(lib.fmtRate(null), lib.NA);
  assert.equal(lib.fmtBytes(null), lib.NA);
  assert.equal(lib.levelFor(null, 50, 100), null);
  assert.equal(lib.fmtMs(0), '0.0');
  assert.equal(lib.fmtRate(0), '0.00 Mbit/s');
});

test('numbers are rounded to the digits that still mean something', () => {
  assert.equal(lib.fmtMs(4.26), '4.3');
  assert.equal(lib.fmtMs(18.4), '18');
  assert.equal(lib.fmtMs(184.4), '184');
  assert.equal(lib.fmtMbit(38.8e6), '38.8');
  assert.equal(lib.fmtBytes(1_500_000), '1.5 MB');
  assert.equal(lib.fmtDuration(4.2), '4.2 s');
  assert.equal(lib.fmtDuration(125), '2 min 5 s');
  assert.equal(lib.levelFor(60, 50, 100), 'warning');
  assert.equal(lib.levelFor(100, 50, 100), 'critical');
});

test('text from the network is inserted as text, never as markup', () => {
  const el = lib.h('div', { class: 'x', title: 'a"b' }, '<img src=x onerror=alert(1)>', null, ['b', false]);
  assert.equal(el.children.length, 2);
  assert.ok(el.children.every(c => c.tagName === '#text'));
  assert.equal(el.textContent, '<img src=x onerror=alert(1)>b');
  assert.equal(el.className, 'x');
});

test('an open incident band ends after 15 minutes instead of reaching now', () => {
  const now = 100_000;
  const m = buildMarkers([], [
    { ts_start: 1000, ts_end: null, source: 'auto' },
    { ts_start: now - 60, ts_end: null, source: 'auto' },
    { ts_start: 2000, ts_end: 2010, source: 'user' },
  ], now);
  assert.deepEqual(m.bands.map(b => b.t1), [1900, now, 2010]);
  assert.equal(m.bands[0].color, '#d00');
  assert.equal(m.bands[2].color, '#d90');
});

test('lag events are ticked by severity, context events in their own color', () => {
  const m = buildMarkers([
    { ts_start: 1, type: 'PACKET_LOSS', severity: 'critical' },
    { ts_start: 2, type: 'PING_SPIKE', severity: 'warning' },
    { ts_start: 3, type: 'HIGH_UPLOAD', severity: 'critical' },
  ], []);
  assert.deepEqual(m.ticks.map(t => t.color), ['#d00', '#d90', '#999']);
});

test('copying works on plain HTTP in the LAN without the clipboard API', async () => {
  assert.equal(await lib.copyText('sudo ./install.sh'), true);
  assert.equal(document.copied, 'sudo ./install.sh');
  assert.equal(document.body.children.length, 0, 'the helper textarea is removed again');
  document.copyWorks = false;
  assert.equal(await lib.copyText('x'), false);
  assert.equal(document.body.children.length, 0);
});

test('a secure context uses the clipboard API and falls back when it refuses', async () => {
  const written = [];
  window.isSecureContext = true;
  navigator.clipboard = { writeText: async t => { written.push(t); } };
  assert.equal(await lib.copyText('a'), true);
  assert.deepEqual(written, ['a']);
  assert.equal(document.copied, null);
  navigator.clipboard = { writeText: async () => { throw new Error('denied'); } };
  assert.equal(await lib.copyText('b'), true);
  assert.equal(document.copied, 'b');
});

test('events close together on the overview become one marker with their count', async () => {
  const { clusters } = await import('../../frontend/js/pages/overview.js');
  const c = clusters([{ ts: 500 }, { ts: 100 }, { ts: 130 }, { ts: 1000 }, { ts: 160 }], 50);
  assert.deepEqual(c.map(g => g.map(e => e.ts)), [[100, 130], [160], [500], [1000]]);
  assert.deepEqual(clusters([], 50), []);
});

test('a field under a switch shows only while the switch and its own condition hold', async () => {
  const { under } = await import('../../frontend/js/pages/settings.js');
  const [plain, own] = under('a.on', [{ path: 'a.x' }, { path: 'a.y', when: v => v('a.mode') === 'disk' }]);
  const values = cfg => path => cfg[path];
  assert.equal(plain.when(values({ 'a.on': false })), false);
  assert.equal(plain.when(values({ 'a.on': true })), true);
  assert.equal(own.when(values({ 'a.on': true, 'a.mode': 'memory' })), false);
  assert.equal(own.when(values({ 'a.on': true, 'a.mode': 'disk' })), true);
});

test('an incident summary is plain text with the cause and its evidence', async () => {
  const { incidentText } = await import('../../frontend/js/pages/incidents.js');
  const text = incidentText({ source: 'auto', ts_start: 1000, ts_end: 1060, title: 'Packet loss', cause: 'Line problem',
    confidence: 'low', analysis: { evidence: ['Router fine', 'Targets lost packets'] } });
  assert.match(text, /Possible cause: Line problem/);
  assert.match(text, /- Targets lost packets/);
  assert.equal(incidentText({ source: 'user', ts_start: 1000 }).split('\n').length, 1);
});

test('a network check nobody could measure stays grey, not green', async () => {
  const { HEALTH_DOT, HEALTH_TEXT } = await import('../../frontend/js/pages/devices.js');
  assert.equal(HEALTH_DOT.na, 'muted');
  assert.equal(HEALTH_DOT.problem, 'critical');
  assert.equal(HEALTH_TEXT.na, 'Not measurable');
});

test('the incident list hides minor incidents but never one that could not be rated', async () => {
  const { visibleIncidents } = await import('../../frontend/js/pages/incidents.js');
  const all = [{ id: 1, impact: 'severe' }, { id: 2, impact: 'noticeable' }, { id: 3, impact: 'minor' }, { id: 4, impact: null }];
  assert.deepEqual(visibleIncidents(all, 'felt').map(i => i.id), [1, 2, 4]);
  assert.deepEqual(visibleIncidents(all, 'severe').map(i => i.id), [1, 4]);
  assert.equal(visibleIncidents(all, 'all').length, 4);
});

test('a link to a devices tab opens it, anything else the device list', async () => {
  const { tabOf } = await import('../../frontend/js/pages/devices.js');
  assert.equal(tabOf(['health']), 'health');
  assert.equal(tabOf(['presence']), 'presence');
  assert.equal(tabOf(['nonsense']), 'list');
  assert.equal(tabOf(undefined), 'list');
});

test('a memory limit only on paper is not shown as a limit', async () => {
  const { memoryLimitText } = await import('../../frontend/js/pages/pi.js');
  assert.deepEqual(memoryLimitText(null), [null, null]);
  assert.equal(memoryLimitText({ controller: false, limit_mb: null, used_mb: null })[0], 'Not in effect');
  assert.equal(memoryLimitText({ controller: true, limit_mb: null, used_mb: null })[0], 'None set');
  assert.deepEqual(memoryLimitText({ controller: true, limit_mb: 350, used_mb: 210 }), ['350 MB', '210 MB in use']);
});

test('a duration never shows 60 seconds or 60 minutes', () => {
  assert.equal(lib.fmtDuration(59.6), '1 min 0 s');
  assert.equal(lib.fmtDuration(179.6), '3 min 0 s');
  assert.equal(lib.fmtDuration(3599.7), '1 h 0 min');
  assert.equal(lib.fmtDuration(7170), '2 h 0 min');
  assert.equal(lib.fmtDuration(1801), '30 min 1 s');
});

test('a day in a list is named today, yesterday or by its date', () => {
  const now = new Date(2026, 10, 13, 15, 0, 0).getTime() / 1000;
  assert.equal(lib.fmtDay(new Date(2026, 10, 13, 0, 0, 1).getTime() / 1000, now), 'Today');
  assert.equal(lib.fmtDay(new Date(2026, 10, 12, 23, 59, 59).getTime() / 1000, now), 'Yesterday');
  assert.equal(lib.fmtDay(new Date(2026, 10, 6, 12, 0, 0).getTime() / 1000, now), '2026-11-06');
});

test('incidents a few minutes apart form one episode, a report of the user stands alone', async () => {
  const { episodes, episodeSummary } = await import('../../frontend/js/pages/incidents.js');
  const inc = (id, start, end, extra = {}) => ({ id, source: 'auto', ts_start: start, ts_end: end, ...extra });
  const list = [                                   // newest first, as the API returns them
    inc(5, 5000, 5100),
    inc(4, 3000, 3600, { impact: 'noticeable', cause: 'B', metrics: { ping_peak: 90, loss_pct: 1, duration: 600 } }),
    inc(3, 2000, 2900, { impact: 'severe', cause: 'A', metrics: { ping_peak: 300, loss_pct: 6, duration: 900 } }),
    { ...inc(2, 1900, 1950), source: 'user' },
    inc(1, 1000, 1800, { impact: 'minor', cause: 'A', metrics: { duration: 800 } }),
  ];
  const eps = episodes(list);
  assert.deepEqual(eps.map(e => e.map(i => i.id)), [[5], [4, 3], [2], [1]]);
  assert.deepEqual(episodeSummary(eps[1]), { start: 2000, end: 3600, impact: 'severe', causes: ['B', 'A'],
    ping_peak: 300, loss_pct: 6, duration: 1500 });
  const bare = episodeSummary([inc(9, 10, null), inc(8, 1, 5)]);
  assert.equal(bare.impact, null);
  assert.equal(bare.ping_peak, null);
  assert.equal(bare.duration, null);
  assert.equal(bare.end, 10);
});
