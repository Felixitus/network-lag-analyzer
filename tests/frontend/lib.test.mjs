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
  assert.deepEqual(m.ticks.map(t => t.color), ['#d00', '#d90', '#09c']);
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
