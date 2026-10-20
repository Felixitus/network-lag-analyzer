// uPlot helpers: time series charts with a shared cursor, tooltip and event markers.
/* global uPlot */
import { cssVar, fmtTime, h } from './lib.js';

const charts = new Set();

function theme() {
  return {
    grid: cssVar('--grid'), axis: cssVar('--axis'), text: cssVar('--text-muted'), ink: cssVar('--text-secondary'),
    critical: cssVar('--critical'), warning: cssVar('--warning'), surface: cssVar('--surface-1'),
  };
}

function withAlpha(color, a) {
  if (color.startsWith('#') && color.length === 7) {
    const n = parseInt(color.slice(1), 16);
    return `rgba(${n >> 16},${(n >> 8) & 255},${n & 255},${a})`;
  }
  return color;
}

const p2 = n => String(n).padStart(2, '0');
/** 24 h time axis; date only when the range spans more than a day. */
function xValues(u, splits, axisIdx, space, incr) {
  const span = u.scales.x.max - u.scales.x.min;
  return splits.map(ts => {
    const d = new Date(ts * 1000);
    const hm = `${p2(d.getHours())}:${p2(d.getMinutes())}`;
    if (incr >= 86400) return `${p2(d.getMonth() + 1)}-${p2(d.getDate())}`;
    if (span > 86400) return `${p2(d.getMonth() + 1)}-${p2(d.getDate())} ${hm}`;
    return incr < 60 ? `${hm}:${p2(d.getSeconds())}` : hm;
  });
}

/** Tooltip: time + value of every series at the cursor position. */
function tooltipPlugin(specs) {
  let tt;
  return {
    hooks: {
      init: u => { tt = h('div', { class: 'tt' }); u.over.appendChild(tt); },
      setCursor: u => {
        const i = u.cursor.idx;
        if (i === null || i === undefined || u.cursor.left < 0) { tt.style.display = 'none'; return; }
        const ts = u.data[0][i];
        const rows = [];
        specs.forEach((s, k) => {
          if (s.hideInTooltip) return;
          const v = u.data[k + 1][i];
          rows.push(h('div', { class: 'r' },
            h('span', { class: `swatch${s.dash ? ' dash' : ''}`, style: s.dash ? { borderColor: s.color } : { background: s.color } }),
            s.label, h('b', null, v === null || v === undefined ? 'n/a' : s.fmt(v))));
        });
        tt.replaceChildren(h('div', { class: 't' }, fmtTime(ts)), ...rows);
        tt.style.display = 'block';
        const left = u.cursor.left, w = tt.offsetWidth, W = u.over.clientWidth;
        tt.style.left = `${left + 14 + w > W ? left - w - 14 : left + 14}px`;
        tt.style.top = `${Math.max(0, Math.min(u.cursor.top - 10, u.over.clientHeight - tt.offsetHeight))}px`;
      },
    },
  };
}

function nullPlugin() { return { hooks: {} }; }

/** Hatching over periods without measurements - so that "not measured" does not look like 0. */
function drawGaps(u, gaps) {
  const ctx = u.ctx;
  const top = u.bbox.top, hgt = u.bbox.height, left = u.bbox.left, right = left + u.bbox.width;
  ctx.save();
  ctx.fillStyle = withAlpha(cssVar('--text-muted') || '#888', 0.10);
  for (const g of gaps) {
    const x0 = Math.max(left, u.valToPos(g[0], 'x', true));
    const x1 = Math.min(right, u.valToPos(g[1], 'x', true));
    if (x1 <= x0) continue;
    ctx.fillRect(x0, top, x1 - x0, hgt);
    // narrow diagonals so that the area clearly reads as "no data"
    ctx.save();
    ctx.beginPath();
    ctx.rect(x0, top, x1 - x0, hgt);
    ctx.clip();
    ctx.strokeStyle = withAlpha(cssVar('--text-muted') || '#888', 0.18);
    ctx.lineWidth = 1 * devicePixelRatio;
    for (let x = x0 - hgt; x < x1 + hgt; x += 7 * devicePixelRatio) {
      ctx.moveTo(x, top + hgt);
      ctx.lineTo(x + hgt, top);
    }
    ctx.stroke();
    ctx.restore();
  }
  ctx.restore();
}

/** Incident bands (behind the data) and event ticks (on top). */
function markerPlugin(getMarkers) {
  return {
    hooks: {
      drawClear: u => {
        const m = getMarkers();
        if (!m) return;
        if (m.gaps && m.gaps.length) drawGaps(u, m.gaps);
        if (!m.bands) return;
        const ctx = u.ctx, t = theme();
        ctx.save();
        for (const b of m.bands) {
          const x0 = u.valToPos(b.t0, 'x', true), x1 = u.valToPos(Math.max(b.t1, b.t0 + 1), 'x', true);
          if (x1 < u.bbox.left || x0 > u.bbox.left + u.bbox.width) continue;
          ctx.fillStyle = withAlpha(b.color || t.critical, b.alpha || 0.12);
          const l = Math.max(x0, u.bbox.left), r = Math.min(x1, u.bbox.left + u.bbox.width);
          ctx.fillRect(l, u.bbox.top, Math.max(2, r - l), u.bbox.height);
        }
        ctx.restore();
      },
      draw: u => {
        const m = getMarkers();
        if (!m || !m.ticks) return;
        const ctx = u.ctx;
        ctx.save();
        for (const k of m.ticks) {
          const x = u.valToPos(k.t, 'x', true);
          if (x < u.bbox.left || x > u.bbox.left + u.bbox.width) continue;
          ctx.fillStyle = k.color;
          ctx.fillRect(x - 1, u.bbox.top, 3 * devicePixelRatio, 7 * devicePixelRatio);
        }
        ctx.restore();
      },
    },
  };
}

/**
 * Time series chart.
 * specs: [{label, color, width, dash, fill, fmt, bars}]
 */
export function timeChart(container, specs, opts = {}) {
  const t = theme();
  let height = opts.height || 180;
  const el = h('div', { class: 'chart' });
  container.appendChild(el);
  let markers = opts.markers || (() => null);
  const series = [{}].concat(specs.map(s => ({
    label: s.label, stroke: s.color, width: s.width || 2, dash: s.dash, spanGaps: false,
    fill: s.fill ? withAlpha(s.color, s.fill) : undefined,
    paths: s.bars ? uPlot.paths.bars({ size: [0.9, 6], align: 0 }) : undefined,
    points: { show: false },
  })));
  const yFmt = opts.yFmt || (v => String(v));
  const uopts = {
    width: Math.max(200, container.clientWidth || 600), height,
    series,
    padding: [10, 24, 0, 0],   // fixed geometry → all charts on a page line up exactly
    cursor: { sync: opts.sync ? { key: opts.sync } : undefined, drag: { x: !!opts.onSelect, y: false },
      points: { size: 8, width: 2 } },
    legend: { show: false },
    scales: { x: { time: true }, y: { range: opts.yRange || ((u, min, max) => [0, Math.max((max || 0) * 1.12, opts.yMinMax || 1)]) } },
    axes: [
      { stroke: t.text, grid: { stroke: t.grid, width: 1 }, ticks: { stroke: t.axis, width: 1 }, font: '11px system-ui', space: 70,
        values: xValues, show: opts.xAxis !== false, size: opts.xAxis === false ? 0 : 30 },
      { stroke: t.text, grid: { stroke: t.grid, width: 1 }, ticks: { show: false }, font: '11px system-ui', size: 52, space: height < 130 ? 18 : 28,
        values: (u, vals) => vals.map(yFmt), label: opts.yLabel, labelSize: opts.yLabel ? 16 : 0, labelFont: '11px system-ui' },
    ],
    plugins: [opts.tooltip === false ? nullPlugin() : tooltipPlugin(specs), markerPlugin(() => markers())],
    hooks: {
      setSelect: opts.onSelect ? [u => {
        if (u.select.width > 5) {
          opts.onSelect(u.posToVal(u.select.left, 'x'), u.posToVal(u.select.left + u.select.width, 'x'));
          u.setSelect({ width: 0, height: 0 }, false);
        }
      }] : [],
      // report the values at the cursor position to the outside (shared readout bar)
      setCursor: opts.onCursor ? [u => {
        const i = u.cursor.idx;
        opts.onCursor(i === null || i === undefined || u.cursor.left < 0
          ? null
          : { ts: u.data[0][i], values: specs.map((_s, k) => u.data[k + 1][i]) });
      }] : [],
    },
  };
  const data = opts.data || [[], ...specs.map(() => [])];
  const u = new uPlot(uopts, data, el);
  if (opts.onClick) {
    u.over.addEventListener('click', () => {
      const i = u.cursor.idx;
      if (i !== null && i !== undefined) opts.onClick(u.data[0][i]);
    });
    u.over.style.cursor = 'pointer';
  }
  const na = h('div', { class: 'na', style: { display: 'none' } });
  el.appendChild(na);
  const ro = new ResizeObserver(() => {
    const w = container.clientWidth;
    if (w > 0 && Math.abs(w - u.width) > 2) u.setSize({ width: w, height });
  });
  ro.observe(container);
  const api = {
    u,
    setData(d, resetScales = true) {
      u.setData(d, resetScales);
      const hasAny = d.slice(1).some(s => s.some(v => v !== null && v !== undefined));
      if (!hasAny && opts.naText) { na.textContent = opts.naText; na.style.display = 'flex'; } else { na.style.display = 'none'; }
    },
    setNa(text) { na.textContent = text || ''; na.style.display = text ? 'flex' : 'none'; },
    setMarkers(fn) { markers = fn; u.redraw(false); },
    setHeight(px) { height = px; u.setSize({ width: u.width, height: px }); },
    destroy() { ro.disconnect(); u.destroy(); charts.delete(api); },
  };
  charts.add(api);
  return api;
}

export function destroyAll() { for (const c of [...charts]) c.destroy(); }

export function legend(specs) {
  return h('div', { class: 'legend' }, specs.filter(s => !s.hideInLegend).map(s => h('span', null,
    h('span', { class: `swatch${s.dash ? ' dash' : ''}`, style: s.dash ? { borderColor: s.color } : { background: s.color } }),
    s.label)));
}

/** Card frame with title + legend + chart. */
export function chartCard(title, specs, opts = {}) {
  const card = h('div', { class: 'card chart-card' });
  const head = h('div', { class: 'chart-title' }, h('h3', null, title), opts.sub ? h('span', { class: 'muted small' }, opts.sub) : null);
  card.append(head);
  if (specs.length > 1 || opts.forceLegend) card.append(legend(specs));
  const body = h('div');
  card.append(body);
  return { card, body, mount: () => timeChart(body, specs, opts) };
}

export const fmt = {
  ms: v => `${v >= 100 ? v.toFixed(0) : v.toFixed(1)} ms`,
  pct: v => `${v.toFixed(1)} %`,
  mbit: v => `${(v / 1e6).toFixed(v >= 1e7 ? 1 : 2)} Mbit/s`,
  mbitAxis: v => `${+(v / 1e6).toFixed(1)}`,
  msAxis: v => `${+v.toFixed(0)}`,
};
