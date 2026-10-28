// Setup wizard and settings.
import { api, clear, fmtBytes, fmtDateTime, h, statusIcon, toast } from '../lib.js';
import { segmented } from './common.js';

function get(obj, path) { return path.split('.').reduce((o, k) => (o == null ? undefined : o[k]), obj); }
function setPath(obj, path, v) {
  const ks = path.split('.'); let o = obj;
  ks.slice(0, -1).forEach(k => { o[k] = o[k] || {}; o = o[k]; });
  o[ks[ks.length - 1]] = v;
}

/** Form from field definitions; returns {el, patch()} */
function form(cfg, fields) {
  const inputs = [];
  const grid = h('div', { class: 'form-grid' });
  for (const f of fields) {
    const val = get(cfg, f.path);
    let input;
    if (f.type === 'bool') {
      input = h('input', { type: 'checkbox', checked: !!val, id: `f-${f.path}` });
      grid.append(h('div', { class: 'field' }, h('label', { class: 'check', for: `f-${f.path}` }, input, f.label), f.help ? h('div', { class: 'help' }, f.help) : null));
    } else if (f.type === 'select') {
      input = h('select', { id: `f-${f.path}` }, f.options.map(([v, l]) => h('option', { value: v, selected: String(val) === String(v) }, l)));
      grid.append(h('div', { class: 'field' }, h('label', { for: `f-${f.path}` }, f.label), input, f.help ? h('div', { class: 'help' }, f.help) : null));
    } else {
      const v = f.type === 'list' ? (val || []).map(x => (typeof x === 'object' ? x.address : x)).join(', ') : (val ?? '');
      input = h('input', { type: f.type === 'password' ? 'password' : f.type === 'number' ? 'number' : 'text', value: String(v), id: `f-${f.path}`,
        step: f.step || 'any', placeholder: f.placeholder || '', autocomplete: 'off' });
      grid.append(h('div', { class: 'field' }, h('label', { for: `f-${f.path}` }, f.label), input, f.help ? h('div', { class: 'help' }, f.help) : null));
    }
    inputs.push([f, input]);
  }
  return {
    el: grid,
    patch() {
      const p = {};
      for (const [f, input] of inputs) {
        let v;
        if (f.type === 'bool') v = input.checked;
        else if (f.type === 'number') v = input.value === '' ? null : Number(input.value);
        else if (f.type === 'numauto') v = input.value.trim() === '' || input.value.trim() === 'auto' ? 'auto' : Number(input.value);
        else if (f.type === 'list') v = input.value.split(/[,\s]+/).filter(Boolean).map(a => ({ address: a }));
        else if (f.type === 'nullable') v = input.value.trim() || null;
        else v = input.value;
        if (f.type === 'password' && v === '********') continue;
        setPath(p, f.path, v);
      }
      return p;
    },
  };
}

function section(title, sub, fieldsForm, extra) {
  const save = h('button', { class: 'btn primary', type: 'button' }, 'Save');
  save.addEventListener('click', async () => {
    save.disabled = true;
    try {
      const r = await api('api/settings', { method: 'PUT', body: fieldsForm.patch() });
      toast(r.restarted ? 'Saved - data sources restarted' : 'Saved');
    } catch (e) { toast(`Error: ${e.message}`, 6000); }
    save.disabled = false;
  });
  return h('div', { class: 'card stack' }, h('div', null, h('h3', null, title), sub ? h('p', { class: 'small muted', style: { margin: '4px 0 0' } }, sub) : null),
    fieldsForm.el, h('div', { class: 'row' }, save, extra || null));
}

// ---------------------------------------------------------------- database
// Small tables that you rarely want to delete are unchecked by default: events,
// incidents and the bufferbloat windows cost almost no space, but they are the
// software's memory.
const SMALL_TABLES = new Set(['events', 'incidents', 'bufferbloat', 'gaming_sessions']);
const DAY = 86400;

function isoDay(tsSeconds) {
  const d = new Date(tsSeconds * 1000);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}
function dayStart(iso) { return new Date(`${iso}T00:00:00`).getTime() / 1000; }

function backupCard(cfg) {
  const body = h('div', { class: 'stack-sm' });
  const run = h('button', { class: 'btn', type: 'button' }, 'Back up now');
  const bf = form(cfg, [
    { path: 'backup.enabled', label: 'Automatic backups', type: 'bool' },
    { path: 'backup.interval_days', label: 'Every (days)', type: 'number' },
    { path: 'backup.keep', label: 'Keep the newest', type: 'number' },
    { path: 'backup.hour', label: 'At (hour, local time)', type: 'number', help: 'Only while the Pi is not busy (load guard level 0)' },
  ]);
  async function load() {
    let r;
    try { r = await api('api/backups'); } catch (e) { clear(body).append(h('div', { class: 'empty' }, e.message)); return; }
    clear(body);
    const l = r.last;
    body.append(h('div', { class: 'small' }, l ? (l.ok ? `Last backup ${fmtDateTime(l.ts)}: ${fmtBytes(l.size)} in ${l.seconds} s, checked OK`
      : `Last backup FAILED ${fmtDateTime(l.ts)}: ${l.error}`) : 'No automatic backup yet.'));
    body.append(r.backups.length ? h('ul', { class: 'list small' }, r.backups.map(b => h('li', { class: 'row' },
      h('span', { class: 'mono' }, b.name), h('span', { class: 'spacer' }), h('span', null, fmtBytes(b.size)),
      h('span', { class: 'muted' }, b.config ? '+ config.yaml' : '')))) : null);
    body.append(h('div', { class: 'small muted' }, `In ${r.dir}. Copy them off the Pi now and then - a backup on the same SD card does not survive the card. Restore: see docs/operations.md, "Backup and restore".`));
  }
  run.addEventListener('click', async () => {
    run.disabled = true; toast('Backing up…');
    try { const r = await api('api/backups/run', { method: 'POST', body: {} }); toast(`Backup written (${fmtBytes(r.size)})`); load(); }
    catch (e) { toast(`Backup failed: ${e.message}`, 6000); }
    run.disabled = false;
  });
  load();
  const card = section('Backups', 'A consistent copy of the database and config.yaml, checked after writing. Older automatic backups are removed; your own copies are never touched.', bf, run);
  card.append(body);
  return card;
}

function databaseCard() {
  const card = h('div', { class: 'card stack' });
  const body = h('div', null, h('div', { class: 'skeleton' }, 'Reading database size …'));
  card.append(h('div', null, h('h3', null, 'Database'),
    h('p', { class: 'small muted', style: { margin: '4px 0 0' } },
      'Space usage and targeted deletion by date - in case the memory card gets tight.')), body);
  load();

  async function load() {
    let d;
    try { d = await api('api/database'); } catch (e) { clear(body).append(h('div', { class: 'empty' }, e.message)); return; }
    clear(body);
    body.append(sizeRow(d), pcapRow(d), tableList(d), deleteForm(d), maintenanceRow(d));
  }

  // PCAP files live next to the database and used to be visible nowhere -
  // that is exactly why they could grow to tens of gigabytes unnoticed.
  function pcapRow(d) {
    const p = d.pcap || {};
    const limit = p.limit_bytes || 0;
    const pct = limit ? Math.min(100, Math.round(p.bytes / limit * 100)) : 0;
    const clean = h('button', { class: 'btn small', type: 'button' }, 'Clean up now');
    clean.addEventListener('click', async () => {
      clean.disabled = true; const t = clean.textContent; clean.textContent = 'Cleaning up …';
      try {
        const r = await api('api/database/pcap-cleanup', { method: 'POST' });
        toast(r.freed_bytes > 0 ? `${fmtBytes(r.freed_bytes)} freed` : 'Nothing to clean up', 5000);
        load();
      } catch (e) { toast(e.message, 6000); }
      clean.textContent = t; clean.disabled = false;
    });
    return h('div', { class: 'stack', style: { marginTop: '16px' } },
      h('div', { class: 'row' }, h('h4', { style: { margin: 0 } }, 'Deep Capture (PCAP files)'),
        h('span', { class: `badge ${p.enabled ? 'warning' : ''}` }, p.enabled ? 'active' : 'off'),
        h('span', { class: 'spacer' }), clean),
      h('div', { class: 'row small' },
        h('b', null, fmtBytes(p.bytes || 0)),
        h('span', { class: 'muted' }, `in ${p.files || 0} file(s) · limit ${fmtBytes(limit)}`)),
      limit ? h('div', { class: 'meter' }, h('div', {
        class: `meter-fill ${pct >= 90 ? 'critical' : pct >= 70 ? 'warning' : ''}`,
        style: { width: `${pct}%` },
      })) : null,
      h('div', { class: 'small muted' },
        'The captures do NOT count towards the database size above. Incident captures are kept for '
        + `${d.deep_capture ? d.deep_capture.protected_days : 7} days; `
        + 'beyond that the total limit applies, which pushes out the oldest captures.'));
  }

  function sizeRow(d) {
    const pct = d.limit_mb ? Math.min(100, Math.round(d.size.used / (d.limit_mb * 1e6) * 100)) : null;
    return h('div', { class: 'stack', style: { marginTop: '12px' } },
      h('div', { class: 'facts' },
        fact('File', fmtBytes(d.size.file)),
        fact('Used', fmtBytes(d.size.used)),
        fact('Free in the file', fmtBytes(d.size.free)),
        fact('Free on disk', d.free_disk == null ? 'Not available' : fmtBytes(d.free_disk)),
        fact('Oldest data point', d.oldest ? fmtDateTime(d.oldest) : 'Not available')),
      pct == null ? h('div', { class: 'small muted' }, 'No size limit set.')
        : h('div', null,
          h('div', { class: 'meter' }, h('div', {
            class: `meter-fill ${pct >= 90 ? 'critical' : pct >= 70 ? 'warning' : ''}`,
            style: { width: `${pct}%` },
          })),
          h('div', { class: 'small muted' }, `${pct} % of the ${d.limit_mb} MB limit`)),
      d.guard && d.guard.acted
        ? h('div', { class: 'banner warn' }, h('b', null, 'Cleaned up automatically'),
          h('span', null, `The limit was exceeded; deleted: ${
            Object.entries(d.guard.deleted).map(([k, v]) => `${k}: ${v}`).join(', ')}.`))
        : null);
  }

  function fact(k, v) {
    return h('div', { class: 'fact' }, h('div', { class: 'k' }, k), h('div', { class: 'v small-v' }, v));
  }

  function tableList(d) {
    const rows = d.tables.map(t => h('tr', null,
      h('td', null, h('div', null, t.label), h('div', { class: 'small mono muted' }, t.table)),
      h('td', { class: 'num' }, t.rows.toLocaleString('en-GB')),
      h('td', { class: 'num' }, t.bytes == null ? '–' : fmtBytes(t.bytes))));
    return h('details', { style: { marginTop: '12px' } },
      h('summary', { style: { cursor: 'pointer', fontWeight: 600 } }, 'Space per table'),
      h('div', { class: 'table-wrap' }, h('table', { class: 'tbl small' },
        h('thead', null, h('tr', null, h('th', null, 'Table'), h('th', { class: 'num' }, 'Rows'),
          h('th', { class: 'num' }, 'Space'))),
        h('tbody', null, ...rows))),
      h('div', { class: 'small muted', style: { marginTop: '6px' } },
        `Never deleted: ${d.protected.join(', ')} - they hold device names, targets, `
        + 'settings and the daily summary.'));
  }

  function deleteForm(d) {
    const today = isoDay(Date.now() / 1000);
    const oldest = d.oldest ? isoDay(d.oldest) : today;
    let mode = 'before';
    const before = h('input', { type: 'date', value: isoDay(Date.now() / 1000 - 30 * DAY), min: oldest, max: today });
    const from = h('input', { type: 'date', value: oldest, min: oldest, max: today });
    const to = h('input', { type: 'date', value: today, min: oldest, max: today });
    // The date field shows a different format depending on the browser language. The line
    // below therefore says in plain words which point in time is meant.
    const resolved = h('div', { class: 'small muted' });
    const updateResolved = () => {
      const b = bounds();
      resolved.textContent = mode === 'before'
        ? `Everything before ${fmtDateTime(b.end)} will be deleted.`
        : (b.start >= b.end ? 'The start date must be before the end date.'
          : `Data from ${fmtDateTime(b.start)} to ${fmtDateTime(b.end)} will be deleted.`);
    };
    const beforeBox = h('div', { class: 'row' }, h('label', null, 'Everything before'), before);
    const rangeBox = h('div', { class: 'row', style: { display: 'none' } },
      h('label', null, 'From'), from, h('label', null, 'to (exclusive)'), to);
    // Sorted by name so that the checkboxes stay in the same place after every
    // reload - the table list above, in contrast, is sorted by size.
    const boxes = [...d.tables].sort((a, b) => a.label.localeCompare(b.label, 'en')).map(t => {
      const cb = h('input', { type: 'checkbox', checked: !SMALL_TABLES.has(t.table) });
      return { table: t.table, cb, el: h('label', { class: 'check' }, cb, t.label) };
    });

    const out = h('div', { class: 'small' });
    const preview = h('button', { class: 'btn', type: 'button' }, 'Preview');
    const del = h('button', { class: 'btn danger', type: 'button', disabled: true }, 'Delete');
    let pending = null;

    function bounds() {
      if (mode === 'before') return { start: null, end: dayStart(before.value) };
      return { start: dayStart(from.value), end: dayStart(to.value) };
    }
    function selected() { return boxes.filter(b => b.cb.checked).map(b => b.table); }

    preview.addEventListener('click', async () => {
      const tables = selected();
      if (!tables.length) { out.textContent = 'No table selected.'; return; }
      const b = bounds();
      if (b.start != null && b.start >= b.end) { out.textContent = 'The start date is not before the end date.'; return; }
      preview.disabled = true;
      try {
        const r = await api('api/database/preview', { method: 'POST', body: { ...b, tables, confirm: 'PREVIEW' } });
        const lines = Object.entries(r.counts).filter(([, n]) => n > 0)
          .map(([t, n]) => `${t}: ${n.toLocaleString('en-GB')}`);
        clear(out).append(
          h('div', null, h('b', null, `${r.total.toLocaleString('en-GB')} rows`),
            ' would be deleted', lines.length ? ` (${lines.join(', ')})` : ''),
          r.total ? h('div', { class: 'muted' }, 'This cannot be undone.') : null);
        pending = r.total ? { ...b, tables } : null;
        del.disabled = !pending;
      } catch (e) { out.textContent = e.message; }
      preview.disabled = false;
    });

    del.addEventListener('click', async () => {
      if (!pending) return;
      if (del.textContent !== 'Really delete?') { del.textContent = 'Really delete?'; return; }
      del.disabled = true; del.textContent = 'Deleting …';
      try {
        const r = await api('api/database/delete', { method: 'POST', body: { ...pending, confirm: 'DELETE' } });
        toast(`${r.total.toLocaleString('en-GB')} rows deleted, ${fmtBytes(r.freed_bytes)} freed`, 6000);
        pending = null;
        load();
      } catch (e) { toast(e.message, 6000); del.disabled = false; }
      del.textContent = 'Delete';
    });

    const invalidate = () => {
      pending = null; del.disabled = true; del.textContent = 'Delete'; clear(out); updateResolved();
    };
    [before, from, to].forEach(i => i.addEventListener('change', invalidate));
    boxes.forEach(b => b.cb.addEventListener('change', invalidate));

    updateResolved();
    return h('div', { class: 'stack', style: { marginTop: '16px' } },
      h('h4', { style: { margin: 0 } }, 'Delete data by date'),
      segmented([['before', 'Everything before a date'], ['range', 'Time span']], 'before', v => {
        mode = v;
        beforeBox.style.display = v === 'before' ? '' : 'none';
        rangeBox.style.display = v === 'range' ? '' : 'none';
        invalidate();
      }),
      beforeBox, rangeBox, resolved,
      h('div', { class: 'check-grid' }, ...boxes.map(b => b.el)),
      h('div', { class: 'row' }, preview, del), out);
  }

  function maintenanceRow(d) {
    const vac = h('button', { class: 'btn', type: 'button' }, 'Shrink file (VACUUM)');
    vac.addEventListener('click', async () => {
      vac.disabled = true;
      const txt = vac.textContent;
      vac.textContent = 'Running … (may take a while)';
      try {
        const r = await api('api/database/vacuum', { method: 'POST' });
        toast(r.freed > 0 ? `${fmtBytes(r.freed)} freed` : 'Nothing to shrink');
        load();
      } catch (e) { toast(e.message, 6000); }
      vac.textContent = txt; vac.disabled = false;
    });
    return h('div', { class: 'stack', style: { marginTop: '16px' } },
      h('div', { class: 'row' }, vac),
      h('div', { class: 'small muted' },
        'Deleted pages initially stay in the file and are reused. '
        + 'Only VACUUM returns the space to the file system - for that it briefly needs '
        + 'as much extra space as the database occupies.'));
  }

  return card;
}


export async function mount(main, { refreshStatus }) {
  const s = await api('api/settings');
  const cfg = s.config;
  main.append(h('div', { class: 'page-head' }, h('div', null, h('h1', null, 'Setup & Settings'),
    h('p', null, `Values from ${s.yaml_path || 'defaults'}; changes made here are stored in the database and override the file.`))));

  // ---------------------------------------------------------------- wizard
  const wiz = h('div', { class: 'card stack' });
  main.append(wiz);
  async function runWizard() {
    clear(wiz).append(h('h3', null, 'Network architecture diagnosis'), h('div', { class: 'skeleton' }, 'Checking interfaces, router, Pi-hole and visibility of client traffic … (about 5 s)'));
    let r;
    try { r = await api('api/setup/check'); } catch (e) { clear(wiz).append(h('div', { class: 'empty' }, e.message)); return; }
    clear(wiz);
    wiz.append(h('div', { class: 'row' }, h('h3', null, 'Network architecture diagnosis'), h('span', { class: 'spacer' }),
      h('button', { class: 'btn', onclick: runWizard }, 'Check again'),
      h('button', { class: 'btn primary', onclick: async () => { await api('api/setup/complete', { method: 'POST' }); toast('Setup completed'); refreshStatus(); } }, 'Complete setup')));
    const caps = h('div', { class: 'cap-grid' }, r.capabilities.map(c => h('div', null, statusIcon(c.ok), h('span', null, c.name),
      c.detail ? h('span', { class: 'small muted' }, `(${c.detail})`) : null)));
    wiz.append(h('div', null, h('h2', { style: { marginBottom: '8px' } }, 'Monitoring capability'), caps));
    if (r.hint) wiz.append(h('div', { class: 'banner warn', style: { marginTop: 0 } }, h('b', null, 'Note'), h('span', null, r.hint)));
    wiz.append(h('details', null, h('summary', { style: { cursor: 'pointer', fontWeight: 600 } }, 'Show individual checks'),
      h('ul', { class: 'checks' }, r.checks.map(c => h('li', null, statusIcon(c.ok),
        h('div', null, h('b', null, c.name), h('div', { class: 'small secondary' }, c.detail), c.hint ? h('div', { class: 'small', style: { color: 'var(--warning-ink)' } }, c.hint) : null))))));
  }
  runWizard();

  // ---------------------------------------------------------------- FRITZ!Box
  const fb = form(cfg, [
    { path: 'fritzbox.enabled', label: 'FRITZ!Box integration active', type: 'bool' },
    { path: 'fritzbox.host', label: 'Address', help: '"auto" = default gateway' },
    { path: 'fritzbox.username', label: 'Username', help: 'A dedicated user is recommended, with the "FRITZ!Box Settings" permission' },
    { path: 'fritzbox.password', label: 'Password', type: 'password' },
    { path: 'fritzbox.capture_enabled', label: 'Use packet capture for traffic per device', type: 'bool', help: 'Headers only (snaplen), no content' },
    { path: 'fritzbox.capture_interface', label: 'Capture interface', help: 'Default "1-lan" (LAN bridge)' },
    { path: 'fritzbox.snaplen', label: 'Snaplen (bytes per packet)', type: 'number', help: '600 (default) also reads the server names of TLS and QUIC connections (measured connections per service). 128 is enough for traffic per device alone. Only read in memory: the PCAP files keep 128 bytes per packet.' },
    { path: 'capture.source', label: 'Traffic source', type: 'select', options: [['auto', 'Automatic'], ['fritzbox', 'FRITZ!Box capture'], ['local', 'Local interface (mirror/gateway)'], ['none', 'None']] },
    { path: 'capture.local_interface', label: 'Local interface', help: 'Only for port mirroring or Pi as gateway' },
  ]);
  const testOut = h('div', { class: 'small' });
  const testBtn = h('button', { class: 'btn', type: 'button' }, 'Test connection & capture');
  testBtn.addEventListener('click', async () => {
    const p = fb.patch().fritzbox;
    testBtn.disabled = true; testOut.textContent = 'Testing login, TR-064 and a 3 s capture …';
    try {
      const r = await api('api/setup/fritzbox-test', { method: 'POST', body: { host: p.host, username: p.username, password: p.password || '', capture_interface: p.capture_interface, snaplen: p.snaplen } });
      clear(testOut).append(h('div', null, statusIcon(r.login.ok), ' Login: ', r.login.detail),
        r.login.hint ? h('div', { style: { color: 'var(--warning-ink)' } }, r.login.hint) : null,
        r.capture ? h('div', null, statusIcon(r.capture.ok), ` Capture: ${r.capture.ok
          ? `${r.capture.packets} packets, ${r.capture.macs} MAC addresses, format ${r.capture.format}, ${r.capture.linktype_name}`
          : (r.capture.error || 'failed')}`) : null,
        r.interfaces && r.interfaces.length ? h('div', { class: 'muted' }, `Interfaces found: ${r.interfaces.join(', ')}`) : null);
    } catch (e) { testOut.textContent = e.message; }
    testBtn.disabled = false;
  });
  main.append(h('div', { style: { height: '16px' } }), section('FRITZ!Box & traffic source',
    'Prerequisite: Home Network → Network → Network Settings → "Allow access for applications". The Pi only sees foreign traffic this way (or via port mirroring).',
    fb, h('div', { class: 'row' }, testBtn)));
  main.lastElementChild.append(testOut);

  // ---------------------------------------------------------------- measurement
  const meas = form(cfg, [
    { path: 'targets', label: 'Internet targets', type: 'list', help: 'IPs or host names, comma-separated' },
    { path: 'gateway', label: 'Gateway', help: '"auto" or IPv4' },
    { path: 'lan_reference', label: 'LAN reference', type: 'nullable', help: 'Optional: a second always-on device (access point, switch, NAS). If it loses packets together with the router, the Pi\'s own cable or port is the problem.' },
    { path: 'probe.interval', label: 'Ping interval (s)', type: 'number' },
    { path: 'probe.gaming_interval', label: 'Interval in Gaming Mode (s)', type: 'number' },
    { path: 'probe.timeout', label: 'Timeout (s)', type: 'number', help: 'A later reply = lost' },
    { path: 'capacity.down_mbit', label: 'Download capacity (Mbit/s)', type: 'numauto', help: '"auto" = FRITZ!Box link rate. Entering the booked rate is more accurate.' },
    { path: 'capacity.up_mbit', label: 'Upload capacity (Mbit/s)', type: 'numauto' },
    { path: 'dns_probe.enabled', label: 'DNS monitoring', type: 'bool' },
    { path: 'traceroute.enabled', label: 'Path measurement at incidents', type: 'bool', help: 'Traceroute to the worst targets when an incident starts or a lag is reported - shows from which hop on packets are lost.' },
    { path: 'traceroute.rounds', label: 'Rounds per path measurement', type: 'number', help: 'Each hop is asked this often, one round per second' },
    { path: 'traceroute.min_interval_s', label: 'At most one automatic measurement per target every (s)', type: 'number' },
  ]);
  main.append(h('div', { style: { height: '16px' } }), section('Measurement', null, meas));

  // ---------------------------------------------------------------- Pi-hole actions
  const pf = form(cfg, [
    { path: 'pihole.api_enabled', label: 'Allow Pi-hole actions from this page', type: 'bool', help: 'Pause blocking, allow or block a domain, restart DNS, update blocklists - each only after a confirmation' },
    { path: 'pihole.api_url', label: 'Pi-hole address', help: 'Only the Pi-hole on this Pi' },
    { path: 'pihole.api_password', label: 'Pi-hole app password', type: 'password', help: 'Pi-hole → Settings → Web interface / API → "Configure app password" (not your login password)' },
  ]);
  main.append(h('div', { style: { height: '16px' } }), section('Pi-hole actions',
    'Off by default. When on, the DNS pages offer to pause blocking and to allow or block a domain. Everything is logged with your user name.', pf));

  // ---------------------------------------------------------------- notifications
  const nf = form(cfg, [
    { path: 'notify.enabled', label: 'Send notifications', type: 'bool' },
    { path: 'notify.ntfy_url', label: 'ntfy address', help: 'e.g. https://ntfy.sh/ followed by a long random topic - the topic is the password. Install the ntfy app and subscribe to it.' },
    { path: 'notify.ntfy_token', label: 'ntfy access token', type: 'password', help: 'Only for a protected topic or your own server' },
    { path: 'notify.telegram_bot_token', label: 'Telegram bot token', type: 'password', help: 'From @BotFather' },
    { path: 'notify.telegram_chat_id', label: 'Telegram chat ID' },
    { path: 'notify.smtp_host', label: 'SMTP server', help: 'For e-mail, e.g. smtp.gmail.com' },
    { path: 'notify.smtp_port', label: 'SMTP port', type: 'number' },
    { path: 'notify.smtp_starttls', label: 'STARTTLS', type: 'bool' },
    { path: 'notify.smtp_username', label: 'SMTP user' },
    { path: 'notify.smtp_password', label: 'SMTP password', type: 'password', help: 'With Gmail an app password' },
    { path: 'notify.mail_from', label: 'Sender address' },
    { path: 'notify.mail_to', label: 'Recipient address' },
    { path: 'notify.router_loss', label: 'Packet loss to the router', type: 'bool' },
    { path: 'notify.router_loss_pct', label: '… from (% in 2 min)', type: 'number' },
    { path: 'notify.internet_down', label: 'Internet down', type: 'bool' },
    { path: 'notify.internet_down_seconds', label: '… after (s)', type: 'number' },
    { path: 'notify.pihole_down', label: 'Pi-hole does not answer', type: 'bool' },
    { path: 'notify.pi_health', label: 'Raspberry Pi critical (power, heat, storage)', type: 'bool' },
    { path: 'notify.line', label: 'Internet line (DSL lost, disconnected)', type: 'bool' },
    { path: 'notify.new_device', label: 'New device in the network', type: 'bool' },
    { path: 'notify.cooldown_minutes', label: 'Repeat an ongoing alert after (min)', type: 'number' },
    { path: 'notify.weekly_report', label: 'Weekly report', type: 'bool', help: 'Outages, worst hours, new devices and DNS signs of the past 7 days' },
    { path: 'notify.weekly_day', label: '… on (0 = Monday … 6 = Sunday)', type: 'number' },
    { path: 'notify.weekly_hour', label: '… from (hour)', type: 'number' },
  ]);
  const nOut = h('div', { class: 'small' });
  const nTest = h('button', { class: 'btn', type: 'button' }, 'Send test message');
  nTest.addEventListener('click', async () => {
    nTest.disabled = true;
    try {
      const r = await api('api/notify/test', { method: 'POST', body: {} });
      clear(nOut).append(...Object.entries(r.result).map(([ch, err]) => h('div', null, statusIcon(!err), ` ${ch}: ${err || 'sent'}`)));
    } catch (e) { nOut.textContent = e.message; }
    nTest.disabled = false;
  });
  const wOut = h('pre', { class: 'small', style: { whiteSpace: 'pre-wrap', display: 'none' } });
  const wPreview = h('button', { class: 'btn', type: 'button' }, 'Preview weekly report');
  wPreview.addEventListener('click', async () => {
    wPreview.disabled = true;
    try {
      const r = await api('api/notify/report');
      wOut.textContent = `${r.title}\n\n${r.text}`;
    } catch (e) { wOut.textContent = e.message; }
    wOut.style.display = '';
    wPreview.disabled = false;
  });
  const wSend = h('button', { class: 'btn', type: 'button' }, 'Send weekly report now');
  wSend.addEventListener('click', async () => {
    wSend.disabled = true;
    try {
      const r = await api('api/notify/report', { method: 'POST', body: {} });
      clear(nOut).append(...Object.entries(r.result).map(([ch, err]) => h('div', null, statusIcon(!err), ` ${ch}: ${err || 'sent'}`)));
    } catch (e) { nOut.textContent = e.message; }
    wSend.disabled = false;
  });
  const nLog = h('ul', { class: 'list small' });
  api('api/notify').then(r => {
    if (!r.log.length) { nLog.append(h('li', { class: 'muted' }, 'No messages sent since the last start.')); return; }
    nLog.append(...r.log.slice(0, 10).map(m => h('li', null, h('b', null, m.title), h('span', { class: 'muted' }, ` · ${fmtDateTime(m.ts)}`),
      h('div', { class: 'secondary' }, m.body),
      h('div', { class: 'muted' }, Object.entries(m.result).map(([ch, err]) => `${ch}: ${err || 'sent'}`).join(' · ') || 'no channel'))));
  }).catch(() => null);
  const notif = section('Notifications',
    'Messages to your phone when something needs attention - after a minimum duration, repeated at most once per cooldown, with an "all clear" when it is over. Save first, then send a test.',
    nf, h('div', { style: { display: 'flex', gap: '8px', flexWrap: 'wrap' } }, nTest, wPreview, wSend));
  notif.append(nOut, wOut, h('details', null, h('summary', { class: 'small', style: { cursor: 'pointer' } }, 'Last messages'), nLog));
  main.append(h('div', { style: { height: '16px' } }), notif);

  const thr = form(cfg, [
    { path: 'thresholds.ping_warning', label: 'Ping warning (ms)', type: 'number' },
    { path: 'thresholds.ping_critical', label: 'Ping critical (ms)', type: 'number' },
    { path: 'thresholds.spike_min_delta', label: 'Spike: min. above baseline (ms)', type: 'number' },
    { path: 'thresholds.jitter_warning', label: 'Jitter warning (ms)', type: 'number' },
    { path: 'thresholds.packet_loss_warning', label: 'Packet loss warning (% / 10 s)', type: 'number' },
    { path: 'thresholds.gateway_warning', label: 'Router warning (ms)', type: 'number' },
    { path: 'thresholds.high_upload_pct', label: 'High upload (% of capacity)', type: 'number' },
    { path: 'thresholds.high_download_pct', label: 'High download (% of capacity)', type: 'number' },
    { path: 'thresholds.retrans_warning_pct', label: 'Retransmissions warning (%)', type: 'number' },
    { path: 'thresholds.game_gap_ms', label: 'Game packet gap (ms)', type: 'number' },
  ]);
  main.append(h('div', { style: { height: '16px' } }), section('Thresholds', 'Take effect immediately, without a restart.', thr));

  const gm = form(cfg, [
    { path: 'gaming_pc.ip', label: 'IP of the gaming PC', type: 'nullable', placeholder: '192.168.178.20' },
    { path: 'gaming.auto_detect', label: 'Detect sessions automatically', type: 'bool' },
    { path: 'gaming.min_pps', label: 'Min. UDP packets/s per direction', type: 'number' },
    { path: 'gaming.stop_after_idle', label: 'Auto stop after inactivity (s)', type: 'number' },
  ]);
  main.append(h('div', { style: { height: '16px' } }), section('Gaming Mode', null, gm));

  const ret = form(cfg, [
    { path: 'retention.raw_days', label: '1 s values (days)', type: 'number' },
    { path: 'retention.detailed_days', label: '10 s aggregates (days)', type: 'number' },
    { path: 'retention.aggregate_days', label: '1 min aggregates (days)', type: 'number' },
    { path: 'retention.flow_days', label: 'Flows (days)', type: 'number' },
    { path: 'retention.event_days', label: 'Events & incidents (days)', type: 'number' },
    { path: 'retention.max_db_mb', label: 'Database size limit (MB)', type: 'number',
      help: 'Emergency brake: if exceeded, raw data and 1 s values are deleted first. 0 = no limit.' },
    { path: 'retention.ping_samples', label: 'Store individual pings', type: 'bool',
      help: 'About 14 MB per day that no evaluation reads. Only enable for troubleshooting.' },
    { path: 'deep_capture.enabled', label: 'Deep Capture (PCAP ring buffer)', type: 'bool', help: 'Headers only; protected on incidents' },
    { path: 'deep_capture.max_files', label: 'PCAP files in the ring', type: 'number' },
    { path: 'deep_capture.file_size_mb', label: 'Size per file (MB)', type: 'number' },
    { path: 'deep_capture.max_total_mb', label: 'PCAP total at most (MB)', type: 'number',
      help: 'Hard limit for ALL captures together, including those belonging to incidents. The only number that really limits.' },
    { path: 'deep_capture.protected_days', label: 'Keep incident captures (days)', type: 'number' },
    { path: 'deep_capture.protect_auto', label: 'Keep capture for', type: 'select',
      options: [['critical', 'critical incidents'], ['all', 'all incidents'], ['none', 'reported lag only']],
      help: 'Reported lags are always kept. "All" can cost a lot of space depending on how often incidents occur.' },
  ]);
  main.append(h('div', { style: { height: '16px' } }),
    section('Storage & Deep Capture', 'The daily summary is exempt from retention - '
      + 'it is tiny and keeps the long-term comparison alive.', ret));

  main.append(h('div', { style: { height: '16px' } }), databaseCard());
  main.append(h('div', { style: { height: '16px' } }), backupCard(cfg));

  // ---------------------------------------------------------------- account
  main.append(h('div', { style: { height: '16px' } }), await accountCard());
  foldSections(main, wiz);
}

// A dozen open forms made this the longest page of all. Every section but the diagnosis
// folds; which ones are open is remembered per browser.
const OPEN_KEY = 'nla-setup-open';
function foldSections(main, keep) {
  let open = [];
  try { open = JSON.parse(localStorage.getItem(OPEN_KEY) || '[]'); } catch { /* private mode */ }
  for (const card of main.querySelectorAll(':scope > .card.stack')) {
    const head = card.firstElementChild;
    const title = head?.querySelector('h3')?.textContent || head?.textContent;
    if (card === keep || !head || !title) continue;
    card.classList.add('fold');
    head.classList.add('fold-head');
    head.setAttribute('role', 'button');
    head.setAttribute('tabindex', '0');
    const set = isOpen => {
      card.classList.toggle('folded', !isOpen);
      head.setAttribute('aria-expanded', String(isOpen));
    };
    set(open.includes(title));
    const toggle = () => {
      const isOpen = card.classList.contains('folded');
      set(isOpen);
      open = isOpen ? [...new Set([...open, title])] : open.filter(t => t !== title);
      try { localStorage.setItem(OPEN_KEY, JSON.stringify(open)); } catch { /* private mode */ }
    };
    head.addEventListener('click', toggle);
    head.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
  }
}

async function accountCard() {
  const st = await api('api/auth/state');
  const card = h('div', { class: 'card stack' }, h('h3', null, 'Account & sessions'));
  if (!st.login_required) {
    card.append(h('p', { class: 'small muted' }, 'Login is switched off (dev mode or security.require_login: false).'));
    return card;
  }
  const cur = h('input', { type: 'password', placeholder: 'Current password', autocomplete: 'current-password', 'aria-label': 'Current password' });
  const user = h('input', { type: 'text', value: st.username || '', maxlength: '64', autocomplete: 'username', 'aria-label': 'Username' });
  const pw1 = h('input', { type: 'password', placeholder: 'New password (min. 10 characters)', autocomplete: 'new-password', 'aria-label': 'New password' });
  const pw2 = h('input', { type: 'password', placeholder: 'Repeat new password', autocomplete: 'new-password', 'aria-label': 'Repeat new password' });
  const save = h('button', { class: 'btn primary', type: 'button' }, 'Change password');
  save.addEventListener('click', async () => {
    if (pw1.value !== pw2.value) { toast('The new passwords do not match'); return; }
    try {
      await api('api/auth/password', { method: 'POST', body: { current_password: cur.value, new_password: pw1.value, new_username: user.value } });
      toast('Saved - all other sessions were signed out', 5000); cur.value = pw1.value = pw2.value = '';
    } catch (e) { toast(e.message, 5000); }
  });
  const all = h('button', { class: 'btn', type: 'button' }, 'Sign out everywhere');
  all.addEventListener('click', async () => {
    if (!confirm('Sign out all browsers, including this one?')) return;
    await api('api/auth/logout', { method: 'POST', body: { everywhere: true } }).catch(() => null);
    location.reload();
  });
  card.append(
    h('p', { class: 'small muted' }, 'Signed in as ' + st.username + '. Changing the password signs out every other browser. ',
      'A forgotten password can only be reset on the Raspberry Pi (python -m backend.account set, see the README).'),
    h('div', { class: 'form-grid' },
      h('div', { class: 'field' }, h('label', null, 'Username'), user),
      h('div', { class: 'field' }, h('label', null, 'Current password'), cur),
      h('div', { class: 'field' }, h('label', null, 'New password'), pw1),
      h('div', { class: 'field' }, h('label', null, 'Repeat'), pw2)),
    h('div', { class: 'row' }, save, all));
  return card;
}
