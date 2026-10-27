// One domain in detail: what it is, where its category comes from, who looked it up, how Pi-hole answered.
import { api, clear, fmtDateTime, h, toast, NA } from '../lib.js';

const nf = new Intl.NumberFormat('en-US');
const n = v => (v === null || v === undefined ? NA : nf.format(v));
const KIND_CLASS = { blocked: 'critical', allowed: 'good', duplicate: '', unknown: '' };

let dialog = null;
function ensureDialog() {
  if (dialog) return dialog;
  dialog = h('dialog', { class: 'modal', 'aria-label': 'Domain details' });
  dialog.addEventListener('click', ev => { if (ev.target === dialog) dialog.close(); });   // click on the backdrop
  document.body.append(dialog);
  return dialog;
}

/** A domain name that opens its details. */
export function domainLink(name, ctx) {
  if (!name) return h('i', null, 'other domains (folded)');
  const b = h('button', { type: 'button', class: 'linkish mono', title: 'What is this?' }, name);
  b.addEventListener('click', ev => { ev.stopPropagation(); openDomain(name, ctx); });
  return b;
}

function ruleForm(name, cls, ctx, suggestion) {
  const target = h('input', { type: 'text', value: suggestion || name, 'aria-label': 'Rule applies to', class: 'mono', style: { flex: 1 } });
  const boxes = Object.entries(ctx.labels).filter(([k]) => k !== 'unknown').map(([k, l]) => h('label', { class: 'check small', title: ctx.info[k] || '' },
    h('input', { type: 'checkbox', value: k, checked: cls.source === 'manual' && cls.categories.includes(k) }), l));
  const svc = h('input', { type: 'text', placeholder: 'Service name (optional)', maxlength: '64', value: cls.source === 'manual' ? (cls.service_name || '') : '' });
  const save = h('button', { class: 'btn primary', type: 'button' }, 'Save rule');
  save.addEventListener('click', async () => {
    const cats = boxes.map(b => b.firstChild).filter(x => x.checked).map(x => x.value);
    if (!cats.length) { toast('Choose at least one category'); return; }
    try {
      await api(`api/dns/rules/${encodeURIComponent(target.value.trim())}`, { method: 'PUT', body: { categories: cats, exact: false, service_name: svc.value } });
      toast('Rule saved - applies to the name and its subdomains');
      if (ctx.onChange) ctx.onChange();
      openDomain(name, ctx);
    } catch (e) { toast(e.message); }
  });
  return h('details', { class: 'rule-form', open: cls.source === null || null },
    h('summary', null, cls.source === 'manual' ? 'Change your rule' : 'Set the category yourself'),
    h('div', { class: 'stack-sm' },
      h('div', { class: 'row small' }, h('span', { class: 'muted' }, 'Applies to'), target),
      h('div', { class: 'check-grid' }, boxes),
      h('div', { class: 'row' }, svc, save),
      h('div', { class: 'small muted' }, 'Your rules win over the shipped list and the UT1 list for the same name.')));
}

function piholeButtons(name) {
  const box = h('section', { class: 'stack-sm', style: { display: 'none' } });
  api(`api/pihole/domain?name=${encodeURIComponent(name)}`).then(st => {
    box.style.display = '';
    const act = async (list, action, q) => {
      if (!window.confirm(q)) return;
      try {
        await api('api/pihole/domain', { method: 'POST', body: { domain: name, list, action, confirm: true } });
        toast('Pi-hole updated'); openDomain(name, lastCtx);
      } catch (e) { toast(`Pi-hole: ${e.message}`, 6000); }
    };
    box.append(h('h3', null, 'In Pi-hole'), h('div', { class: 'row' },
      st.allow ? h('button', { class: 'btn', type: 'button', onclick: () => act('allow', 'remove', `Remove ${name} from Pi-hole's allowlist?`) }, 'Remove from allowlist')
        : h('button', { class: 'btn', type: 'button', onclick: () => act('allow', 'add', `Always allow ${name} for all devices?`) }, 'Always allow'),
      st.deny ? h('button', { class: 'btn', type: 'button', onclick: () => act('deny', 'remove', `Remove ${name} from Pi-hole's denylist?`) }, 'Remove from denylist')
        : h('button', { class: 'btn', type: 'button', onclick: () => act('deny', 'add', `Block ${name} for all devices?`) }, 'Block'),
      h('span', { class: 'small muted' }, 'exactly this name, for all devices')));
  }).catch(() => null);           // actions off or Pi-hole not reachable: no buttons
  return box;
}

let lastCtx = null;
export async function openDomain(name, ctx) {
  lastCtx = ctx;
  const dlg = ensureDialog();
  const close = h('button', { class: 'icon-btn', type: 'button', 'aria-label': 'Close', onclick: () => dlg.close() }, '✕');
  clear(dlg).append(h('div', { class: 'modal-head' }, h('h2', { class: 'mono' }, name), close), h('div', { class: 'skeleton' }, 'Loading…'));
  if (!dlg.open) dlg.showModal();
  let r;
  try { r = await api(`api/dns/domain?name=${encodeURIComponent(name)}&${ctx.qs()}`); }
  catch (e) { dlg.lastChild.replaceWith(h('div', { class: 'empty' }, `Not available - ${e.message}`)); return; }
  const c = r.classification;
  const body = h('div', { class: 'stack' });
  body.append(
    h('section', { class: 'stack-sm' }, h('h3', null, 'What it is'),
      h('div', { class: 'row' }, ctx.badge(c.primary, c), c.also.length ? h('span', { class: 'small muted' }, `also: ${c.also.map(x => x.label).join(', ')}`) : null),
      c.service_name ? h('div', null, h('b', null, c.service_name),
        c.primary === 'infrastructure' ? h('span', { class: 'small muted' }, ' - provider, not the service that was used') : null) : null,
      c.description ? h('div', { class: 'small' }, c.description) : null),
    h('section', { class: 'stack-sm' }, h('h3', null, 'Where this comes from'),
      h('ul', { class: 'list' },
        h('li', { class: 'row small' }, h('span', { class: 'muted' }, 'Source'), h('span', { class: 'spacer' }), h('span', null, c.source_text)),
        c.rule ? h('li', { class: 'row small' }, h('span', { class: 'muted' }, 'Matching rule'), h('span', { class: 'spacer' }),
          h('span', { class: 'mono' }, c.rule.startsWith('=') ? `exactly ${c.rule.slice(1)}` : `${c.rule} and its subdomains`)) : null,
        h('li', { class: 'row small' }, h('span', { class: 'muted' }, 'Confidence'), h('span', { class: 'spacer' }),
          h('span', null, c.confidence ? `${c.confidence} - ${c.confidence_text}` : c.confidence_text)))),
    h('section', { class: 'stack-sm' }, h('h3', null, `Who looked it up (${r.resolution === 'hour' ? 'exact hours' : 'whole days'})`),
      r.clients.length ? h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' },
        h('thead', null, h('tr', null, h('th', null, 'Device'), h('th', { class: 'num' }, 'Lookups'), h('th', { class: 'num' }, 'Blocked'), h('th', null, 'Last'))),
        h('tbody', null, r.clients.map(x => h('tr', null,
          h('td', null, h('a', { href: `#/dns/client/${x.client}`, onclick: () => dlg.close() }, x.name),
            x.basis !== 'mac' ? h('span', { class: 'small muted' }, x.basis === 'ip' ? ' (IP only)' : ' (this Pi)') : null),
          h('td', { class: 'num' }, n(x.queries)), h('td', { class: 'num' }, n(x.blocked)),
          h('td', { class: 'small muted' }, x.last_seen ? fmtDateTime(x.last_seen) : '–')))))) : h('div', { class: 'empty' }, 'No lookups in this range.')),
    h('section', { class: 'stack-sm' }, h('h3', null, 'How Pi-hole answered (last 24 h)'),
      r.pihole.error ? h('div', { class: 'small muted' }, r.pihole.error)
        : r.pihole.statuses.length ? h('ul', { class: 'list' }, r.pihole.statuses.map(s => h('li', { class: 'row small' },
          h('span', { class: `badge ${KIND_CLASS[s.kind] || ''}` }, s.kind), h('span', null, s.text), h('span', { class: 'spacer' }), h('b', null, n(s.count)))))
          : h('div', { class: 'small muted' }, 'Not looked up in the last 24 hours.')),
    piholeButtons(name),
    ruleForm(name, c, ctx, ctx.suggestion),
    h('div', { class: 'small muted' }, r.note));
  dlg.lastChild.replaceWith(body);
}
