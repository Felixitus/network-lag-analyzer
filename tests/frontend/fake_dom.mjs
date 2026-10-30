// Just enough of a DOM for the helpers in frontend/js: elements, text nodes, CSS variables.
export class FakeNode {
  constructor(tag) { this.tagName = tag; this.children = []; this.attrs = {}; this.style = {}; this.dataset = {}; this.listeners = {}; this.parent = null; }
  setAttribute(k, v) { this.attrs[k] = v; }
  appendChild(c) { c.parent = this; this.children.push(c); return c; }
  append(...cs) { for (const c of cs) this.appendChild(c); }
  addEventListener(type, fn) { this.listeners[type] = fn; }
  remove() { if (this.parent) this.parent.children = this.parent.children.filter(c => c !== this); this.parent = null; }
  select() { this.selected = true; }
  get textContent() { return this.text ?? this.children.map(c => c.textContent).join(''); }
}

export const cssVars = { '--critical': '#d00', '--warning': '#d90', '--text-muted': '#999' };

export function install() {
  const body = new FakeNode('body');
  globalThis.Node = FakeNode;
  globalThis.document = {
    body,
    documentElement: new FakeNode('html'),
    cookie: '',
    copied: null,
    copyWorks: true,
    createElement: tag => new FakeNode(tag),
    createTextNode: text => Object.assign(new FakeNode('#text'), { text }),
    execCommand(cmd) {
      const ta = body.children.find(c => c.tagName === 'textarea' && c.selected);
      if (cmd !== 'copy' || !ta || !this.copyWorks) return false;
      this.copied = ta.value;
      return true;
    },
  };
  globalThis.getComputedStyle = () => ({ getPropertyValue: name => ` ${cssVars[name] || ''} ` });
  globalThis.window = { isSecureContext: false };
  // Node 21+ has a read-only navigator of its own
  Object.defineProperty(globalThis, 'navigator', { value: {}, configurable: true, writable: true });
}
