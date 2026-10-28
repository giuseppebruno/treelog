(() => {
'use strict';
const $ = s => document.querySelector(s);
const NS = 'http://www.w3.org/2000/svg';
const fmt = n => n >= 1e6 ? (n / 1e6).toFixed(1) + 'M' : n >= 1e4 ? (n / 1e3).toFixed(1) + 'k' : Math.round(n).toLocaleString('en-GB');
const pct = (a, b) => { if (!b) return '–'; const p = 100 * a / b; return (p < 10 && p > 0 ? p.toFixed(1) : Math.round(p)) + '%'; };
const store = { get(k, d) { try { return localStorage.getItem(k) || d; } catch (e) { return d; } }, set(k, v) { try { localStorage.setItem(k, v); } catch (e) {} } };

const outcome = c => c >= 500 ? 'error' : c >= 400 ? 'blocked' : c >= 300 ? 'redirect' : 'exposed';
const OUT = {
  blocked:  { label: 'Denied (4xx/444)', col: 'good', gl: '✓' },
  exposed:  { label: 'Served (2xx)',        col: 'warn', gl: '!' },
  redirect: { label: 'Redirected (3xx)',    col: 'neutral', gl: '→' },
  error:    { label: 'Server error (5xx)',  col: 'bad', gl: '✕' },
};
const CLS = c => { c = +c; return c >= 500 ? '5xx' : c >= 400 ? '4xx' : c >= 300 ? '3xx' : c >= 200 ? '2xx' : 'other'; };
const STATUS_COL = { '2xx': { col: 'good', gl: '✓' }, '3xx': { col: 'neutral', gl: '' }, '4xx': { col: 'warn', gl: '!' }, '5xx': { col: 'bad', gl: '✕' }, 'other': { col: 'neutral', gl: '' } };
const LVL_COL = { emerg: 'bad', alert: 'bad', crit: 'bad', error: 'serious', warn: 'warn', notice: 'neutral', info: 'neutral', debug: 'neutral' };
const GLYPH = { bad: '✕', serious: '!', warn: '!', neutral: '', good: '✓' };

let D = null, H = null, vhost = store.get('vhost', ''), view = store.get('view', 'cat'), win = +store.get('win', 86400), zoom = [], hideDenied = store.get('hideDenied', '') === '1';
let CAT = k => k;

const geoOn = () => !!(H && H.geo && H.geo.provider !== 'off');
const geoOf = r => (r.g || (D && D.geo && D.geo[r.ip])) || null;
const geoCountry = r => { const g = geoOf(r); return g ? (g[1] || 'Unknown') : 'Unknown'; };
const geoNet = r => { const g = geoOf(r); return g && g[2] ? (g[2] + ' ' + g[3]).trim() : (g && g[1] === 'Private network' ? 'Private network' : 'Unknown'); };
const ipLabel = r => { const g = geoOf(r); return g && g[0] ? `${r.ip} · ${g[0]}` : r.ip; };

// virtual host level: shown only when there are several hosts and none is selected
const HOSTD = r => r.host;
const showHost = () => !!D && D.vhosts.length > 1 && !vhost;
const hierOf = v => showHost() ? v.hier : v.hier.replace('Host › ', '');
const dimsOf = v => showHost() ? v.dims : v.dims.filter(d => d !== HOSTD);
const colAtk = r => OUT[r.o];
const colStatus = r => STATUS_COL[CLS(r.st)];
const colLvl = r => { const c = LVL_COL[r.lvl] || 'neutral'; return { col: c, gl: GLYPH[c] }; };
const VIEWS = {
  cat: { label: 'Attack type', hier: 'Class › Disposition › Host › Target URI', rows: () => D.atkR, dims: [r => CAT(r.cat), r => r.st, HOSTD, r => r.path], color: colAtk, legend: 'atk' },
  out: { label: 'By outcome', hier: 'Disposition › Class › Host › Target URI', rows: () => D.atkR, dims: [r => OUT[r.o].label, r => CAT(r.cat), HOSTD, r => r.path], color: colAtk, legend: 'atk' },
  ip: { label: 'By source IP', hier: 'Source IP › Class › Host › Status',    rows: () => D.ipR,  dims: [r => ipLabel(r), r => CAT(r.cat), HOSTD, r => r.st], color: colAtk, legend: 'atk' },
  path: { label: 'By URI', hier: 'Target URI › Host › Status',      rows: () => D.atkR, dims: [r => r.path, HOSTD, r => r.st], color: colAtk, legend: 'atk' },
  vhost: { label: 'By virtual host', hier: 'Virtual host › Disposition',           rows: () => D.vhostR, dims: [r => r.vhost, r => OUT[r.o].label], color: colAtk, legend: 'atk' },
  country: { label: 'By country', hier: 'Country › Class › Host › Status', rows: () => D.ipR, dims: [r => geoCountry(r), r => CAT(r.cat), HOSTD, r => r.st], color: colAtk, legend: 'atk' },
  asn: { label: 'By network (ASN)', hier: 'Network (ASN) › Class › Host › Status', rows: () => D.ipR, dims: [r => geoNet(r), r => CAT(r.cat), HOSTD, r => r.st], color: colAtk, legend: 'atk' },
  all: { label: 'All traffic', hier: 'All traffic',            rows: () => D.allR, dims: [r => r.kind, r => r.st], color: colStatus, legend: 'status' },
  e5: { label: '5xx on benign requests', hier: '5xx on benign requests',      rows: () => D.e5R,  dims: [r => r.path, HOSTD, r => r.st], color: colStatus, legend: 'status' },
  err: { label: 'Error log', hier: 'Error log',                     rows: () => D.errR, dims: [r => r.lvl, HOSTD, r => r.msg], color: colLvl, legend: 'lvl' },
};
const LEGENDS = {
  atk: [['good', '✓ Denied (4xx/444)'], ['warn', '! Served (2xx)'], ['neutral', '→ Redirected (3xx)'], ['bad', '✕ Server error (5xx)'], ['mixed', 'Mixed dispositions (open the group)']],
  status: [['good', '✓ 2xx'], ['neutral', '3xx / other'], ['warn', '! 4xx'], ['bad', '✕ 5xx'], ['mixed', 'Mixed']],
  lvl: [['bad', '✕ crit / alert / emerg'], ['serious', '! error'], ['warn', '! warn'], ['neutral', 'notice / info'], ['mixed', 'Mixed levels']],
};

$('#hide-denied').onclick = () => { hideDenied = !hideDenied; store.set('hideDenied', hideDenied ? '1' : ''); redraw(); };

function prepare(d) {
  CAT = k => d.categories[k] || k;
  d.vhostR = [];
  for (const [name, req, b, rd, ex, er] of d.vhosts) {
    for (const [o, n] of [['blocked', b], ['redirect', rd], ['exposed', ex], ['error', er]]) if (n) d.vhostR.push({ vhost: name, o, n });
  }
  d.atkR = d.atk.map(([host, cat, st, path, n]) => ({ host, cat, st, path, n, o: outcome(+st) }));
  d.ipR = d.ips.map(([host, ip, cat, st, n]) => ({ host, ip, cat, st, n, o: outcome(+st) }));
  d.errR = d.err.map(([host, lvl, msg, n]) => ({ host, lvl, msg, n }));
  d.e5R = d.e5.map(([host, path, st, n]) => ({ host, path, st, n }));
  const atkByStatus = {}; let atkTot = 0;
  for (const r of d.atkR) { atkByStatus[r.st] = (atkByStatus[r.st] || 0) + r.n; atkTot += r.n; }
  d.atkTot = atkTot;
  d.allR = [];
  let req = 0;
  for (const [st, n] of Object.entries(d.tot)) {
    req += n;
    const a = Math.min(atkByStatus[st] || 0, n);
    if (n - a > 0) d.allR.push({ kind: 'Benign', st, n: n - a });
    if (a > 0) d.allR.push({ kind: 'Hostile', st, n: a });
  }
  d.req = req;
  const cls = { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0 };
  for (const [st, n] of Object.entries(d.tot)) { const c = CLS(st); if (c in cls) cls[c] += n; }
  d.cls = cls;
  d.byOut = { blocked: 0, exposed: 0, redirect: 0, error: 0 };
  for (const r of d.atkR) d.byOut[r.o] += r.n;
}

function buildTree(rows, dims, colorFn) {
  const root = { name: 'Total', value: 0, kids: new Map(), col: undefined, gl: '' };
  const mix = (n, c) => { if (n.col === undefined) { n.col = c.col; n.gl = c.gl; } else if (n.col !== c.col) { n.col = 'mixed'; n.gl = ''; } };
  for (const r of rows) {
    const c = colorFn(r);
    let node = root; root.value += r.n; mix(root, c);
    for (const dim of dims) {
      const k = String(dim(r));
      let ch = node.kids.get(k);
      if (!ch) { ch = { name: k, value: 0, kids: new Map(), col: undefined, gl: '' }; node.kids.set(k, ch); }
      ch.value += r.n; mix(ch, c); node = ch;
    }
  }
  return root;
}
const sortedKids = n => [...n.kids.values()].sort((a, b) => b.value - a.value);

function worst(areas, side) {
  let s = 0, mx = 0, mn = Infinity;
  for (const a of areas) { s += a; if (a > mx) mx = a; if (a < mn) mn = a; }
  const s2 = s * s, w2 = side * side;
  return Math.max(w2 * mx / s2, s2 / (w2 * mn));
}
function squarify(items, x, y, w, h) {
  const total = items.reduce((a, n) => a + n.value, 0);
  if (!total || w <= 0 || h <= 0) return;
  const scale = w * h / total;
  let rest = items.slice();
  while (rest.length) {
    const short = Math.min(w, h);
    const row = []; let areas = [];
    while (rest.length) {
      const a = rest[0].value * scale, test = areas.concat(a);
      if (!row.length || worst(test, short) <= worst(areas, short)) { row.push(rest.shift()); areas = test; } else break;
    }
    const s = areas.reduce((p, c) => p + c, 0);
    if (w >= h) {
      const cw = s / h; let yy = y;
      for (const n of row) { const nh = n.value * scale / cw; n.r = [x, yy, cw, nh]; yy += nh; }
      x += cw; w -= cw;
    } else {
      const rh = s / w; let xx = x;
      for (const n of row) { const nw = n.value * scale / rh; n.r = [xx, y, nw, rh]; xx += nw; }
      y += rh; h -= rh;
    }
  }
}
const el = (tag, attrs, parent, text) => {
  const e = document.createElementNS(NS, tag);
  for (const k in attrs) e.setAttribute(k, attrs[k]);
  if (text !== undefined) e.textContent = text;
  if (parent) parent.appendChild(e);
  return e;
};
const fit = (s, w, cw = 6.3) => { const m = Math.max(0, Math.floor((w - 8) / cw)); return s.length <= m ? s : m > 1 ? s.slice(0, m - 1) + '…' : ''; };

function drawTree() {
  const v = VIEWS[view];
  const host = $('#tm');
  host.textContent = '';
  let rows = v.rows();
  const hiding = hideDenied && v.legend === 'atk';
  if (hiding) rows = rows.filter(r => r.o !== 'blocked');
  let node = buildTree(rows, dimsOf(v), v.color), total = node.value;
  const names = [];
  for (const z of zoom) { const nx = node.kids.get(z); if (!nx) break; node = nx; names.push(z); }
  zoom = names;
  renderCrumbs(total);
  if (!node.value) { const p = document.createElement('div'); p.className = 'empty'; p.textContent = hiding ? 'Nothing to show: every hostile request in this window was denied.' : 'No data in the selected time window.'; host.appendChild(p); return; }
  const W = host.clientWidth, Hh = host.clientHeight;
  const svg = el('svg', { width: W, height: Hh, viewBox: `0 0 ${W} ${Hh}`, role: 'img', 'aria-label': hierOf(v) }, host);
  svg.style.height = Hh + 'px';
  const walk = (n, x, y, w, h, path) => {
    const items = sortedKids(n).filter(k => k.value > 0);
    squarify(items, x, y, w, h);
    for (const k of items) {
      const [kx, ky, kw, kh] = k.r;
      if (kw < 5 || kh < 5) continue;
      const p = path.concat(k.name);
      const G = 1.5, bx = kx + G, by = ky + G, bw = kw - 2 * G, bh = kh - 2 * G;
      if (k.kids.size && kw >= 70 && kh >= 46) {
        const r = el('rect', { x: bx, y: by, width: bw, height: bh, rx: 7, class: 'grp zoomable' }, svg);
        r.__n = { k, p, g: true };
        el('text', { x: bx + 9, y: by + 15, class: 'ghd' }, svg, fit(k.name, bw - 56, 6.9));
        el('text', { x: bx + bw - 9, y: by + 15, class: 'ghd2', 'text-anchor': 'end' }, svg, fmt(k.value));
        walk(k, bx + 4, by + 22, bw - 8, bh - 26, p);
      } else {
        const r = el('rect', { x: bx, y: by, width: bw, height: bh, rx: Math.min(6, bw / 3, bh / 3), class: 'cell c-' + (k.col || 'neutral') + (k.kids.size ? ' zoomable' : '') }, svg);
        r.__n = { k, p, g: !!k.kids.size };
        if (bw > 44 && bh > 18) {
          el('text', { x: bx + 8, y: by + 16, class: 'lbl' }, svg, fit(k.name, bw, 6.8));
          if (bh > 34) el('text', { x: bx + 8, y: by + 31, class: 'lbl2' }, svg, (k.gl ? k.gl + ' ' : '') + fmt(k.value) + (bw > 70 ? ' req' : '') + (bw > 110 ? ' · ' + pct(k.value, node.value) : ''));
        }
      }
    }
  };
  walk(node, 0, 0, W, Hh, zoom);
  svg.__total = total; svg.__root = node.value;
  svg.addEventListener('mousemove', e => {
    const n = e.target.__n;
    if (!n) return hideTip();
    showTip(e, [['b', n.p.join(' › ')], ['', `${fmt(n.k.value)} requests · ${pct(n.k.value, node.value)} of level`]]
      .concat(n.k.col && n.k.col !== 'mixed' && v.legend === 'atk' ? [['', OUT[Object.keys(OUT).find(o => OUT[o].col === n.k.col)].label]] : []));
  });
  svg.addEventListener('mouseleave', hideTip);
  svg.addEventListener('click', e => {
    const n = e.target.__n;
    if (n && n.g) { zoom = n.p.slice(); hideTip(); drawTree(); }
  });
}
function renderCrumbs() {
  const c = $('#crumbs'); c.textContent = '';
  const mk = (label, depth, cur) => {
    if (cur) { const s = document.createElement('span'); s.className = 'cur'; s.textContent = label; c.appendChild(s); return; }
    const b = document.createElement('button'); b.type = 'button'; b.textContent = label;
    b.onclick = () => { zoom = zoom.slice(0, depth); drawTree(); };
    c.appendChild(b);
  };
  mk(hierOf(VIEWS[view]), 0, !zoom.length);
  zoom.forEach((z, i) => { c.appendChild(document.createTextNode(' › ')); mk(z, i + 1, i === zoom.length - 1); });
}

const tip = $('#tip');
function showTip(e, lines) {
  tip.textContent = '';
  for (const [t, s] of lines) { const d = document.createElement('div'); if (t === 'b') { const b = document.createElement('b'); b.textContent = s; d.appendChild(b); } else d.textContent = s; tip.appendChild(d); }
  tip.hidden = false;
  const r = tip.getBoundingClientRect();
  let x = e.clientX + 14, y = e.clientY + 14;
  if (x + r.width > innerWidth - 8) x = e.clientX - r.width - 14;
  if (y + r.height > innerHeight - 8) y = e.clientY - r.height - 14;
  tip.style.left = Math.max(4, x) + 'px'; tip.style.top = Math.max(4, y) + 'px';
}
const hideTip = () => { tip.hidden = true; };

function stackChart(hostSel, legSel, series, idx, defs) {
  const host = $(hostSel); host.textContent = '';
  const W = 600, Hh = 170, L = 38, R = 6, T = 8, B = 20, iw = W - L - R, ih = Hh - T - B;
  const svg = el('svg', { viewBox: `0 0 ${W} ${Hh}`, role: 'img' }, host);
  const tot = series.map(r => idx.reduce((a, i) => a + r[i + 1], 0));
  const mx = Math.max(1, ...tot);
  const mag = Math.pow(10, Math.floor(Math.log10(mx))), nice = [1, 2, 2.5, 5, 10].map(m => m * mag).find(v => v >= mx);
  for (let i = 0; i <= 3; i++) {
    const y = T + ih - ih * i / 3;
    el('line', { x1: L, x2: W - R, y1: y, y2: y, class: 'gl' }, svg);
    el('text', { x: L - 4, y: y + 3, 'text-anchor': 'end', class: 'ax' }, svg, fmt(nice * i / 3));
  }
  const n = series.length, bw = iw / n;
  const lab = t => { const d = new Date(t * 1000); const hm = d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' }); return D.window >= 86400 ? d.toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit' }) + ' ' + hm : hm; };
  series.forEach((row, k) => {
    let y = T + ih;
    idx.forEach((i, j) => {
      const v = row[i + 1]; if (!v) return;
      const h = Math.max(1, v / nice * ih);
      y -= h;
      el('rect', { x: L + k * bw + 0.5, y, width: Math.max(1, bw - 1), height: h, class: 'bar c-' + defs[j].col, 'stroke-width': 0.8 }, svg);
    });
    const hit = el('rect', { x: L + k * bw, y: T, width: bw, height: ih, fill: 'transparent' }, svg);
    hit.__i = k;
  });
  el('text', { x: L, y: Hh - 5, class: 'ax' }, svg, lab(series[0][0]));
  el('text', { x: W - R, y: Hh - 5, class: 'ax', 'text-anchor': 'end' }, svg, lab(series[n - 1][0]));
  svg.addEventListener('mousemove', e => {
    const k = e.target.__i; if (k === undefined) return hideTip();
    const row = series[k];
    showTip(e, [['b', lab(row[0]) + (D.bucket >= 3600 ? '' : ' (+' + Math.round(D.bucket / 60) + ' min)')]]
      .concat(idx.map((i, j) => ['', defs[j].name + ': ' + fmt(row[i + 1])])));
  });
  svg.addEventListener('mouseleave', hideTip);
  legend($(legSel), defs.map(d => [d.col, d.name]), true);
}
function legend(host, items, solid) {
  host.textContent = '';
  for (const [c, t] of items) {
    const s = document.createElement('span'); const i = document.createElement('i'); i.className = 'c-' + c + (solid ? ' solid' : '');
    s.appendChild(i); s.appendChild(document.createTextNode(t)); host.appendChild(s);
  }
}

function kpi(label, value, detail, state) {
  const d = document.createElement('div'); d.className = 'kpi ' + (state || '');
  for (const [c, t] of [['l', label], ['v', value], ['d', detail]]) { const x = document.createElement('div'); x.className = c; x.textContent = t; d.appendChild(x); }
  return d;
}
const HIGH = new Set(['rce', 'sqli', 'traversal', 'probe']);
function renderSummary() {
  const o = D.byOut, atk = D.atkTot, req = D.req;
  const k = $('#kpis'); k.textContent = '';
  const mins = Math.max(1, D.window / 60);
  k.appendChild(kpi('Requests', fmt(req), '≈ ' + (req / (D.window)).toFixed(1) + ' req/s'));
  const r5 = D.cls['5xx'];
  k.appendChild(kpi('5xx responses', fmt(r5), pct(r5, req) + ' of traffic', r5 / Math.max(1, req) > 0.01 ? 'bad' : r5 ? 'warn' : 'good'));
  k.appendChild(kpi('Hostile requests', fmt(atk), pct(atk, req) + ' of traffic · ' + fmt(D.ips_unique) + ' source IPs'));
  k.appendChild(kpi('Denied', pct(o.blocked, atk), fmt(o.blocked) + ' with 4xx/444', atk && o.blocked / atk > 0.9 ? 'good' : 'warn'));
  k.appendChild(kpi('Served 2xx', fmt(o.exposed), pct(o.exposed, atk) + ' of hostile requests', o.exposed ? 'warn' : 'good'));
  k.appendChild(kpi('Caused 5xx', fmt(o.error), pct(o.error, atk) + ' of hostile requests', o.error ? 'bad' : 'good'));
  const b = $('#banner');
  const hi2xx = D.atkR.filter(r => r.o === 'exposed' && HIGH.has(r.cat)).reduce((a, r) => a + r.n, 0);
  let act = null, cls = 'good', msg = '✓ No anomalies: every hostile request was answered with 4xx, 444 or a redirect.';
  if (!atk) msg = 'No hostile requests in the selected time window.';
  else if (o.error) { cls = 'bad'; msg = `✕ The server returned 5xx for ${fmt(o.error)} hostile requests (${pct(o.error, atk)}): possible instability under attack.`; act = ['Show affected URIs', 'error']; }
  else if (hi2xx) { cls = 'warn'; msg = `! ${fmt(hi2xx)} high-risk hostile requests (probing/SQLi/RCE/traversal) were served 2xx: review the list below.`; act = ['Show served requests', 'exposed']; }
  else if (o.exposed) { cls = 'warn'; msg = `! ${fmt(o.exposed)} hostile requests were served 2xx (usually catch-all routes or false positives): review needed.`; act = ['Show served requests', 'exposed']; }
  b.className = 'banner ' + cls; b.textContent = msg;
  if (act) {
    const go = (host) => {
      view = 'out'; zoom = [OUT[act[1]].label]; store.set('view', view);
      if (host !== undefined) { vhost = host; store.set('vhost', host); }
      const done = () => $('#tm').scrollIntoView({ behavior: 'smooth', block: 'center' });
      if (host !== undefined) load().then(done); else { renderViews(); redraw(); done(); }
    };
    const link = (text, host) => {
      const a = document.createElement('button'); a.type = 'button'; a.className = 'act'; a.textContent = text;
      a.onclick = () => go(host); return a;
    };
    // several virtual hosts, none selected: show where it happens and enter the right one
    const col = act[1] === 'error' ? 5 : 4;
    const hosts = vhost ? [] : D.vhosts.filter(v => v[col] > 0).sort((x, y) => y[col] - x[col]);
    if (D.vhosts.length > 1 && hosts.length) {
      b.appendChild(document.createTextNode(' '));
      hosts.slice(0, 4).forEach((v, i) => {
        if (i) b.appendChild(document.createTextNode(' · '));
        b.appendChild(link(v[0] + ' (' + fmt(v[col]) + ')', v[0]));
      });
      if (hosts.length > 4) b.appendChild(document.createTextNode(' · +' + (hosts.length - 4) + ' more'));
    } else {
      b.appendChild(link(act[0] + ' ›'));
    }
  }
  table('#tb-exposed', D.atkR.filter(r => r.o === 'exposed'));
  table('#tb-error', D.atkR.filter(r => r.o === 'error'));
}
function table(sel, rows) {
  const host = $(sel); host.textContent = '';
  if (!rows.length) { const p = document.createElement('div'); p.className = 'empty'; p.textContent = '✓ No requests in the selected time window.'; host.appendChild(p); return; }
  rows = rows.slice().sort((a, b) => (HIGH.has(b.cat) - HIGH.has(a.cat)) || b.n - a.n).slice(0, 10);
  const t = document.createElement('table');
  const hr = t.createTHead().insertRow();
  const withHost = showHost();
  for (const [h, c] of [['Class', ''], ...(withHost ? [['Host', '']] : []), ['Target URI', ''], ['Status', ''], ['Requests', 'n']]) { const th = document.createElement('th'); th.textContent = h; th.className = c; hr.appendChild(th); }
  const tb = t.createTBody();
  for (const r of rows) {
    const tr = tb.insertRow();
    const c0 = tr.insertCell(); const tg = document.createElement('span'); tg.className = 'tag'; tg.textContent = CAT(r.cat); c0.appendChild(tg);
    if (withHost) { const ch = tr.insertCell(); ch.className = 'p'; ch.textContent = r.host; }
    const c1 = tr.insertCell(); c1.className = 'p'; c1.textContent = r.path;
    tr.insertCell().textContent = r.st;
    const c3 = tr.insertCell(); c3.className = 'n'; c3.textContent = fmt(r.n);
  }
  host.appendChild(t);
}

function buildSeg(host, items, current, onPick) {
  host.textContent = '';
  for (const [val, label] of items) {
    const b = document.createElement('button'); b.type = 'button'; b.textContent = label;
    b.setAttribute('aria-pressed', String(val === current));
    if (val === 'vhost') b.dataset.vhost = '1';
    if (val === 'country') b.dataset.geo = '1';
    b.onclick = () => onPick(val);
    host.appendChild(b);
  }
}
function renderWindows() {
  const ret = H ? H.retention : 172800;
  const all = [[3600, '1 h'], [21600, '6 h'], [86400, '24 h'], [172800, '48 h'], [604800, '7 d']];
  const opts = all.filter(a => a[0] <= ret);
  if (!opts.some(a => a[0] === ret)) opts.push([ret, Math.round(ret / 3600) + ' h']);
  if (!opts.some(a => a[0] === win)) win = opts[opts.length - 1][0];
  buildSeg($('#windows'), opts, win, v => { win = v; store.set('win', v); renderWindows(); load(); });
}
function renderSites() {
  const sel = $('#vhost');
  const list = D.vhosts;
  sel.hidden = list.length < 2;
  if (vhost && !list.some(s => s[0] === vhost)) { vhost = ''; store.set('vhost', ''); }
  sel.textContent = '';
  const add = (v, t) => { const o = document.createElement('option'); o.value = v; o.textContent = t; if (v === vhost) o.selected = true; sel.appendChild(o); };
  add('', `All virtual hosts (${list.length})`);
  for (const s of list) add(s[0], `${s[0]} · ${fmt(s[1])} req`);
}
$('#vhost').onchange = e => { vhost = e.target.value; store.set('vhost', vhost); zoom = []; load(); };
function renderViews() {
  const multi = !D || D.vhosts.length > 1, geo = geoOn();
  if ((view === 'vhost' && !multi) || ((view === 'country' || view === 'asn') && !geo)) view = 'cat';
  buildSeg($('#views'), Object.entries(VIEWS).filter(([k]) => (k !== 'vhost' || multi) && ((k !== 'country' && k !== 'asn') || geo)).map(([k, v]) => [k, v.label]), view, v => { view = v; zoom = []; store.set('view', v); renderViews(); redraw(); });
}
function redraw() {
  if (!D) return;
  const hd = $('#hide-denied'), canHide = VIEWS[view].legend === 'atk';
  $('#hd-wrap').hidden = !canHide;
  hd.setAttribute('aria-pressed', String(hideDenied));
  legend($('#legend'), LEGENDS[VIEWS[view].legend]);
  drawTree();
}
function renderFoot() {
  const f = $('#foot');
  if (!H) return;
  const last = H.last_event ? new Date(H.last_event * 1000).toLocaleString('en-GB') : '–';
  const t = `Files tailed: ${H.files} · access lines parsed: ${fmt(H.ok)}` +
          ` · error lines: ${fmt(H.err_ok)} · last event: ${last}`;
  f.textContent = t;
  if (geoOn()) {
    const g = H.geo;
    if (g.state === 'ok') {
      f.appendChild(document.createTextNode(' · IP address data powered by '));
      const a = document.createElement('a'); a.href = 'https://ipinfo.io'; a.target = '_blank'; a.rel = 'noopener noreferrer'; a.textContent = 'IPinfo';
      f.appendChild(a);
    }
  }
}
const mb = n => n >= 1073741824 ? (n / 1073741824).toFixed(1) + ' GB' : Math.max(0.1, n / 1048576).toFixed(n < 10485760 ? 1 : 0) + ' MB';
let ldTimer = null;
function renderLoader() {
  const el = $('#loader'), on = !!(H && H.indexing && H.bytes_total > 0);
  el.hidden = !on;
  if (on) {
    const p = Math.min(100, Math.round(100 * H.bytes_done / H.bytes_total));
    $('#ld-text').textContent = `Initial indexing: file ${Math.min(H.files_done + 1, H.files)} of ${H.files} · ${mb(H.bytes_done)} / ${mb(H.bytes_total)} (${p}%). Figures are partial until it completes.`;
    $('#ld-bar').style.width = p + '%';
    if (!ldTimer) ldTimer = setInterval(load, 1500);
  } else if (ldTimer) { clearInterval(ldTimer); ldTimer = null; }
}
async function load() {
  try {
    const [h, d] = await Promise.all([fetch('/api/health', { cache: 'no-store' }), fetch('/api/data?w=' + win + (vhost ? '&vhost=' + encodeURIComponent(vhost) : ''), { cache: 'no-store' })]);
    if (!h.ok || !d.ok) throw new Error(h.status + '/' + d.status);
    const first = !H;
    H = await h.json(); D = await d.json();
    prepare(D);
    if (first) renderWindows();
    renderSites();
    loadExtras();
    if (first || (D.vhosts.length > 1) !== !!document.querySelector('#views button[data-vhost]') || geoOn() !== !!document.querySelector('#views button[data-geo]')) renderViews();
    renderSummary(); redraw(); renderFoot(); renderLoader();
    stackChart('#ch-traffic', '#lg-traffic', D.series, [0, 1, 2, 3], [
      { col: 'good', name: '2xx' }, { col: 'neutral', name: '3xx' }, { col: 'warn', name: '4xx' }, { col: 'bad', name: '5xx' }]);
    stackChart('#ch-attacks', '#lg-attacks', D.series, [4, 5, 6, 7], [
      { col: 'good', name: 'Denied (4xx/444)' }, { col: 'neutral', name: 'Redirected (3xx)' }, { col: 'warn', name: 'Served (2xx)' }, { col: 'bad', name: 'Server error (5xx)' }]);
  } catch (e) {
    $('#foot').textContent = 'Connection lost, retrying…';
  }
}


const REASONS = { scan: 'Enumeration (many distinct 404s)', brute: 'Credential brute force', flood: 'Request flood', attacks: 'Repeated attacks' };
const SEV = { critical: ['✕', 'Critical'], warning: ['!', 'Warning'], info: ['i', 'Info'], resolved: ['✓', 'Resolved'], test: ['i', 'Test'] };
const IPRE = /^[0-9a-fA-F:.]+$/;  // IPs come from logs: validate before building commands
let OFF = [];
const ago = t => { const s = Math.max(0, Date.now() / 1000 - t); return s < 90 ? 'now' : s < 5400 ? Math.round(s / 60) + ' min ago' : Math.round(s / 3600) + ' h ago'; };
function renderOffenders(o) {
  OFF = o.items;
  $('#ip-sub').textContent = `behavioural detection, last ${o.window} min`;
  const host = $('#tb-ips'); host.textContent = '';
  if (!o.items.length) { const p = document.createElement('div'); p.className = 'empty'; p.textContent = '✓ No offending IPs.'; host.appendChild(p); }
  else {
    const t = document.createElement('table');
    const hr = t.createTHead().insertRow();
    const geo = geoOn();
    for (const [h, c] of [['IP', ''], ...(geo ? [['Origin', '']] : []), ['Reason', ''], ['Requests', 'n'], ['Distinct 404s', 'n'], ['Last seen', 'n']]) { const th = document.createElement('th'); th.textContent = h; th.className = c; hr.appendChild(th); }
    const tb = t.createTBody();
    for (const x of o.items.slice(0, 12)) {
      const tr = tb.insertRow();
      const c0 = tr.insertCell(); c0.className = 'p'; c0.textContent = x.ip;
      if (x.private) { const g = document.createElement('span'); g.className = 'tag'; g.textContent = 'private'; c0.appendChild(document.createTextNode(' ')); c0.appendChild(g); }
      if (geo) {
        const g = x.geo, co = tr.insertCell(); co.className = 'org';
        co.textContent = g ? [g[0] || g[1], (g[2] + ' ' + g[3]).trim()].filter(Boolean).join(' · ') : '–';
        if (g && g[3]) co.title = g[1] + ' · ' + g[2] + ' ' + g[3];
      }
      const c1 = tr.insertCell();
      for (const r of x.reasons) { const g = document.createElement('span'); g.className = 'tag'; g.textContent = REASONS[r] || r; c1.appendChild(g); c1.appendChild(document.createTextNode(' ')); }
      for (const v of [x.req, x.p4]) { const c = tr.insertCell(); c.className = 'n'; c.textContent = fmt(v); }
      const c4 = tr.insertCell(); c4.className = 'n'; c4.textContent = ago(x.last);
    }
    host.appendChild(t);
  }
  renderExport();
}
function renderExport() {
  const ips = OFF.filter(x => !x.private && IPRE.test(x.ip)).map(x => x.ip);
  const f = $('#exp-fmt').value;
  const line = ip => f === 'nginx' ? `deny ${ip};` : f === 'apache' ? `Require not ip ${ip}` :
    f === 'iptables' ? `${ip.includes(':') ? 'ip6tables' : 'iptables'} -A INPUT -s ${ip} -j DROP` : ip;
  $('#exp-text').value = ips.map(line).join('\n');
  return ips.length;
}
$('#exp-fmt').onchange = renderExport;
$('#exp-copy').onclick = async () => {
  const n = renderExport(), msg = $('#exp-msg'), ta = $('#exp-text');
  if (!n) { msg.textContent = 'No IPs to copy.'; return; }
  try { await navigator.clipboard.writeText(ta.value); msg.textContent = n + ' IPs copied.'; }
  catch (e) { ta.closest('details').open = true; ta.select(); msg.textContent = 'Clipboard access denied by the browser: list selected.'; }
};
function renderAlerts(a) {
  $('#al-sub').textContent = a.channels.length ? 'channels: ' + a.channels.join(', ') : 'no channel configured';
  const host = $('#al-list'); host.textContent = '';
  if (!a.channels.length) { const p = document.createElement('div'); p.className = 'empty'; p.textContent = 'Set ALERT_NTFY_URL, ALERT_TELEGRAM_TOKEN + ALERT_TELEGRAM_CHAT_ID or ALERT_WEBHOOK_URL (see README).'; host.appendChild(p); }
  if (!a.history.length) { const p = document.createElement('div'); p.className = 'empty'; p.textContent = '✓ No recent alerts. Active rules: ' + a.rules.join(', ') + '.'; host.appendChild(p); return; }
  for (const h of a.history.slice(0, 8)) {
    const d = document.createElement('div'); d.className = 'al';
    const t = document.createElement('div'); t.className = 't'; t.textContent = new Date(h.t * 1000).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
    const s = document.createElement('div');
    const sv = document.createElement('span'); sv.className = 'sev ' + h.severity; sv.textContent = (SEV[h.severity] || ['', h.severity]).join(' ') + ' · ';
    s.appendChild(sv); s.appendChild(document.createTextNode(h.title));
    const m = document.createElement('div'); m.className = 'm';
    const dl = Object.entries(h.delivery).map(([k, v]) => k + ': ' + v).join(' · ');
    m.textContent = h.message + (dl ? '  [' + dl + ']' : '');
    d.appendChild(t); d.appendChild(s); d.appendChild(m); host.appendChild(d);
  }
}
$('#al-test').onclick = async () => {
  const msg = $('#al-msg'); msg.textContent = 'sending…';
  try {
    const r = await fetch('/api/alerts/test', { method: 'POST', headers: { 'X-Requested-With': 'fetch' } });
    const j = await r.json();
    const dl = Object.entries(j.delivery).map(([k, v]) => k + ': ' + v).join(' · ');
    msg.textContent = dl || 'no channel configured';
    loadExtras();
  } catch (e) { msg.textContent = 'error: ' + e.message; }
};
async function loadExtras() {
  try {
    const [a, o] = await Promise.all([fetch('/api/alerts', { cache: 'no-store' }), fetch('/api/offenders', { cache: 'no-store' })]);
    if (a.ok) renderAlerts(await a.json());
    if (o.ok) renderOffenders(await o.json());
  } catch (e) { /* the footer already reports the lost connection */ }
}

const root = document.documentElement;
const th = store.get('theme', '');
if (th) root.setAttribute('data-theme', th);
$('#theme').onclick = () => {
  const dark = root.getAttribute('data-theme') === 'dark' || (!root.getAttribute('data-theme') && matchMedia('(prefers-color-scheme: dark)').matches);
  const n = dark ? 'light' : 'dark'; root.setAttribute('data-theme', n); store.set('theme', n);
};

renderViews(); renderWindows(); load();
setInterval(() => { if (!document.hidden) load(); }, 10000);
let rt; addEventListener('resize', () => { clearTimeout(rt); rt = setTimeout(redraw, 150); });
})();
