/* Vulnio prototype: state, actions, router and shell */
window.App = (() => {
  const SEED = window.VULNIO_SEED;
  const E = window.Engine;
  const { esc, ic, initials } = window.UI;
  const KEY = 'vulnio-demo-v1';
  const DAY = SEED.DAY;
  const clone = (o) => JSON.parse(JSON.stringify(o));

  let S;
  const ui = { open: new Set(), policyKey: 'default', demoOpen: false, menuOpen: false, filters: {}, busy: {}, ask: [] };
  let cache = null;

  function fresh() {
    const s = clone(SEED);
    delete s.incomingAdvisory;
    s.clockOffset = 0; s.role = 'analyst'; s.demo = {}; s.seq = 1000;
    return s;
  }
  function sync() { S.now = SEED.BASE + S.clockOffset * DAY; cache = null; }
  function load() {
    try { const raw = localStorage.getItem(KEY); S = raw ? JSON.parse(raw) : fresh(); } catch { S = fresh(); }
    sync();
  }
  function save() { try { localStorage.setItem(KEY, JSON.stringify(S)); } catch { /* ignore */ } }

  const list = () => (cache ||= E.all(S));
  const listAll = () => E.all(S, { includePreview: true });
  const me = () => S.people[S.roles[S.role].person];
  const adv = (id) => S.advisories.find(a => a.id === id);
  const id = (p) => p + (++S.seq);

  /* -------------------------------------------------------- reassessment */
  function snapshot() {
    const m = new Map();
    for (const a of list()) m.set(a.advisory + '|' + a.asset, { outcome: a.outcome, band: a.priority.band, score: a.priority.score });
    return m;
  }

  function mutate(reason, fn, { toastTitle } = {}) {
    const before = snapshot();
    fn();
    sync();
    const after = snapshot();
    const changes = [];
    for (const [k, v] of after) {
      const [advisory, asset] = k.split('|');
      const b = before.get(k);
      if (!b) { changes.push({ advisory, asset, from: null, to: v.outcome }); continue; }
      if (b.outcome !== v.outcome) changes.push({ advisory, asset, from: b.outcome, to: v.outcome });
      else if (v.outcome === 'affected' && (b.band !== v.band || Math.abs(b.score - v.score) >= 4)) changes.push({ advisory, asset, kind: 'priority', from: b.band, to: v.band, fromScore: b.score, score: v.score });
    }
    for (const c of changes) {
      if (c.kind === 'priority') S.history.push({ at: new Date(S.now).toISOString(), kind: 'priority', advisory: c.advisory, asset: c.asset, from: c.from, to: c.to, fromScore: c.fromScore, score: c.score, reason });
      else S.history.push({ at: new Date(S.now).toISOString(), kind: 'outcome', advisory: c.advisory, asset: c.asset, from: c.from, to: c.to, reason });
    }
    save();
    render();
    toast(toastTitle || (changes.length ? `Reassessed: ${changes.length} result${changes.length > 1 ? 's' : ''} changed` : 'Reassessed: no outcome changes'), changes, reason);
    return changes;
  }

  /* ---------------------------------------------------------------- toast */
  function toast(title, changes = [], sub = '') {
    const el = document.createElement('div');
    el.className = 'toast';
    const items = changes.slice(0, 5).map(c => c.kind === 'priority'
      ? `<div>${esc(c.asset)} · ${esc(c.advisory)}: priority <span class="band band-${c.from}">${c.fromScore}</span> → <span class="band band-${c.to}">${c.score} · ${E.BAND[c.to]}</span></div>`
      : `<div>${esc(c.asset)} · ${esc(c.advisory)}: ${c.from ? `<b style="display:inline" class="${c.from === 'affected' ? 'red-t' : c.from === 'not_affected' ? 'green-t' : 'amber-t'}">${UI.OUT[c.from]}</b> → ` : 'new → '}<b style="display:inline" class="${c.to === 'affected' ? 'red-t' : c.to === 'not_affected' ? 'green-t' : 'amber-t'}">${UI.OUT[c.to]}</b></div>`).join('');
    el.innerHTML = `<b>${esc(title)}</b>${sub ? `<div class="small dim" style="margin-top:2px">${esc(sub)}</div>` : ''}${items ? `<div class="items">${items}${changes.length > 5 ? `<div>+${changes.length - 5} more</div>` : ''}</div>` : ''}`;
    document.getElementById('toasts').appendChild(el);
    setTimeout(() => { el.style.transition = 'opacity .3s'; el.style.opacity = '0'; setTimeout(() => el.remove(), 300); }, changes.length ? 6500 : 3500);
  }

  /* ---------------------------------------------------------------- modal */
  function modal(html) {
    const root = document.getElementById('modal');
    root.innerHTML = html ? `<div class="overlay" data-action="closeModal" data-self="1"><div class="modal">${html}</div></div>` : '';
  }

  /* -------------------------------------------------------------- actions */
  function addFact(asset, attr, value, source, note, extra = {}) {
    S.facts = S.facts.filter(f => !(f.asset === asset && f.attr === attr && f.source === source));
    S.facts.push({ id: id('f'), asset, attr, value, source, observedAt: new Date(S.now).toISOString(), note, ...extra });
  }

  const actions = {
    nav: (d) => { location.hash = d.href; },
    closeModal: (d, ev) => { if (d.self && ev.target !== ev.currentTarget) return; modal(''); },
    toggleClaim: (d) => { ui.open.has(d.key) ? ui.open.delete(d.key) : ui.open.add(d.key); document.querySelector(`[data-row="${d.key}"]`)?.classList.toggle('open'); },
    role: (d) => { S.role = d.role; ui.menuOpen = false; save(); location.hash = S.roles[d.role].landing; render(); },
    menu: () => { ui.menuOpen = !ui.menuOpen; render(); },
    demo: () => { ui.demoOpen = !ui.demoOpen; render(); },
    filter: (d) => { ui.filters[d.group] = ui.filters[d.group] === d.value ? null : d.value; render(); },
    policyView: (d) => { ui.policyKey = d.value; render(); },

    /* evidence */
    answer: (d) => openAnswer(d.adv, d.asset, d.claim),
    submitAnswer: (d) => {
      const a = adv(d.adv), c = a.claims.find(x => x.id === d.claim);
      const form = document.getElementById('answer-form');
      let v;
      if (c.question.type === 'bool' || c.question.type === 'choice') {
        const sel = form.querySelector('input[name=v]:checked');
        if (!sel) return toast('Pick an answer first');
        if (sel.value === '__unknown') { modal(''); return actions.askOwner(d); }
        v = c.question.type === 'bool' ? sel.value === 'yes' : sel.value;
      } else {
        const raw = form.querySelector('input[name=v]').value.trim();
        if (!raw) return toast('Enter a value first');
        v = c.question.type === 'number' ? Number(raw) : raw;
      }
      const comment = form.querySelector('textarea').value.trim();
      const who = me();
      modal('');
      mutate(`${who.name} answered: ${c.label} → ${E.vtxt(v)}`, () => {
        addFact(d.asset, c.attr, v, 'human', `${who.name}: ${comment || 'answered guided question'}`, { by: who.id });
        S.tasks.filter(t => t.status === 'open' && t.asset === d.asset && adv(t.advisory)?.claims.find(z => z.id === t.claim)?.attr === c.attr)
          .forEach(t => { t.status = 'done'; t.doneAt = new Date(S.now).toISOString(); t.answer = E.vtxt(v); });
      });
    },
    askOwner: (d) => {
      const a = adv(d.adv), c = a.claims.find(x => x.id === d.claim), asset = S.assets[d.asset];
      if (S.tasks.some(t => t.status === 'open' && t.asset === d.asset && t.advisory === d.adv && t.claim === d.claim)) return toast('A question is already open for this condition');
      S.tasks.push({ id: id('t'), advisory: d.adv, asset: d.asset, claim: d.claim, assignee: asset.owner, by: me().id, createdAt: new Date(S.now).toISOString(), status: 'open', note: '' });
      save(); render();
      toast(`Question sent to ${S.people[asset.owner].name}`, [], `"${c.question.text}"`);
    },
    runAgent: (d) => {
      const asset = S.assets[d.asset];
      if (!asset.agent) return toast(`No agent on ${asset.name}`, [], 'Use a platform API or ask the owner instead.');
      ui.busy[d.asset] = true; render();
      setTimeout(() => {
        delete ui.busy[d.asset];
        mutate(`Vulnio Agent collected fresh observations on ${asset.name}`, () => {
          S.connectorIssues = S.connectorIssues.filter(i => !(i.asset === d.asset && i.source === 'agent'));
          const latest = new Map();
          S.facts.filter(f => f.asset === d.asset && f.source === 'agent').forEach(f => latest.set(f.attr, f));
          for (const [attr, f] of latest) addFact(d.asset, attr, f.value, 'agent', f.note);
          for (const [attr, v, note] of (S.probes[d.asset] || [])) addFact(d.asset, attr, v, 'agent', note);
        });
      }, 1300);
    },

    /* claim governance */
    claimStatus: (d) => {
      const a = adv(d.adv), c = a.claims.find(x => x.id === d.claim);
      const who = me();
      if (a.definition.status !== 'approved') { c.status = d.status; save(); render(); return; }
      mutate(`Definition v${a.definition.version + 1}: ${who.name} ${d.status === 'rejected' ? 'rejected' : 'restored'} claim ${c.id} "${c.label}"`, () => {
        c.status = d.status;
        bumpVersion(a, `${d.status === 'rejected' ? 'Rejected' : 'Restored'} ${c.id} "${c.label}"`);
      });
    },
    editClaim: (d) => openEdit(d.adv, d.claim),
    saveEdit: (d) => {
      const a = adv(d.adv), c = a.claims.find(x => x.id === d.claim);
      const raw = document.getElementById('edit-val').value.trim();
      let value;
      try { value = parseValue(c, raw); } catch (e) { return toast('Could not parse value', [], e.message); }
      modal('');
      const before = E.exprText(c);
      const apply = () => { c.value = value; c.origin = c.origin === 'structured' ? 'reviewer' : c.origin === 'ai' ? 'reviewer' : c.origin; c.edited = true; };
      if (a.definition.status !== 'approved') { apply(); save(); render(); return; }
      mutate(`Definition v${a.definition.version + 1}: ${me().name} corrected ${c.id}`, () => { apply(); bumpVersion(a, `Corrected ${c.id}: ${before} → ${E.exprText(c)}`); });
    },
    approveDefinition: (d) => {
      const a = adv(d.adv);
      mutate(`${me().name} approved ${a.id} definition v1`, () => {
        a.definition = { version: 1, status: 'approved', by: me().id, at: new Date(S.now).toISOString() };
        a.versions.push({ version: 1, at: a.definition.at, by: me().id, note: `Approved ${a.claims.filter(c => c.status === 'accepted').length} claims${a.claims.some(c => c.status === 'rejected') ? `, rejected ${a.claims.filter(c => c.status === 'rejected').length}` : ''}` });
        S.history.push({ at: a.definition.at, kind: 'definition', advisory: a.id, text: `Definition v1 approved; assessments are now live`, by: me().id });
      }, { toastTitle: `${a.id} is live` });
    },
    approveUpdate: (d) => {
      const a = adv(d.adv), u = a.pendingUpdate;
      mutate(`${a.id} definition v${a.definition.version + 1}: vendor rev ${u.intel.rev} removed claim ${u.removeClaim}`, () => {
        const c = a.claims.find(x => x.id === u.removeClaim);
        c.status = 'retired'; delete c.pendingChange;
        bumpVersion(a, `Vendor rev ${u.intel.rev}: retired ${c.id} "${c.label}"`);
        a.pendingUpdate = null; a.updateApplied = true;
      });
    },

    /* evidence policy */
    moveSource: (d) => {
      const p = S.policy.precedence, i = p.indexOf(d.src), j = i + Number(d.dir);
      if (j < 0 || j >= p.length) return;
      mutate(`Evidence policy: ${S.sources[d.src].name} moved ${d.dir < 0 ? 'up' : 'down'} in source precedence`, () => { [p[i], p[j]] = [p[j], p[i]]; });
    },
    setFresh: (d) => {
      const v = Math.max(1, Number(d.value) || 1);
      mutate(`Evidence policy: ${S.sources[d.src].name} freshness limit set to ${v} days`, () => { S.policy.freshness[d.src] = v; });
    },
    setMode: (d) => mutate(`Evidence policy: conflict handling set to "${d.value}"`, () => { S.policy.mode = d.value; }),

    /* ask */
    ask: (d) => {
      const q = d.q ?? document.getElementById('ask-input')?.value ?? '';
      if (!q.trim()) return;
      ui.ask.push({ q: q.trim(), at: S.now });
      if (!location.hash.startsWith('#/ask')) location.hash = '#/ask'; else render();
      setTimeout(() => { const el = document.getElementById('ask-end'); el && el.scrollIntoView({ behavior: 'smooth' }); }, 30);
    },
    clearAsk: () => { ui.ask = []; render(); },

    /* demo scenario */
    vendorUpdate: () => {
      const a = adv('CVE-2024-3400');
      if (!a.pendingUpdate || a.pendingUpdate.arrived) return toast('Already applied');
      a.pendingUpdate.arrived = new Date(S.now).toISOString();
      const u = a.pendingUpdate;
      a.intel = a.intel.map(i => i.source === u.intel.source ? { ...u.intel } : i);
      a.passages = a.passages.map(p => p.id === u.passage.id ? { ...p, text: u.passage.text, changed: true } : p);
      a.claims.find(c => c.id === u.removeClaim).pendingChange = 'remove';
      S.history.push({ at: u.arrived, kind: 'definition', advisory: a.id, text: `Vendor advisory revision ${u.intel.rev} ingested. AI proposes retiring claim ${u.removeClaim} (device telemetry). Awaiting review; current results still use v${a.definition.version}.` });
      S.demo.vendor = true; save(); render();
      toast('Palo Alto updated CVE-2024-3400', [], 'AI proposes a definition change. Review it on the advisory page.');
    },
    ingest: () => {
      if (adv('CVE-2025-22224')) return toast('Already ingested');
      const a = clone(SEED.incomingAdvisory);
      a.ingestedAt = new Date(S.now).toISOString();
      S.advisories.unshift(a);
      S.history.push({ at: a.ingestedAt, kind: 'definition', advisory: a.id, text: 'New advisory ingested from NCSC CSAF feed. 3 claims proposed; awaiting review.' });
      S.demo.ingest = true; save(); render();
      toast('New advisory: CVE-2025-22224 (VMware ESXi)', [], 'Claims extracted and ready for review.');
    },
    clock: (d) => {
      const days = Number(d.days);
      mutate(`${days} days later: healthy connectors kept syncing, broken ones did not`, () => {
        const issue = S.connectorIssues.find(i => i.trigger === 'clock');
        const first = issue && !issue.since;
        S.clockOffset += days;
        const now = SEED.BASE + S.clockOffset * DAY;
        S.connectorIssues.forEach(i => { if (i.trigger === 'clock' && !i.since) i.since = new Date(SEED.BASE + 1 * DAY).toISOString(); });
        const blocked = (f) => S.connectorIssues.some(i => i.asset === f.asset && i.source === f.source);
        for (const f of S.facts) {
          if (!S.autoRefresh.includes(f.source) || blocked(f)) continue;
          const lag = (S.sources[f.source].sync ?? 1) * DAY;
          f.observedAt = new Date(Math.max(Date.parse(f.observedAt), now - lag)).toISOString();
        }
        if (first) S.history.push({ at: issue.since, kind: 'conflict', advisory: 'CVE-2023-4966', asset: 'ns-gw-02', text: issue.note + '. Its observations age out after 7 days.' });
      });
    },
    reset: () => { localStorage.removeItem(KEY); ui.ask = []; ui.open.clear(); load(); location.hash = '#/overview'; render(); toast('Demo reset'); },
  };

  function bumpVersion(a, note) {
    a.definition.version += 1;
    a.definition.by = me().id; a.definition.at = new Date(S.now).toISOString();
    a.versions.push({ version: a.definition.version, at: a.definition.at, by: me().id, note });
    S.history.push({ at: a.definition.at, kind: 'definition', advisory: a.id, text: `Definition v${a.definition.version}: ${note}`, by: me().id });
  }

  function parseValue(c, raw) {
    if (c.op === 'version_ranges') {
      const ranges = raw.split(',').map(s => s.trim()).filter(Boolean).map(s => {
        const m = s.match(/^(\S*)\s*(?:\.\.|–|-{2}|to)\s*(\S*)$/);
        if (!m) throw new Error('Use "from..to", e.g. 8.5p1..9.8p1 (leave a side empty for open ranges)');
        return { ...(m[1] ? { gte: m[1] } : {}), ...(m[2] ? { lt: m[2] } : {}) };
      });
      return { ranges, except: c.value.except || [] };
    }
    if (c.op === 'in') return raw.split(',').map(s => s.trim()).filter(Boolean);
    if (typeof c.value === 'boolean') return raw === 'true';
    if (typeof c.value === 'number') return Number(raw);
    return raw;
  }

  function openEdit(advId, claimId) {
    const a = adv(advId), c = a.claims.find(x => x.id === claimId);
    let v = c.value;
    if (c.op === 'version_ranges') v = c.value.ranges.map(r => `${r.gte || ''}..${r.lt || ''}`).join(', ');
    else if (c.op === 'in') v = c.value.join(', ');
    modal(`<div class="hd"><div class="eyebrow">${esc(a.id)} · ${c.id}</div><h3>Correct claim</h3></div>
      <div class="bd">
        <div><b>${esc(c.label)}</b><div class="small muted" style="margin-top:4px">Source passage: “${esc(c.quote)}”</div></div>
        <div><div class="small dim" style="margin-bottom:6px">Expected value for <code>${esc(c.attr)}</code> (${esc(c.op)})</div>
        <input class="inp mono" id="edit-val" value="${esc(E.vtxt(v))}"></div>
        ${c.op === 'version_ranges' ? '<div class="help">Ranges as <code>from..to</code> (from inclusive, to exclusive), comma separated. Example: <code>..4.4p1, 8.5p1..9.8p1</code></div>' : ''}
        <div class="note">${ic('history')}Saving creates a new definition version and reassesses every asset in scope. The previous version stays in the audit trail.</div>
      </div>
      <div class="ft"><button class="btn ghost" data-action="closeModal">Cancel</button><button class="btn primary" data-action="saveEdit" data-adv="${a.id}" data-claim="${c.id}">Save & reassess</button></div>`);
  }

  function openAnswer(advId, assetId, claimId) {
    const a = adv(advId), c = a.claims.find(x => x.id === claimId), asset = S.assets[assetId];
    const cur = E.assess(S, a, assetId);
    const cf = E.counterfactuals(S, cur).find(x => x.result.claim.id === claimId);
    const q = c.question;
    const inputs = q.type === 'bool'
      ? `<div class="opt-row"><label><input type="radio" name="v" value="yes"> Yes</label><label><input type="radio" name="v" value="no"> No</label><label><input type="radio" name="v" value="__unknown"> I don't know</label></div>`
      : q.type === 'choice'
        ? `<div class="opt-row">${q.options.map(o => `<label><input type="radio" name="v" value="${esc(o)}"> ${esc(o)}</label>`).join('')}</div>`
        : `<input class="inp mono" name="v" placeholder="${q.type === 'number' ? 'e.g. 120' : 'value'}" ${q.type === 'number' ? 'type="number"' : ''}>`;
    const o = (x) => x ? `<span class="${x === 'affected' ? 'red-t' : x === 'not_affected' ? 'green-t' : 'amber-t'} b">${UI.OUT[x]}</span>` : '<span class="dim">no change</span>';
    modal(`<div class="hd"><div class="eyebrow">${esc(a.id)} · ${esc(asset.name)}</div><h3>${esc(q.text)}</h3></div>
      <form class="bd" id="answer-form" onsubmit="return false">
        <div class="help"><b style="color:var(--text)">How to verify:</b> ${UI.md(c.howTo)}</div>
        ${inputs}
        <textarea class="inp" rows="2" placeholder="Optional: how did you verify this? (stored with the evidence)"></textarea>
        <div class="outcome-preview">
          <div><div class="tiny dim">IF CONDITION HOLDS</div>${o(cf?.variants.true)}</div>
          <div><div class="tiny dim">IF CONDITION IS DISPROVED</div>${o(cf?.variants.false)}</div>
        </div>
        <div class="note">${ic('user')}Recorded as an owner attestation by ${esc(me().name)}, time-stamped now and valid for ${S.policy.freshness.human} days. Machine evidence can override it per the evidence policy.</div>
      </form>
      <div class="ft"><button class="btn ghost" data-action="closeModal">Cancel</button><button class="btn primary" data-action="submitAnswer" data-adv="${a.id}" data-asset="${assetId}" data-claim="${c.id}">Submit & reassess</button></div>`);
  }

  /* ---------------------------------------------------------------- router */
  function route() {
    const [path, query] = (location.hash || '#/overview').slice(2).split('?');
    if (query) {
      const qs = new URLSearchParams(query);
      if (qs.get('o')) { ui.filters = { ...ui.filters, o: qs.get('o'), flag: null, adv: null }; }
      history.replaceState(null, '', '#/' + path);
    }
    const h = path.split('/').map(decodeURIComponent);
    const [p, x, y] = h;
    const V = window.Views;
    switch (p) {
      case 'overview': case '': return V.overview();
      case 'ask': return V.ask();
      case 'advisories': return V.advisories();
      case 'advisory': return V.advisory(x);
      case 'assessments': return V.assessments();
      case 'assessment': return V.assessment(x, y);
      case 'priorities': return V.priorities();
      case 'gaps': return V.gaps();
      case 'assets': return V.assets();
      case 'asset': return V.asset(x);
      case 'sources': return V.sources();
      case 'history': return V.history();
      case 'tasks': return V.tasks();
      default: return V.overview();
    }
  }

  function navItem(href, icon, label, count, cls = '') {
    const cur = (location.hash || '#/overview').split('?')[0];
    const prefix = { '#/advisories': '#/advisor', '#/assessments': '#/assessment', '#/assets': '#/asset/' }[href];
    const on = cur === href || (prefix && cur.startsWith(prefix));
    return `<a class="nav-item ${on ? 'on' : ''}" href="${href}">${ic(icon)}<span>${label}</span>${count ? `<span class="count ${cls}">${count}</span>` : ''}</a>`;
  }

  function shell(view) {
    const L = list();
    const c = UI.count(L);
    const pendingDefs = S.advisories.filter(a => a.definition.status !== 'approved' || (a.pendingUpdate && a.pendingUpdate.arrived)).length;
    const myTasks = S.tasks.filter(t => t.status === 'open' && (S.role === 'analyst' || t.assignee === me().id)).length;
    const gaps = E.gaps(S, L).length;
    const shifted = S.clockOffset !== 0;
    const u = me();
    return `
    <div class="shell">
      <aside class="side">
        <a href="#/overview"><img class="logo" src="assets/vulnio-logo.svg" alt="Vulnio"></a>
        ${navItem('#/overview', 'overview', 'Overview')}
        ${navItem('#/ask', 'ask', 'Ask Vulnio')}
        <div class="sec">Intelligence</div>
        ${navItem('#/advisories', 'advisory', 'Advisories & claims', pendingDefs)}
        <div class="sec">Assessment</div>
        ${navItem('#/assessments', 'shield', 'Assessments')}
        ${navItem('#/priorities', 'target', 'Priorities', c.affected, 'red')}
        ${navItem('#/gaps', 'search', 'Evidence gaps', gaps)}
        ${navItem('#/tasks', 'inbox', S.role === 'analyst' || S.role === 'ciso' ? 'Owner questions' : 'My questions', myTasks)}
        <div class="sec">Environment</div>
        ${navItem('#/assets', 'server', 'Systems & services')}
        ${navItem('#/sources', 'plug', 'Evidence sources')}
        <div class="sec">Audit</div>
        ${navItem('#/history', 'history', 'History')}
        <div class="foot">Noordhaven Logistics B.V.<br>Prototype, demo data only.</div>
      </aside>
      <div class="main">
        <div class="topbar">
          <div class="crumbs">${view.crumbs || ''}</div>
          <form class="ask" onsubmit="App.act('ask',{q:this.q.value});this.q.value='';return false">${ic('sparkle')}<input name="q" placeholder="Ask: Are we vulnerable to CVE-2024-6387?"></form>
          <div class="clock ${shifted ? 'shifted' : ''}" title="Assessments are valid for a point in time"><span class="live"></span>${shifted ? 'Simulated: ' : 'Evidence as of '}${UI.fmtDT(S.now)}</div>
          <div class="role">
            <button class="role-btn" data-action="menu"><span class="avatar">${initials(u.name)}</span><span class="who"><b>${esc(u.name)}</b><small>${esc(S.roles[S.role].label)}</small></span></button>
            ${ui.menuOpen ? `<div class="menu"><div class="hd">View the product as</div>${Object.values(S.roles).map(r => { const p = S.people[r.person]; return `<button class="mi ${r.id === S.role ? 'on' : ''}" data-action="role" data-role="${r.id}"><span class="avatar sm">${initials(p.name)}</span><span><b>${esc(r.label)}</b><small>${esc(p.name)} · ${esc(p.title)}</small></span></button>`; }).join('')}</div>` : ''}
          </div>
        </div>
        <div class="page">${view.html}</div>
      </div>
    </div>
    ${demoPanel()}`;
  }

  function demoPanel() {
    const d = S.demo || {};
    const it = (n, action, title, sub, done, extra = '') => `<button class="it ${done ? 'done' : ''}" data-action="${action}" ${extra}><span class="n">${n}</span><span><b>${title}</b><small>${sub}</small></span></button>`;
    return `<div class="demo-fab"><button class="btn violet" data-action="demo">${ic('play')}Demo scenario</button></div>
    ${ui.demoOpen ? `<div class="demo-panel"><div class="hd"><b>Demo scenario</b><small>Trigger real-world changes and watch Vulnio reassess.</small></div>
      ${it(1, 'runAgent', 'Agent reconnects on bastion-01', 'Closes 3-week-old evidence gaps', S.facts.some(f => f.asset === 'bastion-01' && f.attr === 'openssh.distro_fix'), 'data-asset="bastion-01"')}
      ${it(2, 'vendorUpdate', 'Palo Alto revises CVE-2024-3400', '"Telemetry no longer required"', d.vendor)}
      ${it(3, 'ingest', 'New advisory from NCSC feed', 'VMware ESXi CVE-2025-22224 (KEV)', d.ingest)}
      ${it(4, 'clock', S.clockOffset ? `Advance another 10 days (now +${S.clockOffset})` : 'Advance clock 10 days', 'Evidence ages, launch approaches', false, 'data-days="10"')}
      ${it('×', 'reset', 'Reset demo', 'Restore original data', false)}
    </div>` : ''}`;
  }

  function render() {
    const view = route();
    document.getElementById('app').innerHTML = shell(view);
    document.title = (view.title ? view.title + ' · ' : '') + 'Vulnio';
    view.after && view.after();
  }

  function act(name, data = {}) { actions[name] && actions[name](data, { target: null, currentTarget: null }); }

  /* --------------------------------------------------------------- events */
  document.addEventListener('click', (ev) => {
    const el = ev.target.closest('[data-action]');
    if (!el) {
      if (ui.menuOpen && !ev.target.closest('.menu')) { ui.menuOpen = false; render(); }
      return;
    }
    const name = el.dataset.action;
    if (!actions[name]) return;
    if (el.tagName === 'A' || el.tagName === 'BUTTON') ev.preventDefault();
    if (name === 'closeModal' && el.dataset.self && ev.target !== el) return;
    ev.stopPropagation();
    actions[name]({ ...el.dataset }, { target: ev.target, currentTarget: el });
  });
  document.addEventListener('change', (ev) => {
    const el = ev.target.closest('[data-change]');
    if (el && actions[el.dataset.change]) actions[el.dataset.change]({ ...el.dataset, value: el.value });
  });
  document.addEventListener('keydown', (ev) => { if (ev.key === 'Escape') { modal(''); if (ui.demoOpen) { ui.demoOpen = false; render(); } } });
  window.addEventListener('hashchange', () => { ui.menuOpen = false; render(); window.scrollTo(0, 0); });

  load();
  return { get S() { return S; }, ui, list, listAll, me, adv, render, act, toast, modal, boot: render };
})();
