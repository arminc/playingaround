/* Vulnio page views. Each returns { crumbs, title, html } */
window.Views = (() => {
  const E = window.Engine;
  const { esc, md, ic, outcome, OUT, CLAIM_STATE, claimIcon, band, cvss, TYPE, origin, initials, age, fmtDate, fmtDT, rel, dist, count, ring } = window.UI;
  const S = () => App.S;
  const ui = () => App.ui;

  /* ------------------------------------------------------------ helpers */
  const src = (id) => { const s = S().sources[id]; return `<span class="src ${id === 'human' ? 'human' : ''}"><span class="ic">${ic(s.icon)}</span>${esc(s.name)}</span>`; };
  const factAge = (f, pol = S().policy) => {
    const ms = S().now - Date.parse(f.observedAt);
    const stale = ms / E.DAY > (pol.freshness[f.source] ?? 30);
    return `<span class="age ${stale ? 'stale' : ''}" title="Observed ${fmtDT(f.observedAt)}">${age(ms)} ago${stale ? ' · stale' : ''}</span>`;
  };
  const advLink = (id) => `<a href="#/advisory/${id}" class="mono blue-t">${id}</a>`;
  const aLink = (a) => `#/assessment/${a.advisory}/${a.asset}`;
  const oc = (o) => o === 'affected' ? 'red-t' : o === 'not_affected' ? 'green-t' : 'amber-t';
  const person = (id) => S().people[id] || { name: id };
  const svcOf = (assetId) => S().services[S().assets[assetId].service];
  const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;

  function reasonLine(a) {
    if (a.outcome === 'affected') return `All ${a.results.length} conditions hold`;
    if (a.outcome === 'not_affected') { const r = a.decisive[0]; return `Disproved: ${r.claim.label}${r.fact ? ` (${S().sources[r.fact.source].name})` : ''}`; }
    const u = a.results.filter(r => r.state === 'unknown');
    return `Unknown: ${u.map(r => r.claim.label + (r.reason === 'stale' ? ' (stale)' : r.reason === 'conflict' ? ' (conflict)' : '')).join('; ')}`;
  }
  const flags = (a) => `${a.conflicts.length ? `<span class="tag warn" title="Sources disagree">${ic('split')}Conflict</span>` : ''}${a.stale.length ? `<span class="tag warn" title="Some evidence exceeded its freshness limit">${ic('clock')}Stale</span>` : ''}${a.preview ? '<span class="tag">Preview</span>' : ''}`;
  const dots = (a) => `<span class="row" style="gap:3px">${a.results.map(r => `<span title="${esc(r.claim.id + ' ' + r.claim.label + ': ' + CLAIM_STATE[r.state])}" style="width:9px;height:9px;border-radius:50%;display:inline-block;background:${r.state === 'true' ? 'var(--red)' : r.state === 'false' ? 'var(--green)' : 'transparent'};border:1.5px ${r.state === 'unknown' ? 'dashed var(--amber)' : 'solid transparent'}"></span>`).join('')}</span>`;
  const validity = (a) => a.validUntil && isFinite(a.validUntil) ? (a.validUntil < S().now ? '<span class="amber-t">expired</span>' : `${fmtDate(a.validUntil)} <span class="dim small">(${rel(a.validUntil, S().now)})</span>`) : '<span class="dim">n/a</span>';

  function pageHead(title, sub, right = '', eyebrow = '') {
    return `<div class="page-head"><div>${eyebrow ? `<div class="eyebrow">${eyebrow}</div>` : ''}<h1>${title}</h1>${sub ? `<div class="sub">${sub}</div>` : ''}</div>${right ? `<div class="row">${right}</div>` : ''}</div>`;
  }

  function nextStep(a) {
    if (a.preview) return `<div class="next"><div class="ic">${ic('sparkle')}</div><div class="txt"><small>Definition in review</small><b>This is a preview. Approve the claims before the result is published.</b></div><a class="btn sm" href="#/advisory/${a.advisory}">Review claims</a></div>`;
    if (a.outcome === 'insufficient') {
      const u = a.results.filter(r => r.state === 'unknown');
      const first = u[0];
      const asset = S().assets[a.asset];
      return `<div class="next"><div class="ic">${ic('arrow')}</div><div class="txt"><small>Next step · ${plural(u.length, 'gap')} to close</small><b>${esc(first.claim.question.text)}</b></div>
        ${asset.agent ? `<button class="btn sm" data-action="runAgent" data-asset="${a.asset}">${App.ui.busy[a.asset] ? '<span class="spin"></span>' : ic('agent')}Run agent check</button>` : ''}
        <button class="btn sm" data-action="askOwner" data-adv="${a.advisory}" data-asset="${a.asset}" data-claim="${first.claim.id}">${ic('send')}Ask ${esc(person(asset.owner).name.split(' ')[0])}</button>
        <button class="btn sm primary" data-action="answer" data-adv="${a.advisory}" data-asset="${a.asset}" data-claim="${first.claim.id}">Answer now</button></div>`;
    }
    if (a.outcome === 'affected') {
      const rem = a.results.filter(r => r.claim.remediation);
      return `<div class="next red"><div class="ic">${ic('wrench')}</div><div class="txt"><small>Recommended action · ${E.BAND[a.priority.band]}</small><b>${esc(rem[0]?.claim.remediation || 'Remediate')}</b></div><span class="band band-${a.priority.band}">Priority ${a.priority.score}</span></div>`;
    }
    const r = a.decisive[0];
    return `<div class="next green"><div class="ic">${ic('shield')}</div><div class="txt"><small>No action needed · valid until ${a.validUntil ? fmtDate(a.validUntil) : 'n/a'}</small><b>${esc(r.claim.label)}: disproved by ${esc(S().sources[r.fact.source].name)}</b></div></div>`;
  }

  /* ============================================================ OVERVIEW */
  function overview() {
    const s = S(), L = App.list(), c = count(L), me = App.me();
    const affected = L.filter(a => a.outcome === 'affected').sort((x, y) => y.priority.score - x.priority.score);
    const systems = (o) => new Set(L.filter(a => a.outcome === o).map(a => a.asset)).size;
    const decided = L.filter(a => a.outcome !== 'insufficient');
    const healthy = L.filter(a => a.outcome !== 'insufficient' && !a.stale.length && !a.conflicts.length).length;
    const gaps = E.gaps(s, L);
    const attention = L.filter(a => a.conflicts.length || a.stale.length);
    const pending = s.advisories.filter(a => a.definition.status !== 'approved' || a.pendingUpdate?.arrived);
    const hist = [...s.history].sort((a, b) => Date.parse(b.at) - Date.parse(a.at)).slice(0, 6);
    const mine = (s.role === 'owner' || s.role === 'developer') ? L.filter(a => s.assets[a.asset].owner === me.id) : [];
    const greet = { analyst: 'Good morning, Eva', ciso: 'Exposure overview', owner: 'Your systems, Joris', developer: 'Your code, Lisa' }[s.role];

    const kpi = (cls, label, num, foot, href) => `<a class="card kpi ${cls}" href="${href}"><div class="lbl">${label}</div><div class="num">${num}</div><div class="foot">${foot}</div></a>`;

    const html = `
      ${pageHead(greet, `Are we vulnerable, where, why, and what first? The answer below is built only from evidence observed up to <b>${fmtDT(s.now)}</b>.`,
        `<a class="btn" href="#/ask">${ic('sparkle')}Ask a question</a><a class="btn primary" href="#/priorities">${ic('target')}What to fix first</a>`)}
      <div class="grid g4">
        ${kpi('red', `${ic('alert')}Affected`, c.affected, `${plural(systems('affected'), 'system')} · evidence proves all conditions`, '#/assessments?o=affected')}
        ${kpi('amber', `${ic('search')}Insufficient evidence`, c.insufficient, `${plural(gaps.length, 'open gap')} · never shown as "safe"`, '#/gaps')}
        ${kpi('green', `${ic('shield')}Not affected`, c.not_affected, `A condition is disproved by evidence`, '#/assessments?o=not_affected')}
        ${kpi('', `${ic('clock')}Evidence health`, Math.round(healthy / (L.length || 1) * 100) + '%', `${healthy} of ${L.length} results fresh, complete & conflict-free`, '#/sources')}
      </div>
      ${pending.length ? `<div class="spacer"></div><div class="card hl-violet">${pending.map(a => `<div class="li click" data-action="nav" data-href="#/advisory/${a.id}"><div class="ico violet">${ic('sparkle')}</div><div class="body"><b>${a.definition.status !== 'approved' ? `New advisory ${a.id}: ${esc(a.title)}` : `${a.id}: vendor revised the advisory`}</b><small>${a.definition.status !== 'approved' ? `${a.claims.length} claims proposed by AI from ${a.intel.length} sources. Results are preview-only until a reviewer approves.` : esc(a.pendingUpdate.rationale)}</small></div><span class="btn sm violet">Review claims ${ic('arrow')}</span></div>`).join('')}</div>` : ''}
      <div class="spacer"></div>
      ${mine.length ? `<div class="card"><div class="hd"><h3>${s.role === 'developer' ? 'Codebases you own' : 'Systems you own'}</h3><span class="hint">Why they're considered affected, and what you can do</span></div><div class="bd flush">${table(mine, { compact: true })}</div></div><div class="spacer"></div>` : ''}
      <div class="grid g-main">
        <div class="grid" style="align-content:start">
          <div class="card"><div class="hd"><h3>Address first</h3><span class="hint">Technical exposure × business context, not CVSS</span><div class="right"><a class="btn sm ghost" href="#/priorities">All priorities ${ic('arrow')}</a></div></div>
            <div class="bd flush">${affected.length ? affected.slice(0, 5).map((a, i) => `
              <div class="li click" data-action="nav" data-href="${aLink(a)}">
                <div class="score" style="width:32px;color:var(--dim)">${i + 1}</div>
                <div class="body"><b>${esc(a.asset)} <span class="dim" style="font-weight:400">· ${esc(svcOf(a.asset).name)}</span></b><small>${a.advisory} · ${esc(a.adv.title)}</small></div>
                <div style="text-align:right">${band(a.priority)}<div class="tiny dim" style="margin-top:4px">${a.priority.factors.filter(f => f.points >= f.max * 0.8 && f.max).slice(0, 2).map(f => f.label).join(' · ')}</div></div>
              </div>`).join('') : '<div class="empty">Nothing is proven affected.</div>'}</div></div>
          <div class="card"><div class="hd"><h3>Advisories</h3><span class="hint">Exposure per vulnerability</span><div class="right"><a class="btn sm ghost" href="#/advisories">All advisories ${ic('arrow')}</a></div></div>
            <div class="bd flush"><table class="t"><thead><tr><th>Vulnerability</th><th>Signals</th><th style="width:190px">Results in scope</th></tr></thead><tbody>
              ${s.advisories.map(adv => { const R = App.listAll().filter(a => a.advisory === adv.id); const k = count(R); return `<tr class="click" data-action="nav" data-href="#/advisory/${adv.id}">
                <td class="ttl"><b>${esc(adv.title)}</b><small class="mono">${adv.id}</small></td>
                <td><div class="row" style="gap:6px">${cvss(adv.cvss)}${adv.kev ? '<span class="tag kev">KEV</span>' : ''}${adv.definition.status !== 'approved' ? '<span class="tag ai">In review</span>' : ''}</div></td>
                <td>${adv.definition.status !== 'approved' ? '<span class="small dim">Preview only</span>' : `${dist(k)}<div class="dist-legend"><span class="red-t">${k.affected}</span><span class="amber-t">${k.insufficient}</span><span class="green-t">${k.not_affected}</span></div>`}</td></tr>`; }).join('')}
            </tbody></table></div></div>
        </div>
        <div class="grid" style="align-content:start">
          <div class="card hl-amber"><div class="hd"><h3>Close these gaps</h3><span class="hint">Evidence that can change a decision</span></div>
            <div class="bd flush">${gaps.slice(0, 4).map(g => `<div class="li click" data-action="nav" data-href="#/gaps"><div class="ico amber">${ic('q')}</div><div class="body"><b>${esc(g.claim.label)}</b><small>${esc(g.asset)} · ${g.reason === 'stale' ? 'evidence stale' : g.reason === 'conflict' ? 'sources conflict' : 'never observed'} · resolves ${plural(g.items.length, 'assessment')}</small></div></div>`).join('') || '<div class="empty">No open gaps.</div>'}</div></div>
          <div class="card"><div class="hd"><h3>Relies on stale or conflicting data</h3></div>
            <div class="bd flush">${attention.slice(0, 5).map(a => `<div class="li click" data-action="nav" data-href="${aLink(a)}"><div class="ico ${a.conflicts.length ? 'amber' : ''}">${ic(a.conflicts.length ? 'split' : 'clock')}</div><div class="body"><b>${esc(a.asset)} · <span class="mono" style="font-weight:500">${a.advisory}</span></b><small>${a.conflicts.length ? `Sources disagree on ${a.conflicts.map(r => r.claim.attr).join(', ')}` : `Stale: ${a.stale.map(r => r.claim.attr).join(', ')}`}</small></div>${outcome(a.outcome)}</div>`).join('') || '<div class="empty">All evidence fresh.</div>'}</div></div>
          <div class="card"><div class="hd"><h3>What changed</h3><div class="right"><a class="btn sm ghost" href="#/history">History ${ic('arrow')}</a></div></div>
            <div class="bd"><div class="tl">${hist.map(histEvent).join('')}</div></div></div>
        </div>
      </div>`;
    return { title: 'Overview', crumbs: '<b>Overview</b>', html };
  }

  function histEvent(h) {
    const s = S();
    if (h.kind === 'outcome') return `<div class="ev ${h.to}"><div class="when">${fmtDT(h.at)} · ${rel(Date.parse(h.at), s.now)}</div>
      <div class="what"><a href="#/assessment/${h.advisory}/${h.asset}"><b>${esc(h.asset)}</b> · <span class="mono small">${h.advisory}</span></a>: ${h.from ? `<span class="${oc(h.from)}">${OUT[h.from]}</span><span class="arrow">→</span>` : '<span class="dim">new</span><span class="arrow">→</span>'}<span class="${oc(h.to)} b">${OUT[h.to]}</span></div>
      <div class="reason">${esc(h.reason)}</div></div>`;
    if (h.kind === 'priority') return `<div class="ev"><div class="when">${fmtDT(h.at)} · ${rel(Date.parse(h.at), s.now)}</div>
      <div class="what"><a href="#/assessment/${h.advisory}/${h.asset}"><b>${esc(h.asset)}</b> · <span class="mono small">${h.advisory}</span></a>: priority <span class="band band-${h.from}">${h.fromScore ?? ''} ${E.BAND[h.from]}</span><span class="arrow">→</span><span class="band band-${h.to}">${h.score ?? ''} ${E.BAND[h.to]}</span></div>
      <div class="reason">${esc(h.reason)}</div></div>`;
    return `<div class="ev ${h.kind === 'definition' ? 'definition' : 'insufficient'}"><div class="when">${fmtDT(h.at)} · ${rel(Date.parse(h.at), s.now)}${h.by ? ' · ' + esc(person(h.by).name) : ''}</div>
      <div class="what">${advLink(h.advisory)}${h.asset ? ` · <b>${esc(h.asset)}</b>` : ''}</div><div class="reason">${esc(h.text)}</div></div>`;
  }

  /* ============================================================ TABLE of assessments */
  function table(list, { compact = false } = {}) {
    if (!list.length) return '<div class="empty">No assessments match.</div>';
    return `<table class="t"><thead><tr><th>System</th><th>Vulnerability</th><th>Outcome</th><th>Conditions</th>${compact ? '' : '<th>Evidence</th><th>Valid until</th>'}<th>Priority</th></tr></thead><tbody>
      ${list.map(a => `<tr class="click" data-action="nav" data-href="${aLink(a)}">
        <td class="ttl"><b>${esc(a.asset)}</b><small>${esc(svcOf(a.asset).name)}</small></td>
        <td class="ttl"><b class="mono" style="font-weight:500">${a.advisory}</b><small>${esc(a.adv.product)}</small></td>
        <td>${outcome(a.outcome, false, a.preview)}<div class="tiny dim" style="margin-top:4px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(reasonLine(a))}</div></td>
        <td>${dots(a)}</td>
        ${compact ? '' : `<td><div class="row" style="gap:5px">${flags(a) || '<span class="dim small">OK</span>'}</div></td><td class="small">${validity(a)}</td>`}
        <td>${a.outcome === 'not_affected' ? '<span class="dim small">No action</span>' : a.outcome === 'insufficient' ? `<span class="small dim">Potential ${a.priority.score}</span>` : band(a.priority)}</td>
      </tr>`).join('')}</tbody></table>`;
  }

  /* ============================================================ ASSESSMENTS */
  function assessments() {
    const s = S();
    const f = ui().filters;
    let L = App.listAll();
    const all = L;
    if (f.o) L = L.filter(a => a.outcome === f.o && !a.preview);
    if (f.adv) L = L.filter(a => a.advisory === f.adv);
    if (f.flag === 'conflict') L = L.filter(a => a.conflicts.length);
    if (f.flag === 'stale') L = L.filter(a => a.stale.length);
    const view = f.view || 'list';
    const chip = (group, value, label, n) => `<button class="chip ${f[group] === value ? 'on' : ''}" data-action="filter" data-group="${group}" data-value="${value}">${label}${n != null ? `<span class="c">${n}</span>` : ''}</button>`;
    const k = count(all.filter(a => !a.preview));

    const assetIds = Object.keys(s.assets);
    const matrix = `<div class="card"><div class="bd flush" style="overflow-x:auto"><table class="t"><thead><tr><th>Vulnerability</th>${assetIds.map(x => `<th style="text-align:center;font-size:10px;letter-spacing:.02em;text-transform:none;font-family:var(--mono)">${x}</th>`).join('')}</tr></thead><tbody>
      ${s.advisories.map(adv => `<tr><td class="ttl"><b class="mono" style="font-weight:500">${adv.id}</b><small>${esc(adv.product)}</small></td>${assetIds.map(x => {
        const a = all.find(y => y.advisory === adv.id && y.asset === x);
        if (!a) return '<td style="text-align:center" class="dim">·</td>';
        const col = a.preview ? 'var(--blue-soft)' : a.outcome === 'affected' ? 'var(--red)' : a.outcome === 'not_affected' ? 'var(--green)' : 'var(--amber)';
        return `<td style="text-align:center"><a href="${aLink(a)}" title="${esc(OUT[a.outcome])}" style="display:inline-block;width:18px;height:18px;border-radius:5px;background:${a.outcome === 'insufficient' ? 'transparent' : col};opacity:${a.outcome === 'not_affected' ? .55 : 1};border:2px ${a.outcome === 'insufficient' ? 'dashed' : 'solid'} ${col}"></a></td>`;
      }).join('')}</tr>`).join('')}</tbody></table></div></div>`;

    const html = `${pageHead('Assessments', 'Every vulnerability × system in scope, evaluated deterministically against the current evidence. Click a row to see the full decision path.',
      `<div class="seg"><button class="${view === 'list' ? 'on' : ''}" data-action="filter" data-group="view" data-value="list">List</button><button class="${view === 'matrix' ? 'on' : ''}" data-action="filter" data-group="view" data-value="matrix">Matrix</button></div>`)}
      <div class="filters">${chip('o', 'affected', 'Affected', k.affected)}${chip('o', 'insufficient', 'Insufficient', k.insufficient)}${chip('o', 'not_affected', 'Not affected', k.not_affected)}
        <span class="dim" style="margin:0 4px">|</span>${chip('flag', 'conflict', 'Conflicting sources', all.filter(a => a.conflicts.length).length)}${chip('flag', 'stale', 'Stale evidence', all.filter(a => a.stale.length).length)}
        <span class="dim" style="margin:0 4px">|</span><select class="sel" data-change="filter" data-group="adv"><option value="">All advisories</option>${s.advisories.map(a => `<option value="${a.id}" ${f.adv === a.id ? 'selected' : ''}>${a.id} · ${esc(a.product)}</option>`).join('')}</select></div>
      ${view === 'matrix' ? matrix : `<div class="card"><div class="bd flush">${table(L.sort((x, y) => ({ affected: 0, insufficient: 1, not_affected: 2 }[x.outcome] - { affected: 0, insufficient: 1, not_affected: 2 }[y.outcome]) || y.priority.score - x.priority.score))}</div></div>`}`;
    return { title: 'Assessments', crumbs: '<b>Assessments</b>', html };
  }

  /* ============================================================ ASSESSMENT DETAIL */
  function assessment(advId, assetId) {
    const s = S(), adv = App.adv(advId), asset = s.assets[assetId];
    if (!adv || !asset) return { html: '<div class="empty">Not found</div>' };
    const pk = ui().policyKey;
    const pol = E.policyFor(s, pk);
    const a = E.assess(s, adv, assetId, { policy: pol });
    a.priority = E.priority(s, a);
    const orgA = pk === 'default' ? a : E.assess(s, adv, assetId);
    const svc = s.services[asset.service];
    const cfs = E.counterfactuals(s, a);
    const unknown = a.results.filter(r => r.state === 'unknown');

    let headline, expl;
    if (a.outcome === 'affected') { headline = `${asset.name} is affected`; expl = `All ${a.results.length} required conditions hold, based on ${plural(new Set(a.results.map(r => r.fact.source)).size, 'evidence source')}.`; }
    else if (a.outcome === 'not_affected') { const d = a.decisive; headline = `${asset.name} is not affected`; expl = `${d.map(r => `“${r.claim.label}”`).join(' and ')} ${d.length > 1 ? 'are' : 'is'} disproved by evidence. One disproved condition is sufficient.`; }
    else { headline = `Not enough evidence to decide`; expl = `${a.trueCount} of ${a.results.length} conditions hold, ${unknown.length} cannot be determined (${[...new Set(unknown.map(r => r.reason))].map(x => ({ stale: 'stale evidence', missing: 'never observed', conflict: 'conflicting sources' }[x])).join(', ')}). Vulnio will not report “not affected” without proof.`; }

    const claimRow = (r) => {
      const key = `${advId}|${assetId}|${r.claim.id}`;
      const open = ui().open.has(key);
      const p = adv.passages.find(x => x.id === r.claim.ref);
      const rowsOf = [];
      if (r.fact) rowsOf.push({ f: r.fact, tag: '<span class="tag struct">Used</span>', cls: 'used' });
      (r.corroborating || []).forEach(f => rowsOf.push({ f, tag: '<span class="tag rev">Agrees</span>' }));
      (r.overridden || []).forEach(f => rowsOf.push({ f, tag: '<span class="tag warn">Overridden</span>', cls: 'x' }));
      if (r.reason === 'conflict') (r.usable || []).forEach(f => rowsOf.push({ f, tag: '<span class="tag warn">Conflicting</span>' }));
      (r.excluded || []).forEach(e => rowsOf.push({ f: e.fact, tag: `<span class="tag ${e.why === 'stale' ? 'warn' : ''}">${e.why === 'stale' ? 'Stale: excluded' : 'Excluded'}</span>`, cls: 'x' }));
      const ev = r.fact
        ? `<span class="val">${esc(E.vtxt(r.fact.value))}</span><span class="row" style="gap:8px">${src(r.fact.source)}${factAge(r.fact, pol)}${r.conflict ? `<span class="tag warn">${ic('split')}conflict</span>` : ''}</span>`
        : r.reason === 'hypothetical' ? '<span class="val violet-t">hypothetical</span>'
          : `<span class="val amber-t">${r.reason === 'stale' ? 'stale evidence only' : r.reason === 'conflict' ? 'sources disagree' : 'no evidence'}</span><span class="small dim">${r.reason === 'stale' ? (r.excluded.length + ' observation(s) excluded by freshness policy') : r.reason === 'conflict' ? 'Strict policy blocks a decision' : 'Not observed by any connected source'}</span>`;
      const snip = r.fact?.snippet;
      return `<div class="claim-row ${open ? 'open' : ''}" data-row="${key}">
        <div class="claim-main" data-action="toggleClaim" data-key="${key}">
          ${claimIcon(r.state)}
          <div class="lbl"><b>${esc(r.claim.label)}</b><code>${esc(E.exprText(r.claim))}</code></div>
          <div class="ev">${ev}</div>
          <div class="stt ${r.state === 'true' ? 'red-t' : r.state === 'false' ? 'green-t' : 'amber-t'}">${CLAIM_STATE[r.state]}</div>
          <div class="chev">${ic('chev')}</div>
        </div>
        <div class="claim-detail">
          <div class="row" style="margin-bottom:10px;gap:6px"><span class="tag">${r.claim.id}</span><span class="tag">${TYPE[r.claim.type]}</span>${origin(r.claim.origin)}</div>
          ${p ? `<div class="quote">“${esc(r.claim.quote)}”<span class="from">${esc(p.src)} · passage ${p.id} · <a class="blue-t" href="#/advisory/${advId}">view in advisory</a></span></div>` : ''}
          ${rowsOf.length ? `<div class="facts">${rowsOf.map(x => `<div class="f ${x.cls || ''}">${src(x.f.source)}<span class="v">${esc(E.vtxt(x.f.value))}</span><span class="n" title="${esc(x.f.note)}">${esc(x.f.note || '')}</span>${factAge(x.f, pol)}<span style="text-align:right">${x.tag}</span></div>`).join('')}</div>` : ''}
          ${snip ? `<div class="snippet"><span class="file">${esc(snip.file)}:${snip.line} · ${esc(asset.repo || '')}</span>${snip.code.split('\n').map(l => l.startsWith(String(snip.line)) ? `<span class="hl">${esc(l)}</span>` : esc(l)).join('\n')}</div>` : ''}
          <div class="why">${ic('link')}<span>${esc(r.why || '')}${r.fact && r.validUntil ? ` · counts until ${fmtDate(r.validUntil)} (${S().sources[r.fact.source].name} freshness ${pol.freshness[r.fact.source]}d)` : ''}</span></div>
          <div class="why">${ic('search')}<span><b style="color:var(--text)">How to verify:</b> ${md(r.claim.howTo)}</span></div>
          <div class="row" style="margin-top:12px">
            ${asset.agent ? `<button class="btn sm" data-action="runAgent" data-asset="${assetId}">${App.ui.busy[assetId] ? '<span class="spin"></span>' : ic('agent')}Run agent check</button>` : ''}
            <button class="btn sm" data-action="askOwner" data-adv="${advId}" data-asset="${assetId}" data-claim="${r.claim.id}">${ic('send')}Ask ${esc(person(asset.owner).name)}</button>
            <button class="btn sm" data-action="answer" data-adv="${advId}" data-asset="${assetId}" data-claim="${r.claim.id}">${ic('user')}Provide answer</button>
          </div>
        </div></div>`;
    };

    // what would change the outcome
    const changes = cfs.map(cf => {
      const r = cf.result;
      const alt = r.state === 'true' ? 'false' : r.state === 'false' ? 'true' : null;
      if (r.state === 'unknown') return `<div class="li"><div class="ico amber">${ic('q')}</div><div class="body"><b>${esc(r.claim.label)}</b><small>If it holds → <span class="${oc(cf.variants.true)} b">${OUT[cf.variants.true]}</span> · if disproved → <span class="${oc(cf.variants.false)} b">${OUT[cf.variants.false]}</span></small></div><button class="btn sm" data-action="answer" data-adv="${advId}" data-asset="${assetId}" data-claim="${r.claim.id}">Resolve</button></div>`;
      if (cf.variants[alt] === a.outcome) return '';
      if (a.outcome === 'affected') return `<div class="li"><div class="ico green">${ic('wrench')}</div><div class="body"><b>${esc(r.claim.remediation || `Change: ${r.claim.label}`)}</b><small>Makes “${esc(r.claim.label)}” false → <span class="green-t b">${OUT[cf.variants.false]}</span>${r.claim.remediation ? '' : ' <span class="dim">(no vendor remedy for this condition)</span>'}</small></div></div>`;
      return `<div class="li"><div class="ico red">${ic('alert')}</div><div class="body"><b>If “${esc(r.claim.label)}” started to hold</b><small>→ <span class="${oc(cf.variants[alt])} b">${OUT[cf.variants[alt]]}</span>. Vulnio reassesses automatically when this evidence changes.</small></div></div>`;
    }).filter(Boolean);
    const remFirst = a.outcome === 'affected' ? changes.sort((x, y) => (y.includes('dim') ? -1 : 0) - (x.includes('dim') ? -1 : 0)) : changes;

    const pols = E.byPolicies(s, adv, assetId);
    const bySrc = E.bySources(s, adv, assetId);
    const hist = s.history.filter(h => h.advisory === advId && (!h.asset || h.asset === assetId)).sort((x, y) => Date.parse(y.at) - Date.parse(x.at));

    const html = `
      ${pageHead(`${esc(asset.name)} <span class="dim" style="font-weight:500;font-size:18px">· ${esc(asset.kind)}</span>`, `${esc(adv.title)}`,
        `${cvss(adv.cvss)}${adv.kev ? '<span class="tag kev">CISA KEV</span>' : ''}<span class="tag">${esc(adv.exploitation.label)}</span>`, `${adv.id} · ${esc(svc.name)}`)}
      ${pk !== 'default' ? `<div class="card hl-violet pad" style="margin-bottom:16px"><div class="row"><span class="violet-t">${ic('split')}</span><div class="grow"><b>What-if view: “${esc(pol.label)}”</b><div class="small muted">The organization policy result is ${outcome(orgA.outcome)}. Nothing is saved.</div></div><button class="btn sm" data-action="policyView" data-value="default">Back to organization policy</button></div></div>` : ''}
      <div class="card">
        <div class="bd"><div class="verdict">${ring(a)}<div class="grow"><div class="row" style="margin-bottom:6px">${outcome(a.outcome, true, a.preview)}${flags(a)}</div><h2>${esc(headline)}</h2><p>${esc(expl)}</p></div></div></div>
        <div class="meta">
          <div><small>Valid until</small><b>${validity(a)}</b></div>
          <div><small>Evidence confidence</small><b>${a.confidence === 'none' ? '<span class="amber-t">Undetermined</span>' : a.confidence[0].toUpperCase() + a.confidence.slice(1)}</b></div>
          <div><small>Definition</small><b><a href="#/advisory/${advId}" class="blue-t">v${adv.definition.version} · ${a.results.length} claims</a></b> ${a.preview ? '<span class="tag ai">draft</span>' : ''}</div>
          <div><small>Evidence policy</small><b>${esc(pol.label)}</b></div>
        </div>
      </div>
      <div class="spacer"></div>${nextStep(a)}<div class="spacer"></div>
      <div class="grid g-main">
        <div class="grid" style="align-content:start">
          <div class="card"><div class="hd"><h3>Decision path</h3><span class="hint">Claims from the advisory × facts about ${esc(asset.name)}</span>
            <div class="right"><select class="sel" data-change="policyView">${Object.entries(E.PRESETS).map(([k, p]) => `<option value="${k}" ${k === pk ? 'selected' : ''}>${esc(p.label)}</option>`).join('')}</select></div></div>
            <div class="bd flush">${a.results.map(claimRow).join('')}</div>
            <div class="logic">${ic('bolt')}<span>Rule: <code>affected ⇔ ${a.results.map(r => r.claim.id).join(' ∧ ')}</code>. Any disproved claim → not affected. Any unknown (and none disproved) → insufficient evidence.</span></div>
          </div>
          <div class="card"><div class="hd"><h3>${a.outcome === 'affected' ? 'How to remove the vulnerable condition' : a.outcome === 'insufficient' ? 'What would decide it' : 'What would change this'}</h3><span class="hint">Computed by re-running the engine with one claim flipped</span></div>
            <div class="bd flush">${remFirst.join('') || '<div class="empty">No single change alters the outcome.</div>'}
            ${a.outcome === 'affected' && adv.id === 'CVE-2023-4966' ? `<div class="li"><div class="ico">${ic('flag')}</div><div class="body"><b>After patching: kill all active sessions</b><small>Remediation guidance from passage p3. Not an exposure condition, so not a claim.</small></div></div>` : ''}</div></div>
          ${hist.length ? `<div class="card"><div class="hd"><h3>Assessment history</h3></div><div class="bd"><div class="tl">${hist.map(histEvent).join('')}</div></div></div>` : ''}
        </div>
        <div class="grid" style="align-content:start">
          <div class="card"><div class="hd"><h3>${a.outcome === 'affected' ? 'Priority' : 'Potential priority'}</h3><div class="right">${a.outcome === 'not_affected' ? '<span class="dim small">No action</span>' : band(a.priority)}</div></div>
            <div class="bd">${a.outcome !== 'affected' ? `<div class="small muted" style="margin-bottom:12px">${a.outcome === 'insufficient' ? 'If this system turns out to be affected, this is where it would rank. Used to order evidence gaps.' : 'Shown for context only. Not affected systems are not prioritised.'}</div>` : ''}
              ${a.priority.factors.map(f => `<div style="margin-bottom:11px"><div class="row" style="justify-content:space-between;margin-bottom:4px"><span class="small b">${f.label}</span><span class="mono small ${f.points < 0 ? 'green-t' : ''}">${f.points > 0 ? '+' : ''}${f.points}${f.max ? ' / ' + f.max : ''}</span></div>${f.max ? `<div class="bar"><i style="width:${Math.max(0, f.points) / f.max * 100}%"></i></div>` : ''}<div class="tiny dim" style="margin-top:3px">${esc(f.detail)}</div></div>`).join('')}
              <hr class="sep"><div class="note">${ic('alert')}CVSS ${adv.cvss.toFixed(1)} describes the vulnerability in general. Priority describes it <i>here</i>.</div></div></div>
          <div class="card"><div class="hd"><h3>Does the source matter?</h3></div>
            <div class="bd flush"><table class="t"><thead><tr><th>Evidence policy</th><th>Outcome</th></tr></thead><tbody>
              ${pols.map(p => `<tr class="click" data-action="policyView" data-value="${p.key}"><td class="small">${esc(p.label)}${p.key === pk ? ' <span class="tag struct">viewing</span>' : ''}</td><td>${outcome(p.a.outcome)}</td></tr>`).join('')}
            </tbody></table>
            <div style="padding:10px 14px;border-top:1px solid var(--line)" class="tiny dim">IF ONLY ONE SOURCE WAS TRUSTED</div>
            <table class="t"><tbody>${bySrc.map(b => `<tr><td>${src(b.source)}</td><td>${outcome(b.a.outcome)}</td></tr>`).join('')}</tbody></table></div></div>
          <div class="card"><div class="hd"><h3>Business context</h3><div class="right"><a class="btn sm ghost" href="#/asset/${assetId}">System ${ic('arrow')}</a></div></div>
            <div class="bd"><dl class="kv">
              <dt>Service</dt><dd>${esc(svc.name)}</dd>
              <dt>Owner</dt><dd>${esc(person(asset.owner).name)}</dd>
              <dt>Exposure</dt><dd>${esc(asset.exposureNote)}</dd>
              <dt>Data</dt><dd>${esc(svc.dataLabel)}</dd>
              <dt>Users</dt><dd>${esc(svc.usersLabel)}</dd>
              ${(svc.events || []).map(e => `<dt>Planned</dt><dd><span class="amber-t">${ic('calendar', '').replace('<svg', '<svg style="width:13px;height:13px;vertical-align:-2px"')}</span> ${esc(e.name)}, ${fmtDate(e.at)} <span class="dim">(${rel(Date.parse(e.at), s.now)})</span></dd>`).join('')}
            </dl></div></div>
        </div>
      </div>`;
    return { title: `${asset.name} · ${adv.id}`, crumbs: `<a href="#/assessments">Assessments</a> / <a href="#/advisory/${advId}">${advId}</a> / <b>${esc(asset.name)}</b>`, html };
  }

  /* ============================================================ ADVISORIES */
  function advisories() {
    const s = S();
    const html = `${pageHead('Advisories & claims', 'Vulnerability intelligence from vendors, national CERTs, CVE databases and threat feeds, turned into versioned, reviewable claim sets that the engine can execute.',
      `<button class="btn" data-action="ingest">${ic('plug')}Check NCSC feed</button>`)}
      <div class="card"><div class="bd flush"><table class="t"><thead><tr><th>Vulnerability</th><th>Signals</th><th>Sources</th><th>Definition</th><th>Claims</th><th style="width:180px">Results</th></tr></thead><tbody>
        ${s.advisories.map(adv => { const R = App.listAll().filter(a => a.advisory === adv.id); const k = count(R); const ai = adv.claims.filter(c => c.origin === 'ai').length;
          return `<tr class="click" data-action="nav" data-href="#/advisory/${adv.id}">
          <td class="ttl"><b>${esc(adv.title)}</b><small><span class="mono">${adv.id}</span> · ${esc(adv.vendor)} · published ${fmtDate(adv.published)}</small></td>
          <td><div class="row" style="gap:6px">${cvss(adv.cvss)}${adv.kev ? '<span class="tag kev">KEV</span>' : ''}</div></td>
          <td class="small muted">${adv.intel.length} sources<div class="tiny dim">${adv.intel.map(i => i.kind).filter((v, i, x) => x.indexOf(v) === i).join(', ')}</div></td>
          <td>${adv.definition.status === 'approved' ? `<span class="tag rev">v${adv.definition.version} approved</span>` : '<span class="tag ai">Awaiting review</span>'}${adv.pendingUpdate?.arrived ? '<div style="margin-top:4px"><span class="tag warn">Vendor update</span></div>' : ''}</td>
          <td class="small">${adv.claims.filter(c => c.status === 'accepted' || c.status === 'proposed').length} <span class="dim">(${ai} AI)</span></td>
          <td>${adv.definition.status !== 'approved' ? '<span class="small dim">Preview only</span>' : `${dist(k)}<div class="dist-legend"><span class="red-t">${k.affected}</span><span class="amber-t">${k.insufficient}</span><span class="green-t">${k.not_affected}</span></div>`}</td></tr>`; }).join('')}
      </tbody></table></div></div>
      <div class="spacer"></div>
      <div class="grid g3">
        <div class="card pad"><div class="row" style="margin-bottom:6px"><span class="blue-t">${ic('layers')}</span><b>Structured data is normalized</b></div><div class="small muted">Vendor, product, versions and identifiers come straight from CSAF / CVE records. No AI involved.</div></div>
        <div class="card pad"><div class="row" style="margin-bottom:6px"><span class="violet-t">${ic('sparkle')}</span><b>AI proposes the rest</b></div><div class="small muted">Configuration, features, mitigations and privileges are extracted from advisory text. Each claim links to its source passage.</div></div>
        <div class="card pad"><div class="row" style="margin-bottom:6px"><span class="green-t">${ic('check')}</span><b>Humans approve, logic decides</b></div><div class="small muted">Only approved claims are executed. Every correction creates a new version and triggers reassessment.</div></div>
      </div>`;
    return { title: 'Advisories', crumbs: '<b>Advisories & claims</b>', html };
  }

  function markPassage(adv, p) {
    let t = esc(p.text);
    for (const c of adv.claims.filter(c => c.ref === p.id)) {
      const q = esc(c.quote);
      const cls = c.status === 'rejected' || c.status === 'retired' ? 'rejected' : c.origin === 'structured' ? 'struct' : '';
      t = t.replace(q, `<mark class="q ${cls}" title="${esc(c.id + ': ' + c.label)}">${q}<sup>${c.id}</sup></mark>`);
    }
    return t;
  }

  function advisory(advId) {
    const s = S(), adv = App.adv(advId);
    if (!adv) return { html: '<div class="empty">Advisory not found</div>' };
    const R = App.listAll().filter(a => a.advisory === advId);
    const review = adv.definition.status !== 'approved';
    const upd = adv.pendingUpdate?.arrived ? adv.pendingUpdate : null;
    const proposed = adv.claims.filter(c => c.status === 'proposed').length;
    const active = E.activeClaims(adv);

    const claimCard = (c) => {
      const st = c.pendingChange === 'remove' ? 'pending' : c.status;
      const status = c.status === 'accepted' ? (c.pendingChange ? '<span class="tag warn">Proposed removal</span>' : '<span class="tag rev">Accepted</span>')
        : c.status === 'proposed' ? '<span class="tag ai">Proposed</span>' : c.status === 'retired' ? '<span class="tag">Retired</span>' : '<span class="tag bad">Rejected</span>';
      let acts = '';
      if (c.status === 'proposed') acts = `<button class="btn sm ok" data-action="claimStatus" data-adv="${advId}" data-claim="${c.id}" data-status="accepted">${ic('check')}Accept</button><button class="btn sm no" data-action="claimStatus" data-adv="${advId}" data-claim="${c.id}" data-status="rejected">${ic('x')}Reject</button><button class="btn sm ghost" data-action="editClaim" data-adv="${advId}" data-claim="${c.id}">${ic('edit')}</button>`;
      else if (c.status === 'accepted' && !c.pendingChange) acts = `<button class="btn sm ghost" data-action="editClaim" data-adv="${advId}" data-claim="${c.id}" title="Correct">${ic('edit')}Correct</button><button class="btn sm ghost" data-action="claimStatus" data-adv="${advId}" data-claim="${c.id}" data-status="rejected" title="Reject">${ic('x')}</button>`;
      else if (c.status === 'rejected') acts = `<button class="btn sm ghost" data-action="claimStatus" data-adv="${advId}" data-claim="${c.id}" data-status="${review ? 'proposed' : 'accepted'}">Restore</button>`;
      return `<div class="rev-claim ${st}"><div class="cid">${c.id}</div><div>
        <div class="row" style="gap:6px;margin-bottom:5px">${status}<span class="tag">${TYPE[c.type]}</span>${origin(c.origin)}${c.edited ? '<span class="tag rev">Corrected</span>' : ''}</div>
        <b>${esc(c.label)}</b><div><code class="expr">${esc(E.exprText(c))}</code></div>
        <div class="small dim" style="margin-top:6px">“${esc(c.quote)}” · ${c.ref}</div>
        ${c.ai ? `<div class="rat">${ic('sparkle')}<span>${esc(c.ai.rationale)} <span class="conf">confidence ${Math.round(c.ai.confidence * 100)}%</span></span></div>` : ''}
        ${c.pendingChange ? `<div class="rat" style="color:var(--amber)">${ic('alert')}<span>${esc(adv.pendingUpdate.rationale)}</span></div>` : ''}
      </div><div class="acts">${acts}</div></div>`;
    };

    // evidence plan matrix
    const plan = `<table class="t"><thead><tr><th>Claim</th>${adv.scope.map(x => `<th style="text-align:center;text-transform:none;letter-spacing:0;font-family:var(--mono);font-size:10.5px">${x}</th>`).join('')}</tr></thead><tbody>
      ${active.map(c => `<tr><td class="small"><span class="mono dim">${c.id}</span> ${esc(c.label)}</td>${adv.scope.map(x => {
        const a = R.find(y => y.asset === x); const r = a.results.find(y => y.claim.id === c.id);
        const needed = r.state === 'unknown' && a.outcome === 'insufficient';
        const notNeeded = r.state === 'unknown' && a.outcome === 'not_affected';
        return `<td style="text-align:center"><a href="${aLink(a)}" title="${esc(CLAIM_STATE[r.state] + (needed ? ' · needed to decide' : notNeeded ? ' · not needed, already disproved' : ''))}" style="display:inline-block">${notNeeded ? '<span class="dim">–</span>' : claimIcon(r.state).replace('class="st ', 'style="width:22px;height:22px;font-size:11px" class="st ')}</a></td>`;
      }).join('')}</tr>`).join('')}
      <tr><td class="small b">Outcome</td>${adv.scope.map(x => { const a = R.find(y => y.asset === x); return `<td style="text-align:center"><span class="tiny b ${oc(a.outcome)}">${a.outcome === 'affected' ? 'AFF' : a.outcome === 'not_affected' ? 'NOT' : 'INS'}</span></td>`; }).join('')}</tr></tbody></table>`;

    const steps = [
      ['Ingested', `${adv.intel.length} sources`, true],
      ['Claims extracted', `${adv.claims.length} claims, ${adv.claims.filter(c => c.origin === 'ai').length} by AI`, true],
      ['Reviewed', review ? `${proposed} awaiting review` : upd ? 'Change proposed' : `v${adv.definition.version} by ${person(adv.definition.by).name}`, !review && !upd],
      ['Evidence planned', `${R.reduce((n, a) => n + a.results.filter(r => r.state === 'unknown' && a.outcome === 'insufficient').length, 0)} facts needed`, !review],
      ['Assessed', review ? 'Preview only' : `${adv.scope.length} systems`, !review],
    ];

    const html = `
      ${pageHead(esc(adv.title), `${esc(adv.vendor)} · ${esc(adv.product)} · published ${fmtDate(adv.published)}`, `${cvss(adv.cvss)}${adv.kev ? '<span class="tag kev">CISA KEV</span>' : ''}<span class="tag">${esc(adv.exploitation.label)}</span>`, adv.id)}
      ${upd ? `<div class="card hl-violet pad" style="margin-bottom:16px"><div class="row" style="align-items:flex-start"><span class="violet-t" style="margin-top:2px">${ic('sparkle')}</span><div class="grow">
          <b>Vendor revised this advisory (rev ${upd.intel.rev}, ${fmtDate(upd.intel.at)}). AI proposes a definition change.</b>
          <div class="small muted" style="margin-top:4px">${esc(upd.rationale)}</div>
          <div class="small" style="margin-top:8px"><span class="red-t">− c4 Device telemetry enabled</span></div>
          <div class="small muted" style="margin-top:8px">Impact preview: ${(() => { const c = adv.claims.find(x => x.id === upd.removeClaim); const saved = c.status; c.status = 'retired'; const after = adv.scope.map(x => E.assess(s, adv, x)); c.status = saved; const flips = after.filter(a => R.find(r => r.asset === a.asset).outcome !== a.outcome); return flips.length ? flips.map(a => `<b>${a.asset}</b> becomes <span class="${oc(a.outcome)} b">${OUT[a.outcome]}</span>`).join(', ') : 'no outcome changes'; })()}</div>
        </div><button class="btn primary" data-action="approveUpdate" data-adv="${advId}">${ic('check')}Approve v${adv.definition.version + 1} & reassess</button></div></div>` : ''}
      ${review ? `<div class="card hl-violet pad" style="margin-bottom:16px"><div class="row"><span class="violet-t">${ic('sparkle')}</span><div class="grow"><b>Draft definition: review the AI-proposed claims</b><div class="small muted">Results below are a preview. Nothing is published or prioritized until you approve.${adv.claims.some(c => c.ai && c.ai.confidence < 0.7) ? ' One claim has low confidence.' : ''}</div></div>
        <button class="btn primary" data-action="approveDefinition" data-adv="${advId}" ${proposed ? 'disabled' : ''}>${ic('check')}Approve definition${proposed ? ` (${proposed} left)` : ''}</button></div></div>` : ''}
      <div class="pipe">${steps.map(([t, sub, done], i) => `<div class="stp ${done ? 'done' : (i === 2 && (review || upd)) ? 'cur' : ''}"><small>${done ? '✓ ' : ''}Step ${i + 1}</small><b>${t}</b><span>${esc(sub)}</span></div>`).join('')}</div>
      <div class="spacer"></div>
      <div class="grid g2">
        <div class="card"><div class="hd"><h3>Source text</h3><span class="hint">Highlights link to claims</span></div>
          <div class="bd adv-text">${adv.passages.map(p => `<p class="${p.changed ? 'changed' : ''}"><span class="pid">${p.id}</span>${markPassage(adv, p)} <span class="psrc">(${esc(p.src)}${p.changed ? ', revised' : ''})</span></p>`).join('')}
            <hr class="sep"><div class="tiny dim" style="margin-bottom:8px">INTELLIGENCE SOURCES</div>
            ${adv.intel.map(i => `<div class="row small" style="justify-content:space-between;padding:4px 0"><span>${esc(i.source)} <span class="dim">· ${esc(i.kind)}</span></span><span class="mono dim">rev ${i.rev} · ${fmtDate(i.at)}</span></div>`).join('')}
          </div></div>
        <div class="card"><div class="hd"><h3>Claims</h3><span class="hint">${review ? 'Draft' : `Definition v${adv.definition.version}`} · all must hold</span></div>
          <div class="bd flush">${adv.claims.map(claimCard).join('')}</div>
          <div class="logic">${ic('bolt')}<span><code>affected ⇔ ${active.map(c => c.id).join(' ∧ ') || '∅'}</code></span></div></div>
      </div>
      <div class="spacer"></div>
      <div class="card"><div class="hd"><h3>Evidence plan</h3><span class="hint">Each claim × each system in scope (${esc(adv.scopeNote)}). Vulnio asks only for facts that can change a result.</span></div>
        <div class="bd flush" style="overflow-x:auto">${plan}</div></div>
      <div class="spacer"></div>
      <div class="grid g2">
        <div class="card"><div class="hd"><h3>Results</h3></div><div class="bd flush">${table(R, { compact: true })}</div></div>
        <div class="card"><div class="hd"><h3>Definition versions</h3></div><div class="bd"><div class="tl">${[...adv.versions].reverse().map(v => `<div class="ev definition"><div class="when">v${v.version} · ${v.at ? fmtDT(v.at) : 'draft'} · ${esc(person(v.by).name)}</div><div class="reason">${esc(v.note)}</div></div>`).join('')}</div></div></div>
      </div>`;
    return { title: adv.id, crumbs: `<a href="#/advisories">Advisories</a> / <b>${adv.id}</b>`, html };
  }

  /* ============================================================ PRIORITIES */
  function priorities() {
    const s = S(), L = App.list();
    const aff = L.filter(a => a.outcome === 'affected').sort((x, y) => y.priority.score - x.priority.score);
    const pot = L.filter(a => a.outcome === 'insufficient').sort((x, y) => y.priority.score - x.priority.score);
    const bySev = [...aff].sort((x, y) => y.adv.cvss - x.adv.cvss);
    const row = (a, i) => {
      const rem = a.results.find(r => r.claim.remediation);
      const top = [...a.priority.factors].filter(f => f.max).sort((x, y) => y.points / y.max - x.points / x.max).slice(0, 3);
      return `<tr class="click" data-action="nav" data-href="${aLink(a)}"><td class="score dim" style="width:40px">${i + 1}</td>
        <td>${band(a.priority)}</td>
        <td class="ttl"><b>${esc(a.asset)}</b><small>${esc(svcOf(a.asset).name)}</small></td>
        <td class="ttl"><b class="mono" style="font-weight:500">${a.advisory}</b><small>${cvss(a.adv.cvss)} <span class="dim">for reference</span></small></td>
        <td class="small">${top.map(f => `<div><span class="b">${f.label}</span> <span class="dim">${esc(f.detail.length > 46 ? f.detail.slice(0, 46) + '…' : f.detail)}</span></div>`).join('')}</td>
        <td class="small">${esc(rem?.claim.remediation || '')}</td></tr>`;
    };
    const html = `${pageHead('Priorities', 'What to patch or mitigate first. Priority combines proven exposure with reachability, exploitation, business criticality, data, users and planned events. CVSS is shown for reference only.')}
      <div class="card"><div class="hd"><h3>Affected: ordered by priority</h3><span class="hint">${aff.length} results</span></div><div class="bd flush"><table class="t"><thead><tr><th>#</th><th>Priority</th><th>System</th><th>Vulnerability</th><th>Why this rank</th><th>Recommended action</th></tr></thead><tbody>${aff.map(row).join('') || '<tr><td colspan="6" class="empty">Nothing proven affected</td></tr>'}</tbody></table></div></div>
      <div class="spacer"></div>
      <div class="grid g2">
        <div class="card"><div class="hd"><h3>Could become urgent</h3><span class="hint">Insufficient evidence, ranked by potential priority</span></div><div class="bd flush">
          ${pot.map(a => `<div class="li click" data-action="nav" data-href="${aLink(a)}"><div class="ico amber">${ic('q')}</div><div class="body"><b>${esc(a.asset)} · <span class="mono" style="font-weight:500">${a.advisory}</span></b><small>${esc(reasonLine(a))}</small></div><span class="small dim">potential ${a.priority.score}</span></div>`).join('') || '<div class="empty">None</div>'}</div></div>
        <div class="card"><div class="hd"><h3>Why not sort by CVSS?</h3></div><div class="bd">
          <div class="small muted" style="margin-bottom:12px">Sorting the same affected results by CVSS would give:</div>
          ${bySev.map((a, i) => { const r = aff.indexOf(a); return `<div class="row small" style="padding:5px 0;border-bottom:1px solid var(--line)"><span class="mono dim" style="width:20px">${i + 1}</span><span class="grow">${esc(a.asset)} · ${a.advisory}</span>${cvss(a.adv.cvss)}<span class="dim" style="width:90px;text-align:right">Vulnio: #${r + 1}</span></div>`; }).join('')}
          <div class="note" style="margin-top:12px">${ic('alert')}${pot.length + L.filter(a => a.outcome === 'not_affected' && a.adv.cvss >= 9).length} other high-CVSS findings are either disproved or still unknown, so a severity-only list would mix them in as well.</div></div></div>
      </div>`;
    return { title: 'Priorities', crumbs: '<b>Priorities</b>', html };
  }

  /* ============================================================ GAPS */
  function gaps() {
    const s = S(), L = App.list(), G = E.gaps(s, L);
    const html = `${pageHead('Evidence gaps', 'Unknown is actionable. These are the missing, stale or conflicting facts that stand between an assessment and a decision, ordered by how much they matter.')}
      <div class="grid g3" style="margin-bottom:16px">
        <div class="card kpi amber"><div class="lbl">Open gaps</div><div class="num">${G.length}</div><div class="foot">across ${new Set(G.map(g => g.asset)).size} systems</div></div>
        <div class="card kpi"><div class="lbl">Undecided assessments</div><div class="num">${L.filter(a => a.outcome === 'insufficient').length}</div><div class="foot">of ${L.length} total</div></div>
        <div class="card kpi"><div class="lbl">Oldest gap</div><div class="num">${(() => { const t = s.tasks.filter(t => t.status === 'open').map(t => Date.parse(t.createdAt)); return t.length ? age(s.now - Math.min(...t)) : '–'; })()}</div><div class="foot">since first owner question</div></div>
      </div>
      <div class="card"><div class="bd flush">${G.map((g, i) => {
        const asset = s.assets[g.asset]; const it = g.items[0];
        const task = s.tasks.find(t => t.status === 'open' && t.asset === g.asset && App.adv(t.advisory)?.claims.find(c => c.id === t.claim)?.attr === g.attr);
        return `<div class="li" style="align-items:flex-start;padding:16px 18px">
          <div class="score dim" style="width:28px">${i + 1}</div>
          <div class="body">
            <div class="row" style="gap:8px;margin-bottom:4px"><b style="display:inline">${esc(g.claim.label)}</b><span class="tag warn">${g.reason === 'stale' ? 'Stale evidence' : g.reason === 'conflict' ? 'Conflicting sources' : 'Never observed'}</span>${task ? `<span class="tag">${ic('send')}Asked ${esc(person(task.assignee).name)} ${rel(Date.parse(task.createdAt), s.now)}</span>` : ''}</div>
            <small><b style="display:inline;color:var(--text)">${esc(asset.name)}</b> · <code>${esc(g.attr)}</code> · ${g.items.map(x => `<a class="blue-t" href="${aLink(x.a)}">${x.a.advisory}</a>: if holds → <span class="${oc(x.ifTrue)}">${OUT[x.ifTrue]}</span>, if disproved → <span class="${oc(x.ifFalse)}">${OUT[x.ifFalse]}</span>`).join(' · ')}</small>
            <div class="why" style="margin-top:6px">${ic('search')}<span>${md(g.claim.howTo)}</span></div>
          </div>
          <div style="text-align:right;min-width:230px"><div class="small dim" style="margin-bottom:8px">Potential priority <b style="color:var(--text)">${g.potential}</b></div>
            <div class="row" style="justify-content:flex-end;gap:6px">
              ${asset.agent ? `<button class="btn sm" data-action="runAgent" data-asset="${g.asset}">${App.ui.busy[g.asset] ? '<span class="spin"></span>' : ic('agent')}Agent</button>` : ''}
              ${task ? '' : `<button class="btn sm" data-action="askOwner" data-adv="${it.a.advisory}" data-asset="${g.asset}" data-claim="${it.claim.id}">${ic('send')}Ask owner</button>`}
              <button class="btn sm primary" data-action="answer" data-adv="${it.a.advisory}" data-asset="${g.asset}" data-claim="${it.claim.id}">Answer</button></div></div>
        </div>`;
      }).join('') || '<div class="empty">No open evidence gaps. Every assessment has a decision.</div>'}</div></div>`;
    return { title: 'Evidence gaps', crumbs: '<b>Evidence gaps</b>', html };
  }

  /* ============================================================ TASKS */
  function tasks() {
    const s = S(), me = App.me();
    const mineOnly = s.role === 'owner' || s.role === 'developer';
    const T = s.tasks.filter(t => !mineOnly || t.assignee === me.id);
    const open = T.filter(t => t.status === 'open'), done = T.filter(t => t.status === 'done');
    const card = (t) => {
      const adv = App.adv(t.advisory), c = adv.claims.find(x => x.id === t.claim), asset = s.assets[t.asset];
      const a = E.assess(s, adv, t.asset); const cf = E.counterfactuals(s, a).find(x => x.result.claim.id === t.claim);
      return `<div class="card" style="margin-bottom:14px"><div class="bd">
        <div class="row" style="margin-bottom:10px"><span class="avatar sm">${initials(person(t.by).name)}</span><span class="small muted"><b style="color:var(--text)">${esc(person(t.by).name)}</b> asked ${mineOnly ? 'you' : `<b style="color:var(--text)">${esc(person(t.assignee).name)}</b>`} · ${rel(Date.parse(t.createdAt), s.now)}</span><span class="grow"></span>${t.status === 'done' ? `<span class="tag rev">${ic('check')}Answered: ${esc(t.answer)}</span>` : outcome(a.outcome)}</div>
        <h3 style="font-size:17px">${esc(c.question.text)}</h3>
        <div class="small muted" style="margin-top:4px"><b style="color:var(--text)">${esc(asset.name)}</b> · ${esc(adv.id)} ${esc(adv.title)}</div>
        ${t.note ? `<div class="quote" style="margin-top:12px">${esc(t.note)}</div>` : ''}
        ${t.status === 'open' ? `
        <div class="grid g2" style="margin-top:14px;gap:12px">
          <div class="help"><b style="color:var(--text)">Why we ask:</b> the advisory says “${esc(c.quote)}”. Your answer ${cf && (cf.variants.true !== a.outcome || cf.variants.false !== a.outcome) ? `decides the result: holds → <span class="${oc(cf.variants.true)} b">${OUT[cf.variants.true]}</span>, disproved → <span class="${oc(cf.variants.false)} b">${OUT[cf.variants.false]}</span>.` : 'is recorded as evidence.'}</div>
          <div class="help"><b style="color:var(--text)">How to check:</b> ${md(c.howTo)}</div>
        </div>
        <div class="row" style="margin-top:14px"><button class="btn primary" data-action="answer" data-adv="${adv.id}" data-asset="${t.asset}" data-claim="${c.id}">${ic('user')}Answer</button><a class="btn ghost" href="#/assessment/${adv.id}/${t.asset}">See why this matters ${ic('arrow')}</a></div>` : ''}
      </div></div>`;
    };
    const html = `${pageHead(mineOnly ? 'My questions' : 'Owner questions', mineOnly ? 'Security needs a few facts only you can confirm. Each question explains why it matters and how to check. Your answer is stored as time-stamped evidence.' : 'Guided questions sent to system owners when no reliable machine evidence exists.')}
      <div class="grid g-main"><div>${open.map(card).join('') || '<div class="card"><div class="empty">No open questions. Nice.</div></div>'}</div>
      <div><div class="card"><div class="hd"><h3>Answered</h3></div><div class="bd flush">${done.map(t => `<div class="li"><div class="ico green">${ic('check')}</div><div class="body"><b>${esc(t.asset)} · ${esc(App.adv(t.advisory).claims.find(c => c.id === t.claim).label)}</b><small>${esc(person(t.assignee).name)} answered “${esc(t.answer)}” · ${rel(Date.parse(t.doneAt), s.now)}</small></div></div>`).join('') || '<div class="empty">Nothing yet</div>'}</div></div></div></div>`;
    return { title: 'Questions', crumbs: `<b>${mineOnly ? 'My questions' : 'Owner questions'}</b>`, html };
  }

  /* ============================================================ ASSETS */
  function assets() {
    const s = S(), L = App.list();
    const html = `${pageHead('Systems & services', 'The unit of assessment is a system; systems roll up into business services that carry criticality, data, users and planned events.')}
      <div class="grid g2">${Object.values(s.services).map(svc => {
        const as = Object.values(s.assets).filter(a => a.service === svc.id);
        return `<div class="card"><div class="hd"><div><h3>${esc(svc.name)}</h3><div class="tiny dim" style="margin-top:2px">${esc(person(svc.owner).name)} · ${esc(svc.dataLabel)} · ${esc(svc.usersLabel)}</div></div><div class="right"><span class="tag">Tier ${6 - svc.criticality}</span></div></div>
          ${(svc.events || []).map(e => `<div class="li" style="background:var(--amber-bg)"><div class="ico amber">${ic('calendar')}</div><div class="body"><b>${esc(e.name)}</b><small>${fmtDate(e.at)} (${rel(Date.parse(e.at), s.now)}) · ${esc(e.note)}</small></div></div>`).join('')}
          <div class="bd flush">${as.map(a => { const R = L.filter(x => x.asset === a.id); const k = count(R);
            return `<div class="li click" data-action="nav" data-href="#/asset/${a.id}"><div class="ico">${ic(a.kind.includes('Kubernetes') ? 'code' : 'server')}</div><div class="body"><b>${esc(a.name)}</b><small>${esc(a.kind)} · ${esc(a.os)} · ${esc(a.exposure.default)}</small></div>
              <div class="row" style="gap:6px">${k.affected ? `<span class="pill o-affected">${k.affected}</span>` : ''}${k.insufficient ? `<span class="pill o-insufficient">${k.insufficient}</span>` : ''}${k.not_affected ? `<span class="pill o-not_affected">${k.not_affected}</span>` : ''}${!R.length ? '<span class="dim small">no advisories</span>' : ''}</div></div>`; }).join('')}</div></div>`;
      }).join('')}</div>`;
    return { title: 'Systems', crumbs: '<b>Systems & services</b>', html };
  }

  function asset(id) {
    const s = S(), a = s.assets[id];
    if (!a) return { html: '<div class="empty">Not found</div>' };
    const svc = s.services[a.service];
    const R = App.listAll().filter(x => x.asset === id);
    const F = s.facts.filter(f => f.asset === id).sort((x, y) => x.attr.localeCompare(y.attr) || Date.parse(y.observedAt) - Date.parse(x.observedAt));
    const agentFacts = F.filter(f => f.source === 'agent');
    const lastAgent = agentFacts.length ? Math.max(...agentFacts.map(f => Date.parse(f.observedAt))) : null;
    const html = `${pageHead(esc(a.name), `${esc(a.kind)} · ${esc(a.os)} · ${esc(svc.name)}`,
      a.agent ? `<button class="btn" data-action="runAgent" data-asset="${id}">${App.ui.busy[id] ? '<span class="spin"></span>' : ic('agent')}Collect with agent</button>` : '', 'System')}
      <div class="grid g-main">
        <div class="grid" style="align-content:start">
          <div class="card"><div class="hd"><h3>Assessments</h3></div><div class="bd flush">${table(R, { compact: true })}</div></div>
          <div class="card"><div class="hd"><h3>Facts</h3><span class="hint">Every observation with source, time and freshness</span></div><div class="bd flush"><table class="t"><thead><tr><th>Attribute</th><th>Value</th><th>Source</th><th>Observed</th><th>Note</th></tr></thead><tbody>
            ${F.map(f => `<tr><td><code>${esc(f.attr)}</code></td><td class="mono">${esc(E.vtxt(f.value))}</td><td>${src(f.source)}</td><td>${factAge(f)}</td><td class="small muted" style="max-width:320px">${esc(f.note || '')}</td></tr>`).join('')}
          </tbody></table></div></div>
        </div>
        <div class="grid" style="align-content:start">
          <div class="card"><div class="hd"><h3>Context</h3></div><div class="bd"><dl class="kv">
            <dt>Owner</dt><dd>${esc(person(a.owner).name)}</dd>
            <dt>Service</dt><dd>${esc(svc.name)} (tier ${6 - svc.criticality})</dd>
            <dt>Exposure</dt><dd>${esc(a.exposureNote)}</dd>
            <dt>Data</dt><dd>${esc(svc.dataLabel)}</dd>
            <dt>Users</dt><dd>${esc(svc.usersLabel)}</dd>
            ${a.repo ? `<dt>Repository</dt><dd class="mono">${esc(a.repo)}</dd>` : ''}
            ${(a.controls || []).map(c => `<dt>Control</dt><dd>${esc(c.label)}</dd>`).join('')}
            <dt>Agent</dt><dd>${a.agent ? (lastAgent ? `Last check-in ${age(s.now - lastAgent)} ago${(s.now - lastAgent) / E.DAY > s.policy.freshness.agent ? ' <span class="amber-t">(offline)</span>' : ''}` : 'Installed') : '<span class="dim">Not applicable, uses platform API</span>'}</dd>
          </dl></div></div>
          ${(svc.events || []).length ? `<div class="card"><div class="hd"><h3>Planned events</h3></div><div class="bd flush">${svc.events.map(e => `<div class="li"><div class="ico amber">${ic('calendar')}</div><div class="body"><b>${esc(e.name)}</b><small>${fmtDate(e.at)} · ${rel(Date.parse(e.at), s.now)} · ${esc(e.note)}</small></div></div>`).join('')}</div></div>` : ''}
        </div>
      </div>`;
    return { title: a.name, crumbs: `<a href="#/assets">Systems</a> / <b>${esc(a.name)}</b>`, html };
  }

  /* ============================================================ SOURCES */
  function sources() {
    const s = S(), pol = s.policy;
    const html = `${pageHead('Evidence sources', 'Existing tools remain the evidence providers. Vulnio records what each one observed, when, and how much to trust it, and keeps disagreements visible.')}
      <div class="grid g-main">
        <div class="card"><div class="hd"><h3>Connected sources</h3></div><div class="bd flush"><table class="t"><thead><tr><th>Source</th><th>Type</th><th>Reliability</th><th class="num">Facts</th><th class="num">Stale</th><th>Freshness limit</th></tr></thead><tbody>
          ${Object.values(s.sources).map(x => { const F = s.facts.filter(f => f.source === x.id); const stale = F.filter(f => (s.now - Date.parse(f.observedAt)) / E.DAY > pol.freshness[x.id]).length;
            return `<tr><td>${src(x.id)}</td><td class="small muted">${esc(x.kind)}</td><td><span class="tag ${x.reliability === 'high' ? 'rev' : ''}">${x.reliability}</span></td><td class="num">${F.length}</td><td class="num ${stale ? 'amber-t' : 'dim'}">${stale}</td>
              <td><input class="inp days mono" type="number" min="1" value="${pol.freshness[x.id]}" data-change="setFresh" data-src="${x.id}"> <span class="small dim">days</span></td></tr>`; }).join('')}
        </tbody></table></div></div>
        <div class="grid" style="align-content:start">
          <div class="card"><div class="hd"><h3>Conflict handling</h3></div><div class="bd">
            <div class="seg" style="margin-bottom:10px">${[['precedence', 'Source precedence'], ['recent', 'Most recent'], ['strict', 'Strict']].map(([k, l]) => `<button class="${pol.mode === k ? 'on' : ''}" data-action="setMode" data-value="${k}">${l}</button>`).join('')}</div>
            <div class="small muted">${{ precedence: 'When sources disagree, the highest-ranked source wins. The losing observation stays visible.', recent: 'When sources disagree, the most recent observation wins.', strict: 'When sources disagree, the claim is unknown until someone resolves it.' }[pol.mode]}</div></div></div>
          <div class="card"><div class="hd"><h3>Source precedence</h3><span class="hint">Highest trust first</span></div><div class="bd"><div class="src-order">
            ${pol.precedence.map((x, i) => `<div class="o"><span class="rk">${i + 1}</span>${src(x)}<span class="grow"></span><button class="btn sm ghost" data-action="moveSource" data-src="${x}" data-dir="-1" ${i === 0 ? 'disabled' : ''}>↑</button><button class="btn sm ghost" data-action="moveSource" data-src="${x}" data-dir="1" ${i === pol.precedence.length - 1 ? 'disabled' : ''}>↓</button></div>`).join('')}
          </div><div class="note" style="margin-top:12px">${ic('bolt')}Every change reassesses all results and is recorded in history.</div></div></div>
        </div>
      </div>`;
    return { title: 'Evidence sources', crumbs: '<b>Evidence sources</b>', html };
  }

  /* ============================================================ HISTORY */
  function history() {
    const s = S();
    const f = ui().filters.hk;
    const H = [...s.history].filter(h => !f || h.kind === f).sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
    const chip = (v, l) => `<button class="chip ${f === v ? 'on' : ''}" data-action="filter" data-group="hk" data-value="${v}">${l}</button>`;
    const html = `${pageHead('History', 'Every change in outcome, priority or definition, with the reason. Results are valid for a point in time and evidence state, so the audit trail is part of the product.')}
      <div class="filters">${chip('outcome', 'Outcome changes')}${chip('priority', 'Priority changes')}${chip('definition', 'Definitions')}${chip('conflict', 'Conflicts')}</div>
      <div class="card"><div class="bd"><div class="tl">${H.map(histEvent).join('') || '<div class="empty">No events</div>'}</div></div></div>`;
    return { title: 'History', crumbs: '<b>History</b>', html };
  }

  /* ============================================================ ASK */
  function interpret(q) {
    const s = S(), t = q.toLowerCase();
    const cve = (t.match(/cve-\d{4}-\d{4,7}/) || [])[0];
    const byKw = s.advisories.find(a => a.keywords.some(k => t.includes(k)));
    const asset = Object.values(s.assets).find(a => t.includes(a.id));
    if (/stale|conflict|outdated|disagree|trust/.test(t)) return { intent: 'quality' };
    if (/first|priorit|urgent|address|top/.test(t)) return { intent: 'priorities' };
    if (/gap|learn|missing|unknown|need to know|close/.test(t)) return { intent: 'gaps' };
    if (/chang|since|last week|yesterday/.test(t) && !cve) return { intent: 'changes' };
    if (cve) return { intent: 'exposure', cve: cve.toUpperCase() };
    if (asset) return { intent: 'asset', asset: asset.id };
    if (byKw) return { intent: /which|use|using|run|where/.test(t) ? 'product' : 'exposure', cve: byKw.id };
    return { intent: 'help' };
  }

  function answer(q) {
    const s = S(), L = App.listAll(), it = interpret(q);
    const interp = `<div class="interp">${ic('sparkle')}Interpreted as <b>${it.intent}</b>${it.cve ? `(${it.cve})` : ''}${it.asset ? `(${it.asset})` : ''} · answered by the deterministic engine from ${s.facts.length} facts</div>`;
    const mini = (list) => `<div class="card" style="margin-top:10px"><div class="bd flush">${table(list, { compact: true })}</div></div>`;
    let body = '';
    if (it.intent === 'exposure' || it.intent === 'product') {
      const adv = App.adv(it.cve);
      if (!adv) body = `<p><b>${esc(it.cve)}</b> is not in the intelligence base yet. In the product, Vulnio would fetch it from the NCSC CSAF feed and NVD, extract claims, and ask you to review them before answering.</p>`;
      else {
        const R = L.filter(a => a.advisory === adv.id), k = count(R);
        const aff = R.filter(a => a.outcome === 'affected');
        const verdict = adv.definition.status !== 'approved' ? `<b class="violet-t">Preliminary:</b> the definition is still in review.`
          : aff.length ? `<b class="red-t">Yes.</b> ${plural(aff.length, 'system')} ${aff.length > 1 ? 'are' : 'is'} proven affected: ${aff.map(a => `<b>${a.asset}</b>`).join(', ')}.`
            : k.insufficient ? `<b class="amber-t">Not proven either way.</b> Nothing is proven affected, but ${plural(k.insufficient, 'system')} cannot be decided yet.`
              : `<b class="green-t">No.</b> Every system in scope has at least one disproved condition.`;
        body = `<p>${verdict} ${k.insufficient && aff.length ? `${plural(k.insufficient, 'more system')} lack evidence.` : ''} ${k.not_affected} of ${R.length} systems are not affected.</p>
          <p class="small muted" style="margin-top:6px">${esc(adv.title)} · ${cvss(adv.cvss)} ${adv.kev ? '<span class="tag kev">KEV</span>' : ''} · ${esc(adv.scopeNote)}</p>${mini(R)}`;
      }
    } else if (it.intent === 'priorities') {
      const aff = L.filter(a => a.outcome === 'affected' && !a.preview).sort((x, y) => y.priority.score - x.priority.score);
      const top = aff[0];
      body = `<p>Start with <b>${top.asset}</b> (${top.advisory}), priority ${top.priority.score}: ${top.priority.factors.filter(f => f.max && f.points >= f.max * 0.8).map(f => f.label.toLowerCase()).join(', ')}. ${top.results.find(r => r.claim.remediation)?.claim.remediation}.</p>${mini(aff.slice(0, 5))}`;
    } else if (it.intent === 'quality') {
      const R = L.filter(a => a.conflicts.length || a.stale.length);
      body = `<p>${plural(R.length, 'conclusion')} ${R.length === 1 ? 'relies' : 'rely'} on stale or conflicting evidence. ${R.filter(a => a.conflicts.length).length} involve source conflicts. Open a result to compare outcomes per source.</p>${mini(R)}`;
    } else if (it.intent === 'gaps') {
      const G = E.gaps(s, App.list());
      body = `<p>${plural(G.length, 'fact')} would close your largest exposure gaps. The most valuable one: <b>${esc(G[0]?.claim.label || '–')}</b> on <b>${G[0]?.asset || ''}</b>.</p>
        <div class="card" style="margin-top:10px"><div class="bd flush">${G.slice(0, 5).map(g => `<div class="li click" data-action="nav" data-href="#/gaps"><div class="ico amber">${ic('q')}</div><div class="body"><b>${esc(g.claim.label)}</b><small>${g.asset} · ${g.items.map(i => i.a.advisory).join(', ')} · potential priority ${g.potential}</small></div></div>`).join('')}</div></div>`;
    } else if (it.intent === 'changes') {
      const H = [...s.history].filter(h => h.kind === 'outcome' || h.kind === 'definition').sort((a, b) => Date.parse(b.at) - Date.parse(a.at)).slice(0, 6);
      body = `<p>Here is what changed most recently, and why:</p><div class="card" style="margin-top:10px"><div class="bd"><div class="tl">${H.map(histEvent).join('')}</div></div></div>`;
    } else if (it.intent === 'asset') {
      const R = L.filter(a => a.asset === it.asset), k = count(R);
      body = `<p><b>${it.asset}</b>: ${k.affected} affected, ${k.insufficient} insufficient, ${k.not_affected} not affected.</p>${mini(R)}`;
    } else {
      body = `<p>I can answer questions about exposure to a CVE or product, which systems are affected, evidence quality, gaps, priorities and recent changes. Try one of the suggestions below.</p>`;
    }
    return `<div class="msg user">${esc(q)}</div><div class="msg bot">${interp}<div class="card pad">${body}</div></div>`;
  }

  function ask() {
    const sugg = ['Are we vulnerable to CVE-2024-6387?', 'Are we exposed to the xz backdoor from the news?', 'Which systems use NetScaler?', 'Which conclusions rely on stale or conflicting data?', 'What do we need to learn to close our largest gaps?', 'What should we address first, and why?', 'What changed since last week?'];
    const html = `${pageHead('Ask Vulnio', 'Natural-language questions across the shared evidence base. AI interprets the question; every answer comes from the same deterministic assessments you can audit.', ui().ask.length ? `<button class="btn ghost" data-action="clearAsk">Clear</button>` : '')}
      <div class="chat">${ui().ask.map(m => answer(m.q)).join('')}<div id="ask-end"></div></div>
      <div class="spacer"></div>
      <form class="askbox" onsubmit="App.act('ask',{q:this.q.value});return false"><input id="ask-input" name="q" placeholder="Ask about a CVE, product, system, evidence or priorities…" autocomplete="off"><button class="btn primary">${ic('send')}Ask</button></form>
      <div class="spacer"></div><div class="suggest">${sugg.map(q => `<button data-action="ask" data-q="${esc(q)}">${esc(q)}</button>`).join('')}</div>`;
    return { title: 'Ask', crumbs: '<b>Ask Vulnio</b>', html, after: () => document.getElementById('ask-input')?.focus() };
  }

  return { overview, assessments, assessment, advisories, advisory, priorities, gaps, tasks, assets, asset, sources, history, ask };
})();
