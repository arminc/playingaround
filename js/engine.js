/* Vulnio deterministic assessment engine.
 * Same claims + same facts + same policy + same clock => same outcome.
 * Claim states use three-valued logic: true | false | unknown.
 * Definition logic: ALL active claims must be true for "affected".
 */
window.Engine = (() => {
  const DAY = 864e5;

  /* ---------------------------------------------------------- versions */
  const tok = (v) => (String(v).match(/\d+/g) || []).map(Number);
  function cmpVer(a, b) {
    const x = tok(a), y = tok(b);
    for (let i = 0; i < Math.max(x.length, y.length); i++) {
      const p = x[i] ?? -1, q = y[i] ?? -1;
      if (p !== q) return p < q ? -1 : 1;
    }
    return 0;
  }

  function test(op, exp, act) {
    switch (op) {
      case 'eq': return act === exp;
      case 'neq': return act !== exp;
      case 'in': return exp.includes(String(act));
      case 'version_ranges':
        if ((exp.except || []).includes(String(act))) return false;
        return exp.ranges.some(r => (r.gte == null || cmpVer(act, r.gte) >= 0) && (r.lt == null || cmpVer(act, r.lt) < 0));
      default: return false;
    }
  }

  const vtxt = (v) => typeof v === 'boolean' ? (v ? 'true' : 'false') : String(v);
  const rangeTxt = (r) => `${r.gte ? '[' + r.gte : '(−∞'}, ${r.lt ? r.lt + ')' : '∞)'}`;
  function exprText(c) {
    switch (c.op) {
      case 'eq': return `${c.attr} = ${vtxt(c.value)}`;
      case 'neq': return `${c.attr} ≠ ${vtxt(c.value)}`;
      case 'in': return `${c.attr} ∈ {${c.value.join(', ')}}`;
      case 'version_ranges':
        return `${c.attr} ∈ ${c.value.ranges.map(rangeTxt).join(' ∪ ')}` + ((c.value.except || []).length ? ` \\ {${c.value.except.join(', ')}}` : '');
    }
    return c.attr;
  }

  /* ------------------------------------------------------------ policy */
  const PRESETS = {
    default: { label: 'Organization policy' },
    recent:  { label: 'Most recent observation wins', mode: 'recent' },
    strict:  { label: 'Strict: conflicts block a decision', mode: 'strict' },
    human:   { label: 'Prefer owner attestations', first: 'human' },
    scanner: { label: 'Prefer vulnerability scanner', first: 'scanner' },
    cmdb:    { label: 'Prefer CMDB', first: 'cmdb' },
  };

  function policyFor(state, key = 'default', extra = {}) {
    const base = state.policy;
    const p = PRESETS[key] || {};
    const pol = { key, label: p.label, mode: p.mode || base.mode, precedence: [...base.precedence], freshness: { ...base.freshness }, ...extra };
    if (p.first) { pol.mode = 'precedence'; pol.precedence = [p.first, ...pol.precedence.filter(s => s !== p.first)]; }
    return pol;
  }

  /* ------------------------------------------------------------ claims */
  function evaluateClaim(state, claim, assetId, policy, now) {
    const all = state.facts.filter(f => f.asset === assetId && f.attr === claim.attr && Date.parse(f.observedAt) <= now);
    const usable = [], excluded = [];
    for (const f of all) {
      const age = (now - Date.parse(f.observedAt)) / DAY;
      const limit = policy.freshness[f.source] ?? 30;
      if (policy.onlySource && f.source !== policy.onlySource) excluded.push({ fact: f, why: 'source', detail: 'Excluded by source selection' });
      else if (age > limit) excluded.push({ fact: f, why: 'stale', detail: `${Math.floor(age)}d old, freshness limit ${limit}d` });
      else usable.push(f);
    }
    const base = { claim, all, excluded, usable, corroborating: [], overridden: [], conflict: false };
    if (!usable.length) {
      const stale = excluded.some(e => e.why === 'stale');
      return { ...base, state: 'unknown', reason: stale ? 'stale' : 'missing',
        why: stale ? 'All evidence for this condition is older than its freshness limit' : 'No evidence has been observed for this condition' };
    }
    const distinct = [...new Set(usable.map(f => JSON.stringify(f.value)))];
    const conflict = distinct.length > 1;
    const rank = (f) => { const i = policy.precedence.indexOf(f.source); return i < 0 ? 99 : i; };
    const recentFirst = (a, b) => Date.parse(b.observedAt) - Date.parse(a.observedAt);
    if (conflict && policy.mode === 'strict') {
      return { ...base, conflict, state: 'unknown', reason: 'conflict', why: `Sources disagree (${distinct.map(d => vtxt(JSON.parse(d))).join(' vs ')}) and the policy does not resolve conflicts` };
    }
    const sorted = [...usable].sort(policy.mode === 'recent' ? recentFirst : (a, b) => rank(a) - rank(b) || recentFirst(a, b));
    const fact = sorted[0];
    const same = sorted.slice(1).filter(f => JSON.stringify(f.value) === JSON.stringify(fact.value));
    const diff = sorted.slice(1).filter(f => JSON.stringify(f.value) !== JSON.stringify(fact.value));
    const holds = test(claim.op, claim.value, fact.value);
    const limit = policy.freshness[fact.source] ?? 30;
    return {
      ...base, conflict, fact, corroborating: same, overridden: diff,
      state: holds ? 'true' : 'false',
      reason: conflict ? 'resolved' : 'observed',
      why: conflict
        ? `Conflict resolved by ${policy.mode === 'recent' ? 'most recent observation' : 'source precedence'}: ${state.sources[fact.source].name} wins`
        : `Observed by ${state.sources[fact.source].name}`,
      validUntil: Date.parse(fact.observedAt) + limit * DAY,
    };
  }

  function activeClaims(adv) {
    const preview = adv.definition.status !== 'approved';
    return adv.claims.filter(c => c.status === 'accepted' || (preview && c.status === 'proposed'));
  }

  function combine(states) {
    if (!states.length) return 'insufficient';
    if (states.includes('false')) return 'not_affected';
    if (states.every(s => s === 'true')) return 'affected';
    return 'insufficient';
  }

  /* -------------------------------------------------------- assessment */
  function assess(state, adv, assetId, opts = {}) {
    const now = opts.now ?? state.now;
    const policy = opts.policy || policyFor(state);
    const claims = activeClaims(adv);
    const results = claims.map(c => {
      if (opts.overrides && opts.overrides[c.id]) return { claim: c, state: opts.overrides[c.id], reason: 'hypothetical', excluded: [], all: [], corroborating: [], overridden: [] };
      return evaluateClaim(state, c, assetId, policy, now);
    });
    const outcome = combine(results.map(r => r.state));
    const decisive = outcome === 'not_affected' ? results.filter(r => r.state === 'false')
      : outcome === 'insufficient' ? results.filter(r => r.state === 'unknown') : results;

    // Time validity: an affected result needs all facts; a not-affected result holds as long as any disproving fact is fresh
    let validUntil = null;
    if (outcome === 'affected') validUntil = Math.min(...results.map(r => r.validUntil || Infinity));
    if (outcome === 'not_affected') validUntil = Math.max(...decisive.map(r => r.validUntil || 0));

    const conflicts = results.filter(r => r.conflict);
    const stale = results.filter(r => r.excluded.some(e => e.why === 'stale'));
    const reliabilities = (outcome === 'insufficient' ? [] : decisive).map(r => r.fact && state.sources[r.fact.source].reliability);
    let confidence = 'strong';
    if (outcome === 'insufficient') confidence = 'none';
    else if (reliabilities.includes('medium') || conflicts.some(c => decisive.includes(c))) confidence = 'moderate';
    if (outcome !== 'insufficient' && decisive.every(r => r.fact && r.fact.source === 'human')) confidence = 'weak';

    return {
      adv, advisory: adv.id, asset: assetId, outcome, results, decisive, validUntil, conflicts, stale, confidence,
      preview: adv.definition.status !== 'approved', policy, now,
      trueCount: results.filter(r => r.state === 'true').length,
    };
  }

  /* Which facts would change the outcome? */
  function counterfactuals(state, a) {
    const out = [];
    for (const r of a.results) {
      const variants = {};
      for (const s of ['true', 'false']) {
        if (s === r.state) continue;
        const o = { ...Object.fromEntries(a.results.filter(x => x.reason === 'hypothetical').map(x => [x.claim.id, x.state])), [r.claim.id]: s };
        variants[s] = assess(state, a.adv, a.asset, { policy: a.policy, now: a.now, overrides: o }).outcome;
      }
      out.push({ result: r, variants });
    }
    return out;
  }

  function byPolicies(state, adv, assetId) {
    return Object.keys(PRESETS).map(k => ({ key: k, label: PRESETS[k].label, a: assess(state, adv, assetId, { policy: policyFor(state, k) }) }));
  }

  function bySources(state, adv, assetId) {
    const attrs = new Set(activeClaims(adv).map(c => c.attr));
    const srcs = [...new Set(state.facts.filter(f => f.asset === assetId && attrs.has(f.attr)).map(f => f.source))];
    return srcs.map(s => ({ source: s, a: assess(state, adv, assetId, { policy: policyFor(state, 'default', { onlySource: s }) }) }));
  }

  /* ---------------------------------------------------------- priority */
  function priority(state, a) {
    const adv = a.adv, asset = state.assets[a.asset], svc = state.services[asset.service];
    const f = [];
    const ex = { active: 25, poc: 12, none: 4 }[adv.exploitation.level] ?? 5;
    f.push({ key: 'exploit', label: 'Exploitation', points: ex, max: 25, detail: adv.exploitation.label });
    const expo = asset.exposure[adv.surface] || asset.exposure.default;
    f.push({ key: 'exposure', label: 'Reachability', points: { internet: 25, partner: 16, internal: 5 }[expo], max: 25, detail: `${expo === 'internet' ? 'Internet-facing' : expo === 'partner' ? 'Partner-reachable' : 'Internal only'}: ${asset.exposureNote}` });
    f.push({ key: 'crit', label: 'Business criticality', points: svc.criticality * 3, max: 15, detail: `${svc.name} (tier ${6 - svc.criticality})` });
    f.push({ key: 'data', label: 'Data sensitivity', points: { pii: 10, secrets: 9, financial: 8, operational: 6, internal: 4 }[svc.data], max: 10, detail: svc.dataLabel });
    f.push({ key: 'users', label: 'Users affected', points: svc.users * 2, max: 10, detail: svc.usersLabel });
    let ev = { points: 0, detail: 'No planned events in the next 60 days' };
    for (const e of svc.events || []) {
      const d = (Date.parse(e.at) - a.now) / DAY;
      const p = d < -2 ? 0 : d <= 7 ? 10 : d <= 21 ? 6 : d <= 60 ? 3 : 0;
      if (p > ev.points) ev = { points: p, detail: `${e.name} ${d < 0 ? 'in progress' : 'in ' + Math.ceil(d) + ' days'}` };
    }
    f.push({ key: 'event', label: 'Planned events', points: ev.points, max: 10, detail: ev.detail });
    const ctl = (asset.controls || []).filter(c => c.surfaces.includes(adv.surface));
    if (ctl.length) f.push({ key: 'controls', label: 'Compensating controls', points: ctl.reduce((s, c) => s + c.points, 0), max: 0, detail: ctl.map(c => c.label).join(', ') });
    f.push({ key: 'conf', label: 'Evidence confidence', points: { strong: 5, moderate: 3, weak: 1, none: 2 }[a.confidence], max: 5, detail: a.confidence === 'none' ? 'Potential priority if confirmed' : `${a.confidence[0].toUpperCase() + a.confidence.slice(1)} evidence` });
    const score = Math.max(0, Math.min(100, f.reduce((s, x) => s + x.points, 0)));
    const band = score >= 75 ? 'critical' : score >= 60 ? 'high' : score >= 40 ? 'medium' : 'low';
    return { score, band, factors: f };
  }

  const BAND = { critical: 'Act now', high: 'This week', medium: 'This month', low: 'Backlog' };

  /* ------------------------------------------------------ organisation */
  function all(state, { includePreview = false } = {}) {
    const out = [];
    for (const adv of state.advisories) {
      if (!includePreview && adv.definition.status !== 'approved') continue;
      for (const asset of adv.scope) {
        const a = assess(state, adv, asset);
        a.priority = priority(state, a);
        out.push(a);
      }
    }
    return out;
  }

  function gaps(state, list) {
    const map = new Map();
    for (const a of list.filter(x => x.outcome === 'insufficient' && !x.preview)) {
      const cfs = counterfactuals(state, a);
      for (const r of a.results.filter(r => r.state === 'unknown')) {
        const key = a.asset + '|' + r.claim.attr;
        const cf = cfs.find(c => c.result === r);
        const g = map.get(key) || { key, asset: a.asset, attr: r.claim.attr, claim: r.claim, reason: r.reason, items: [], potential: 0 };
        g.items.push({ a, claim: r.claim, ifTrue: cf.variants.true, ifFalse: cf.variants.false });
        g.potential = Math.max(g.potential, a.priority.score);
        map.set(key, g);
      }
    }
    return [...map.values()].map(g => {
      // how many other unknowns remain in each assessment (fewer = closer to a decision)
      g.closes = g.items.filter(i => i.ifTrue !== 'insufficient' || i.ifFalse !== 'insufficient').length;
      g.value = g.potential + g.closes * 15;
      return g;
    }).sort((x, y) => y.value - x.value);
  }

  return { cmpVer, test, exprText, vtxt, PRESETS, BAND, policyFor, evaluateClaim, activeClaims, assess, counterfactuals, byPolicies, bySources, priority, all, gaps, DAY };
})();
