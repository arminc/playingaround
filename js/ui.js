/* Shared UI helpers */
window.UI = (() => {
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const md = (s) => esc(s).replace(/`([^`]+)`/g, '<code>$1</code>');

  const P = {
    overview: '<path d="M4 13h6V4H4zM14 20h6V11h-6zM4 20h6v-3H4zM14 7h6V4h-6z"/>',
    ask: '<path d="M21 12a8 8 0 0 1-11.6 7.1L4 20l1-4.6A8 8 0 1 1 21 12z"/><path d="M9 10h6M9 13.5h4"/>',
    advisory: '<path d="M6 3h9l4 4v14H6z"/><path d="M15 3v4h4M9 12h7M9 16h5"/>',
    shield: '<path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/>',
    target: '<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="4"/><circle cx="12" cy="12" r=".6"/>',
    search: '<circle cx="11" cy="11" r="6.5"/><path d="M20 20l-4.4-4.4"/>',
    server: '<rect x="3.5" y="4" width="17" height="7" rx="1.5"/><rect x="3.5" y="13" width="17" height="7" rx="1.5"/><path d="M7 7.5h.01M7 16.5h.01"/>',
    db: '<ellipse cx="12" cy="5.5" rx="7" ry="2.5"/><path d="M5 5.5v6c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5v-6"/><path d="M5 11.5v6c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5v-6"/>',
    agent: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
    code: '<path d="M8 8l-4 4 4 4M16 8l4 4-4 4M13.5 5l-3 14"/>',
    layers: '<path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5"/>',
    user: '<circle cx="12" cy="8" r="4"/><path d="M4 21c1.5-4 4.5-6 8-6s6.5 2 8 6"/>',
    radar: '<circle cx="12" cy="12" r="8"/><path d="M12 12l5-5"/><circle cx="12" cy="12" r="3"/>',
    globe: '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.5 2.5 3.5 5.5 3.5 8.5s-1 6-3.5 8.5c-2.5-2.5-3.5-5.5-3.5-8.5s1-6 3.5-8.5z"/>',
    history: '<path d="M4 12a8 8 0 1 0 2.4-5.7L4 8.5"/><path d="M4 4v4.5h4.5M12 8v4.5l3 2"/>',
    inbox: '<path d="M4 13l2.5-8h11L20 13v6H4z"/><path d="M4 13h4.5l1 2.5h5l1-2.5H20"/>',
    plug: '<path d="M9 3v5M15 3v5M6 8h12v3a6 6 0 0 1-12 0zM12 17v4"/>',
    bolt: '<path d="M13 3L5 13.5h6L10 21l8-10.5h-6z"/>',
    check: '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
    x: '<path d="M6 6l12 12M18 6L6 18"/>',
    q: '<path d="M9.2 9a3 3 0 1 1 4.3 2.7c-.9.4-1.5 1.2-1.5 2.2v.6M12 18h.01"/>',
    arrow: '<path d="M5 12h14M13 6l6 6-6 6"/>',
    chev: '<path d="M9 6l6 6-6 6"/>',
    clock: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
    alert: '<path d="M12 4l9 16H3z"/><path d="M12 10v4M12 17h.01"/>',
    split: '<path d="M6 4v5a4 4 0 0 0 4 4h4a4 4 0 0 1 4 4v3M18 4v5a4 4 0 0 1-4 4"/>',
    sparkle: '<path d="M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8zM19 16l.8 2.2L22 19l-2.2.8L19 22l-.8-2.2L16 19l2.2-.8z"/>',
    flag: '<path d="M5 21V4M5 4h11l-2 4 2 4H5"/>',
    wrench: '<path d="M14.5 6.5a4 4 0 0 0 5 5L12 19a2.1 2.1 0 0 1-3-3l7.5-7.5a4 4 0 0 1-2-2z"/>',
    calendar: '<rect x="4" y="5" width="16" height="15" rx="2"/><path d="M4 10h16M9 3v4M15 3v4"/>',
    play: '<path d="M7 5l12 7-12 7z"/>',
    reset: '<path d="M4 12a8 8 0 1 0 2.4-5.7L4 8.5"/><path d="M4 4v4.5h4.5"/>',
    edit: '<path d="M4 20h4L19 9l-4-4L4 16z"/>',
    send: '<path d="M4 12l16-8-6 16-2.5-6.5z"/>',
    link: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
  };
  const ic = (name, cls = '') => `<svg class="${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">${P[name] || ''}</svg>`;

  const OUT = {
    affected: 'Affected',
    not_affected: 'Not affected',
    insufficient: 'Insufficient evidence',
  };
  const outcome = (o, lg = false, preview = false) => preview
    ? `<span class="pill o-preview ${lg ? 'lg' : ''}"><span class="dot"></span>Preview: ${OUT[o]}</span>`
    : `<span class="pill o-${o} ${lg ? 'lg' : ''}"><span class="dot"></span>${OUT[o]}</span>`;

  const CLAIM_STATE = { true: 'Holds', false: 'Disproved', unknown: 'Unknown' };
  const claimIcon = (s, hyp) => `<span class="st st-${s} ${hyp ? 'st-hyp' : ''}">${s === 'true' ? ic('check') : s === 'false' ? ic('x') : '?'}</span>`;

  const band = (p) => `<span class="band band-${p.band}">${p.score} · ${Engine.BAND[p.band]}</span>`;
  const cvss = (v) => `<span class="cvss ${v >= 9 ? 'hi' : ''}">CVSS ${v.toFixed(1)}</span>`;

  const TYPE = {
    product_present: 'Product present', version_in_range: 'Version range', platform: 'Platform', feature_enabled: 'Feature enabled',
    config_value: 'Configuration', mitigation_absent: 'Mitigation absent', privilege: 'Privilege / attack path', code_usage: 'Code usage', reachability: 'Reachability',
  };
  const origin = (o) => o === 'ai' ? `<span class="tag ai">${ic('sparkle')}AI-proposed</span>` : o === 'reviewer' ? `<span class="tag rev">${ic('user')}Reviewer-added</span>` : `<span class="tag struct">${ic('layers')}Structured data</span>`;

  const initials = (name) => name.split(' ').filter(w => w[0] === w[0].toUpperCase()).map(w => w[0]).slice(0, 2).join('');

  function age(ms) {
    const s = Math.max(0, ms / 1000);
    if (s < 3600) return Math.max(1, Math.round(s / 60)) + 'm';
    if (s < 86400) return Math.round(s / 3600) + 'h';
    return Math.round(s / 86400) + 'd';
  }
  const fmtDate = (t) => new Date(t).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
  const fmtDT = (t) => new Date(t).toLocaleString('en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
  function rel(t, now) {
    const d = (now - t) / 864e5;
    if (d < 0) { const f = -d; return f < 1 ? 'in ' + Math.round(f * 24) + 'h' : 'in ' + Math.round(f) + ' days'; }
    if (d < 1 / 24) return 'just now';
    if (d < 1) return Math.round(d * 24) + 'h ago';
    if (d < 2) return 'yesterday';
    return Math.round(d) + ' days ago';
  }

  const dist = (c) => {
    const t = (c.affected + c.not_affected + c.insufficient) || 1;
    return `<div class="dist"><i class="a" style="width:${c.affected / t * 100}%"></i><i class="u" style="width:${c.insufficient / t * 100}%"></i><i class="n" style="width:${c.not_affected / t * 100}%"></i></div>`;
  };
  const count = (list) => list.reduce((c, a) => (c[a.outcome]++, c), { affected: 0, not_affected: 0, insufficient: 0 });

  function ring(a) {
    const n = a.results.length || 1, R = 48, C = 2 * Math.PI * R, gap = n > 1 ? 5 : 0;
    const seg = C / n;
    const col = { true: '#ff5f5f', false: '#2fd69b', unknown: '#ffc53d' };
    const arcs = a.results.map((r, i) => `<circle cx="59" cy="59" r="${R}" fill="none" stroke="${col[r.state]}" stroke-width="9" stroke-dasharray="${seg - gap} ${C - seg + gap}" stroke-dashoffset="${-i * seg}" ${r.state === 'unknown' ? 'stroke-opacity=".85"' : ''} stroke-linecap="butt" transform="rotate(-90 59 59)"/>`).join('');
    const big = a.outcome === 'not_affected' ? a.results.filter(r => r.state === 'false').length : a.trueCount;
    const lbl = a.outcome === 'not_affected' ? 'DISPROVED' : 'PROVEN';
    const num = a.outcome === 'not_affected' ? `${big}` : `${big}/${a.results.length}`;
    return `<svg class="ring" viewBox="0 0 118 118"><circle cx="59" cy="59" r="${R}" fill="none" stroke="rgba(255,255,255,.07)" stroke-width="9"/>${arcs}
      <text x="59" y="62" text-anchor="middle" font-family="Inter Display,Inter" font-weight="700" font-size="26" fill="#f4f6ff">${num}</text>
      <text x="59" y="79" text-anchor="middle" font-family="Inter" font-weight="600" font-size="8.5" letter-spacing="1.5" fill="#a3abcc">${lbl}</text></svg>`;
  }

  return { esc, md, ic, outcome, OUT, CLAIM_STATE, claimIcon, band, cvss, TYPE, origin, initials, age, fmtDate, fmtDT, rel, dist, count, ring };
})();
