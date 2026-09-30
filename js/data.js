/* Vulnio demo dataset.
 * Fictional organisation (Noordhaven Logistics B.V.) assessed against real, well-known CVEs.
 * All times are relative to BASE so the demo always looks "current".
 */
window.VULNIO_SEED = (() => {
  const BASE = Date.parse('2026-09-30T09:00:00Z');
  const DAY = 864e5;
  const ago = (d) => new Date(BASE - d * DAY).toISOString();
  const ahead = (d) => new Date(BASE + d * DAY).toISOString();

  let n = 0;
  const F = (asset, attr, value, source, days, note, extra = {}) =>
    ({ id: 'f' + (++n), asset, attr, value, source, observedAt: ago(days), note, ...extra });

  /* ------------------------------------------------------------------ people */
  const people = {
    eva:    { id: 'eva',    name: 'Eva Jansen',       title: 'Vulnerability Analyst', team: 'Security Operations' },
    mark:   { id: 'mark',   name: 'Mark Visser',      title: 'CISO', team: 'Security' },
    joris:  { id: 'joris',  name: 'Joris Bakker',     title: 'Infrastructure Lead', team: 'Infrastructure' },
    sanne:  { id: 'sanne',  name: 'Sanne de Vries',   title: 'Product Owner, Customer Portal', team: 'Digital' },
    lisa:   { id: 'lisa',   name: 'Lisa Hoekstra',    title: 'Product Security Engineer', team: 'Digital' },
    pieter: { id: 'pieter', name: 'Pieter de Graaf',  title: 'Operations IT Manager', team: 'Operations IT' },
    fatima: { id: 'fatima', name: 'Fatima El Amrani', title: 'Integration Lead', team: 'Integration' },
    daan:   { id: 'daan',   name: 'Daan Mulder',      title: 'Platform Engineer', team: 'Platform' },
  };

  const roles = {
    analyst:   { id: 'analyst',   label: 'Vulnerability analyst', person: 'eva',  landing: '#/overview' },
    owner:     { id: 'owner',     label: 'System owner',          person: 'joris', landing: '#/tasks' },
    ciso:      { id: 'ciso',      label: 'CISO',                  person: 'mark', landing: '#/overview' },
    developer: { id: 'developer', label: 'Developer / ProdSec',   person: 'lisa', landing: '#/assessment/CVE-2021-44228/portal-api' },
  };

  /* ----------------------------------------------------------------- sources */
  const sources = {
    agent:    { id: 'agent',    name: 'Vulnio Agent',        kind: 'Direct observation',    reliability: 'high',   icon: 'agent',   sync: 0.05 },
    vcenter:  { id: 'vcenter',  name: 'vCenter API',         kind: 'Platform API',          reliability: 'high',   icon: 'server',  sync: 0.1 },
    panorama: { id: 'panorama', name: 'Panorama API',        kind: 'Platform API',          reliability: 'high',   icon: 'shield',  sync: 0.5 },
    adm:      { id: 'adm',      name: 'NetScaler ADM',       kind: 'Platform API',          reliability: 'high',   icon: 'server',  sync: 1 },
    code:     { id: 'code',     name: 'Code analysis',       kind: 'Source code (GitHub)',  reliability: 'high',   icon: 'code',    sync: 1 },
    sbom:     { id: 'sbom',     name: 'Dependency-Track',    kind: 'SBOM / SCA',            reliability: 'high',   icon: 'layers',  sync: 2 },
    human:    { id: 'human',    name: 'Owner attestation',   kind: 'Human answer',          reliability: 'medium', icon: 'user',    sync: null },
    scanner:  { id: 'scanner',  name: 'Tenable Nessus',      kind: 'Vulnerability scanner', reliability: 'medium', icon: 'radar',   sync: 3 },
    easm:     { id: 'easm',     name: 'Attack surface scan', kind: 'External exposure',     reliability: 'medium', icon: 'globe',   sync: 2 },
    cmdb:     { id: 'cmdb',     name: 'ServiceNow CMDB',     kind: 'Asset inventory',       reliability: 'medium', icon: 'db',      sync: 1 },
  };

  const policy = {
    mode: 'precedence', // precedence | recent | strict
    precedence: ['agent', 'vcenter', 'panorama', 'adm', 'code', 'sbom', 'human', 'scanner', 'easm', 'cmdb'],
    freshness: { agent: 7, vcenter: 7, panorama: 7, adm: 7, code: 30, sbom: 30, human: 30, scanner: 14, easm: 7, cmdb: 90 },
  };

  /* ---------------------------------------------------------------- services */
  const services = {
    portal:   { id: 'portal',   name: 'Customer Portal',        criticality: 5, data: 'pii',         dataLabel: 'Customer PII',          users: 5, usersLabel: '48,000 customers',  owner: 'sanne',
                events: [{ name: 'Track & Trace 2.0 public launch', at: ahead(14), note: 'Marketing campaign, expected 3x traffic' }] },
    wms:      { id: 'wms',      name: 'Warehouse Management',   criticality: 5, data: 'operational', dataLabel: 'Operational / orders',  users: 3, usersLabel: '620 warehouse staff', owner: 'pieter',
                events: [{ name: 'Peak season (Black Friday)', at: ahead(56), note: 'Change freeze from 1 Nov' }] },
    remote:   { id: 'remote',   name: 'Remote Access',          criticality: 4, data: 'internal',    dataLabel: 'Corporate network access', users: 4, usersLabel: '900 employees',   owner: 'joris', events: [] },
    edi:      { id: 'edi',      name: 'Partner EDI Integration', criticality: 4, data: 'financial',  dataLabel: 'Orders & invoices',     users: 2, usersLabel: '140 partners',      owner: 'fatima', events: [] },
    platform: { id: 'platform', name: 'CI/CD Platform',         criticality: 3, data: 'secrets',     dataLabel: 'Source code & secrets', users: 2, usersLabel: '85 engineers',      owner: 'daan', events: [] },
    virt:     { id: 'virt',     name: 'Virtualization Platform', criticality: 4, data: 'internal',   dataLabel: 'Hosts all internal VMs', users: 4, usersLabel: 'All internal services', owner: 'joris', events: [] },
  };

  /* ------------------------------------------------------------------ assets */
  // exposure: per attack surface (ssh, app, vpn, mgmt, local); falls back to default
  const assets = {
    'web-01':       { id: 'web-01',       name: 'web-01',       kind: 'Linux VM',            os: 'Ubuntu 22.04 LTS', service: 'portal',   owner: 'sanne',  agent: true,
                      exposure: { default: 'internal', app: 'internet' }, exposureNote: 'HTTPS via load balancer; SSH only from bastion' },
    'web-02':       { id: 'web-02',       name: 'web-02',       kind: 'Linux VM',            os: 'Ubuntu 22.04 LTS', service: 'portal',   owner: 'sanne',  agent: true,
                      exposure: { default: 'internal', app: 'internet' }, exposureNote: 'HTTPS via load balancer; SSH only from bastion' },
    'portal-api':   { id: 'portal-api',   name: 'portal-api',   kind: 'Kubernetes deployment', os: 'Java 17 / Spring Boot', service: 'portal', owner: 'lisa', agent: false,
                      repo: 'github.com/noordhaven/portal-api', exposure: { default: 'internet' }, exposureNote: 'Public ingress api.noordhaven.nl',
                      controls: [{ label: 'WAF with JNDI lookup rules', points: -4, surfaces: ['app'] }] },
    'bastion-01':   { id: 'bastion-01',   name: 'bastion-01',   kind: 'Linux VM',            os: 'Ubuntu 24.04 LTS', service: 'remote',   owner: 'joris',  agent: true,
                      exposure: { default: 'internet' }, exposureNote: 'SSH (22/tcp) reachable from the internet' },
    'ns-gw-01':     { id: 'ns-gw-01',     name: 'ns-gw-01',     kind: 'NetScaler MPX',       os: 'NetScaler 13.1',   service: 'remote',   owner: 'joris',  agent: false,
                      exposure: { default: 'internet' }, exposureNote: 'Gateway vserver vpn.noordhaven.nl' },
    'ns-gw-02':     { id: 'ns-gw-02',     name: 'ns-gw-02',     kind: 'NetScaler VPX (DR)',  os: 'NetScaler 13.1',   service: 'remote',   owner: 'joris',  agent: false,
                      exposure: { default: 'internet' }, exposureNote: 'DR gateway, public IP assigned' },
    'pa-fw-ams-01': { id: 'pa-fw-ams-01', name: 'pa-fw-ams-01', kind: 'Palo Alto PA-3220',   os: 'PAN-OS 11.1',      service: 'remote',   owner: 'joris',  agent: false,
                      exposure: { default: 'internet' }, exposureNote: 'GlobalProtect portal gp.noordhaven.nl' },
    'pa-fw-rtm-01': { id: 'pa-fw-rtm-01', name: 'pa-fw-rtm-01', kind: 'Palo Alto PA-3220',   os: 'PAN-OS 10.2',      service: 'remote',   owner: 'joris',  agent: false,
                      exposure: { default: 'internet' }, exposureNote: 'GlobalProtect gateway Rotterdam' },
    'wms-app-01':   { id: 'wms-app-01',   name: 'wms-app-01',   kind: 'Linux VM',            os: 'RHEL 9.3',         service: 'wms',      owner: 'pieter', agent: true,
                      exposure: { default: 'internal' }, exposureNote: 'Internal only (warehouse VLANs)' },
    'edi-gw-01':    { id: 'edi-gw-01',    name: 'edi-gw-01',    kind: 'Linux VM',            os: 'RHEL 7.9',         service: 'edi',      owner: 'fatima', agent: true,
                      exposure: { default: 'partner' }, exposureNote: 'SFTP/SSH reachable by 140 partner IP ranges' },
    'ci-runner-01': { id: 'ci-runner-01', name: 'ci-runner-01', kind: 'Linux VM',            os: 'Debian 12',        service: 'platform', owner: 'daan',   agent: true,
                      exposure: { default: 'internal' }, exposureNote: 'Internal only' },
    'esx-01':       { id: 'esx-01',       name: 'esx-01',       kind: 'ESXi host',           os: 'ESXi 8.0 U2',      service: 'virt',     owner: 'joris',  agent: false,
                      exposure: { default: 'internal' }, exposureNote: 'Management network only' },
    'esx-02':       { id: 'esx-02',       name: 'esx-02',       kind: 'ESXi host',           os: 'ESXi 8.0 U3',      service: 'virt',     owner: 'joris',  agent: false,
                      exposure: { default: 'internal' }, exposureNote: 'Management network only' },
  };

  /* -------------------------------------------------------------- advisories */
  const advisories = [
    {
      id: 'CVE-2024-6387', title: 'OpenSSH "regreSSHion": unauthenticated RCE in sshd', vendor: 'OpenSSH', product: 'OpenSSH server (sshd)',
      cvss: 8.1, kev: false, exploitation: { level: 'poc', label: 'Public PoC, complex exploitation' }, published: '2024-07-01', surface: 'ssh',
      keywords: ['openssh', 'ssh', 'sshd', 'regresshion'],
      scope: ['web-01', 'web-02', 'bastion-01', 'wms-app-01', 'edi-gw-01', 'ci-runner-01'], scopeNote: 'Linux hosts from CMDB + agent inventory',
      intel: [
        { source: 'NCSC CSAF feed', kind: 'National CERT', rev: 3, at: '2024-07-05' },
        { source: 'OpenSSH 9.8 release notes', kind: 'Vendor', rev: 1, at: '2024-07-01' },
        { source: 'Qualys Threat Research', kind: 'Research', rev: 1, at: '2024-07-01' },
        { source: 'NVD', kind: 'CVE database', rev: 4, at: '2024-09-12' },
      ],
      definition: { version: 2, status: 'approved', by: 'eva', at: ago(38) },
      versions: [
        { version: 1, at: ago(40), by: 'AI extraction', note: 'Initial extraction: 4 claims proposed from 4 sources' },
        { version: 2, at: ago(38), by: 'eva', note: 'Reviewer added c5 (distribution backport). Without it, every Ubuntu/Debian/RHEL host would be reported affected on version alone.' },
      ],
      passages: [
        { id: 'p1', src: 'Qualys', text: 'A signal handler race condition was found in OpenSSH\'s server (sshd). If a client does not authenticate within LoginGraceTime seconds, sshd\'s SIGALRM handler is called asynchronously and calls functions that are not async-signal-safe.' },
        { id: 'p2', src: 'OpenSSH', text: 'OpenSSH versions earlier than 4.4p1 are vulnerable unless patched for CVE-2006-5051 and CVE-2008-4109, and versions from 8.5p1 up to, but not including, 9.8p1 are vulnerable.' },
        { id: 'p3', src: 'Qualys', text: 'Exploitation has been demonstrated on glibc-based Linux systems. OpenBSD is not vulnerable.' },
        { id: 'p4', src: 'OpenSSH', text: 'If sshd cannot be updated, setting LoginGraceTime to 0 in the configuration file mitigates the remote code execution, at the cost of exposing sshd to a denial of service by exhausting all MaxStartups connections.' },
        { id: 'p5', src: 'NCSC', text: 'Linux distributions have published backported fixes. Check the package version of your distribution instead of the upstream version number.' },
      ],
      claims: [
        { id: 'c1', type: 'product_present', label: 'OpenSSH server is installed', attr: 'openssh.installed', op: 'eq', value: true, ref: 'p1', quote: 'OpenSSH\'s server (sshd)', status: 'accepted', origin: 'structured',
          howTo: 'Check the package manager: `dpkg -l openssh-server` or `rpm -q openssh-server`.', question: { text: 'Is OpenSSH server (sshd) installed on this system?', type: 'bool' } },
        { id: 'c2', type: 'version_in_range', label: 'Installed version is in an affected range', attr: 'openssh.version', op: 'version_ranges',
          value: { ranges: [{ lt: '4.4p1' }, { gte: '8.5p1', lt: '9.8p1' }] }, ref: 'p2', quote: 'versions from 8.5p1 up to, but not including, 9.8p1 are vulnerable', status: 'accepted', origin: 'structured',
          howTo: 'Run `ssh -V` or `sshd -V` on the host.', question: { text: 'Which OpenSSH version is installed (e.g. 9.6p1)?', type: 'text' },
          remediation: 'Upgrade OpenSSH to 9.8p1 or later' },
        { id: 'c3', type: 'platform', label: 'Runs on glibc-based Linux', attr: 'os.libc', op: 'eq', value: 'glibc', ref: 'p3', quote: 'glibc-based Linux systems', status: 'accepted', origin: 'ai',
          ai: { confidence: 0.91, rationale: 'Advisory states exploitation was demonstrated on glibc Linux and OpenBSD is not vulnerable. Modelled as platform condition; musl/BSD hosts disprove it.' },
          howTo: 'Check `ldd --version`. Alpine (musl) and BSD systems do not satisfy this condition.', question: { text: 'Which C library does the OS use?', type: 'choice', options: ['glibc', 'musl', 'other'] } },
        { id: 'c4', type: 'mitigation_absent', label: 'Mitigation absent: LoginGraceTime is not 0', attr: 'sshd.LoginGraceTime', op: 'neq', value: 0, ref: 'p4', quote: 'setting LoginGraceTime to 0', status: 'accepted', origin: 'ai',
          ai: { confidence: 0.88, rationale: 'Workaround text describes a configuration that removes the vulnerable code path. Modelled as mitigation: the claim holds while LoginGraceTime is not 0.' },
          howTo: 'Run `sshd -T | grep -i logingracetime` on the host. The default is 120.', question: { text: 'What is the effective LoginGraceTime value? (`sshd -T | grep -i logingracetime`)', type: 'number' },
          remediation: 'Temporary mitigation: set LoginGraceTime 0 (accepts DoS risk via MaxStartups)' },
        { id: 'c5', type: 'mitigation_absent', label: 'Distribution fix is not installed', attr: 'openssh.distro_fix', op: 'eq', value: false, ref: 'p5', quote: 'backported fixes', status: 'accepted', origin: 'reviewer',
          ai: { confidence: 0.74, rationale: 'Added by reviewer Eva Jansen in v2. Distros backport the fix without changing the upstream version string.' },
          howTo: 'Compare the installed package with the distribution security notice (USN / DSA / RHSA).', question: { text: 'Is the distribution security update for CVE-2024-6387 installed?', type: 'bool' },
          remediation: 'Install the distribution security update for openssh-server' },
      ],
    },
    {
      id: 'CVE-2021-44228', title: 'Apache Log4j "Log4Shell": JNDI lookup RCE', vendor: 'Apache', product: 'Log4j 2 (log4j-core)',
      cvss: 10.0, kev: true, exploitation: { level: 'active', label: 'Actively exploited (CISA KEV)' }, published: '2021-12-10', surface: 'app',
      keywords: ['log4j', 'log4shell', 'java', 'jndi'],
      scope: ['portal-api', 'wms-app-01', 'edi-gw-01'], scopeNote: 'Java workloads from SBOM inventory',
      intel: [
        { source: 'Apache Logging security page', kind: 'Vendor', rev: 6, at: '2021-12-28' },
        { source: 'NCSC CSAF feed', kind: 'National CERT', rev: 9, at: '2022-01-14' },
        { source: 'CISA KEV', kind: 'Threat intel', rev: 1, at: '2021-12-10' },
        { source: 'NVD', kind: 'CVE database', rev: 12, at: '2023-11-07' },
      ],
      definition: { version: 1, status: 'approved', by: 'eva', at: ago(60) },
      versions: [{ version: 1, at: ago(60), by: 'eva', note: 'Accepted 4 claims (1 structured, 3 AI-proposed)' }],
      passages: [
        { id: 'p1', src: 'Apache', text: 'Apache Log4j2 2.0-beta9 through 2.14.1 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.' },
        { id: 'p2', src: 'Apache', text: 'An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.' },
        { id: 'p3', src: 'Apache', text: 'Note that only the log4j-core JAR file is impacted by this vulnerability. Applications using only the log4j-api JAR file without the log4j-core JAR file are not impacted.' },
        { id: 'p4', src: 'NCSC', text: 'For releases that cannot be upgraded, the risk can be mitigated by removing the JndiLookup class from the classpath: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class' },
      ],
      claims: [
        { id: 'c1', type: 'product_present', label: 'log4j-core is on the classpath', attr: 'log4j.core_present', op: 'eq', value: true, ref: 'p3', quote: 'only the log4j-core JAR file is impacted', status: 'accepted', origin: 'ai',
          ai: { confidence: 0.95, rationale: 'Advisory explicitly excludes log4j-api-only usage; product claim narrowed to log4j-core.' },
          howTo: 'Check the SBOM or search the deployed artefact for log4j-core-*.jar.', question: { text: 'Does the application ship log4j-core (not only log4j-api)?', type: 'bool' } },
        { id: 'c2', type: 'version_in_range', label: 'log4j-core version is affected', attr: 'log4j.core_version', op: 'version_ranges',
          value: { ranges: [{ gte: '2.0-beta9', lt: '2.15.0' }], except: ['2.12.2', '2.12.3', '2.3.1'] }, ref: 'p1', quote: '2.0-beta9 through 2.14.1 (excluding security releases 2.12.2, 2.12.3, and 2.3.1)', status: 'accepted', origin: 'structured',
          howTo: 'Read the version from the SBOM or the jar manifest.', question: { text: 'Which log4j-core version is deployed?', type: 'text' },
          remediation: 'Upgrade log4j-core to 2.17.1 or later' },
        { id: 'c3', type: 'mitigation_absent', label: 'Mitigation absent: JndiLookup class present', attr: 'log4j.jndilookup_present', op: 'eq', value: true, ref: 'p4', quote: 'removing the JndiLookup class from the classpath', status: 'accepted', origin: 'ai',
          ai: { confidence: 0.9, rationale: 'Removal of JndiLookup eliminates the vulnerable lookup. Modelled as mitigation absent.' },
          howTo: '`unzip -l log4j-core-*.jar | grep JndiLookup` inside the deployed artefact.', question: { text: 'Is JndiLookup.class still present in the deployed log4j-core jar?', type: 'bool' },
          remediation: 'Remove JndiLookup.class from the deployed jar (temporary)' },
        { id: 'c4', type: 'code_usage', label: 'Attacker-controlled input reaches a Log4j logger', attr: 'code.untrusted_input_logged', op: 'eq', value: true, ref: 'p2', quote: 'An attacker who can control log messages or log message parameters', status: 'accepted', origin: 'ai',
          ai: { confidence: 0.82, rationale: 'Exploitation requires attacker-influenced data in a log call. Evaluated by code analysis where source is available; otherwise by owner answer.' },
          howTo: 'Run code analysis for request data flowing into log calls, or ask the vendor for vendor software.', question: { text: 'Can external users influence any value that is written to the logs?', type: 'bool' },
          remediation: 'Stop logging untrusted input without sanitisation' },
      ],
    },
    {
      id: 'CVE-2023-4966', title: 'NetScaler ADC / Gateway "Citrix Bleed": session token disclosure', vendor: 'Citrix (Cloud Software Group)', product: 'NetScaler ADC & Gateway',
      cvss: 9.4, kev: true, exploitation: { level: 'active', label: 'Actively exploited (CISA KEV)' }, published: '2023-10-10', surface: 'vpn',
      keywords: ['netscaler', 'citrix', 'bleed', 'adc', 'gateway'],
      scope: ['ns-gw-01', 'ns-gw-02'], scopeNote: 'NetScaler appliances from ADM + CMDB',
      intel: [
        { source: 'Citrix security bulletin CTX579459', kind: 'Vendor', rev: 2, at: '2023-10-23' },
        { source: 'NCSC CSAF feed', kind: 'National CERT', rev: 4, at: '2023-10-27' },
        { source: 'CISA KEV', kind: 'Threat intel', rev: 1, at: '2023-10-18' },
      ],
      definition: { version: 1, status: 'approved', by: 'eva', at: ago(52) },
      versions: [{ version: 1, at: ago(52), by: 'eva', note: 'Accepted 3 claims. AI classified the session-kill instruction as remediation guidance, not an exposure condition.' }],
      passages: [
        { id: 'p1', src: 'Citrix', text: 'Sensitive information disclosure in NetScaler ADC and NetScaler Gateway when configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) or AAA virtual server.' },
        { id: 'p2', src: 'Citrix', text: 'Affected: NetScaler ADC and NetScaler Gateway 14.1 before 14.1-8.50, 13.1 before 13.1-49.15, 13.0 before 13.0-92.19. Only customer-managed NetScaler appliances are affected.' },
        { id: 'p3', src: 'Citrix', text: 'After upgrading, we recommend terminating all active and persistent sessions: kill icaconnection -all, kill aaa session -all, kill rdp connection -all.' },
      ],
      claims: [
        { id: 'c1', type: 'product_present', label: 'Customer-managed NetScaler appliance', attr: 'netscaler.present', op: 'eq', value: true, ref: 'p2', quote: 'customer-managed NetScaler appliances', status: 'accepted', origin: 'structured',
          howTo: 'Check NetScaler ADM or the CMDB.', question: { text: 'Is this a customer-managed NetScaler appliance?', type: 'bool' } },
        { id: 'c2', type: 'version_in_range', label: 'Firmware build is affected', attr: 'netscaler.version', op: 'version_ranges',
          value: { ranges: [{ gte: '14.1', lt: '14.1-8.50' }, { gte: '13.1', lt: '13.1-49.15' }, { gte: '13.0', lt: '13.0-92.19' }] }, ref: 'p2', quote: '14.1 before 14.1-8.50, 13.1 before 13.1-49.15, 13.0 before 13.0-92.19', status: 'accepted', origin: 'structured',
          howTo: 'Run `show ns version` on the appliance CLI.', question: { text: 'Which firmware build is running (show ns version)?', type: 'text' },
          remediation: 'Upgrade to 13.1-49.15 or later, then kill all active sessions' },
        { id: 'c3', type: 'feature_enabled', label: 'Configured as Gateway or AAA virtual server', attr: 'netscaler.gateway_vserver', op: 'eq', value: true, ref: 'p1', quote: 'configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) or AAA virtual server', status: 'accepted', origin: 'ai',
          ai: { confidence: 0.94, rationale: 'Feature condition. Any of the listed vserver types satisfies it.' },
          howTo: '`show vpn vserver` and `show authentication vserver` on the appliance.', question: { text: 'Is a Gateway (VPN/ICA/CVPN/RDP) or AAA virtual server configured?', type: 'bool' } },
      ],
    },
    {
      id: 'CVE-2024-3400', title: 'PAN-OS GlobalProtect: OS command injection', vendor: 'Palo Alto Networks', product: 'PAN-OS (GlobalProtect)',
      cvss: 10.0, kev: true, exploitation: { level: 'active', label: 'Actively exploited (CISA KEV)' }, published: '2024-04-12', surface: 'vpn',
      keywords: ['pan-os', 'panos', 'palo alto', 'globalprotect', 'firewall'],
      scope: ['pa-fw-ams-01', 'pa-fw-rtm-01'], scopeNote: 'Firewalls from Panorama',
      intel: [
        { source: 'Palo Alto PSIRT advisory', kind: 'Vendor', rev: 1, at: '2024-04-12' },
        { source: 'NCSC CSAF feed', kind: 'National CERT', rev: 1, at: '2024-04-12' },
        { source: 'CISA KEV', kind: 'Threat intel', rev: 1, at: '2024-04-12' },
      ],
      definition: { version: 1, status: 'approved', by: 'eva', at: ago(26) },
      versions: [{ version: 1, at: ago(26), by: 'eva', note: 'Accepted 5 claims from vendor advisory rev 1' }],
      passages: [
        { id: 'p1', src: 'Palo Alto', text: 'A command injection vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software for specific PAN-OS versions and distinct feature configurations may enable an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.' },
        { id: 'p2', src: 'Palo Alto', text: 'Affected: PAN-OS 11.1 < 11.1.2-h3, PAN-OS 11.0 < 11.0.4-h1, PAN-OS 10.2 < 10.2.9-h1. Cloud NGFW, Panorama appliances and Prisma Access are not impacted.' },
        { id: 'p3', src: 'Palo Alto', text: 'This issue is applicable only to PAN-OS firewalls configured with GlobalProtect gateway or GlobalProtect portal (or both) and device telemetry enabled.' },
        { id: 'p4', src: 'Palo Alto', text: 'Customers with a Threat Prevention subscription can block attacks for this vulnerability by enabling Threat ID 95187 and applying vulnerability protection to the GlobalProtect interface.' },
      ],
      claims: [
        { id: 'c1', type: 'product_present', label: 'PAN-OS hardware or VM firewall', attr: 'panos.present', op: 'eq', value: true, ref: 'p2', quote: 'Cloud NGFW, Panorama appliances and Prisma Access are not impacted', status: 'accepted', origin: 'structured',
          howTo: 'Check Panorama managed devices.', question: { text: 'Is this a PAN-OS firewall (not Cloud NGFW / Prisma Access)?', type: 'bool' } },
        { id: 'c2', type: 'version_in_range', label: 'PAN-OS version is affected', attr: 'panos.version', op: 'version_ranges',
          value: { ranges: [{ gte: '11.1', lt: '11.1.2-h3' }, { gte: '11.0', lt: '11.0.4-h1' }, { gte: '10.2', lt: '10.2.9-h1' }] }, ref: 'p2', quote: 'PAN-OS 11.1 < 11.1.2-h3, PAN-OS 11.0 < 11.0.4-h1, PAN-OS 10.2 < 10.2.9-h1', status: 'accepted', origin: 'structured',
          howTo: '`show system info` on the firewall.', question: { text: 'Which PAN-OS version is running?', type: 'text' },
          remediation: 'Upgrade PAN-OS to a fixed hotfix (e.g. 11.1.2-h3)' },
        { id: 'c3', type: 'feature_enabled', label: 'GlobalProtect gateway or portal configured', attr: 'panos.globalprotect', op: 'eq', value: true, ref: 'p3', quote: 'configured with GlobalProtect gateway or GlobalProtect portal (or both)', status: 'accepted', origin: 'ai',
          ai: { confidence: 0.96, rationale: 'Feature condition, either gateway or portal satisfies it.' },
          howTo: 'Network > GlobalProtect > Gateways / Portals in the firewall UI.', question: { text: 'Is a GlobalProtect gateway or portal configured?', type: 'bool' } },
        { id: 'c4', type: 'feature_enabled', label: 'Device telemetry enabled', attr: 'panos.telemetry', op: 'eq', value: true, ref: 'p3', quote: 'and device telemetry enabled', status: 'accepted', origin: 'ai',
          ai: { confidence: 0.86, rationale: 'Advisory rev 1 lists telemetry as a required condition.' },
          howTo: 'Device > Setup > Telemetry.', question: { text: 'Is device telemetry enabled?', type: 'bool' } },
        { id: 'c5', type: 'mitigation_absent', label: 'Mitigation absent: Threat ID 95187 not enforced on GP interface', attr: 'panos.tp95187_enforced', op: 'eq', value: false, ref: 'p4', quote: 'enabling Threat ID 95187 and applying vulnerability protection to the GlobalProtect interface', status: 'accepted', origin: 'ai',
          ai: { confidence: 0.84, rationale: 'Vendor workaround. Only effective when the vulnerability protection profile is applied to the GlobalProtect interface.' },
          howTo: 'Check the vulnerability protection profile bound to the GlobalProtect zone/interface.', question: { text: 'Is Threat ID 95187 blocking and applied to the GlobalProtect interface?', type: 'bool' },
          remediation: 'Enable Threat ID 95187 on the GlobalProtect interface (temporary)' },
      ],
      // applied by the "vendor updates advisory" demo event
      pendingUpdate: {
        intel: { source: 'Palo Alto PSIRT advisory', kind: 'Vendor', rev: 2, at: '2024-04-16' },
        passage: { id: 'p3', text: 'This issue is applicable only to PAN-OS firewalls configured with GlobalProtect gateway or GlobalProtect portal (or both). Device telemetry does not need to be enabled for PAN-OS firewalls to be exposed to attacks related to this vulnerability.' },
        removeClaim: 'c4',
        rationale: 'Vendor revision 2 states device telemetry is no longer a required condition. Claim c4 no longer has a supporting passage and would make results falsely "not affected".',
      },
    },
    {
      id: 'CVE-2024-3094', title: 'xz / liblzma supply-chain backdoor', vendor: 'Tukaani (xz-utils)', product: 'xz-utils / liblzma',
      cvss: 10.0, kev: false, exploitation: { level: 'poc', label: 'Backdoor known; limited in-the-wild use' }, published: '2024-03-29', surface: 'ssh',
      keywords: ['xz', 'liblzma', 'backdoor', 'news'],
      scope: ['web-01', 'web-02', 'bastion-01', 'wms-app-01', 'edi-gw-01', 'ci-runner-01'], scopeNote: 'Linux hosts from CMDB + agent inventory',
      intel: [
        { source: 'Openwall oss-security', kind: 'Research', rev: 1, at: '2024-03-29' },
        { source: 'NCSC CSAF feed', kind: 'National CERT', rev: 2, at: '2024-04-02' },
        { source: 'NVD', kind: 'CVE database', rev: 3, at: '2024-04-10' },
      ],
      definition: { version: 1, status: 'approved', by: 'eva', at: ago(33) },
      versions: [{ version: 1, at: ago(33), by: 'eva', note: 'Accepted 3 claims' }],
      passages: [
        { id: 'p1', src: 'Openwall', text: 'Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. Versions 5.6.0 and 5.6.1 contain the backdoor.' },
        { id: 'p2', src: 'Openwall', text: 'The resulting modified liblzma library can be used by any software linked against it, intercepting and modifying the data interaction with this library.' },
        { id: 'p3', src: 'NCSC', text: 'The malicious build step is only executed on x86-64 Linux when building Debian or RPM packages.' },
      ],
      claims: [
        { id: 'c1', type: 'product_present', label: 'xz-utils / liblzma installed', attr: 'xz.present', op: 'eq', value: true, ref: 'p2', quote: 'modified liblzma library', status: 'accepted', origin: 'structured',
          howTo: '`dpkg -l liblzma5` or `rpm -q xz-libs`.', question: { text: 'Is xz / liblzma installed?', type: 'bool' } },
        { id: 'c2', type: 'version_in_range', label: 'Backdoored version 5.6.0 or 5.6.1', attr: 'xz.version', op: 'in', value: ['5.6.0', '5.6.1'], ref: 'p1', quote: 'Versions 5.6.0 and 5.6.1 contain the backdoor', status: 'accepted', origin: 'structured',
          howTo: 'Run `xz --version`.', question: { text: 'Which xz version is installed?', type: 'text' }, remediation: 'Downgrade/upgrade xz to a clean version (5.4.x or 5.6.2+)' },
        { id: 'c3', type: 'platform', label: 'x86-64 Linux', attr: 'os.arch', op: 'eq', value: 'x86_64', ref: 'p3', quote: 'x86-64 Linux', status: 'accepted', origin: 'ai',
          ai: { confidence: 0.9, rationale: 'Build-time condition limits the payload to x86-64.' },
          howTo: '`uname -m`.', question: { text: 'What is the CPU architecture?', type: 'choice', options: ['x86_64', 'aarch64', 'other'] } },
      ],
    },
  ];

  // Advisory that arrives via the "new advisory ingested" demo event
  const incomingAdvisory = {
    id: 'CVE-2025-22224', title: 'VMware ESXi VMCI: TOCTOU out-of-bounds write (VM escape)', vendor: 'Broadcom (VMware)', product: 'VMware ESXi',
    cvss: 9.3, kev: true, exploitation: { level: 'active', label: 'Actively exploited (CISA KEV)' }, published: '2025-03-04', surface: 'local',
    keywords: ['esxi', 'vmware', 'vmci', 'escape', 'vsphere'],
    scope: ['esx-01', 'esx-02'], scopeNote: 'ESXi hosts from vCenter',
    intel: [
      { source: 'NCSC CSAF feed', kind: 'National CERT', rev: 1, at: '2025-03-04' },
      { source: 'Broadcom VMSA-2025-0004', kind: 'Vendor', rev: 1, at: '2025-03-04' },
      { source: 'CISA KEV', kind: 'Threat intel', rev: 1, at: '2025-03-04' },
    ],
    definition: { version: 0, status: 'in_review', by: null, at: null },
    versions: [{ version: 0, at: null, by: 'AI extraction', note: 'Draft: 3 claims proposed, awaiting review' }],
    passages: [
      { id: 'p1', src: 'Broadcom', text: 'VMware ESXi and Workstation contain a TOCTOU (Time-of-Check Time-of-Use) vulnerability that leads to an out-of-bounds write.' },
      { id: 'p2', src: 'Broadcom', text: 'A malicious actor with local administrative privileges on a virtual machine may exploit this issue to execute code as the virtual machine\'s VMX process running on the host.' },
      { id: 'p3', src: 'Broadcom', text: 'Affected: ESXi 8.0 before ESXi80U3d-24585383 (8.0 U2: ESXi80U2d-24585300), ESXi 7.0 before ESXi70U3s-24585291. There are no workarounds.' },
    ],
    claims: [
      { id: 'c1', type: 'product_present', label: 'VMware ESXi host', attr: 'esxi.present', op: 'eq', value: true, ref: 'p1', quote: 'VMware ESXi', status: 'proposed', origin: 'structured',
        howTo: 'vCenter inventory.', question: { text: 'Is this an ESXi host?', type: 'bool' } },
      { id: 'c2', type: 'version_in_range', label: 'ESXi build below fixed build', attr: 'esxi.build', op: 'version_ranges',
        value: { ranges: [{ gte: '8.0.3', lt: '8.0.3-24585383' }, { gte: '8.0.2', lt: '8.0.2-24585300' }, { gte: '7.0', lt: '7.0.3-24585291' }] }, ref: 'p3', quote: 'ESXi 8.0 before ESXi80U3d-24585383 (8.0 U2: ESXi80U2d-24585300), ESXi 7.0 before ESXi70U3s-24585291', status: 'proposed', origin: 'structured',
        howTo: '`vmware -vl` on the host or vCenter summary.', question: { text: 'Which ESXi build is running?', type: 'text' }, remediation: 'Patch to ESXi80U3d-24585383 / ESXi80U2d-24585300' },
      { id: 'c3', type: 'privilege', label: 'Attacker can obtain local admin in a guest VM', attr: 'vsphere.guest_admin_possible', op: 'eq', value: true, ref: 'p2', quote: 'local administrative privileges on a virtual machine', status: 'proposed', origin: 'ai',
        ai: { confidence: 0.63, rationale: 'Attack path requires admin in a guest. Low confidence: in most estates any compromised VM satisfies this. Reviewer may prefer to reject this claim and treat it as always true.' },
        howTo: 'Ask the platform owner whether guests run untrusted workloads or have admins outside the infrastructure team.', question: { text: 'Do any VMs on this host have administrators outside the infrastructure team, or run internet-facing workloads?', type: 'bool' } },
    ],
  };

  /* ------------------------------------------------------------------- facts */
  const sshNoteDefault = 'sshd -T (effective config)';
  const facts = [
    // --- OS basics
    F('web-01', 'os.libc', 'glibc', 'agent', 0.1, 'ldd (Ubuntu GLIBC 2.35)'),
    F('web-02', 'os.libc', 'glibc', 'agent', 0.1, 'ldd (Ubuntu GLIBC 2.35)'),
    F('bastion-01', 'os.libc', 'glibc', 'cmdb', 40, 'OS = Ubuntu 24.04 LTS (inferred glibc)'),
    F('wms-app-01', 'os.libc', 'glibc', 'agent', 0.2, 'ldd (GNU libc 2.34)'),
    F('edi-gw-01', 'os.libc', 'glibc', 'agent', 0.3, 'ldd (GNU libc 2.17)'),
    F('ci-runner-01', 'os.libc', 'glibc', 'agent', 0.2, 'ldd (Debian GLIBC 2.36)'),
    ...['web-01', 'web-02', 'wms-app-01', 'edi-gw-01', 'ci-runner-01'].map(a => F(a, 'os.arch', 'x86_64', 'agent', 0.2, 'uname -m')),
    F('bastion-01', 'os.arch', 'x86_64', 'cmdb', 40, 'CMDB hardware profile'),

    // --- OpenSSH
    F('web-01', 'openssh.installed', true, 'agent', 0.1, 'dpkg: openssh-server 1:8.9p1-3ubuntu0.10'),
    F('web-01', 'openssh.version', '8.9p1', 'agent', 0.1, 'sshd -V'),
    F('web-01', 'openssh.version', '8.9p1', 'scanner', 5, 'Plugin 201194 banner check'),
    F('web-01', 'openssh.distro_fix', true, 'agent', 0.1, 'USN-6859-1 fix installed (1:8.9p1-3ubuntu0.10)'),
    F('web-01', 'sshd.LoginGraceTime', 120, 'agent', 0.1, sshNoteDefault),

    F('web-02', 'openssh.installed', true, 'agent', 0.1, 'dpkg: openssh-server 1:8.9p1-3ubuntu0.6'),
    F('web-02', 'openssh.version', '8.9p1', 'agent', 0.1, 'sshd -V'),
    F('web-02', 'openssh.distro_fix', false, 'agent', 0.1, '1:8.9p1-3ubuntu0.6 is older than fixed 1:8.9p1-3ubuntu0.10'),
    F('web-02', 'sshd.LoginGraceTime', 120, 'agent', 0.1, sshNoteDefault),

    F('bastion-01', 'openssh.installed', true, 'cmdb', 40, 'Software list: OpenSSH'),
    F('bastion-01', 'openssh.installed', true, 'scanner', 18, 'Port 22 banner'),
    F('bastion-01', 'openssh.version', '9.6p1', 'scanner', 18, 'Banner: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13'),
    F('bastion-01', 'openssh.version', '9.6p1', 'agent', 21, 'sshd -V (last agent check-in)'),
    F('bastion-01', 'net.internet_exposed', true, 'easm', 1, '22/tcp open on 185.12.44.10'),

    F('wms-app-01', 'openssh.installed', true, 'agent', 0.2, 'rpm: openssh-server-8.7p1-38.el9'),
    F('wms-app-01', 'openssh.version', '8.7p1', 'agent', 0.2, 'sshd -V'),
    F('wms-app-01', 'openssh.distro_fix', false, 'agent', 0.2, 'Vendor fix package not installed'),
    F('wms-app-01', 'sshd.LoginGraceTime', 120, 'agent', 2, sshNoteDefault + ': drift, config management reverted change?'),
    F('wms-app-01', 'sshd.LoginGraceTime', 0, 'human', 12, 'Pieter de Graaf: "Set to 0 on all WMS hosts during July change CHG-4471"', { by: 'pieter' }),

    F('edi-gw-01', 'openssh.installed', true, 'agent', 0.3, 'rpm: openssh-server-7.4p1-23.el7_9'),
    F('edi-gw-01', 'openssh.version', '7.4p1', 'agent', 0.3, 'sshd -V'),
    F('edi-gw-01', 'sshd.LoginGraceTime', 60, 'agent', 0.3, sshNoteDefault),

    F('ci-runner-01', 'openssh.installed', true, 'agent', 0.2, 'dpkg: openssh-server 1:9.2p1-2+deb12u3'),
    F('ci-runner-01', 'openssh.version', '9.2p1', 'agent', 0.2, 'sshd -V'),
    F('ci-runner-01', 'openssh.version', '9.2p1', 'scanner', 3, 'Scanner reports CVE-2024-6387 on version match'),
    F('ci-runner-01', 'openssh.distro_fix', true, 'agent', 0.2, 'DSA-5724-1 fix installed (1:9.2p1-2+deb12u3)'),
    F('ci-runner-01', 'sshd.LoginGraceTime', 120, 'agent', 0.2, sshNoteDefault),

    // --- Log4j
    F('portal-api', 'log4j.core_present', true, 'sbom', 2, 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1'),
    F('portal-api', 'log4j.core_version', '2.14.1', 'sbom', 2, 'Transitive via com.noordhaven:legacy-tracking-client:3.2'),
    F('portal-api', 'log4j.jndilookup_present', true, 'code', 1, 'JndiLookup.class present in built image layer'),
    F('portal-api', 'code.untrusted_input_logged', true, 'code', 1, 'HTTP parameter `ref` flows into log.info()', {
      snippet: { file: 'src/main/java/nl/noordhaven/portal/tracking/TrackingController.java', line: 88,
        code: '84  @GetMapping("/track")\n85  public TrackingView track(@RequestParam String ref) {\n86      var shipment = shipments.byReference(ref);\n87      if (shipment == null) {\n88          log.info("Unknown tracking reference {}", ref);   // <- attacker-controlled\n89          throw new NotFoundException();\n90      }' } }),
    F('wms-app-01', 'log4j.core_present', true, 'sbom', 6, 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1 (vendor bundle)'),
    F('wms-app-01', 'log4j.core_version', '2.14.1', 'sbom', 6, 'Vendor WMS 7.2 bundle'),
    F('wms-app-01', 'log4j.jndilookup_present', false, 'agent', 2, 'JndiLookup.class absent from /opt/wms/lib/log4j-core-2.14.1.jar (vendor hotfix WMS-2021-12)'),
    F('edi-gw-01', 'log4j.core_present', false, 'sbom', 4, 'Only log4j:log4j 1.2.17 found (Log4j 1.x, different CVEs)'),

    // --- NetScaler
    F('ns-gw-01', 'netscaler.present', true, 'adm', 1, 'Managed instance'),
    F('ns-gw-01', 'netscaler.version', '13.1-49.15', 'adm', 1, 'show ns version'),
    F('ns-gw-01', 'netscaler.version', '13.1-49.15', 'cmdb', 60, 'CMDB firmware field'),
    F('ns-gw-01', 'netscaler.gateway_vserver', true, 'adm', 1, 'vpn vserver vs_gateway_prod'),
    F('ns-gw-02', 'netscaler.present', true, 'adm', 3, 'Managed instance (DR)'),
    F('ns-gw-02', 'netscaler.version', '13.1-49.15', 'adm', 3, 'show ns version'),
    F('ns-gw-02', 'netscaler.version', '13.1-48.47', 'scanner', 4, 'Detected from HTTP ETag fingerprint'),
    F('ns-gw-02', 'netscaler.gateway_vserver', true, 'adm', 3, 'vpn vserver vs_gateway_dr'),

    // --- PAN-OS
    F('pa-fw-ams-01', 'panos.present', true, 'panorama', 0.5, 'PA-3220 managed device'),
    F('pa-fw-ams-01', 'panos.version', '11.1.2-h1', 'panorama', 0.5, 'show system info'),
    F('pa-fw-ams-01', 'panos.globalprotect', true, 'panorama', 0.5, 'GP portal gp.noordhaven.nl + gateway'),
    F('pa-fw-ams-01', 'panos.telemetry', false, 'panorama', 0.5, 'Device telemetry disabled'),
    F('pa-fw-ams-01', 'panos.tp95187_enforced', false, 'panorama', 0.5, 'Vulnerability profile not bound to GP zone'),
    F('pa-fw-rtm-01', 'panos.present', true, 'panorama', 0.5, 'PA-3220 managed device'),
    F('pa-fw-rtm-01', 'panos.version', '10.2.9-h1', 'panorama', 0.5, 'show system info'),
    F('pa-fw-rtm-01', 'panos.globalprotect', true, 'panorama', 0.5, 'GP gateway'),
    F('pa-fw-rtm-01', 'panos.telemetry', true, 'panorama', 0.5, 'Device telemetry enabled'),
    F('pa-fw-rtm-01', 'panos.tp95187_enforced', false, 'panorama', 0.5, 'Vulnerability profile not bound to GP zone'),

    // --- xz
    ...[['web-01', '5.2.5'], ['web-02', '5.2.5'], ['wms-app-01', '5.2.5'], ['edi-gw-01', '5.2.2'], ['ci-runner-01', '5.4.1']].flatMap(([a, v]) => [
      F(a, 'xz.present', true, 'agent', 0.2, 'package manager'),
      F(a, 'xz.version', v, 'agent', 0.2, 'xz --version'),
    ]),
    F('bastion-01', 'xz.present', true, 'scanner', 18, 'Local package enumeration'),
    F('bastion-01', 'xz.version', '5.4.5', 'scanner', 18, 'Local package enumeration'),

    // --- ESXi
    F('esx-01', 'esxi.present', true, 'vcenter', 0.1, 'Host in cluster PROD-A'),
    F('esx-01', 'esxi.build', '8.0.2-23305546', 'vcenter', 0.1, 'ESXi 8.0 U2 build 23305546'),
    F('esx-02', 'esxi.present', true, 'vcenter', 0.1, 'Host in cluster PROD-A'),
    F('esx-02', 'esxi.build', '8.0.3-24585383', 'vcenter', 0.1, 'ESXi 8.0 U3d build 24585383'),
  ];

  /* ------------------------------------------------------ simulated agent probes */
  const probes = {
    'bastion-01': [
      ['openssh.installed', true, 'dpkg: openssh-server 1:9.6p1-3ubuntu13'],
      ['openssh.version', '9.6p1', 'sshd -V'],
      ['openssh.distro_fix', false, '1:9.6p1-3ubuntu13 is older than fixed 1:9.6p1-3ubuntu13.3'],
      ['sshd.LoginGraceTime', 120, sshNoteDefault],
      ['os.libc', 'glibc', 'ldd (Ubuntu GLIBC 2.39)'],
      ['os.arch', 'x86_64', 'uname -m'],
      ['xz.present', true, 'package manager'],
      ['xz.version', '5.4.5', 'xz --version'],
    ],
    'wms-app-01': [['sshd.LoginGraceTime', 120, sshNoteDefault + ' (re-checked)']],
  };
  // Refresh everything else agents can see when "reconnect" is used.
  ['web-01', 'web-02', 'edi-gw-01', 'ci-runner-01'].forEach(a => { probes[a] = probes[a] || []; });

  /* Connectors that keep syncing when the demo clock advances, and known collection problems */
  const autoRefresh = ['agent', 'vcenter', 'panorama', 'adm', 'code', 'sbom', 'easm'];
  const connectorIssues = [
    { asset: 'bastion-01', source: 'agent', since: ago(21), note: 'Agent has not checked in since the host was rebuilt' },
    { asset: 'ns-gw-02', source: 'adm', since: null, trigger: 'clock', note: 'NetScaler ADM lost its connection to the DR appliance (expired nsroot password)' },
  ];

  /* ------------------------------------------------------------------- tasks */
  const tasks = [
    { id: 't1', advisory: 'CVE-2024-6387', asset: 'bastion-01', claim: 'c4', assignee: 'joris', by: 'eva', createdAt: ago(3), status: 'open',
      note: 'The agent on bastion-01 has not checked in for 3 weeks. Can you confirm the sshd setting?' },
    { id: 't2', advisory: 'CVE-2024-6387', asset: 'wms-app-01', claim: 'c4', assignee: 'pieter', by: 'eva', createdAt: ago(1), status: 'open',
      note: 'Your July attestation says LoginGraceTime is 0, but the agent saw 120 two days ago. Which is correct today?' },
  ];

  /* ----------------------------------------------------------------- history */
  const history = [
    { at: ago(26), kind: 'definition', advisory: 'CVE-2024-3400', text: 'Definition v1 approved (5 claims)', by: 'eva' },
    { at: ago(12), kind: 'outcome', advisory: 'CVE-2024-6387', asset: 'wms-app-01', from: 'affected', to: 'not_affected', reason: 'Owner attested LoginGraceTime 0 (mitigation present)' },
    { at: ago(6), kind: 'conflict', advisory: 'CVE-2023-4966', asset: 'ns-gw-02', text: 'Conflict detected: NetScaler ADM reports 13.1-49.15, Tenable reports 13.1-48.47. Resolved by source precedence.' },
    { at: ago(4), kind: 'outcome', advisory: 'CVE-2024-3094', asset: 'bastion-01', from: 'not_affected', to: 'insufficient', reason: 'xz version evidence (Tenable, 14-day limit) became stale; agent offline' },
    { at: ago(3), kind: 'outcome', advisory: 'CVE-2024-6387', asset: 'ci-runner-01', from: 'affected', to: 'not_affected', reason: 'Agent observed Debian fix 1:9.2p1-2+deb12u3. Scanner finding is a version-only match.' },
    { at: ago(2), kind: 'outcome', advisory: 'CVE-2024-6387', asset: 'wms-app-01', from: 'not_affected', to: 'affected', reason: 'Agent observed LoginGraceTime 120; conflicts with owner attestation, agent has precedence' },
    { at: ago(1), kind: 'outcome', advisory: 'CVE-2021-44228', asset: 'portal-api', from: 'insufficient', to: 'affected', reason: 'Code analysis found request parameter logged in TrackingController.java:88' },
  ];

  return { BASE, DAY, people, roles, sources, policy, services, assets, advisories, incomingAdvisory, facts, probes, tasks, history, autoRefresh, connectorIssues };
})();
