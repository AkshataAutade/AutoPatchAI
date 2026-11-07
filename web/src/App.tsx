import { useEffect, useMemo, useState } from 'react'
import {
  Activity, AlertTriangle, ArrowDown, ArrowUpRight, Bell, BookOpen,
  Check, CheckCircle2, ChevronDown, CircleHelp, Clock3, Code2,
  Command, FileCode2, Filter, GitBranch, GitPullRequest, History,
  Layers3, LockKeyhole, Play, RefreshCw, Search, Settings2, Shield,
  ShieldAlert, ShieldCheck, Sparkles, X,
} from 'lucide-react'
import './App.css'

type Finding = {
  id: string
  title: string
  file: string
  line: number
  severity: 'Critical' | 'High' | 'Medium' | 'Low'
  category: string
  confidence: number
  description: string
  codeBefore: string
  codeAfter: string
  recommendation: string
  status: 'open' | 'fixed' | 'dismissed'
}

const initialFindings: Finding[] = [
  {
    id: 'AI-142', title: 'SQL injection in user lookup', file: 'src/api/users.ts', line: 48,
    severity: 'Critical', category: 'Injection', confidence: 98,
    description: 'User-controlled input is concatenated into a SQL query. An attacker may alter the query structure and access or modify records outside the intended account.',
    codeBefore: 'const query = `SELECT * FROM users WHERE id = ${req.params.id}`',
    codeAfter: 'const query = "SELECT * FROM users WHERE id = ?"\ndb.query(query, [req.params.id])',
    recommendation: 'Use a parameterized query so input is passed as data rather than executable SQL.', status: 'open',
  },
  {
    id: 'AI-139', title: 'Hardcoded cloud access key', file: 'src/config/storage.ts', line: 12,
    severity: 'Critical', category: 'Secrets', confidence: 100,
    description: 'A credential-like value is embedded in source code. If valid, it can be exposed through repository access, build artifacts, or logs.',
    codeBefore: 'accessKey: "AKIA••••••••••••••••"',
    codeAfter: 'accessKey: process.env.STORAGE_ACCESS_KEY',
    recommendation: 'Rotate the exposed credential and load its replacement from a managed secret store or environment configuration.', status: 'open',
  },
  {
    id: 'AI-136', title: 'Cross-site scripting in profile page', file: 'src/pages/profile.tsx', line: 86,
    severity: 'High', category: 'XSS', confidence: 94,
    description: 'Profile content reaches an HTML rendering sink without an evident sanitization step. Untrusted markup could execute in another user’s browser.',
    codeBefore: '<div dangerouslySetInnerHTML={{ __html: profile.bio }} />',
    codeAfter: '<p>{profile.bio}</p>',
    recommendation: 'Prefer framework-escaped text rendering. If rich HTML is a requirement, sanitize it with a maintained allowlist sanitizer.', status: 'open',
  },
  {
    id: 'AI-131', title: 'Missing authorization on export route', file: 'src/api/export.ts', line: 24,
    severity: 'High', category: 'Access control', confidence: 89,
    description: 'The route returns account export data without a visible ownership check. Confirm authorization is not enforced by upstream middleware.',
    codeBefore: 'app.get("/export/:userId", async (req, res) => {\n  return res.json(await exportUser(req.params.userId))\n})',
    codeAfter: 'app.get("/export/:userId", requireAuth, async (req, res) => {\n  assertOwnsAccount(req.user, req.params.userId)\n  return res.json(await exportUser(req.params.userId))\n})',
    recommendation: 'Require authentication and verify the requester is authorized to export the requested account.', status: 'open',
  },
  {
    id: 'AI-127', title: 'Outdated cryptographic hash', file: 'src/auth/password.ts', line: 31,
    severity: 'Medium', category: 'Cryptography', confidence: 97,
    description: 'MD5 is used to derive a password-related value. It is not suitable for password storage or security-sensitive hashing.',
    codeBefore: 'return createHash("md5").update(password).digest("hex")',
    codeAfter: 'return await argon2.hash(password)',
    recommendation: 'Use a password hashing function designed for this purpose, such as Argon2id, with parameters appropriate to your environment.', status: 'open',
  },
]

const severityOrder = ['Critical', 'High', 'Medium', 'Low']

function App() {
  const [findings, setFindings] = useState(initialFindings)
  const [selectedId, setSelectedId] = useState('AI-142')
  const [query, setQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState('All severities')
  const [showOpenOnly, setShowOpenOnly] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [scanComplete, setScanComplete] = useState(false)
  const [notice, setNotice] = useState('')
  const [activeNav, setActiveNav] = useState('Overview')
  const [mobilePanel, setMobilePanel] = useState<'findings' | 'details'>('findings')

  useEffect(() => {
    if (!notice) return
    const timeout = window.setTimeout(() => setNotice(''), 3600)
    return () => window.clearTimeout(timeout)
  }, [notice])

  const filteredFindings = useMemo(() => findings.filter((finding) => {
    const matchesText = `${finding.id} ${finding.title} ${finding.file} ${finding.category}`.toLowerCase().includes(query.toLowerCase())
    const matchesSeverity = severityFilter === 'All severities' || finding.severity === severityFilter
    const matchesStatus = !showOpenOnly || finding.status === 'open'
    return matchesText && matchesSeverity && matchesStatus
  }), [findings, query, severityFilter, showOpenOnly])

  const selectedFinding = findings.find((finding) => finding.id === selectedId) ?? filteredFindings[0]
  const openCount = findings.filter((finding) => finding.status === 'open').length
  const criticalCount = findings.filter((finding) => finding.severity === 'Critical' && finding.status === 'open').length

  function updateStatus(status: Finding['status']) {
    if (!selectedFinding) return
    setFindings((current) => current.map((finding) => finding.id === selectedFinding.id ? { ...finding, status } : finding))
    setNotice(status === 'fixed' ? 'Fix approved. Validation is ready to run.' : 'Finding dismissed from the active queue.')
  }

  function startScan() {
    if (scanning) return
    setScanning(true)
    setScanComplete(false)
    window.setTimeout(() => {
      setScanning(false)
      setScanComplete(true)
      setNotice('Sample scan complete. Findings are demonstration data.')
    }, 1700)
  }

  const navItems = [
    { label: 'Overview', icon: Layers3 },
    { label: 'Findings', icon: ShieldAlert, count: openCount },
    { label: 'Pull requests', icon: GitPullRequest },
    { label: 'Activity', icon: History },
  ]

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#overview" aria-label="Aegis home">
          <span className="brand-mark"><Shield size={19} strokeWidth={2.2} /></span>
          <span>aegis<span className="brand-period">.</span></span>
          <span className="brand-tag">SECURITY</span>
        </a>

        <button className="workspace-select" type="button">
          <span className="workspace-avatar">N</span>
          <span className="workspace-copy"><strong>Northstar Labs</strong><small>Personal workspace</small></span>
          <ChevronDown size={15} />
        </button>

        <div className="side-label">WORKSPACE</div>
        <nav className="primary-nav" aria-label="Main navigation">
          {navItems.map(({ label, icon: Icon, count }) => (
            <button key={label} type="button" className={`nav-item ${activeNav === label ? 'active' : ''}`} onClick={() => { setActiveNav(label); if (label === 'Findings') setMobilePanel('findings') }}>
              <Icon size={17} strokeWidth={1.8} /><span>{label}</span>
              {count !== undefined && <span className="nav-count">{count}</span>}
            </button>
          ))}
        </nav>

        <div className="side-label repositories-label">REPOSITORIES <button type="button" title="Add repository" onClick={() => setNotice('Repository connection will be added in the next build.')}><span>+</span></button></div>
        <button type="button" className="repo-item selected"><span className="repo-icon"><Code2 size={14} /></span><span>api-platform</span><span className="repo-branch">main</span></button>
        <button type="button" className="repo-item" onClick={() => setNotice('Connect a repository to scan its source code.')}><span className="repo-icon"><Code2 size={14} /></span><span>web-client</span></button>
        <button type="button" className="repo-item" onClick={() => setNotice('Connect a repository to scan its source code.')}><span className="repo-icon"><Code2 size={14} /></span><span>infra-config</span></button>

        <div className="sidebar-spacer" />
        <div className="side-status"><span className="status-dot" /> All systems operational</div>
        <button type="button" className="nav-item bottom-nav" onClick={() => setNotice('Workspace settings are coming soon.')}><Settings2 size={17} /><span>Settings</span></button>
        <button type="button" className="user-profile" onClick={() => setNotice('Signed in as Alex Morgan')}>
          <span className="user-avatar">AM</span><span className="workspace-copy"><strong>Alex Morgan</strong><small>Security engineer</small></span><ChevronDown size={15} />
        </button>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="breadcrumb"><span>Repositories</span><span className="crumb-slash">/</span><strong>api-platform</strong><span className="branch-pill"><GitBranch size={12} /> main</span></div>
          <div className="topbar-actions"><span className="scan-label"><span className="status-dot" /> Protected</span><button className="icon-button" type="button" aria-label="Notifications" onClick={() => setNotice('You are all caught up.')}><Bell size={17} /></button><button className="icon-button help-button" type="button" aria-label="Help" onClick={() => setNotice('Select a finding to review evidence and a proposed fix.')}><CircleHelp size={17} /></button></div>
        </header>

        <div className="page-content">
          <div className="page-heading">
            <div><div className="eyebrow">REPOSITORY SECURITY</div><h1>Overview</h1><p className="heading-subtitle">Your security posture, at a glance.</p></div>
            <div className="heading-actions"><button type="button" className="secondary-button" onClick={() => setNotice('Report export will be available after connecting a scanner.')}><ArrowDown size={15} /> Export report</button><button type="button" className="primary-button" onClick={startScan} disabled={scanning}>{scanning ? <RefreshCw className="spin" size={15} /> : scanComplete ? <Check size={15} /> : <Play size={14} fill="currentColor" />}{scanning ? 'Scanning…' : scanComplete ? 'Scan again' : 'Run scan'}</button></div>
          </div>

          <div className="demo-banner"><Sparkles size={15} /><span><strong>Interactive preview</strong> Findings below are sample data. Connect a repository and analyzer to scan real code.</span><button type="button" aria-label="Dismiss preview notice" onClick={(event) => event.currentTarget.parentElement?.remove()}><X size={15} /></button></div>

          <section className="metrics-grid" aria-label="Security metrics">
            <article className="metric-card posture-card"><div className="metric-top"><span>SECURITY SCORE</span><span className="score-trend"><ArrowUpRight size={13} /> +8 this week</span></div><div className="score-row"><div className="score-value">72<span>/100</span></div><div className="score-ring"><span>72</span></div></div><div className="score-track"><span /></div><div className="metric-foot">Good progress <span>·</span> room to improve</div></article>
            <article className="metric-card"><div className="metric-top"><span>OPEN FINDINGS</span><ShieldAlert size={16} className="metric-icon orange" /></div><div className="metric-value">{openCount}<span className="metric-delta">{openCount === 5 ? '+2' : 'updated'}</span></div><div className="metric-foot">Across <strong>3 categories</strong></div></article>
            <article className="metric-card"><div className="metric-top"><span>CRITICAL RISK</span><AlertTriangle size={16} className="metric-icon red" /></div><div className="metric-value">{criticalCount}<span className="metric-word">findings</span></div><div className="metric-foot">Requires immediate attention</div></article>
            <article className="metric-card"><div className="metric-top"><span>LAST SCAN</span><Clock3 size={16} className="metric-icon teal" /></div><div className="metric-value scan-time">{scanComplete ? 'Just now' : '18 min'}<span className="metric-word">ago</span></div><div className="metric-foot">{scanComplete ? 'Preview scan completed' : 'Today at 10:42 AM'} <span className="scan-success"><CheckCircle2 size={13} /> Completed</span></div></article>
          </section>

          <section className="scan-summary"><div className="summary-icon"><Activity size={17} /></div><div className="summary-copy"><strong>{scanning ? 'Analysis in progress' : 'Repository analysis'}</strong><span>{scanning ? 'Checking source patterns and dependency metadata…' : '5 checks completed · 2 min 14 sec'}</span></div><div className="check-list"><span><Check size={13} /> Code patterns</span><span><Check size={13} /> Dependencies</span><span><Check size={13} /> Secrets</span></div><button type="button" className="summary-link" onClick={() => setNotice('Scan history will appear here as real scans are connected.')}>Details <ArrowUpRight size={13} /></button></section>

          <section className="findings-section">
            <div className="section-heading"><div><div className="title-with-count"><h2>Findings</h2><span className="total-pill">{filteredFindings.length}</span></div><p>Prioritized by severity and confidence</p></div><div className="findings-tools"><label className="search-box"><Search size={15} /><input aria-label="Search findings" placeholder="Search findings..." value={query} onChange={(event) => setQuery(event.target.value)} /><kbd><Command size={10} /> K</kbd></label><label className="select-wrap"><Filter size={14} /><select aria-label="Filter by severity" value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}><option>All severities</option>{severityOrder.map((severity) => <option key={severity}>{severity}</option>)}</select><ChevronDown size={13} /></label><button type="button" className={`filter-toggle ${showOpenOnly ? 'filter-on' : ''}`} title="Show open findings only" onClick={() => setShowOpenOnly(!showOpenOnly)}><span className="toggle-track"><span /></span><span>Open only</span></button></div></div>

            <div className={`workbench ${mobilePanel}`}>
              <div className="finding-list" role="list" aria-label="Security findings">
                {filteredFindings.length === 0 ? <div className="empty-state"><ShieldCheck size={24} /><strong>No findings match</strong><span>Try adjusting your search or filters.</span></div> : filteredFindings.map((finding) => (
                  <button type="button" role="listitem" key={finding.id} className={`finding-row ${selectedFinding?.id === finding.id ? 'selected' : ''}`} onClick={() => { setSelectedId(finding.id); setMobilePanel('details') }}>
                    <span className={`severity-marker ${finding.severity.toLowerCase()}`} />
                    <span className="finding-row-content"><span className="finding-title-line"><strong>{finding.title}</strong>{finding.status === 'fixed' && <span className="fixed-tag"><Check size={10} /> Fixed</span>}{finding.status === 'dismissed' && <span className="dismissed-tag">Dismissed</span>}</span><span className="finding-meta"><span className={`severity-text ${finding.severity.toLowerCase()}`}>{finding.severity}</span><span className="meta-dot">·</span><span>{finding.file.split('/').pop()}:{finding.line}</span></span></span>
                    <span className="finding-confidence"><strong>{finding.confidence}%</strong><small>confidence</small></span>
                  </button>
                ))}
                <div className="list-footer"><span>Showing {filteredFindings.length} of {findings.length} findings</span><button type="button" onClick={() => setShowOpenOnly(false)}>View all <ArrowUpRight size={12} /></button></div>
              </div>

              {selectedFinding ? <article className="finding-detail">
                <div className="detail-header"><div className="detail-id"><span className={`severity-marker ${selectedFinding.severity.toLowerCase()}`} />{selectedFinding.id}<span className="detail-divider">/</span><span className="detail-category">{selectedFinding.category}</span></div><button type="button" className="icon-button detail-close" aria-label="Show findings list" onClick={() => setMobilePanel('findings')}><X size={16} /></button><span className="detail-confidence"><Sparkles size={13} /> {selectedFinding.confidence}% confidence</span></div>
                <h3>{selectedFinding.title}</h3>
                <p className="detail-description">{selectedFinding.description}</p>
                <button className="file-location" type="button" onClick={() => setNotice('Source viewer will be connected with repository access.')}><FileCode2 size={14} /><span>{selectedFinding.file}</span><span className="line-number">:{selectedFinding.line}</span><ArrowUpRight size={12} /></button>

                <div className="detail-subhead"><span>PROPOSED REMEDIATION</span><span className="ai-assisted"><Sparkles size={11} /> AI assisted</span></div>
                <p className="recommendation">{selectedFinding.recommendation}</p>
                <div className="code-diff"><div className="code-toolbar"><span><Code2 size={12} /> Suggested change</span><span className="diff-lines">1 addition · 1 removal</span></div><div className="code-line removed"><span>−</span><code>{selectedFinding.codeBefore}</code></div><div className="code-line added"><span>+</span><code>{selectedFinding.codeAfter}</code></div></div>

                <div className="validation-note"><LockKeyhole size={14} /><span><strong>Review before applying</strong> · Changes require your approval. Tests will run after approval.</span></div>
                <div className="detail-actions">{selectedFinding.status === 'open' ? <><button type="button" className="approve-button" onClick={() => updateStatus('fixed')}><Check size={15} /> Approve fix</button><button type="button" className="reject-button" onClick={() => updateStatus('dismissed')}><X size={15} /> Dismiss</button></> : <button type="button" className="reopen-button" onClick={() => updateStatus('open')}><RefreshCw size={14} /> Reopen finding</button>}<button type="button" className="learn-button" onClick={() => setNotice('Guidance links will be attached to analyzer findings.')}><BookOpen size={14} /> Guidance</button></div>
              </article> : <article className="finding-detail empty-detail"><ShieldCheck size={28} /><strong>Select a finding to inspect</strong><span>Evidence and suggested remediations appear here.</span></article>}
            </div>
          </section>

          <footer className="page-footer"><span><ShieldCheck size={14} /> Aegis Security</span><span>Sample workspace <span className="footer-separator">·</span> No code is being scanned or uploaded</span><button type="button" onClick={() => setNotice('Built for evidence-first, human-reviewed remediation.')}><CircleHelp size={13} /> About this preview</button></footer>
        </div>
      </main>
      {notice && <div className="toast" role="status"><CheckCircle2 size={16} />{notice}<button type="button" aria-label="Dismiss notification" onClick={() => setNotice('')}><X size={14} /></button></div>}
    </div>
  )
}

export default App
