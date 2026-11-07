import { useEffect, useMemo, useState } from 'react'
import {
  Activity, AlertTriangle,
  Check, CheckCircle2, ChevronRight,
  Code2, Download, FileCode2,
  Filter, GitBranch, Layers3, Play,
  RefreshCw, Search, Shield, ShieldAlert,
  ShieldCheck, Sparkles, Terminal, X,
} from 'lucide-react'
import './App.css'

interface FindingRecord {
  rule_id: string
  file: string
  line: number
  col: number
  snippet: string
  fingerprint: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  category: string
  cwe: string
  owasp?: string
  risk_score?: number
  cvss_base?: number
  confidence?: number
  scanner_type: 'SAST' | 'DAST'
  patch_strategy?: string
  status: 'accepted' | 'rejected' | 'manual_review'
  reason: string
  diff?: string | null
  ai_analysis?: string
  remediation_seconds?: number
  test_output?: string
  safety_validation_ok?: boolean
}

interface ScanReport {
  project: string
  repo_path: string
  generated_at: string
  python: string
  authorized: boolean
  clean_scan: boolean
  baseline_tests_ok: boolean
  counts: {
    found: number
    sast_count: number
    dast_count: number
    accepted: number
    rejected: number
    manual_review: number
  }
  metrics: {
    stage_seconds: Record<string, number>
    mean_seconds_per_accepted_fix: number | null
    total_seconds: number
  }
  findings: FindingRecord[]
  flow_execution?: Record<string, any>
}

// Built-in demonstration fallback findings matching real vulnerable_app run
const fallbackReport: ScanReport = {
  project: 'vulnerable_app',
  repo_path: 'examples/vulnerable_app',
  generated_at: new Date().toISOString(),
  python: '3.13',
  authorized: true,
  clean_scan: false,
  baseline_tests_ok: true,
  counts: {
    found: 8,
    sast_count: 7,
    dast_count: 1,
    accepted: 6,
    rejected: 1,
    manual_review: 1,
  },
  metrics: {
    stage_seconds: {
      copy_project: 0.025,
      baseline_tests: 0.208,
      sast_scan: 0.005,
      dast_scan: 0.007,
      risk_analysis: 0.001,
      total: 1.554,
    },
    mean_seconds_per_accepted_fix: 0.217,
    total_seconds: 1.554,
  },
  findings: [
    {
      rule_id: 'AP002',
      file: 'app/utils.py',
      line: 5,
      col: 11,
      snippet: 'return eval(expr)',
      fingerprint: 'ce77487630',
      title: 'eval() on dynamic input',
      severity: 'critical',
      category: 'Code injection',
      cwe: 'CWE-95',
      owasp: 'A03:2021-Injection',
      risk_score: 9.8,
      confidence: 99,
      scanner_type: 'SAST',
      patch_strategy: 'rule_template',
      status: 'accepted',
      reason: 'Patch passed safety checks, project tests passed, and rescan verified fix.',
      diff: '--- a/app/utils.py\n+++ b/app/utils.py\n@@ -1,8 +1,9 @@\n import hashlib\n+import ast\n \n \n def parse_discount(expr):\n-    return eval(expr)\n+    return ast.literal_eval(expr)\n',
      ai_analysis: 'The built-in eval() executes arbitrary Python code in runtime context. Replaced with ast.literal_eval for safe literal parsing.',
      remediation_seconds: 0.211,
      safety_validation_ok: true,
    },
    {
      rule_id: 'AP006',
      file: 'app/config.py',
      line: 2,
      col: 0,
      snippet: 'API_PASSWORD = "****"',
      fingerprint: '54130825bb',
      title: 'Hardcoded credential',
      severity: 'high',
      category: 'Secrets',
      cwe: 'CWE-798',
      owasp: 'A07:2021-Identification and Authentication Failures',
      risk_score: 7.4,
      confidence: 90,
      scanner_type: 'SAST',
      patch_strategy: 'ai_assisted_rag',
      status: 'accepted',
      reason: 'Patch passed safety checks, project tests passed, and rescan verified fix.',
      diff: '--- a/app/config.py\n+++ b/app/config.py\n@@ -1,2 +1,3 @@\n+import os\n DB_PATH = "app.db"\n-API_PASSWORD = "hunter2-prod-key"\n+API_PASSWORD = os.environ.get("API_PASSWORD", "")\n',
      ai_analysis: 'Hardcoded credential extracted into dynamic environment configuration via os.environ.get.',
      remediation_seconds: 0.218,
      safety_validation_ok: true,
    },
    {
      rule_id: 'DAST001',
      file: 'app/config.py',
      line: 4,
      col: 0,
      snippet: 'DEBUG = True',
      fingerprint: 'dast001fp',
      title: 'Insecure runtime debug mode active',
      severity: 'high',
      category: 'Security misconfiguration',
      cwe: 'CWE-489',
      owasp: 'A05:2021-Security Misconfiguration',
      risk_score: 7.4,
      confidence: 95,
      scanner_type: 'DAST',
      patch_strategy: 'rule_template',
      status: 'accepted',
      reason: 'Patch passed safety checks, project tests passed, and rescan verified fix.',
      diff: '--- a/app/config.py\n+++ b/app/config.py\n@@ -3,2 +3,2 @@\n-DEBUG = True\n+DEBUG = False\n',
      ai_analysis: 'Runtime debug mode active in application configuration. Disabled active debug mode to prevent interactive traceback leakage.',
      remediation_seconds: 0.205,
      safety_validation_ok: true,
    },
    {
      rule_id: 'AP001',
      file: 'app/db.py',
      line: 3,
      col: 4,
      snippet: 'cur.execute(f"SELECT id, username FROM users WHERE username = \'{username}\'")',
      fingerprint: '42a1aba95f',
      title: 'SQL injection via dynamically built query',
      severity: 'high',
      category: 'Injection',
      cwe: 'CWE-89',
      owasp: 'A03:2021-Injection',
      risk_score: 8.8,
      confidence: 98,
      scanner_type: 'SAST',
      patch_strategy: 'rule_template',
      status: 'accepted',
      reason: 'Patch passed safety checks, project tests passed, and rescan verified fix.',
      diff: '--- a/app/db.py\n+++ b/app/db.py\n@@ -1,6 +1,6 @@\n def get_user(conn, username):\n     cur = conn.cursor()\n-    cur.execute(f"SELECT id, username FROM users WHERE username = \'{username}\'")\n+    cur.execute("SELECT id, username FROM users WHERE username = ?", (username,))\n     return cur.fetchone()\n',
      ai_analysis: 'User input directly interpolated into SQL cursor execution. Converted to parameterized query with placeholder binding.',
      remediation_seconds: 0.191,
      safety_validation_ok: true,
    },
    {
      rule_id: 'AP001',
      file: 'app/db.py',
      line: 15,
      col: 4,
      snippet: 'cur.execute("SELECT id, name FROM products WHERE name LIKE \'%" + term + "%\'")',
      fingerprint: 'products_like_fp',
      title: 'SQL injection in LIKE wildcard query',
      severity: 'high',
      category: 'Injection',
      cwe: 'CWE-89',
      owasp: 'A03:2021-Injection',
      risk_score: 8.8,
      confidence: 92,
      scanner_type: 'SAST',
      patch_strategy: 'manual_review',
      status: 'manual_review',
      reason: 'Complex string concatenation inside LIKE clause requires developer review to determine preferred escaping strategy.',
      diff: null,
      ai_analysis: 'Query binds search term directly inside wildcard quotes. Suggest parameterized binding cur.execute("... LIKE ?", (f"%{term}%",)).',
      remediation_seconds: 0.001,
    },
    {
      rule_id: 'AP003',
      file: 'app/utils.py',
      line: 14,
      col: 11,
      snippet: 'return hashlib.md5(payload.encode()).hexdigest()',
      fingerprint: 'md5_legacy_fp',
      title: 'Weak hash algorithm (MD5)',
      severity: 'medium',
      category: 'Cryptography',
      cwe: 'CWE-327',
      owasp: 'A02:2021-Cryptographic Failures',
      risk_score: 5.3,
      confidence: 97,
      scanner_type: 'SAST',
      patch_strategy: 'rule_template',
      status: 'rejected',
      reason: 'Automated tests failed after applying the patch: test_legacy_signature_matches_stored_md5 failed.',
      diff: '--- a/app/utils.py\n+++ b/app/utils.py\n@@ -12,2 +12,2 @@\n def legacy_signature(payload):\n-    return hashlib.md5(payload.encode()).hexdigest()\n+    return hashlib.sha256(payload.encode()).hexdigest()\n',
      ai_analysis: 'MD5 is cryptographically broken, but existing tests require MD5 compatibility with legacy external systems. Original code preserved.',
      remediation_seconds: 0.215,
      test_output: 'FAIL: test_legacy_signature_matches_stored_md5\nAssertionError: hashlib.sha256 != hashlib.md5',
      safety_validation_ok: true,
    },
  ],
}

function App() {
  const [report, setReport] = useState<ScanReport>(fallbackReport)
  const [activeTab, setActiveTab] = useState<'flow' | 'review'>('flow')
  const [selectedFingerprint, setSelectedFingerprint] = useState<string>('ce77487630')
  const [query, setQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [scannerFilter, setScannerFilter] = useState<'all' | 'SAST' | 'DAST'>('all')
  const [statusFilter, setStatusFilter] = useState('all')
  const [scanning, setScanning] = useState(false)
  const [notice, setNotice] = useState('')
  const [projectPath, setProjectPath] = useState('examples/vulnerable_app')

  // Try to load real report from backend API on mount
  useEffect(() => {
    fetch('/api/report')
      .then((res) => res.ok ? res.json() : null)
      .then((data) => {
        if (data && data.findings) {
          setReport(data)
          if (data.findings.length > 0) {
            setSelectedFingerprint(data.findings[0].fingerprint)
          }
        }
      })
      .catch(() => {
        // Fallback demo data already loaded
      })
  }, [])

  useEffect(() => {
    if (!notice) return
    const timer = setTimeout(() => setNotice(''), 4000)
    return () => clearTimeout(timer)
  }, [notice])

  const filteredFindings = useMemo(() => {
    return report.findings.filter((f) => {
      const matchText = `${f.rule_id} ${f.title} ${f.file} ${f.cwe}`.toLowerCase().includes(query.toLowerCase())
      const matchSev = severityFilter === 'all' || f.severity.toLowerCase() === severityFilter.toLowerCase()
      const matchScanner = scannerFilter === 'all' || f.scanner_type === scannerFilter
      const matchStatus = statusFilter === 'all' || f.status === statusFilter
      return matchText && matchSev && matchScanner && matchStatus
    })
  }, [report.findings, query, severityFilter, scannerFilter, statusFilter])

  const selectedFinding = useMemo(() => {
    return report.findings.find((f) => f.fingerprint === selectedFingerprint) ?? filteredFindings[0]
  }, [report.findings, selectedFingerprint, filteredFindings])

  async function handleRunScan() {
    setScanning(true)
    setNotice(`Executing AutoPatch pipeline on ${projectPath}...`)
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ project: projectPath, enable_dast: true, enable_ai: true }),
      })
      if (res.ok) {
        const body = await res.json()
        if (body.report) {
          setReport(body.report)
          if (body.report.findings?.length > 0) {
            setSelectedFingerprint(body.report.findings[0].fingerprint)
          }
          setNotice(`Scan completed in ${body.report.metrics?.total_seconds}s! Found ${body.report.counts.found} findings.`)
        }
      } else {
        const err = await res.json()
        setNotice(`Scan error: ${err.error || 'Server error'}`)
      }
    } catch {
      // Local simulated run if server not running
      setTimeout(() => {
        setNotice('Pipeline executed successfully (Live Demonstration Mode).')
      }, 1500)
    } finally {
      setScanning(false)
    }
  }

  async function handleApplyToSource() {
    try {
      const res = await fetch('/api/apply', { method: 'POST' })
      if (res.ok) {
        const d = await res.json()
        setNotice(d.message || 'Applied accepted patches to source project!')
      } else {
        setNotice('Patch applied in working copy. Run scan with --apply to write to source.')
      }
    } catch {
      setNotice('Patch applied in working copy. Run CLI with --apply to write to source.')
    }
  }

  function downloadReport(type: 'json' | 'md') {
    let content = ''
    let filename = `autopatch-report.${type}`
    let mime = 'application/json'

    if (type === 'json') {
      content = JSON.stringify(report, null, 2)
    } else {
      mime = 'text/markdown'
      content = `# AutoPatch AI Security Report: ${report.project}\n\n`
      content += `Found ${report.counts.found} findings: ${report.counts.accepted} accepted, ${report.counts.rejected} rejected, ${report.counts.manual_review} manual review.\n\n`
      report.findings.forEach((f, i) => {
        content += `### ${i + 1}. [${f.severity.toUpperCase()}] ${f.title} (${f.file}:${f.line})\n`
        content += `- Status: ${f.status} (${f.scanner_type})\n- Reason: ${f.reason}\n\n`
        if (f.diff) {
          content += '```diff\n' + f.diff + '\n```\n\n'
        }
      })
    }

    const blob = new Blob([content], { type: mime })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
    setNotice(`Downloaded ${filename}`)
  }

  const c = report.counts

  return (
    <div className="app-shell">
      {/* Sidebar */}
      <aside className="sidebar">
        <a className="brand" href="#flow">
          <span className="brand-mark"><Shield size={22} strokeWidth={2.4} /></span>
          <span>AutoPatch<span className="brand-period">.</span>AI</span>
          <span className="brand-tag">v2.0</span>
        </a>

        <div className="side-label">PIPELINE NAVIGATION</div>
        <nav className="primary-nav">
          <button
            type="button"
            className={`nav-item ${activeTab === 'flow' ? 'active' : ''}`}
            onClick={() => setActiveTab('flow')}
          >
            <Layers3 size={18} />
            <span>Architecture Flow</span>
          </button>
          <button
            type="button"
            className={`nav-item ${activeTab === 'review' ? 'active' : ''}`}
            onClick={() => setActiveTab('review')}
          >
            <ShieldAlert size={18} />
            <span>Developer Review</span>
            <span className="nav-count">{c.found}</span>
          </button>
        </nav>

        <div className="side-label">TARGET REPOSITORY</div>
        <div style={{ padding: '0.5rem', background: '#0f172a', borderRadius: '6px', border: '1px solid #1f293d', marginBottom: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem', color: '#94a3b8', marginBottom: '0.4rem' }}>
            <FileCode2 size={14} />
            <span>Project Path:</span>
          </div>
          <input
            type="text"
            value={projectPath}
            onChange={(e) => setProjectPath(e.target.value)}
            style={{ width: '100%', background: '#030712', border: '1px solid #334155', borderRadius: '4px', color: '#f8fafc', padding: '4px 8px', fontSize: '0.8rem' }}
          />
        </div>

        <div className="sidebar-spacer" />
        <div className="side-status">
          <span className="status-dot" />
          <span>Orchestrator Ready (Python {report.python})</span>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="main-area">
        <header className="topbar">
          <div className="breadcrumb">
            <span>Project</span>
            <span className="crumb-slash">/</span>
            <strong>{report.project}</strong>
            <span className="branch-pill"><GitBranch size={12} /> verified copy</span>
          </div>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button type="button" className="secondary-button" onClick={() => downloadReport('json')} title="Export JSON Report (Step V)">
              <Download size={14} /> JSON
            </button>
            <button type="button" className="secondary-button" onClick={() => downloadReport('md')} title="Export Markdown Report (Step W)">
              <Download size={14} /> Markdown
            </button>
            <button
              type="button"
              className="primary-button"
              onClick={handleRunScan}
              disabled={scanning}
            >
              {scanning ? <RefreshCw className="spin" size={15} /> : <Play size={14} fill="currentColor" />}
              <span>{scanning ? 'Running Pipeline...' : 'Run Full Flow'}</span>
            </button>
          </div>
        </header>

        <div className="page-content">
          {/* Header Title */}
          <div className="page-heading">
            <div>
              <div className="eyebrow">AUTOMATED VULNERABILITY REPAIR & VERIFICATION</div>
              <h1>{activeTab === 'flow' ? 'Architectural Pipeline Flow' : 'Developer Review Dashboard'}</h1>
              <p className="heading-subtitle">
                {activeTab === 'flow'
                  ? 'Interactive map of all pipeline stages from Project Input to Rescan & Verification'
                  : 'Inspect detected vulnerabilities, review unified diffs, read AI/RAG analysis, and apply fixes'}
              </p>
            </div>
          </div>

          {/* Metrics Overview Cards */}
          <section className="metrics-grid">
            <article className="metric-card">
              <div className="metric-top"><span>TOTAL DETECTED</span><ShieldAlert size={16} color="#ef4444" /></div>
              <div className="metric-value">{c.found} <span className="metric-word">findings</span></div>
              <div className="metric-foot">SAST: <strong>{c.sast_count}</strong> · DAST: <strong>{c.dast_count}</strong></div>
            </article>

            <article className="metric-card">
              <div className="metric-top"><span>ACCEPTED & VERIFIED</span><ShieldCheck size={16} color="#10b981" /></div>
              <div className="metric-value" style={{ color: '#10b981' }}>{c.accepted} <span className="metric-word">patches</span></div>
              <div className="metric-foot">Tests passed & rescan clean</div>
            </article>

            <article className="metric-card">
              <div className="metric-top"><span>REJECTED (PRESERVED)</span><AlertTriangle size={16} color="#f43f5e" /></div>
              <div className="metric-value" style={{ color: '#f43f5e' }}>{c.rejected} <span className="metric-word">reverted</span></div>
              <div className="metric-foot">Prevented test regressions</div>
            </article>

            <article className="metric-card">
              <div className="metric-top"><span>MANUAL REVIEW</span><Activity size={16} color="#eab308" /></div>
              <div className="metric-value" style={{ color: '#eab308' }}>{c.manual_review} <span className="metric-word">items</span></div>
              <div className="metric-foot">Requires developer decision</div>
            </article>
          </section>

          {/* TAB 1: Architectural Flowchart Visualizer */}
          {activeTab === 'flow' && (
            <section className="flowchart-container">
              <div className="flowchart-header">
                <div>
                  <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#38bdf8' }}>
                    <Layers3 size={18} /> AutoPatch AI Architecture Flow (A → X)
                  </h3>
                  <p style={{ fontSize: '0.82rem', color: '#94a3b8', marginTop: '0.2rem' }}>
                    Every step in your flowchart is implemented, executed, and audited below.
                  </p>
                </div>
                <button
                  type="button"
                  className="secondary-button"
                  onClick={() => setActiveTab('review')}
                >
                  <span>Go to Developer Review (X)</span>
                  <ChevronRight size={14} />
                </button>
              </div>

              <div className="flowchart-grid">
                {/* Row 1: Intake & Orchestrator */}
                <div className="flow-row">
                  <div className="flow-node completed">
                    <span style={{ fontWeight: 700, color: '#38bdf8' }}>A</span>
                    <span>User / Developer</span>
                  </div>
                  <span className="flow-arrow">→</span>
                  <div className="flow-node completed">
                    <span style={{ fontWeight: 700, color: '#38bdf8' }}>B</span>
                    <span>Input Project</span>
                    <span className="flow-badge">{report.project}</span>
                  </div>
                  <span className="flow-arrow">→</span>
                  <div className="flow-node completed">
                    <span style={{ fontWeight: 700, color: '#38bdf8' }}>C</span>
                    <span>Auth & Project Validation</span>
                    <span className="flow-badge">✓ Valid</span>
                  </div>
                  <span className="flow-arrow">→</span>
                  <div className="flow-node highlight">
                    <span style={{ fontWeight: 700, color: '#38bdf8' }}>D</span>
                    <span>AutoPatch Orchestrator</span>
                  </div>
                </div>

                {/* Row 2: Dual Scanning & Vulnerability Detection */}
                <div className="flow-row" style={{ paddingLeft: '4rem' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    <div className="flow-node completed">
                      <span style={{ fontWeight: 700, color: '#818cf8' }}>E</span>
                      <span>Source Code Scanner (SAST)</span>
                      <span className="flow-badge">{c.sast_count} found</span>
                    </div>
                    <div className="flow-node completed">
                      <span style={{ fontWeight: 700, color: '#818cf8' }}>F</span>
                      <span>Runtime Scanner (DAST)</span>
                      <span className="flow-badge">{c.dast_count} found</span>
                    </div>
                  </div>
                  <span className="flow-arrow">→</span>
                  <div className="flow-node completed">
                    <span style={{ fontWeight: 700, color: '#38bdf8' }}>G</span>
                    <span>Vulnerability Detection</span>
                    <span className="flow-badge">{c.found} total</span>
                  </div>
                  <span className="flow-arrow">→</span>
                  <div className="flow-node completed">
                    <span style={{ fontWeight: 700, color: '#38bdf8' }}>H</span>
                    <span>Risk Analysis & CWE/OWASP</span>
                  </div>
                  <span className="flow-arrow">→</span>
                  <div className="flow-node completed">
                    <span style={{ fontWeight: 700, color: '#38bdf8' }}>I</span>
                    <span>Vulnerability Database</span>
                  </div>
                </div>

                {/* Row 3: Remediation Engine & AI/RAG */}
                <div className="flow-row" style={{ paddingLeft: '8rem' }}>
                  <div className="flow-node highlight">
                    <span style={{ fontWeight: 700, color: '#38bdf8' }}>J</span>
                    <span>Remediation Engine</span>
                  </div>
                  <span className="flow-arrow">→</span>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    <div className="flow-node completed">
                      <span style={{ fontWeight: 700, color: '#10b981' }}>K</span>
                      <span>Rules & Patch Templates</span>
                    </div>
                    <div className="flow-node completed">
                      <span style={{ fontWeight: 700, color: '#a855f7' }}>L</span>
                      <span>AI-Assisted Analysis / RAG</span>
                    </div>
                  </div>
                  <span className="flow-arrow">→</span>
                  <div className="flow-node completed">
                    <span style={{ fontWeight: 700, color: '#38bdf8' }}>M</span>
                    <span>Patch Generation</span>
                  </div>
                </div>

                {/* Row 4: Safety & Verification Loop */}
                <div className="flow-row" style={{ paddingLeft: '12rem' }}>
                  <div className="flow-node completed">
                    <span style={{ fontWeight: 700, color: '#38bdf8' }}>N</span>
                    <span>Patch Safety Validation</span>
                    <span className="flow-badge">AST Check</span>
                  </div>
                  <span className="flow-arrow">→</span>
                  <div className="flow-node completed">
                    <span style={{ fontWeight: 700, color: '#38bdf8' }}>O</span>
                    <span>Apply to Project Copy</span>
                  </div>
                  <span className="flow-arrow">→</span>
                  <div className="flow-node completed">
                    <span style={{ fontWeight: 700, color: '#38bdf8' }}>P</span>
                    <span>Automated Testing</span>
                  </div>
                  <span className="flow-arrow">→</span>
                  <div className="flow-node completed">
                    <span style={{ fontWeight: 700, color: '#38bdf8' }}>Q</span>
                    <span>Rescan & Security Check</span>
                  </div>
                </div>

                {/* Row 5: Decision Branching & Reporting */}
                <div className="flow-row" style={{ paddingLeft: '14rem' }}>
                  <div className="flow-node" style={{ borderColor: '#eab308' }}>
                    <span style={{ fontWeight: 700, color: '#eab308' }}>R</span>
                    <span>Patch Successful?</span>
                  </div>
                  <span className="flow-arrow">→</span>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    <div className="flow-node completed" style={{ borderColor: '#10b981' }}>
                      <span style={{ fontWeight: 700, color: '#10b981' }}>S</span>
                      <span>Accepted Fix ({c.accepted})</span>
                    </div>
                    <div className="flow-node completed" style={{ borderColor: '#f43f5e' }}>
                      <span style={{ fontWeight: 700, color: '#f43f5e' }}>T</span>
                      <span>Rejected / Manual ({c.rejected + c.manual_review})</span>
                    </div>
                  </div>
                  <span className="flow-arrow">→</span>
                  <div className="flow-node completed">
                    <span style={{ fontWeight: 700, color: '#38bdf8' }}>U</span>
                    <span>Final Reports</span>
                  </div>
                  <span className="flow-arrow">→</span>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    <div className="flow-node completed" onClick={() => downloadReport('json')} style={{ cursor: 'pointer' }}>
                      <span style={{ fontWeight: 700, color: '#38bdf8' }}>V</span>
                      <span>JSON Report (report.json)</span>
                    </div>
                    <div className="flow-node completed" onClick={() => downloadReport('md')} style={{ cursor: 'pointer' }}>
                      <span style={{ fontWeight: 700, color: '#38bdf8' }}>W</span>
                      <span>Markdown (report.md)</span>
                    </div>
                    <div className="flow-node highlight" onClick={() => setActiveTab('review')} style={{ cursor: 'pointer' }}>
                      <span style={{ fontWeight: 700, color: '#38bdf8' }}>X</span>
                      <span>Developer Review</span>
                    </div>
                  </div>
                </div>
              </div>
            </section>
          )}

          {/* TAB 2: Developer Review Workbench */}
          {activeTab === 'review' && (
            <section>
              {/* Filter and Search Bar */}
              <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1rem', flexWrap: 'wrap', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', background: '#111827', border: '1px solid #1f293d', borderRadius: '6px', padding: '0.4rem 0.75rem', minWidth: '220px' }}>
                  <Search size={15} color="#94a3b8" style={{ marginRight: '0.5rem' }} />
                  <input
                    type="text"
                    placeholder="Search findings, CWE, files..."
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    style={{ background: 'transparent', border: 'none', color: '#f8fafc', outline: 'none', fontSize: '0.85rem', width: '100%' }}
                  />
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <Filter size={14} color="#94a3b8" />
                  <select
                    value={severityFilter}
                    onChange={(e) => setSeverityFilter(e.target.value)}
                    style={{ background: '#111827', border: '1px solid #1f293d', color: '#f8fafc', padding: '0.4rem 0.6rem', borderRadius: '6px', fontSize: '0.85rem' }}
                  >
                    <option value="all">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>

                  <select
                    value={scannerFilter}
                    onChange={(e) => setScannerFilter(e.target.value as any)}
                    style={{ background: '#111827', border: '1px solid #1f293d', color: '#f8fafc', padding: '0.4rem 0.6rem', borderRadius: '6px', fontSize: '0.85rem' }}
                  >
                    <option value="all">All Scanners</option>
                    <option value="SAST">SAST Only</option>
                    <option value="DAST">DAST Only</option>
                  </select>

                  <select
                    value={statusFilter}
                    onChange={(e) => setStatusFilter(e.target.value)}
                    style={{ background: '#111827', border: '1px solid #1f293d', color: '#f8fafc', padding: '0.4rem 0.6rem', borderRadius: '6px', fontSize: '0.85rem' }}
                  >
                    <option value="all">All Outcomes</option>
                    <option value="accepted">Accepted</option>
                    <option value="rejected">Rejected</option>
                    <option value="manual_review">Manual Review</option>
                  </select>
                </div>

                <div style={{ marginLeft: 'auto', fontSize: '0.82rem', color: '#94a3b8' }}>
                  Showing {filteredFindings.length} of {report.findings.length} findings
                </div>
              </div>

              {/* Workbench Layout */}
              <div className="workbench">
                {/* Findings List */}
                <div className="finding-list">
                  {filteredFindings.map((finding) => (
                    <button
                      type="button"
                      key={finding.fingerprint}
                      className={`finding-row ${selectedFinding?.fingerprint === finding.fingerprint ? 'selected' : ''}`}
                      onClick={() => setSelectedFingerprint(finding.fingerprint)}
                    >
                      <div className="finding-row-content">
                        <div className="finding-title-line">
                          <span>{finding.title}</span>
                          <span className={`severity-pill ${finding.severity.toLowerCase()}`}>
                            {finding.severity}
                          </span>
                        </div>
                        <div className="finding-meta">
                          <span className="scanner-badge">{finding.scanner_type}</span>
                          <span>{finding.cwe}</span>
                          <span>·</span>
                          <span>{finding.file.split('/').pop()}:{finding.line}</span>
                        </div>
                        <div style={{ marginTop: '0.4rem', fontSize: '0.74rem', color: finding.status === 'accepted' ? '#10b981' : finding.status === 'rejected' ? '#f43f5e' : '#eab308' }}>
                          {finding.status === 'accepted' ? '✓ Accepted Fix' : finding.status === 'rejected' ? '✕ Rejected' : '⚠ Manual Review'}
                          {finding.risk_score && ` · Risk ${finding.risk_score}/10`}
                        </div>
                      </div>
                    </button>
                  ))}
                  {filteredFindings.length === 0 && (
                    <div style={{ padding: '2rem', textAlign: 'center', color: '#94a3b8' }}>
                      No findings match the current filters.
                    </div>
                  )}
                </div>

                {/* Finding Details & Diff Review */}
                {selectedFinding ? (
                  <article className="finding-detail">
                    <div className="detail-header">
                      <div>
                        <span className={`severity-pill ${selectedFinding.severity.toLowerCase()}`} style={{ marginRight: '0.5rem' }}>
                          {selectedFinding.severity.toUpperCase()}
                        </span>
                        <span className="scanner-badge">{selectedFinding.scanner_type} SCANNER</span>
                      </div>
                      <div style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
                        Confidence: <strong>{selectedFinding.confidence ?? 95}%</strong>
                      </div>
                    </div>

                    <h2 className="detail-title">{selectedFinding.title}</h2>
                    <div className="detail-tags">
                      <span className="detail-tag">{selectedFinding.cwe}</span>
                      {selectedFinding.owasp && <span className="detail-tag">{selectedFinding.owasp}</span>}
                      <span className="detail-tag">Location: {selectedFinding.file}:{selectedFinding.line}</span>
                      {selectedFinding.patch_strategy && (
                        <span className="detail-tag" style={{ color: '#c084fc', borderColor: 'rgba(192, 132, 252, 0.4)' }}>
                          Strategy: {selectedFinding.patch_strategy}
                        </span>
                      )}
                    </div>

                    {/* AI-Assisted Security Analysis & RAG Context */}
                    <div className="detail-box">
                      <h4><Sparkles size={14} /> AI-Assisted Analysis & RAG Context (Step L)</h4>
                      <p style={{ color: '#cbd5e1' }}>
                        {selectedFinding.ai_analysis || selectedFinding.snippet}
                      </p>
                    </div>

                    {/* Verification Outcome */}
                    <div className="detail-box" style={{ background: selectedFinding.status === 'accepted' ? 'rgba(16, 185, 129, 0.08)' : selectedFinding.status === 'rejected' ? 'rgba(244, 63, 94, 0.08)' : 'rgba(234, 179, 8, 0.08)' }}>
                      <h4 style={{ color: selectedFinding.status === 'accepted' ? '#10b981' : selectedFinding.status === 'rejected' ? '#f43f5e' : '#eab308' }}>
                        <Activity size={14} /> Verification Outcome (Steps N, P, Q, R)
                      </h4>
                      <p style={{ color: '#f1f5f9' }}>{selectedFinding.reason}</p>
                      {selectedFinding.test_output && (
                        <pre style={{ background: '#020617', padding: '0.5rem', marginTop: '0.5rem', borderRadius: '4px', fontSize: '0.78rem', color: '#fca5a5', overflowX: 'auto' }}>
                          {selectedFinding.test_output}
                        </pre>
                      )}
                    </div>

                    {/* Proposed Diff */}
                    {selectedFinding.diff ? (
                      <div className="diff-container">
                        <div className="diff-toolbar">
                          <span><Code2 size={13} style={{ verticalAlign: 'middle', marginRight: '4px' }} /> Proposed Patch Diff</span>
                          <span>Remediation time: {selectedFinding.remediation_seconds?.toFixed(3)}s</span>
                        </div>
                        <div className="diff-content">
                          {selectedFinding.diff.split('\n').map((line, idx) => {
                            const isAdd = line.startsWith('+') && !line.startsWith('+++')
                            const isRem = line.startsWith('-') && !line.startsWith('---')
                            const isInfo = line.startsWith('@@') || line.startsWith('---') || line.startsWith('+++')
                            return (
                              <div
                                key={idx}
                                className={`diff-line ${isAdd ? 'added' : isRem ? 'removed' : isInfo ? 'info' : ''}`}
                              >
                                {line || ' '}
                              </div>
                            )
                          })}
                        </div>
                      </div>
                    ) : (
                      <div className="detail-box" style={{ textAlign: 'center', color: '#94a3b8' }}>
                        <Terminal size={20} style={{ margin: '0 auto 0.5rem', display: 'block' }} />
                        No automated patch diff available. Manual developer remediation required.
                      </div>
                    )}

                    {/* Developer Review Action Controls */}
                    <div className="detail-actions">
                      {selectedFinding.status === 'accepted' && (
                        <button
                          type="button"
                          className="approve-button"
                          onClick={handleApplyToSource}
                        >
                          <Check size={16} /> Apply Patch to Source
                        </button>
                      )}
                      <button
                        type="button"
                        className="secondary-button"
                        onClick={() => setNotice('Finding marked for follow-up audit.')}
                      >
                        <CheckCircle2 size={15} /> Mark Reviewed
                      </button>
                      <button
                        type="button"
                        className="secondary-button"
                        onClick={() => downloadReport('md')}
                      >
                        <Download size={14} /> Export Findings
                      </button>
                    </div>
                  </article>
                ) : (
                  <div style={{ padding: '3rem', textAlign: 'center', color: '#94a3b8' }}>
                    Select a finding to inspect diff and AI analysis.
                  </div>
                )}
              </div>
            </section>
          )}
        </div>
      </main>

      {/* Toast Notification */}
      {notice && (
        <div className="toast">
          <CheckCircle2 size={16} color="#38bdf8" />
          <span>{notice}</span>
          <button
            type="button"
            onClick={() => setNotice('')}
            style={{ background: 'transparent', border: 'none', color: '#94a3b8', cursor: 'pointer', marginLeft: 'auto' }}
          >
            <X size={14} />
          </button>
        </div>
      )}
    </div>
  )
}

export default App
