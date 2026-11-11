import React, { useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';

const API = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

function Brand({ compact = false }) {
  return <div className={`brand ${compact ? 'brand-compact' : ''}`}><span className="brand-mark">S</span><span>SKYGUARD</span></div>;
}

function AuthView({ onAuth }) {
  const [mode, setMode] = useState('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const registering = mode === 'register';

  async function submit(event) {
    event.preventDefault();
    setError('');
    if (registering && password !== confirmPassword) {
      setError('The passwords do not match.');
      return;
    }
    if (registering && password.length < 10) {
      setError('Use at least 10 characters for your password.');
      return;
    }
    setBusy(true);
    try {
      await onAuth(mode, email.trim(), password);
    } catch (err) {
      setError(err.message || 'We could not sign you in. Please try again.');
    } finally {
      setBusy(false);
    }
  }

  return <main className="auth-page">
    <section className="auth-visual" aria-label="SkyGuard platform introduction">
      <div className="auth-visual-top"><Brand /><span className="secure-label"><i /> PRIVATE WORKSPACE</span></div>
      <div className="auth-pitch">
        <div className="eyebrow light-eyebrow">CODE HEALTH, IN ONE PLACE</div>
        <h1>See the issue.<br />Understand the cause.</h1>
        <p>Scan projects locally, review findings with useful source context, and keep runtime errors visible to your team.</p>
        <div className="auth-feature-list">
          <div><span className="feature-icon">01</span><span><b>Local agent scan</b><small>Redacted source context syncs to your API.</small></span></div>
          <div><span className="feature-icon">02</span><span><b>Clear findings</b><small>File locations, severity, and status together.</small></span></div>
          <div><span className="feature-icon">03</span><span><b>Runtime visibility</b><small>Forward Python application errors when enabled.</small></span></div>
        </div>
      </div>
      <div className="auth-visual-foot"><span>BUILT FOR DEVELOPERS</span><span>SKYGUARD · LOCAL PREVIEW</span></div>
    </section>
    <section className="auth-panel">
      <div className="auth-mobile-brand"><Brand /></div>
      <div className="auth-form-wrap">
        <div className="auth-form-heading"><div className="eyebrow">YOUR DEVELOPMENT WORKSPACE</div><h2>{registering ? 'Create your account' : 'Welcome back'}</h2><p>{registering ? 'Start tracking issues across your projects.' : 'Sign in to continue to your projects.'}</p></div>
        <div className="auth-tabs" role="tablist" aria-label="Account access">
          <button type="button" role="tab" aria-selected={!registering} className={!registering ? 'selected' : ''} onClick={() => { setMode('login'); setError(''); }}>Sign in</button>
          <button type="button" role="tab" aria-selected={registering} className={registering ? 'selected' : ''} onClick={() => { setMode('register'); setError(''); }}>Create account</button>
        </div>
        <form className="auth-form" onSubmit={submit}>
          {error && <div className="form-alert" role="alert"><span>!</span>{error}</div>}
          <label htmlFor="email">Email address</label>
          <input id="email" type="email" autoComplete="email" placeholder="you@company.com" required value={email} onChange={e => setEmail(e.target.value)} />
          <div className="label-row"><label htmlFor="password">Password</label>{registering && <span>10 characters minimum</span>}</div>
          <div className="password-field"><input id="password" type={showPassword ? 'text' : 'password'} autoComplete={registering ? 'new-password' : 'current-password'} placeholder={registering ? 'Create a strong password' : 'Enter your password'} minLength={registering ? 10 : 1} required value={password} onChange={e => setPassword(e.target.value)} /><button type="button" className="show-password" onClick={() => setShowPassword(v => !v)}>{showPassword ? 'Hide' : 'Show'}</button></div>
          {registering && <><label htmlFor="confirm-password">Confirm password</label><input id="confirm-password" type={showPassword ? 'text' : 'password'} autoComplete="new-password" placeholder="Enter your password again" required value={confirmPassword} onChange={e => setConfirmPassword(e.target.value)} /></>}
          <button className="auth-submit" disabled={busy}>{busy ? <><span className="spinner" />{registering ? 'Creating account…' : 'Signing in…'}</> : registering ? 'Create account' : 'Sign in'}<span aria-hidden="true">→</span></button>
        </form>
        <div className="auth-trust"><span className="lock-icon">▣</span><span>The agent scans locally and uploads redacted source context by default. `.env` values are excluded; use --no-context-upload to keep source local.</span></div>
      </div>
      <div className="auth-panel-foot">By continuing, you agree to use SkyGuard only with projects you own or are authorized to inspect.</div>
    </section>
  </main>;
}

function App() {
  const [authToken, setAuthToken] = useState(localStorage.getItem('skyguard_token') || '');
  const [apiConnected, setApiConnected] = useState(false);
  const [profileMenuOpen, setProfileMenuOpen] = useState(false);
  const profileMenuRef = useRef(null);
  const [projects, setProjects] = useState([]);
  const [pid, setPid] = useState('');
  const [findings, setFindings] = useState([]);
  const [latestScan, setLatestScan] = useState(null);
  const [selected, setSelected] = useState(null);
  const [busy, setBusy] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [name, setName] = useState('');
  const [root, setRoot] = useState('');
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [showScan, setShowScan] = useState(false);
  const [showRuntime, setShowRuntime] = useState(false);
  const [watchMode, setWatchMode] = useState(false);
  const [refreshServiceMode, setRefreshServiceMode] = useState(false);
  const [context, setContext] = useState({ files: [], count: 0, complete: false, updated_at: null });
  const [contextOpen, setContextOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const [connectionToken, setConnectionToken] = useState('');
  const [tokenProjectId, setTokenProjectId] = useState('');

  async function request(path, options = {}) {
    const headers = { ...(options.headers || {}), ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}) };
    let response;
    try { response = await fetch(API + path, { cache: 'no-store', ...options, headers }); }
    catch (error) { setApiConnected(false); throw error; }
    setApiConnected(true);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      if (response.status === 401 && !path.startsWith('/api/auth/')) {
        localStorage.removeItem('skyguard_token');
        setAuthToken('');
      }
      throw new Error(data.detail || `Request failed (${response.status})`);
    }
    return data;
  }

  async function authenticate(mode, email, password) {
    const data = await request(`/api/auth/${mode}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }) });
    localStorage.setItem('skyguard_token', data.access_token);
    setAuthToken(data.access_token);
  }

  async function loadProjects(preferred) {
    try {
      const data = await request('/api/projects');
      setProjects(data);
      const next = preferred && data.some(project => project.id === preferred)
        ? preferred
        : data.some(project => project.id === pid) ? pid : (data[0]?.id || '');
      setPid(next);
      setErr('');
    } catch (error) {
      setErr(`Could not load projects. Check that the SkyGuard API is running at ${API}. ${error.message}`);
    }
  }

  async function loadFindings(id = pid) {
    if (!id) { setFindings([]); return; }
    try {
      const data = await request(`/api/projects/${id}/findings`);
      setFindings(data);
      setSelected(current => current ? (data.find(item => item.id === current.id) || null) : null);
      setErr('');
    } catch (error) { setErr(error.message); }
  }

  async function loadLatestScan(id = pid) {
    if (!id) { setLatestScan(null); return; }
    try {
      const scans = await request(`/api/projects/${id}/scans`);
      setLatestScan(scans[0] || null);
    } catch { setLatestScan(null); }
  }

  async function loadProjectContext(id = pid, includeFiles = false) {
    if (!id) { setContext({ files: [], count: 0, complete: false, updated_at: null }); return; }
    try { setContext(await request(`/api/projects/${id}/context${includeFiles ? '' : '?summary=true'}`)); }
    catch { setContext({ files: [], count: 0, complete: false, updated_at: null }); }
  }

  async function refreshDashboard() {
    if (!pid) return;
    setRefreshing(true);
    setErr('');
    try {
      const localResponse = await fetch('http://127.0.0.1:8765/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-SkyGuard-Request': '1' },
        body: JSON.stringify({ project_id: pid }),
        cache: 'no-store',
      });
      const localResult = await localResponse.json().catch(() => ({}));
      if (!localResponse.ok) throw new Error(localResult.detail || `Local scan failed (${localResponse.status})`);
      const data = await request(`/api/projects/${pid}/findings`);
      setFindings(data);
      setSelected(current => current ? (data.find(item => item.id === current.id) || null) : null);
      await loadLatestScan(pid);
      await request('/api/health');
      await loadProjectContext(pid,contextOpen);
    } catch (error) {
      setErr(`Could not scan this project: ${error.message}. Start the local refresh agent using the “Refresh rescans” commands in Connect, then try again.`);
      setShowScan(true);
      setRefreshServiceMode(true);
    } finally {
      setRefreshing(false);
    }
  }

  useEffect(() => { if (authToken) loadProjects(); }, [authToken]);
  useEffect(() => {
    function closeMenu(event) { if (!profileMenuRef.current?.contains(event.target)) setProfileMenuOpen(false); }
    function closeOnEscape(event) { if (event.key === 'Escape') setProfileMenuOpen(false); }
    document.addEventListener('mousedown', closeMenu);
    document.addEventListener('keydown', closeOnEscape);
    return () => { document.removeEventListener('mousedown', closeMenu); document.removeEventListener('keydown', closeOnEscape); };
  }, []);
  useEffect(() => {
    setSelected(null);
    loadFindings(pid);
    loadLatestScan(pid);
    if (!authToken || !pid) return undefined;
    const timer = setInterval(() => { loadFindings(pid); loadLatestScan(pid); loadProjectContext(pid); }, 3000);
    return () => clearInterval(timer);
  }, [pid, authToken]);
  useEffect(() => { if (authToken) loadProjectContext(pid); }, [pid, authToken]);

  async function createProject(event) {
    event.preventDefault();
    setBusy(true); setErr('');
    try {
      const project = await request('/api/projects', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: name.trim(), root_label: root.trim() || null }) });
      setConnectionToken(project.connection_token); setTokenProjectId(project.id);
      setName(''); setRoot(''); setShowCreate(false);
      await loadProjects(project.id); setShowScan(true);
    } catch (error) { setErr(error.message); }
    finally { setBusy(false); }
  }

  async function rotateProjectToken() {
    if (!pid || !window.confirm('Generate a new connection token? Any agent using the previous token will need to be updated.')) return;
    setBusy(true); setErr('');
    try {
      const result = await request(`/api/projects/${pid}/token`, { method: 'POST' });
      setConnectionToken(result.connection_token); setTokenProjectId(pid);
    } catch (error) { setErr(error.message); }
    finally { setBusy(false); }
  }

  async function deleteProject() {
    if (!pid || !window.confirm('Delete this project and its findings? This cannot be undone.')) return;
    setBusy(true); setErr('');
    try {
      await request(`/api/projects/${pid}`, { method: 'DELETE' });
      setSelected(null); setFindings([]); setPid('');
      await loadProjects('');
    }
    catch (error) { setErr(error.message); }
    finally { setBusy(false); }
  }

  async function findingAction(action, field) {
    if (!selected) return;
    setBusy(true); setErr('');
    try {
      const result = await request(`/api/findings/${selected.id}/${action}`, { method: 'POST' });
      setSelected(current => ({ ...current, [field]: result[field] }));
      await loadFindings();
    } catch (error) { setErr(error.message); }
    finally { setBusy(false); }
  }

  async function updateStatus(status) {
    if (!selected) return;
    try {
      await request(`/api/findings/${selected.id}/status`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status }) });
      setSelected(current => ({ ...current, status })); await loadFindings();
    } catch (error) { setErr(error.message); }
  }

  const filtered = useMemo(() => findings.filter(item =>
    (statusFilter === 'all' || item.status === statusFilter) &&
    (severityFilter === 'all' || item.severity === severityFilter) &&
    `${item.title} ${item.message} ${item.file_path} ${item.category}`.toLowerCase().includes(query.toLowerCase())
  ), [findings, statusFilter, severityFilter, query]);
  const counts = {
    total: findings.length,
    urgent: findings.filter(item => ['HIGH', 'CRITICAL'].includes(item.severity) && item.status === 'open').length,
    open: findings.filter(item => item.status === 'open').length,
    fixed: findings.filter(item => item.status === 'fixed').length,
    runtime: findings.filter(item => item.category === 'RUNTIME_ERROR').length,
  };
  const active = projects.find(project => project.id === pid);
  const projectToken = tokenProjectId === pid ? connectionToken : 'YOUR_PROJECT_TOKEN';
  const projectPath = 'C:\\path\\to\\your-project';
  const command = refreshServiceMode
    ? `py -m skyguard_agent connect "${projectPath}" --api ${API} --project-id ${pid} --token ${projectToken}\npy -m skyguard_agent serve "${projectPath}"`
    : `py -m skyguard_agent ${watchMode ? 'watch' : 'scan'} "${projectPath}" --api ${API} --project-id ${pid} --token ${projectToken}`;

  async function copy(text) {
    try { await navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1800); }
    catch { setErr('Clipboard is unavailable. Select and copy the command manually.'); }
  }

  function signOut() { localStorage.removeItem('skyguard_token'); setAuthToken(''); setProjects([]); setFindings([]); setPid(''); }

  if (!authToken) return <AuthView onAuth={authenticate} />;

  return <div className="app-shell">
    <aside className="sidebar">
      <Brand />
      <div className="workspace-label">WORKSPACE <span className="workspace-dot" /></div>
      <nav className="side-nav" aria-label="Main navigation">
        <button className="side-link active" onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}><span>⌂</span>Overview</button>
        <button className="side-link" onClick={() => document.getElementById('findings')?.scrollIntoView({ behavior: 'smooth' })}><span>⊙</span>Findings <b>{counts.open || ''}</b></button>
        <button className="side-link" onClick={() => setShowCreate(true)}><span>▤</span>Projects</button>
      </nav>
      <div className="sidebar-projects"><div className="sidebar-section-title">YOUR PROJECTS <button aria-label="Add project" onClick={() => setShowCreate(true)}>+</button></div>
        {projects.length ? projects.slice(0, 6).map(project => <button key={project.id} className={`project-link ${pid === project.id ? 'current' : ''}`} onClick={() => setPid(project.id)}><span className="project-avatar">{project.name.slice(0, 1).toUpperCase()}</span><span className="project-link-name">{project.name}</span></button>) : <p className="sidebar-empty">Your projects will appear here.</p>}
      </div>
      <div className="sidebar-bottom"><div className={`connection-indicator ${apiConnected ? 'connected' : 'disconnected'}`}><i /> API {apiConnected ? 'CONNECTED' : 'DISCONNECTED'}</div><div className="profile-wrap" ref={profileMenuRef}><div className="profile-button"><span className="profile-avatar">SG</span><span className="profile-label"><b>SkyGuard account</b><small>Signed in</small></span><button className="profile-menu-trigger" aria-label="Account options" aria-haspopup="menu" aria-expanded={profileMenuOpen} onClick={() => setProfileMenuOpen(value => !value)}>···</button></div>{profileMenuOpen && <div className="account-menu" role="menu"><div className="account-menu-title">ACCOUNT</div><button role="menuitem" onClick={() => { setProfileMenuOpen(false); signOut(); }}><span>↪</span> Sign out</button></div>}</div></div>
    </aside>

    <main className="main-content">
      <header className="topbar"><div className="breadcrumbs"><span>Workspace</span><span>/</span><b>{active?.name || 'Overview'}</b></div><div className="topbar-actions">{pid && <span className="live-label"><i /> LIVE UPDATES</span>}<button className="button button-dark button-small" onClick={() => setShowCreate(true)}><span>＋</span> New project</button></div></header>
      <div className="page-wrap">
        {err && <div className="page-alert" role="alert"><span>!</span><div>{err}</div><button onClick={() => setErr('')} aria-label="Dismiss">×</button></div>}
        <section className="page-heading"><div><div className="eyebrow">DEVELOPER WORKSPACE</div><h1>{active?.name || 'Project overview'}</h1><p>{active ? 'Review code health, recent findings, and runtime issues for this project.' : 'Create a project and connect your local codebase to start reviewing findings.'}</p>{active && <p className="scan-status" aria-live="polite">{latestScan ? `Last agent scan: ${latestScan.files_scanned} files checked, ${latestScan.findings_count} findings reported (${new Date(latestScan.ended_at).toLocaleString()}).` : 'No completed agent scan yet. Run the local agent command to send scan results here.'}</p>}</div><div className="heading-actions">{pid && <><button className="button button-light" onClick={refreshDashboard} disabled={refreshing}><span>{refreshing ? '…' : '↻'}</span> {refreshing ? 'Scanning…' : 'Scan & refresh'}</button><button className="button button-danger" onClick={deleteProject} disabled={busy}>Delete project</button></>}<button className="button button-dark" onClick={() => setShowCreate(true)}>＋ Add project</button></div></section>

        {showCreate && <div className="modal-backdrop" onMouseDown={event => { if (event.target === event.currentTarget) setShowCreate(false); }}><form className="dialog" onSubmit={createProject}><div className="dialog-top"><div><div className="eyebrow">PROJECT SETUP</div><h2>Create a project</h2></div><button type="button" className="icon-button" aria-label="Close" onClick={() => setShowCreate(false)}>×</button></div><label htmlFor="project-name">Project name</label><input id="project-name" autoFocus value={name} onChange={event => setName(event.target.value)} placeholder="e.g. Customer portal" required maxLength="120"/><label htmlFor="project-folder">Local folder label <span className="optional">OPTIONAL</span></label><input id="project-folder" value={root} onChange={event => setRoot(event.target.value)} placeholder="e.g. customer-portal"/><div className="dialog-note">The local agent scans the project and sends redacted source context to the configured API by default. Environment files are excluded.</div><div className="dialog-actions"><button className="button button-light" type="button" onClick={() => setShowCreate(false)}>Cancel</button><button className="button button-dark" disabled={busy || !name.trim()}>{busy ? 'Creating…' : 'Create project'}</button></div></form></div>}

        {showScan && pid && <section className="connect-card"><div className="connect-card-header"><div><div className="eyebrow">LOCAL AGENT</div><h2>Connect {active?.name || 'your project'}</h2><p>Run this from the SkyGuard agent folder. Replace the sample path with your project’s absolute path.</p></div><div className="connect-actions"><button className="button button-light button-small" disabled={busy} onClick={rotateProjectToken}>{tokenProjectId === pid ? 'Rotate token' : 'Generate token'}</button><button className="icon-button" aria-label="Close setup" onClick={() => setShowScan(false)}>×</button></div></div><div className="setup-steps"><span><b>01</b> Install the agent once</span><span><b>02</b> Scan your project folder</span><span><b>03</b> Review findings here</span></div><div className="agent-mode" role="group" aria-label="Agent scan mode"><button className={!watchMode && !refreshServiceMode ? 'selected' : ''} onClick={() => { setWatchMode(false); setRefreshServiceMode(false); }}>One-time scan</button><button className={watchMode ? 'selected' : ''} onClick={() => { setWatchMode(true); setRefreshServiceMode(false); }}>Watch for changes</button><button className={refreshServiceMode ? 'selected' : ''} onClick={() => { setWatchMode(false); setRefreshServiceMode(true); }}>Refresh rescans</button></div><p className="scan-explainer">{refreshServiceMode ? 'Run both commands below. The first connects and scans; the second keeps a local agent ready. After that, the dashboard Refresh button rescans the connected folder and removes findings no longer detected.' : watchMode ? 'The agent scans now, then rescans and uploads after supported files change. Keep this terminal running.' : 'This runs one scan now. Use Refresh rescans to let the dashboard trigger a fresh local scan.'}</p><pre className="code-block"><code>cd C:\path\to\SkyGuard-project\agent{'\n'}pip install -r requirements.txt{'\n'}{command}</code></pre><div className="code-actions"><button className="button button-dark button-small" onClick={() => copy(command)}>{copied ? 'Copied' : `Copy ${refreshServiceMode ? 'commands' : watchMode ? 'watch' : 'scan'} command`}</button><small>Findings update in this view after the scan completes.</small></div><div className="runtime-setup"><button className="runtime-toggle" onClick={() => setShowRuntime(value => !value)}>{showRuntime ? '−' : '+'} Python runtime error monitoring <span>OPTIONAL</span></button>{showRuntime && <div className="runtime-content"><p>Static scans never execute your app. Runtime events appear only after this integration is installed in the app environment and the app is restarted. This enables FastAPI HTTP 404/500 capture and Python ERROR logs. A 404 means the requested route does not exist; use an actual failing route or the included runtime demo.</p><pre className="code-block"><code>py -m pip install -e "C:\path\to\SkyGuard-project\agent"{'\n'}$env:SKYGUARD_PROJECT_ID = "{pid}"{'\n'}$env:SKYGUARD_PROJECT_TOKEN = "{projectToken}"{'\n'}{'# In your FastAPI module, after app = FastAPI(...)'}{'\n'}import os{'\n'}from skyguard_agent.runtime import configure_fastapi_monitoring, configure_runtime_monitoring{'\n'}configure_fastapi_monitoring(app, api_url="{API}", project_id=os.environ["SKYGUARD_PROJECT_ID"], token=os.environ["SKYGUARD_PROJECT_TOKEN"]){'\n'}configure_runtime_monitoring(api_url="{API}", project_id=os.environ["SKYGUARD_PROJECT_ID"], token=os.environ["SKYGUARD_PROJECT_TOKEN"], project_root=r"C:\path\to\your-project")</code></pre><small>Set both variables in the terminal that starts your app, add both calls to its server module, and restart that app. Browser-only errors and unlogged exceptions are not sent by this server integration.</small></div>}</div></section>}

        {pid && <section className="context-card"><button className="context-card-toggle" onClick={() => { const open=!contextOpen; setContextOpen(open); if(open) loadProjectContext(pid,true); }}><span><b>Whole-project context</b><small>{context.count ? `${context.count} source and documentation files indexed` : 'No codebase has been indexed yet'}</small></span><span>{contextOpen ? 'Hide files' : 'View file map'}　{contextOpen ? '−' : '+'}</span></button><p>The local agent indexes supported source and documentation files for this project. Environment files are checked locally but never uploaded; common credentials in other files are redacted heuristically. Gemini reasoning is currently paused.{context.count > 0 && !context.complete && <strong className="context-incomplete"> Index may be partial because a local file or size limit was reached.</strong>}</p>{contextOpen && <div className="context-file-list">{context.files.length ? context.files.map(file => <div key={file.file_path}><code>{file.file_path}</code><small>{file.size_bytes.toLocaleString()} chars</small></div>) : <span>Run the local agent scan to create the project index.</span>}</div>}</section>}
        {!projects.length ? <section className="empty-project"><div className="empty-symbol">S</div><div className="eyebrow">A CLEARER VIEW OF YOUR CODE</div><h2>Start with a project</h2><p>Connect a local repository to scan supported files and review findings in one focused workspace.</p><button className="button button-dark" onClick={() => setShowCreate(true)}>＋ Create your first project</button><div className="empty-steps"><span><b>01</b> Create a project</span><span><b>02</b> Run the local agent</span><span><b>03</b> Review results</span></div></section> : <>
          <section className="metrics-grid" aria-label="Finding summary">
            <article className="metric-card"><div className="metric-top"><span>Open findings</span><span className="metric-icon">◎</span></div><strong>{counts.open}</strong><small>Require review</small></article>
            <article className="metric-card"><div className="metric-top"><span>High priority</span><span className="metric-icon metric-alert">!</span></div><strong>{counts.urgent}</strong><small>Open high or critical</small></article>
            <article className="metric-card"><div className="metric-top"><span>Runtime errors</span><span className="metric-icon">⌁</span></div><strong>{counts.runtime}</strong><small>Captured application errors</small></article>
            <article className="metric-card"><div className="metric-top"><span>Resolved</span><span className="metric-icon">✓</span></div><strong>{counts.fixed}</strong><small>Marked fixed</small></article>
          </section>

          <section className="findings-layout" id="findings"><div className="panel findings-panel"><div className="panel-heading"><div><div className="eyebrow">ISSUE TRACKER</div><h2>Findings</h2><p>Static analysis and connected runtime events</p></div><span className="result-count">{filtered.length} <small>of {findings.length}</small></span></div>
            <div className="filter-row"><label className="search-field"><span>⌕</span><input aria-label="Search findings" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search title, message, or file" /></label><select aria-label="Filter by status" value={statusFilter} onChange={event => setStatusFilter(event.target.value)}><option value="all">All statuses</option><option value="open">Open</option><option value="investigating">Investigating</option><option value="fixed">Fixed</option><option value="ignored">Ignored</option></select><select aria-label="Filter by severity" value={severityFilter} onChange={event => setSeverityFilter(event.target.value)}><option value="all">All severity</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option></select></div>
            {filtered.length ? <div className="finding-list">{filtered.map(item => <button key={item.id} className={`finding-row ${selected?.id === item.id ? 'selected' : ''}`} onClick={() => setSelected(item)}><div className="finding-row-main"><span className={`severity-dot ${item.severity.toLowerCase()}`} /><span className="finding-title">{item.title}</span><span className={`severity-label ${item.severity.toLowerCase()}`}>{item.severity}</span></div><div className="finding-row-meta"><span className="mono">{item.file_path || 'Unknown file'}{item.line ? `:${item.line}` : ''}</span><span className="category-label">{(item.category || 'STATIC_ANALYSIS').replaceAll('_', ' ')}</span><span className={`status-label ${item.status}`}>{item.status}</span></div><p className="finding-message">{item.message}</p></button>)}</div> : <div className="empty-findings"><span className="empty-list-icon">⌕</span><b>{findings.length ? 'No results match these filters' : 'No findings yet'}</b><p>{findings.length ? 'Try another search or update your filters.' : 'Run a scan from your local agent. New results appear here automatically.'}</p>{!findings.length && <button className="text-action" onClick={() => setShowScan(true)}>View connection steps <span>→</span></button>}</div>}
          </div>

          <aside className="panel detail-panel"><div className="panel-heading detail-heading"><div><div className="eyebrow">INVESTIGATION</div><h2>Finding details</h2></div>{selected && <span className="analyzer-chip">{selected.analyzer || 'SkyGuard'}</span>}</div>
            {selected ? <div className="detail-body"><div className="detail-title-row"><span className={`severity-label ${selected.severity.toLowerCase()}`}>{selected.severity}</span><span className={`status-label ${selected.status}`}>{selected.status}</span></div><h3>{selected.title}</h3><div className="detail-location mono">{selected.file_path || 'Unknown file'}{selected.line ? `:${selected.line}` : ''}{selected.column_no ? `:${selected.column_no}` : ''}</div><p className="detail-message">{selected.message}</p><h4>Source context</h4><pre className="source-block"><code>{selected.code_snippet || 'No source snippet was supplied.'}</code></pre>{selected.category === 'RUNTIME_ERROR' && selected.code_snippet && <><h4>Runtime stack trace</h4><pre className="source-block trace-block"><code>{selected.code_snippet}</code></pre></>}<div className="detail-actions"><button className="button button-dark button-small" disabled title="Gemini API setup is paused">Explain with AI</button><button className="button button-light button-small" disabled title="Gemini API setup is paused">Suggested fix</button></div><div className="ai-paused">AI explanations and suggested fixes are paused until the Gemini API is configured.</div><div className="status-control"><label htmlFor="finding-status">Issue status</label><select id="finding-status" value={selected.status} onChange={event => updateStatus(event.target.value)}><option value="open">Open</option><option value="investigating">Investigating</option><option value="fixed">Fixed</option><option value="ignored">Ignored</option></select></div></div> : <div className="detail-empty"><span>↖</span><b>Select a finding</b><p>Choose an issue to inspect its location, analyzer output, source context, and status.</p></div>}
          </aside></section>
        </>}
        <footer className="app-footer"><span>SKYGUARD · LOCAL AGENT ANALYSIS</span><span>Redacted source context syncs to the configured API.</span></footer>
      </div>
    </main>
  </div>;
}

createRoot(document.getElementById('root')).render(<App />);
