import { useCallback, useEffect, useMemo, useState } from 'react'

type Conn = {
  agentId: string; agentName: string; direction: string; proto: string; state: string
  local: string; remote: string; remoteHost: string
  pid?: number | null; process: string; exe: string; cmdline: string; user: string
  ppid?: number | null; parent: string; parentExe: string
  unit: string; container: string; containerId: string
  started?: string | null; firstSeen: string; lastSeen: string
  isGhost: boolean; isNew: boolean; suspicious: boolean; flags: string[]
  detail?: string
}
type Agent = { id: string; name: string; hostname: string; os: string; version: string; lastSeen: string; socketCount: number }
type Recording = { id: string; name: string; startedAt: string; endedAt?: string | null; eventCount: number }
type IpInfo = {
  ip: string; isp: string; org: string; as: string; country: string; countryCode: string
  region: string; city: string; timezone: string; reverse: string
  fetchedAt: string; expiresAt: string; fromCache?: boolean
}

function parseIp(addr: string): string | null {
  if (!addr) return null
  if (addr.startsWith('[')) { const end = addr.indexOf(']'); return end > 0 ? addr.slice(1, end) : null }
  const parts = addr.split(':')
  if (parts.length === 2) return parts[0] === '0.0.0.0' ? null : parts[0]
  if (parts.length === 1) return addr === '0.0.0.0' ? null : addr
  return null // unbracketed IPv6 with a port is ambiguous; bracketed form is what the agent sends
}

type SortKey = 'agentName' | 'direction' | 'process' | 'detail' | 'exe' | 'local' | 'remote' | 'state' | 'firstSeen' | 'lastSeen'

const COLUMNS: { key: SortKey; label: string }[] = [
  { key: 'agentName', label: 'Agent' }, { key: 'direction', label: 'Direction' },
  { key: 'process', label: 'Process' }, { key: 'detail', label: 'Detail' }, { key: 'exe', label: 'Executable' },
  { key: 'local', label: 'Local' }, { key: 'remote', label: 'Remote' },
  { key: 'state', label: 'State' }, { key: 'firstSeen', label: 'First seen' },
  { key: 'lastSeen', label: 'Last seen' },
]

function killCommands(c: Conn): string[] {
  const cmds: string[] = []
  if (c.pid) {
    if (c.agentName && c.exe.includes('\\')) cmds.push(`taskkill /PID ${c.pid} /F`)
    else cmds.push(`kill ${c.pid}`, `kill -9 ${c.pid}`)
  }
  if (c.unit) cmds.push(`systemctl stop ${c.unit}`)
  if (c.container) cmds.push(`docker kill ${c.container}`)
  return cmds
}

export default function App() {
  const [conns, setConns] = useState<Conn[]>([])
  const [counts, setCounts] = useState<Record<string, number>>({})
  const [agents, setAgents] = useState<Agent[]>([])
  const [recordings, setRecordings] = useState<Recording[]>([])
  const [view, setView] = useState<'all' | 'outgoing' | 'incoming' | 'suspicious'>('all')
  const [nav, setNav] = useState<'agents' | 'recordings' | 'settings' | 'about'>('agents')
  const [appriseUrls, setAppriseUrls] = useState('')
  const [appriseApiUrl, setAppriseApiUrl] = useState('')
  const [appriseStatus, setAppriseStatus] = useState('')
  const [q, setQ] = useState('')
  const [agentFilter, setAgentFilter] = useState('')
  const [dirFilter, setDirFilter] = useState('')
  const [onlyNew, setOnlyNew] = useState(false)
  const [onlySusp, setOnlySusp] = useState(false)
  const [onlyListen, setOnlyListen] = useState(false)
  const [sortKey, setSortKey] = useState<SortKey>('lastSeen')
  const [sortDir, setSortDir] = useState<1 | -1>(-1)
  const [selected, setSelected] = useState<Conn | null>(null)
  const [showAddAgent, setShowAddAgent] = useState(false)
  const [newAgentName, setNewAgentName] = useState('')
  const [compose, setCompose] = useState('')
  const [linger, setLinger] = useState(30)
  const [recordingName, setRecordingName] = useState('')
  const [killStatus, setKillStatus] = useState('')
  const [confirmKill, setConfirmKill] = useState(false)
  const [paused, setPaused] = useState(false)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null)
  const [deleteStatus, setDeleteStatus] = useState('')
  const [ipInfo, setIpInfo] = useState<IpInfo | null>(null)
  const [ipInfoMsg, setIpInfoMsg] = useState('')
  const [ipInfoLoading, setIpInfoLoading] = useState(false)

  const load = useCallback(async () => {
    try {
      const [c, a, r] = await Promise.all([
        fetch('/api/connections').then(x => x.json()),
        fetch('/api/agents').then(x => x.json()),
        fetch('/api/recordings').then(x => x.json()),
      ])
      setConns(c.connections ?? []); setCounts(c.counts ?? {})
      setAgents(a ?? []); setRecordings(r ?? [])
      setLastUpdated(new Date())
    } catch { /* server down: keep last state, UI shows stale counts */ }
  }, [])

  // Pause freezes the displayed snapshot: no automatic polling while
  // paused, so rows stop shifting under you. The server, agents,
  // recordings and alerts keep running in the background, and the
  // next load after resuming shows the latest state. Explicit
  // actions (delete, add agent, recording, linger) still refresh.
  useEffect(() => {
    if (paused) return
    load(); const t = setInterval(load, 2000); return () => clearInterval(t)
  }, [load, paused])
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === '/' && document.activeElement?.tagName !== 'INPUT') { e.preventDefault(); document.getElementById('search')?.focus() }
      if (e.key === 'Escape') setSelected(null)
    }
    window.addEventListener('keydown', onKey); return () => window.removeEventListener('keydown', onKey)
  }, [])

  const filtered = useMemo(() => {
    let rows = conns
    if (view === 'outgoing') rows = rows.filter(c => c.direction === 'outbound')
    if (view === 'incoming') rows = rows.filter(c => c.direction === 'inbound' || c.direction === 'listen')
    if (view === 'suspicious') rows = rows.filter(c => c.suspicious)
    if (agentFilter) rows = rows.filter(c => c.agentId === agentFilter)
    if (dirFilter) rows = rows.filter(c => c.direction === dirFilter)
    if (onlyNew) rows = rows.filter(c => c.isNew)
    if (onlySusp) rows = rows.filter(c => c.suspicious)
    if (onlyListen) rows = rows.filter(c => c.direction === 'listen')
    if (q) {
      const needle = q.toLowerCase()
      rows = rows.filter(c => [c.process, c.exe, c.cmdline, c.remote, c.remoteHost, c.local, c.unit, c.container, c.agentName, String(c.pid ?? '')].join(' ').toLowerCase().includes(needle))
    }
    const sorted = [...rows].sort((a, b) => {
      const av = String((a as unknown as Record<string, unknown>)[sortKey] ?? '')
      const bv = String((b as unknown as Record<string, unknown>)[sortKey] ?? '')
      return av.localeCompare(bv) * sortDir
    })
    return sorted
  }, [conns, view, agentFilter, dirFilter, onlyNew, onlySusp, onlyListen, q, sortKey, sortDir])

  const groupedIncoming = useMemo(() => {
    const map = new Map<string, { service: string; process: string; unit: string; container: string; remotes: Set<string>; count: number }>()
    for (const c of filtered.filter(x => x.direction === 'inbound' || x.direction === 'listen')) {
      const key = `${c.agentName}|${c.process}|${c.local}`
      const entry = map.get(key) ?? { service: c.local, process: c.process, unit: c.unit, container: c.container, remotes: new Set(), count: 0 }
      if (c.remote) entry.remotes.add(c.remote)
      entry.count++
      map.set(key, entry)
    }
    return [...map.values()].sort((a, b) => b.remotes.size - a.remotes.size)
  }, [filtered])

  async function createAgent() {
    const res = await fetch('/api/agents', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: newAgentName || 'new-agent' }) })
    const data = await res.json()
    const serverUrl = window.location.origin
    const comp = await fetch(`/api/agents/${data.id}/compose?serverUrl=${encodeURIComponent(serverUrl)}`).then(x => x.text())
    setCompose(comp + `\n# Agent ID: ${data.id}\n# Token is embedded in the compose above. Do NOT commit this file to a public repo.\n`)
    load()
  }

  async function deleteAgent(id: string, name: string) {
    if (deleteConfirmId !== id) { setDeleteConfirmId(id); setDeleteStatus(''); return }
    setDeleteConfirmId(null)
    const res = await fetch(`/api/agents/${id}`, { method: 'DELETE' })
    if (!res.ok) { setDeleteStatus(`Could not delete ${name} (${res.status}).`); return }
    setDeleteStatus(`Deleted agent ${name}. If it is still running, its next snapshot will be rejected until it is re-registered.`)
    // Drop its rows immediately, even if paused, so the deletion is visible.
    setConns(prev => prev.filter(c => c.agentId !== id))
    setAgents(prev => prev.filter(a => a.id !== id))
    if (agentFilter === id) setAgentFilter('')
    setSelected(prev => (prev && prev.agentId === id ? null : prev))
  }

  // Cached IP info for the selected row's remote IP. GET never calls
  // ip-api — it only reads the server cache. Fetching is explicit.
  useEffect(() => {
    if (!selected) { setIpInfo(null); setIpInfoMsg(''); return }
    const ip = parseIp(selected.remote)
    if (!ip) { setIpInfo(null); setIpInfoMsg(''); return }
    ;(async () => {
      try {
        const data = await fetch(`/api/ip-info?ip=${encodeURIComponent(ip)}`).then(x => x.json())
        if (data.cached === false) { setIpInfo(null); setIpInfoMsg(data.message ?? '') }
        else { setIpInfo(data); setIpInfoMsg('') }
      } catch { setIpInfoMsg('Could not load cached IP info.') }
    })()
  }, [selected])

  async function fetchIpInfo(force: boolean) {
    if (!selected) return
    const ip = parseIp(selected.remote)
    if (!ip) return
    setIpInfoLoading(true); setIpInfoMsg('')
    try {
      const res = await fetch(`/api/ip-info?ip=${encodeURIComponent(ip)}${force ? '&force=true' : ''}`, { method: 'POST' })
      const data = await res.json()
      if (!res.ok) setIpInfoMsg(data.error ?? `Fetch failed (${res.status}).`)
      else {
        setIpInfo(data)
        if (data.reverse) setSelected(prev => (prev ? { ...prev, remoteHost: data.reverse } : prev))
        load()
      }
    } catch { setIpInfoMsg('Fetch failed.') }
    setIpInfoLoading(false)
  }

  async function startRecording() {
    await fetch('/api/recordings/start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: recordingName || 'recording' }) })
    load()
  }
  async function stopRecording(id: string) {
    await fetch(`/api/recordings/${id}/stop`, { method: 'POST' }); load()
  }
  async function saveLinger(seconds: number) {
    setLinger(seconds)
    await fetch('/api/settings/linger', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ seconds }) })
  }
  async function saveApprise() {
    await fetch('/api/settings/apprise', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ urls: appriseUrls, apiUrl: appriseApiUrl }) })
    setAppriseStatus('Apprise settings saved on the server. They are used for rule alerts; URLs are never shown back in the UI.')
  }
  async function doKill(c: Conn) {
    if (!c.pid) return
    setKillStatus('Requesting kill…')
    const res = await fetch(`/api/agents/${c.agentId}/kill`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pid: c.pid, exe: c.exe, started: c.started ?? null, reason: 'NetGlass UI kill' }) })
    const data = await res.json()
    setKillStatus(`Kill request ${data.killId} is pending — the agent re-checks PID + exe + start time before killing.`)
    for (let i = 0; i < 12; i++) {
      await new Promise(r => setTimeout(r, 1000))
      const status = await fetch(`/api/kill-requests/${data.killId}`).then(x => x.json()).catch(() => null)
      if (status && status.status !== 'pending') { setKillStatus(`Kill ${status.status}: ${status.result}`); break }
    }
  }

  function toggleSort(key: SortKey) {
    if (sortKey === key) setSortDir(d => (d === 1 ? -1 : 1) as 1 | -1)
    else { setSortKey(key); setSortDir(1) }
  }

  const activeRecording = recordings.find(r => !r.endedAt)
  const card: React.CSSProperties = { background: '#0d1b33', border: '1px solid #1e3a5f', borderRadius: 12, padding: 12 }
  const inputStyle: React.CSSProperties = { background: '#0a1526', border: '1px solid #1e3a5f', borderRadius: 8, color: '#e2e8f0', padding: '8px 10px' }
  const navItem = (key: typeof nav, label: string, icon: string) => (
    <button
      key={key}
      onClick={() => setNav(key)}
      style={{
        display: 'flex', gap: 10, alignItems: 'center', width: '100%', textAlign: 'left',
        background: nav === key ? '#14315e' : 'transparent', border: nav === key ? '1px solid #2563eb' : '1px solid transparent',
        borderRadius: 10, color: nav === key ? '#fff' : '#94a3b8', padding: '10px 12px', fontSize: 15, cursor: 'pointer',
      }}
    ><span>{icon}</span>{label}</button>
  )

  return (
    <div className="ng-layout" style={{ display: 'flex', minHeight: '100vh', background: 'linear-gradient(160deg, #04091c 0%, #0a1930 60%, #071224 100%)', color: '#e2e8f0', fontFamily: 'system-ui, sans-serif' }}>
      {/* Sidebar, as in the reference screenshot */}
      <aside className="ng-sidebar" style={{ width: 230, flexShrink: 0, padding: 20, borderRight: '1px solid #1e293b', background: 'rgba(4, 12, 28, 0.7)', display: 'flex', flexDirection: 'column', gap: 8 }}>
        <div className="ng-logo" style={{ marginBottom: 12 }}>
          <svg width="72" height="72" viewBox="0 0 72 72" aria-label="NetGlass logo">
            <g stroke="#38bdf8" strokeWidth="1.5" opacity="0.9">
              <line x1="14" y1="14" x2="36" y2="26" /><line x1="58" y1="14" x2="36" y2="26" />
              <line x1="14" y1="58" x2="36" y2="26" /><line x1="58" y1="58" x2="36" y2="26" />
            </g>
            <circle cx="14" cy="14" r="4" fill="#38bdf8" /><circle cx="58" cy="14" r="4" fill="#38bdf8" />
            <circle cx="14" cy="58" r="4" fill="#38bdf8" /><circle cx="58" cy="58" r="4" fill="#38bdf8" />
            <circle cx="42" cy="32" r="18" fill="none" stroke="#38bdf8" strokeWidth="3" />
            <line x1="55" y1="45" x2="66" y2="56" stroke="#38bdf8" strokeWidth="4" strokeLinecap="round" />
            <text x="42" y="40" textAnchor="middle" fontSize="22" fontWeight="800" fill="#e2e8f0">N</text>
          </svg>
          <div style={{ fontSize: 26, fontWeight: 800, marginTop: 4 }}>Net<span style={{ color: '#22d3ee' }}>Glass</span></div>
        </div>
        <div className="ng-nav" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {navItem('agents', 'Agents', '▣')}
        {navItem('recordings', 'Recordings', '▶')}
        {navItem('settings', 'Settings', '⚙')}
        {navItem('about', 'About', 'ⓘ')}
        </div>
        <div className="ng-footer" style={{ marginTop: 'auto', fontSize: 12, color: '#64748b' }}>
          Local-first. No cloud.<br />Agents report to this server only.
        </div>
      </aside>

      <main className="ng-main" style={{ flex: 1, minWidth: 0, padding: 20, maxWidth: 1500 }}>
      <h1 style={{ margin: '0 0 4px', fontSize: 34 }}>Net<span style={{ color: '#22d3ee' }}>Glass</span></h1>
      <p style={{ color: '#94a3b8', marginTop: 0 }}>Local-first process network visibility. No cloud. Click a row for the full story, including how to kill it.</p>

      {nav === 'agents' && (<>
      <div className="ng-stats" style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 12 }}>
        {([
          ['Total', counts.total, '🖥'], ['Outbound', counts.outbound, '✓'], ['Inbound', counts.inbound, '←'],
          ['Listeners', counts.listen, '👥'], ['Suspicious', conns.filter(c => c.suspicious).length, '⬡'],
          ['New (24h)', conns.filter(c => c.isNew).length, '◷'],
          ['Ghosts', conns.filter(c => c.isGhost).length, '👻'],
        ] as const).map(([label, value, icon]) => (
          <button key={label} onClick={() => {
            if (label === 'Suspicious') { setView('suspicious'); setOnlySusp(false) }
            if (label === 'New (24h)') setOnlyNew(true)
            if (label === 'Listeners') setOnlyListen(true)
          }} style={{ ...card, textAlign: 'left', display: 'flex', gap: 10, alignItems: 'center', cursor: 'pointer', flex: '1 1 110px' }}>
            <span style={{ fontSize: 20 }}>{icon}</span>
            <span><div style={{ fontSize: 22, fontWeight: 700 }}>{value ?? 0}</div><div style={{ fontSize: 12, color: '#94a3b8' }}>{label}</div></span>
          </button>
        ))}
        <button onClick={() => setShowAddAgent(v => !v)} style={{ background: 'linear-gradient(90deg, #2563eb, #0ea5e9)', color: '#fff', border: 'none', borderRadius: 12, padding: '12px 18px', fontWeight: 700, cursor: 'pointer' }}>+ Add agent</button>
        <button onClick={() => setPaused(p => !p)} style={{ ...card, fontWeight: 700, cursor: 'pointer' }}>
          {paused ? '▶ Resume live updates' : '⏸ Pause live updates'}
        </button>
      </div>

      {paused && (
        <div style={{ border: '1px solid #f59e0b', borderRadius: 12, padding: 10, marginBottom: 12, background: '#422006' }}>
          <strong>⏸ Paused</strong> — showing the snapshot from {lastUpdated ? lastUpdated.toLocaleTimeString() : 'the last load'}.
          No new connections will appear until you resume. The server, agents, recordings and alerts keep running in the background, so nothing is lost — resuming shows the latest state.
        </div>
      )}

      <div className="ng-filters" style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 12, alignItems: 'center' }}>
        {([['all', 'All'], ['outgoing', 'Outgoing'], ['incoming', 'Incoming'], ['suspicious', 'Suspicious']] as const).map(([key, label]) => (
          <button key={key} onClick={() => setView(key)} disabled={view === key} style={{ background: view === key ? '#2563eb' : '#0d1b33', color: '#fff', border: '1px solid #1e3a5f', borderRadius: 10, padding: '8px 14px', cursor: 'pointer' }}>{label}</button>
        ))}
        <input id="search" value={q} onChange={e => setQ(e.target.value)} placeholder="Search…  ( / to focus )" style={{ ...inputStyle, flex: 1, minWidth: 240 }} />
        <select value={agentFilter} onChange={e => setAgentFilter(e.target.value)} style={inputStyle}>
          <option value="">All agents</option>
          {agents.map(a => <option key={a.id} value={a.id}>{a.name} ({a.hostname || a.id.slice(0, 8)})</option>)}
        </select>
        <select value={dirFilter} onChange={e => setDirFilter(e.target.value)} style={inputStyle}>
          <option value="">All directions</option><option>outbound</option><option>inbound</option><option>listen</option><option>local</option>
        </select>
        <label><input type="checkbox" checked={onlyNew} onChange={e => setOnlyNew(e.target.checked)} /> Only new</label>
        <label><input type="checkbox" checked={onlySusp} onChange={e => setOnlySusp(e.target.checked)} /> Only suspicious</label>
        <button onClick={() => setOnlyListen(v => !v)} style={{ background: onlyListen ? '#2563eb' : '#0d1b33', color: '#fff', border: '1px solid #1e3a5f', borderRadius: 20, padding: '6px 12px', cursor: 'pointer' }}>
          {onlyListen ? '● Only listeners' : '○ Only listeners'}
        </button>
        <label title="How long a closed connection stays visible, faded">Ghost linger
          <input type="range" min={0} max={300} value={linger} onChange={e => saveLinger(Number(e.target.value))} /> {linger}s
        </label>
      </div>
      </>)}

      {nav === 'agents' && (<>
      {showAddAgent && (
        <div style={{ ...card, borderColor: '#2563eb', boxShadow: '0 0 24px rgba(37, 99, 235, 0.25)', marginBottom: 12 }}>
          <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
            <span style={{ fontSize: 28, background: '#2563eb', borderRadius: '50%', padding: 10 }}>▣</span>
            <div><h3 style={{ margin: 0 }}>Add an agent</h3><p style={{ color: '#94a3b8', margin: '4px 0 0' }}>Monitor another host or docker container on your network.</p></div>
          </div>
          <div style={{ marginTop: 12 }}>
          <input value={newAgentName} onChange={e => setNewAgentName(e.target.value)} placeholder="Agent name, e.g. debian-server" style={inputStyle} />
          <button className="primary" onClick={createAgent} style={{ marginLeft: 8, background: 'linear-gradient(90deg, #2563eb, #0ea5e9)', color: '#fff', border: 'none', borderRadius: 10, padding: '8px 14px', cursor: 'pointer' }}>▶ Generate Docker compose</button>
          </div>
          <p style={{ color: '#94a3b8' }}>Windows: download the release exe and run it with <code>--server {window.location.origin} --token &lt;token&gt;</code>, or run it with no arguments and enter the server and token when prompted.</p>
          {compose && <><textarea value={compose} readOnly rows={16} style={{ width: '100%', fontFamily: 'monospace' }} />
            <button onClick={() => navigator.clipboard.writeText(compose)}>Copy compose</button>
            <button onClick={() => { const blob = new Blob([compose], { type: 'text/yaml' }); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'docker-compose.netglass-agent.yml'; a.click() }}>Download compose</button></>}
        </div>
      )}

      <div style={{ ...card, marginBottom: 12 }}>
        <strong>Recording:</strong>{' '}
        {activeRecording
          ? <><span>● Recording “{activeRecording.name}” — {activeRecording.eventCount} events</span>{' '}
              <button onClick={() => stopRecording(activeRecording.id)}>Stop</button></>
          : <><input value={recordingName} onChange={e => setRecordingName(e.target.value)} placeholder="Recording name" />{' '}
              <button className="primary" onClick={startRecording}>Start recording</button></>}
        <div style={{ marginTop: 8 }}>
          {recordings.map(r => (
            <span key={r.id} style={{ marginRight: 12, fontSize: 13 }}>
              {r.name} ({r.eventCount} events, {r.endedAt ? 'ended' : 'active'}){' '}
              <a href={`/api/recordings/${r.id}/export`}>Export CSV</a>
            </span>
          ))}
        </div>
      </div>

      <div style={{ ...card, marginBottom: 12 }}>
        <strong>Agents</strong>
        <span style={{ color: '#94a3b8', fontSize: 12 }}> — last updated {lastUpdated ? lastUpdated.toLocaleTimeString() : 'never'}{paused ? ' (paused)' : ''}</span>
        {agents.length === 0 && <span style={{ color: '#94a3b8' }}> — none connected, click Add agent above.</span>}
        {agents.map(a => (
          <div key={a.id} style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', marginTop: 6, fontSize: 13 }}>
            <span><strong>{a.name}</strong> ({a.hostname || a.id.slice(0, 8)}) — {a.os || 'unknown OS'} — last seen {a.lastSeen ? new Date(a.lastSeen).toLocaleTimeString() : 'never'}, {a.socketCount} sockets</span>
            <button
              className={deleteConfirmId === a.id ? 'danger' : undefined}
              onClick={() => deleteAgent(a.id, a.name)}
              title="Revoke this agent's token and remove its live connections. Recordings and alerts are kept."
            >
              {deleteConfirmId === a.id ? 'Click again to confirm delete' : 'Delete agent'}
            </button>
          </div>
        ))}
        {deleteStatus && <div style={{ fontSize: 13, marginTop: 6 }}>{deleteStatus}</div>}
        <div style={{ fontSize: 12, color: '#94a3b8', marginTop: 4 }}>
          Deleting revokes the agent's token and removes its live connections. A still-running agent will be rejected until re-registered. Recordings and alerts from it are kept as history.
        </div>
      </div>

      {view === 'incoming' && (
        <div style={{ marginBottom: 16 }}>
          <h3>Local services being connected to</h3>
          {groupedIncoming.map(g => (
            <div key={g.service + g.process} style={{ border: '1px solid #1e293b', borderRadius: 6, padding: 8, marginBottom: 6 }}>
              <strong>{g.process}</strong> on {g.service} {g.unit && `(${g.unit})`} {g.container && `[${g.container}]`} —{' '}
              {g.remotes.size} distinct remote(s), {g.count} socket(s)
              <div style={{ color: '#94a3b8', fontSize: 12 }}>{[...g.remotes].slice(0, 10).join(', ')}{g.remotes.size > 10 ? '…' : ''}</div>
            </div>
          ))}
          {groupedIncoming.length === 0 && <p style={{ color: '#94a3b8' }}>No incoming or listening connections in the current filter.</p>}
        </div>
      )}

      <div className="ng-table-wrap">
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
        <thead><tr>
          {COLUMNS.map(col => (
            <th key={col.key} onClick={() => toggleSort(col.key)} style={{ textAlign: 'left', borderBottom: '1px solid #334155', padding: 6, cursor: 'pointer', whiteSpace: 'nowrap' }}>
              {col.label}{sortKey === col.key ? (sortDir === 1 ? ' ▲' : ' ▼') : ''}
            </th>
          ))}
          <th style={{ textAlign: 'left', borderBottom: '1px solid #334155', padding: 6 }}>Flags</th>
        </tr></thead>
        <tbody>
          {filtered.map((c, i) => (
            <tr key={`${c.agentId}-${c.local}-${c.remote}-${c.pid}-${i}`} onClick={() => { setSelected(c); setConfirmKill(false); setKillStatus('') }}
              style={{ background: c.suspicious ? '#450a0a' : c.isGhost ? '#1e293b' : undefined, opacity: c.isGhost ? 0.6 : 1, cursor: 'pointer' }}>
              <td style={{ padding: 6 }}>{c.agentName}</td>
              <td style={{ padding: 6 }}>{c.direction}{c.isGhost ? ' (closed)' : ''}</td>
              <td style={{ padding: 6 }}><strong>{c.process}</strong> <span style={{ color: '#94a3b8' }}>pid {c.pid ?? ''}</span></td>
              <td style={{ padding: 6, maxWidth: 280, color: c.detail ? '#e2e8f0' : '#64748b' }}>{c.detail || '—'}</td>
              <td style={{ padding: 6, maxWidth: 300, overflowWrap: 'anywhere' }}>{c.exe}</td>
              <td style={{ padding: 6 }}>{c.local}</td>
              <td style={{ padding: 6 }}>{c.remote}{c.remoteHost ? <><br /><span style={{ color: '#94a3b8' }}>{c.remoteHost}</span></> : null}</td>
              <td style={{ padding: 6 }}>{c.state}</td>
              <td style={{ padding: 6 }}>{c.firstSeen ? new Date(c.firstSeen).toLocaleString() : ''}</td>
              <td style={{ padding: 6 }}>{c.lastSeen ? new Date(c.lastSeen).toLocaleString() : ''}</td>
              <td style={{ padding: 6 }}>{c.flags.join(', ')}</td>
            </tr>
          ))}
          {filtered.length === 0 && <tr><td colSpan={11} style={{ padding: 12, color: '#94a3b8' }}>No connections match. Connect an agent, or clear the filters.</td></tr>}
        </tbody>
      </table>
      </div>
      </>)}

      {nav === 'recordings' && (
        <div style={{ ...card, marginBottom: 12 }}>
          <h2 style={{ marginTop: 0 }}>Recordings</h2>
          <p style={{ color: '#94a3b8' }}>Recordings save seen + closed events in order, for review after the fact. Start one here, or from the Agents page.</p>
          {activeRecording
            ? <><span>● Recording “{activeRecording.name}” — {activeRecording.eventCount} events</span>{' '}
                <button onClick={() => stopRecording(activeRecording.id)}>Stop</button></>
            : <><input value={recordingName} onChange={e => setRecordingName(e.target.value)} placeholder="Recording name" style={inputStyle} />{' '}
                <button onClick={startRecording} style={{ background: 'linear-gradient(90deg, #2563eb, #0ea5e9)', color: '#fff', border: 'none', borderRadius: 10, padding: '8px 14px', cursor: 'pointer' }}>● Start recording</button></>}
          <div style={{ marginTop: 12 }}>
            {recordings.map(r => (
              <div key={r.id} style={{ fontSize: 13, marginBottom: 6 }}>
                {r.name} ({r.eventCount} events, {r.endedAt ? 'ended' : 'active'}){' '}
                <a href={`/api/recordings/${r.id}/export`}>Export CSV</a>
                {!r.endedAt && <button style={{ marginLeft: 8 }} onClick={() => stopRecording(r.id)}>Stop</button>}
              </div>
            ))}
            {recordings.length === 0 && <p style={{ color: '#94a3b8' }}>No recordings yet.</p>}
          </div>
        </div>
      )}

      {nav === 'settings' && (
        <div style={{ ...card, marginBottom: 12, maxWidth: 700 }}>
          <h2 style={{ marginTop: 0 }}>Settings</h2>
          <h3>Ghost linger</h3>
          <label>How long a closed connection stays visible, faded:{' '}
            <input type="range" min={0} max={300} value={linger} onChange={e => saveLinger(Number(e.target.value))} /> {linger}s
          </label>
          <h3>Live updates</h3>
          <button onClick={() => setPaused(p => !p)}>{paused ? '▶ Resume live updates' : '⏸ Pause live updates'}</button>
          <p style={{ fontSize: 12, color: '#94a3b8' }}>Pause only freezes what is shown. The server, agents, recordings and alerts keep running.</p>
          <h3>Apprise notifications</h3>
          <p style={{ fontSize: 12, color: '#94a3b8' }}>Used for rule alerts. URLs are stored server-side and never shown back in the UI. Leave both blank to disable, or set an Apprise API URL instead of direct URLs.</p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <input value={appriseUrls} onChange={e => setAppriseUrls(e.target.value)} placeholder="Apprise URLs (space-separated, e.g. gotify://…)" style={inputStyle} />
            <input value={appriseApiUrl} onChange={e => setAppriseApiUrl(e.target.value)} placeholder="Apprise API URL (optional, e.g. http://apprise:8080/notify)" style={inputStyle} />
            <div><button onClick={saveApprise}>Save Apprise settings</button></div>
            {appriseStatus && <div style={{ fontSize: 13 }}>{appriseStatus}</div>}
          </div>
          <h3>About this install</h3>
          <p style={{ fontSize: 13, color: '#94a3b8' }}>NetGlass v1 is LAN-trust only — no login yet. Do not expose it to the internet without a reverse proxy with authentication in front of it.</p>
        </div>
      )}

      {nav === 'about' && (
        <div style={{ ...card, marginBottom: 12, maxWidth: 700 }}>
          <h2 style={{ marginTop: 0 }}>About NetGlass</h2>
          <p>Local-first process network visibility. No cloud. Agents on each host report their sockets — process, executable, command line, parent, systemd unit or container, and remote destination — to this central server, which shows them live, with ghosts for recently-closed connections, recordings for review, and Apprise alerts for patterns.</p>
          <ul style={{ fontSize: 14, lineHeight: 1.6 }}>
            <li>Click a row for the full story, including how to kill that process (with a PID + exe + start-time re-check on the agent).</li>
            <li>Reverse DNS is filled in automatically from the local resolver and cached. ip-api.com enrichment is only fetched when you click Fetch for a specific IP, then cached for 30 days.</li>
            <li>Delete an agent from the Agents panel to revoke its token. Recordings and alerts are kept as history.</li>
            <li>Pause freezes the displayed snapshot without losing anything — the server keeps collecting.</li>
          </ul>
          <button onClick={() => setNav('agents')}>← Back to Agents</button>
        </div>
      )}

      {selected && (
        <div className="ng-drawer" style={{ position: 'fixed', right: 16, top: 16, bottom: 16, width: 420, overflow: 'auto', background: '#0d1b33', border: '1px solid #2563eb', borderRadius: 12, padding: 16 }}>
          <button onClick={() => setSelected(null)} style={{ float: 'right' }}>Close (Esc)</button>
          <h2 style={{ marginTop: 0 }}>{selected.process} <span style={{ fontSize: 14, color: '#94a3b8' }}>pid {selected.pid ?? ''}</span></h2>
          <p><strong>{selected.direction}</strong> {selected.proto} {selected.state}<br />{selected.local} → {selected.remote || '—'}{selected.remoteHost ? ` (${selected.remoteHost})` : ''}</p>
          {selected.detail && (
            <div style={{ border: '1px solid #2563eb', borderRadius: 8, padding: 10, marginBottom: 12, background: '#0a1930' }}>
              <strong>What this is:</strong> {selected.detail}
            </div>
          )}
          <h3>Exactly what made this (outgoing) / is being hit (incoming)</h3>
          <dl style={{ fontSize: 13 }}>
            <dt>Executable</dt><dd style={{ overflowWrap: 'anywhere' }}>{selected.exe || '—'} <button onClick={() => navigator.clipboard.writeText(selected.exe)}>Copy</button></dd>
            <dt>Command line</dt><dd style={{ overflowWrap: 'anywhere' }}>{selected.cmdline || '—'}</dd>
            <dt>Parent</dt><dd>{selected.parent} (pid {selected.ppid ?? ''}) — {selected.parentExe || '—'}</dd>
            <dt>User / unit / container</dt><dd>{selected.user || '—'} / {selected.unit || '—'} / {selected.container || selected.containerId || '—'}</dd>
            <dt>Process started</dt><dd>{selected.started ? new Date(selected.started).toLocaleString() : '—'}</dd>
            <dt>First / last seen</dt><dd>{selected.firstSeen ? new Date(selected.firstSeen).toLocaleString() : ''} / {selected.lastSeen ? new Date(selected.lastSeen).toLocaleString() : ''}</dd>
            <dt>Flags</dt><dd>{selected.flags.join(', ') || '—'}</dd>
          </dl>
          <h3>IP info — {parseIp(selected.remote) ?? 'no remote IP'} (ip-api.com, on demand)</h3>
          <p style={{ fontSize: 12, color: '#94a3b8' }}>
            Reverse DNS for the remote IP is filled in automatically from the server's local resolver and cached.
            The ip-api enrichment below (ISP, org, ASN, country, city) is <strong>never</strong> fetched automatically —
            it only runs when you click Fetch for this IP, and the result is cached for 30 days. Private IPs are never sent to ip-api.
          </p>
          {!parseIp(selected.remote) && <p style={{ fontSize: 13 }}>No remote IP on this row (listener / local connection).</p>}
          {parseIp(selected.remote) && !ipInfo && !ipInfoMsg.toLowerCase().includes('private') && (
            <button className="primary" disabled={ipInfoLoading} onClick={() => fetchIpInfo(false)}>
              {ipInfoLoading ? 'Fetching…' : `Fetch IP info for ${parseIp(selected.remote)}`}
            </button>
          )}
          {ipInfo && (
            <div style={{ fontSize: 13 }}>
              <dl>
                <dt>ISP</dt><dd>{ipInfo.isp || '—'}</dd>
                <dt>Organization</dt><dd>{ipInfo.org || '—'}</dd>
                <dt>ASN</dt><dd>{ipInfo.as || '—'}</dd>
                <dt>Country</dt><dd>{ipInfo.country ? `${ipInfo.country} (${ipInfo.countryCode})` : '—'}</dd>
                <dt>City / region</dt><dd>{[ipInfo.city, ipInfo.region].filter(Boolean).join(', ') || '—'}</dd>
                <dt>Timezone</dt><dd>{ipInfo.timezone || '—'}</dd>
                <dt>Reverse hostname</dt><dd>{ipInfo.reverse || '—'}</dd>
                <dt>Cached</dt><dd>{ipInfo.fetchedAt ? new Date(ipInfo.fetchedAt).toLocaleString() : ''} — expires {ipInfo.expiresAt ? new Date(ipInfo.expiresAt).toLocaleDateString() : ''}</dd>
              </dl>
              <button disabled={ipInfoLoading} onClick={() => fetchIpInfo(true)}>{ipInfoLoading ? 'Refreshing…' : 'Refresh IP info'}</button>
            </div>
          )}
          {ipInfoMsg && <p style={{ fontSize: 13 }}>{ipInfoMsg}</p>}
          <h3>How to kill it</h3>
          {killCommands(selected).map(cmd => (
            <div key={cmd} style={{ fontFamily: 'monospace', fontSize: 13, marginBottom: 4 }}>{cmd} <button onClick={() => navigator.clipboard.writeText(cmd)}>Copy</button></div>
          ))}
          <label><input type="checkbox" checked={confirmKill} onChange={e => setConfirmKill(e.target.checked)} /> I understand this kills PID {selected.pid} on {selected.agentName} after the agent re-checks exe + start time.</label>
          <div style={{ marginTop: 8 }}>
            <button className="danger" disabled={!confirmKill || !selected.pid} onClick={() => doKill(selected)}>Kill this process</button>
          </div>
          {killStatus && <p style={{ fontSize: 13 }}>{killStatus}</p>}
          <p style={{ fontSize: 12, color: '#94a3b8' }}>If the process belongs to a systemd unit or container, stopping the unit/container is usually safer than killing the PID — it will not just restart.</p>
        </div>
      )}
      </main>
    </div>
  )
}
