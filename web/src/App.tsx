import { useCallback, useEffect, useMemo, useState } from 'react'

type Conn = {
  agentId: string; agentName: string; direction: string; proto: string; state: string
  local: string; remote: string; remoteHost: string
  pid?: number | null; process: string; exe: string; cmdline: string; user: string
  ppid?: number | null; parent: string; parentExe: string
  unit: string; container: string; containerId: string
  started?: string | null; firstSeen: string; lastSeen: string
  isGhost: boolean; isNew: boolean; suspicious: boolean; flags: string[]
  detail?: string; signature?: string
  score?: number; tier?: string; findings?: Finding[]
  isWhitelisted?: boolean; isHidden?: boolean
}
type AppPref = { agentId: string; agentName: string; exe: string; process: string; kind: string; createdAt: string }
type Finding = {
  ruleId: string; title: string; category: string; engine: string
  severity: string; score: number; evidence: string; explanation: string
}
type CheckItem = {
  id: string; title: string; category: string; engine: string
  severity: string; score: number; description: string
  enabled: boolean; unavailableReason?: string | null
}
type Agent = { id: string; name: string; hostname: string; os: string; version: string; lastSeen: string; socketCount: number }
type Recording = { id: string; name: string; startedAt: string; endedAt?: string | null; eventCount: number }
type AlertItem = { at: string; rule: string; message: string; agent: string; detail: string }
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

type SortKey = 'agentName' | 'direction' | 'process' | 'score' | 'detail' | 'exe' | 'local' | 'remote' | 'state' | 'firstSeen' | 'lastSeen'

const COLUMNS: { key: SortKey; label: string }[] = [
  { key: 'agentName', label: 'Agent' }, { key: 'direction', label: 'Direction' },
  { key: 'process', label: 'Process' }, { key: 'score', label: 'Score' }, { key: 'detail', label: 'Detail' }, { key: 'exe', label: 'Executable' },
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
  const [alerts, setAlerts] = useState<AlertItem[]>([])
  const [checks, setChecks] = useState<CheckItem[]>([])
  const [appPrefs, setAppPrefs] = useState<AppPref[]>([])
  const [showHidden, setShowHidden] = useState(false)
  const [prefStatus, setPrefStatus] = useState('')
  // Triage-first: Attention is the default view. It shows only rows
  // with a reason to care (suspicious, new, public, uncommon port).
  // All / flat is always one tap away, and the drawer still carries
  // the full detail for every row — nothing is hidden, only grouped.
  const [view, setView] = useState<'attention' | 'all' | 'outgoing' | 'incoming' | 'listeners' | 'suspicious'>('attention')
  const [nav, setNav] = useState<'agents' | 'alerts' | 'checks' | 'prefs' | 'manage' | 'recordings' | 'settings' | 'about'>('agents')
  const [grouped, setGrouped] = useState(true)
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set())
  const [showColumns, setShowColumns] = useState(false)
  const [visibleCols, setVisibleCols] = useState<SortKey[]>(() => {
    try {
      const saved = localStorage.getItem('ng-columns')
      if (saved) { const parsed = JSON.parse(saved) as string[]; const valid = parsed.filter(c => COLUMNS.some(col => col.key === c)) as SortKey[]; if (valid.length) return valid }
    } catch { /* fall through to defaults */ }
    return ['agentName', 'direction', 'process', 'score', 'detail', 'remote']
  })
  const [appriseUrls, setAppriseUrls] = useState('')
  const [appriseApiUrl, setAppriseApiUrl] = useState('')
  const [appriseStatus, setAppriseStatus] = useState('')
  const [q, setQ] = useState('')
  const [agentFilter, setAgentFilter] = useState('')
  const [sortKey, setSortKey] = useState<SortKey>('lastSeen')
  const [sortDir, setSortDir] = useState<1 | -1>(-1)
  const [selected, setSelected] = useState<Conn | null>(null)
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
      const [c, a, r, al, ch, pr] = await Promise.all([
        fetch(showHidden ? '/api/connections?includeHidden=true' : '/api/connections').then(x => x.json()),
        fetch('/api/agents').then(x => x.json()),
        fetch('/api/recordings').then(x => x.json()),
        fetch('/api/alerts').then(x => x.json()).catch(() => []),
        fetch('/api/checks').then(x => x.json()).catch(() => []),
        fetch('/api/app-prefs').then(x => x.json()).catch(() => []),
      ])
      setConns(c.connections ?? []); setCounts(c.counts ?? {})
      setAgents(a ?? []); setRecordings(r ?? []); setAlerts(Array.isArray(al) ? al : [])
      setChecks(Array.isArray(ch) ? ch : [])
      setAppPrefs(Array.isArray(pr) ? pr : [])
      setLastUpdated(new Date())
    } catch { /* server down: keep last state, UI shows stale counts */ }
  }, [showHidden])

  useEffect(() => {
    try { localStorage.setItem('ng-columns', JSON.stringify(visibleCols)) } catch { /* private mode */ }
  }, [visibleCols])

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

  const isAttention = (c: Conn) =>
    !c.isWhitelisted && !c.isHidden && (
    c.tier === 'High' || c.tier === 'Medium' || c.suspicious || c.isNew ||
    c.flags.includes('PUBLIC') || c.flags.includes('UNCOMMON_PORT') ||
    c.flags.includes('TMP_EXE') || c.flags.includes('DELETED_EXE') || c.flags.includes('NO_EXE'))

  const filtered = useMemo(() => {
    let rows = showHidden ? conns : conns.filter(c => !c.isHidden)
    if (view === 'attention') rows = rows.filter(isAttention)
    if (view === 'outgoing') rows = rows.filter(c => c.direction === 'outbound')
    if (view === 'incoming') rows = rows.filter(c => c.direction === 'inbound' || c.direction === 'listen')
    if (view === 'listeners') rows = rows.filter(c => c.direction === 'listen')
    if (view === 'suspicious') rows = rows.filter(c => c.suspicious && !c.isWhitelisted && !c.isHidden)
    if (agentFilter) rows = rows.filter(c => c.agentId === agentFilter)
    if (q) {
      const needle = q.toLowerCase()
      rows = rows.filter(c => [c.process, c.exe, c.cmdline, c.remote, c.remoteHost, c.local, c.unit, c.container, c.agentName, String(c.pid ?? ''), c.detail ?? ''].join(' ').toLowerCase().includes(needle))
    }
    const sorted = [...rows].sort((a, b) => {
      if (view === 'attention') {
        const sd = (b.score ?? 0) - (a.score ?? 0)
        if (sd !== 0) return sd
      }
      const av = String((a as unknown as Record<string, unknown>)[sortKey] ?? '')
      const bv = String((b as unknown as Record<string, unknown>)[sortKey] ?? '')
      return av.localeCompare(bv) * sortDir
    })
    return sorted
  }, [conns, view, agentFilter, q, sortKey, sortDir, showHidden])

  // Grouped view: collapse repeats of the same service into one row.
  // Grouping is display-only — expanding a group shows its individual
  // sockets, and clicking any socket opens the full drawer.
  const groups = useMemo(() => {
    const map = new Map<string, { key: string; agentName: string; process: string; detail: string; container: string; exe: string; count: number; suspicious: number; isNew: number; ghosts: number; listeners: number; maxScore: number; tier: string; remotes: Set<string>; rows: Conn[] }>()
    for (const c of filtered) {
      const key = `${c.agentId}|${c.process}|${c.detail || c.container || c.exe}`
      const g = map.get(key) ?? { key, agentName: c.agentName, process: c.process, detail: c.detail ?? '', container: c.container, exe: c.exe, count: 0, suspicious: 0, isNew: 0, ghosts: 0, listeners: 0, maxScore: 0, tier: 'None', remotes: new Set(), rows: [] }
      g.count++; if (c.suspicious) g.suspicious++; if (c.isNew) g.isNew++; if (c.isGhost) g.ghosts++; if (c.direction === 'listen') g.listeners++; if ((c.score ?? 0) > g.maxScore) { g.maxScore = c.score ?? 0; g.tier = c.tier ?? 'None' }
      if (c.remote) g.remotes.add(c.remote)
      g.rows.push(c)
      map.set(key, g)
    }
    return [...map.values()].sort((a, b) => (b.maxScore - a.maxScore) || (b.suspicious - a.suspicious) || (b.isNew - a.isNew) || (b.count - a.count))
  }, [filtered])

  const summary = useMemo(() => {
    const live = conns.filter(c => !c.isWhitelisted && !c.isHidden)
    const suspicious = live.filter(c => c.suspicious).length
    const newListeners = live.filter(c => c.isNew && c.direction === 'listen').length
    const publicListeners = live.filter(c => c.flags.includes('PUBLIC')).length
    const newDestinations = live.filter(c => c.isNew && c.direction === 'outbound').length
    const parts: string[] = []
    if (suspicious) parts.push(`${suspicious} suspicious`)
    if (newListeners) parts.push(`${newListeners} new listener${newListeners === 1 ? '' : 's'}`)
    if (publicListeners) parts.push(`${publicListeners} public listener${publicListeners === 1 ? '' : 's'}`)
    if (newDestinations) parts.push(`${newDestinations} new outbound destination${newDestinations === 1 ? '' : 's'}`)
    if (alerts.length) parts.push(`${alerts.length} rule alert${alerts.length === 1 ? '' : 's'}`)
    return { parts, total: conns.length, agents: agents.length, ghosts: conns.filter(c => c.isGhost).length }
  }, [conns, agents, alerts])

  const flagWhy: Record<string, string> = {
    NEW: 'First seen in the last 24 hours — new to this host.',
    LISTENER: 'Listening for incoming connections.',
    TMP_EXE: 'Executable is in a temporary directory — a common malware tactic.',
    DELETED_EXE: 'Executable was deleted from disk while still running — suspicious.',
    NO_EXE: 'No executable could be found for this process.',
    PUBLIC: 'Listening on a public interface — reachable from other machines.',
    UNCOMMON_PORT: 'Port is not a well-known service port.',
  }

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

  // Hide / whitelist actions. Identity is agent + exe path, so
  // hiding an app on one host does not affect the same app on
  // another. Apps with no exe path cannot be acted on: an empty
  // exe key would match every unknown process on that host.
  // Restoring is a DELETE of the pref; it takes effect on the
  // next agent snapshot (~2s), with history intact.
  async function setAppPref(agentId: string, exe: string, process: string, kind: 'hide' | 'whitelist') {
    const res = await fetch('/api/app-prefs', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ agentId, exe, process, kind }) })
    if (!res.ok) { setPrefStatus('Could not save that preference.'); return }
    setPrefStatus(kind === 'hide'
      ? `Hidden ${process || exe} — its connections will disappear from Agents, Attention and alerts on the next snapshot. Recordings are kept, and you can restore it from Hidden & whitelisted.`
      : `Whitelisted ${process || exe} — its connections stay visible but are no longer scored and will not appear in Attention or trigger alerts.`)
    setSelected(null); load()
  }
  async function clearAppPref(agentId: string, exe: string, process: string) {
    await fetch(`/api/app-prefs?agentId=${encodeURIComponent(agentId)}&exe=${encodeURIComponent(exe)}`, { method: 'DELETE' })
    setPrefStatus(`Restored ${process || exe} — normal scoring and display resume on the next snapshot.`)
    setSelected(null); load()
  }
  async function restoreAllPrefs(kind: 'hide' | 'whitelist') {
    const targets = appPrefs.filter(p => p.kind === kind)
    for (const p of targets)
      await fetch(`/api/app-prefs?agentId=${encodeURIComponent(p.agentId)}&exe=${encodeURIComponent(p.exe)}`, { method: 'DELETE' })
    setPrefStatus(targets.length
      ? `Restored all ${targets.length} ${kind === 'hide' ? 'hidden' : 'whitelisted'} app${targets.length === 1 ? '' : 's'}.`
      : `Nothing to restore.`)
    load()
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

  // One cell renderer for both grouped and flat tables, so the
  // visible-columns picker applies everywhere. Full detail for any
  // row is always in the drawer, regardless of visible columns.
  const cellFor = (c: Conn, key: SortKey) => {
    switch (key) {
      case 'agentName': return c.agentName
      case 'direction': return <>{c.direction}{c.isGhost ? ' (closed)' : ''}</>
      case 'process': return <><strong>{c.process}</strong> <span style={{ color: '#94a3b8' }}>pid {c.pid ?? ''}</span>{c.isHidden ? <span style={{ color: '#94a3b8', fontSize: 12 }}> · Hidden</span> : null}{c.isWhitelisted ? <span style={{ color: '#34d399', fontSize: 12 }}> · Whitelisted</span> : null}</>
      case 'score': return c.isWhitelisted ? <span style={{ color: '#34d399', fontSize: 12 }}>Whitelisted</span> : (c.score ?? 0) > 0 ? <><strong style={{ color: c.tier === 'High' ? '#f87171' : c.tier === 'Medium' ? '#fbbf24' : '#94a3b8' }}>{c.score}</strong> <span style={{ color: '#94a3b8', fontSize: 12 }}>{c.tier}</span></> : '—'
      case 'detail': return <span style={{ color: c.detail ? '#e2e8f0' : '#64748b' }}>{c.detail || '—'}</span>
      case 'exe': return <span style={{ overflowWrap: 'anywhere' }}>{c.exe}</span>
      case 'local': return c.local
      case 'remote': return <>{c.remote}{c.remoteHost ? <><br /><span style={{ color: '#94a3b8' }}>{c.remoteHost}</span></> : null}</>
      case 'state': return c.state
      case 'firstSeen': return c.firstSeen ? new Date(c.firstSeen).toLocaleString() : ''
      case 'lastSeen': return c.lastSeen ? new Date(c.lastSeen).toLocaleString() : ''
    }
  }
  const rowStyle = (c: Conn): React.CSSProperties => ({
    background: c.suspicious && !c.isWhitelisted ? '#450a0a' : c.isGhost ? '#1e293b' : undefined,
    opacity: (c.isGhost || c.isHidden) ? 0.6 : 1, cursor: 'pointer',
    borderLeft: c.tier === 'High' ? '4px solid #ef4444' : c.tier === 'Medium' ? '4px solid #f59e0b' : isAttention(c) ? '4px solid #f59e0b' : '4px solid transparent',
  })
  const openRow = (c: Conn) => { setSelected(c); setConfirmKill(false); setKillStatus('') }

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
      <aside className="ng-sidebar" style={{ width: 230, flexShrink: 0, padding: 20, borderRight: '1px solid #1e293b', display: 'flex', flexDirection: 'column', gap: 8 }}>
        <div className="ng-logo" style={{ marginBottom: 12 }}>
          <img src="/logo.png" width="72" height="72" alt="NetGlass logo" style={{ borderRadius: 16, display: "block" }} />
          <div style={{ fontSize: 26, fontWeight: 800, marginTop: 4 }}>Net<span style={{ color: '#22d3ee' }}>Glass</span></div>
        </div>
        <div className="ng-nav" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {navItem('agents', 'Agents', '▣')}
        {navItem('alerts', `Alerts${alerts.length ? ` (${alerts.length})` : ''}`, '⚠')}
        {navItem('checks', 'Checks', '⬡')}
        {navItem('prefs', `Hidden & whitelisted${appPrefs.length ? ` (${appPrefs.length})` : ''}`, '🛡')}
        {navItem('manage', 'Manage agents', '⚙')}
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
      {nav === 'agents' && (
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', marginBottom: 12 }}>
          <button onClick={() => setNav('manage')} style={{ background: 'linear-gradient(90deg, #2563eb, #0ea5e9)', color: '#fff', border: 'none', borderRadius: 12, padding: '10px 16px', fontWeight: 700, cursor: 'pointer' }}>+ Add agent</button>
          <button onClick={() => setPaused(p => !p)} style={{ ...card, fontWeight: 700, cursor: 'pointer' }}>
            {paused ? '▶ Resume live updates' : '⏸ Pause live updates'}
          </button>
          <button onClick={() => setGrouped(g => !g)} style={{ ...card, cursor: 'pointer' }}>
            {grouped ? '▤ Grouped by service' : '☰ All sockets (flat)'}
          </button>
          <button onClick={() => setShowColumns(v => !v)} style={{ ...card, cursor: 'pointer' }}>Columns ▾</button>
          <button onClick={() => setShowHidden(v => !v)} style={{ ...card, cursor: 'pointer' }}>
            {showHidden ? '👁 Showing hidden apps' : '⊘ Show hidden apps'}
          </button>
        </div>
      )}
      {prefStatus && nav === 'agents' && (
        <div style={{ ...card, marginBottom: 12 }}>
          {prefStatus} <button onClick={() => setPrefStatus('')}>Dismiss</button>
        </div>
      )}

      {nav === 'agents' && (<>
      <div className="ng-stats" style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 12 }}>
        {([
          ['Total', counts.total, '🖥'], ['Outbound', counts.outbound, '✓'], ['Inbound', counts.inbound, '←'],
          ['Listeners', counts.listen, '👥'], ['Suspicious', conns.filter(c => c.suspicious && !c.isWhitelisted && !c.isHidden).length, '⬡'],
          ['New (24h)', conns.filter(c => c.isNew && !c.isWhitelisted && !c.isHidden).length, '◷'],
          ['Ghosts', conns.filter(c => c.isGhost).length, '👻'],
        ] as const).map(([label, value, icon]) => (
          <div key={label} style={{ ...card, textAlign: 'left', display: 'flex', gap: 10, alignItems: 'center', flex: '1 1 110px' }}>
            <span style={{ fontSize: 20 }}>{icon}</span>
            <span><div style={{ fontSize: 22, fontWeight: 700 }}>{value ?? 0}</div><div style={{ fontSize: 12, color: '#94a3b8' }}>{label}</div></span>
          </div>
        ))}
      </div>

      {paused && (
        <div style={{ border: '1px solid #f59e0b', borderRadius: 12, padding: 10, marginBottom: 12, background: '#422006' }}>
          <strong>⏸ Paused</strong> — showing the snapshot from {lastUpdated ? lastUpdated.toLocaleTimeString() : 'the last load'}.
          No new connections will appear until you resume. The server, agents, recordings and alerts keep running in the background, so nothing is lost — resuming shows the latest state.
        </div>
      )}

      <div style={{ ...card, marginBottom: 12, borderColor: summary.parts.length ? '#f59e0b' : '#1e3a5f' }}>
        <strong>{summary.parts.length ? `⚠ ${summary.parts.join(' · ')}` : '✓ Nothing concerning right now.'}</strong>
        <span style={{ color: '#94a3b8', fontSize: 13 }}> — {summary.total} connections across {summary.agents} agent{summary.agents === 1 ? '' : 's'}, {summary.ghosts} ghost{summary.ghosts === 1 ? '' : 's'}.</span>
        {view !== 'attention' && <button onClick={() => setView('attention')} style={{ marginLeft: 8 }}>Show attention only</button>}
        {grouped && <span style={{ color: '#94a3b8', fontSize: 13 }}> Grouped by service — expand a group, then click a socket for its full detail.</span>}
        {!grouped && <span style={{ color: '#94a3b8', fontSize: 13 }}> Flat list — every socket, with all visible columns, click any row for its full detail.</span>}
      </div>

      <div className="ng-filters" style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 12, alignItems: 'center' }}>
        {([['attention', 'Attention'], ['all', 'All'], ['outgoing', 'Outgoing'], ['incoming', 'Incoming'], ['listeners', 'Listeners'], ['suspicious', 'Suspicious']] as const).map(([key, label]) => (
          <button key={key} onClick={() => setView(key)} disabled={view === key} style={{ background: view === key ? '#2563eb' : '#0d1b33', color: '#fff', border: '1px solid #1e3a5f', borderRadius: 10, padding: '8px 14px', cursor: 'pointer' }}>{label}</button>
        ))}
        <input id="search" value={q} onChange={e => setQ(e.target.value)} placeholder="Search…  ( / to focus )" style={{ ...inputStyle, flex: 1, minWidth: 240 }} />
        <select value={agentFilter} onChange={e => setAgentFilter(e.target.value)} style={inputStyle}>
          <option value="">All agents</option>
          {agents.map(a => <option key={a.id} value={a.id}>{a.name} ({a.hostname || a.id.slice(0, 8)})</option>)}
        </select>

      </div>
      {showColumns && (
        <div style={{ ...card, marginBottom: 12 }}>
          <strong>Columns</strong> <span style={{ color: '#94a3b8', fontSize: 12 }}>— defaults are Agent, Direction, Process, Score, Detail, Remote. Everything else is always in the drawer.</span>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 8 }}>
            {COLUMNS.map(col => (
              <label key={col.key}><input type="checkbox" checked={visibleCols.includes(col.key)} onChange={e => setVisibleCols(v => e.target.checked ? [...v, col.key] : v.filter(c => c !== col.key))} /> {col.label}</label>
            ))}
          </div>
          <div style={{ marginTop: 8 }}>
            <button onClick={() => setVisibleCols(['agentName', 'direction', 'process', 'score', 'detail', 'remote'])}>Reset to defaults</button>{' '}
            <button onClick={() => setVisibleCols(COLUMNS.map(c => c.key))}>Show all columns</button>
          </div>
        </div>
      )}
      </>)}

      {nav === 'agents' && (<>
      {activeRecording && (
        <div style={{ ...card, marginBottom: 12 }}>
          <span>● Recording “{activeRecording.name}” — {activeRecording.eventCount} events</span>{' '}
          <button onClick={() => stopRecording(activeRecording.id)}>Stop</button>{' '}
          <button onClick={() => setNav('recordings')}>Recordings →</button>
        </div>
      )}

      {grouped ? (
        <div>
          {groups.map(g => {
            const expanded = expandedGroups.has(g.key)
            return (
              <div key={g.key} style={{ ...card, marginBottom: 8, borderLeft: g.tier === 'High' ? '4px solid #ef4444' : (g.tier === 'Medium' || g.isNew ? '4px solid #f59e0b' : undefined) }}>
                <button onClick={() => setExpandedGroups(prev => { const next = new Set(prev); if (next.has(g.key)) next.delete(g.key); else next.add(g.key); return next })} style={{ background: 'transparent', border: 'none', color: '#e2e8f0', cursor: 'pointer', textAlign: 'left', width: '100%', padding: 0 }}>
                  <span style={{ fontSize: 16 }}>{expanded ? '▾' : '▸'} <strong>{g.process}</strong></span>{' '}
                  {g.maxScore > 0 && <span style={{ color: g.tier === 'High' ? '#f87171' : '#fbbf24', fontWeight: 700 }}>{g.maxScore} ({g.tier})</span>}{' '}
                  <span style={{ color: '#94a3b8' }}>{g.agentName}{g.detail ? ` — ${g.detail}` : g.container ? ` — ${g.container}` : ''}</span>
                  <div style={{ fontSize: 13, color: '#94a3b8', marginTop: 4 }}>
                    {g.count} socket{g.count === 1 ? '' : 's'}
                    {g.listeners ? ` · ${g.listeners} listener${g.listeners === 1 ? '' : 's'}` : ''}
                    {g.suspicious ? ` · ⚠ ${g.suspicious} suspicious` : ''}
                    {g.isNew ? ` · ${g.isNew} new` : ''}
                    {g.ghosts ? ` · ${g.ghosts} closed` : ''}
                    {g.remotes.size ? ` · ${g.remotes.size} remote${g.remotes.size === 1 ? '' : 's'}` : ''}
                  </div>
                </button>
                {expanded && (
                  <div className="ng-table-wrap" style={{ marginTop: 8 }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                      <thead><tr>
                        {COLUMNS.filter(col => visibleCols.includes(col.key)).map(col => (
                          <th key={col.key} onClick={() => toggleSort(col.key)} style={{ textAlign: 'left', borderBottom: '1px solid #334155', padding: 6, cursor: 'pointer', whiteSpace: 'nowrap' }}>
                            {col.label}{sortKey === col.key ? (sortDir === 1 ? ' ▲' : ' ▼') : ''}
                          </th>
                        ))}
                        <th style={{ textAlign: 'left', borderBottom: '1px solid #334155', padding: 6 }}>Flags</th>
                      </tr></thead>
                      <tbody>
                        {g.rows.map((c, i) => (
                          <tr key={`${c.agentId}-${c.local}-${c.remote}-${c.pid}-${i}`} onClick={() => openRow(c)} style={rowStyle(c)}>
                            {visibleCols.map(col => <td key={col} style={{ padding: 6, maxWidth: 300 }}>{cellFor(c, col)}</td>)}
                            <td style={{ padding: 6 }}>{c.flags.join(', ')}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    <p style={{ fontSize: 12, color: '#94a3b8' }}>Click any socket for its full detail — executable, command line, parent, unit/container, timestamps, kill, and IP info.</p>
                  </div>
                )}
              </div>
            )
          })}
          {groups.length === 0 && <p style={{ color: '#94a3b8' }}>No groups match. Try Attention → All, or clear the search.</p>}
        </div>
      ) : (
        <div className="ng-table-wrap">
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead><tr>
              {COLUMNS.filter(col => visibleCols.includes(col.key)).map(col => (
                <th key={col.key} onClick={() => toggleSort(col.key)} style={{ textAlign: 'left', borderBottom: '1px solid #334155', padding: 6, cursor: 'pointer', whiteSpace: 'nowrap' }}>
                  {col.label}{sortKey === col.key ? (sortDir === 1 ? ' ▲' : ' ▼') : ''}
                </th>
              ))}
              <th style={{ textAlign: 'left', borderBottom: '1px solid #334155', padding: 6 }}>Flags</th>
            </tr></thead>
            <tbody>
              {filtered.map((c, i) => (
                <tr key={`${c.agentId}-${c.local}-${c.remote}-${c.pid}-${i}`} onClick={() => openRow(c)} style={rowStyle(c)}>
                  {visibleCols.map(col => <td key={col} style={{ padding: 6, maxWidth: 300 }}>{cellFor(c, col)}</td>)}
                  <td style={{ padding: 6 }}>{c.flags.join(', ')}</td>
                </tr>
              ))}
              {filtered.length === 0 && <tr><td colSpan={visibleCols.length + 1} style={{ padding: 12, color: '#94a3b8' }}>No connections match. Try Attention → All, or clear the filters.</td></tr>}
            </tbody>
          </table>
        </div>
      )}
      </>)}

      {nav === 'alerts' && (
        <div style={{ ...card, marginBottom: 12 }}>
          <h2 style={{ marginTop: 0 }}>Alerts</h2>
          <p style={{ color: '#94a3b8' }}>Rule hits saved by the server (latest 200). Apprise notifications, if configured, fire for the same hits. Click “Find connection” to jump to that connection in the flat Agents list — if it has already closed, it will be a ghost or gone, and this alert is the remaining record.</p>
          {alerts.map((a, i) => (
            <div key={`${a.at}-${i}`} style={{ border: '1px solid #1e3a5f', borderRadius: 8, padding: 10, marginBottom: 8 }}>
              <strong>{a.rule}</strong> <span style={{ color: '#94a3b8', fontSize: 13 }}>{a.at ? new Date(a.at).toLocaleString() : ''} · {a.agent}</span>
              <div style={{ fontSize: 14, marginTop: 4 }}>{a.message}</div>
              {a.detail && <div style={{ fontSize: 12, color: '#94a3b8' }}>{a.detail}</div>}
              <button style={{ marginTop: 6 }} onClick={() => {
                const ag = agents.find(x => x.name === a.agent)
                if (ag) setAgentFilter(ag.id)
                const pid = a.detail.split(' ')[0]
                if (/^\d+$/.test(pid)) setQ(pid)
                setGrouped(false); setView('all'); setNav('agents')
              }}>Find connection →</button>
            </div>
          ))}
          {alerts.length === 0 && <p style={{ color: '#94a3b8' }}>No rule alerts yet.</p>}
        </div>
      )}

      {nav === 'checks' && (
        <div style={{ ...card, marginBottom: 12 }}>
          <h2 style={{ marginTop: 0 }}>Checks — modular threat detection</h2>
          <p style={{ color: '#94a3b8' }}>
            Each check is one independent rule: it returns a finding (rule, severity, score, evidence, explanation) or nothing.
            A new check is one class + one registration line — no ingest logic to edit. A high score means <strong>investigate</strong>, not confirmed malware.
            Scores are starting defaults and are tunable per check in code. Disabled checks stay listed here.
          </p>
          {(['Process', 'Destination', 'PortProtocol', 'Behavior', 'Listening', 'Ghost'] as const).map(cat => (
            <div key={cat} style={{ marginBottom: 16 }}>
              <h3>{cat === 'PortProtocol' ? 'Port / Protocol' : cat}</h3>
              {checks.filter(c => c.category === cat).map(c => (
                <div key={c.id} style={{ border: '1px solid #1e3a5f', borderRadius: 8, padding: 10, marginBottom: 8, opacity: c.enabled ? 1 : 0.6 }}>
                  <strong>{c.title}</strong> <span style={{ color: '#94a3b8', fontSize: 12 }}>{c.id} · {c.engine} · {c.severity} · +{c.score}</span>
                  <div style={{ fontSize: 13, marginTop: 4 }}>{c.description}</div>
                  {c.unavailableReason && <div style={{ fontSize: 12, color: '#fbbf24', marginTop: 4 }}>⚠ {c.unavailableReason}</div>}
                  <button style={{ marginTop: 6 }} onClick={async () => {
                    await fetch(`/api/checks/${c.id}/toggle`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled: !c.enabled }) })
                    load()
                  }}>{c.enabled ? 'Disable check' : 'Enable check'}</button>
                </div>
              ))}
              {checks.filter(c => c.category === cat).length === 0 && <p style={{ color: '#94a3b8', fontSize: 13 }}>No checks in this category yet (server may be on an older build).</p>}
            </div>
          ))}
        </div>
      )}

      {nav === 'manage' && (<>
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

        <div style={{ ...card, marginBottom: 12 }}>
          <strong>Agents</strong>
          <span style={{ color: '#94a3b8', fontSize: 12 }}> — last updated {lastUpdated ? lastUpdated.toLocaleTimeString() : 'never'}{paused ? ' (paused)' : ''}</span>
          {agents.length === 0 && <span style={{ color: '#94a3b8' }}> — none connected.</span>}
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

      {nav === 'prefs' && (
        <div style={{ ...card, marginBottom: 12 }}>
          <h2 style={{ marginTop: 0 }}>Hidden &amp; whitelisted apps</h2>
          <p style={{ color: '#94a3b8' }}>
            Nothing here is deleted. <strong>Hidden</strong> apps disappear from Agents, Attention, counts and rule alerts, but are still
            collected and recorded — restoring one brings it back with its history intact. <strong>Whitelisted</strong> apps stay visible,
            but their connections are never scored, never appear in Attention, and never trigger rule alerts. Use whitelist for known-good
            noisy apps, hide for apps you simply do not want to look at. A preference applies to one agent + executable path only, so the
            same app on another host is unaffected. Changes take effect on the next agent snapshot (about 2 seconds).
          </p>
          {prefStatus && <div style={{ marginBottom: 12 }}>{prefStatus}</div>}
          {(['hide', 'whitelist'] as const).map(kind => (
            <div key={kind} style={{ marginBottom: 16 }}>
              <h3>{kind === 'hide' ? 'Hidden apps' : 'Whitelisted apps'}</h3>
              {appPrefs.filter(p => p.kind === kind).length === 0 && (
                <p style={{ color: '#94a3b8', fontSize: 13 }}>
                  {kind === 'hide' ? 'No hidden apps. Hide one from its detail drawer on the Agents page.' : 'No whitelisted apps. Whitelist one from its detail drawer on the Agents page.'}
                </p>
              )}
              {appPrefs.filter(p => p.kind === kind).map(p => (
                <div key={`${p.agentId}|${p.exe}`} style={{ border: '1px solid #1e3a5f', borderRadius: 8, padding: 10, marginBottom: 8, fontSize: 13 }}>
                  <strong>{p.process || p.exe}</strong> <span style={{ color: '#94a3b8' }}>on {p.agentName || p.agentId.slice(0, 8)} · since {p.createdAt ? new Date(p.createdAt).toLocaleString() : ''}</span>
                  <div style={{ overflowWrap: 'anywhere', color: '#94a3b8', marginTop: 4 }}>{p.exe}</div>
                  <div style={{ marginTop: 6, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    <button onClick={() => clearAppPref(p.agentId, p.exe, p.process)}>Restore app</button>
                    <button onClick={() => setAppPref(p.agentId, p.exe, p.process, kind === 'hide' ? 'whitelist' : 'hide')}>
                      {kind === 'hide' ? 'Whitelist instead' : 'Hide instead'}
                    </button>
                  </div>
                </div>
              ))}
              {appPrefs.filter(p => p.kind === kind).length > 0 && (
                <button onClick={() => restoreAllPrefs(kind)}>Restore all {kind === 'hide' ? 'hidden' : 'whitelisted'} apps</button>
              )}
            </div>
          ))}
          <p style={{ fontSize: 12, color: '#94a3b8' }}>
            Lost something? Turn on “Show hidden apps” on the Agents page to see hidden rows muted in the list, or restore them here.
            Deleting an agent also removes its app preferences.
          </p>
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
            <li>Attention is the default view — only suspicious, new, public, or uncommon-port rows. Grouped by service by default; switch to All sockets for the flat list. Neither hides anything: expand a group, click a socket, and the drawer still shows the full executable, command line, parent, unit/container, timestamps, kill, and IP info.</li>
            <li>Click a row for the full story, including how to kill that process (with a PID + exe + start-time re-check on the agent).</li>
            <li>Reverse DNS is filled in automatically from the local resolver and cached. ip-api.com enrichment is only fetched when you click Fetch for a specific IP, then cached for 30 days.</li>
            <li>Delete an agent from the Agents panel to revoke its token. Recordings and alerts are kept as history.</li>
            <li>Pause freezes the displayed snapshot without losing anything — the server keeps collecting.</li>
            <li>Hide or whitelist an app from its detail drawer: hidden apps vanish from the list (but are still recorded), whitelisted apps stay visible but are never scored. Both are reversible in one click from Hidden &amp; whitelisted, or by restoring all of a kind at once.</li>
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
          {(selected.score ?? 0) > 0 && (
            <div style={{ border: '1px solid #2563eb', borderRadius: 8, padding: 10, marginBottom: 12, background: '#0a1930' }}>
              <strong>Risk score: {selected.score} / 100 ({selected.tier})</strong>
              <span style={{ color: '#94a3b8', fontSize: 12 }}> — sum of findings below, capped at 100. High means investigate, not confirmed malware.</span>
            </div>
          )}
          {(selected.findings ?? []).length > 0 && (
            <div style={{ marginBottom: 12 }}>
              <h3 style={{ margin: '0 0 6px' }}>Findings</h3>
              {(selected.findings ?? []).map(f => (
                <div key={f.ruleId} style={{ border: '1px solid #1e3a5f', borderRadius: 8, padding: 10, marginBottom: 8 }}>
                  <strong>{f.title}</strong> <span style={{ color: f.severity === 'High' ? '#f87171' : f.severity === 'Medium' ? '#fbbf24' : '#94a3b8', fontSize: 12 }}>{f.severity} · +{f.score} · {f.ruleId}</span>
                  <div style={{ fontSize: 13, marginTop: 4 }}>{f.evidence}</div>
                  <div style={{ fontSize: 12, color: '#94a3b8', marginTop: 4 }}>{f.explanation}</div>
                </div>
              ))}
            </div>
          )}
          {selected.flags.length > 0 && (
            <div style={{ border: '1px solid #f59e0b', borderRadius: 8, padding: 10, marginBottom: 12 }}>
              <strong>Why it matters:</strong>
              <ul style={{ fontSize: 13, margin: '6px 0 0', paddingLeft: 18 }}>
                {selected.flags.map(f => <li key={f}><strong>{f}</strong> — {flagWhy[f] ?? 'Flagged by the agent.'}</li>)}
              </ul>
            </div>
          )}
          <details open style={{ marginBottom: 12 }}>
            <summary style={{ cursor: 'pointer', fontWeight: 700 }}>Raw detail — exactly what made this / is being hit</summary>
            <dl style={{ fontSize: 13 }}>
              <dt>Executable</dt><dd style={{ overflowWrap: 'anywhere' }}>{selected.exe || '—'} <button onClick={() => navigator.clipboard.writeText(selected.exe)}>Copy</button></dd>
              <dt>Signature</dt><dd>{selected.signature || 'unknown'} (Windows agent only; Linux is always unknown)</dd>
              <dt>Command line</dt><dd style={{ overflowWrap: 'anywhere' }}>{selected.cmdline || '—'}</dd>
              <dt>Parent</dt><dd>{selected.parent} (pid {selected.ppid ?? ''}) — {selected.parentExe || '—'}</dd>
              <dt>User / unit / container</dt><dd>{selected.user || '—'} / {selected.unit || '—'} / {selected.container || selected.containerId || '—'}</dd>
              <dt>Process started</dt><dd>{selected.started ? new Date(selected.started).toLocaleString() : '—'}</dd>
              <dt>First / last seen</dt><dd>{selected.firstSeen ? new Date(selected.firstSeen).toLocaleString() : ''} / {selected.lastSeen ? new Date(selected.lastSeen).toLocaleString() : ''}</dd>
              <dt>Flags</dt><dd>{selected.flags.join(', ') || '—'}</dd>
            </dl>
          </details>
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
          <h3>Hide or whitelist this app</h3>
          {selected.isWhitelisted && <p style={{ fontSize: 13, color: '#34d399' }}>This app is whitelisted — its connections are not scored and will not appear in Attention or trigger alerts.</p>}
          {selected.isHidden && <p style={{ fontSize: 13, color: '#94a3b8' }}>This app is hidden — it only appears here because “Show hidden apps” is on.</p>}
          {!selected.exe && <p style={{ fontSize: 13, color: '#94a3b8' }}>This app has no executable path, so it cannot be hidden or whitelisted — an empty path would match every unknown process on this host.</p>}
          {selected.exe && !selected.isWhitelisted && !selected.isHidden && (
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 8 }}>
              <button onClick={() => setAppPref(selected.agentId, selected.exe, selected.process, 'hide')}>Hide this app</button>
              <button onClick={() => setAppPref(selected.agentId, selected.exe, selected.process, 'whitelist')}>Whitelist this app</button>
            </div>
          )}
          {selected.exe && selected.isWhitelisted && (
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 8 }}>
              <button onClick={() => clearAppPref(selected.agentId, selected.exe, selected.process)}>Restore app (resume scoring)</button>
              <button onClick={() => setAppPref(selected.agentId, selected.exe, selected.process, 'hide')}>Hide instead</button>
            </div>
          )}
          {selected.exe && selected.isHidden && (
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 8 }}>
              <button onClick={() => clearAppPref(selected.agentId, selected.exe, selected.process)}>Restore app (show again)</button>
              <button onClick={() => setAppPref(selected.agentId, selected.exe, selected.process, 'whitelist')}>Whitelist instead</button>
            </div>
          )}
          <p style={{ fontSize: 12, color: '#94a3b8' }}>Applies to {selected.process} on {selected.agentName} only (executable path). Recordings are kept either way, so restoring loses nothing.</p>
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
