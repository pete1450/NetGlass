import { useCallback, useEffect, useMemo, useState } from 'react'

type Conn = {
  agentId: string; agentName: string; direction: string; proto: string; state: string
  local: string; remote: string; remoteHost: string
  pid?: number | null; process: string; exe: string; cmdline: string; user: string
  ppid?: number | null; parent: string; parentExe: string
  unit: string; container: string; containerId: string
  started?: string | null; firstSeen: string; lastSeen: string
  isGhost: boolean; isNew: boolean; suspicious: boolean; flags: string[]
}
type Agent = { id: string; name: string; hostname: string; os: string; version: string; lastSeen: string; socketCount: number }
type Recording = { id: string; name: string; startedAt: string; endedAt?: string | null; eventCount: number }

type SortKey = 'agentName' | 'direction' | 'process' | 'exe' | 'local' | 'remote' | 'state' | 'firstSeen' | 'lastSeen'

const COLUMNS: { key: SortKey; label: string }[] = [
  { key: 'agentName', label: 'Agent' }, { key: 'direction', label: 'Direction' },
  { key: 'process', label: 'Process' }, { key: 'exe', label: 'Executable' },
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
  const [view, setView] = useState<'all' | 'outgoing' | 'incoming'>('all')
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

  const load = useCallback(async () => {
    try {
      const [c, a, r] = await Promise.all([
        fetch('/api/connections').then(x => x.json()),
        fetch('/api/agents').then(x => x.json()),
        fetch('/api/recordings').then(x => x.json()),
      ])
      setConns(c.connections ?? []); setCounts(c.counts ?? {})
      setAgents(a ?? []); setRecordings(r ?? [])
    } catch { /* server down: keep last state, UI shows stale counts */ }
  }, [])

  useEffect(() => { load(); const t = setInterval(load, 2000); return () => clearInterval(t) }, [load])
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

  return (
    <div style={{ padding: 16, maxWidth: 1400, margin: '0 auto' }}>
      <h1 style={{ margin: '0 0 4px' }}>NetGlass</h1>
      <p style={{ color: '#94a3b8', marginTop: 0 }}>Local-first process network visibility. No cloud. Click a row for the full story, including how to kill it.</p>

      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 12 }}>
        {([
          ['Total', counts.total], ['Outbound', counts.outbound], ['Inbound', counts.inbound],
          ['Listeners', counts.listen], ['Suspicious', conns.filter(c => c.suspicious).length],
          ['New (24h)', conns.filter(c => c.isNew).length],
          ['Ghosts', conns.filter(c => c.isGhost).length],
        ] as const).map(([label, value]) => (
          <button key={label} onClick={() => {
            if (label === 'Suspicious') setOnlySusp(true)
            if (label === 'New (24h)') setOnlyNew(true)
            if (label === 'Listeners') setOnlyListen(true)
          }} style={{ textAlign: 'left' }}>
            <div style={{ fontSize: 22, fontWeight: 700 }}>{value ?? 0}</div><div style={{ fontSize: 12, color: '#94a3b8' }}>{label}</div>
          </button>
        ))}
        <button className="primary" onClick={() => setShowAddAgent(v => !v)}>+ Add agent</button>
      </div>

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 12, alignItems: 'center' }}>
        <button onClick={() => setView('all')} disabled={view === 'all'}>All</button>
        <button onClick={() => setView('outgoing')} disabled={view === 'outgoing'}>Outgoing — what made this?</button>
        <button onClick={() => setView('incoming')} disabled={view === 'incoming'}>Incoming — what is being hit?</button>
        <input id="search" value={q} onChange={e => setQ(e.target.value)} placeholder="Search…  ( / to focus )" style={{ flex: 1, minWidth: 240 }} />
        <select value={agentFilter} onChange={e => setAgentFilter(e.target.value)}>
          <option value="">All agents</option>
          {agents.map(a => <option key={a.id} value={a.id}>{a.name} ({a.hostname || a.id.slice(0, 8)})</option>)}
        </select>
        <select value={dirFilter} onChange={e => setDirFilter(e.target.value)}>
          <option value="">All directions</option><option>outbound</option><option>inbound</option><option>listen</option><option>local</option>
        </select>
        <label><input type="checkbox" checked={onlyNew} onChange={e => setOnlyNew(e.target.checked)} /> Only new</label>
        <label><input type="checkbox" checked={onlySusp} onChange={e => setOnlySusp(e.target.checked)} /> Only suspicious</label>
        <label><input type="checkbox" checked={onlyListen} onChange={e => setOnlyListen(e.target.checked)} /> Only listeners</label>
        <label title="How long a closed connection stays visible, faded">Ghost linger
          <input type="range" min={0} max={300} value={linger} onChange={e => saveLinger(Number(e.target.value))} /> {linger}s
        </label>
      </div>

      {showAddAgent && (
        <div style={{ border: '1px solid #334155', borderRadius: 8, padding: 12, marginBottom: 12 }}>
          <h3 style={{ marginTop: 0 }}>Add an agent</h3>
          <input value={newAgentName} onChange={e => setNewAgentName(e.target.value)} placeholder="Agent name, e.g. debian-server" />
          <button className="primary" onClick={createAgent} style={{ marginLeft: 8 }}>Generate Docker compose</button>
          <p style={{ color: '#94a3b8' }}>Windows: download the release exe and run it with <code>--server {window.location.origin} --token &lt;token&gt;</code>, or run it with no arguments and enter the server and token when prompted.</p>
          {compose && <><textarea value={compose} readOnly rows={16} style={{ width: '100%', fontFamily: 'monospace' }} />
            <button onClick={() => navigator.clipboard.writeText(compose)}>Copy compose</button>
            <button onClick={() => { const blob = new Blob([compose], { type: 'text/yaml' }); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'docker-compose.netglass-agent.yml'; a.click() }}>Download compose</button></>}
        </div>
      )}

      <div style={{ border: '1px solid #334155', borderRadius: 8, padding: 12, marginBottom: 12 }}>
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

      <div style={{ fontSize: 13, color: '#94a3b8', marginBottom: 8 }}>
        Agents: {agents.map(a => `${a.name} — last seen ${a.lastSeen ? new Date(a.lastSeen).toLocaleTimeString() : 'never'}, ${a.socketCount} sockets`).join(' · ') || 'none connected — click Add agent'}
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
              <td style={{ padding: 6, maxWidth: 300, overflowWrap: 'anywhere' }}>{c.exe}</td>
              <td style={{ padding: 6 }}>{c.local}</td>
              <td style={{ padding: 6 }}>{c.remote}{c.remoteHost ? <><br /><span style={{ color: '#94a3b8' }}>{c.remoteHost}</span></> : null}</td>
              <td style={{ padding: 6 }}>{c.state}</td>
              <td style={{ padding: 6 }}>{c.firstSeen ? new Date(c.firstSeen).toLocaleString() : ''}</td>
              <td style={{ padding: 6 }}>{c.lastSeen ? new Date(c.lastSeen).toLocaleString() : ''}</td>
              <td style={{ padding: 6 }}>{c.flags.join(', ')}</td>
            </tr>
          ))}
          {filtered.length === 0 && <tr><td colSpan={10} style={{ padding: 12, color: '#94a3b8' }}>No connections match. Connect an agent, or clear the filters.</td></tr>}
        </tbody>
      </table>

      {selected && (
        <div style={{ position: 'fixed', right: 16, top: 16, bottom: 16, width: 420, overflow: 'auto', background: '#1e293b', border: '1px solid #334155', borderRadius: 8, padding: 16 }}>
          <button onClick={() => setSelected(null)} style={{ float: 'right' }}>Close (Esc)</button>
          <h2 style={{ marginTop: 0 }}>{selected.process} <span style={{ fontSize: 14, color: '#94a3b8' }}>pid {selected.pid ?? ''}</span></h2>
          <p><strong>{selected.direction}</strong> {selected.proto} {selected.state}<br />{selected.local} → {selected.remote || '—'}{selected.remoteHost ? ` (${selected.remoteHost})` : ''}</p>
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
    </div>
  )
}
