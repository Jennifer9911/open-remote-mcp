import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  Activity, Cable, CheckCircle2, ChevronRight, CircleDot, Cpu, FolderLock,
  Github, KeyRound, Laptop, LogOut, Radio, RefreshCw, Save, ShieldCheck,
  TerminalSquare, Trash2, Wrench
} from 'lucide-react';
import './styles.css';

type Device = {
  id: string;
  name: string;
  platform?: string | null;
  status: 'online' | 'offline' | 'revoked';
  lastSeen?: string | null;
  createdAt: string;
  revokedAt?: string | null;
  capabilities: string[];
  localRoots: string[];
  localShell: boolean;
  allowedTools: string[] | null;
};
type Call = { id: string; at: string; deviceId: string; tool: string; ok: boolean; ms: number; summary: string };
type Config = {
  version: string;
  publicBaseUrl: string;
  mcpEndpoint: string;
  oauthIssuer: string;
  oauthEnabled: boolean;
  devicePairingEnabled: boolean;
  persistence: string;
};

const sections = [
  ['overview', 'Overview', Activity],
  ['devices', 'Devices & policy', Laptop],
  ['activity', 'Audit log', Radio],
  ['security', 'Security', ShieldCheck],
  ['setup', 'Connect', Cable]
] as const;

async function jsonFetch(url: string, init?: RequestInit) {
  const response = await fetch(url, { credentials: 'include', ...init });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw Object.assign(new Error(body.error ?? `HTTP ${response.status}`), { status: response.status, body });
  return body;
}

function Login({ onLogin }: { onLogin: () => void }) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [working, setWorking] = useState(false);
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setWorking(true);
    setError('');
    try {
      await jsonFetch('/api/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ password })
      });
      onLogin();
    } catch {
      setError('Incorrect owner password.');
    } finally {
      setWorking(false);
    }
  }
  return <div className="login-shell">
    <form className="login-card" onSubmit={submit}>
      <div className="brand-mark login-logo"><Radio size={22}/></div>
      <span className="eyebrow">OPEN REMOTE MCP</span>
      <h1>Control plane</h1>
      <p>Sign in as the server owner to manage devices, policies, OAuth clients, and audit history.</p>
      <label>Owner password</label>
      <input type="password" value={password} onChange={e => setPassword(e.target.value)} autoFocus/>
      {error && <div className="form-error">{error}</div>}
      <button className="primary wide" disabled={working}>{working ? 'Signing in…' : 'Sign in'}</button>
    </form>
  </div>;
}

function App() {
  const [authenticated, setAuthenticated] = useState<boolean | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [calls, setCalls] = useState<Call[]>([]);
  const [config, setConfig] = useState<Config | null>(null);
  const [section, setSection] = useState('overview');
  const [loading, setLoading] = useState(false);

  async function checkSession() {
    const result = await fetch('/api/session', { credentials: 'include' }).then(r => r.json()).catch(() => ({ authenticated: false }));
    setAuthenticated(!!result.authenticated);
  }

  async function refresh() {
    if (!authenticated) return;
    setLoading(true);
    try {
      const [d, a, c] = await Promise.all([jsonFetch('/api/devices'), jsonFetch('/api/activity'), jsonFetch('/api/config')]);
      setDevices(d);
      setCalls(a);
      setConfig(c);
    } catch (error: any) {
      if (error?.status === 401) setAuthenticated(false);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { checkSession(); }, []);
  useEffect(() => {
    if (!authenticated) return;
    refresh();
    const id = setInterval(refresh, 5000);
    return () => clearInterval(id);
  }, [authenticated]);

  async function logout() {
    await fetch('/api/logout', { method: 'POST', credentials: 'include' });
    setAuthenticated(false);
  }

  async function savePolicy(deviceId: string, allowedTools: string[] | null) {
    await jsonFetch(`/api/devices/${encodeURIComponent(deviceId)}/policy`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ allowedTools })
    });
    await refresh();
  }

  async function revoke(deviceId: string) {
    if (!window.confirm('Revoke this device? Its saved credential will stop working immediately.')) return;
    await jsonFetch(`/api/devices/${encodeURIComponent(deviceId)}/revoke`, { method: 'POST' });
    await refresh();
  }

  if (authenticated === null) return <div className="splash"><Radio/><span>Loading control plane…</span></div>;
  if (!authenticated) return <Login onLogin={() => setAuthenticated(true)}/>;

  const online = devices.filter(d => d.status === 'online').length;
  const success = calls.length ? Math.round(calls.filter(c => c.ok).length / calls.length * 100) : 100;
  const recent = calls.slice(0, 7);

  return <div className="app-shell">
    <aside>
      <div className="brand"><div className="brand-mark"><Radio size={19}/></div><div><b>Open Remote MCP</b><span>Control plane</span></div></div>
      <nav>{sections.map(([id, label, Icon]) =>
        <button className={section === id ? 'active' : ''} onClick={() => setSection(id)} key={id}><Icon size={17}/><span>{label}</span></button>
      )}</nav>
      <div className="aside-bottom">
        <div className="security-chip"><ShieldCheck size={15}/><span>OAuth + local policy</span></div>
        <a href="https://github.com/Jennifer9911/open-remote-mcp" target="_blank"><Github size={16}/> GitHub <ChevronRight size={14}/></a>
      </div>
    </aside>

    <main>
      <header>
        <div><span className="eyebrow">REMOTE MCP CONTROL PLANE · V{config?.version ?? '0.2.0'}</span><h1>{sections.find(x => x[0] === section)?.[1]}</h1></div>
        <div className="header-actions">
          <button className="refresh" onClick={refresh}><RefreshCw size={16} className={loading ? 'spin' : ''}/> Refresh</button>
          <button className="refresh" onClick={logout}><LogOut size={16}/> Sign out</button>
        </div>
      </header>

      {section === 'overview' && <Overview online={online} devices={devices} calls={recent} success={success} config={config}/>}
      {section === 'devices' && <Devices devices={devices} onSavePolicy={savePolicy} onRevoke={revoke} pairUrl={(config?.publicBaseUrl ?? '') + '/device'}/>}
      {section === 'activity' && <ActivityView calls={calls}/>}
      {section === 'security' && <Security/>}
      {section === 'setup' && <Setup config={config}/>}
    </main>
  </div>;
}

function Overview({ online, devices, calls, success, config }: { online: number; devices: Device[]; calls: Call[]; success: number; config: Config | null }) {
  return <>
    <section className="hero">
      <div>
        <div className="status-line"><span className="pulse"/> OAuth-enabled relay ready</div>
        <h2>One secure bridge from AI to your machines.</h2>
        <p>A self-hosted Remote MCP endpoint with OAuth 2.1-style PKCE authorization, device pairing, persistent audit logs, and local-first execution boundaries.</p>
        <div className="hero-actions">
          <a className="primary button-link" href={(config?.publicBaseUrl ?? '') + '/device'} target="_blank"><Cable size={16}/> Pair a device</a>
          <button className="secondary" onClick={() => navigator.clipboard.writeText(config?.mcpEndpoint ?? '')}><Wrench size={16}/> Copy MCP endpoint</button>
        </div>
      </div>
      <div className="relay-visual">
        <div className="node"><Cpu/><span>AI client</span></div><div className="beam"><i/><i/><i/></div>
        <div className="node strong"><Radio/><span>OAuth relay</span></div><div className="beam"><i/><i/><i/></div>
        <div className="node"><Laptop/><span>Agent</span></div>
      </div>
    </section>

    <section className="metrics">
      <Metric icon={<Laptop/>} label="Online devices" value={String(online)} note={devices.length ? `${devices.length} registered` : 'No devices paired'}/>
      <Metric icon={<Activity/>} label="Audit events" value={String(calls.length)} note="Recent persisted events"/>
      <Metric icon={<CheckCircle2/>} label="Success rate" value={`${success}%`} note="Recent executions"/>
      <Metric icon={<KeyRound/>} label="Client auth" value="PKCE" note="OAuth + refresh tokens"/>
    </section>

    <section className="grid-2">
      <Card title="Devices" action="Live status">
        {devices.length ? devices.slice(0, 4).map(d => <DeviceRow d={d} key={d.id}/>) : <Empty text="Start the agent to pair your first machine."/>}
      </Card>
      <Card title="Recent activity" action="Persisted audit">
        {calls.length ? calls.map(c => <CallRow c={c} key={c.id}/>) : <Empty text="Tool calls will appear here after the first execution."/>}
      </Card>
    </section>
  </>;
}

function Metric({ icon, label, value, note }: { icon: React.ReactNode; label: string; value: string; note: string }) {
  return <div className="metric"><div className="metric-icon">{icon}</div><span>{label}</span><strong>{value}</strong><small>{note}</small></div>;
}
function Card({ title, action, children }: { title: string; action?: string; children: React.ReactNode }) {
  return <div className="card"><div className="card-head"><h3>{title}</h3>{action && <span>{action}</span>}</div>{children}</div>;
}
function DeviceRow({ d }: { d: Device }) {
  return <div className="row"><div className="device-icon"><Laptop size={18}/></div><div className="grow"><b>{d.name}</b><small>{(d.platform ?? 'unknown') + ' · ' + d.id}</small></div><span className={'pill ' + d.status}><CircleDot size={11}/>{d.status}</span></div>;
}
function CallRow({ c }: { c: Call }) {
  return <div className="row"><div className={'call-icon ' + (c.ok ? 'good' : 'bad')}><TerminalSquare size={17}/></div><div className="grow"><b>{c.tool}</b><small>{c.deviceId + ' · ' + c.ms + ' ms'}</small></div><span className="time">{new Date(c.at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span></div>;
}
function Empty({ text }: { text: string }) { return <div className="empty"><Radio size={22}/><span>{text}</span></div>; }

function Devices({ devices, onSavePolicy, onRevoke, pairUrl }: {
  devices: Device[];
  onSavePolicy: (deviceId: string, tools: string[] | null) => Promise<void>;
  onRevoke: (deviceId: string) => Promise<void>;
  pairUrl: string;
}) {
  return <div className="page-stack">
    <div className="info-banner">
      <Laptop/><div><b>Paired machines</b><span>Local roots and shell authority are enforced by the agent. Server policy can only disable exposed tools; it cannot broaden local authority.</span></div>
      <a className="primary button-link compact" href={pairUrl} target="_blank">Pair device</a>
    </div>
    <div className="device-grid policy-grid">
      {devices.length ? devices.map(device => <DevicePolicyCard key={device.id} device={device} onSave={onSavePolicy} onRevoke={onRevoke}/>) : <Empty text="No paired devices yet."/>}
    </div>
  </div>;
}

function DevicePolicyCard({ device, onSave, onRevoke }: {
  device: Device;
  onSave: (deviceId: string, tools: string[] | null) => Promise<void>;
  onRevoke: (deviceId: string) => Promise<void>;
}) {
  const effectiveInitial = device.allowedTools ?? device.capabilities;
  const [selected, setSelected] = useState<string[]>(effectiveInitial);
  const [saving, setSaving] = useState(false);
  useEffect(() => setSelected(device.allowedTools ?? device.capabilities), [device.id, device.allowedTools?.join(','), device.capabilities.join(',')]);

  function toggle(tool: string) {
    setSelected(current => current.includes(tool) ? current.filter(t => t !== tool) : [...current, tool]);
  }
  async function save() {
    setSaving(true);
    try {
      const isAll = device.capabilities.every(tool => selected.includes(tool)) && selected.length === device.capabilities.length;
      await onSave(device.id, isAll ? null : selected);
    } finally {
      setSaving(false);
    }
  }

  return <div className={'device-card policy-card ' + (device.status === 'revoked' ? 'revoked-card' : '')}>
    <div className="device-top"><div className="device-icon big"><Laptop/></div><span className={'pill ' + device.status}>{device.status}</span></div>
    <h3>{device.name}</h3>
    <p>{device.platform ?? 'Unknown platform'} · {device.localShell ? 'shell locally enabled' : 'shell locally disabled'}</p>

    <div className="policy-section">
      <span className="mini-title">SERVER TOOL POLICY</span>
      <div className="tool-list">{device.capabilities.map(tool =>
        <label className={'tool-toggle ' + (selected.includes(tool) ? 'on' : '')} key={tool}>
          <input type="checkbox" checked={selected.includes(tool)} onChange={() => toggle(tool)} disabled={device.status === 'revoked'}/>
          <span>{tool}</span>
        </label>
      )}</div>
    </div>

    <div className="policy-section">
      <span className="mini-title">LOCAL FILE ROOTS · READ ONLY</span>
      <div className="roots">{device.localRoots.length ? device.localRoots.map(root => <code key={root}>{root}</code>) : <span className="muted-inline">Not reported</span>}</div>
    </div>

    <dl>
      <div><dt>Device ID</dt><dd title={device.id}>{device.id}</dd></div>
      <div><dt>Last seen</dt><dd>{device.lastSeen ? new Date(device.lastSeen).toLocaleString() : 'Never'}</dd></div>
      <div><dt>Local shell</dt><dd>{device.localShell ? 'Enabled' : 'Disabled'}</dd></div>
    </dl>

    <div className="device-actions">
      <button className="small-button" onClick={save} disabled={saving || device.status === 'revoked'}><Save size={14}/>{saving ? 'Saving…' : 'Save policy'}</button>
      <button className="small-button danger" onClick={() => onRevoke(device.id)} disabled={device.status === 'revoked'}><Trash2 size={14}/>Revoke</button>
    </div>
  </div>;
}

function ActivityView({ calls }: { calls: Call[] }) {
  return <Card title="Persisted tool-call audit trail"><div className="table"><div className="tr head"><span>Tool</span><span>Device</span><span>Status</span><span>Latency</span><span>Time</span></div>{calls.length ? calls.map(c => <div className="tr" key={c.id}><b>{c.tool}</b><span>{c.deviceId}</span><span className={c.ok ? 'success' : 'failure'}>{c.ok ? 'Success' : 'Failed'}</span><span>{c.ms} ms</span><span>{new Date(c.at).toLocaleString()}</span></div>) : <Empty text="No audit events yet."/>}</div></Card>;
}

function Security() {
  const items = [
    [KeyRound, 'OAuth + PKCE', 'Dynamic client registration, S256 PKCE, short-lived access tokens, and rotating refresh tokens protect MCP client access.'],
    [Cable, 'Device authorization', 'Agents use one-time pairing codes and receive a device-specific credential only after owner approval.'],
    [FolderLock, 'Local hard boundary', 'File operations use realpath checks against local roots, including symlink escape protection.'],
    [TerminalSquare, 'Shell is explicit', 'Shell is disabled by default. Enabling it grants full shell authority for that OS account; filesystem roots do not sandbox shell commands.'],
    [ShieldCheck, 'Two-layer policy', 'The dashboard can narrow tool access, while the local agent remains the final authority and cannot be remotely broadened.'],
    [Activity, 'Persistent audit', 'Tool outcomes and latency are persisted in SQLite instead of disappearing when the relay restarts.']
  ] as const;
  return <div className="security-grid">{items.map(([Icon, title, body]) => <div className="security-card" key={title}><div><Icon/></div><h3>{title}</h3><p>{body}</p><span><CheckCircle2 size={14}/> included in v0.2</span></div>)}</div>;
}

function Setup({ config }: { config: Config | null }) {
  const base = config?.publicBaseUrl ?? 'https://your-host.example';
  return <div className="setup-grid">
    <Card title="1. Deploy the relay"><Code>{`PUBLIC_BASE_URL=${base}\nADMIN_PASSWORD=...\nSESSION_SECRET=...\nnpm run build && npm start`}</Code></Card>
    <Card title="2. Start a device agent"><Code>{`REMOTE_MCP_SERVER=${base.replace(/^http/, 'ws')}/agent \\\nALLOWED_ROOTS=/path/to/workspace \\\nnpm run start -w @open-remote-mcp/agent`}</Code><p className="hint">The first launch prints a pairing code. Approve it in the browser; no device token needs to be copied manually.</p></Card>
    <Card title="3. Add the Remote MCP app"><Code>{config?.mcpEndpoint ?? base + '/mcp'}</Code><p className="hint">The server publishes OAuth authorization-server and protected-resource metadata. Compatible clients can dynamically register and run the PKCE flow.</p></Card>
    <Card title="4. Harden production"><p className="hint">Use HTTPS, strong owner/session secrets, narrow local roots, keep shell disabled unless necessary, and run the agent under a dedicated OS account for stronger isolation.</p></Card>
  </div>;
}
function Code({ children }: { children: React.ReactNode }) { return <pre><code>{children}</code></pre>; }

createRoot(document.getElementById('root')!).render(<React.StrictMode><App/></React.StrictMode>);
