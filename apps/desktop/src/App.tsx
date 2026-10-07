import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Activity, AlertTriangle, ArrowDownToLine, Check, ChevronRight, Copy,
  Clock3, FileLock2, Inbox, KeyRound, LayoutDashboard, Link2,
  LockKeyhole, Mail, MessageSquareText, MonitorCheck, RefreshCw, RotateCcw, Search, Send, Settings2,
  Shield, ShieldAlert, ShieldCheck
} from "lucide-react";

type Evidence = { source: string; code: string; detail?: string };
type Event = { id: string; created_at: string; kind: string; subject: string; risk: number;
  verdict: string; evidence: Evidence[]; explanation: string; model_used: string; status: string };
type Audit = { id: string; created_at: string; event_id?: string; action: string;
  authorization: string; result: string; detail: Record<string, unknown> };
type Quarantine = { id: string; event_id: string; original_path: string; sha256: string;
  created_at: string; restored_at: string | null };
type AgentStatus = { version: string; gmail: { connected: boolean; oauth_status: string; last_scan: string | null };
  tools: Record<string, boolean>; reputation_configured: boolean; virustotal_configured: boolean; scan_queue: number };
type Settings = { model_provider: string; model_name: string; model_endpoint: string;
  gmail_client_id: string; downloads_dir: string; email_interval_minutes: number; max_scan_bytes: number;
  virustotal_file_lookups: boolean };
type Tab = "overview" | "alerts" | "email" | "assistant" | "quarantine" | "models" | "settings" | "audit";
type ChatMessage = { id: string; role: "user" | "assistant"; text: string; target?: Tab;
  note?: string; notePending?: boolean; noteUnavailable?: boolean; modelUsed?: string };

const nav: { id: Tab; label: string; icon: typeof Shield }[] = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "alerts", label: "Alerts", icon: ShieldAlert },
  { id: "email", label: "Email", icon: Mail },
  { id: "assistant", label: "Assistant", icon: MessageSquareText },
  { id: "quarantine", label: "Quarantine", icon: FileLock2 },
  { id: "models", label: "Models", icon: Activity },
  { id: "settings", label: "Integrations", icon: Settings2 },
  { id: "audit", label: "Audit log", icon: Clock3 }
];

const defaultModels: Record<string, string> = {
  ollama: "qwen3:8b", llama_cpp: "local-model", huggingface: "Qwen/Qwen3-4B-Thinking-2507",
  openai: "gpt-4.1-mini", anthropic: "claude-sonnet-4-5"
};

async function rpc<T>(method: string, params: Record<string, unknown> = {}): Promise<T> {
  return invoke<T>("agent_rpc", { method, params });
}

function time(value?: string | null) {
  if (!value) return "Never";
  const numeric = Number(value);
  return new Date(Number.isFinite(numeric) && value.length <= 11 ? numeric * 1000 : value).toLocaleString();
}

function statusLabel(event: Event) {
  if (event.status === "quarantined") return "Quarantined";
  if (event.status === "restored") return "Restored";
  return event.verdict === "low" ? "Low risk" : event.verdict.charAt(0).toUpperCase() + event.verdict.slice(1);
}

function riskClass(verdict: string) {
  return verdict === "malicious" || verdict === "high" ? "danger" : verdict === "suspicious" ? "warning" : "success";
}

function Empty({ icon: Icon, title, detail }: { icon: typeof Shield; title: string; detail: string }) {
  return <div className="empty"><Icon size={28} strokeWidth={1.7} /><strong>{title}</strong><span>{detail}</span></div>;
}

export default function App() {
  const [tab, setTab] = useState<Tab>("assistant");
  const [agent, setAgent] = useState<AgentStatus | null>(null);
  const [events, setEvents] = useState<Event[]>([]);
  const [audit, setAudit] = useState<Audit[]>([]);
  const [quarantine, setQuarantine] = useState<Quarantine[]>([]);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [secrets, setSecrets] = useState<Record<string, boolean>>({});
  const [selected, setSelected] = useState<string | null>(null);
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState("");
  const [keyInput, setKeyInput] = useState("");
  const [gmailSecret, setGmailSecret] = useState("");
  const [safeBrowsingKey, setSafeBrowsingKey] = useState("");
  const [virustotalKey, setVirustotalKey] = useState("");
  const [authUrl, setAuthUrl] = useState("");
  const [modelTest, setModelTest] = useState("");
  const [chatInput, setChatInput] = useState("");
  const [chatBusy, setChatBusy] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const chatHistoryRef = useRef<HTMLDivElement>(null);
  const chatGenerationRef = useRef(0);

  const refresh = useCallback(async () => {
    try {
      const [status, latestEvents, latestAudit, latestQuarantine, currentSettings, secretStatus] = await Promise.all([
        rpc<AgentStatus>("status"), rpc<Event[]>("events_list"), rpc<Audit[]>("audit_list"),
        rpc<Quarantine[]>("quarantine_list"), rpc<Settings>("settings_get"),
        rpc<Record<string, boolean>>("secrets_status")
      ]);
      setAgent(status); setEvents(latestEvents); setAudit(latestAudit); setQuarantine(latestQuarantine);
      setSecrets(secretStatus);
      setSettings(previous => previous ?? currentSettings);
    } catch {
      setAgent(null);
    }
  }, []);

  useEffect(() => { refresh(); const timer = window.setInterval(refresh, 5000); return () => clearInterval(timer); }, [refresh]);
  useEffect(() => { chatHistoryRef.current?.scrollTo({ top: chatHistoryRef.current.scrollHeight }); }, [messages, chatBusy, tab]);

  const selectedEvent = useMemo(() => events.find(event => event.id === selected) ?? null, [events, selected]);
  const alertCount = events.filter(event => event.risk >= 30 && event.status === "open").length;
  const highCount = events.filter(event => event.risk >= 60 && event.status === "open").length;
  const recentEmails = events.filter(event => event.kind === "email");
  const recentDownloads = events.filter(event => event.kind === "download");

  async function action(label: string, method: string, params: Record<string, unknown> = {}) {
    setBusy(label); setNotice("");
    try {
      const result = await rpc<Record<string, unknown>>(method, params);
      setNotice(`${label}: ${result.status || (result.saved ? "saved" : "done")}`);
      await refresh();
      return result;
    } catch (error) {
      setNotice(`${label}: ${String(error)}`);
      return null;
    } finally {
      setBusy("");
    }
  }

  async function saveSettings(changes: Partial<Settings>) {
    await action("Settings", "settings_update", changes);
  }

  async function saveSecret(name: string, value: string, reset: () => void) {
    if (!value.trim()) return;
    const result = await action("Credential", "secret_set", { name, value: value.trim() });
    if (result) reset();
  }

  function resetChat() {
    chatGenerationRef.current += 1;
    setMessages([]);
    setChatInput("");
    setChatBusy(false);
  }

  async function waitForModelReply(replyId: string, messageId: string, generation: number) {
    for (let attempt = 0; attempt < 70; attempt++) {
      await new Promise(resolve => window.setTimeout(resolve, 1000));
      if (chatGenerationRef.current !== generation) return;
      try {
        const result = await rpc<{ status: string; note?: string; model_used?: string }>("assistant_reply", { reply_id: replyId });
        if (result.status === "pending") continue;
        setMessages(previous => previous.map(item => item.id === messageId ? {
          ...item, notePending: false, note: result.status === "ready" ? result.note : undefined,
          modelUsed: result.model_used, noteUnavailable: result.status !== "ready"
        } : item));
        return;
      } catch {
        setMessages(previous => previous.map(item => item.id === messageId ?
          { ...item, notePending: false, noteUnavailable: true } : item));
        return;
      }
    }
    if (chatGenerationRef.current === generation) setMessages(previous => previous.map(item => item.id === messageId ?
      { ...item, notePending: false, noteUnavailable: true } : item));
  }

  async function sendChat() {
    const message = chatInput.trim();
    if (!message || chatBusy) return;
    const generation = chatGenerationRef.current;
    setChatInput(""); setChatBusy(true);
    setMessages(previous => [...previous, { id: crypto.randomUUID(), role: "user", text: message }]);
    try {
      const history = messages.slice(-11).map(item => ({ role: item.role, content: item.note || item.text }));
      const reply = await rpc<{ kind: string; status: string; message: string; reply_id?: string }>("assistant_request", { message, history });
      if (chatGenerationRef.current !== generation) return;
      const messageId = crypto.randomUUID();
      setMessages(previous => [...previous, { id: messageId, role: "assistant", text: reply.message,
        notePending: Boolean(reply.reply_id),
        target: reply.kind === "chat" && reply.status === "local_model_required" ? "models" :
          reply.kind === "email" && reply.status !== "not_connected" ? "email" :
          reply.status === "not_connected" || reply.status === "unconfigured" ? "settings" :
          reply.kind === "url" || reply.kind.startsWith("virustotal_") ? "alerts" : undefined }]);
      if (reply.reply_id) void waitForModelReply(reply.reply_id, messageId, generation);
      await refresh();
    } catch (error) {
      if (chatGenerationRef.current === generation) setMessages(previous => [...previous,
        { id: crypto.randomUUID(), role: "assistant", text: `I couldn't complete that check: ${String(error)}` }]);
    } finally { if (chatGenerationRef.current === generation) setChatBusy(false); }
  }

  function eventTable(rows: Event[], emptyDetail: string) {
    if (!rows.length) return <Empty icon={ShieldCheck} title="No findings yet" detail={emptyDetail} />;
    return <div className="table-wrap"><table><thead><tr><th>Finding</th><th>Risk</th><th>Status</th><th>Time</th><th aria-label="Open" /></tr></thead>
      <tbody>{rows.map(event => <tr key={event.id} onClick={() => { setSelected(event.id); setTab("alerts"); }} tabIndex={0}
        onKeyDown={e => { if (e.key === "Enter") { setSelected(event.id); setTab("alerts"); } }}>
        <td><span className={`type-icon ${riskClass(event.verdict)}`}>{event.kind === "email" ? <Inbox size={17} /> : event.kind === "url" ? <Link2 size={17} /> : <ArrowDownToLine size={17} />}</span>
          <span className="row-main"><strong>{event.subject}</strong><small>{event.kind}</small></span></td>
        <td><span className={`risk-value ${riskClass(event.verdict)}`}>{event.risk}</span></td>
        <td><span className={`pill ${riskClass(event.verdict)}`}>{statusLabel(event)}</span></td>
        <td className="muted">{time(event.created_at)}</td><td><ChevronRight size={16} /></td>
      </tr>)}</tbody></table></div>;
  }

  return <div className="shell">
    <aside className="sidebar">
      <div className="brand" aria-label="Bluely"><img className="brand-mascot" src="/bluely-mascot.png" alt="Bluely mascot" /></div>
      <nav aria-label="Main navigation">{nav.map(item => <button key={item.id} className={`nav-item ${tab === item.id ? "active" : ""}`} onClick={() => setTab(item.id)}>
        <item.icon size={18} strokeWidth={1.8} /><span>{item.label}</span>{item.id === "alerts" && alertCount > 0 && <b>{alertCount}</b>}
      </button>)}</nav>
      <div className="sidebar-bottom"><span className={`status-dot ${agent ? "online" : "offline"}`} />{agent ? "Agent connected" : "Agent offline"}<small>v0.1.0</small></div>
    </aside>
    <main className={`main ${agent ? "" : "agent-offline"}`}>
      <header className="topbar"><div><h1>{nav.find(item => item.id === tab)?.label}</h1></div><div className="topbar-actions">
        {tab === "assistant" && <button className="icon-button" title="Reset chat" aria-label="Reset chat" disabled={!messages.length && !chatInput && !chatBusy} onClick={resetChat}><RotateCcw size={18} /></button>}
        <button className="icon-button" title="Refresh data" aria-label="Refresh data" onClick={refresh}><RefreshCw size={18} /></button></div></header>
      {notice && <div className="notice" role="status"><span>{notice}</span><button title="Dismiss notification" aria-label="Dismiss notification" onClick={() => setNotice("")}>×</button></div>}
      {!agent && <div className="offline-banner"><AlertTriangle size={18} /><div><strong>Agent is not running</strong><span>Start the local service with <code>bluely setup</code>, then refresh.</span></div></div>}

      {tab === "overview" && <div className="page">
        <div className="section-head"><div><h2>This device</h2></div><span className="muted">Updated {new Date().toLocaleTimeString()}</span></div>
        <div className="metrics"><div><span>Open alerts</span><strong>{alertCount}</strong><small>{highCount} high or malicious</small></div>
          <div><span>Email findings</span><strong>{recentEmails.length}</strong><small>{agent?.gmail.connected ? "Gmail connected" : "Gmail not connected"}</small></div>
          <div><span>Downloads scanned</span><strong>{recentDownloads.length}</strong><small>{agent?.scan_queue ?? 0} in progress</small></div>
          <div><span>Quarantined</span><strong>{quarantine.filter(q => !q.restored_at).length}</strong><small>User approved</small></div></div>
        <div className="section-head lower"><div><h2>Recent findings</h2></div>
          <button className="text-button" onClick={() => setTab("alerts")}>View all <ChevronRight size={16} /></button></div>
        {eventTable(events.slice(0, 8), "Connect Gmail or scan a download to see evidence here.")}
        <div className="system-strip"><MonitorCheck size={19} /><span>ClamAV <strong>{agent?.tools.clamscan ? "Ready" : "Missing"}</strong></span>
          <span>YARA <strong>{agent?.tools.yara ? "Ready" : "Missing"}</strong></span>
          <span>URL reputation <strong>{agent?.reputation_configured ? "Ready" : "Not configured"}</strong></span>
          <span>VirusTotal <strong>{agent?.virustotal_configured ? "Connected" : "Not configured"}</strong></span></div>
      </div>}

      {tab === "alerts" && <div className="page"><div className="section-head"><div><h2>All findings</h2><p>Tool evidence and policy decisions</p></div></div>
        <div className="alert-layout"><div>{eventTable(events, "No alerts have been recorded on this device.")}</div>
          <div className="detail-pane">{selectedEvent ? <><div className="detail-top"><span className={`pill ${riskClass(selectedEvent.verdict)}`}>{statusLabel(selectedEvent)}</span><strong>{selectedEvent.risk} / 100</strong></div>
            <h3>{selectedEvent.subject}</h3><p className="muted">{selectedEvent.kind} · {time(selectedEvent.created_at)}</p>
            <h4>Evidence</h4><ul className="evidence">{selectedEvent.evidence.map((finding, index) => <li key={index}><span>{finding.source}</span><strong>{finding.code.replaceAll("_", " ")}</strong><small>{finding.detail}</small></li>)}</ul>
            <h4>Analysis</h4><p className="explanation">{selectedEvent.explanation || "No model explanation is available. The tool verdict remains active."}</p>
            {selectedEvent.model_used && <p className="muted tiny">{selectedEvent.model_used}</p>}
            {selectedEvent.kind === "download" && selectedEvent.status === "open" && selectedEvent.evidence.some(f => ["clamav_detected", "yara_high_confidence"].includes(f.code)) &&
              <button className="primary danger-button" disabled={Boolean(busy)} onClick={() => {
                if (window.confirm(`Move this detected file into Bluely quarantine?\n\n${selectedEvent.subject}`)) action("Quarantine", "quarantine", { event_id: selectedEvent.id, confirmed: true });
              }}><FileLock2 size={16} /> Quarantine file</button>}
          </> : <Empty icon={Search} title="Select a finding" detail="Choose a row to review its evidence." />}</div></div>
      </div>}

      {tab === "email" && <div className="page narrow"><div className="section-head"><div><h2>Gmail security</h2><p>Read-only account monitoring</p></div>
        <span className={`pill ${agent?.gmail.connected ? "success" : "neutral"}`}>{agent?.gmail.connected ? "Connected" : "Not connected"}</span></div>
        <div className="control-band"><div><strong>Account</strong><span>{agent?.gmail.connected ? "Read-only Gmail access active" : "Add your OAuth client ID under Integrations"}</span>
          <small>Last scan: {time(agent?.gmail.last_scan)}</small></div><div className="button-group">
          <button className="secondary" disabled={Boolean(busy) || !agent} onClick={async () => {
            const result = await action("Gmail", "gmail_connect");
            if (result?.authorization_url) setAuthUrl(String(result.authorization_url));
          }}><KeyRound size={16} /> Connect</button>
          <button className="primary" disabled={Boolean(busy) || !agent?.gmail.connected} onClick={() => action("Email scan", "gmail_scan")}><Search size={16} /> Scan now</button></div></div>
        {agent?.gmail.oauth_status === "waiting" && <div className="inline-info">Complete authorization in the browser window.</div>}
        {authUrl && !agent?.gmail.connected && <button className="secondary auth-copy" onClick={() => navigator.clipboard.writeText(authUrl)}><Copy size={16} /> Copy authorization link</button>}
        {agent?.gmail.oauth_status.startsWith("error") && <div className="inline-error">Google authorization failed. Check your OAuth client and try again.</div>}
        <div className="section-head lower"><div><h2>Email findings</h2><p>Suspicious messages from the past seven days and new mail</p></div></div>
        {eventTable(recentEmails, "No suspicious email findings yet.")}
      </div>}

      {tab === "assistant" && <div className="page chat-page"><div className="chat-history" ref={chatHistoryRef} role="log" aria-live="polite">
        {!messages.length && <div className="chat-empty"><MessageSquareText size={26} strokeWidth={1.5} /><h2>What would you like to check?</h2></div>}
        {messages.map(message => <div key={message.id} className={`chat-line ${message.role}`}><span>{message.role === "user" ? "You" : "Bluely"}</span>{message.text && <p>{message.text}</p>}
          {message.notePending && <small className="chat-note-status">{message.text ? "Drafting a follow-up..." : "Thinking..."}</small>}
          {message.note && <p className="chat-note">{message.note}</p>}
          {message.noteUnavailable && <small className="chat-note-status">Model reply unavailable. Check the selected model in Models.</small>}
          {message.modelUsed && message.note && <small className="chat-model">{message.modelUsed}</small>}
          {message.target && <button className="text-button" onClick={() => setTab(message.target!)}>Open {nav.find(item => item.id === message.target)?.label} <ChevronRight size={15} /></button>}</div>)}
        {chatBusy && <div className="chat-line assistant"><span>Bluely</span><p>Checking...</p></div>}
      </div><form className="chat-compose" onSubmit={e => { e.preventDefault(); void sendChat(); }}><input value={chatInput} onChange={e => setChatInput(e.target.value)} placeholder="Ask Bluely..." aria-label="Message Bluely" />
        <button className="primary" type="submit" disabled={!chatInput.trim() || chatBusy} aria-label="Send message" title="Send message"><Send size={17} /></button></form>
        {!messages.length && <div className="chat-suggestions"><button onClick={() => setChatInput("Check my email")}>Check my email</button><button onClick={() => setChatInput("Is https://example.com safe?")}>Check a URL</button><button onClick={() => setChatInput("Scan /home/user/Downloads/file")}>Scan a file</button></div>}
      </div>}

      {tab === "quarantine" && <div className="page narrow"><div className="section-head"><div><h2>Quarantined files</h2><p>Files moved after your approval</p></div></div>
        {!quarantine.length ? <Empty icon={FileLock2} title="Quarantine is empty" detail="Confirmed scanner detections can be moved here from Alerts." /> :
          <div className="quarantine-list">{quarantine.map(record => <div className="quarantine-row" key={record.id}><FileLock2 size={20} /><div><strong>{record.original_path.split("/").pop()}</strong><span>{record.original_path}</span><small>SHA-256 {record.sha256} · {time(record.created_at)}</small></div>
            {record.restored_at ? <span className="pill success">Restored</span> : <button className="secondary" disabled={Boolean(busy)} onClick={() => {
              if (window.confirm(`Restore this file to its original location?\n\n${record.original_path}`)) action("Restore", "restore", { id: record.id, confirmed: true });
            }}><RotateCcw size={16} /> Restore</button>}</div>)}</div>}
      </div>}

      {tab === "models" && settings && <div className="page narrow"><div className="section-head"><div><h2>Analysis model</h2><p>One explicitly selected provider</p></div><span className="pill neutral">Explanations only</span></div>
        <section className="form-section full"><div className="form-grid"><label>Provider<select value={settings.model_provider} onChange={e => setSettings({ ...settings, model_provider: e.target.value, model_name: defaultModels[e.target.value] })}>
          <option value="ollama">Ollama · local</option><option value="llama_cpp">llama.cpp · local</option><option value="huggingface">Hugging Face · hosted</option>
          <option value="openai">OpenAI · cloud</option><option value="anthropic">Anthropic · cloud</option></select></label>
          <label>Model<input value={settings.model_name} onChange={e => setSettings({ ...settings, model_name: e.target.value })} /></label>
          {["ollama", "llama_cpp"].includes(settings.model_provider) && <label className="wide">Local endpoint<input value={settings.model_endpoint} onChange={e => setSettings({ ...settings, model_endpoint: e.target.value })} /></label>}</div>
          <div className="form-actions"><span>Cloud providers receive coded evidence only. Email bodies, URLs, and file contents stay local.</span>
            <div className="button-group"><button className="secondary" disabled={Boolean(busy)} onClick={async () => {
              const saved = await action("Settings", "settings_update", { model_provider: settings.model_provider, model_name: settings.model_name, model_endpoint: settings.model_endpoint });
              if (!saved) return;
              const result = await action("Model test", "model_test");
              if (result) setModelTest(String(result.response || "Connected"));
            }}><Activity size={16} /> Save & test</button>
              <button className="primary" disabled={Boolean(busy)} onClick={() => saveSettings({ model_provider: settings.model_provider, model_name: settings.model_name, model_endpoint: settings.model_endpoint })}><Check size={16} /> Save model</button></div></div>
          {modelTest && <p className="model-test" role="status">{modelTest}</p>}</section>
        {["huggingface", "openai", "anthropic"].includes(settings.model_provider) && <section className="form-section full lower"><h3>Provider key <span className={`pill ${secrets[`${settings.model_provider}_api_key`] ? "success" : "neutral"}`}>{secrets[`${settings.model_provider}_api_key`] ? "Stored" : "Missing"}</span></h3>
          <div className="input-row"><input type="password" value={keyInput} onChange={e => setKeyInput(e.target.value)} placeholder="API key" aria-label="Provider API key" autoComplete="off" />
            <button className="secondary" onClick={() => saveSecret(`${settings.model_provider}_api_key`, keyInput, () => setKeyInput(""))}><KeyRound size={16} /> Store key</button></div></section>}
      </div>}

      {tab === "settings" && settings && <div className="page narrow"><div className="section-head"><div><h2>Integrations & schedule</h2><p>Local service configuration</p></div></div>
        <section className="form-section full"><h3>Gmail OAuth <span className={`pill ${agent?.gmail.connected ? "success" : "neutral"}`}>{agent?.gmail.connected ? "Connected" : "Not connected"}</span></h3>
          <div className="form-grid"><label className="wide">Desktop OAuth client ID<input value={settings.gmail_client_id} onChange={e => setSettings({ ...settings, gmail_client_id: e.target.value })} placeholder="Client ID from Google Cloud" /></label>
            <label className="wide">Client secret <span className="field-state">{secrets.gmail_client_secret ? "Stored" : "Optional for some desktop clients"}</span><div className="input-row"><input type="password" value={gmailSecret} onChange={e => setGmailSecret(e.target.value)} autoComplete="off" placeholder="Client secret" />
              <button className="secondary" onClick={() => saveSecret("gmail_client_secret", gmailSecret, () => setGmailSecret(""))}><KeyRound size={16} /> Store</button></div></label></div>
          <div className="form-actions"><span>Gmail access is read-only.</span><button className="primary" onClick={() => saveSettings({ gmail_client_id: settings.gmail_client_id })}><Check size={16} /> Save Gmail ID</button></div></section>
        <section className="form-section full lower"><h3>URL reputation <span className={`pill ${agent?.reputation_configured ? "success" : "neutral"}`}>{agent?.reputation_configured ? "Ready" : "Missing key"}</span></h3>
          <div className="input-row"><input type="password" value={safeBrowsingKey} onChange={e => setSafeBrowsingKey(e.target.value)} placeholder="Google Safe Browsing API key" autoComplete="off" aria-label="Safe Browsing API key" />
            <button className="secondary" onClick={() => saveSecret("safe_browsing_api_key", safeBrowsingKey, () => setSafeBrowsingKey(""))}><KeyRound size={16} /> Store key</button></div></section>
        <section className="form-section full lower"><h3>VirusTotal <span className={`pill ${agent?.virustotal_configured ? "success" : "neutral"}`}>{agent?.virustotal_configured ? "Connected" : "Missing key"}</span></h3>
          <div className="input-row"><input type="password" value={virustotalKey} onChange={e => setVirustotalKey(e.target.value)} placeholder="VirusTotal API key" autoComplete="off" aria-label="VirusTotal API key" />
            <button className="secondary" onClick={() => saveSecret("virustotal_api_key", virustotalKey, () => setVirustotalKey(""))}><KeyRound size={16} /> Store key</button>
            {agent?.virustotal_configured && <button className="secondary" onClick={() => action("VirusTotal", "virustotal_disconnect")}>Disconnect</button>}</div>
          <label className="check-row"><input type="checkbox" checked={settings.virustotal_file_lookups} onChange={e => setSettings({ ...settings, virustotal_file_lookups: e.target.checked })} />Look up downloaded-file SHA-256 hashes</label>
          <div className="form-actions"><span>Automatic checks send hashes only. Full URLs and files are sent only after your confirmation in VirusTotal.</span>
            <button className="primary" onClick={() => saveSettings({ virustotal_file_lookups: settings.virustotal_file_lookups })}><Check size={16} /> Save preference</button></div></section>
        <section className="form-section full lower"><h3>Scanning</h3><div className="form-grid"><label>Gmail interval (minutes)<input type="number" min="1" max="1440" value={settings.email_interval_minutes} onChange={e => setSettings({ ...settings, email_interval_minutes: Number(e.target.value) })} /></label>
          <label>Maximum download size (MB)<input type="number" min="1" max="2048" value={Math.round(settings.max_scan_bytes / 1048576)} onChange={e => setSettings({ ...settings, max_scan_bytes: Number(e.target.value) * 1048576 })} /></label>
          <label className="wide">Downloads folder<input value={settings.downloads_dir} onChange={e => setSettings({ ...settings, downloads_dir: e.target.value })} /></label></div>
          <div className="form-actions"><span>ClamAV {agent?.tools.clamscan ? "ready" : "missing"} · YARA {agent?.tools.yara ? "ready" : "missing"}</span>
            <button className="primary" onClick={() => saveSettings({ email_interval_minutes: settings.email_interval_minutes, max_scan_bytes: settings.max_scan_bytes, downloads_dir: settings.downloads_dir })}><Check size={16} /> Save schedule</button></div></section>
        <section className="form-section full lower"><h3>Chromium extension</h3><p className="muted">Load <code>apps/browser-extension</code> in Chromium, then register its extension ID with <code>bluely setup --extension-id ID</code>.</p>
          <div className="tool-line"><LockKeyhole size={18} /><span>Native host accepts URL checks and download scans only.</span></div></section>
      </div>}

      {tab === "audit" && <div className="page"><div className="section-head"><div><h2>Action history</h2><p>Local record of scans, settings, and file actions</p></div></div>
        {!audit.length ? <Empty icon={Clock3} title="No actions yet" detail="Actions will appear here when the agent runs." /> : <div className="table-wrap"><table><thead><tr><th>Action</th><th>Authorization</th><th>Result</th><th>Time</th></tr></thead><tbody>
          {audit.map(row => <tr key={row.id}><td><strong>{row.action.replaceAll("_", " ")}</strong></td><td>{row.authorization.replaceAll("_", " ")}</td><td><span className={`pill ${row.result === "success" ? "success" : row.result === "error" ? "danger" : "neutral"}`}>{row.result}</span></td><td className="muted">{time(row.created_at)}</td></tr>)}</tbody></table></div>}
      </div>}
    </main>
  </div>;
}
