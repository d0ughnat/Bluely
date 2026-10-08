import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Activity, AlertTriangle, ArrowDownToLine, Check, ChevronRight, Copy,
  Clock3, FileLock2, Inbox, KeyRound, LayoutDashboard, Link2,
  LockKeyhole, LogOut, Mail, MessageSquareText, MonitorCheck, RefreshCw, RotateCcw, Search, Send, Settings2,
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
  unread_alerts: number;
  tools: Record<string, boolean>; reputation_configured: boolean; virustotal_configured: boolean; scan_queue: number };
type Settings = { model_provider: string; model_name: string; model_endpoint: string;
  gmail_client_id: string; downloads_dir: string; email_interval_minutes: number; max_scan_bytes: number;
  virustotal_file_lookups: boolean };
type Tab = "overview" | "alerts" | "email" | "assistant" | "quarantine" | "models" | "settings" | "audit";
type ScanResult = { status: string; kind: string; messages: number; findings: number; truncated?: boolean;
  top_finding?: { id: string; kind: string; subject: string; risk: number; verdict: string; summary: string } | null };
type ChatMessage = { id: string; role: "user" | "assistant"; text: string; target?: Tab;
  note?: string; notePending?: boolean; noteUnavailable?: boolean; modelUsed?: string;
  scanPending?: boolean; scanResult?: ScanResult; scanUnavailable?: boolean };
type EmailScanPopup = { status: "scanning" | "complete" | "running" | "error"; result?: ScanResult };

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

function savedSuggestions(): string[] {
  try {
    const value: unknown = JSON.parse(window.localStorage.getItem("bluely.assistant.suggestions") || "[]");
    return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string" && item.length <= 120).slice(-9) : [];
  } catch {
    return [];
  }
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
  const [emailScanPopup, setEmailScanPopup] = useState<EmailScanPopup | null>(null);
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [suggestionStatus, setSuggestionStatus] = useState<"loading" | "ready" | "unavailable" | "local_model_required">("loading");
  const chatHistoryRef = useRef<HTMLDivElement>(null);
  const chatGenerationRef = useRef(0);
  const suggestionGenerationRef = useRef(0);
  const emailScanGenerationRef = useRef(0);
  const previousSuggestionsRef = useRef<string[]>(savedSuggestions());
  const alertAckPendingRef = useRef(false);

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

  const agentReady = Boolean(agent);
  useEffect(() => {
    if (tab !== "assistant") return;
    const generation = ++suggestionGenerationRef.current;
    setSuggestions([]);
    setSuggestionStatus("loading");
    if (!agentReady) {
      setSuggestionStatus("unavailable");
      return;
    }
    void (async () => {
      try {
        const started = await rpc<{ status: string; reply_id?: string }>("assistant_suggestions", {
          previous: previousSuggestionsRef.current.slice(-9)
        });
        if (generation !== suggestionGenerationRef.current) return;
        if (started.status === "local_model_required") {
          setSuggestionStatus("local_model_required");
          return;
        }
        if (!started.reply_id) throw new Error("Suggestion request was not started");
        for (let attempt = 0; attempt < 75; attempt++) {
          await new Promise(resolve => window.setTimeout(resolve, 1000));
          if (generation !== suggestionGenerationRef.current) return;
          const result = await rpc<{ status: string; suggestions?: string[] }>("assistant_reply", { reply_id: started.reply_id });
          if (result.status === "pending") continue;
          if (result.status !== "ready" || !result.suggestions?.length) throw new Error("Suggestions unavailable");
          setSuggestions(result.suggestions);
          previousSuggestionsRef.current = [...previousSuggestionsRef.current, ...result.suggestions].slice(-9);
          try { window.localStorage.setItem("bluely.assistant.suggestions", JSON.stringify(previousSuggestionsRef.current)); } catch { /* Suggestions still work without persistence. */ }
          setSuggestionStatus("ready");
          return;
        }
        throw new Error("Suggestion request timed out");
      } catch {
        if (generation === suggestionGenerationRef.current) setSuggestionStatus("unavailable");
      }
    })();
    return () => { suggestionGenerationRef.current += 1; };
  }, [tab, agentReady]);

  const newestVisibleAlert = events.find(event => event.risk >= 30 && event.status === "open")?.created_at;
  useEffect(() => {
    if (tab !== "alerts" || !agent?.unread_alerts || !newestVisibleAlert || alertAckPendingRef.current) return;
    alertAckPendingRef.current = true;
    void rpc("alerts_mark_seen", { through: newestVisibleAlert }).then(refresh).catch(error => {
      setNotice(`Alerts: ${String(error)}`);
    }).finally(() => { alertAckPendingRef.current = false; });
  }, [tab, agent?.unread_alerts, newestVisibleAlert, refresh]);

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

  async function saveGmailCredentials() {
    if (!settings) return;
    const clientId = settings.gmail_client_id.trim();
    const clientSecret = gmailSecret.trim();
    if (!clientId || (!clientSecret && !secrets.gmail_client_secret)) {
      setNotice("Gmail: enter the client ID and matching client secret");
      return;
    }
    setBusy("Gmail credentials");
    setNotice("");
    try {
      if (clientSecret) await rpc("secret_set", { name: "gmail_client_secret", value: clientSecret });
      await rpc("settings_update", { gmail_client_id: clientId });
      setGmailSecret("");
      setSettings(previous => previous ? { ...previous, gmail_client_id: clientId } : previous);
      await refresh();
      setNotice("Gmail credentials saved. Choose Log in from the top bar.");
    } catch (error) {
      setNotice(`Gmail credentials: ${String(error)}`);
    } finally {
      setBusy("");
    }
  }

  async function loginToGmail() {
    if (!settings?.gmail_client_id || !secrets.gmail_client_secret) {
      setTab("settings");
      setNotice("Add and save the Gmail OAuth client ID and secret before logging in.");
      return;
    }
    setAuthUrl("");
    const result = await action("Gmail", "gmail_connect");
    if (!result?.authorization_url) return;
    const url = String(result.authorization_url);
    setAuthUrl(url);
    try {
      await invoke("open_in_chromium", { address: url });
      setNotice("Gmail: complete Google sign-in in Chromium");
    } catch (error) {
      setTab("email");
      setNotice(`Could not open Chromium: ${String(error)}. Copy the authorization link below to continue.`);
    }
  }

  async function signOutOfGmail() {
    const result = await action("Gmail", "gmail_disconnect");
    if (result) setAuthUrl("");
  }

  async function scanEmail() {
    const generation = ++emailScanGenerationRef.current;
    setEmailScanPopup({ status: "scanning" });
    try {
      const started = await rpc<{ status: string; scan_id?: string }>("gmail_scan");
      if (generation !== emailScanGenerationRef.current) return;
      if (started.status === "running") {
        setEmailScanPopup({ status: "running" });
        return;
      }
      if (started.status !== "started" || !started.scan_id) throw new Error("Email scan did not start");
      for (let attempt = 0; attempt < 290; attempt++) {
        await new Promise(resolve => window.setTimeout(resolve, 2000));
        if (generation !== emailScanGenerationRef.current) return;
        const result = await rpc<ScanResult>("assistant_scan_result", { scan_id: started.scan_id });
        if (result.status === "pending") continue;
        setEmailScanPopup({ status: result.status === "completed" ? "complete" : "error", result });
        await refresh();
        return;
      }
      throw new Error("Email scan timed out");
    } catch {
      if (generation === emailScanGenerationRef.current) setEmailScanPopup({ status: "error" });
    }
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

  async function waitForScanResult(scanId: string, messageId: string, generation: number) {
    for (let attempt = 0; attempt < 290; attempt++) {
      await new Promise(resolve => window.setTimeout(resolve, 2000));
      if (chatGenerationRef.current !== generation) return;
      try {
        const result = await rpc<ScanResult>("assistant_scan_result", { scan_id: scanId });
        if (result.status === "pending") continue;
        setMessages(previous => previous.map(item => item.id === messageId ?
          { ...item, scanPending: false, scanResult: result,
            scanUnavailable: !["completed", "cancelled"].includes(result.status),
            text: result.status === "completed" ? result.kind === "email" ?
              `Email scan complete. Checked ${result.messages} message${result.messages === 1 ? "" : "s"} and found ${result.findings} finding${result.findings === 1 ? "" : "s"}.` :
              `File scan complete. ${result.findings ? "The result is below." : "No result was recorded."}` :
              result.status === "cancelled" ? "The scan was cancelled." : "The scan result is unavailable." } : item));
        await refresh();
        return;
      } catch {
        setMessages(previous => previous.map(item => item.id === messageId ?
          { ...item, scanPending: false, scanUnavailable: true, text: "The scan result is unavailable." } : item));
        return;
      }
    }
    if (chatGenerationRef.current === generation) setMessages(previous => previous.map(item => item.id === messageId ?
      { ...item, scanPending: false, scanUnavailable: true, text: "The scan is taking longer than expected. Check Alerts for any findings." } : item));
  }

  async function sendChat(override?: string) {
    const message = (override ?? chatInput).trim();
    if (!message || chatBusy) return;
    const generation = chatGenerationRef.current;
    setChatInput(""); setChatBusy(true);
    setMessages(previous => [...previous, { id: crypto.randomUUID(), role: "user", text: message }]);
    try {
      const history = messages.slice(-11).map(item => ({ role: item.role, content: item.note || item.text }));
      const reply = await rpc<{ kind: string; status: string; message: string; reply_id?: string; scan_id?: string }>("assistant_request", { message, history });
      if (chatGenerationRef.current !== generation) return;
      const messageId = crypto.randomUUID();
      setMessages(previous => [...previous, { id: messageId, role: "assistant", text: reply.message,
        notePending: Boolean(reply.reply_id),
        scanPending: Boolean(reply.scan_id),
        target: reply.kind === "chat" && reply.status === "local_model_required" ? "models" :
          reply.kind === "email" && reply.status !== "not_connected" ? "email" :
          reply.status === "not_connected" || reply.status === "unconfigured" ? "settings" :
          reply.kind === "url" || reply.kind.startsWith("virustotal_") ? "alerts" : undefined }]);
      if (reply.reply_id) void waitForModelReply(reply.reply_id, messageId, generation);
      if (reply.scan_id) void waitForScanResult(reply.scan_id, messageId, generation);
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
        <item.icon size={18} strokeWidth={1.8} /><span>{item.label}</span>{item.id === "alerts" && Boolean(agent?.unread_alerts) && <b>{agent!.unread_alerts}</b>}
      </button>)}</nav>
      <div className="sidebar-bottom"><span className={`status-dot ${agent ? "online" : "offline"}`} />{agent ? "Agent connected" : "Agent offline"}<small>v0.1.0</small></div>
    </aside>
    <main className={`main ${agent ? "" : "agent-offline"}`}>
      <header className="topbar"><div><h1>{nav.find(item => item.id === tab)?.label}</h1></div><div className="topbar-actions">
        {agent?.gmail.connected ? <button className="secondary" disabled={Boolean(busy)} onClick={signOutOfGmail}><LogOut size={16} /> Sign out</button> :
          <button className="secondary" disabled={Boolean(busy) || !agent || agent.gmail.oauth_status === "waiting"} onClick={loginToGmail}><KeyRound size={16} /> {agent?.gmail.oauth_status === "waiting" ? "Signing in..." : "Log in"}</button>}
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
        {eventTable(events.slice(0, 8), "Log in to Gmail or scan a download to see evidence here.")}
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
        <div className="control-band"><div><strong>Account</strong><span>{agent?.gmail.connected ? "Read-only Gmail access active" : !settings?.gmail_client_id ? "Add your OAuth client ID under Integrations" : !secrets.gmail_client_secret ? "Add your OAuth client secret under Integrations" : "Use Log in in the top bar"}</span>
          <small>Last scan: {time(agent?.gmail.last_scan)}</small></div><div className="button-group">
          <button className="primary" disabled={Boolean(busy) || emailScanPopup?.status === "scanning" || !agent?.gmail.connected} onClick={() => void scanEmail()}><Search size={16} /> Scan now</button>
          {emailScanPopup && <div className="email-scan-popup" role="status"><div className="email-scan-popup-head"><strong>{emailScanPopup.status === "scanning" ? "Scanning Gmail..." : emailScanPopup.status === "complete" ? "Email scan complete" : emailScanPopup.status === "running" ? "Scan already running" : "Email scan unavailable"}</strong>
            <button type="button" aria-label="Dismiss scan result" title="Dismiss" onClick={() => { emailScanGenerationRef.current += 1; setEmailScanPopup(null); }}>×</button></div>
            {emailScanPopup.status === "scanning" && <p>Checking messages. Results will appear here.</p>}
            {emailScanPopup.status === "running" && <p>Another email scan is in progress. Findings will appear below and in Alerts.</p>}
            {emailScanPopup.status === "error" && <p>The scan could not finish. Check your Gmail connection and try again.</p>}
            {emailScanPopup.status === "complete" && emailScanPopup.result && <><p>Checked {emailScanPopup.result.messages} message{emailScanPopup.result.messages === 1 ? "" : "s"}; found {emailScanPopup.result.findings} finding{emailScanPopup.result.findings === 1 ? "" : "s"}.</p>
              {emailScanPopup.result.top_finding ? <button className="email-scan-finding" onClick={() => { setSelected(emailScanPopup.result!.top_finding!.id); setEmailScanPopup(null); setTab("alerts"); }}><strong>Most critical: {emailScanPopup.result.top_finding.subject}</strong><span>{emailScanPopup.result.top_finding.summary}</span><small>View in Alerts <ChevronRight size={14} /></small></button> : <small>No suspicious messages found in this scan.</small>}
              {emailScanPopup.result.truncated && <small>The scan reached its message limit; more mail may remain unchecked.</small>}</>}
          </div>}</div></div>
        {agent?.gmail.oauth_status === "waiting" && <div className="inline-info">Complete authorization in the browser window.</div>}
        {!agent?.gmail.connected && settings?.gmail_client_id && !secrets.gmail_client_secret && <div className="inline-info">Google requires the client secret for this OAuth client. <button className="text-button" onClick={() => setTab("settings")}>Open Integrations</button></div>}
        {authUrl && !agent?.gmail.connected && <button className="secondary auth-copy" onClick={() => navigator.clipboard.writeText(authUrl)}><Copy size={16} /> Copy authorization link</button>}
        {agent?.gmail.oauth_status.startsWith("error") && <div className="inline-error">{agent.gmail.oauth_status.replace(/^error:\s*/, "Google authorization failed: ")}</div>}
        <div className="section-head lower"><div><h2>Email findings</h2><p>Suspicious messages from the past seven days and new mail</p></div></div>
        {eventTable(recentEmails, "No suspicious email findings yet.")}
      </div>}

      {tab === "assistant" && <div className="page chat-page"><div className="chat-history" ref={chatHistoryRef} role="log" aria-live="polite">
        {!messages.length && <div className="chat-empty"><MessageSquareText size={26} strokeWidth={1.5} /><h2>What would you like to check?</h2></div>}
        {messages.map(message => <div key={message.id} className={`chat-line ${message.role}`}><span>{message.role === "user" ? "You" : "Bluely"}</span>{message.text && <p>{message.text}</p>}
          {message.notePending && <small className="chat-note-status">{message.text ? "Drafting a follow-up..." : "Thinking..."}</small>}
          {message.scanPending && <small className="chat-note-status">Scanning... Results will appear here.</small>}
          {message.scanResult?.status === "completed" && <div className="scan-result" role="status"><strong>{message.scanResult.findings ? "Most critical finding" : "No findings from this scan"}</strong>
            {message.scanResult.top_finding ? <button className="scan-result-link" onClick={() => { setSelected(message.scanResult!.top_finding!.id); setTab("alerts"); }}>
              <span>{message.scanResult.top_finding.subject}</span><b className={riskClass(message.scanResult.top_finding.verdict)}>{message.scanResult.top_finding.risk} / 100 · {message.scanResult.top_finding.verdict}</b>
              <small>{events.find(event => event.id === message.scanResult?.top_finding?.id)?.explanation || message.scanResult.top_finding.summary}</small>
              <span className="scan-result-open">View in Alerts <ChevronRight size={15} /></span>
            </button> : <small>{message.scanResult.kind === "email" ? "No suspicious messages were found in this scan. Continue to use normal caution." : "No finding was recorded for this file."}</small>}
            {message.scanResult.truncated && <small>The scan reached its message limit; more mail may remain unchecked.</small>}
          </div>}
          {message.scanUnavailable && <small className="chat-note-status">Check Alerts for any findings recorded before the scan stopped.</small>}
          {message.note && <p className="chat-note">{message.note}</p>}
          {message.noteUnavailable && <small className="chat-note-status">AI follow-up unavailable. You can retry or test the selected model in Models.</small>}
          {message.modelUsed && message.note && <small className="chat-model">{message.modelUsed}</small>}
          {message.target && <button className="text-button" onClick={() => setTab(message.target!)}>Open {nav.find(item => item.id === message.target)?.label} <ChevronRight size={15} /></button>}</div>)}
        {chatBusy && <div className="chat-line assistant"><span>Bluely</span><p>Checking...</p></div>}
      </div><form className="chat-compose" onSubmit={e => { e.preventDefault(); void sendChat(); }}><input value={chatInput} onChange={e => setChatInput(e.target.value)} placeholder="Ask Bluely..." aria-label="Message Bluely" />
        <button className="primary" type="submit" disabled={!chatInput.trim() || chatBusy} aria-label="Send message" title="Send message"><Send size={17} /></button></form>
        <div className="chat-suggestions" aria-live="polite">{suggestionStatus === "ready" ? suggestions.map(suggestion =>
          <button key={suggestion} onClick={() => setChatInput(suggestion)}>{suggestion}</button>) :
          <small>{suggestionStatus === "loading" ? "Creating new suggestions..." :
            suggestionStatus === "local_model_required" ? "Select a local model in Models for AI suggestions." :
            "AI suggestions are unavailable right now. You can still ask Bluely anything."}</small>}</div>
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
            <label className="wide">Client secret <span className="field-state">{secrets.gmail_client_secret ? "Stored" : "Required for this Google client"}</span><input type="password" value={gmailSecret} onChange={e => setGmailSecret(e.target.value)} autoComplete="off" placeholder="Client secret from the same OAuth client" /></label></div>
          <div className="form-actions"><span>Save both credentials, then use Log in in the top bar. Gmail access is read-only.</span><button className="primary" disabled={Boolean(busy) || !settings.gmail_client_id.trim() || (!secrets.gmail_client_secret && !gmailSecret.trim())} onClick={saveGmailCredentials}><Check size={16} /> Save Gmail credentials</button></div></section>
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
