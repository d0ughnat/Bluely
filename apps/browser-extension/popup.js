async function render() {
  const status = document.getElementById("agent-status");
  try {
    const response = await chrome.runtime.sendNativeMessage("com.blueguard.agent", { method: "status", params: {} });
    if (!response?.ok) throw new Error(response?.error || "Agent unavailable");
    status.textContent = response.result.reputation_configured ? "Agent connected · URL checks active" : "Agent connected · reputation key needed";
    status.classList.add("ready");
  } catch {
    status.textContent = "Agent unavailable";
    status.classList.add("error");
  }
  const data = await chrome.storage.local.get(["lastUrlCheck", "lastDownload"]);
  if (data.lastUrlCheck) document.getElementById("url-check").textContent = `${data.lastUrlCheck.host || "Unknown"} · ${data.lastUrlCheck.status}`;
  if (data.lastDownload) document.getElementById("download-check").textContent = `${data.lastDownload.name} · ${data.lastDownload.status}`;
}
render();
