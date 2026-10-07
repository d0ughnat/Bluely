const host = "com.blueguard.agent";
const activeWarnings = new Map();
const navigationUrl = new Map();

async function callAgent(method, params = {}) {
  try {
    const response = await chrome.runtime.sendNativeMessage(host, { method, params });
    if (!response?.ok) throw new Error(response?.error || "Agent unavailable");
    return response.result;
  } catch (error) {
    await chrome.storage.local.set({ agentError: String(error.message || error) });
    return null;
  }
}

chrome.webNavigation.onCommitted.addListener(async ({ tabId, frameId, url }) => {
  if (frameId !== 0 || !/^https?:\/\//i.test(url)) return;
  activeWarnings.delete(tabId);
  navigationUrl.set(tabId, url);
  const result = await callAgent("check_url", { url });
  if (navigationUrl.get(tabId) !== url) return;
  await chrome.storage.local.set({ lastUrlCheck: { host: result?.host || "", status: result?.status || "unavailable", at: Date.now() } });
  if (result?.status === "malicious") {
    const warning = { host: result.host, threats: result.threats };
    activeWarnings.set(tabId, warning);
    chrome.tabs.sendMessage(tabId, { type: "blueguard-warning", warning }).catch(() => {});
  }
});

chrome.tabs.onUpdated.addListener((tabId, change) => {
  if (change.status !== "complete") return;
  const warning = activeWarnings.get(tabId);
  if (warning) chrome.tabs.sendMessage(tabId, { type: "blueguard-warning", warning }).catch(() => {});
});

chrome.tabs.onRemoved.addListener((tabId) => {
  activeWarnings.delete(tabId);
  navigationUrl.delete(tabId);
});

chrome.downloads.onChanged.addListener(async (change) => {
  if (change.state?.current !== "complete") return;
  const [item] = await chrome.downloads.search({ id: change.id });
  if (!item?.filename) return;
  const result = await callAgent("scan_download", { path: item.filename, url: item.finalUrl || item.url || "" });
  await chrome.storage.local.set({ lastDownload: {
    name: item.filename.split(/[\\/]/).pop(),
    status: result?.status || "agent_unavailable",
    at: Date.now()
  } });
});
