# Bluely

Bluely is a local-first security proof of concept for Linux and Windows. A user agent scans Gmail and completed Chromium downloads, checks URLs using Safe Browsing hash prefixes, and records evidence for a Tauri desktop client. The model explains findings; deterministic policy controls the verdict. File quarantine and restore require confirmation in the desktop UI.

## What this release covers

- One local user and one Gmail account; first scan covers seven days, then a 15-minute incremental schedule.
- Chrome/Edge navigation warnings and post-download ClamAV/YARA scans on Linux or Microsoft Defender scans on Windows.
- Read-only Gmail OAuth, local SQLite findings and audit log, OS-keyring credentials.
- Ollama, llama.cpp/OpenAI-compatible local endpoints, hosted Hugging Face, OpenAI, and Anthropic explanation adapters. One provider is selected explicitly; cloud providers receive coded evidence only.
- User-approved quarantine and confirmed restore for strong scanner detections.
- Optional VirusTotal SHA-256 reputation for completed downloads, manual URL/domain/IP/hash reports, and confirmed URL or file submissions.
- An assistant that accepts email-scan and URL-check requests, with local-model conversation and model follow-ups but no model tool execution rights.

The Chromium extension observes downloads **after completion**. It cannot guarantee that another program has not opened a file before Bluely finishes scanning. A `no_match` URL result means it was not found on the configured threat list, not that the site is safe. This release does not include vulnerability inventory, a cloud dashboard, or system-wide prevention.

## Install on Windows 10/11 x64

Once the Windows release is published, open **PowerShell** and run this one line. It downloads the installer with `curl.exe`, checks it, requests administrator approval, installs Bluely, and opens the app:

```powershell
curl.exe -fL https://raw.githubusercontent.com/d0ughnat/Bluely/main/packaging/windows/install.ps1 -o "$env:TEMP\bluely-install.ps1"; if ($LASTEXITCODE -ne 0) { throw 'Bluely installer download failed' }; & "$env:TEMP\bluely-install.ps1"
```

The installer requires administrator approval to register the Defender scan broker. Windows may show an unsigned-app warning until a code-signing certificate is available. The agent starts with Bluely and at future sign-ins. Data and settings live under `%LOCALAPPDATA%\Bluely`; secrets use Windows Credential Manager. Microsoft Defender must be enabled for file scan verdicts. YARA is optional.

To connect the browser extension, open `chrome://extensions` or `edge://extensions`, enable Developer mode, and load the `browser-extension` folder in the Bluely installation's `resources` folder. Copy the extension ID, paste it into **Integrations → Chromium extension**, and select **Register extension**. Reload the extension. Its popup should show the agent connection. The browser extension is unpacked; it is not published to a browser store.

The Windows build is produced on a Windows x64 runner by `.github/workflows/windows.yml`: PyInstaller creates the Python programs, then Tauri creates one NSIS setup executable. The installer registers a SYSTEM startup task for the Defender broker and removes it on uninstall. To build locally, install Python 3.12, Node 20, Rust/MSVC and the [Tauri Windows prerequisites](https://v2.tauri.app/start/prerequisites/#windows), then follow the workflow commands. The installer currently has no code signature.

## Install on Pop!_OS / Ubuntu

Install the runtime scanners and update ClamAV signatures:

```bash
sudo apt update
sudo apt install clamav clamav-freshclam yara python3-venv
sudo freshclam
```

Create the agent environment from the repository root:

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/bluely setup
.venv/bin/bluely rpc status
```

`setup` registers and starts `blueguard-agent.service` as a **user** service. This legacy internal name and the existing data paths remain unchanged so current installations keep their findings and settings. The service runs while you are logged in, even when the desktop window is closed.

### Desktop

Install the [Tauri v2 Linux prerequisites](https://v2.tauri.app/start/prerequisites/#linux) before building. On Pop!_OS / Ubuntu these include `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev`, `libdbus-1-dev`, and `patchelf`.

```bash
cd apps/desktop
npm install
npm run tauri dev
npm run tauri build
```

The AppImage is written under `apps/desktop/src-tauri/target/release/bundle/appimage/`. The Python agent is installed separately; the AppImage is the UI.

### Chromium extension

1. Open `chrome://extensions`, enable Developer mode, and load `apps/browser-extension` as an unpacked extension.
2. Copy its extension ID.
3. From the repository root run `.venv/bin/bluely setup --extension-id YOUR_EXTENSION_ID`.
4. Reopen or reload the extension. Its popup shows whether the native host can reach the agent.

The native host only exposes URL checking, download scanning, and status. It cannot call quarantine or restore.

### Assistant-first workflow

The desktop navigation is intentionally centered on **Assistant**. Ask it to check email, inspect a URL, check a VirusTotal domain/IP/hash, or scan a local download. Browser interception and VirusTotal lookups remain agent tools; they are not separate desktop screens. The Assistant links to Alerts, Email, and other views only when review is useful.

### Assistant and VirusTotal

In **Assistant**, ask "check my email" or "is https://example.com safe?". The command parser selects read-only actions; a model cannot issue commands. The selected model writes a professional follow-up from coded results. Other conversation uses the selected local model and recent chat messages. Raw general chat is not sent to cloud providers. A local model generates fresh question suggestions when Assistant opens and when you return to it. Use Reset chat to clear the visible thread. Assistant-initiated email and file scans show a result card when they finish, with the highest-risk finding linked to its detail in Alerts. The **Scan now** button in Email keeps that tab open and shows progress and results in a small popup. A Safe Browsing `no_match` is never described as proof of safety.

Store a VirusTotal API key in **Integrations** to enable those Assistant actions. It supports existing reports for URLs, public domains, public IPs, and SHA-256 hashes; explicit URL submission and file upload return an analysis ID that can be checked later. Full URL lookup and submission disclose the path and query, so both require confirmation. File upload discloses bytes, requires confirmation, and is limited to 32 MB; Bluely substitutes a generic filename. Automatic download checks send only SHA-256 hashes when enabled. Do not query private indicators: [VirusTotal warns that submitted URLs may enter its dataset](https://docs.virustotal.com/reference/scan-url). The public API is [limited to four requests per minute and is not for commercial use](https://docs.virustotal.com/docs/api-overview); Bluely enforces the per-minute limit locally. VirusTotal votes add evidence but cannot, by themselves, authorize quarantine.

### Gmail and URL reputation

Create a Google Cloud desktop OAuth client with the Gmail API enabled and your Gmail address as a test user. Enter the client ID and the matching client secret from that OAuth client in **Integrations**, choose **Save Gmail credentials**, then choose **Log in** in the top bar. Saving credentials prepares the connection; Gmail shows **Connected** only after Google sign-in finishes. **Sign out** removes the local Gmail token while retaining saved findings and client credentials. Google reports `client_secret is missing` for the configured client when only its ID is sent, so Bluely checks for both before opening Chromium. Bluely requests only `gmail.readonly`; this is a [restricted Gmail scope](https://developers.google.com/workspace/gmail/api/auth/scopes), so public distribution needs Google verification.

For URL checks, enable Google Safe Browsing API in a personal Google Cloud project and store its API key in **Integrations**. The integration sends four-byte URL hash prefixes, never literal URLs. Google's [Safe Browsing API terms](https://developers.google.com/safe-browsing/reference/Appropriate.Usage) permit non-commercial use; a future commercial release needs a different service or agreement.

## Verify

```bash
PYTHONPATH=agent python3 -m unittest discover -s tests -v
cd apps/desktop && npm run build
```

Use a controlled phishing-email fixture and the standard EICAR test string to exercise the workflow. Never use live malware for a demo. If ClamAV, YARA, the keyring, Gmail, Safe Browsing, or the selected model is unavailable, Bluely reports that state; it does not silently turn missing evidence into a safe verdict.
