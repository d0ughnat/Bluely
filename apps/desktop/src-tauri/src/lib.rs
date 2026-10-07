use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::Command;
use std::time::Duration;

#[tauri::command]
async fn agent_rpc(method: String, params: Value) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || agent_rpc_blocking(method, params))
        .await
        .map_err(|error| format!("Agent request failed: {error}"))?
}

fn agent_rpc_blocking(method: String, params: Value) -> Result<Value, String> {
    let socket = std::env::var("XDG_RUNTIME_DIR")
        .map(|dir| format!("{dir}/blueguard.sock"))
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_default();
            format!("{home}/.local/share/blueguard/blueguard.sock")
        });
    let mut stream = UnixStream::connect(socket)
        .map_err(|_| "Bluely agent is unavailable. Run bluely setup.".to_string())?;
    let read_timeout = if method == "model_test" { 75 } else { 25 };
    stream
        .set_read_timeout(Some(Duration::from_secs(read_timeout)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    let request = json!({"method": method, "params": params});
    stream
        .write_all(request.to_string().as_bytes())
        .map_err(|e| e.to_string())?;
    stream.write_all(b"\n").map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    let response: Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
    if response["ok"] == true {
        Ok(response["result"].clone())
    } else {
        Err(response["error"]
            .as_str()
            .unwrap_or("Agent error")
            .to_string())
    }
}

#[tauri::command]
fn open_in_chromium(address: String) -> Result<(), String> {
    let parsed = validate_web_address(&address)?;
    for browser in ["chromium", "chromium-browser", "google-chrome", "google-chrome-stable"] {
        match Command::new(browser).arg("--new-tab").arg(parsed.as_str()).spawn() {
            Ok(_) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("Could not start Chromium: {error}")),
        }
    }
    Err("Chromium or Chrome is not installed".to_string())
}

fn validate_web_address(address: &str) -> Result<url::Url, String> {
    let parsed = url::Url::parse(&address).map_err(|_| "Enter a valid web address".to_string())?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err("Only HTTP and HTTPS addresses can be opened".to_string());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("Addresses containing credentials are not supported".to_string());
    }

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::validate_web_address;

    #[test]
    fn chromium_only_accepts_public_web_schemes_without_credentials() {
        assert!(validate_web_address("https://example.com/search?q=test").is_ok());
        assert!(validate_web_address("javascript:alert(1)").is_err());
        assert!(validate_web_address("file:///etc/passwd").is_err());
        assert!(validate_web_address("https://user:pass@example.com").is_err());
        assert!(validate_web_address("https://").is_err());
    }
}

pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![agent_rpc, open_in_chromium])
        .run(tauri::generate_context!())
        .expect("error while running Bluely");
}
