use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, Runtime};
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;
use tokio::sync::Mutex;

// ── Shared State ──────────────────────────────────────────────

pub struct VpnState {
    pub child: Arc<Mutex<Option<CommandChild>>>,
}

impl VpnState {
    pub fn new() -> Self {
        Self {
            child: Arc::new(Mutex::new(None)),
        }
    }
}

// ── Event Payloads ────────────────────────────────────────────

#[derive(Clone, Serialize)]
pub struct LogPayload {
    pub message: String,
}

/// Response from the VPN prelogin probe.
#[derive(Clone, Serialize, Deserialize)]
pub struct PreloginResponse {
    pub auth_method: String,   // "password" | "duo" | "saml"
    pub gateway_valid: bool,
    pub server_ip: Option<String>,
    pub region: Option<String>,
    pub panos_version: Option<String>,
}

/// Simplified XML parsing for prelogin response.
#[derive(Debug, Deserialize)]
#[serde(rename = "prelogin-response")]
struct PreloginXml {
    #[serde(rename = "saml-auth-method", default)]
    saml_auth_method: Option<String>,
    #[serde(rename = "server-ip", default)]
    server_ip: Option<String>,
    #[serde(rename = "region", default)]
    region: Option<String>,
    #[serde(rename = "panos-version", default)]
    panos_version: Option<String>,
}

// ── Platform-specific helpers ─────────────────────────────────

/// Resolve the openconnect binary path.
///
/// On macOS / Linux, privilege-escalation wrappers (osascript, pkexec)
/// run in a sanitized root environment that does **not** inherit the
/// user's `$PATH`. Homebrew installs (`/opt/homebrew/bin`,
/// `/usr/local/bin`) won't be found. We resolve the absolute path at
/// build time so the elevated shell can find the binary.
fn openconnect_bin() -> String {
    if cfg!(target_os = "windows") {
        "openconnect.exe".to_string()
    } else {
        let candidates = [
            "/opt/homebrew/bin/openconnect", // macOS Apple Silicon (Homebrew)
            "/usr/local/bin/openconnect",    // macOS Intel (Homebrew)
            "/usr/bin/openconnect",          // Linux (apt / dnf / pacman)
            "/usr/sbin/openconnect",         // Some Linux distros
            "/snap/bin/openconnect",         // Ubuntu Snap
        ];

        for path in candidates {
            if Path::new(path).exists() {
                return path.to_string();
            }
        }

        // Fallback: hope it's on PATH (works in non-elevated contexts)
        "openconnect".to_string()
    }
}

/// Check if openconnect is installed and return its path, or an error
/// with install instructions.
#[tauri::command]
pub fn check_openconnect() -> Result<String, String> {
    let bin = openconnect_bin();
    // If we resolved to an absolute path, the binary exists
    if bin.starts_with('/') || (cfg!(target_os = "windows") && Path::new(&bin).is_absolute()) {
        return Ok(bin);
    }
    // Fallback name — check if it's actually on PATH
    if cfg!(target_os = "windows") {
        if let Ok(out) = std::process::Command::new("where")
            .arg("openconnect.exe")
            .output()
        {
            if out.status.success() {
                return Ok(bin);
            }
        }
        Err("OpenConnect not found. Install it:\n  choco install openconnect\n  or: winget install openconnect".into())
    } else {
        if let Ok(out) = std::process::Command::new("which")
            .arg("openconnect")
            .output()
        {
            if out.status.success() {
                return Ok(bin);
            }
        }
        Err("OpenConnect not found. Install it:\n  macOS: brew install openconnect\n  Linux: sudo apt install openconnect".into())
    }
}

/// Find a HIP report script for GlobalProtect compliance checks.
///
/// If the server requires Host Information Profile (HIP) data, openconnect
/// uses `--csd-wrapper` to run a script that generates the report. This
/// function looks for the script at standard install locations.
/// Note: hipreport.sh is not included with Homebrew openconnect and must
/// be obtained separately if needed.
fn hipreport_script() -> Option<String> {
    if cfg!(target_os = "windows") {
        return None;
    }
    let candidates = [
        "/opt/homebrew/etc/vpnc/hipreport.sh",
        "/usr/local/etc/vpnc/hipreport.sh",
        "/opt/homebrew/share/vpnc-scripts/hipreport.sh",
        "/usr/local/share/vpnc-scripts/hipreport.sh",
        "/usr/share/vpnc-scripts/hipreport.sh",
        "/etc/vpnc/hipreport.sh",
    ];
    for path in candidates {
        if Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    None
}

/// Build the base openconnect argument string with common flags.
///
/// Appends `--reconnect-timeout` for automatic reconnection on network
/// drops, and `--csd-wrapper` for HIP compliance if the script is found.
/// Returns (args, hip_enabled) tuple.
fn build_oc_base(gateway: &str, username: &str, extra_flags: &str) -> (String, bool) {
    let mut args = format!(
        "{} --protocol=gp --user={} {} --reconnect-timeout=300 --passwd-on-stdin",
        openconnect_bin(),
        shell_escape(username),
        extra_flags,
    );
    let hip_enabled = if let Some(hip) = hipreport_script() {
        // Only add --csd-wrapper if we have the script
        args.push_str(&format!(" --csd-wrapper={}", shell_escape(&hip)));
        true
    } else {
        // Don't add --csd-wrapper at all if script doesn't exist
        // This avoids "failed to submit hid report" errors
        false
    };
    args.push_str(&format!(" {}", shell_escape(gateway)));
    (args, hip_enabled)
}

/// Escape a value for safe embedding in a shell command string.
///
/// On Unix (macOS / Linux) we escape single-quotes for POSIX sh.
/// On Windows we escape for cmd.exe double-quoted strings.
fn shell_escape(s: &str) -> String {
    if cfg!(target_os = "windows") {
        // For cmd.exe: wrap in double quotes, escape internal quotes
        s.replace('^', "^^")
            .replace('&', "^&")
            .replace('<', "^<")
            .replace('>', "^>")
            .replace('|', "^|")
            .replace('"', "^\"")
    } else {
        s.replace('\'', "'\\''")
    }
}

/// Build the full command string that pipes `stdin_lines` into the openconnect
/// invocation `oc_args`, wrapped in the platform's privilege-escalation
/// mechanism.
///
/// Each element in `stdin_lines` is sent as a separate line to openconnect's
/// stdin. This supports multi-prompt flows (e.g. password + Duo challenge).
///
/// - **macOS**: Try `sudo -n` first (cached credentials), fallback to `osascript`
/// - **Linux**: `pkexec sh -c '…'`
/// - **Windows**: relies on the Tauri shell plugin spawning a helper that
///   triggers a UAC elevation prompt.
fn build_elevated_command(oc_args: &str, stdin_lines: &[&str]) -> ElevatedCommand {
    #[cfg(target_os = "macos")]
    {
        // Create a temp log file for real-time output
        let log_path = "/tmp/donsprotect-vpn.log";
        
        let fmt = "%s\\n".repeat(stdin_lines.len());
        let escaped_args: Vec<String> = stdin_lines
            .iter()
            .map(|s| format!("'{}'", shell_escape(s)))
            .collect();
        // Redirect all output to log file that we can tail
        let inner = format!(
            "rm -f {} && printf '{}' {} | {} > {} 2>&1 &",
            log_path,
            fmt,
            escaped_args.join(" "),
            oc_args,
            log_path,
        );
        let script = format!(
            "do shell script \"{}\" with administrator privileges",
            inner.replace('\\', "\\\\").replace('"', "\\\""),
        );
        ElevatedCommand {
            program: "osascript".into(),
            args: vec!["-e".into(), script],
            log_file: Some(log_path.to_string()),
        }
    }

    #[cfg(target_os = "linux")]
    {
        let fmt = "%s\\n".repeat(stdin_lines.len());
        let escaped_args: Vec<String> = stdin_lines
            .iter()
            .map(|s| format!("'{}'", shell_escape(s)))
            .collect();
        let inner = format!(
            "printf '{}' {} | {} 2>&1",
            fmt,
            escaped_args.join(" "),
            oc_args,
        );
        ElevatedCommand {
            program: "pkexec".into(),
            args: vec!["sh".into(), "-c".into(), inner],
            log_file: None,
        }
    }

    #[cfg(target_os = "windows")]
    {
        // On Windows we use PowerShell's Start-Process -Verb RunAs to
        // get a UAC elevation prompt, then pipe stdin_lines via echo.
        let echo_parts: Vec<String> = stdin_lines
            .iter()
            .map(|s| format!("echo {}", shell_escape(s)))
            .collect();
        let inner = format!(
            "({}) | {} 2>&1",
            echo_parts.join(" & "),
            oc_args,
        );
        ElevatedCommand {
            program: "powershell".into(),
            args: vec![
                "-NoProfile".into(),
                "-Command".into(),
                format!(
                    "Start-Process cmd -ArgumentList '/c {}' -Verb RunAs -Wait",
                    inner.replace('\'', "''"),
                ),
            ],
            log_file: None,
        }
    }
}

struct ElevatedCommand {
    program: String,
    args: Vec<String>,
    log_file: Option<String>,
}

// ── Commands ──────────────────────────────────────────────────

/// Probe the VPN gateway to detect its authentication method.
///
/// Sends a GET request to `/ssl-vpn/prelogin.esp` and parses the XML
/// response to determine:
/// - **password**: Standard username/password (no SAML, no Duo)
/// - **duo**: Duo Push or passcode (server responds with RADIUS challenge after password)
/// - **saml**: SAML SSO redirect (response contains `<saml-auth-method>`)
///
/// This allows automatic tab selection and gateway validation.
#[tauri::command]
pub async fn prelogin_probe(gateway: String) -> Result<PreloginResponse, String> {
    if gateway.trim().is_empty() {
        return Err("Gateway cannot be empty".into());
    }

    let url = format!("https://{}/ssl-vpn/prelogin.esp", gateway);
    
    // Build HTTP client that accepts self-signed certs (common for VPNs)
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    // Send prelogin request
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Failed to connect to gateway: {}", e))?;

    if !response.status().is_success() {
        return Err(format!(
            "Gateway returned error status: {}",
            response.status()
        ));
    }

    let body = response
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    // Parse XML response
    let prelogin: PreloginXml = quick_xml::de::from_str(&body)
        .map_err(|e| format!("Failed to parse prelogin XML: {}", e))?;

    // Determine auth method based on response
    let auth_method = if prelogin.saml_auth_method.is_some() {
        // SAML SSO gateway (e.g., prisma.usfca.edu)
        "saml".to_string()
    } else {
        // For non-SAML gateways, we need to distinguish between password-only
        // and Duo-enabled. Unfortunately, the prelogin response doesn't always
        // explicitly indicate Duo support. We use heuristics:
        // - Known Duo gateways (svpn, svpn1) default to "duo"
        // - Others default to "password"
        if gateway.starts_with("svpn") {
            "duo".to_string()
        } else {
            "password".to_string()
        }
    };

    Ok(PreloginResponse {
        auth_method,
        gateway_valid: true,
        server_ip: prelogin.server_ip,
        region: prelogin.region,
        panos_version: prelogin.panos_version,
    })
}

/// Student / password-only mode: pipe password to openconnect via stdin.
#[tauri::command]
pub async fn connect_student<R: Runtime>(
    app: AppHandle<R>,
    gateway: String,
    username: String,
    password: String,
) -> Result<(), String> {
    emit_log(&app, "Starting VPN connection...");
    let (oc_args, hip_enabled) = build_oc_base(&gateway, &username, "");
    if hip_enabled {
        emit_log(&app, "✓ HIP (Host Information Profile) compliance enabled");
    } else {
        emit_log(&app, "ℹ HIP script not found (optional - connection may still succeed)");
    }
    spawn_openconnect(&app, &oc_args, &[&password]).await
}

/// Duo mode: pipe password + Duo challenge response to openconnect.
///
/// For Duo Push gateways (svpn.usfca.edu), the GlobalProtect server sends
/// a RADIUS challenge after receiving the password. OpenConnect reads the
/// challenge response from stdin: either "push" (triggers Duo push) or a
/// numeric passcode.
#[tauri::command]
pub async fn connect_duo<R: Runtime>(
    app: AppHandle<R>,
    gateway: String,
    username: String,
    password: String,
    challenge: String,
) -> Result<(), String> {
    emit_log(&app, "Starting Duo VPN connection...");
    let (oc_args, hip_enabled) = build_oc_base(&gateway, &username, "");
    if hip_enabled {
        emit_log(&app, "✓ HIP (Host Information Profile) compliance enabled");
    } else {
        emit_log(&app, "ℹ HIP script not found (optional - connection may still succeed)");
    }
    spawn_openconnect(&app, &oc_args, &[&password, &challenge]).await
}

/// Faculty SAML mode: use prelogin-cookie from SAML auth.
/// After the SAML flow, we have a `prelogin-cookie` and `saml-username`.
/// These are fed to openconnect via --usergroup=gateway:prelogin-cookie.
#[tauri::command]
pub async fn connect_faculty<R: Runtime>(
    app: AppHandle<R>,
    gateway: String,
    cookie: String,
    username: String,
) -> Result<(), String> {
    emit_log(&app, "Starting SSO VPN connection...");
    let (oc_args, hip_enabled) = build_oc_base(&gateway, &username, "--usergroup=gateway:prelogin-cookie");
    if hip_enabled {
        emit_log(&app, "✓ HIP (Host Information Profile) compliance enabled");
    } else {
        emit_log(&app, "ℹ HIP script not found (optional - connection may still succeed)");
    }
    spawn_openconnect(&app, &oc_args, &[&cookie]).await
}

/// Kill the running VPN process.
#[tauri::command]
pub async fn disconnect<R: Runtime>(app: AppHandle<R>) -> Result<(), String> {
    let state = app.state::<VpnState>();
    let mut child = state.child.lock().await;

    if let Some(c) = child.take() {
        emit_log(&app, "Disconnecting...");

        // 1. Kill the privilege-escalation wrapper (osascript / pkexec / powershell).
        let _ = c.kill();

        // 2. Clean up orphaned openconnect processes.
        //    Killing osascript/pkexec does NOT reliably propagate SIGKILL to
        //    the openconnect child running as root. The orphan keeps the tun
        //    interface locked, causing "Could not create tun" on reconnect.
        cleanup_openconnect();

        let _ = app.emit("vpn-status", "disconnected");
        emit_log(&app, "Disconnected.");
    } else {
        emit_log(&app, "No active connection.");
    }

    Ok(())
}

/// Best-effort cleanup of orphaned openconnect processes.
///
/// When we SIGKILL the privilege-escalation wrapper, the child openconnect
/// (running as root) can become an orphan. We try platform-appropriate
/// methods to reap it. If none succeed (e.g. no cached sudo credentials
/// on macOS), the user may need to manually run:
///     `sudo killall -9 openconnect`
pub fn cleanup_openconnect() {
    #[cfg(target_os = "macos")]
    {
        // `sudo -n` is non-interactive: succeeds only if credentials are
        // cached (within the sudo timeout). Won't prompt the user.
        let _ = std::process::Command::new("sudo")
            .args(["-n", "killall", "-9", "openconnect"])
            .output();
    }

    #[cfg(target_os = "linux")]
    {
        // Same strategy: non-interactive sudo.
        let _ = std::process::Command::new("sudo")
            .args(["-n", "killall", "-9", "openconnect"])
            .output();
        // Fallback: pkill (works if user's session has lingering privileges)
        let _ = std::process::Command::new("pkill")
            .args(["-9", "openconnect"])
            .output();
    }

    #[cfg(target_os = "windows")]
    {
        // taskkill can kill elevated processes from an elevated parent.
        let _ = std::process::Command::new("taskkill")
            .args(["/F", "/IM", "openconnect.exe"])
            .output();
    }
}

// ── Helpers ───────────────────────────────────────────────────

pub fn emit_log<R: Runtime>(app: &AppHandle<R>, msg: &str) {
    let _ = app.emit(
        "vpn-log",
        LogPayload {
            message: msg.to_string(),
        },
    );
}

/// Check if an openconnect output line indicates a successful tunnel.
/// This looks for the line where openconnect reports the assigned VPN IP,
/// which only appears after successful authentication and tunnel establishment.
fn is_connected_line(line: &str) -> bool {
    let lower = line.to_lowercase();
    // "Configured as 10.99.48.107, with SSL connected..." is the key success line
    lower.contains("configured as")
        || lower.contains("esp session established")
        || lower.contains("esp tunnel connected")
        || lower.contains("continuing in background")
}

/// Check if an openconnect output line indicates a reconnection attempt.
fn is_reconnecting_line(line: &str) -> bool {
    let lower = line.to_lowercase();
    lower.contains("reconnect")
        || lower.contains("tun device went down")
        || lower.contains("session expired")
        || lower.contains("dead peer")
        || lower.contains("keepalive timeout")
}

/// Check if an openconnect output line indicates an error/failure.
fn is_error_line(line: &str) -> bool {
    let lower = line.to_lowercase();
    (lower.contains("error") || lower.contains("failed") || lower.contains("unable"))
        && !lower.contains("resumed")
        // ESP tunnel failure is normal - SSL/TLS fallback works fine
        && !lower.contains("failed to connect esp tunnel")
}

/// Check if a line should be filtered out (noisy harmless messages).
fn should_filter_line(line: &str) -> bool {
    let lower = line.to_lowercase();
    // Filter shell-init errors (harmless, caused by root privilege escalation)
    if lower.contains("shell-init: error") && lower.contains("getcwd") {
        return true;
    }
    // Filter minor routing errors that don't affect connectivity
    if lower.contains("can't assign requested address") 
        || (lower.contains("file exists") && lower.contains("route:")) {
        return true;
    }
    // Filter verbose route add messages (keep network routes concise)
    if line.trim().starts_with("add net ") || line.trim().starts_with("add host ") {
        return true;
    }
    // Filter verbose HIP warning continuation lines
    if line.trim().starts_with("VPN connectivity may be disabled")
        || line.trim().starts_with("You need to provide a --csd-wrapper") {
        return true;
    }
    false
}

/// Spawn openconnect with elevated privileges and stream output.
///
/// Privilege escalation is platform-specific:
/// - **macOS** — `osascript "do shell script … with administrator privileges"`
/// - **Linux** — `pkexec sh -c '…'`
/// - **Windows** — PowerShell `Start-Process -Verb RunAs` (UAC prompt)
async fn spawn_openconnect<R: Runtime>(
    app: &AppHandle<R>,
    oc_args: &str,
    stdin_lines: &[&str],
) -> Result<(), String> {
    // Check no existing connection
    {
        let state = app.state::<VpnState>();
        let existing = state.child.lock().await;
        if existing.is_some() {
            return Err("Already connected. Disconnect first.".into());
        }
    }

    let elevated = build_elevated_command(oc_args, stdin_lines);

    emit_log(app, "Requesting administrator privileges...");

    let shell = app.shell();
    let (mut rx, child) = shell
        .command(&elevated.program)
        .args(elevated.args)
        .spawn()
        .map_err(|e| format!("Failed to spawn {}: {}", elevated.program, e))?;

    // Store child handle
    {
        let state = app.state::<VpnState>();
        let mut lock = state.child.lock().await;
        *lock = Some(child);
    }

    let _ = app.emit("vpn-status", "connecting");
    emit_log(app, "");
    emit_log(app, "⏳ Please wait - osascript buffers output until connection completes");
    emit_log(app, "   This may take 30-60 seconds. The app is NOT frozen.");
    emit_log(app, "");

    // Shared flag to coordinate between log tailing and polling tasks
    let connected_flag = Arc::new(AtomicBool::new(false));

    // Poll for openconnect process to show it's actually running
    let poll_handle = app.clone();
    let poll_connected = connected_flag.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        let output = std::process::Command::new("pgrep")
            .arg("-l")
            .arg("openconnect")
            .output();
        if let Ok(out) = output {
            if out.status.success() && !out.stdout.is_empty() {
                emit_log(&poll_handle, "✓ Confirmed: openconnect is running in background");
                emit_log(&poll_handle, "  Waiting for authentication and connection...");
                emit_log(&poll_handle, "");
                
                // Keep checking every 10 seconds to show we're still alive
                for i in 1..=6 {
                    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                    
                    // Stop polling if connection was successful
                    if poll_connected.load(Ordering::Relaxed) {
                        break;
                    }
                    
                    let check = std::process::Command::new("pgrep")
                        .arg("openconnect")
                        .output();
                    if let Ok(c) = check {
                        if c.status.success() {
                            emit_log(&poll_handle, &format!("  ⏱ Still connecting... ({} seconds elapsed)", 15 + i * 10));
                        } else {
                            emit_log(&poll_handle, "");
                            emit_log(&poll_handle, "⚠ openconnect process ended - waiting for output...");
                            break;
                        }
                    }
                }
            } else {
                emit_log(&poll_handle, "⚠ openconnect not detected. Process may have failed immediately.");
                emit_log(&poll_handle, "   Check that gateway address is correct.");
            }
        }
    });

    // If we have a log file, tail it in real-time
    if let Some(log_path) = elevated.log_file.clone() {
        let tail_handle = app.clone();
        let tail_connected = connected_flag.clone();
        tauri::async_runtime::spawn(async move {
            // Wait for log file to be created
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            
            emit_log(&tail_handle, "📄 Monitoring openconnect log file...");
            emit_log(&tail_handle, "");
            
            let mut last_size = 0u64;
            let mut connected = false;
            
            for i in 0..120 { // Monitor for up to 2 minutes
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                
                if let Ok(mut file) = std::fs::File::open(&log_path) {
                    use std::io::{Read, Seek, SeekFrom};
                    
                    if let Ok(metadata) = file.metadata() {
                        let current_size = metadata.len();
                        if current_size > last_size {
                            file.seek(SeekFrom::Start(last_size)).ok();
                            let mut new_content = String::new();
                            if file.read_to_string(&mut new_content).is_ok() {
                                for line in new_content.lines() {
                                    if !line.is_empty() && !should_filter_line(line) {
                                        if is_error_line(line) {
                                            emit_log(&tail_handle, &format!("❌ {}", line));
                                        } else {
                                            emit_log(&tail_handle, line);
                                        }
                                        
                                        if !connected && is_connected_line(line) {
                                            connected = true;
                                            tail_connected.store(true, Ordering::Relaxed);
                                            emit_log(&tail_handle, "");
                                            emit_log(&tail_handle, "→ Tunnel established successfully!");
                                            let _ = tail_handle.emit("vpn-status", "connected");
                                        }
                                    }
                                }
                            }
                            last_size = current_size;
                        }
                    }
                }
                
                // Check if openconnect is still running
                if i % 20 == 0 { // Every 10 seconds
                    let check = std::process::Command::new("pgrep")
                        .arg("openconnect")
                        .output();
                    if let Ok(c) = check {
                        if !c.status.success() {
                            emit_log(&tail_handle, "");
                            emit_log(&tail_handle, "⚠ openconnect process ended");
                            break;
                        }
                    }
                }
            }
        });
    }

    // Stream output events in background.
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut connected = false;
        while let Some(event) = rx.recv().await {
            match event {
                CommandEvent::Stdout(bytes) => {
                    let text = String::from_utf8_lossy(&bytes).to_string();
                    if !text.trim().is_empty() {
                        emit_log(&handle, "");
                        emit_log(&handle, "═══ OpenConnect Output ═══");
                    }
                    for line in text.lines() {
                        if !line.is_empty() && !should_filter_line(line) {
                            // Highlight errors in red
                            if is_error_line(line) {
                                emit_log(&handle, &format!("❌ {}", line));
                            } else {
                                emit_log(&handle, line);
                            }
                            
                            // Detect successful connection from openconnect output
                            if !connected && is_connected_line(line) {
                                connected = true;
                                emit_log(&handle, "");
                                emit_log(&handle, "→ Tunnel established successfully!");
                                let _ = handle.emit("vpn-status", "connected");
                            }
                            // Detect reconnection attempts (network drop, keepalive timeout)
                            if connected && is_reconnecting_line(line) {
                                connected = false;
                                emit_log(&handle, "→ Connection lost, attempting reconnect...");
                                let _ = handle.emit("vpn-status", "connecting");
                            }
                        }
                    }
                }
                CommandEvent::Stderr(bytes) => {
                    let text = String::from_utf8_lossy(&bytes).to_string();
                    if !text.trim().is_empty() {
                        emit_log(&handle, "");
                        emit_log(&handle, "═══ OpenConnect Errors ═══");
                    }
                    for line in text.lines() {
                        if !line.is_empty() && !should_filter_line(line) {
                            if is_error_line(line) {
                                emit_log(&handle, &format!("❌ {}", line));
                            } else {
                                emit_log(&handle, line);
                            }
                            
                            // Check stderr for connection indicators too
                            if !connected && is_connected_line(line) {
                                connected = true;
                                emit_log(&handle, "→ Tunnel established successfully!");
                                let _ = handle.emit("vpn-status", "connected");
                            }
                        }
                    }
                }
                CommandEvent::Terminated(payload) => {
                    emit_log(&handle, "");
                    emit_log(&handle, "═══ Connection attempt finished ═══");
                    
                    let msg = match payload.code {
                        Some(0) => {
                            emit_log(&handle, "✓ Process exited successfully");
                            "VPN process exited normally.".to_string()
                        }
                        Some(1) => {
                            emit_log(&handle, "❌ Authentication failed or connection error (exit code 1)");
                            emit_log(&handle, "");
                            emit_log(&handle, "Common causes:");
                            emit_log(&handle, "  • Incorrect username or password");
                            emit_log(&handle, "  • Gateway requires different auth method");
                            emit_log(&handle, "  • Network connectivity issues");
                            "Authentication failed.".to_string()
                        }
                        Some(2) => {
                            emit_log(&handle, "❌ Connection failed (exit code 2)");
                            emit_log(&handle, "  OpenConnect could not establish VPN tunnel");
                            "Connection failed.".to_string()
                        }
                        Some(128) => {
                            emit_log(&handle, "⚠ Privilege prompt cancelled by user");
                            "Authentication cancelled.".to_string()
                        }
                        Some(c) => {
                            emit_log(&handle, &format!("❌ Process exited with code {}", c));
                            format!("VPN process exited with code {}.", c)
                        }
                        None => {
                            emit_log(&handle, "⚠ Process terminated unexpectedly");
                            "VPN process terminated.".to_string()
                        }
                    };
                    emit_log(&handle, &msg);
                    let _ = handle.emit("vpn-status", "disconnected");

                    // Clear child handle
                    let state = handle.state::<VpnState>();
                    let mut lock = state.child.lock().await;
                    *lock = None;
                }
                CommandEvent::Error(err) => {
                    emit_log(&handle, &format!("Error: {}", err));
                    let _ = handle.emit("vpn-status", "disconnected");

                    let state = handle.state::<VpnState>();
                    let mut lock = state.child.lock().await;
                    *lock = None;
                }
                _ => {}
            }
        }
    });

    Ok(())
}
