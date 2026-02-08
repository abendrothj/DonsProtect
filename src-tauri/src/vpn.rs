use std::sync::Arc;

use serde::Serialize;
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

// ── Platform-specific helpers ─────────────────────────────────

/// Return the openconnect binary name for this platform.
fn openconnect_bin() -> &'static str {
    if cfg!(target_os = "windows") {
        // On Windows, openconnect is typically installed via the GUI
        // installer and available as openconnect.exe on PATH, or users
        // can install via chocolatey / winget.
        "openconnect.exe"
    } else {
        "openconnect"
    }
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

/// Build the full command string that pipes `stdin_data` into the openconnect
/// invocation `oc_args`, wrapped in the platform's privilege-escalation
/// mechanism.
///
/// - **macOS**: `osascript "do shell script … with administrator privileges"`
/// - **Linux**: `pkexec sh -c '…'`
/// - **Windows**: relies on the Tauri shell plugin spawning a helper that
///   triggers a UAC elevation prompt.
fn build_elevated_command(oc_args: &str, stdin_data: &str) -> ElevatedCommand {
    #[cfg(target_os = "macos")]
    {
        let inner = format!(
            "printf '%s' '{}' | {} 2>&1",
            shell_escape(stdin_data),
            oc_args,
        );
        let script = format!(
            "do shell script \"{}\" with administrator privileges",
            inner.replace('\\', "\\\\").replace('"', "\\\""),
        );
        ElevatedCommand {
            program: "osascript".into(),
            args: vec!["-e".into(), script],
        }
    }

    #[cfg(target_os = "linux")]
    {
        let inner = format!(
            "printf '%s' '{}' | {} 2>&1",
            shell_escape(stdin_data),
            oc_args,
        );
        ElevatedCommand {
            program: "pkexec".into(),
            args: vec!["sh".into(), "-c".into(), inner],
        }
    }

    #[cfg(target_os = "windows")]
    {
        // On Windows we use PowerShell's Start-Process -Verb RunAs to
        // get a UAC elevation prompt, then pipe stdin_data via echo.
        // The command runs in a new elevated cmd window.
        let inner = format!(
            "echo {} | {} 2>&1",
            shell_escape(stdin_data),
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
        }
    }
}

struct ElevatedCommand {
    program: String,
    args: Vec<String>,
}

// ── Commands ──────────────────────────────────────────────────

/// Student mode: pipe username/password to openconnect via stdin.
#[tauri::command]
pub async fn connect_student<R: Runtime>(
    app: AppHandle<R>,
    gateway: String,
    username: String,
    password: String,
) -> Result<(), String> {
    emit_log(&app, "Starting student VPN connection...");

    let oc_args = format!(
        "{} --protocol=gp --user={} --passwd-on-stdin {}",
        openconnect_bin(),
        shell_escape(&username),
        shell_escape(&gateway),
    );

    spawn_openconnect(&app, &oc_args, &password).await
}

/// Faculty mode: use prelogin-cookie from SAML auth.
/// After the SAML flow, we have a `prelogin-cookie` and `saml-username`.
/// These are fed to openconnect via --usergroup=gateway:prelogin-cookie.
#[tauri::command]
pub async fn connect_faculty<R: Runtime>(
    app: AppHandle<R>,
    gateway: String,
    cookie: String,
    username: String,
) -> Result<(), String> {
    emit_log(&app, "Starting faculty VPN connection...");

    let oc_args = format!(
        "{} --protocol=gp --user={} --usergroup=gateway:prelogin-cookie --passwd-on-stdin {}",
        openconnect_bin(),
        shell_escape(&username),
        shell_escape(&gateway),
    );

    spawn_openconnect(&app, &oc_args, &cookie).await
}

/// Kill the running VPN process.
#[tauri::command]
pub async fn disconnect<R: Runtime>(app: AppHandle<R>) -> Result<(), String> {
    let state = app.state::<VpnState>();
    let mut child = state.child.lock().await;

    if let Some(c) = child.take() {
        emit_log(&app, "Disconnecting...");
        c.kill().map_err(|e| format!("Failed to kill process: {}", e))?;
        let _ = app.emit("vpn-status", "disconnected");
        emit_log(&app, "Disconnected.");
    } else {
        emit_log(&app, "No active connection.");
    }

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────

fn emit_log<R: Runtime>(app: &AppHandle<R>, msg: &str) {
    let _ = app.emit(
        "vpn-log",
        LogPayload {
            message: msg.to_string(),
        },
    );
}

/// Check if an openconnect output line indicates a successful tunnel.
fn is_connected_line(line: &str) -> bool {
    let lower = line.to_lowercase();
    lower.contains("connected to")
        || lower.contains("esp tunnel connected")
        || lower.contains("tunnel negotiation")
        || lower.contains("established dtls")
        || lower.contains("connected as")
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
    stdin_data: &str,
) -> Result<(), String> {
    // Check no existing connection
    {
        let state = app.state::<VpnState>();
        let existing = state.child.lock().await;
        if existing.is_some() {
            return Err("Already connected. Disconnect first.".into());
        }
    }

    let elevated = build_elevated_command(oc_args, stdin_data);

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

    // Stream output events in background.
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut connected = false;
        while let Some(event) = rx.recv().await {
            match event {
                CommandEvent::Stdout(bytes) => {
                    let text = String::from_utf8_lossy(&bytes).to_string();
                    for line in text.lines() {
                        if !line.is_empty() {
                            emit_log(&handle, line);
                        }
                        // Detect successful connection from openconnect output
                        if !connected && is_connected_line(line) {
                            connected = true;
                            let _ = handle.emit("vpn-status", "connected");
                        }
                    }
                }
                CommandEvent::Stderr(bytes) => {
                    let text = String::from_utf8_lossy(&bytes).to_string();
                    for line in text.lines() {
                        if !line.is_empty() {
                            emit_log(&handle, line);
                        }
                    }
                }
                CommandEvent::Terminated(payload) => {
                    let msg = match payload.code {
                        Some(0) => "VPN process exited normally.".to_string(),
                        Some(c) => format!("VPN process exited with code {}.", c),
                        None => "VPN process terminated.".to_string(),
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
