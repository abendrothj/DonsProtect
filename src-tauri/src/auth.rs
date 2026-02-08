use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Listener, Manager, Runtime, WebviewUrl, WebviewWindowBuilder};

use crate::vpn::LogPayload;

/// Result from a successful GlobalProtect SAML authentication.
#[derive(Clone, Serialize)]
pub struct SamlResult {
    pub username: String,
    pub cookie: String,
}

/// JavaScript injected into every page of the SAML webview.
///
/// GlobalProtect SAML works like this:
///   1. User authenticates at the IdP (Duo, Okta, etc.)
///   2. The IdP sends a hidden form POST back to the GP portal's ACS endpoint
///      (a URL containing `/SAML20/SP/ACS`)
///   3. The GP server responds with `prelogin-cookie` and `saml-username`
///      as custom **HTTP response headers**.
///
/// Since the embedded webview doesn't expose HTTP response headers to JS,
/// we intercept the ACS form submission *before* it happens:
///   - We hook all form `submit` events.
///   - When the form action contains `/SAML20/SP/ACS`, we grab the
///     SAMLResponse field and encode it in the page title.
///   - The Rust side picks this up, replays the POST with reqwest, and reads
///     the `prelogin-cookie` + `saml-username` response headers.
const SAML_INTERCEPT_SCRIPT: &str = r#"
(function() {
    if (window.__gp_saml_hooked) return;
    window.__gp_saml_hooked = true;

    /* Hook form submissions destined for the GP ACS endpoint */
    document.addEventListener('submit', function(e) {
        var form = e.target;
        var action = (form.action || '').toString();
        if (action.indexOf('/SAML20/SP/ACS') === -1) return;

        /* Grab the SAMLResponse value */
        var resp = '';
        for (var i = 0; i < form.elements.length; i++) {
            if (form.elements[i].name === 'SAMLResponse') {
                resp = form.elements[i].value;
                break;
            }
        }
        if (!resp) return;

        /* Prevent the browser from actually submitting the form */
        e.preventDefault();
        e.stopPropagation();

        /* Encode the ACS URL and SAMLResponse into the title.
           Format:  GP_SAML:<acs_url>|<base64_SAMLResponse>
           The SAMLResponse is already base64, but it may contain chars
           that break a simple split – so we encode it again. */
        document.title = 'GP_SAML:' + action + '|' + encodeURIComponent(resp);
    }, true);
})();
"#;

/// Opens a webview to the gateway's GlobalProtect SAML login.
///
/// Injects JS that intercepts the SAML ACS form submission and passes the
/// SAMLResponse back to Rust. Rust replays the POST with reqwest so it can
/// read the `prelogin-cookie` and `saml-username` response headers that the
/// GP server returns.
///
/// Returns a `SamlResult` with the username and prelogin-cookie.
#[tauri::command]
pub async fn start_saml_flow<R: Runtime>(
    app: AppHandle<R>,
    gateway: String,
) -> Result<SamlResult, String> {
    let _ = app.emit(
        "vpn-log",
        LogPayload {
            message: "Opening SSO login...".into(),
        },
    );

    let clientos = if cfg!(target_os = "windows") {
        "Windows"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else {
        "Mac"
    };

    let url = format!(
        "https://{}/global-protect/prelogin.esp?tmp=tmp&clientVer=4100&clientos={}",
        gateway, clientos,
    );

    // Channel to receive the intercepted SAMLResponse + ACS URL
    let (tx, rx) = tokio::sync::oneshot::channel::<(String, String)>();
    let tx = Arc::new(Mutex::new(Some(tx)));
    let tx_for_page = tx.clone();

    let _auth_window = WebviewWindowBuilder::new(
        &app,
        "auth",
        WebviewUrl::External(url.parse().map_err(|e| format!("Bad URL: {}", e))?),
    )
    .title("USFCA SSO Login")
    .inner_size(900.0, 700.0)
    .center()
    .initialization_script(SAML_INTERCEPT_SCRIPT)
    .on_page_load(move |webview, _payload| {
        // Re-inject on every page load (SSO redirects through multiple pages)
        let _ = webview.eval(SAML_INTERCEPT_SCRIPT);

        // Check if the title carries our intercepted data
        if let Ok(title) = webview.title() {
            if let Some(data) = title.strip_prefix("GP_SAML:") {
                if let Some((acs_url, saml_resp_encoded)) = data.split_once('|') {
                    let acs_url = acs_url.to_string();
                    let saml_resp = saml_resp_encoded.to_string();
                    if let Ok(mut guard) = tx_for_page.lock() {
                        if let Some(sender) = guard.take() {
                            let _ = sender.send((acs_url, saml_resp));
                        }
                    }
                    let _ = webview.close();
                }
            }
        }
    })
    .build()
    .map_err(|e| format!("Failed to open auth window: {}", e))?;

    // Also listen for title changes on the auth window
    if let Some(auth) = app.get_webview_window("auth") {
        let tx_title = tx.clone();
        let app_for_title = app.clone();
        auth.listen("tauri://webview-title-changed", move |_event| {
            if let Some(auth_w) = app_for_title.get_webview_window("auth") {
                if let Ok(title) = auth_w.title() {
                    if let Some(data) = title.strip_prefix("GP_SAML:") {
                        if let Some((acs_url, saml_resp_encoded)) = data.split_once('|') {
                            let acs_url = acs_url.to_string();
                            let saml_resp = saml_resp_encoded.to_string();
                            let _ = app_for_title.emit(
                                "vpn-log",
                                LogPayload {
                                    message: "SAML response captured.".into(),
                                },
                            );
                            if let Ok(mut guard) = tx_title.lock() {
                                if let Some(sender) = guard.take() {
                                    let _ = sender.send((acs_url, saml_resp));
                                }
                            }
                            let _ = auth_w.close();
                        }
                    }
                }
            }
        });
    }

    // Wait for the intercepted SAML data
    let (acs_url, saml_resp_encoded) = rx
        .await
        .map_err(|_| "Auth window closed without completing SAML login.".to_string())?;

    emit_log(&app, "Replaying SAML assertion to gateway...");

    // Replay the SAML POST to the ACS endpoint from Rust so we can read the
    // response headers that contain prelogin-cookie and saml-username.
    let saml_response = urlencoding::decode(&saml_resp_encoded)
        .map_err(|e| format!("Failed to decode SAMLResponse: {}", e))?
        .into_owned();

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // some GP portals use self-signed certs
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let resp = client
        .post(&acs_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(format!("SAMLResponse={}", urlencoding::encode(&saml_response)))
        .send()
        .await
        .map_err(|e| format!("Failed to POST to ACS: {}", e))?;

    // Extract prelogin-cookie and saml-username from response headers
    let username = resp
        .headers()
        .get("saml-username")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or("Gateway did not return saml-username header.")?;

    let cookie = resp
        .headers()
        .get("prelogin-cookie")
        .or_else(|| resp.headers().get("portal-userauthcookie"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or("Gateway did not return prelogin-cookie header.")?;

    emit_log(&app, &format!("Authenticated as {}", username));

    Ok(SamlResult { username, cookie })
}

fn emit_log<R: Runtime>(app: &AppHandle<R>, msg: &str) {
    let _ = app.emit(
        "vpn-log",
        LogPayload {
            message: msg.to_string(),
        },
    );
}
