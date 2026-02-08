mod auth;
mod vpn;

use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager, RunEvent,
};
use vpn::VpnState;

pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(VpnState::new())
        .invoke_handler(tauri::generate_handler![
            vpn::connect_student,
            vpn::connect_faculty,
            vpn::disconnect,
            auth::start_saml_flow,
        ])
        .setup(|app| {
            // ── Tray Menu ──
            let show = MenuItem::with_id(app, "show", "Show Status", true, None::<&str>)?;
            let connect = MenuItem::with_id(app, "connect", "Connect", true, None::<&str>)?;
            let disconnect =
                MenuItem::with_id(app, "disconnect", "Disconnect", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;

            let menu = Menu::with_items(app, &[&show, &connect, &disconnect, &quit])?;

            // ── Tray Icon ──
            let _tray = TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    "connect" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    "disconnect" => {
                        let handle = app.clone();
                        tauri::async_runtime::spawn(async move {
                            let _ = vpn::disconnect(handle).await;
                        });
                    }
                    "quit" => {
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(w) = app.get_webview_window("main") {
                            if w.is_visible().unwrap_or(false) {
                                let _ = w.hide();
                            } else {
                                let _ = w.show();
                                let _ = w.set_focus();
                            }
                        }
                    }
                })
                .build(app)?;

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error building DonsProtect");

    app.run(|app_handle, event| {
        if let RunEvent::Exit = event {
            // Clean shutdown: kill any running VPN process
            let state = app_handle.state::<VpnState>();
            let mut child = state.child.blocking_lock();
            if let Some(c) = child.take() {
                let _ = c.kill();
            }
            // Also kill any orphaned openconnect that survived the wrapper kill
            vpn::cleanup_openconnect();
        }
    });
}
