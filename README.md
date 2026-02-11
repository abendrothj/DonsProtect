# DonsProtect

A lightweight, transparent desktop VPN client for the University of San Francisco. Built as a clean alternative to the official Palo Alto GlobalProtect client, which resists force-quitting and runs opaque background processes.

DonsProtect uses the exact same GlobalProtect protocol under the hood (via [OpenConnect](https://www.infradead.org/openconnect/)) but gives you full control: you can see every log line, quit any time, and nothing lingers after you close it.

Works on **macOS**, **Windows**, and **Linux**.

> Made by **Jake Abendroth**, USF student.

---

## Why This Exists

The official GlobalProtect client:

- Installs persistent system services and daemons that survive reboots
- Fights you when you try to quit or uninstall it
- Runs opaque background agents with no visibility into what they're doing
- Cannot be easily force-quit without workarounds

DonsProtect does none of that. It's a single app. You launch it, connect, and when you quit — everything dies. No background agents, no system extensions, no residual processes.

## Features

- **System tray app** — lives in your system tray / menu bar, toggle the window with a click
- **Student login** — authenticate with your USF NetID and password
- **Faculty/Staff Duo login** — authenticate with password + Duo Push or passcode
- **Faculty/Staff SSO login** — authenticate via SAML through USFCA's identity provider
- **Full log visibility** — see every line of OpenConnect output in real time
- **Clean quit** — closing the app kills the VPN tunnel completely. Nothing left behind
- **Cross-platform** — runs on macOS, Windows, and Linux
- **Dark mode UI** — clean, modern interface
- **Same protocol** — uses GlobalProtect (`--protocol=gp`), the same as the official client

## Screenshot

```text
┌──────────────────────────┐
│       DonsProtect        │
│     USFCA VPN Client     │
│                          │
│    🔴 Disconnected       │
│                          │
│  Gateway: [vpn1.usfca]  │
│                          │
│ [Password] [Duo] [SSO]  │
│                          │
│  NetID:    [________]    │
│  Password: [________]    │
│                          │
│      [ Connect ]         │
│                          │
│  Logs                    │
│  ┌─────────────────────┐ │
│  │ DonsProtect ready.  │ │
│  └─────────────────────┘ │
└──────────────────────────┘
```

## Prerequisites

### OpenConnect

DonsProtect wraps OpenConnect. Install it for your platform:

<details>
<summary><strong>macOS</strong></summary>

```bash
brew install openconnect
```

</details>

<details>
<summary><strong>Windows</strong></summary>

Download the installer from the [OpenConnect GUI releases](https://github.com/openconnect/openconnect-gui/releases) or use a package manager:

```powershell
# Chocolatey
choco install openconnect

# or winget
winget install openconnect
```

Make sure `openconnect.exe` is on your `PATH`.

</details>

<details>
<summary><strong>Linux (Debian / Ubuntu)</strong></summary>

```bash
sudo apt install openconnect
```

</details>

<details>
<summary><strong>Linux (Fedora / RHEL)</strong></summary>

```bash
sudo dnf install openconnect
```

</details>

<details>
<summary><strong>Linux (Arch)</strong></summary>

```bash
sudo pacman -S openconnect
```

</details>

Verify installation (all platforms):

```bash
openconnect --version
```

You need version **8.0+** (GlobalProtect support). Version 9.x+ is recommended.

### Rust & Cargo

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

On Windows, download and run [rustup-init.exe](https://rustup.rs/).

### Platform Build Dependencies

<details>
<summary><strong>macOS</strong></summary>

```bash
xcode-select --install
```

</details>

<details>
<summary><strong>Windows</strong></summary>

- [Microsoft Visual Studio C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
- [WebView2](https://developer.microsoft.com/en-us/microsoft-edge/webview2/) (included in Windows 10/11 with Edge)

</details>

<details>
<summary><strong>Linux</strong></summary>

```bash
# Debian / Ubuntu
sudo apt install libwebkit2gtk-4.1-dev build-essential curl wget file \
  libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev

# Fedora
sudo dnf install webkit2gtk4.1-devel openssl-devel curl wget file \
  libxdo-devel libappindicator-gtk3-devel librsvg2-devel

# Arch
sudo pacman -S webkit2gtk-4.1 base-devel curl wget file openssl \
  xdotool libappindicator-gtk3 librsvg
```

</details>

### Tauri CLI

```bash
cargo install tauri-cli --version "^2"
```

## Building

```bash
# Clone the repo
git clone https://github.com/jabendroth/DonsProtect.git
cd DonsProtect

# Development (hot-reload)
cargo tauri dev

# Production build
cargo tauri build
```

Build output locations:

| Platform | Output |
|----------|--------|
| macOS | `src-tauri/target/release/bundle/macos/DonsProtect.app` |
| Windows | `src-tauri/target/release/bundle/nsis/DonsProtect_x.x.x_x64-setup.exe` |
| Linux (deb) | `src-tauri/target/release/bundle/deb/dons-protect_x.x.x_amd64.deb` |
| Linux (AppImage) | `src-tauri/target/release/bundle/appimage/dons-protect_x.x.x_amd64.AppImage` |

## Usage

### Student Login (Password)

1. Select **vpn1.usfca.edu** from the gateway dropdown
2. Enter your USF **NetID** and **password**
3. Click **Connect**
4. Your OS will prompt for admin/root credentials (OpenConnect needs root to create a tunnel interface)

### Faculty / Staff Login (Duo Push)

1. Select **svpn.usfca.edu** (or **svpn1.usfca.edu** backup) from the gateway dropdown
2. Enter your USF **NetID** and **password**
3. Optionally enter a **Duo passcode**, or leave blank for a push notification
4. Click **Connect with Duo**
5. Approve the Duo push on your phone (if you left the passcode blank)

### Faculty / Staff Login (SSO / SAML)

1. Select **prisma.usfca.edu** from the gateway dropdown
2. Click **Log in with SSO**
3. Complete authentication in the popup window (redirects to `idpa.usfca.edu`)
4. The VPN connects automatically after authentication

### Disconnecting

Click **Disconnect** in the app, use the tray menu, or just quit the app entirely.

## Architecture

```
DonsProtect
├── src/                      # Frontend (plain HTML/CSS/JS, no frameworks)
│   ├── index.html            # Dark-mode dashboard UI
│   ├── main.js               # Tauri IPC calls & event listeners
│   └── styles.css            # Styling
└── src-tauri/                # Rust backend (Tauri v2)
    └── src/
        ├── main.rs           # Entry point
        ├── lib.rs            # App setup, tray icon, menu
        ├── vpn.rs            # OpenConnect process management (cross-platform)
        └── auth.rs           # GlobalProtect SAML authentication
```

### How the VPN Connection Works

DonsProtect speaks the same **Palo Alto GlobalProtect** protocol as the official client:

1. **Password mode** (vpn1): Runs `openconnect --protocol=gp --user=<NetID> --passwd-on-stdin <gateway>` with elevated privileges, piping the password.

2. **Duo mode** (svpn / svpn1): Same as password mode, but pipes both the password and the Duo challenge response (`push` or a passcode) as two stdin lines. The GlobalProtect server sends a RADIUS challenge after the password, and OpenConnect reads the second line as the response.

3. **SSO / SAML mode** (prisma):
   - Opens a webview to the GlobalProtect prelogin endpoint
   - User completes authentication at `idpa.usfca.edu` (Shibboleth IdP)
   - JavaScript intercepts the SAML ACS form submission
   - Rust replays the SAML POST to capture the `prelogin-cookie` and `saml-username` response headers
   - Runs `openconnect --protocol=gp --user=<saml-username> --usergroup=gateway:prelogin-cookie --passwd-on-stdin <gateway>`, piping the prelogin-cookie

3. **Elevated privileges** (platform-specific):

   | Platform | Mechanism |
   |----------|-----------|
   | macOS | `osascript "do shell script … with administrator privileges"` |
   | Linux | `pkexec sh -c '…'` (PolicyKit) |
   | Windows | PowerShell `Start-Process -Verb RunAs` (UAC prompt) |

### USFCA Gateways

| Gateway | Audience | Auth Method |
|---------|----------|-------------|
| `vpn1.usfca.edu` | Students, Board of Trustees | NetID + Password |
| `svpn.usfca.edu` | Faculty, Staff, Student Workers | Password + Duo Push |
| `svpn1.usfca.edu` | Faculty, Staff (backup) | Password + Duo Push |
| `prisma.usfca.edu` | Faculty, Staff, Student Workers | SAML SSO via `idpa.usfca.edu` |

All are Palo Alto GlobalProtect portals. `prisma.usfca.edu` runs on Prisma Access (cloud).

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Framework | [Tauri v2](https://v2.tauri.app/) |
| Backend | Rust |
| Frontend | Vanilla HTML/CSS/JS (zero npm dependencies) |
| VPN | [OpenConnect](https://www.infradead.org/openconnect/) with `--protocol=gp` |
| Auth | SAML via embedded webview + [reqwest](https://docs.rs/reqwest) header capture |
| Platforms | macOS, Windows, Linux |

**No npm. No node_modules. No webpack. No React.** The frontend is three static files.

## Differences from Official GlobalProtect

| | GlobalProtect | DonsProtect |
|---|---|---|
| Quit behavior | Resists quitting, restarts itself | Quit kills everything |
| Background agents | Multiple persistent services/daemons | None |
| System extensions | Installs kernel/network extensions | None (uses OpenConnect) |
| Visibility | Opaque, no logs | Full OpenConnect log stream |
| Uninstall | Requires special uninstaller tool | Delete the app |
| Protocol | GlobalProtect (proprietary client) | GlobalProtect (OpenConnect, open source) |
| Force quit | Often fails or reconnects | Works normally |
| Cross-platform | Separate clients per OS | Single codebase, all desktops |

## Troubleshooting

### "openconnect: command not found"

Install OpenConnect for your platform (see [Prerequisites](#prerequisites)).

### Connection fails immediately

- Make sure you're not already connected via the official GlobalProtect client
- Check that the gateway hostname resolves: `nslookup vpn1.usfca.edu`
- Try connecting manually to verify OpenConnect works:
  ```bash
  sudo openconnect --protocol=gp vpn1.usfca.edu
  ```
  (On Windows, run an elevated Command Prompt instead of using `sudo`.)

### SAML window doesn't capture cookie

- The Duo SSO flow must complete fully in the popup window
- If the window closes without connecting, try again — some IdP redirects can be flaky
- Check the log pane for error details

### Admin/root prompt doesn't appear

- **macOS**: Ensure your user account has admin privileges
- **Linux**: Make sure `pkexec` is installed (`sudo apt install policykit-1`)
- **Windows**: UAC must be enabled (it is by default)

### Linux: "Failed to spawn pkexec"

Install PolicyKit:
```bash
# Debian / Ubuntu
sudo apt install policykit-1

# Fedora
sudo dnf install polkit

# Arch
sudo pacman -S polkit
```

### Windows: OpenConnect not found

Ensure `openconnect.exe` is on your system `PATH`. You can verify by running `openconnect --version` in Command Prompt.

## Credits

- [OpenConnect](https://www.infradead.org/openconnect/) — the VPN engine
- [Tauri](https://tauri.app/) — the app framework
- [gp-saml-gui](https://github.com/dlenski/gp-saml-gui) — inspiration for the SAML auth approach
- University of San Francisco ITS — for running the GlobalProtect infrastructure
