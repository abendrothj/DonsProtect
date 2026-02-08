document.addEventListener("DOMContentLoaded", async () => {
  const { invoke } = window.__TAURI__.core;
  const { listen } = window.__TAURI__.event;

  // ── DOM refs ──
  const dot         = document.getElementById("status-dot");
  const statusText  = document.getElementById("status-text");
  const gateway     = document.getElementById("gateway");
  const logs        = document.getElementById("logs");
  const tabs        = document.querySelectorAll(".tab");

  const panelStudent   = document.getElementById("panel-student");
  const panelFaculty   = document.getElementById("panel-faculty");
  const panelConnected = document.getElementById("panel-connected");

  const btnStudent    = document.getElementById("btn-connect-student");
  const btnFaculty    = document.getElementById("btn-connect-faculty");
  const btnDisconnect = document.getElementById("btn-disconnect");

  const usernameInput = document.getElementById("username");
  const passwordInput = document.getElementById("password");

  let state = "disconnected"; // disconnected | connecting | connected

  // ── State management ──
  function setState(s) {
    state = s;
    dot.className = "dot " + s;

    if (s === "disconnected") {
      statusText.textContent = "Disconnected";
      showAuthPanels();
    } else if (s === "connecting") {
      statusText.textContent = "Connecting...";
      hideAuthPanels();
      panelConnected.classList.add("active");
    } else if (s === "connected") {
      statusText.textContent = "Connected";
      hideAuthPanels();
      panelConnected.classList.add("active");
    }
  }

  function hideAuthPanels() {
    panelStudent.classList.remove("active");
    panelFaculty.classList.remove("active");
    panelConnected.classList.remove("active");
  }

  function showAuthPanels() {
    panelConnected.classList.remove("active");
    const active = document.querySelector(".tab.active").dataset.tab;
    panelStudent.classList.toggle("active", active === "student");
    panelFaculty.classList.toggle("active", active === "faculty");
  }

  function appendLog(msg) {
    const ts = new Date().toLocaleTimeString();
    logs.textContent += "[" + ts + "] " + msg + "\n";
    logs.scrollTop = logs.scrollHeight;
  }

  // ── Tab switching ──
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      if (state !== "disconnected") return;
      tabs.forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      showAuthPanels();
    });
  });

  // Gateway dropdown auto-switches tab
  gateway.addEventListener("change", () => {
    if (state !== "disconnected") return;
    const isStudent = gateway.value === "vpn1.usfca.edu";
    tabs.forEach((t) => t.classList.remove("active"));
    document.querySelector(isStudent ? '[data-tab="student"]' : '[data-tab="faculty"]').classList.add("active");
    showAuthPanels();
  });

  // ── Event listeners from Rust ──
  await listen("vpn-log", (e) => {
    appendLog(e.payload.message);
  });

  await listen("vpn-status", (e) => {
    setState(e.payload);
  });

  // ── Connect: Student ──
  btnStudent.addEventListener("click", async () => {
    const user = usernameInput.value.trim();
    const pass = passwordInput.value;
    if (!user || !pass) {
      appendLog("Please enter your NetID and password.");
      return;
    }
    setState("connecting");
    appendLog("Initiating student connection...");
    try {
      await invoke("connect_student", {
        gateway: gateway.value,
        username: user,
        password: pass,
      });
    } catch (err) {
      appendLog("Error: " + err);
      setState("disconnected");
    }
  });

  // ── Connect: Faculty (SAML) ──
  btnFaculty.addEventListener("click", async () => {
    setState("connecting");
    appendLog("Opening Duo SSO...");
    try {
      const result = await invoke("start_saml_flow", {
        gateway: gateway.value,
      });
      appendLog("Authenticated as " + result.username + ". Starting VPN...");
      await invoke("connect_faculty", {
        gateway: gateway.value,
        cookie: result.cookie,
        username: result.username,
      });
    } catch (err) {
      appendLog("Error: " + err);
      setState("disconnected");
    }
  });

  // ── Disconnect ──
  btnDisconnect.addEventListener("click", async () => {
    try {
      await invoke("disconnect");
    } catch (err) {
      appendLog("Error: " + err);
    }
  });

  // ── Init ──
  appendLog("DonsProtect ready.");
});
