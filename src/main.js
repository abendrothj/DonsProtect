document.addEventListener("DOMContentLoaded", async () => {
  const { invoke } = window.__TAURI__.core;
  const { listen } = window.__TAURI__.event;

  // ── DOM refs ──
  const dot           = document.getElementById("status-dot");
  const statusText    = document.getElementById("status-text");
  const gateway       = document.getElementById("gateway");
  const gatewayCustom = document.getElementById("gateway-custom");
  const logs          = document.getElementById("logs");
  const tabs          = document.querySelectorAll(".tab");

  const panelPassword  = document.getElementById("panel-password");
  const panelDuo       = document.getElementById("panel-duo");
  const panelSso       = document.getElementById("panel-sso");
  const panelConnected = document.getElementById("panel-connected");
  const authPanels     = [panelPassword, panelDuo, panelSso];

  const btnPassword   = document.getElementById("btn-connect-password");
  const btnDuo        = document.getElementById("btn-connect-duo");
  const btnSso        = document.getElementById("btn-connect-sso");
  const btnDisconnect = document.getElementById("btn-disconnect");

  const gatewayStatus     = document.getElementById("gateway-status");
  const gatewayStatusIcon = document.getElementById("gateway-status-icon");
  const gatewayStatusText = document.getElementById("gateway-status-text");

  // Password-only fields
  const usernameInput = document.getElementById("username");
  const passwordInput = document.getElementById("password");

  // Duo fields
  const duoUsernameInput = document.getElementById("duo-username");
  const duoPasswordInput = document.getElementById("duo-password");
  const duoCodeInput     = document.getElementById("duo-code");

  let state = "disconnected"; // disconnected | connecting | connected

  // ── Gateway helpers ──
  function getGateway() {
    return gateway.value === "__custom__" ? gatewayCustom.value.trim() : gateway.value;
  }

  // Map gateway to the recommended tab
  const GATEWAY_TAB = {
    "vpn1.usfca.edu":   "password",
    "svpn.usfca.edu":   "duo",
    "svpn1.usfca.edu":  "duo",
    "prisma.usfca.edu": "sso",
  };

  function tabForGateway(gw) {
    return GATEWAY_TAB[gw] || "password";
  }

  // ── Gateway validation via prelogin probe ──
  async function probeGateway(gw) {
    if (!gw || gw.trim() === "") {
      gatewayStatus.style.display = "none";
      return;
    }
    
    // Show validating state
    gatewayStatus.style.display = "flex";
    gatewayStatus.className = "gateway-status validating";
    gatewayStatusIcon.className = "status-icon spinner";
    gatewayStatusText.textContent = "Validating gateway...";
    
    try {
      appendLog("Validating gateway " + gw + "...");
      const result = await invoke("prelogin_probe", { gateway: gw });
      
      // Show valid state
      gatewayStatus.className = "gateway-status valid";
      gatewayStatusIcon.className = "status-icon check";
      
      const authLabel = {
        "password": "Password",
        "duo": "Duo Push",
        "saml": "SAML SSO"
      }[result.auth_method] || result.auth_method;
      
      let statusMsg = "Gateway valid • Auth: " + authLabel;
      if (result.server_ip) {
        statusMsg += " • IP: " + result.server_ip;
      }
      if (result.region) {
        statusMsg += " • Region: " + result.region;
      }
      
      gatewayStatusText.textContent = statusMsg;
      appendLog("✓ " + statusMsg);
      
      // Auto-switch to the detected auth method
      activateTab(result.auth_method);
      
      return result;
    } catch (err) {
      // Show invalid state
      gatewayStatus.className = "gateway-status invalid";
      gatewayStatusIcon.className = "status-icon cross";
      gatewayStatusText.textContent = "Gateway unreachable or invalid";
      
      appendLog("⚠ Gateway probe failed: " + err);
      return null;
    }
  }

  // ── Persistence ──
  function savePrefs() {
    try {
      localStorage.setItem("dp_gateway", gateway.value);
      if (gateway.value === "__custom__") {
        localStorage.setItem("dp_gateway_custom", gatewayCustom.value);
      }
      localStorage.setItem("dp_tab", document.querySelector(".tab.active").dataset.tab);
      localStorage.setItem("dp_username", usernameInput.value);
      localStorage.setItem("dp_duo_username", duoUsernameInput.value);
    } catch (_) { /* localStorage unavailable */ }
  }

  function loadPrefs() {
    try {
      const gw = localStorage.getItem("dp_gateway");
      if (gw && [...gateway.options].some((o) => o.value === gw)) {
        gateway.value = gw;
        if (gw === "__custom__") {
          gatewayCustom.style.display = "";
          gatewayCustom.value = localStorage.getItem("dp_gateway_custom") || "";
        }
      }
      const tab = localStorage.getItem("dp_tab");
      if (tab) activateTab(tab);
      else activateTab(tabForGateway(gateway.value));

      const user = localStorage.getItem("dp_username");
      if (user) usernameInput.value = user;
      const duoUser = localStorage.getItem("dp_duo_username");
      if (duoUser) duoUsernameInput.value = duoUser;
    } catch (_) { /* localStorage unavailable */ }
  }

  // ── State management ──
  function setState(s) {
    state = s;
    dot.className = "dot " + s;

    const idle = s === "disconnected";
    gateway.disabled = !idle;
    gatewayCustom.disabled = !idle;
    
    // Hide gateway status when connecting/connected
    if (!idle) {
      gatewayStatus.style.display = "none";
    }

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
    authPanels.forEach((p) => p.classList.remove("active"));
    panelConnected.classList.remove("active");
  }

  function showAuthPanels() {
    panelConnected.classList.remove("active");
    const active = document.querySelector(".tab.active").dataset.tab;
    authPanels.forEach((p) => p.classList.remove("active"));
    const target = document.getElementById("panel-" + active);
    if (target) target.classList.add("active");
  }

  function activateTab(tabName) {
    tabs.forEach((t) => t.classList.remove("active"));
    const target = document.querySelector('[data-tab="' + tabName + '"]');
    if (target) target.classList.add("active");
    showAuthPanels();
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
      activateTab(tab.dataset.tab);
    });
  });

  // Gateway dropdown auto-switches tab & toggles custom input
  gateway.addEventListener("change", async () => {
    if (state !== "disconnected") return;
    const isCustom = gateway.value === "__custom__";
    gatewayCustom.style.display = isCustom ? "" : "none";
    
    if (!isCustom && gateway.value) {
      // Probe the selected gateway to auto-detect auth method
      await probeGateway(gateway.value);
    } else if (!isCustom) {
      // Fallback to static mapping
      activateTab(tabForGateway(gateway.value));
    }
  });

  // Probe custom gateway when user finishes typing
  let probeTimeout = null;
  gatewayCustom.addEventListener("input", () => {
    if (state !== "disconnected") return;
    clearTimeout(probeTimeout);
    probeTimeout = setTimeout(async () => {
      const gw = gatewayCustom.value.trim();
      if (gw) {
        await probeGateway(gw);
      }
    }, 800); // Debounce: wait 800ms after user stops typing
  });

  // ── Event listeners from Rust ──
  await listen("vpn-log", (e) => {
    appendLog(e.payload.message);
  });

  await listen("vpn-status", (e) => {
    setState(e.payload);
  });

  // ── Connect: Password only (vpn1 — students) ──
  btnPassword.addEventListener("click", async () => {
    const gw = getGateway();
    const user = usernameInput.value.trim();
    const pass = passwordInput.value;
    if (!gw) { appendLog("Please enter a gateway address."); return; }
    if (!user || !pass) { appendLog("Please enter your NetID and password."); return; }
    savePrefs();
    setState("connecting");
    passwordInput.value = "";
    appendLog("Initiating connection...");
    try {
      await invoke("connect_student", { gateway: gw, username: user, password: pass });
    } catch (err) {
      appendLog("Error: " + err);
      setState("disconnected");
    }
  });

  // ── Connect: Duo (svpn — faculty, password + Duo challenge) ──
  btnDuo.addEventListener("click", async () => {
    const gw = getGateway();
    const user = duoUsernameInput.value.trim();
    const pass = duoPasswordInput.value;
    const code = duoCodeInput.value.trim();
    if (!gw) { appendLog("Please enter a gateway address."); return; }
    if (!user || !pass) { appendLog("Please enter your NetID and password."); return; }
    savePrefs();
    setState("connecting");
    duoPasswordInput.value = "";
    duoCodeInput.value = "";
    const challenge = code || "push";
    appendLog("Initiating Duo connection (" + (code ? "passcode" : "push") + ")...");
    try {
      await invoke("connect_duo", { gateway: gw, username: user, password: pass, challenge: challenge });
    } catch (err) {
      appendLog("Error: " + err);
      setState("disconnected");
    }
  });

  // ── Connect: SSO / SAML (prisma — faculty) ──
  btnSso.addEventListener("click", async () => {
    const gw = getGateway();
    if (!gw) { appendLog("Please enter a gateway address."); return; }
    savePrefs();
    setState("connecting");
    appendLog("Opening SSO login...");
    try {
      const result = await invoke("start_saml_flow", { gateway: gw });
      appendLog("Authenticated as " + result.username + ". Starting VPN...");
      await invoke("connect_faculty", { gateway: gw, cookie: result.cookie, username: result.username });
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
  loadPrefs();

  // Probe the preselected gateway on load
  const initialGateway = getGateway();
  if (initialGateway && gateway.value !== "__custom__") {
    probeGateway(initialGateway);
  }

  try {
    const bin = await invoke("check_openconnect");
    appendLog("DonsProtect ready. (openconnect: " + bin + ")");
  } catch (err) {
    appendLog("WARNING: " + err);
    appendLog("DonsProtect cannot connect without OpenConnect installed.");
  }
});
