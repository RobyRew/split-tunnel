const { invoke } = window.__TAURI__.core;
const $ = (id) => document.getElementById(id);
const F = ["host", "user", "port", "key", "lport"];

let connected = false;
let signedIn = false;

function say(text, kind = "") {
  const m = $("msg");
  m.textContent = text;
  m.className = "msg " + kind;
}

const show = (id, on) => $(id).classList.toggle("hidden", !on);

function readForm() {
  return {
    host: $("host").value.trim(),
    user: $("user").value.trim() || "tunnel",
    port: parseInt($("port").value, 10) || 2223,
    local_port: parseInt($("lport").value, 10) || 1080,
    key_path: $("key").value.trim(),
    autostart: $("autostart").checked,
    manage_spotify: $("spot").checked,
    enroll_base: $("base").value.trim(),
    // Preserved as-is: the OIDC block is discovered from the server, not typed,
    // so the form must not clobber it on every keystroke.
    oidc: window.__oidc || {},
  };
}

async function save(quiet) {
  try {
    await invoke("save_config", { cfg: readForm() });
    if (!quiet) say("Saved.", "ok");
  } catch (e) {
    say(String(e), "err");
  }
}

function relative(ts) {
  const secs = ts - Math.floor(Date.now() / 1000);
  if (secs <= 0) return "expired";
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  return h > 0 ? `${h}h ${m}m` : `${m}m`;
}

function paint(status) {
  const state = (status && status.state ? status.state : "Stopped").toLowerCase();
  const pill = $("pill");
  pill.className = "pill " + state;
  pill.textContent =
    state === "connected" ? "Connected"
    : state === "starting" ? "Starting…"
    : state === "reconnecting" ? "Reconnecting"
    : state === "error" ? "Error" : "Stopped";

  connected = state !== "stopped" && state !== "error";
  const btn = $("toggle");
  btn.textContent = connected ? "Disconnect" : "Connect";
  btn.classList.toggle("on", connected);

  if (status && status.detail) {
    say(status.detail, state === "error" ? "err" : "");
  } else if (state === "connected") {
    say("Traffic for the configured app is routed through your server.", "ok");
  }
}

/** Reflect the sign-in state machine. Polled, because the browser half of the
 *  device flow can take as long as the user takes. */
async function paintAuth() {
  let a;
  try { a = await invoke("auth_state"); } catch (_) { return; }
  const state = a.state;
  const d = a.detail || {};

  show("card-signin", state === "SignedOut" || state === "Failed");
  show("card-waiting", state === "Waiting");
  show("card-account", state === "SignedIn" || state === "Enrolling");
  signedIn = state === "SignedIn";

  if (state === "Waiting") {
    $("ucode").textContent = d.user_code || "—";
    $("vuri").textContent = d.verification_uri || "—";
  }

  if (state === "Enrolling") {
    $("who").textContent = "Finishing…";
    $("certinfo").textContent = "Requesting your certificate.";
  }

  if (state === "SignedIn") {
    $("who").textContent = d.email || "signed in";
    const rec = await invoke("enrollment").catch(() => null);
    $("certinfo").textContent = rec
      ? `Access valid for ${relative(rec.expires_at)} — renews itself. Server ${rec.host}:${rec.port}`
      : `Access valid for ${relative(d.expires_at)} — renews itself.`;
  }

  if (state === "Failed" && d) say(String(d), "err");
}

async function refresh() {
  try { paint(await invoke("get_status")); } catch (_) {}
  await paintAuth();
}

async function boot() {
  const c = await invoke("get_config");
  window.__oidc = c.oidc || {};
  $("host").value = c.host;
  $("user").value = c.user;
  $("port").value = c.port;
  $("lport").value = c.local_port;
  $("key").value = c.key_path;
  $("base").value = c.enroll_base || "";
  $("spot").checked = c.manage_spotify;
  $("lporth").textContent = c.local_port;
  $("autostart").checked = await invoke("autostart_enabled");

  $("pag").textContent = (await invoke("pageant_running"))
    ? "running — reusing your existing agent"
    : "not running — the bundled agent will be used";

  const t = await invoke("tool_paths");
  $("plink").textContent = t.plink;
  $("ssh").textContent = t.ssh_available ? t.ssh : `${t.ssh} (NOT FOUND)`;

  F.forEach((id) => $(id).addEventListener("input", () => save(true)));
  $("lport").addEventListener("input", () => ($("lporth").textContent = $("lport").value));
  $("spot").addEventListener("change", () => save(true));

  $("autostart").addEventListener("change", async (e) => {
    try {
      const on = await invoke("set_autostart", { enabled: e.target.checked });
      e.target.checked = on;
      say(on ? "Will start with Windows." : "Auto-start disabled.", "ok");
    } catch (err) {
      e.target.checked = false;
      say(String(err), "err");
    }
  });

  $("signin").addEventListener("click", async () => {
    const base = $("base").value.trim();
    if (!base) return say("Enter the tunnel server address first.", "err");
    $("signin").disabled = true;
    try {
      say("Contacting the server…");
      // Ask the server which identity provider to use, so the user never has
      // to know a client id or an issuer URL.
      window.__oidc = await invoke("discover", { base });
      await save(true);
      await invoke("sign_in");
      say("Waiting for you to finish signing in…");
    } catch (e) {
      say(String(e), "err");
    } finally {
      $("signin").disabled = false;
      refresh();
    }
  });

  $("cancel").addEventListener("click", async () => {
    await invoke("cancel_sign_in").catch(() => {});
    say("Sign-in cancelled.");
    refresh();
  });

  $("signout").addEventListener("click", async () => {
    await invoke("sign_out").catch(() => {});
    say("Signed out. Your key and certificate were deleted.");
    refresh();
  });

  $("renew").addEventListener("click", async () => {
    try {
      say("Renewing…");
      const rec = await invoke("renew");
      say(`Renewed — valid for ${relative(rec.expires_at)}.`, "ok");
    } catch (e) {
      say(String(e), "err");
    }
    refresh();
  });

  $("save").addEventListener("click", () => save(false));

  $("toggle").addEventListener("click", async () => {
    try {
      if (connected) {
        await invoke("stop_tunnel");
        say("Disconnected.");
      } else {
        await save(true);
        await invoke("start_tunnel");
        say("Connecting…");
      }
      refresh();
    } catch (e) {
      say(String(e), "err");
    }
  });

  refresh();
  setInterval(refresh, 2000);
}

boot().catch((e) => say(String(e), "err"));
