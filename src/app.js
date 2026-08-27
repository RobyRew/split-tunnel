const { invoke } = window.__TAURI__.core;
const $ = (id) => document.getElementById(id);
const F = ["host", "user", "port", "key", "lport"];

let connected = false;
let lastAuth = null;

function say(text, kind = "") {
  const m = $("msg");
  m.textContent = text;
  m.className = "msg " + kind;
}

const show = (id, on) => $(id).classList.toggle("hidden", !on);

/**
 * Run an async action with visible progress on its own button.
 *
 * Every button went through this after the first build shipped: pressing one
 * did nothing observable for several seconds, which reads as "broken" long
 * before it reads as "working". The button now disables itself, says what it
 * is doing, and reports the outcome in place.
 */
async function withBusy(btn, busyLabel, fn, okLabel) {
  const original = btn.dataset.label || btn.textContent;
  btn.dataset.label = original;
  btn.disabled = true;
  btn.classList.add("busy");
  btn.innerHTML = `<span class="spin"></span>${busyLabel}`;
  try {
    const result = await fn();
    btn.classList.remove("busy");
    if (okLabel) {
      btn.classList.add("done");
      btn.textContent = okLabel;
      setTimeout(() => {
        btn.classList.remove("done");
        btn.textContent = original;
      }, 1600);
    } else {
      btn.textContent = original;
    }
    return result;
  } catch (e) {
    btn.classList.remove("busy");
    btn.classList.add("failed");
    btn.textContent = "Failed";
    setTimeout(() => {
      btn.classList.remove("failed");
      btn.textContent = original;
    }, 2000);
    throw e;
  } finally {
    btn.disabled = false;
  }
}

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

// ── Server reachability ───────────────────────────────────────────────────
let probeTimer = null;

function setDot(state, text) {
  const dot = $("srvdot");
  const label = $("srvtext");
  dot.className = "dot " + state;
  label.textContent = text;
  label.className = "srvtext " + state;
  // Sign-in cannot work against a server we could not reach; saying so up
  // front beats a failure ten seconds into the flow.
  $("signin").disabled = state !== "up";
}

async function probeServer() {
  const base = $("base").value.trim();
  if (!base) return setDot("idle", "Enter your tunnel server address");
  setDot("checking", "Checking…");
  try {
    const r = await invoke("check_server", { base });
    if (r.reachable) {
      setDot("up", `Online · sign in via ${r.issuer} · access lasts ${r.cert_ttl}`);
    } else {
      setDot("down", r.detail);
    }
  } catch (e) {
    setDot("down", String(e));
  }
}

function scheduleProbe(delay = 700) {
  clearTimeout(probeTimer);
  setDot("checking", "Checking…");
  probeTimer = setTimeout(probeServer, delay);
}

// ── Painting ──────────────────────────────────────────────────────────────
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
  if (!btn.disabled) {
    btn.textContent = connected ? "Disconnect" : "Connect";
    btn.dataset.label = btn.textContent;
  }
  btn.classList.toggle("on", connected);

  if (status && status.detail) {
    say(status.detail, state === "error" ? "err" : "");
  } else if (state === "connected") {
    say("Traffic for the configured app is routed through your server.", "ok");
  }
}

/** Reflect the sign-in state machine. Polled, because the browser half of the
 *  device flow takes as long as the user takes. */
async function paintAuth() {
  let a;
  try { a = await invoke("auth_state"); } catch (_) { return; }
  const state = a.state;
  const d = a.detail || {};
  const changed = JSON.stringify(a) !== JSON.stringify(lastAuth);
  lastAuth = a;

  show("card-signin", state === "SignedOut" || state === "Failed");
  show("card-waiting", state === "Waiting");
  show("card-account", state === "SignedIn" || state === "Enrolling");

  if (state === "Waiting") {
    $("ucode").textContent = d.user_code || "—";
    $("vuri").textContent = d.verification_uri || "—";
  }

  if (state === "Enrolling") {
    $("who").innerHTML = '<span class="spin dark"></span>Finishing sign-in…';
    $("certinfo").textContent = "Creating your key and requesting a certificate.";
  }

  if (state === "SignedIn") {
    $("who").textContent = d.email || "Signed in";
    const rec = await invoke("enrollment").catch(() => null);
    $("certinfo").textContent = rec
      ? `Access valid for ${relative(rec.expires_at)} — renews itself. Server ${rec.host}:${rec.port}`
      : `Access valid for ${relative(d.expires_at)} — renews itself.`;
    if (changed) say("Signed in. You can connect now.", "ok");
  }

  if (state === "Failed" && changed) say(String(d), "err");
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

  $("base").addEventListener("input", () => { save(true); scheduleProbe(); });
  $("recheck").addEventListener("click", (e) =>
    withBusy(e.currentTarget, "Checking…", probeServer).catch(() => {}));

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

  $("signin").addEventListener("click", async (e) => {
    const base = $("base").value.trim();
    if (!base) return say("Enter the tunnel server address first.", "err");
    try {
      await withBusy(e.currentTarget, "Opening your browser…", async () => {
        say("Contacting the server…");
        // Ask the server which identity provider to use, so the user never has
        // to know a client id or an issuer URL.
        window.__oidc = await invoke("discover", { base });
        await save(true);
        await invoke("sign_in");
      });
      say("Waiting for you to finish signing in — check your browser.");
    } catch (err) {
      say(String(err), "err");
    }
    refresh();
  });

  $("cancel").addEventListener("click", async (e) => {
    await withBusy(e.currentTarget, "Cancelling…", () => invoke("cancel_sign_in")).catch(() => {});
    say("Sign-in cancelled.");
    refresh();
  });

  $("signout").addEventListener("click", async (e) => {
    await withBusy(e.currentTarget, "Signing out…", () => invoke("sign_out")).catch(() => {});
    say("Signed out. Your key and certificate were deleted.");
    refresh();
  });

  $("renew").addEventListener("click", async (e) => {
    try {
      const rec = await withBusy(e.currentTarget, "Renewing…", () => invoke("renew"), "Renewed");
      say(`Renewed — valid for ${relative(rec.expires_at)}.`, "ok");
    } catch (err) {
      say(String(err), "err");
    }
    refresh();
  });

  $("save").addEventListener("click", (e) =>
    withBusy(e.currentTarget, "Saving…", () => save(false), "Saved").catch(() => {}));

  $("toggle").addEventListener("click", async (e) => {
    const btn = e.currentTarget;
    try {
      if (connected) {
        await withBusy(btn, "Disconnecting…", () => invoke("stop_tunnel"));
        say("Disconnected.");
      } else {
        // Held busy until the tunnel is genuinely up (or has failed), rather
        // than until the command returns — start_tunnel only *launches* the
        // supervisor, so returning immediately looked like nothing happened.
        await withBusy(btn, "Connecting…", async () => {
          await save(true);
          await invoke("start_tunnel");
          for (let i = 0; i < 40; i++) {
            await new Promise((r) => setTimeout(r, 500));
            const s = await invoke("get_status").catch(() => null);
            if (!s) continue;
            if (s.state === "Connected") return;
            if (s.state === "Error") throw new Error(s.detail || "could not connect");
          }
          throw new Error("timed out waiting for the tunnel");
        });
      }
      refresh();
    } catch (err) {
      say(String(err && err.message ? err.message : err), "err");
      refresh();
    }
  });

  refresh();
  probeServer();
  setInterval(refresh, 2000);
}

boot().catch((e) => say(String(e), "err"));
