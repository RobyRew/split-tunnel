// The Tauri bridge is injected only when `withGlobalTauri` is true in
// tauri.conf.json. It was not, and this line threw before anything was wired —
// producing a window where no button did anything and no error was visible.
// Never fail silently here again.
if (!window.__TAURI__ || !window.__TAURI__.core) {
  document.addEventListener("DOMContentLoaded", () => {
    document.body.insertAdjacentHTML(
      "afterbegin",
      '<div style="margin:14px;padding:12px;border-radius:10px;background:#1e1014;' +
        'border:1px solid #3d1622;color:#ffb3c1;font:13px/1.5 system-ui">' +
        "<b>The app could not talk to its backend.</b><br>" +
        "window.__TAURI__ is missing — this build is broken. Please reinstall " +
        "the latest release.</div>"
    );
  });
  throw new Error("window.__TAURI__ missing (withGlobalTauri not enabled)");
}

const { invoke: rawInvoke } = window.__TAURI__.core;
const $ = (id) => document.getElementById(id);
const F = ["host", "user", "port", "key", "lport"];

let connected = false;
let lastAuth = null;

// ── Log ───────────────────────────────────────────────────────────────────
// Every call in and out, kept in memory and shown in the app.
//
// This exists because the first build gave no sign of what it was doing: a
// button press that failed looked identical to one that did nothing, and the
// only error surface was one small line that scrolls off screen. Guessing
// from the outside is not debugging.
const LOG = [];

function log(kind, text, detail) {
  const line = {
    t: new Date().toTimeString().slice(0, 8),
    kind,
    text,
    detail: detail === undefined ? "" : detail,
  };
  LOG.push(line);
  if (LOG.length > 400) LOG.shift();
  renderLog();
}

function renderLog() {
  const el = $("logbox");
  if (!el) return;
  el.textContent = LOG.map((l) => {
    const d = l.detail ? `  ${l.detail}` : "";
    return `${l.t}  ${l.kind.padEnd(5)} ${l.text}${d}`;
  }).join("\n");
  el.scrollTop = el.scrollHeight;
}

const brief = (v) => {
  if (v === null || v === undefined) return "";
  const s = typeof v === "string" ? v : JSON.stringify(v);
  return s.length > 220 ? s.slice(0, 220) + "…" : s;
};

/** invoke(), but every call and its outcome is logged. */
async function invoke(cmd, args) {
  log("call", cmd, args ? brief(args) : "");
  try {
    const r = await rawInvoke(cmd, args);
    log("ok", cmd, brief(r));
    return r;
  } catch (e) {
    log("ERROR", cmd, brief(String(e)));
    throw e;
  }
}

// ── Messaging ─────────────────────────────────────────────────────────────
function say(text, kind = "") {
  const m = $("msg");
  m.textContent = text;
  m.className = "msg " + kind;
  if (text) log(kind === "err" ? "ERROR" : "ui", text);
}

/** Errors deserve a banner, not a line that scrolls away. */
function fail(text) {
  const b = $("banner");
  b.textContent = text;
  b.classList.remove("hidden");
  log("ERROR", text);
}

function clearBanner() {
  $("banner").classList.add("hidden");
}

const show = (id, on) => $(id).classList.toggle("hidden", !on);

/** Run an async action with visible progress on its own button. */
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
  $("srvdot").className = "dot " + state;
  const label = $("srvtext");
  label.textContent = text;
  label.className = "srvtext " + state;
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
      clearBanner();
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

async function paintAuth() {
  let a;
  try { a = await rawInvoke("auth_state"); } catch (_) { return; }
  const state = a.state;
  const d = a.detail || {};
  const changed = JSON.stringify(a) !== JSON.stringify(lastAuth);
  if (changed) log("auth", state, brief(d));
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
    const rec = await rawInvoke("enrollment").catch(() => null);
    $("certinfo").textContent = rec
      ? `Access valid for ${relative(rec.expires_at)} — renews itself. Server ${rec.host}:${rec.port}`
      : `Access valid for ${relative(d.expires_at)} — renews itself.`;
    if (changed) { say("Signed in. You can connect now.", "ok"); clearBanner(); }
  }

  if (state === "Failed" && changed) fail(String(d));
}

async function refresh() {
  try { paint(await rawInvoke("get_status")); } catch (_) {}
  await paintAuth();
}

// ── Wiring ────────────────────────────────────────────────────────────────
/**
 * Attach every handler. Contains NO awaits on purpose.
 *
 * In the first build all of this lived after several `await invoke(...)` calls
 * inside boot(). Any one of them failing meant no handler was ever attached
 * and the whole window became inert — which is precisely the "nothing reacts
 * to anything" symptom. Wiring first means the UI always responds, even when
 * loading state fails.
 */
function wireEvents() {
  F.forEach((id) => $(id).addEventListener("input", () => save(true)));
  $("lport").addEventListener("input", () => ($("lporth").textContent = $("lport").value));
  $("spot").addEventListener("change", () => save(true));

  $("base").addEventListener("input", () => { save(true); scheduleProbe(); });
  $("recheck").addEventListener("click", (e) =>
    withBusy(e.currentTarget, "Checking…", probeServer).catch(() => {}));

  $("copylog").addEventListener("click", async (e) => {
    const text = $("logbox").textContent;
    try {
      await navigator.clipboard.writeText(text);
      const b = e.currentTarget;
      b.textContent = "Copied";
      setTimeout(() => (b.textContent = "Copy"), 1400);
    } catch (_) {
      // Clipboard can be refused; selecting the text still works.
      say("Could not copy — select the log text and copy manually.", "err");
    }
  });

  $("autostart").addEventListener("change", async (e) => {
    const box = e.currentTarget;
    try {
      const on = await invoke("set_autostart", { enabled: box.checked });
      box.checked = on;
      say(on ? "Will start with Windows." : "Auto-start disabled.", "ok");
    } catch (err) {
      box.checked = false;
      say(String(err), "err");
    }
  });

  $("signin").addEventListener("click", async (e) => {
    clearBanner();
    const base = $("base").value.trim();
    if (!base) return fail("Enter the tunnel server address first.");
    try {
      await withBusy(e.currentTarget, "Opening your browser…", async () => {
        say("Contacting the server…");
        window.__oidc = await invoke("discover", { base });
        await save(true);
        await invoke("sign_in");
      });
      say("Waiting for you to finish signing in — check your browser.");
    } catch (err) {
      fail(String(err));
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
    clearBanner();
    try {
      const rec = await withBusy(e.currentTarget, "Renewing…", () => invoke("renew"), "Renewed");
      say(`Renewed — valid for ${relative(rec.expires_at)}.`, "ok");
    } catch (err) {
      fail(String(err));
    }
    refresh();
  });

  $("save").addEventListener("click", (e) =>
    withBusy(e.currentTarget, "Saving…", () => save(false), "Saved").catch(() => {}));

  $("toggle").addEventListener("click", async (e) => {
    clearBanner();
    const btn = e.currentTarget;
    try {
      if (connected) {
        await withBusy(btn, "Disconnecting…", () => invoke("stop_tunnel"));
        say("Disconnected.");
      } else {
        // Held busy until the tunnel is genuinely up, not until the command
        // returns — start_tunnel only launches the supervisor.
        await withBusy(btn, "Connecting…", async () => {
          await save(true);
          await invoke("start_tunnel");
          for (let i = 0; i < 40; i++) {
            await new Promise((r) => setTimeout(r, 500));
            const s = await rawInvoke("get_status").catch(() => null);
            if (!s) continue;
            if (s.state === "Connected") return;
            if (s.state === "Error") throw new Error(s.detail || "could not connect");
          }
          throw new Error("timed out waiting for the tunnel");
        });
      }
      refresh();
    } catch (err) {
      fail(String(err && err.message ? err.message : err));
      refresh();
    }
  });

  log("ui", "handlers attached");
}

async function loadState() {
  const v = await invoke("app_version").catch(() => "?");
  $("ver").textContent = "v" + v;
  log("ui", "version", v);

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

  $("autostart").checked = await invoke("autostart_enabled").catch(() => false);

  const pag = await invoke("pageant_running").catch(() => false);
  $("pag").textContent = pag
    ? "running — reusing your existing agent"
    : "not running — the bundled agent will be used";

  const t = await invoke("tool_paths").catch(() => ({}));
  $("plink").textContent = t.plink || "—";
  $("ssh").textContent = t.ssh_available ? t.ssh : `${t.ssh || "ssh"} (NOT FOUND)`;

  const diag = await invoke("diagnostics").catch(() => null);
  if (diag) log("diag", "startup", brief(diag));
}

async function boot() {
  // Order matters: handlers first, so nothing below can leave the UI inert.
  try {
    wireEvents();
  } catch (e) {
    fail("The interface failed to start: " + e);
    return;
  }
  try {
    await loadState();
  } catch (e) {
    fail("Could not load settings: " + e + " — the app still works, check the Log.");
  }
  refresh();
  probeServer();
  setInterval(refresh, 2000);
}

window.addEventListener("error", (e) => fail("Script error: " + (e.message || e)));
window.addEventListener("unhandledrejection", (e) =>
  log("ERROR", "unhandled", brief(String(e.reason))));

boot().catch((e) => fail(String(e)));
