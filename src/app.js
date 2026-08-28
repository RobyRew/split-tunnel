// The Tauri bridge is injected only when `withGlobalTauri` is true in
// tauri.conf.json. It was not, once, and this line threw before anything was
// wired — producing a window where no button did anything and no error was
// visible. Never fail silently here again.
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
const show = (id, on) => $(id).classList.toggle("hidden", !on);

const FIELDS = ["host", "user", "port", "key", "lport", "proxy"];

let cfg = {};
let connected = false;
let lastAuth = null;
let signedIn = false;
let updateDismissed = false;

// ── Log ───────────────────────────────────────────────────────────────────
// Every call in and out. This exists because an early build gave no sign of
// what it was doing: a button press that failed looked identical to one that
// did nothing. Can be switched off entirely — see keep_log.
const LOG = [];

function log(kind, text, detail) {
  if (cfg.keep_log === false) return;
  LOG.push({
    t: new Date().toTimeString().slice(0, 8),
    kind,
    text,
    detail: detail === undefined ? "" : detail,
  });
  if (LOG.length > 400) LOG.shift();
  const el = $("logbox");
  if (!el) return;
  el.textContent = LOG.map(
    (l) => `${l.t}  ${l.kind.padEnd(5)} ${l.text}${l.detail ? "  " + l.detail : ""}`
  ).join("\n");
  el.scrollTop = el.scrollHeight;
}

const brief = (v) => {
  if (v === null || v === undefined) return "";
  const s = typeof v === "string" ? v : JSON.stringify(v);
  return s.length > 220 ? s.slice(0, 220) + "…" : s;
};

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

/** Errors get a banner, not a line that scrolls away. */
function fail(text) {
  $("banner").textContent = text;
  $("banner").classList.remove("hidden");
  log("ERROR", text);
}
const clearBanner = () => $("banner").classList.add("hidden");

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

// ── Config ────────────────────────────────────────────────────────────────
// There is no Save button. Every change is written once typing settles — a
// Save button beside Connect only ever raised the question of whether you had
// to press it before connecting.
function readForm() {
  return {
    ...cfg,
    host: $("host").value.trim(),
    user: $("user").value.trim() || "tunnel",
    port: parseInt($("port").value, 10) || 2223,
    local_port: parseInt($("lport").value, 10) || 1080,
    key_path: $("key").value.trim(),
    autostart: $("autostart").checked,
    manage_spotify: $("spot").checked,
    enroll_base: $("base").value.trim(),
    proxy: $("proxy").value.trim(),
    keep_log: $("keeplog").checked,
    update_check_hours: parseInt($("updhours").value, 10) || 0,
    theme: $("theme").value,
    oidc: cfg.oidc || {},
  };
}

let saveTimer = null;
const saveSoon = () => {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => save(), 400);
};

async function save() {
  try {
    cfg = readForm();
    await invoke("save_config", { cfg });
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

// ── Theme ─────────────────────────────────────────────────────────────────
// "system" leaves it to prefers-color-scheme, which the webview inherits from
// the Windows app theme.
function applyTheme(t) {
  document.documentElement.setAttribute("data-theme", t === "system" ? "" : t);
}

// ── Server reachability ───────────────────────────────────────────────────
let probeTimer = null;
let probeSeq = 0;

function setDot(state, text) {
  $("srvdot").className = "dot " + state;
  $("srvtext").textContent = text;
  $("srvtext").className = "srvtext " + state;
  $("signin").disabled = state !== "up";
}

async function probeServer() {
  const base = $("base").value.trim();
  if (!base) return setDot("idle", "Waiting for an address…");
  setDot("checking", "Checking…");
  const mine = ++probeSeq;
  try {
    const r = await invoke("check_server", { base });
    if (mine !== probeSeq) return; // a newer probe already answered
    if (r.reachable) {
      setDot("up", `Online · ${r.issuer} · access lasts ${r.cert_ttl}`);
      clearBanner();
    } else {
      setDot("down", r.detail);
      if (r.raw) log("ERROR", "check_server raw", r.raw);
    }
  } catch (e) {
    if (mine === probeSeq) setDot("down", String(e));
  }
}

const scheduleProbe = (delay = 900) => {
  clearTimeout(probeTimer);
  setDot("checking", "Checking…");
  probeTimer = setTimeout(probeServer, delay);
};

// ── Painting ──────────────────────────────────────────────────────────────
function paintStatus(status) {
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

  if (status && status.detail && state === "error") fail(status.detail);
}

/** Which step of the flow the window should be showing. */
function paintSteps(state) {
  const haveServer = !!(cfg.enroll_base || "").trim();
  const waiting = state === "Waiting";
  signedIn = state === "SignedIn";

  show("card-setup", !signedIn && !waiting && !haveServer);
  show("card-signin", !signedIn && !waiting && haveServer);
  show("card-waiting", waiting);
  show("card-ready", signedIn);
  show("card-apps", signedIn);
  show("card-spotify", signedIn);
  // Connect is meaningless before there is anything to connect with.
  $("toggle").disabled = !signedIn && !(cfg.host || "").trim();
}

async function paintAuth() {
  let a;
  try { a = await rawInvoke("auth_state"); } catch (_) { return; }
  const state = a.state;
  const d = a.detail || {};
  const changed = JSON.stringify(a) !== JSON.stringify(lastAuth);
  if (changed) log("auth", state, brief(d));
  lastAuth = a;

  paintSteps(state);

  if (state === "Waiting") {
    const hasCode = !!(d.user_code && d.user_code.length);
    show("ucode", hasCode);
    show("codehint", hasCode);
    show("copyurl", !!d.verification_uri);
    if (hasCode) $("ucode").textContent = d.user_code;
    $("vuri").textContent = d.verification_uri || "—";
    $("waitmsg").textContent = hasCode
      ? "A browser window should have opened. If not, go to this address and enter the code:"
      : "Sign in there, then come back. If it did not open, use this link:";
  }

  if (state === "Enrolling") {
    $("who").innerHTML = '<span class="spin dark"></span>Finishing sign-in…';
    $("certinfo").textContent = "Creating your key and requesting a certificate.";
  }

  if (state === "SignedIn") {
    $("who").textContent = d.email || "Signed in";
    const rec = await rawInvoke("enrollment").catch(() => null);
    $("certinfo").textContent = rec
      ? `Valid for ${relative(rec.expires_at)} — renews itself · ${rec.host}:${rec.port}`
      : `Valid for ${relative(d.expires_at)} — renews itself`;
    if (changed) clearBanner();
  }

  if (state === "Failed" && changed) fail(String(d));
}

/** Who is actually using the tunnel. */
async function paintApps() {
  if (!signedIn) return;
  if (!connected) {
    $("applist").innerHTML = '<span class="hint">Not connected.</span>';
    return;
  }
  const apps = await rawInvoke("connected_apps").catch(() => []);
  if (!apps.length) {
    $("applist").innerHTML =
      '<span class="hint">Connected, but no app is using it yet.</span>';
    return;
  }
  $("applist").innerHTML = apps
    .map(
      (a) =>
        `<div class="app"><span class="appname">${a.name}</span>` +
        `<span class="hint">${a.connections} connection${a.connections === 1 ? "" : "s"}</span></div>`
    )
    .join("");
}

async function paintSpotify() {
  if (!signedIn) return;
  const s = await rawInvoke("spotify_state").catch(() => null);
  if (!s || !s.found) {
    $("spotstate").textContent =
      "Spotify's settings file was not found. Open Spotify once, then come back.";
    show("spotfix", false);
    show("spotoff", false);
    return;
  }
  if (s.points_at_us) {
    $("spotstate").textContent = s.running
      ? "Pointed here — quit Spotify completely and reopen it to take effect."
      : "Pointed here. Start Spotify and it will use the tunnel.";
    show("spotfix", false);
    show("spotoff", true);
  } else {
    $("spotstate").textContent =
      s.mode === 0
        ? "Not using a proxy."
        : `Using a different proxy (mode ${s.mode}, ${s.addr}:${s.port}).`;
    show("spotfix", true);
    show("spotoff", false);
  }
}

async function refresh() {
  try { paintStatus(await rawInvoke("get_status")); } catch (_) {}
  await paintAuth();
  await paintApps();
}

// ── Updates ───────────────────────────────────────────────────────────────
async function checkUpdate(quiet) {
  try {
    const u = await invoke("check_update");
    $("ver2").textContent = u.current;
    if (u.available) {
      $("updver").textContent = `${u.current} → ${u.version}`;
      $("updstatus").textContent = `${u.version} available`;
      show("updnow", true);
      if (!updateDismissed) show("update", true);
    } else {
      show("update", false);
      show("updnow", false);
      $("updstatus").textContent = "up to date";
    }
    return u;
  } catch (e) {
    // Not banner-worthy: on a managed network it usually just means the proxy
    // was not resolved, which the connection test covers properly.
    $("updstatus").textContent = quiet ? "check failed" : String(e);
    log("ERROR", "check_update", String(e));
    return null;
  }
}

// ── Wiring ────────────────────────────────────────────────────────────────
// Contains NO awaits: handlers used to be registered after several awaited
// commands, so one failure left the whole window inert.
function wireEvents() {
  FIELDS.forEach((id) => $(id).addEventListener("input", saveSoon));
  $("lport").addEventListener("input", () => ($("lporth").textContent = $("lport").value));
  $("base").addEventListener("input", () => { saveSoon(); scheduleProbe(); });

  ["spot", "keeplog"].forEach((id) => $(id).addEventListener("change", save));
  $("updhours").addEventListener("change", save);
  $("theme").addEventListener("change", () => { applyTheme($("theme").value); save(); });

  const closeMenu = () => $("settings").classList.add("hidden");
  $("gear").addEventListener("click", (e) => {
    e.stopPropagation();
    $("settings").classList.toggle("hidden");
  });
  document.addEventListener("click", (e) => {
    if (!$("settings").contains(e.target) && e.target !== $("gear")) closeMenu();
  });

  $("recheck").addEventListener("click", (e) =>
    withBusy(e.currentTarget, "Checking…", probeServer).catch(() => {}));

  $("nettest").addEventListener("click", async (e) => {
    $("card-log").open = true;
    try {
      await withBusy(e.currentTarget, "Testing…", async () => {
        await save();
        const rows = await rawInvoke("network_test");
        log("test", "── connection test ──");
        rows.forEach((r) => log(r.ok ? "PASS" : "FAIL", r.name, r.detail));
        const bad = rows.filter((r) => !r.ok).map((r) => r.name);
        say(bad.length ? `Failed: ${bad.join(", ")}` : "All checks passed.",
            bad.length ? "err" : "ok");
      });
    } catch (err) { fail(String(err)); }
  });

  $("checkupd").addEventListener("click", (e) => {
    $("updstatus").textContent = "checking…";
    withBusy(e.currentTarget, "Checking…", () => checkUpdate(false)).catch(() => {});
  });
  $("upddismiss").addEventListener("click", () => {
    updateDismissed = true;
    show("update", false);
  });
  $("updopen").addEventListener("click", () => {
    show("update", false);
    $("settings").classList.remove("hidden");
  });
  $("updnow").addEventListener("click", async (e) => {
    try {
      closeMenu();
      await withBusy(e.currentTarget, "Updating…", async () => {
        say("Downloading and verifying the update…");
        // The app restarts itself on success; control does not come back.
        await invoke("install_update");
      });
    } catch (err) { fail(`Update failed: ${err}`); }
  });

  $("copylog").addEventListener("click", async (e) => {
    const b = e.currentTarget;
    try {
      await rawInvoke("copy_text", { text: $("logbox").textContent });
      b.textContent = "Copied";
      setTimeout(() => (b.textContent = "Copy"), 1400);
    } catch (_) {
      const r = document.createRange();
      r.selectNodeContents($("logbox"));
      window.getSelection().removeAllRanges();
      window.getSelection().addRange(r);
      say("Log selected — press Ctrl+C to copy.", "ok");
    }
  });

  $("copyurl").addEventListener("click", async (e) => {
    const b = e.currentTarget;
    try {
      await rawInvoke("copy_text", { text: $("vuri").textContent });
      b.textContent = "Copied";
      setTimeout(() => (b.textContent = "Copy link"), 1400);
    } catch (_) { say("Select the link above and copy it.", "err"); }
  });

  $("autostart").addEventListener("change", async (e) => {
    const box = e.currentTarget;
    try {
      box.checked = await invoke("set_autostart", { enabled: box.checked });
      say(box.checked ? "Will start with Windows." : "Auto-start disabled.", "ok");
    } catch (err) {
      box.checked = false;
      fail(String(err));
    }
  });

  $("signin").addEventListener("click", async (e) => {
    clearBanner();
    const base = $("base").value.trim();
    if (!base) return fail("Enter the tunnel server address first.");
    try {
      await withBusy(e.currentTarget, "Opening your browser…", async () => {
        say("Contacting the server…");
        cfg.oidc = await invoke("discover", { base });
        await save();
        await invoke("sign_in");
      });
      say("Waiting for you to finish signing in — check your browser.");
    } catch (err) { fail(String(err)); }
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
    } catch (err) { fail(String(err)); }
    refresh();
  });

  $("spotfix").addEventListener("click", async (e) => {
    try {
      const s = await withBusy(e.currentTarget, "Applying…", () => invoke("spotify_apply"), "Done");
      say(
        s.points_at_us
          ? (s.running ? "Done — quit Spotify completely and reopen it." : "Done.")
          : "Written, but Spotify still does not show our proxy. Set it by hand in Spotify → Settings → Proxy.",
        s.points_at_us ? "ok" : "err"
      );
    } catch (err) { fail(String(err)); }
    paintSpotify();
  });

  $("spotoff").addEventListener("click", async (e) => {
    await withBusy(e.currentTarget, "Restoring…", () => invoke("spotify_restore")).catch(() => {});
    say("Spotify set back to no proxy.");
    paintSpotify();
  });

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
          await save();
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
        say("Connected.", "ok");
        paintSpotify();
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
  $("ver").textContent = "v" + (await invoke("app_version").catch(() => "?"));

  cfg = await invoke("get_config");
  $("host").value = cfg.host || "";
  $("user").value = cfg.user || "tunnel";
  $("port").value = cfg.port || 2223;
  $("lport").value = cfg.local_port || 1080;
  $("key").value = cfg.key_path || "";
  $("base").value = cfg.enroll_base || "";
  $("proxy").value = cfg.proxy || "";
  $("spot").checked = !!cfg.manage_spotify;
  $("keeplog").checked = cfg.keep_log !== false;
  $("updhours").value = String(cfg.update_check_hours ?? 24);
  $("theme").value = cfg.theme || "system";
  $("lporth").textContent = cfg.local_port || 1080;
  applyTheme($("theme").value);

  $("autostart").checked = await invoke("autostart_enabled").catch(() => false);

  const pag = await invoke("pageant_running").catch(() => false);
  $("pag").textContent = pag ? "running" : "not running";

  const t = await invoke("tool_paths").catch(() => ({}));
  $("plink").textContent = t.plink || "—";
  $("ssh").textContent = t.ssh_available ? t.ssh : `${t.ssh || "ssh"} (NOT FOUND)`;

  const diag = await invoke("diagnostics").catch(() => null);
  if (diag) {
    log("diag", "startup", brief(diag));
    $("proxynow").textContent = diag.proxy || "none";
  }
}

async function boot() {
  try {
    wireEvents();
  } catch (e) {
    fail("The interface failed to start: " + e);
    return;
  }
  try {
    await loadState();
  } catch (e) {
    fail("Could not load settings: " + e + " — check the Log.");
  }
  refresh();
  paintSpotify();
  if ($("base").value.trim()) probeServer();
  setInterval(refresh, 2000);
  if ((cfg.update_check_hours ?? 24) > 0) checkUpdate(true);
}

window.addEventListener("error", (e) => fail("Script error: " + (e.message || e)));
window.addEventListener("unhandledrejection", (e) =>
  log("ERROR", "unhandled", brief(String(e.reason))));

boot().catch((e) => fail(String(e)));
