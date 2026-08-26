const { invoke } = window.__TAURI__.core;
const $ = (id) => document.getElementById(id);
const F = ["host", "user", "port", "key", "lport"];

let connected = false;

function say(text, kind = "") {
  const m = $("msg");
  m.textContent = text;
  m.className = "msg " + kind;
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

async function refresh() {
  try { paint(await invoke("get_status")); } catch (_) {}
}

async function boot() {
  const c = await invoke("get_config");
  $("host").value = c.host;
  $("user").value = c.user;
  $("port").value = c.port;
  $("lport").value = c.local_port;
  $("key").value = c.key_path;
  $("spot").checked = c.manage_spotify;
  $("lporth").textContent = c.local_port;
  $("autostart").checked = await invoke("autostart_enabled");

  $("pag").textContent = (await invoke("pageant_running"))
    ? "running — reusing your existing agent"
    : "not running — the bundled agent will be used";

  const t = await invoke("tool_paths");
  $("plink").textContent = t.plink;

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
