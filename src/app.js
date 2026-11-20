// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// EON DNS's interface. It has no network of its own: everything goes through
// the host. Names that come from lookups enter the page only as textContent.

"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const appWindow = window.__TAURI__.window.getCurrentWindow();
const $ = (id) => document.getElementById(id);

let strings = {};
let lang = "en";
let settings = null;
let presets = [];
let lists = [];
let state = { on: false };
let stats = null;
let log = [];
let busy = false;

// ---- words and numbers ------------------------------------------------------------

function t(key, vars = {}) {
  let text = strings[key] ?? key;
  for (const [n, v] of Object.entries(vars)) text = text.replaceAll(`{${n}}`, String(v));
  return text;
}
const num = (n) => new Intl.NumberFormat(lang).format(n);

function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "text") node.textContent = v;
    else if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined && v !== false) node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children) if (c) node.append(c);
  return node;
}

function applyStrings() {
  document.documentElement.lang = lang;
  for (const n of document.querySelectorAll("[data-i18n]")) n.textContent = t(n.dataset.i18n);
  for (const n of document.querySelectorAll("[data-i18n-label]")) n.setAttribute("aria-label", t(n.dataset.i18nLabel));
  for (const n of document.querySelectorAll("[data-i18n-placeholder]")) n.placeholder = t(n.dataset.i18nPlaceholder);
}

function presetName(id) {
  return presets.find((p) => p.id === id)?.name || id;
}

function joinNames(names) {
  return new Intl.ListFormat(lang, { style: "long", type: "conjunction" }).format(names);
}

// ---- the ring: sixty ticks, the last hour ------------------------------------------

const SVG = "http://www.w3.org/2000/svg";

function drawRing() {
  const ring = $("ring");
  ring.replaceChildren();
  const minutes = stats?.minutes || [];
  const peak = Math.max(1, ...minutes.map((m) => m[0]));
  for (let i = 0; i < 60; i++) {
    const [lookups, blocked] = minutes[i] || [0, 0];
    const a = -Math.PI / 2 + (i / 60) * Math.PI * 2;
    const inner = 168;
    const length = 14 + (state.on ? (lookups / peak) * 22 : 0);
    const outer = inner + length;
    const line = (r1, r2, cls) => {
      const l = document.createElementNS(SVG, "line");
      l.setAttribute("x1", 200 + r1 * Math.cos(a));
      l.setAttribute("y1", 200 + r1 * Math.sin(a));
      l.setAttribute("x2", 200 + r2 * Math.cos(a));
      l.setAttribute("y2", 200 + r2 * Math.sin(a));
      l.setAttribute("class", cls);
      ring.append(l);
    };
    line(inner, outer, lookups === 0 ? "tick quiet" : "tick");
    if (state.on && blocked > 0) {
      const share = Math.max(0.25, blocked / Math.max(1, lookups));
      line(outer - length * share, outer, "warm");
    }
  }
}

// ---- the overview --------------------------------------------------------------------

function routeSentence() {
  const route = $("route");
  route.replaceChildren();
  if (!state.on) {
    route.textContent = t("route.off");
    return;
  }
  if (settings.mode === "native") {
    route.append(t("route.native.before"), el("strong", { text: presetName(settings.native_preset) }), t("route.native.after"));
    return;
  }
  const names = settings.engine.upstreams.map((u) => (u.kind === "preset" ? presetName(u.id) : u.kind === "plain" ? u.addr : u.server_name));
  route.append(
    t("route.local.before", { how: t(`transport.short.${settings.engine.transport}`) }),
    el("strong", { text: joinNames(names) }),
    settings.engine.validate ? t("route.local.dnssec") : t("route.local.after"),
  );
}

function drawOverview() {
  document.body.classList.toggle("on", state.on);
  document.body.classList.toggle("busy", busy);
  const sw = $("switch");
  sw.setAttribute("aria-checked", String(state.on));
  sw.setAttribute("aria-label", state.on ? t("switch.label.on") : t("switch.label.off"));
  $("switch-state").textContent = busy ? t("switch.working") : state.on ? t("switch.on") : t("switch.off");
  $("switch-hint").textContent = busy ? "" : state.on ? t("switch.hint.on") : t("switch.hint.off");
  routeSentence();
  const problem = state.problem;
  $("problem").hidden = !problem;
  $("problem").textContent = problem ? (problem.startsWith("problem.") ? t(problem) : t("problem.other", { detail: problem })) : "";
  const local = settings.mode === "local";
  $("fig-lookups").textContent = stats ? num(stats.lookups) : "–";
  $("fig-blocked").textContent = stats ? num(stats.blocked) : "–";
  $("fig-speed").textContent = stats?.median_ms != null ? t("fig.ms", { ms: num(Math.round(stats.median_ms)) }) : "–";
  document.querySelector(".figures").hidden = !local;
  $("ring-caption").hidden = !local;
  drawRing();
  const recent = log.filter((e) => e.verdict.by === "rule" || e.verdict.by === "listed").slice(0, 6);
  $("recent").replaceChildren(...recent.map((e) => el("li", {}, [el("span", { class: "name", text: e.name }), el("span", { class: "reason", text: verdictText(e.verdict) })])));
  $("recent-empty").textContent = !local ? t("recent.native") : !settings.engine.log ? t("recent.logoff") : recent.length ? "" : t("recent.none");
  document.querySelector(".recent").hidden = !local;
}

function verdictText(v) {
  if (v.by === "listed") return t(`list.${v.detail}.short`);
  if (v.by === "rule") return t("verdict.rule");
  if (v.by === "allowed") return t("verdict.allowed");
  return "";
}

// ---- protection ----------------------------------------------------------------------

function drawProtection() {
  const on = new Set(settings.engine.lists);
  $("lists").replaceChildren(
    ...lists.map((l) => {
      const box = el("input", { type: "checkbox", id: `list-${l.id}` });
      box.checked = on.has(l.id);
      box.addEventListener("change", () => {
        settings.engine.lists = box.checked ? [...settings.engine.lists, l.id] : settings.engine.lists.filter((x) => x !== l.id);
        save();
      });
      const meta = l.size ? t("list.size", { n: num(l.size) }) : on.has(l.id) ? t("list.fetching") : "";
      return el("label", { class: "row", for: `list-${l.id}` }, [
        box,
        el("span", { class: "what" }, [el("span", { class: "title", text: t(`list.${l.id}`) }), el("span", { class: "note", text: t(`list.${l.id}.hint`) })]),
        el("span", { class: "meta", text: meta }),
      ]);
    }),
  );
  for (const kind of ["allow", "block"]) {
    $(`${kind}-list`).replaceChildren(
      ...settings.engine[kind].map((name) =>
        el("li", {}, [
          name,
          el("button", { type: "button", "aria-label": t("rules.remove", { name }), title: t("rules.remove", { name }), onclick: () => { settings.engine[kind] = settings.engine[kind].filter((n) => n !== name); save(); } }, [svgIcon("x")]),
        ]),
      ),
    );
  }
}

function svgIcon(name) {
  const s = document.createElementNS(SVG, "svg");
  s.setAttribute("class", "icon");
  s.setAttribute("aria-hidden", "true");
  const u = document.createElementNS(SVG, "use");
  u.setAttribute("href", `icons.svg#i-${name}`);
  s.append(u);
  return s;
}

function addRule(kind, raw) {
  const name = raw.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
  if (!/^[a-z0-9_-]+(\.[a-z0-9_-]+)+$/.test(name)) return false;
  for (const other of ["allow", "block"]) settings.engine[other] = settings.engine[other].filter((n) => n !== name);
  settings.engine[kind] = [...settings.engine[kind], name];
  save();
  return true;
}

// ---- resolvers -----------------------------------------------------------------------

function drawResolvers() {
  for (const r of document.querySelectorAll('input[name="mode"]')) r.checked = r.value === settings.mode;
  const chosen = settings.engine.upstreams.filter((u) => u.kind === "preset").map((u) => u.id);
  const native = settings.mode === "native";
  $("presets").replaceChildren(
    ...presets.map((p) => {
      const box = el("input", { type: native ? "radio" : "checkbox", name: native ? "native-preset" : null, id: `preset-${p.id}` });
      box.checked = native ? settings.native_preset === p.id : chosen.includes(p.id);
      box.addEventListener("change", () => {
        if (native) settings.native_preset = p.id;
        else {
          const ids = box.checked ? [...chosen, p.id] : chosen.filter((x) => x !== p.id);
          if (ids.length === 0) { box.checked = true; return; }
          settings.engine.upstreams = [...ids.map((id) => ({ kind: "preset", id })), ...settings.engine.upstreams.filter((u) => u.kind !== "preset")];
        }
        save();
      });
      return el("label", { class: "row", for: `preset-${p.id}` }, [
        box,
        el("span", { class: "what" }, [el("span", { class: "title", text: p.name }), el("span", { class: "note", text: t(`preset.${p.id}`) })]),
        el("span", { class: "meta", text: p.transports.map((x) => x.toUpperCase()).join(", ") }),
      ]);
    }),
  );
  $("transport").value = settings.engine.transport;
  $("validate").checked = settings.engine.validate;
  document.querySelector(".controls").hidden = native;
}

async function runBench() {
  const button = $("bench-run");
  button.disabled = true;
  $("bench-results").replaceChildren(el("li", { class: "note", text: t("bench.running") }));
  try {
    const scores = await invoke("benchmark", { transport: settings.engine.transport });
    const best = Math.min(...scores.filter((s) => s.median_ms != null && s.failures === 0).map((s) => s.median_ms));
    const worst = Math.max(1, ...scores.map((s) => s.median_ms || 0));
    scores.sort((a, b) => (a.median_ms ?? 1e9) - (b.median_ms ?? 1e9));
    $("bench-results").replaceChildren(
      ...scores.map((s) => {
        const failed = s.median_ms == null || s.failures > 6;
        const bar = el("span", { class: "bar" });
        bar.style.width = failed ? "100%" : `${Math.max(4, (s.median_ms / worst) * 100)}%`;
        return el("li", { class: failed ? "failed" : s.median_ms === best ? "best" : "" }, [
          el("span", { text: presetName(s.upstream.id) }),
          el("span", {}, [bar]),
          el("span", { class: "ms", text: failed ? t("bench.failed") : t("fig.ms", { ms: num(Math.round(s.median_ms)) }) }),
        ]);
      }),
    );
  } finally {
    button.disabled = false;
  }
}

// ---- the log -------------------------------------------------------------------------

function drawLog() {
  $("log-on").checked = settings.engine.log;
  const filter = $("log-filter").value.trim().toLowerCase();
  const blockedOnly = $("log-blocked").checked;
  const rows = log.filter((e) => (!filter || e.name.includes(filter)) && (!blockedOnly || e.verdict.by === "rule" || e.verdict.by === "listed")).slice(0, 300);
  const time = new Intl.DateTimeFormat(lang, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  $("log-body").replaceChildren(
    ...rows.map((e) => {
      const blocked = e.verdict.by === "rule" || e.verdict.by === "listed";
      const result = blocked ? verdictText(e.verdict) : e.code === "NOERROR" ? (e.answers[0] || t("log.empty")) : e.code;
      const action = blocked
        ? el("button", { type: "button", class: "ghost", onclick: () => addRule("allow", e.name), text: t("log.allow") })
        : el("button", { type: "button", class: "ghost", onclick: () => addRule("block", e.name), text: t("log.block") });
      return el("tr", {}, [
        el("td", { class: "time", text: time.format(new Date(e.at * 1000)) }),
        el("td", { class: "name", text: e.name, title: e.name }),
        el("td", { text: e.kind }),
        el("td", { class: blocked ? "blocked" : e.code === "SERVFAIL" ? "failed" : "", text: result }),
        el("td", { class: "num", text: num(Math.round(e.micros / 100) / 10) }),
        el("td", {}, [action]),
      ]);
    }),
  );
  $("log-empty").textContent = settings.mode !== "local" ? t("recent.native") : !settings.engine.log ? t("log.off") : rows.length ? "" : t("log.none");
}

// ---- settings ------------------------------------------------------------------------

function drawSettings(version) {
  $("language").value = lang;
  $("close-to-tray").checked = settings.close_to_tray;
  $("cache").value = String(settings.engine.cache);
  if (version) $("about-version").textContent = t("about.version", { v: version });
}

// ---- talking to the host -------------------------------------------------------------

async function save() {
  try {
    state = await invoke("save_settings", { settings });
  } catch (e) {
    state.problem = String(e);
  }
  const boot = await invoke("boot");
  lists = boot.lists;
  drawAll();
}

function drawAll() {
  drawOverview();
  drawProtection();
  drawResolvers();
  drawLog();
}

async function pull() {
  const r = await invoke("stats");
  stats = r.stats;
  log = r.log || [];
  drawOverview();
  if (!$("view-log").hidden) drawLog();
}

function showView(name) {
  for (const b of document.querySelectorAll(".tabs button")) b.toggleAttribute("aria-current", false), b.dataset.view === name && b.setAttribute("aria-current", "page");
  for (const v of document.querySelectorAll(".view")) v.hidden = v.id !== `view-${name}`;
  if (name === "log") drawLog();
}

async function start() {
  const boot = await invoke("boot");
  settings = boot.settings;
  presets = boot.presets;
  lists = boot.lists;
  state = boot.state;
  lang = (settings.language || navigator.language || "en").startsWith("tr") ? "tr" : "en";
  strings = await invoke("strings", { language: lang });
  applyStrings();
  drawAll();
  drawSettings(boot.version);
  await pull();

  $("switch").addEventListener("click", async () => {
    if (busy) return;
    busy = true;
    drawOverview();
    try {
      state = await invoke("turn", { on: !state.on });
    } finally {
      busy = false;
      await pull();
    }
  });
  for (const b of document.querySelectorAll(".tabs button")) b.addEventListener("click", () => showView(b.dataset.view));
  for (const f of document.querySelectorAll(".rule-add")) {
    f.addEventListener("submit", (ev) => {
      ev.preventDefault();
      const input = f.querySelector("input");
      if (addRule(f.dataset.rule, input.value)) input.value = "";
      else input.setAttribute("aria-invalid", "true");
    });
    f.querySelector("input").addEventListener("input", (ev) => ev.target.removeAttribute("aria-invalid"));
  }
  $("why-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const name = $("why-input").value.trim();
    if (!name) return;
    const v = await invoke("explain", { name });
    const out = $("why-answer");
    if (!v) { out.className = "note"; out.textContent = t("why.notrunning"); return; }
    const blocked = v.by === "rule" || v.by === "listed";
    out.className = `note ${blocked ? "blocked" : "passed"}`;
    out.textContent = v.by === "listed" ? t("why.listed", { list: t(`list.${v.detail}`) })
      : v.by === "rule" ? t("why.rule", { rule: v.detail })
      : v.by === "allowed" ? t("why.allowed", { rule: v.detail })
      : t("why.pass");
  });
  for (const r of document.querySelectorAll('input[name="mode"]')) r.addEventListener("change", () => { settings.mode = r.value; save(); });
  $("transport").addEventListener("change", () => { settings.engine.transport = $("transport").value; save(); });
  $("validate").addEventListener("change", () => { settings.engine.validate = $("validate").checked; save(); });
  $("bench-run").addEventListener("click", runBench);
  $("log-on").addEventListener("change", () => { settings.engine.log = $("log-on").checked; save(); });
  $("log-filter").addEventListener("input", drawLog);
  $("log-blocked").addEventListener("change", drawLog);
  $("log-clear").addEventListener("click", async () => { await invoke("clear_log"); await pull(); drawLog(); });
  $("language").addEventListener("change", async () => {
    settings.language = $("language").value;
    lang = settings.language;
    strings = await invoke("strings", { language: lang });
    applyStrings();
    await save();
    drawSettings();
  });
  $("close-to-tray").addEventListener("change", () => { settings.close_to_tray = $("close-to-tray").checked; save(); });
  $("cache").addEventListener("change", () => { settings.engine.cache = Number($("cache").value); save(); });
  $("win-min").addEventListener("click", () => appWindow.minimize());
  $("win-max").addEventListener("click", () => appWindow.toggleMaximize());
  $("win-close").addEventListener("click", () => appWindow.close());
  await listen("stats", (e) => { stats = e.payload; drawOverview(); });
  await listen("state", (e) => { state = e.payload; drawOverview(); });
  setInterval(pull, 2000);
}

start();
