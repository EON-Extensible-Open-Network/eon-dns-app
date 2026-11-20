// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// EON DNS's window, driven over the Chrome DevTools protocol (which a debug
// build opens when EON_WEBVIEW_ARGS asks). It never touches the system's DNS:
// EON_DNS_NO_SYSTEM skips the elevated step, the resolver answers on a spare
// port, and the data folder is a fresh temporary one. Real lookups go out,
// encrypted, to the presets.
//
//   node tools/ui-check.mjs <debug eon-dns.exe> [screenshots dir]

import { spawn } from "node:child_process";
import { createSocket } from "node:dgram";
import { createServer } from "node:net";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const [exe, shots] = process.argv.slice(2);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const data = mkdtempSync(join(tmpdir(), "eon-dns-ui-"));
if (shots) mkdirSync(shots, { recursive: true });
const cdpPort = 9500 + Math.floor(Math.random() * 300);
/** A port that both UDP and TCP can bind on loopback: Windows reserves ranges. */
async function freePort() {
  for (let i = 0; i < 50; i++) {
    const port = 15300 + Math.floor(Math.random() * 2000);
    const ok = await new Promise((done) => {
      const tcp = createServer().once("error", () => done(false)).listen(port, "127.0.0.1", () => {
        const udp = createSocket("udp4").once("error", () => { tcp.close(); done(false); });
        udp.bind(port, "127.0.0.1", () => { udp.close(); tcp.close(); done(true); });
      });
    });
    if (ok) return port;
  }
  throw new Error("no free port");
}
const dnsPort = await freePort();
writeFileSync(join(data, "settings.json"), JSON.stringify({ language: "en", close_to_tray: false }));
const app = spawn(exe, [], {
  env: { ...process.env, EON_DNS_DATA: data, EON_DNS_PORT: String(dnsPort), EON_DNS_NO_SYSTEM: "1", EON_WEBVIEW_ARGS: `--remote-debugging-port=${cdpPort}` },
  stdio: "ignore",
});

let failures = 0;
const check = (what, ok) => { console.log(`${ok ? "  ok  " : "  FAIL"} ${what}`); if (!ok) failures++; };

let cdp;
async function devtools() {
  for (let i = 0; i < 300; i++) {
    try {
      const pages = await (await fetch(`http://127.0.0.1:${cdpPort}/json`)).json();
      const page = pages.find((p) => p.type === "page" && p.webSocketDebuggerUrl);
      if (page) {
        const ws = new WebSocket(page.webSocketDebuggerUrl);
        await new Promise((ok, no) => { ws.onopen = ok; ws.onerror = no; });
        let next = 1; const waiting = new Map();
        ws.onmessage = (e) => { const m = JSON.parse(e.data); if (m.id && waiting.has(m.id)) { waiting.get(m.id)(m); waiting.delete(m.id); } };
        return { send: (method, params = {}) => new Promise((ok) => { const id = next++; waiting.set(id, ok); ws.send(JSON.stringify({ id, method, params })); }) };
      }
    } catch { /* not yet */ }
    await sleep(200);
  }
  throw new Error("no DevTools endpoint");
}
async function js(expression) {
  const r = await cdp.send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
  if (r.result?.exceptionDetails) throw new Error(JSON.stringify(r.result.exceptionDetails).slice(0, 300));
  return r.result?.result?.value;
}
async function until(expression, ms = 15000) {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (await js(expression).catch(() => false)) return true; await sleep(150); }
  return false;
}
async function shot(name) {
  if (!shots) return;
  for (let i = 0; i < 5; i++) {
    const r = await cdp.send("Page.captureScreenshot", { format: "png" });
    if (r.result?.data) { writeFileSync(join(shots, `dns-${name}.png`), Buffer.from(r.result.data, "base64")); return; }
    await sleep(300);
  }
}

/** One A query to the local resolver; answers the first address, or null. */
function lookup(name) {
  return new Promise((done) => {
    const s = createSocket("udp4");
    const labels = name.split(".").flatMap((l) => [l.length, ...Buffer.from(l)]);
    const q = Buffer.from([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, ...labels, 0, 0, 1, 0, 1]);
    const timer = setTimeout(() => { s.close(); done(null); }, 8000);
    s.on("message", (m) => {
      clearTimeout(timer); s.close();
      const answers = m.readUInt16BE(6);
      if (!answers) return done(`rcode ${m[3] & 15}`);
      // The last four bytes of the first A answer, good enough for a check.
      let i = 12; while (m[i]) i += m[i] + 1; i += 5;
      for (let a = 0; a < answers; a++) {
        if (m[i] & 0xc0) i += 2; else { while (m[i]) i += m[i] + 1; i++; }
        const type = m.readUInt16BE(i); const len = m.readUInt16BE(i + 8);
        if (type === 1) return done([...m.subarray(i + 10, i + 14)].join("."));
        i += 10 + len;
      }
      done("other");
    });
    s.send(q, dnsPort, "127.0.0.1");
  });
}
const clickText = (text) => js(`(() => { const n = [...document.querySelectorAll('button, label')].find((b) => b.textContent.trim() === ${JSON.stringify(text)} && b.offsetParent !== null); if (!n) return false; n.click(); return true; })()`);

try {
  cdp = await devtools();
  await cdp.send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 800, deviceScaleFactor: 1, mobile: false });
  check("the window opens off, saying lookups are readable", await until(`document.getElementById('switch').getAttribute('aria-checked') === 'false' && document.getElementById('route').textContent === t('route.off')`));
  check("the switch is a labelled switch", await js(`document.getElementById('switch').getAttribute('role') === 'switch' && !!document.getElementById('switch').getAttribute('aria-label')`));
  await shot("01-off");

  await js(`document.getElementById('switch').click()`);
  const turnedOn = await until(`document.body.classList.contains('on') && document.getElementById('switch-state').textContent === t('switch.on')`, 20000);
  if (!turnedOn) console.log("    state:", await js(`JSON.stringify(state)`));
  check("pressing it turns protection on", turnedOn);
  check("and says where lookups go", await js(`document.getElementById('route').textContent.includes('Cloudflare') && document.getElementById('route').textContent.includes('Quad9')`));
  const ip = await lookup("wikipedia.org");
  check(`a real lookup through the local resolver answers (${ip})`, /^\d+\.\d+\.\d+\.\d+$/.test(ip || ""));

  // The log, a rule, and the answer the rule gives.
  await js(`(() => { document.querySelector('[data-view=log]').click(); })()`);
  await js(`document.getElementById('log-on').click()`);
  await until(`settings.engine.log === true`);
  await js(`document.querySelector('[data-view=protection]').click()`);
  await js(`(() => { const i = document.getElementById('block-input'); i.value = 'Ads.Example.com'; i.form.requestSubmit(); })()`);
  check("a rule is added, cleaned up", await until(`[...document.querySelectorAll('#block-list li')].some((li) => li.textContent.startsWith('ads.example.com'))`));
  const blocked = await lookup("x.ads.example.com");
  check("and a name under it is answered 0.0.0.0", blocked === "0.0.0.0");
  await js(`(() => { const i = document.getElementById('why-input'); i.value = 'tracker.ads.example.com'; i.form.requestSubmit(); })()`);
  check("'why' explains it", await until(`document.getElementById('why-answer').textContent === t('why.rule', { rule: 'ads.example.com' })`));
  check("the malware list is on and downloaded", await until(`[...document.querySelectorAll('#lists .row')][0].querySelector('input').checked && /\\d/.test(document.querySelector('#lists .row .meta').textContent)`, 60000));
  await shot("03-protection");

  for (const n of ["github.com", "mozilla.org", "example.org"]) await lookup(n);
  await js(`document.querySelector('[data-view=overview]').click()`);
  check("the overview counts lookups and blocks", await until(`Number(document.getElementById('fig-lookups').textContent.replace(/\\D/g, '')) >= 5 && document.getElementById('fig-blocked').textContent === '1'`));
  check("and lists what was blocked", await until(`[...document.querySelectorAll('#recent .name')].some((n) => n.textContent === 'x.ads.example.com')`));
  check("the ring has sixty ticks, one of them amber", await js(`document.querySelectorAll('#ring .tick').length === 60 && document.querySelectorAll('#ring .warm').length >= 1`));
  await shot("02-on");

  await js(`document.querySelector('[data-view=log]').click()`);
  check("the log shows the lookups made since it was switched on", await until(`document.querySelectorAll('#log-body tr').length >= 4 && document.querySelector('#log-body tr td.name').textContent === 'example.org'`));
  await js(`(() => { const r = [...document.querySelectorAll('#log-body tr')].find((tr) => tr.children[1].textContent === 'x.ads.example.com'); r.querySelector('button').click(); })()`);
  check("'Allow' on a blocked row adds an allow rule", await until(`(async () => (await invoke('explain', { name: 'x.ads.example.com' }))?.by === 'allowed')()`));
  const allowedNow = await lookup("x.ads.example.com");
  check(`and the name is asked upstream again (${allowedNow})`, allowedNow !== "0.0.0.0");
  await shot("04-log");

  await js(`document.querySelector('[data-view=resolvers]').click()`);
  await js(`document.getElementById('bench-run').click()`);
  check("timing the resolvers from here ranks them", await until(`document.querySelectorAll('#bench-results li .bar').length === 7`, 90000));
  await shot("05-resolvers");

  await js(`(async () => { document.getElementById('language').value = 'tr'; document.getElementById('language').dispatchEvent(new Event('change')); })()`);
  await js(`document.querySelector('[data-view=overview]').click()`);
  check("Turkish throughout", await until(`document.getElementById('switch-state').textContent === 'Korunuyor' && document.querySelector('[data-view=protection]').textContent === 'Koruma'`));
  await shot("06-tr");

  await js(`document.getElementById('switch').click()`);
  check("pressing again turns it off", await until(`!document.body.classList.contains('on')`, 20000));
  check("and the local resolver stops answering", (await lookup("wikipedia.org")) === null);
} catch (error) {
  console.error(error);
  failures++;
} finally {
  app.kill();
  await sleep(500);
  try { rmSync(data, { recursive: true, force: true }); } catch { /* the webview may hold files a moment */ }
}
console.log(failures ? `\n${failures} failure(s)` : "\nall window checks pass");
process.exit(failures ? 1 : 0);
