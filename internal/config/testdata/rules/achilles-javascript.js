// Tests for configs/rules/achilles-javascript.yaml (opengrep --test). Never run.
// "ruleid: X" says the next line must be reported by rule X; "ok: X" says it must not.
const express = require("express");
const { exec, execFile } = require("child_process");
const child_process = require("child_process");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const axios = require("axios");
const escapeHtml = require("escape-html");
const serialize = require("node-serialize");
const vm = require("vm");

const app = express();

app.get("/lookup", (req, res) => {
  // ruleid: achilles.javascript.command-injection
  exec("nslookup " + req.query.host, (err, out) => res.send(out));
});

app.get("/lookup-sync", (req, res) => {
  const host = req.query.host;
  // ruleid: achilles.javascript.command-injection
  const out = child_process.execSync(`dig ${host}`);
  res.json({ out: String(out) });
});

app.get("/lookup-safe", (req, res) => {
  // ok: achilles.javascript.command-injection
  execFile("nslookup", [req.query.host], (err, out) => res.json({ out }));
});

app.get("/hello", (req, res) => {
  // ruleid: achilles.javascript.reflected-xss
  res.send("<h1>Hello " + req.query.name + "</h1>");
});

app.get("/hello-safe", (req, res) => {
  // ok: achilles.javascript.reflected-xss
  res.send("<h1>Hello " + escapeHtml(req.query.name) + "</h1>");
});

app.get("/hello-json", (req, res) => {
  // ok: achilles.javascript.reflected-xss
  res.json({ hello: req.query.name });
});

function render(el, html, name) {
  // HTML the page builds itself is not flagged.
  // ok: achilles.javascript.dom-xss
  el.innerHTML = html;
  // ok: achilles.javascript.dom-xss
  document.write("<p>" + name + "</p>");
  // ok: achilles.javascript.dom-xss
  el.innerHTML = "<b>static</b>";
  // ok: achilles.javascript.dom-xss
  el.textContent = name;
}

function fromTheUrl(el) {
  // ruleid: achilles.javascript.dom-xss
  el.innerHTML = decodeURIComponent(location.hash.slice(1));
  const q = new URLSearchParams(window.location.search).get("q");
  // ruleid: achilles.javascript.dom-xss
  el.innerHTML = "<h2>Results for " + q + "</h2>";
  // ruleid: achilles.javascript.dom-xss
  document.write(document.referrer);
  // ruleid: achilles.javascript.dom-xss
  $("#greeting").html(localStorage.getItem("name"));
  // ok: achilles.javascript.dom-xss
  el.innerHTML = DOMPurify.sanitize(location.hash);
  // ok: achilles.javascript.dom-xss
  el.textContent = q;
  // ok: achilles.javascript.dom-xss
  el.innerHTML = "<a href='/search?q=" + encodeURIComponent(q) + "'>again</a>";
}

window.addEventListener("message", (event) => {
  // ruleid: achilles.javascript.dom-xss
  document.getElementById("out").innerHTML = event.data.html;
});

app.get("/users", async (req, res) => {
  // ruleid: achilles.javascript.sql-injection
  const rows = await db.query("SELECT * FROM users WHERE name = '" + req.query.name + "'");
  res.json(rows);
});

app.get("/users2", async (req, res) => {
  const id = req.params.id;
  // ruleid: achilles.javascript.sql-injection
  const rows = await pool.query(`SELECT * FROM users WHERE id = ${id}`);
  res.json(rows);
});

app.get("/users-safe", async (req, res) => {
  // ok: achilles.javascript.sql-injection
  const rows = await pool.query("SELECT * FROM users WHERE id = $1", [req.params.id]);
  res.json(rows);
});

app.get("/file", (req, res) => {
  // ruleid: achilles.javascript.path-traversal
  fs.readFile(path.join("/srv/files", req.query.name), (err, data) => res.send(data));
});

app.get("/file-safe", (req, res) => {
  const name = path.basename(req.query.name);
  // ok: achilles.javascript.path-traversal
  fs.readFile(path.join("/srv/files", name), (err, data) => res.json({ size: data.length }));
});

app.get("/download", (req, res) => {
  // ruleid: achilles.javascript.path-traversal
  res.sendFile(req.query.file);
});

app.get("/download-rooted", (req, res) => {
  // ok: achilles.javascript.path-traversal
  res.sendFile(req.query.file, { root: "/srv/files" });
});

app.get("/proxy", async (req, res) => {
  // ruleid: achilles.javascript.ssrf
  const r = await axios.get(req.query.url);
  res.json(r.data);
});

app.get("/proxy-fixed", async (req, res) => {
  // ok: achilles.javascript.ssrf
  const r = await axios.get("https://api.example.com/items", { params: { q: req.query.q } });
  res.json(r.data);
});

app.get("/go", (req, res) => {
  // ruleid: achilles.javascript.open-redirect
  res.redirect(req.query.next);
});

app.get("/home", (req, res) => {
  // ok: achilles.javascript.open-redirect
  res.redirect("/dashboard");
});

function compile(src) {
  // ruleid: achilles.javascript.code-injection
  const f = new Function("x", src);
  // ruleid: achilles.javascript.code-injection
  vm.runInNewContext(src, {});
  // ok: achilles.javascript.code-injection
  const g = new Function("x", "return x * 2");
  return [f, g];
}

app.post("/profile", (req, res) => {
  // ruleid: achilles.javascript.unsafe-deserialization
  const profile = serialize.unserialize(req.cookies.profile);
  // ok: achilles.javascript.unsafe-deserialization
  const safe = JSON.parse(req.cookies.profile);
  res.json({ profile, safe });
});

function client() {
  const https = require("https");
  // ruleid: achilles.javascript.tls-verification-disabled
  const agent = new https.Agent({ keepAlive: true, rejectUnauthorized: false });
  // ok: achilles.javascript.tls-verification-disabled
  const strict = new https.Agent({ keepAlive: true, rejectUnauthorized: true });
  return [agent, strict];
}

function hashes(password, key, iv) {
  // ruleid: achilles.javascript.weak-crypto
  crypto.createHash("md5").update(password).digest("hex");
  // ruleid: achilles.javascript.weak-crypto
  crypto.createCipheriv("aes-128-ecb", key, null);
  // ruleid: achilles.javascript.weak-crypto
  crypto.createCipheriv("des-ede3-cbc", key, iv);
  // ok: achilles.javascript.weak-crypto
  crypto.createHash("sha256").update(password).digest("hex");
  // ok: achilles.javascript.weak-crypto
  crypto.createCipheriv("aes-256-gcm", key, iv);
}

app.listen(3000);
