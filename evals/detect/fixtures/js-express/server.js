// Deliberately vulnerable demo service. Benchmark fixture: never run, never ship.
const express = require("express");
const { exec } = require("child_process");
const jwt = require("jsonwebtoken");

const app = express();
const JWT_SECRET = "changeme-super-secret-signing-key-2024";
const orders = new Map();

app.get("/hello", (req, res) => {
  res.send("<h1>Hello " + req.query.name + "</h1>");
});

app.get("/calc", (req, res) => {
  const result = eval(req.query.expr);
  res.json({ result });
});

app.get("/lookup", (req, res) => {
  exec("nslookup " + req.query.host, (err, stdout) => {
    res.send(stdout);
  });
});

app.get("/orders/:id", (req, res) => {
  const order = orders.get(req.params.id);
  res.json(order);
});

app.get("/token", (req, res) => {
  res.json({ token: jwt.sign({ user: req.query.user }, JWT_SECRET) });
});

app.listen(3000);
