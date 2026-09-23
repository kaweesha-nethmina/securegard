const express = require('express');
const app = express();

// sg-sql-injection-concat
app.get('/user', (req, res) => {
  const query = "SELECT * FROM users WHERE id = " + req.query.id;
  db.query(query);
});

// sg-hardcoded-secret-generic + sg-aws-access-key
const apiKey = "AKIAABCDEFGHIJKLMNOP";
const stripeSecret = "sk_live_51H8xyzABCDEFGHIJKLMNOPQRSTUVWX1234567890";

// sg-xss-innerhtml
function render(userInput) {
  document.getElementById('out').innerHTML = userInput;
}

// sg-eval-usage
function run(code) {
  return eval(code);
}

// sg-command-injection
const { exec } = require('child_process');
app.get('/ping', (req, res) => {
  exec('ping -c 1 ' + req.query.host);
});

// sg-weak-hash
const crypto = require('crypto');
function hashPassword(pw) {
  return crypto.createHash('md5').update(pw).digest('hex');
}

// sg-insecure-random
function genToken() {
  const token = Math.random().toString(36);
  return token;
}

// sg-cors-wildcard
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  next();
});
