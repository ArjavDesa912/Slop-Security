// 🚨 Example file with security vulnerabilities for testing vibe-check
// DO NOT USE IN PRODUCTION - This is intentionally vulnerable code!

const express = require('express');
const mysql = require('mysql');

const app = express();

// ❌ A02: Hardcoded API key
const STRIPE_KEY = "sk_live_abc123def456ghi789jkl";
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

// ❌ A03: SQL Injection vulnerability
app.get('/user', (req, res) => {
    const userId = req.query.id;
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    connection.query(query, (err, results) => {
        res.json(results);
    });
});

// ❌ A03: XSS via innerHTML
app.get('/render', (req, res) => {
    const userContent = req.query.content;
    res.send(`<div id="content"></div><script>document.getElementById('content').innerHTML = "${userContent}";</script>`);
});

// ❌ A03: Command Injection
const { exec } = require('child_process');
app.get('/ping', (req, res) => {
    const host = req.query.host;
    exec(`ping -c 4 ${host}`, (error, stdout) => {
        res.send(stdout);
    });
});

// ❌ A02: Weak crypto
const crypto = require('crypto');
function hashPassword(password) {
    return crypto.createHash('md5').update(password).digest('hex');
}

// ❌ A02: Insecure random
function generateToken() {
    return Math.random().toString(36).substring(7);
}

// ❌ A05: Debug mode enabled
app.set('debug', true);

// ❌ A03: eval usage
app.post('/calculate', (req, res) => {
    const expression = req.body.expression;
    const result = eval(expression);
    res.json({ result });
});

// ❌ A10: SSRF vulnerability
const axios = require('axios');
app.get('/fetch', async (req, res) => {
    const url = req.query.url;
    const response = await axios.get(url);
    res.json(response.data);
});

app.listen(3000);
