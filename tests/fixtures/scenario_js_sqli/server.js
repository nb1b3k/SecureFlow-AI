// Intentionally vulnerable fixture: classic string-concatenation SQL injection
// in a Node/Express handler. semgrep's auto config has JS rules for this;
// AI Discovery should also flag it. CWE-89 / OWASP A03.

const express = require('express');
const mysql = require('mysql');

const app = express();
const db = mysql.createConnection({ host: 'localhost', user: 'root', database: 'app' });


app.get('/user', (req, res) => {
  const userId = req.query.id;
  // Direct concatenation of user input into SQL is the canonical CWE-89.
  const query = "SELECT * FROM users WHERE id = " + userId;
  db.query(query, (err, rows) => {
    if (err) return res.status(500).send(err.message);
    res.json(rows[0] || null);
  });
});


app.listen(3000);
