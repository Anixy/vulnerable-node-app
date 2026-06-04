const express = require('express');
const mysql = require('mysql');
const { exec } = require('child_process');

const app = express();
const port = 3000;

// VULNERABILITY 1: Hardcoded Secrets
const dbPassword = "super_secret_password_123";
const apiKey = "AKIAIOSFODNN7EXAMPLE";

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: dbPassword,
  database: 'test_db'
});

app.use(express.json());

app.get('/', (req, res) => {
  res.send('Welcome to the Vulnerable Node App!');
});

// VULNERABILITY 2: SQL Injection
app.get('/users', (req, res) => {
  const username = req.query.username;
  // Vulnerable query: directly concatenating user input
  const query = "SELECT * FROM users WHERE username = '" + username + "'";
  
  connection.query(query, (error, results) => {
    if (error) {
      return res.status(500).send('Database error');
    }
    res.json(results);
  });
});

// VULNERABILITY 3: Command Injection & XSS
app.get('/ping', (req, res) => {
  const target = req.query.target;
  // Vulnerable command execution: directly using user input
  exec('ping -c 4 ' + target, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).send(error.message);
    }
    // Vulnerable to Cross-Site Scripting (XSS) if output contains unescaped HTML
    res.send(`<pre>${stdout}</pre>`); 
  });
});

// VULNERABILITY 5: SQL Injection in Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  // Vulnerable query: directly concatenating user input in a POST request
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  
  connection.query(query, (error, results) => {
    if (error) {
      return res.status(500).send('Database error');
    }
    if (results.length > 0) {
      res.send('Login successful');
    } else {
      res.status(401).send('Invalid credentials');
    }
  });
});

app.listen(port, () => {
  console.log(`App listening at http://localhost:${port}`);
});
