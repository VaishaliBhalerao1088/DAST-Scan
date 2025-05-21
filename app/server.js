const express = require('express');
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Missing security headers (intentional vulnerability)
// No Content-Security-Policy, X-XSS-Protection, etc.

// Database simulation for SQL injection demo
const users = [
{ id: 1, username: 'admin', password: 'admin123' },
{ id: 2, username: 'user', password: 'password123' }
];

// Vulnerable endpoints
app.get('/', (req, res) => res.send(`
<html>
    <head>
    <title>Vulnerable Demo App</title>
    </head>
    <body>
    <h1>DAST Scan Target</h1>
    <form action="/search" method="get">
        <input name="query" placeholder="Test XSS...">
        <button>Search</button>
    </form>
    <hr>
    <h2>Links:</h2>
    <ul>
        <li><a href="/user?id=1">User Profile</a> (SQL Injection)</li>
        <li><a href="/reflect?data=<script>alert('XSS')</script>">Reflected XSS</a></li>
        <li><a href="/download?file=../../../etc/passwd">Path Traversal</a></li>
    </ul>
    </body>
</html>
`));

// XSS Vulnerability - Direct reflection of user input
app.get('/search', (req, res) => {
const query = req.query.query || '';
// No input sanitization (intentional vulnerability)
res.send(`
    <html>
    <head><title>Search Results</title></head>
    <body>
        <h1>Search Results</h1>
        <p>Results for: ${query}</p>
        <a href="/">Back to Home</a>
    </body>
    </html>
`);
});

// SQL Injection Vulnerability
app.get('/user', (req, res) => {
const userId = req.query.id;
// Vulnerable to SQL injection (simulated)
// In a real app with SQL, this would be exploitable

let user = users.find(u => u.id == userId);
if (user) {
    res.send(`
    <html>
        <head><title>User Profile</title></head>
        <body>
        <h1>User Profile</h1>
        <p>ID: ${userId}</p>
        <p>Username: ${user.username}</p>
        <a href="/">Back to Home</a>
        </body>
    </html>
    `);
} else {
    res.status(404).send('User not found');
}
});

// Another XSS vector with direct reflection
app.get('/reflect', (req, res) => {
const data = req.query.data || '';
res.send(`
    <html>
    <head><title>Data Reflection</title></head>
    <body>
        <h1>Reflected Data:</h1>
        <div>${data}</div>
        <a href="/">Back to Home</a>
    </body>
    </html>
`);
});

// Path Traversal vulnerability
app.get('/download', (req, res) => {
const file = req.query.file || 'safe.txt';
// No path validation (intentional vulnerability)
res.send(`Would download: ${file} (Path traversal demo)`);
});

// Insecure cookie setting
app.get('/login', (req, res) => {
res.cookie('session', 'secretvalue', { 
    // Missing secure and httpOnly flags
});
res.send('Login successful! Insecure cookie set.');
});

app.listen(3000, () => console.log('Target running on port 3000'));
