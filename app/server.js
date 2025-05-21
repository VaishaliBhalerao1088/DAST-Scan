const express = require('express');
const app = express();
app.use(express.urlencoded({ extended: true }));

// Vulnerable endpoints
app.get('/', (req, res) => res.send(`
  <html>
    <body>
      <h1>DAST Scan Target</h1>
      <form action="/search">
        <input name="query" placeholder="Test XSS...">
        <button>Search</button>
      </form>
      <a href="/user?id=1">Profile</a>
    </body>
  </html>
`));

app.get('/search', (req, res) => {
  res.send(`Results for: ${req.query.query}`); // XSS
});

app.listen(3000, () => console.log('Target running on port 3000'));