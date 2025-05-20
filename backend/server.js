const express = require('express');
const app = express();
const port = 3000;

app.get('/', (req, res) => {
  res.send('<h1>Hello from Node.js API</h1>');
});

app.listen(port, () => {
  console.log(`API listening on http://localhost:${port}`);
});
