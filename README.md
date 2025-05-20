# Sample Node + React App with OWASP ZAP GitHub Action

This is a simple demo project showcasing how to run an OWASP ZAP DAST scan using GitHub Actions on a Node.js + React app.

## Project Structure

```
sample-app/
├── .github/
│   └── workflows/
│       └── zap-scan.yml
├── backend/
│   ├── server.js
│   └── package.json
├── frontend/
│   ├── public/
│   ├── src/
│   ├── package.json
│   └── ...
└── README.md
```

## Running the Demo

1. Clone this repo
2. Run both backend and frontend locally if testing manually
3. Push to GitHub main branch or trigger via Actions UI

## Output

The ZAP scan will run against your Node API and return security findings in the GitHub Actions console.
