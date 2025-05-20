import React, { useState } from 'react';
import './App.css';

function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [message, setMessage] = useState('');

  const handleLogin = (e) => {
    e.preventDefault();
    // Intentionally vulnerable to XSS
    setMessage(`Welcome ${username}!`);
  };

  const handleSearch = (e) => {
    e.preventDefault();
    // Intentionally vulnerable to XSS
    setMessage(`Searching for: ${searchQuery}`);
  };

  return (
    <div className="App">
      <header className="App-header">
        <h1>DAST Scanner Demo</h1>
        <p>This is a demo application to showcase OWASP ZAP scanning capabilities</p>
      </header>

      <main className="App-main">
        <section className="demo-section">
          <h2>1. Login Form (XSS Demo)</h2>
          <form onSubmit={handleLogin}>
            <input
              type="text"
              placeholder="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <button type="submit">Login</button>
          </form>
        </section>

        <section className="demo-section">
          <h2>2. Search Form (XSS Demo)</h2>
          <form onSubmit={handleSearch}>
            <input
              type="text"
              placeholder="Search..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
            <button type="submit">Search</button>
          </form>
        </section>

        {message && (
          <section className="demo-section">
            <h2>Response:</h2>
            <div dangerouslySetInnerHTML={{ __html: message }} />
          </section>
        )}

        <section className="demo-section">
          <h2>3. Sensitive Information</h2>
          <p>This section contains sensitive information that should be protected:</p>
          <ul>
            <li>API Key: <code>sk_test_123456789</code></li>
            <li>Database Password: <code>db_password_123</code></li>
          </ul>
        </section>
      </main>
    </div>
  );
}

export default App;
