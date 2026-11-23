"""
=============================================================================
Codomax Cybersecurity & Ethical Hacking Virtual Internship
Module 03: Web Application Security (Day 11 - Day 15)
Author: Ayan Mondal (Intern ID: CDS/INT/2026/26637504)
File: sandbox/app.py

Description:
A controlled educational sandbox web application contrasting intentionally
vulnerable endpoints with remediated, hardened equivalents.
Demonstrates:
  1. SQL Injection (SQLi)
  2. Broken Authentication & Session Weaknesses
  3. Reflected Cross-Site Scripting (XSS)
  4. Broken Access Control / Insecure Direct Object References (IDOR)

WARNING / DISCLAIMER:
This software is strictly intended for local educational and authorized lab
testing purposes only. Do not deploy to public or production environments.
=============================================================================
"""

import os
import sqlite3
import html
import secrets
from flask import Flask, request, session, redirect, url_for, render_template_string, make_response
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# Cryptographically random key for secure session signing
app.secret_key = secrets.token_hex(32)

# Session cookie hardening defaults
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # Set to True in production HTTPS
)

DB_PATH = os.path.join(os.path.dirname(__file__), "lab.db")


def init_db():
    """Initialize local SQLite database with seed data for the lab."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Drop existing tables if any
    cursor.execute("DROP TABLE IF EXISTS users")
    cursor.execute("DROP TABLE IF EXISTS products")
    cursor.execute("DROP TABLE IF EXISTS profiles")

    # Users table
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            plaintext_password TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

    # Products table (for SQLi demonstration)
    cursor.execute("""
        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            price REAL NOT NULL,
            stock INTEGER NOT NULL
        )
    """)

    # Profiles table (for IDOR demonstration)
    cursor.execute("""
        CREATE TABLE profiles (
            user_id INTEGER PRIMARY KEY,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL,
            ssn_or_id TEXT NOT NULL,
            account_balance REAL NOT NULL,
            api_secret_key TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    # Seed Users
    alice_hash = generate_password_hash("SuperAdminPass2026!")
    bob_hash = generate_password_hash("BobPassword123!")
    charlie_hash = generate_password_hash("CharlieSecure#456")

    cursor.executemany("""
        INSERT INTO users (username, plaintext_password, password_hash, role)
        VALUES (?, ?, ?, ?)
    """, [
        ("alice_admin", "SuperAdminPass2026!", alice_hash, "administrator"),
        ("bob_user", "BobPassword123!", bob_hash, "user"),
        ("charlie_user", "CharlieSecure#456", charlie_hash, "user")
    ])

    # Seed Products
    cursor.executemany("""
        INSERT INTO products (name, category, price, stock)
        VALUES (?, ?, ?, ?)
    """, [
        ("Firewall Appliance X100", "Network Security", 1299.99, 15),
        ("Hardware Security Key (FIDO2)", "Hardware", 49.50, 120),
        ("Encrypted NVMe SSD 2TB", "Storage", 189.00, 45),
        ("Enterprise SIEM License", "Software", 4500.00, 5),
        ("VPN Gateway Pro", "Network Security", 899.00, 22)
    ])

    # Seed Profiles (Contains PII & Sensitive financial info)
    cursor.executemany("""
        INSERT INTO profiles (user_id, full_name, email, ssn_or_id, account_balance, api_secret_key)
        VALUES (?, ?, ?, ?, ?, ?)
    """, [
        (1, "Alice Montgomery (CISO)", "alice.admin@codomax-labs.internal", "CDS-SSN-9981-A", 95000.00, "sec_live_998811aliceAdminSecret"),
        (2, "Bob Jenkins (Developer)", "bob.user@codomax-labs.internal", "CDS-SSN-4412-B", 4200.50, "sec_live_4412bobTokenUser"),
        (3, "Charlie Davis (Analyst)", "charlie.user@codomax-labs.internal", "CDS-SSN-7731-C", 6150.00, "sec_live_7731charlieApiKey")
    ])

    conn.commit()
    conn.close()


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def render_lab_page(title, body_template, **context):
    """Render a unified HTML shell without requiring external files."""
    session_user = session.get("user")
    nav_user = f"<span>Logged in as: <strong>{session_user}</strong></span> <a href='/logout'>[Logout]</a>" if session_user else "<span style='color:#8b949e;'>[Guest Session]</span>"

    page_html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - Codomax Web Security Lab</title>
    <style>
        :root {{
            --bg: #0d1117;
            --surface: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --heading: #f0f6fc;
            --vuln: #f85149;
            --vuln-bg: rgba(248, 81, 73, 0.1);
            --safe: #2ea043;
            --safe-bg: rgba(46, 160, 67, 0.1);
            --accent: #58a6ff;
            --code-bg: #090d13;
        }}
        body {{
            margin: 0;
            padding: 20px;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            line-height: 1.6;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        header {{
            border-bottom: 1px solid var(--border);
            padding-bottom: 15px;
            margin-bottom: 25px;
        }}
        h1, h2, h3 {{ color: var(--heading); }}
        a {{ color: var(--accent); text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .nav-bar {{
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            background: var(--surface);
            padding: 12px 18px;
            border-radius: 6px;
            border: 1px solid var(--border);
            margin-bottom: 25px;
            align-items: center;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            font-size: 12px;
            font-weight: 600;
            border-radius: 12px;
        }}
        .badge-vuln {{ background: var(--vuln-bg); color: var(--vuln); border: 1px solid var(--vuln); }}
        .badge-safe {{ background: var(--safe-bg); color: var(--safe); border: 1px solid var(--safe); }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        .card.vuln-card {{ border-left: 4px solid var(--vuln); }}
        .card.safe-card {{ border-left: 4px solid var(--safe); }}
        input, button, select, textarea {{
            background: var(--code-bg);
            border: 1px solid var(--border);
            color: var(--text);
            padding: 8px 12px;
            border-radius: 4px;
            font-size: 14px;
        }}
        button {{
            background: #238636;
            color: white;
            cursor: pointer;
            font-weight: 600;
            border: none;
        }}
        button.btn-vuln {{ background: #da3633; }}
        button:hover {{ opacity: 0.9; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        th, td {{
            text-align: left;
            padding: 10px;
            border-bottom: 1px solid var(--border);
        }}
        th {{ color: var(--heading); background: rgba(255,255,255,0.03); }}
        pre, code {{
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
            background: var(--code-bg);
            border-radius: 4px;
        }}
        pre {{
            padding: 12px;
            overflow-x: auto;
            border: 1px solid var(--border);
        }}
        code {{ padding: 2px 5px; font-size: 13px; }}
        .alert {{
            padding: 12px 16px;
            border-radius: 6px;
            margin-bottom: 15px;
        }}
        .alert-info {{ background: rgba(88, 166, 255, 0.1); border: 1px solid var(--accent); color: var(--heading); }}
        .alert-danger {{ background: var(--vuln-bg); border: 1px solid var(--vuln); color: #ff7b72; }}
        .alert-success {{ background: var(--safe-bg); border: 1px solid var(--safe); color: #7ee787; }}
        .intern-meta {{
            font-size: 13px;
            color: #8b949e;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Codomax Web Application Security Lab (Module 03)</h1>
            <div class="intern-meta">
                <strong>Intern:</strong> Ayan Mondal | <strong>Intern ID:</strong> CDS/INT/2026/26637504 | <strong>Track:</strong> Cybersecurity & Ethical Hacking
            </div>
        </header>

        <div class="nav-bar">
            <a href="/">🏠 Lab Overview</a>
            <span>|</span>
            <a href="/vulnerable/search"><span class="badge badge-vuln">VULN</span> SQLi</a>
            <a href="/secure/search"><span class="badge badge-safe">SECURE</span> SQLi</a>
            <span>|</span>
            <a href="/vulnerable/login"><span class="badge badge-vuln">VULN</span> Auth</a>
            <a href="/secure/login"><span class="badge badge-safe">SECURE</span> Auth</a>
            <span>|</span>
            <a href="/vulnerable/feedback"><span class="badge badge-vuln">VULN</span> XSS</a>
            <a href="/secure/feedback"><span class="badge badge-safe">SECURE</span> XSS</a>
            <span>|</span>
            <a href="/vulnerable/profile"><span class="badge badge-vuln">VULN</span> IDOR</a>
            <a href="/secure/profile"><span class="badge badge-safe">SECURE</span> IDOR</a>
            <span>|</span>
            {nav_user}
        </div>

        {body_template}
    </div>
</body>
</html>
    """
    return render_template_string(page_html, **context)


# =============================================================================
# ROUTE: Home / Dashboard
# =============================================================================
@app.route("/")
def index():
    content = """
    <div class="card">
        <h2>Interactive Web Application Security Testbed</h2>
        <p>This lab demonstrates real-world vulnerability patterns contrasted with verified defense controls following the <code>Identify -> Test -> Fix -> Document</code> methodology.</p>
        <div class="alert alert-info">
            <strong>Lab Environment Scope:</strong> Listening strictly on <code>127.0.0.1:5000</code>. All operations are safe, self-contained within an isolated SQLite database, and designed for hands-on verification and walkthrough recordings.
        </div>
    </div>

    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
        <div class="card vuln-card">
            <h3><span class="badge badge-vuln">VULNERABLE</span> Endpoints</h3>
            <ul>
                <li><a href="/vulnerable/search"><code>/vulnerable/search</code></a> — Raw SQL string formatting injection.</li>
                <li><a href="/vulnerable/login"><code>/vulnerable/login</code></a> — Plaintext storage, account enumeration & session fixation.</li>
                <li><a href="/vulnerable/feedback"><code>/vulnerable/feedback</code></a> — Unescaped reflection enabling Stored/Reflected XSS.</li>
                <li><a href="/vulnerable/profile?user_id=1"><code>/vulnerable/profile?user_id=X</code></a> — Direct object reference without authorization.</li>
            </ul>
        </div>
        <div class="card safe-card">
            <h3><span class="badge badge-safe">SECURE</span> Endpoints</h3>
            <ul>
                <li><a href="/secure/search"><code>/secure/search</code></a> — Parameterized SQL queries (prepared statements).</li>
                <li><a href="/secure/login"><code>/secure/login</code></a> — PBKDF2/SHA256 password hashing, uniform errors, regenerated cookies.</li>
                <li><a href="/secure/feedback"><code>/secure/feedback</code></a> — HTML entity encoding & strict CSP defense headers.</li>
                <li><a href="/secure/profile"><code>/secure/profile</code></a> — Session-based stateful authorization check enforcing access boundaries.</li>
            </ul>
        </div>
    </div>

    <div class="card">
        <h3>Database & Test Utility Controls</h3>
        <p>Current active database: <code>lab.db</code>. Reset seeds at any time if records are altered during testing.</p>
        <form method="POST" action="/reset-db">
            <button type="submit">🔄 Reset & Re-Seed SQLite Database</button>
        </form>
    </div>
    """
    return render_lab_page("Dashboard", content)


@app.route("/reset-db", methods=["POST"])
def reset_database():
    init_db()
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    resp = make_response(redirect(url_for("index")))
    resp.set_cookie("insecure_user_token", "", expires=0)
    return resp


# =============================================================================
# 1. SQL INJECTION (OWASP A03:2021 - Injection)
# =============================================================================

@app.route("/vulnerable/search", methods=["GET"])
def vuln_search():
    query = request.args.get("q", "")
    results = []
    error = None
    raw_sql = ""

    if query:
        # VULNERABILITY: Raw string concatenation directly inside SQL execution
        raw_sql = f"SELECT id, name, category, price, stock FROM products WHERE name LIKE '%{query}%'"
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(raw_sql)
            results = cursor.fetchall()
        except Exception as e:
            error = str(e)
        finally:
            conn.close()

    rows_html = ""
    for row in results:
        rows_html += f"<tr><td>{row[0]}</td><td>{row[1]}</td><td>{row[2]}</td><td>{row[3]}</td><td>{row[4]}</td></tr>"

    results_table = f"""
    <h3>Results ({len(results)})</h3>
    <table>
        <thead>
            <tr><th>ID</th><th>Name / Col 1</th><th>Category / Col 2</th><th>Price / Col 3</th><th>Stock / Col 4</th></tr>
        </thead>
        <tbody>
            {rows_html}
        </tbody>
    </table>
    """ if results else ("<p>No products found matching.</p>" if query and not error else "")

    content = f"""
    <div class="card vuln-card">
        <h2><span class="badge badge-vuln">Vulnerable</span> Product Catalog Search (SQL Injection)</h2>
        <p>This endpoint constructs SQL queries via string formatting without parameterization. Attackers can escape string delimiters and append arbitrary SQL clauses.</p>
        
        <form method="GET" action="/vulnerable/search">
            <input type="text" name="q" value="{html.escape(query)}" placeholder="Search products..." style="width: 320px;">
            <button type="submit" class="btn-vuln">Search (Vulnerable)</button>
        </form>

        <div style="margin-top: 15px; font-size: 13px;">
            <strong>Test Payloads:</strong>
            <ul>
                <li>Safe sample search: <code>Firewall</code></li>
                <li>Boolean bypass (dump all): <code>' OR '1'='1</code></li>
                <li>UNION exploitation (steal user credentials): <code>' UNION SELECT id, username, plaintext_password, 0, role FROM users --</code></li>
            </ul>
        </div>

        {f'<p style="margin-top:15px;"><strong>Executed SQL Query:</strong></p><pre><code>{html.escape(raw_sql)}</code></pre>' if raw_sql else ''}
        {f'<div class="alert alert-danger"><strong>SQL Error:</strong> {html.escape(error)}</div>' if error else ''}
        {results_table}
    </div>
    """
    return render_lab_page("Vulnerable Search", content)


@app.route("/secure/search", methods=["GET"])
def secure_search():
    query = request.args.get("q", "")
    results = []
    executed_code = ""

    if query:
        # SECURE REMEDIATION: Parameterized queries using placeholders (?)
        executed_code = 'cursor.execute("SELECT id, name, category, price, stock FROM products WHERE name LIKE ?", (f"%{query}%",))'
        conn = get_db_connection()
        cursor = conn.cursor()
        search_pattern = f"%{query}%"
        cursor.execute("SELECT id, name, category, price, stock FROM products WHERE name LIKE ?", (search_pattern,))
        results = cursor.fetchall()
        conn.close()

    rows_html = ""
    for row in results:
        rows_html += f"<tr><td>{row['id']}</td><td>{row['name']}</td><td>{row['category']}</td><td>${row['price']:.2f}</td><td>{row['stock']}</td></tr>"

    results_table = f"""
    <h3>Results ({len(results)})</h3>
    <table>
        <thead>
            <tr><th>ID</th><th>Name</th><th>Category</th><th>Price</th><th>Stock</th></tr>
        </thead>
        <tbody>
            {rows_html}
        </tbody>
    </table>
    """ if results else (f"<p>No products found matching <code>{html.escape(query)}</code>.</p>" if query else "")

    content = f"""
    <div class="card safe-card">
        <h2><span class="badge badge-safe">Secure</span> Product Catalog Search (Parameterized Query)</h2>
        <p>This remediated endpoint binds user input as typed parameters to prepared statement placeholders. Special characters like quotes and semicolons are treated solely as literal search text.</p>
        
        <form method="GET" action="/secure/search">
            <input type="text" name="q" value="{html.escape(query)}" placeholder="Search products securely..." style="width: 320px;">
            <button type="submit">Search (Secure)</button>
        </form>

        <div style="margin-top: 15px; font-size: 13px;">
            <strong>Test Exploit Attempt:</strong> <code>' UNION SELECT id, username, plaintext_password, 0, role FROM users --</code>
            <p>Notice that SQL injection attempts return 0 results safely without executing unauthorized clauses.</p>
        </div>

        {f'<p style="margin-top:15px;"><strong>Remediation Implementation:</strong></p><pre><code>{executed_code}</code></pre>' if executed_code else ''}
        {results_table}
    </div>
    """
    return render_lab_page("Secure Search", content)


# =============================================================================
# 2. BROKEN AUTHENTICATION (OWASP A07:2021 - Identification & Auth Failures)
# =============================================================================

@app.route("/vulnerable/login", methods=["GET", "POST"])
def vuln_login():
    message = None
    msg_type = "danger"

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, plaintext_password, role FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        # VULNERABILITY 1: Username enumeration via differentiated error responses
        if not user:
            message = "Error: Username does not exist in our system."
        # VULNERABILITY 2: Plaintext password comparison
        elif user["plaintext_password"] != password:
            message = "Error: Invalid password entered for this user account."
        else:
            # VULNERABILITY 3: Predictable, unhardened custom session token without HttpOnly
            msg_type = "success"
            message = f"Authenticated successfully as {user['username']} ({user['role']})!"
            content = f"""
            <div class="card vuln-card">
                <h2><span class="badge badge-vuln">Vulnerable</span> Login Endpoint</h2>
                <div class="alert alert-{msg_type}">{message}</div>
                <p><a href="/">Return to Dashboard</a></p>
            </div>
            """
            resp = make_response(render_lab_page("Vulnerable Login", content))
            resp.set_cookie("insecure_user_token", f"user={user['username']}&role={user['role']}", httponly=False)
            session["user"] = user["username"]
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            return resp

    content = f"""
    <div class="card vuln-card">
        <h2><span class="badge badge-vuln">Vulnerable</span> Login Endpoint</h2>
        <p>Flaws demonstrated: Disclosing username existence (user enumeration), comparing credentials via plaintext strings, and issuing unencrypted, non-HttpOnly session cookies accessible to JavaScript.</p>

        {f'<div class="alert alert-{msg_type}">{message}</div>' if message else ''}

        <form method="POST" action="/vulnerable/login" style="max-width: 350px;">
            <div style="margin-bottom: 12px;">
                <label>Username:</label><br>
                <input type="text" name="username" style="width: 100%;" required>
            </div>
            <div style="margin-bottom: 15px;">
                <label>Password:</label><br>
                <input type="password" name="password" style="width: 100%;" required>
            </div>
            <button type="submit" class="btn-vuln">Login (Vulnerable)</button>
        </form>

        <div style="margin-top: 20px; font-size: 13px;">
            <strong>Lab Accounts:</strong><br>
            • <code>alice_admin</code> / <code>SuperAdminPass2026!</code><br>
            • <code>bob_user</code> / <code>BobPassword123!</code><br>
            <em>Try typing an invalid username vs invalid password to observe credential enumeration behavior.</em>
        </div>
    </div>
    """
    return render_lab_page("Vulnerable Login", content)


@app.route("/secure/login", methods=["GET", "POST"])
def secure_login():
    message = None
    msg_type = "danger"

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        # SECURE REMEDIATION 1: Timing-safe hash verification (PBKDF2-HMAC-SHA256)
        # SECURE REMEDIATION 2: Generic error message preventing username enumeration
        valid_creds = False
        if user and check_password_hash(user["password_hash"], password):
            valid_creds = True

        if not valid_creds:
            message = "Invalid username or password. Please verify credentials."
        else:
            # SECURE REMEDIATION 3: Session fixation prevention (regenerate session upon login)
            session.clear()
            session["user"] = user["username"]
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            session["anti_csrf_token"] = secrets.token_hex(16)
            msg_type = "success"
            message = f"Authenticated securely as {user['username']}! Session regenerated."

    content = f"""
    <div class="card safe-card">
        <h2><span class="badge badge-safe">Secure</span> Hardened Login Endpoint</h2>
        <p>Remediations applied: Salted PBKDF2 hash verification, constant error responses preventing account enumeration, session fixation mitigation via <code>session.clear()</code>, and hardened <code>HttpOnly</code> cookies.</p>

        {f'<div class="alert alert-{msg_type}">{message}</div>' if message else ''}

        <form method="POST" action="/secure/login" style="max-width: 350px;">
            <div style="margin-bottom: 12px;">
                <label>Username:</label><br>
                <input type="text" name="username" style="width: 100%;" required>
            </div>
            <div style="margin-bottom: 15px;">
                <label>Password:</label><br>
                <input type="password" name="password" style="width: 100%;" required>
            </div>
            <button type="submit">Login (Secure)</button>
        </form>

        <div style="margin-top: 20px; font-size: 13px;">
            <strong>Hardening Highlights:</strong><br>
            • Hashes stored via <code>werkzeug.security.generate_password_hash</code>.<br>
            • Identical error regardless of whether username or password is incorrect.<br>
            • Session identifier rotated upon successful privilege state transition.
        </div>
    </div>
    """
    return render_lab_page("Secure Login", content)


# =============================================================================
# 3. CROSS-SITE SCRIPTING (OWASP A03:2021 - Injection / XSS)
# =============================================================================

@app.route("/vulnerable/feedback", methods=["GET"])
def vuln_feedback():
    comment = request.args.get("comment", "")
    rendered_output = ""

    if comment:
        # VULNERABILITY: User input directly rendered without HTML escaping
        rendered_output = f"<div class='alert alert-info'>Your feedback submission: <strong>{comment}</strong></div>"

    content = f"""
    <div class="card vuln-card">
        <h2><span class="badge badge-vuln">Vulnerable</span> Customer Feedback (Reflected XSS)</h2>
        <p>This endpoint echoes untrusted user input directly back to the HTTP response document without contextual HTML entity encoding or Content-Security-Policy (CSP) headers.</p>

        <form method="GET" action="/vulnerable/feedback">
            <input type="text" name="comment" value="{html.escape(comment)}" placeholder="Submit your comments..." style="width: 350px;">
            <button type="submit" class="btn-vuln">Echo Feedback (Vulnerable)</button>
        </form>

        <div style="margin-top: 15px; font-size: 13px;">
            <strong>Test Payloads:</strong>
            <ul>
                <li>Benign feedback: <code>Great platform performance!</code></li>
                <li>Script execution: <code>&lt;script&gt;alert('XSS_POC_2026')&lt;/script&gt;</code></li>
                <li>Image DOM injection: <code>&lt;img src=x onerror="alert(document.cookie)"&gt;</code></li>
            </ul>
        </div>

        {f'<div style="margin-top: 20px;">{rendered_output}</div>' if rendered_output else ''}
    </div>
    """
    return render_lab_page("Vulnerable Feedback", content)


@app.route("/secure/feedback", methods=["GET"])
def secure_feedback():
    comment = request.args.get("comment", "")
    escaped_comment = ""

    if comment:
        # SECURE REMEDIATION 1: Contextual output encoding (HTML entity escaping)
        escaped_comment = html.escape(comment)

    content = f"""
    <div class="card safe-card">
        <h2><span class="badge badge-safe">Secure</span> Customer Feedback (HTML Sanitized + CSP)</h2>
        <p>Remediations applied: All dynamic data is encoded into harmless character entities (<code>&amp;lt;</code>, <code>&amp;gt;</code>, <code>&amp;quot;</code>), preventing execution by the browser's DOM parser.</p>

        <form method="GET" action="/secure/feedback">
            <input type="text" name="comment" value="{escaped_comment}" placeholder="Submit feedback securely..." style="width: 350px;">
            <button type="submit">Echo Feedback (Secure)</button>
        </form>

        <div style="margin-top: 15px; font-size: 13px;">
            <strong>Test Exploit Attempt:</strong> <code>&lt;script&gt;alert(1)&lt;/script&gt;</code>
            <p>Notice that tags are displayed literally as text rather than being parsed and executed as active scripts.</p>
        </div>

        {f'<div style="margin-top: 20px;"><div class="alert alert-success">Your feedback submission (safely encoded): <strong>{escaped_comment}</strong></div></div>' if escaped_comment else ''}
    </div>
    """
    resp = make_response(render_lab_page("Secure Feedback", content))
    # SECURE REMEDIATION 2: Defense-in-depth Content-Security-Policy (CSP) header
    resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


# =============================================================================
# 4. BROKEN ACCESS CONTROL (IDOR) (OWASP A01:2021 - Broken Access Control)
# =============================================================================

@app.route("/vulnerable/profile", methods=["GET"])
def vuln_profile():
    requested_id = request.args.get("user_id", "")
    profile_data = None
    error = None

    if requested_id:
        # VULNERABILITY: Insecure Direct Object Reference (IDOR)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT u.username, u.role, p.user_id, p.full_name, p.email, p.ssn_or_id, p.account_balance, p.api_secret_key
            FROM profiles p
            JOIN users u ON u.id = p.user_id
            WHERE p.user_id = ?
        """, (requested_id,))
        profile_data = cursor.fetchone()
        conn.close()

        if not profile_data:
            error = f"Profile record #{requested_id} not found."

    table_html = ""
    if profile_data:
        table_html = f"""
        <div class="card" style="margin-top: 20px; background: rgba(255,255,255,0.02);">
            <h3>Profile Record #{profile_data['user_id']} ({profile_data['username']})</h3>
            <table style="width: 100%;">
                <tr><th>Full Legal Name</th><td>{profile_data['full_name']}</td></tr>
                <tr><th>System Role</th><td><code>{profile_data['role']}</code></td></tr>
                <tr><th>Internal Email</th><td>{profile_data['email']}</td></tr>
                <tr><th>Identity ID / SSN</th><td><span style="color:#f85149; font-weight:bold;">{profile_data['ssn_or_id']}</span></td></tr>
                <tr><th>Account Balance</th><td>${profile_data['account_balance']:.2f}</td></tr>
                <tr><th>Production API Secret</th><td><code>{profile_data['api_secret_key']}</code></td></tr>
            </table>
        </div>
        """

    content = f"""
    <div class="card vuln-card">
        <h2><span class="badge badge-vuln">Vulnerable</span> User Profile Dossier (IDOR)</h2>
        <p>This endpoint looks up sensitive account PII using a client-controlled <code>user_id</code> URL parameter without inspecting user authentication or session ownership.</p>

        <form method="GET" action="/vulnerable/profile">
            <label>Query Profile by User ID:</label>
            <input type="number" name="user_id" value="{requested_id or 2}" style="width: 80px;">
            <button type="submit" class="btn-vuln">Fetch Profile (Vulnerable)</button>
        </form>

        <div style="margin-top: 15px; font-size: 13px;">
            <strong>Horizontal / Vertical Privilege Escalation Vectors:</strong><br>
            • Standard user profile: <code>?user_id=2</code> (Bob)<br>
            • Lateral user profile: <code>?user_id=3</code> (Charlie)<br>
            • Unauthorized Admin PII / Financial Dossier: <code>?user_id=1</code> (Alice - CISO)<br>
            <em>Any unauthenticated guest can view anyone's API key, balance, and PII by changing the integer parameter!</em>
        </div>

        {f'<div class="alert alert-danger" style="margin-top: 15px;">{error}</div>' if error else ''}
        {table_html}
    </div>
    """
    return render_lab_page("Vulnerable Profile", content)


@app.route("/secure/profile", methods=["GET"])
def secure_profile():
    # SECURE REMEDIATION:
    # 1. Require active authenticated session
    # 2. Derive object identity strictly from server-side session ('user_id'), NEVER from client URL query params!
    
    if "user_id" not in session:
        content = """
        <div class="card safe-card">
            <h2><span class="badge badge-safe">Secure</span> Protected Profile Dossier (RBAC Enforced)</h2>
            <div class="alert alert-danger">
                <strong>Access Denied (HTTP 401 Unauthorized):</strong> You must be authenticated to view profile records.
            </div>
            <p>Please log in through the <a href="/secure/login">Secure Login Portal</a> first.</p>
        </div>
        """
        return render_lab_page("Unauthorized", content), 401

    logged_user_id = session["user_id"]
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.username, u.role, p.user_id, p.full_name, p.email, p.ssn_or_id, p.account_balance, p.api_secret_key
        FROM profiles p
        JOIN users u ON u.id = p.user_id
        WHERE p.user_id = ?
    """, (logged_user_id,))
    profile_data = cursor.fetchone()
    conn.close()

    table_html = ""
    if profile_data:
        table_html = f"""
        <div class="card" style="margin-top: 15px;">
            <h3>Your Authenticated Profile</h3>
            <table>
                <tr><th>Full Legal Name</th><td>{profile_data['full_name']}</td></tr>
                <tr><th>System Role</th><td><code>{profile_data['role']}</code></td></tr>
                <tr><th>Email Address</th><td>{profile_data['email']}</td></tr>
                <tr><th>Identity ID / SSN</th><td>{profile_data['ssn_or_id']}</td></tr>
                <tr><th>Account Balance</th><td>${profile_data['account_balance']:.2f}</td></tr>
                <tr><th>Production API Secret</th><td><code>{profile_data['api_secret_key']}</code></td></tr>
            </table>
        </div>
        """

    content = f"""
    <div class="card safe-card">
        <h2><span class="badge badge-safe">Secure</span> Protected Profile Dossier (Access Control Enforced)</h2>
        <div class="alert alert-success">
            <strong>Access Granted:</strong> Verified authenticated session for <code>{session['user']}</code> (User ID: <code>{session['user_id']}</code>, Role: <code>{session['role']}</code>).
        </div>
        <p>Object identity is bound directly to server-side session state. An attacker cannot manipulate URL parameters to inspect records belonging to other users.</p>

        {table_html}
    </div>
    """
    return render_lab_page("Secure Profile", content)


# =============================================================================
# Main Entry Point
# =============================================================================
if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        print(f"[*] Initializing SQLite database at {DB_PATH}...")
        init_db()
        print("[+] Seed database populated successfully.")

    print("\n" + "=" * 60)
    print(" Codomax Web Application Security Lab - Module 03")
    print(" Intern: Ayan Mondal (CDS/INT/2026/26637504)")
    print(" Server running locally at: http://127.0.0.1:5000")
    print("=" * 60 + "\n")

    app.run(host="127.0.0.1", port=5000, debug=True)
