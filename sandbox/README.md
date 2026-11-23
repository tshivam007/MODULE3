# 🧪 Codomax Module 03: Secure Web Application Sandbox

**Author:** Ayan Mondal  
**Intern ID:** CDS/INT/2026/26637504  
**Track:** Cybersecurity & Ethical Hacking  
**Module:** Module 03 — Web Application Security (Day 11 – Day 15)  

---

## 📌 Sandbox Purpose & Scope

This sandbox is a self-contained, lightweight Python Flask laboratory created to satisfy the **Identify -> Test -> Fix -> Document** hands-on requirement of Module 03. It contrasts four primary OWASP Top 10 vulnerability categories side-by-side:

| Lab Module | OWASP Top 10 Category | Vulnerable Endpoint (`/vulnerable/...`) | Hardened Endpoint (`/secure/...`) |
| :--- | :--- | :--- | :--- |
| **Lab 1** | **A03:2021 — Injection** | Raw SQL string interpolation (`/vulnerable/search`) | Prepared statement parameterization (`/secure/search`) |
| **Lab 2** | **A07:2021 — Identification & Auth** | Disclosing error enumeration & plaintext check (`/vulnerable/login`) | Constant error response & PBKDF2 hash check (`/secure/login`) |
| **Lab 3** | **A03:2021 — Injection (XSS)** | Unsanitized reflection without escaping (`/vulnerable/feedback`) | Contextual HTML entity encoding & CSP headers (`/secure/feedback`) |
| **Lab 4** | **A01:2021 — Broken Access Control** | URL-based parameter tampering IDOR (`/vulnerable/profile?user_id=1`) | Session-bound identity & RBAC validation (`/secure/profile`) |

> [!NOTE]
> All endpoints execute strictly on the local loopback interface (`127.0.0.1:5000`) and interact with a local isolated SQLite database (`lab.db`). No external network requests or internet-facing servers are involved.

---

## 🚀 Quickstart Guide

### 1. Prerequisites
- Python 3.9+ (Python 3.10, 3.11, 3.12, 3.13, 3.14 supported)
- Virtual environment (recommended)

### 2. Install Dependencies
```bash
# Navigate to the sandbox directory
cd sandbox

# Install required packages
pip install -r requirements.txt
```

### 3. Run Automated Vulnerability Verification Suite
Before starting the web UI, you can run the non-interactive automated test suite to verify that all 4 vulnerability and remediation patterns behave as expected:
```bash
python verify_lab.py
```
*Expected Output:*
```
[+] TEST 1: SQL Injection Analysis (Search Endpoint)
  [!] /vulnerable/search: EXPLOITABLE! Leaked database credentials via UNION injection.
  [✓] /secure/search: PROTECTED! Parameterized query sanitized exploit attempt.

[+] TEST 2: Authentication Failures & Account Enumeration
  [!] /vulnerable/login: EXPLOITABLE! Differentiated error reveals valid usernames.
  [✓] /secure/login: PROTECTED! Uniform error message prevents username harvesting.

[+] TEST 3: Reflected Cross-Site Scripting (XSS)
  [!] /vulnerable/feedback: EXPLOITABLE! Raw script tags reflected without HTML escaping.
  [✓] /secure/feedback: PROTECTED! Characters entity-encoded & CSP header enforced.

[+] TEST 4: Broken Access Control (Insecure Direct Object Reference - IDOR)
  [!] /vulnerable/profile: EXPLOITABLE! IDOR allows unauthorized access to Admin PII & API Secret.
  [✓] /secure/profile: PROTECTED! Unauthorized access returned 401; session isolates user records.
```

### 4. Launch the Interactive Web Application
```bash
python app.py
```
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 🔬 Interactive Hands-On Testing Matrix

### Exercise 1: SQL Injection
1. Navigate to `http://127.0.0.1:5000/vulnerable/search`.
2. Input payload:
   ```sql
   ' UNION SELECT id, username, plaintext_password, 0, role FROM users --
   ```
3. Observe how the application leaks administrative credentials (`alice_admin`, `SuperAdminPass2026!`).
4. Repeat the exact payload at `http://127.0.0.1:5000/secure/search`.
5. Observe that the parameterized query treats the entire injection payload as literal string data, yielding zero results without database errors.

### Exercise 2: Authentication Failures & Account Harvesting
1. Navigate to `http://127.0.0.1:5000/vulnerable/login`.
2. Submit `username=nonexistent_user` with any password. Notice error: `"Error: Username does not exist in our system."`
3. Submit `username=alice_admin` with password `wrongpassword`. Notice error: `"Error: Invalid password entered for this user account."`
4. The error difference allows an adversary to enumerate valid usernames.
5. Navigate to `http://127.0.0.1:5000/secure/login`.
6. Submit invalid usernames vs valid usernames with wrong passwords. Both consistently return: `"Invalid username or password. Please verify credentials."`

### Exercise 3: Reflected Cross-Site Scripting (XSS)
1. Navigate to `http://127.0.0.1:5000/vulnerable/feedback`.
2. Submit payload:
   ```html
   <script>alert('XSS-Exploited-Module03')</script>
   ```
3. Observe the JavaScript alert popup execute in your browser DOM.
4. Navigate to `http://127.0.0.1:5000/secure/feedback` and submit the same payload.
5. Observe that the payload renders harmlessly as sanitized text entities (`&lt;script&gt;`), and inspect Developer Tools (Network tab) to see the `Content-Security-Policy: default-src 'self'` header.

### Exercise 4: Broken Access Control (IDOR)
1. Navigate to `http://127.0.0.1:5000/vulnerable/profile?user_id=2` to view user Bob Jenkins.
2. In the URL bar, tamper with the parameter to `?user_id=1`.
3. Notice that without logging in, you can directly view CISO Alice Montgomery's PII, account balance ($95,000.00), and sensitive API secret (`sec_live_998811aliceAdminSecret`).
4. Navigate to `http://127.0.0.1:5000/secure/profile`.
5. Access is strictly denied with `HTTP 401 Unauthorized`. Once logged in as Bob via `/secure/login`, Bob can only see his own record derived from `session['user_id']`.

---

## 🎥 Recording the Demo Walkthrough Video

For the Module 03 video walkthrough submission:
1. **Tooling:** Use OBS Studio, Windows Game Bar (`Win + G`), or ShareX.
2. **Setup:** Open `http://127.0.0.1:5000` on the left half of your screen and terminal running `verify_lab.py` or code on the right half.
3. **Pacing (3-5 minutes):**
   - **Minute 1:** Introduce yourself (Ayan Mondal, Intern ID CDS/INT/2026/26637504) and the internship module goal.
   - **Minute 2:** Demonstrate SQL Injection and Reflected XSS exploits vs. their secure remediations.
   - **Minute 3:** Demonstrate Account Enumeration and IDOR privilege escalation vs. session authorization.
   - **Minute 4:** Run `verify_lab.py` showing all 4 tests passing in the terminal.
   - **Minute 5:** Conclude with the secure coding takeaways (prepared statements, contextual encoding, RBAC, least privilege).
