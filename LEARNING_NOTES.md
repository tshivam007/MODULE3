# 📘 Codomax Cybersecurity Internship: Learning Notes
## Module 03: Web Application Security (Day 11 – Day 15)

**Intern Name:** Ayan Mondal  
**Intern ID:** CDS/INT/2026/26637504  
**Program:** Cybersecurity & Ethical Hacking Virtual Internship  
**Organization:** Codomax Digital Solutions  
**Date of Completion:** November 2026  

---

## 📑 Table of Contents
1. [Web Application Architecture & The HTTP Protocol](#1-web-application-architecture--the-http-protocol)
2. [State Management, Cookies & Session Lifecycles](#2-state-management-cookies--session-lifecycles)
3. [Authentication vs. Authorization Mechanics](#3-authentication-vs-authorization-mechanics)
4. [OWASP Top 10 Vulnerability Deep-Dive](#4-owasp-top-10-vulnerability-deep-dive)
5. [Secure Coding & Defensive Engineering Principles](#5-secure-coding--defensive-engineering-principles)
6. [Summary Checklist & Best Practices](#6-summary-checklist--best-practices)

---

## 1. Web Application Architecture & The HTTP Protocol

### 1.1 The Client-Server Model
Web applications operate on a distributed request-response paradigm governed by the **Hypertext Transfer Protocol (HTTP)** at the Application Layer (Layer 7 of the OSI Model). 

```text
+----------------+          HTTP Request (Verb, Path, Headers, Body)          +-------------------+
|                | ---------------------------------------------------------> |                   |
|  User Browser  |                                                            |   Web / App       |
|    (Client)    | <--------------------------------------------------------- |     Server        |
+----------------+          HTTP Response (Status Code, Headers, HTML/JSON)   +-------------------+
                                                                                        |
                                                                                        v
                                                                              +-------------------+
                                                                              |  Database / Cache |
                                                                              +-------------------+
```

1. **Client Request Initiation:** The browser resolves the domain via DNS, establishes a TCP three-way handshake (`SYN` -> `SYN-ACK` -> `ACK`), negotiates TLS encryption (HTTPS), and dispatches an HTTP request.
2. **Server Processing:** The reverse proxy / web server parses incoming headers, enforces route handlers, authenticates session tokens, queries persistent storage, and generates a formatted payload.
3. **Response Rendering:** The browser receives the response code and payload, parses HTML/CSS/JavaScript, constructs the Document Object Model (DOM), and renders the graphical interface.

### 1.2 Anatomical Breakdown of HTTP Transactions

#### HTTP Request Format
An HTTP request consists of a Request Line, Request Headers, an Empty Line delimiter (`\r\n`), and an optional Request Body:
```http
POST /api/v1/auth/login HTTP/1.1
Host: portal.codomax-labs.internal
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Content-Type: application/json
Content-Length: 54
Origin: https://portal.codomax-labs.internal
Connection: keep-alive

{"username": "bob_jenkins", "password": "TargetPass2026!"}
```

#### HTTP Response Format
```http
HTTP/1.1 200 OK
Date: Thu, 19 Nov 2026 12:00:00 GMT
Server: nginx/1.24.0
Content-Type: application/json; charset=UTF-8
Content-Length: 62
Set-Cookie: session_id=f48b9...; Path=/; Secure; HttpOnly; SameSite=Strict
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload

{"status": "success", "message": "Authentication approved."}
```

### 1.3 HTTP Methods & Semantic Security
| HTTP Method | Idempotent | Safe | Typical Use Case | Security Implications |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | Yes | Yes | Retrieving resources | Must **never** mutate state or include sensitive credentials in query parameters (URLs appear in server access logs and browser histories). |
| `POST` | No | No | Submitting data, creating records | Susceptible to Cross-Site Request Forgery (CSRF) unless validated via anti-CSRF tokens or `SameSite` flags. |
| `PUT` | Yes | No | Completely replacing a resource | Requires strict authorization checks to prevent unauthorized overwrites. |
| `PATCH` | No | No | Partial update of a resource | Prone to Mass Assignment vulnerabilities if object bindings are not strictly restricted. |
| `DELETE` | Yes | No | Removing a resource | Must verify server-side ownership before unlinking records. |
| `OPTIONS` | Yes | Yes | Querying permitted methods | Used by Cross-Origin Resource Sharing (CORS) preflight requests. |

### 1.4 HTTP Status Codes Reference
- **`2xx` Success:** `200 OK` (Standard success), `201 Created` (Resource created), `204 No Content` (Action completed without body).
- **`3xx` Redirection:** `301 Moved Permanently` (Cached redirect), `302 Found` (Temporary redirect).
- **`4xx` Client Error:** 
  - `400 Bad Request` (Malformed syntax)
  - `401 Unauthorized` (Lacks valid authentication credentials)
  - `403 Forbidden` (Authenticated identity lacks authorization permission)
  - `404 Not Found` (Resource does not exist)
  - `405 Method Not Allowed` (HTTP verb not permitted for route)
  - `429 Too Many Requests` (Rate limit exceeded)
- **`5xx` Server Error:** `500 Internal Server Error`, `502 Bad Gateway`, `503 Service Unavailable`.

---

## 2. State Management, Cookies & Session Lifecycles

### 2.1 The Stateless Nature of HTTP
HTTP is fundamentally stateless: each request operates independently, with no inherent memory of previous interactions. To build continuous interactive experiences (such as authenticated account portals or shopping carts), state must be maintained out-of-band using **Session Identifiers** passed between client and server.

### 2.2 Cookies & Protective Security Attributes
A cookie is a small key-value pair stored by the client browser upon receiving a `Set-Cookie` header from the server. To protect session integrity against client-side exploitation, three critical cookie flags must be applied:

| Cookie Attribute | Directive Value | Security Purpose & Defense Mechanism |
| :--- | :--- | :--- |
| **`HttpOnly`** | Flag present | Instructs the browser that the cookie **cannot** be accessed via client-side scripts (e.g., `document.cookie`). This provides crucial mitigation against session hijacking via Cross-Site Scripting (XSS). |
| **`Secure`** | Flag present | Guarantees that the cookie is transmitted **strictly over encrypted TLS connections (HTTPS)**. Prevents plaintext credential leakage over untrusted or intercepted networks (Wi-Fi sniffing, MITM). |
| **`SameSite`** | `Strict` | The cookie is **never** dispatched on cross-site requests (e.g., following an external link or iframe). Provides the highest defense against CSRF. |
| **`SameSite`** | `Lax` | The cookie is withheld on cross-site subrequests (images, frames, `POST` forms), but is sent when navigating top-level safe links (`GET`). Balanced default. |
| **`SameSite`** | `None` | The cookie is sent on all cross-site requests. Requires the `Secure` flag to be set simultaneously. |

```http
Set-Cookie: app_session=9a8d4f0...e42; Path=/; Domain=codomax.internal; Secure; HttpOnly; SameSite=Strict; Max-Age=3600
```

### 2.3 Session Management Lifecycle
```mermaid
sequenceDiagram
    autonumber
    actor User as User Browser
    participant Server as Application Server
    participant DB as Session Store / DB

    User->>Server: POST /login (Username & Password)
    Server->>DB: Validate credentials (PBKDF2/Argon2)
    DB-->>Server: Credentials Valid
    Server->>Server: Invalidate old session & generate cryptographically random Session ID
    Server->>DB: Store Session ID with user_id, timestamp, expiry
    Server-->>User: Set-Cookie: session_id=SECURE_RANDOM; HttpOnly; Secure; SameSite=Strict
    Note over User,Server: Subsequent Authenticated Requests
    User->>Server: GET /dashboard (Cookie: session_id=SECURE_RANDOM)
    Server->>DB: Validate Session ID
    DB-->>Server: Session Active & Valid
    Server-->>User: HTTP 200 OK (Render Dashboard)
```

### 2.4 Session Security Vulnerabilities
1. **Session Hijacking:** An attacker steals an active session token (via XSS, sniffing unencrypted traffic, or server log leakage) and impersonates the legitimate user.
2. **Session Fixation:** An attacker sets a known session identifier in the victim's browser prior to authentication. If the application fails to issue a **new session identifier upon login**, the attacker uses the fixed token to gain authenticated access.
   - *Mitigation:* Explicitly invalidate and regenerate session tokens immediately upon any privilege transition (login, password change, role elevation).
3. **Insufficient Session Expiration:** Sessions that linger indefinitely permit prolonged attack windows.
   - *Mitigation:* Implement both **Idle Timeout** (e.g., invalidate after 15–30 minutes of inactivity) and **Absolute Timeout** (e.g., invalidate after 8–12 hours regardless of activity).

---

## 3. Authentication vs. Authorization Mechanics

Understanding the operational boundary between Authentication and Authorization is fundamental to web application security:

| Dimension | Authentication (AuthN) | Authorization (AuthZ) |
| :--- | :--- | :--- |
| **Fundamental Question** | *"Who are you?"* | *"What are you permitted to do?"* |
| **Core Function** | Identity verification | Access permission evaluation |
| **Common Mechanisms** | Passwords, MFA tokens, Biometrics, Passkeys | Access Control Lists (ACLs), RBAC, ABAC |
| **Standard HTTP Response** | `401 Unauthorized` (Unauthenticated) | `403 Forbidden` (Authenticated, but denied) |
| **Failure Mode** | Credential stuffing, brute force, bypass | IDOR, horizontal/vertical privilege escalation |

```text
+---------------------+      Verify Credentials      +-------------------------+
| Unidentified Entity | ---------------------------> |  Authentication Engine  |
+---------------------+                              +-------------------------+
                                                                  |
                                                       Issues Identity Claims
                                                                  v
+---------------------+       Evaluate Permissions   +-------------------------+
| Authenticated User  | ---------------------------> |  Authorization Engine   |
+---------------------+                              +-------------------------+
                                                                  |
                                                          Permit / Deny
                                                                  v
                                                     [Target Protected Resource]
```

### 3.1 Authorization Models
1. **Role-Based Access Control (RBAC):** Permissions are assigned to predefined static roles (e.g., `User`, `Moderator`, `Admin`). Users are mapped to roles.
2. **Attribute-Based Access Control (ABAC):** Granular access decisions evaluate attributes of the subject (user department, clearance), object (document sensitivity), action (`read`, `write`), and environment (time of day, client IP, location).

### 3.2 Privilege Escalation Vectors
- **Vertical Privilege Escalation:** A low-privileged user accesses functions reserved for higher-privileged tiers (e.g., a standard employee executing an administrator's user deletion endpoint: `POST /admin/delete_user`).
- **Horizontal Privilege Escalation:** A user accesses private data or actions belonging to a peer of identical privilege rank (e.g., User A accessing User B's billing invoice by tampering with an ID: `GET /invoices?id=1004`).

---

## 4. OWASP Top 10 Vulnerability Deep-Dive

The Open Web Application Security Project (OWASP) Top 10 documents the most critical security risks facing modern web architectures.

### 4.1 A01:2021 — Broken Access Control
- **Core Concept:** Flaws occurring when an application fails to properly enforce restrictions on what authenticated users are allowed to do. Ranked #1 because it represents over 94% of audited applications.
- **Classic Sub-Types:**
  - **Insecure Direct Object References (IDOR):** The server accepts an untrusted user-supplied identifier (e.g., integer ID, filename) to access an internal record directly without validating ownership.
  - **Missing Function Level Access Control:** Administrative UI elements are hidden in CSS/JS, but backend API endpoints lack server-side role validation.
  - **CORS Misconfiguration:** Overly permissive headers (`Access-Control-Allow-Origin: *` with credentials) enabling cross-origin data theft.

### 4.2 A02:2021 — Cryptographic Failures
- **Core Concept:** Inadequate protection of sensitive data in transit or at rest.
- **Common Vulnerabilities:**
  - Storing passwords in plaintext or using obsolete collision-vulnerable hash functions (MD5, SHA-1).
  - Transmitting sensitive traffic over plaintext HTTP rather than enforcing TLS 1.3 with HSTS (`Strict-Transport-Security`).
  - Hardcoded encryption keys or insufficient cryptographic pseudo-random number generator (PRNG) entropy.

### 4.3 A03:2021 — Injection
- **Core Concept:** Untrusted, unsanitized user data is concatenated directly into command or query interpreters, altering the programmatic execution logic.
- **SQL Injection (SQLi):**
  - *Mechanism:* Bypassing string literals to inject SQL syntax.
  - *Attack Examples:*
    - Boolean bypass: `SELECT * FROM users WHERE user='' OR '1'='1' AND pass='...'`
    - UNION-based extraction: `' UNION SELECT null, username, password FROM users --`
  - *Remediation:* Enforce Parameterized Queries (Prepared Statements) or Object Relational Mappers (ORMs) with typed parameter bindings.
- **Cross-Site Scripting (XSS):**
  - *Reflected XSS:* Untrusted input from a request (search box, URL parameter) is mirrored immediately into the HTTP response body without contextual encoding.
  - *Stored XSS:* Malicious payload is permanently saved in the database (comment section, user profile name) and served to every visiting user.
  - *DOM-based XSS:* Client-side JavaScript reads data from an untrusted source (e.g., `location.hash`) and writes it insecurely to an execution sink (e.g., `innerHTML`, `eval()`).

### 4.4 A07:2021 — Identification and Authentication Failures
- **Core Concept:** Weaknesses in verifying a user's identity or maintaining session boundaries.
- **Common Weaknesses:**
  - Permitting weak passwords without complexity, length, or credential stuffing checks.
  - Vulnerability to automated brute force due to missing rate limiting, CAPTCHA, or lockout mechanisms.
  - Username enumeration through differing error responses (`"Username not found"` vs. `"Incorrect password"`).
  - Failure to rotate session identifiers upon successful authentication.

### 4.5 Emerging Threats: CSRF & SSRF
- **Cross-Site Request Forgery (CSRF):** Tricking a victim's authenticated browser into executing unwanted actions on a trusted web application. Defended via synchronized anti-CSRF tokens and `SameSite=Strict/Lax` cookie attributes.
- **Server-Side Request Forgery (SSRF):** Exploiting an application that fetches remote resources (e.g., webhook testing, profile avatar import) to coerce the backend server into initiating unauthorized requests to internal network services (e.g., AWS Metadata `http://169.254.169.254/`).

---

## 5. Secure Coding & Defensive Engineering Principles

Securing web applications requires a defense-in-depth engineering strategy implemented at every layer of the software development lifecycle:

```text
+-------------------------------------------------------------------------+
|                           DEFENSE-IN-DEPTH                              |
+-------------------------------------------------------------------------+
| 1. Perimeter / Transport : TLS 1.3, HSTS, WAF, Rate Limiting            |
| 2. Client Security       : CSP, X-Frame-Options, HttpOnly, SameSite     |
| 3. Application Gateway   : Input Validation (Strict Allow-lists)         |
| 4. Business Logic        : State-Verified Authentication & RBAC Checks   |
| 5. Presentation Layer    : Contextual HTML/JS/CSS Output Encoding       |
| 6. Data Access Layer     : Parameterized Queries (Prepared Statements)   |
| 7. Persistent Storage    : Argon2id Hashing, Encryption-at-Rest         |
+-------------------------------------------------------------------------+
```

### 5.1 Input Validation vs. Output Encoding
- **Input Validation (Allow-Listing):** Verify that input conforms strictly to expected formats, character sets, and lengths *before* processing. Reject or sanitize unexpected characters.
- **Output Encoding:** Transform untrusted characters into safe, inert visual representations *immediately before* rendering into the target document context:
  - HTML Context: `<` becomes `&lt;`, `>` becomes `&gt;`, `&` becomes `&amp;`
  - Attribute Context: `"` becomes `&quot;`, `'` becomes `&#x27;`
  - JavaScript Context: Unicode escape sequences (`\u0022`)

### 5.2 Parameterized Database Queries
Never construct SQL statements using raw string concatenation:
```python
# ❌ VULNERABLE: Direct string interpolation allows query structure hijacking
query = f"SELECT * FROM accounts WHERE account_id = '{user_input}'"
cursor.execute(query)

# ✅ SECURE: Database engine treats input purely as literal scalar values
query = "SELECT * FROM accounts WHERE account_id = ?"
cursor.execute(query, (user_input,))
```

### 5.3 Modern Password Hashing Standards
Plain hashes (MD5, SHA-256) are calculated rapidly on modern GPUs, enabling billions of guesses per second. Production architectures must use adaptive, salted, memory-hard algorithms:
- **Argon2id:** Winner of the Password Hashing Competition; resistant to GPU and side-channel attacks.
- **PBKDF2-HMAC-SHA256:** NIST-approved key derivation function with high iteration counts (minimum 600,000 rounds).
- **bcrypt:** Time-tested adaptive hashing function utilizing Blowfish key scheduling.

---

## 6. Summary Checklist & Best Practices

| Security Domain | Mandatory Implementation Standards |
| :--- | :--- |
| **Transport Security** | Enforce HTTPS everywhere; enable `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`. |
| **Cookies** | Set `HttpOnly`, `Secure`, and `SameSite=Lax` or `Strict` on all authentication and session tokens. |
| **Session Control** | Regenerate session identifiers on login; enforce 15-minute idle timeouts; clear cookies on logout. |
| **Access Control** | Enforce authorization checks on the server; bind record queries strictly to `session['user_id']`. |
| **SQL Queries** | Mandate prepared statements / parameterized bindings across 100% of database interactions. |
| **XSS Prevention** | Use framework auto-escaping (Jinja2, React, Angular); implement a strict `Content-Security-Policy`. |
| **Error Handling** | Return uniform error messages; disable debug banners and stack trace displays in production. |
| **Audit Logging** | Record timestamped security events (logins, failures, permission denials) without logging credentials. |

---
*Created as part of the Codomax Digital Solutions Cybersecurity Virtual Internship.*
