# Web Server Attacks — I

## What This Room Is About

Reconnaissance and misconfiguration identification against four web server types commonly found on Linux infrastructure: Apache2, Python's built-in HTTP Server, Node.js Express, and Nginx. The goal is fingerprinting servers and finding what they expose before any active exploitation begins.

---

## Tools Used

- `curl` — header inspection and response body retrieval
- `gobuster` — directory and file brute-forcing
- `nikto` — automated misconfiguration scanner
- Browser DevTools (Network tab) — header inspection via GUI

---

## What I Learned

### Identifying Web Servers

Before touching any inputs or running scanners, identify what server you're dealing with — it determines which misconfigurations are likely and which paths are worth checking.

```bash
curl -sI http://TARGET_IP:PORT
```

The `Server` response header is the primary fingerprint:

| Port | Server |
|------|--------|
| 80   | Apache2 |
| 8000 | Python HTTP Server |
| 3000 | Node.js Express |
| 8080 | Nginx |

**Key insight:** Express sets no `Server` header. Its identifier is `X-Powered-By: Express`. A missing `Server` header on port 3000 is itself a signal — always check for `X-Powered-By` when `Server` is absent.

If headers are suppressed, trigger a 404 with a fake path and read the error page body — each server has a distinctive default error page format.

---

### Python HTTP Server

Started with `python3 -m http.server`, often left running by developers for file-sharing convenience.

**Key findings:**

- Serves the **entire working directory** — no access control, no blocklist, no auth
- No `index.html` → auto-generates a directory listing of every file
- Dotfiles (`.env`) are fully accessible despite being hidden in normal navigation
- Archives (`.zip`, `.tar.gz`) in the directory can be downloaded and may contain source code, DB dumps, or credentials
- **No exploitation needed** — this is a misconfiguration, not a vulnerability

**What to do when you find it:** Download everything visible. Prioritize `.env`, config files, and any archives.

---

### Apache2

Most widely deployed web server. Default Ubuntu config leaves several things exposed.

**Version disclosure:** `Server: Apache/2.4.49` in the response header reveals the exact version for CVE lookup.

**Directory listing:** When `Options +Indexes` is enabled and no `index.html` exists, Apache returns a file listing. Always browse paths like `/files/` and read every file — CSV exports, notes, and backups often appear here.

**`mod_status` page:** Accessible at `/server-status`. When misconfigured with `Require all granted`, it exposes:
- Active connections and what paths they're requesting
- Total requests since server start
- Worker states (idle, writing, reading)
- Exact server version

This leaks real-time information about other users and internal paths.

**Finding unlinked files with Gobuster:**

```bash
gobuster dir -u http://TARGET_IP:80 -w /usr/share/wordlists/dirb/common.txt
```

Files that don't appear in listings but sit in the document root: `.bak` backup files (contain credentials, configs, source code), `.htpasswd` files (hashed credentials, crackable offline).

**Checklist for Apache:**
1. Check version header
2. Browse directories with listing enabled
3. Visit `/server-status`
4. Run Gobuster for unlinked files

---

### Node.js Express

Not a file server — it runs application code that decides what to return for every request. The risk here is development-mode features left enabled in production.

**Fingerprinting:** `X-Powered-By: Express` in response headers. Root path often returns a JSON status:

```json
{"status":"ok","app":"company-portal","version":"1.2.0"}
```

**Verbose errors:** Custom error handlers often expose stack traces regardless of `NODE_ENV`. A `500` from an API endpoint can leak internal file paths, module names, and database queries.

**Debug route enumeration:** Some Express apps have a debug endpoint listing all registered routes:

```bash
curl -s http://TARGET_IP:3000/api/routes
```

If it exists, you get a full map of every path the application handles.

**Exposed environment variables:** A debug endpoint returning `process.env` may expose `DB_PASSWORD`, `SECRET_KEY`, `API_KEY`. `NODE_ENV=development` on a production server is a sign the app was never hardened.

**Static file serving:** `express.static()` middleware serves front-end assets. Client-side JS files sometimes contain embedded API endpoints, internal hostnames, or debug flags.

---

### Nginx

Most commonly used as a reverse proxy or load balancer, sitting in front of an application server.

**Version disclosure:** `Server: nginx/1.24.0` in headers, also in the 404 error page body. Controlled by `server_tokens` directive (default: on).

**Directory listing (autoindex):** Not enabled by default — requires explicit config:

```nginx
location /files/ {
    autoindex on;
}
```

Finding this means a developer intentionally configured it and may have left sensitive files inside.

**`/nginx_status` endpoint:** Exposed by `stub_status` module when misconfigured with `allow all`. Returns:
- Total accepted/handled connections
- Total requests since server start
- Current active connection states (reading, writing, waiting)

---

### Common Misconfigurations Across All Servers

**Missing security headers** — none of the four servers send these by default:
- `X-Frame-Options` — clickjacking protection
- `X-Content-Type-Options` — MIME sniffing protection
- `Content-Security-Policy` — XSS protection

**Automated scanning with Nikto:**

```bash
nikto -h http://TARGET_IP:80 -nointeractive
```

Nikto checks hundreds of paths and patterns. On a misconfigured Apache server it will flag: exposed `/server-status`, backup files, directory listing, and missing headers. Note: Nikto is loud — not suitable for stealth engagements.

---

## Key Commands

```bash
# Fingerprint server via headers
curl -sI http://TARGET_IP:PORT

# GET request to trigger error page body
curl -s http://TARGET_IP:PORT/nonexistent-path

# Directory/file brute-force
gobuster dir -u http://TARGET_IP:80 -w /path/to/wordlist.txt

# Automated misconfiguration scan
nikto -h http://TARGET_IP:80 -nointeractive
```

---

## Key Takeaway

Reconnaissance isn't just scanning — it's reading what the server tells you. Every server type leaks differently: Apache through headers and status pages, Python through serving everything, Express through debug endpoints left in production, Nginx through autoindex and stub_status. The skill is knowing where each one talks and listening before you do anything else.

Misconfigurations are often more valuable than exploits — they require no CVE, no payload, and leave less noise in logs.

---
