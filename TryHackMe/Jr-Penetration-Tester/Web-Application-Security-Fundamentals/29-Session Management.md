# Session Management

## What This Room Is About

How web applications manage sessions across the full lifecycle — creation,
tracking, expiry, and termination — and where vulnerabilities appear at
each stage.

---

## What I Learned

### What is a Session

HTTP is stateless — every request is independent. Sessions solve this by
assigning a value to the user that is submitted with each request, letting
the server track who you are and what you're allowed to do without
re-authenticating every time.

**Session lifecycle:**
1. **Creation** — session assigned on first visit, before login
2. **Tracking** — session value submitted with every request
3. **Expiry** — session invalidated after a set lifetime
4. **Termination** — session invalidated on logout

---

### Authentication vs Authorization

| Concept | What it does |
|---------|-------------|
| Identification | User claims an identity (username) |
| Authentication | User proves the identity (password) |
| Authorization | Server checks what the identity is allowed to do |
| Accountability | Actions are logged and tied to the session |

Session management connects all four. A flaw in any one of them is an
authentication or authorization vulnerability.

---

### Cookies vs Tokens

**Cookie-based sessions (old-school)**
- Server sends `Set-Cookie` header, browser stores and auto-attaches it
to every request
- Browser enforces attributes: `Secure`, `HTTPOnly`, `SameSite`, `Expire`
- Vulnerable to CSRF — browser sends cookie automatically, even on
cross-site requests

**Token-based sessions (modern)**
- Server returns token in response body after login
- JavaScript stores it in LocalStorage and manually attaches it as
`Authorization: Bearer <token>` on each request
- Not vulnerable to CSRF — other domains can't read LocalStorage
- No automatic browser protections — token security is the app's
responsibility

**Simple rule:**
- Cookies = browser manages the session
- Tokens = JavaScript manages the session

---

### Vulnerabilities at Each Stage

#### Session Creation

**Weak session values** — predictable or guessable session IDs. A common
example: base64-encoding the username as the session value. If the
pattern is reversed, an attacker generates valid sessions for any account.

**Controllable session values** — JWTs contain all information needed to
create and verify themselves. If signature verification isn't enforced,
an attacker generates their own valid token.

**Session fixation** — applications that create a session before login
are vulnerable if the session value isn't rotated after authentication.
An attacker records the pre-auth session, waits for the victim to log in,
and inherits the authenticated session.

**Insecure session transmission** — in SSO flows, session material passes
through the browser between servers. An open redirect at this point lets
an attacker control where the session is delivered.

#### Session Tracking

**Vertical bypass** — performing an action reserved for a more privileged
user (e.g. accessing admin functions as a regular user).

**Horizontal bypass** — performing an allowed action on data belonging to
a different user (e.g. viewing another user's order).

Both happen when the server doesn't properly check what the session is
actually authorized to do.

#### Session Expiry

Single vulnerability: expiry time is too long. Sessions should be scoped
to the application's use case. A banking app needs a shorter session
lifetime than a webmail client.

#### Session Termination

Sessions not invalidated server-side on logout. If an attacker hijacks
a session and the victim logs out, the hijacked session stays valid.

For JWTs this is harder — the lifetime is embedded in the token. Fix:
maintain a server-side blocklist of revoked tokens to check against.

---

When testing an application: check how sessions are created, whether
rotation happens post-login, what happens to the session after logout,
and whether authorization is enforced per-request or only at login.
