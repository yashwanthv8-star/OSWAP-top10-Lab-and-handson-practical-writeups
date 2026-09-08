# Server-Side Request Forgery (SSRF) — Basic Exploitation & Blacklist Bypass Attempt

**OWASP Category:** A10:2021 – Server-Side Request Forgery
**Target:** PortSwigger Web Security Academy — SSRF lab series
**Tooling:** Burp Suite Community Edition (Proxy, Intercept, Repeater)
**Status:** Lab 1 — ✅ Solved · Lab 2 — 🔜 In Progress

---

## 1. Overview

Server-Side Request Forgery occurs when an application accepts a user-controllable URL or address and fetches it server-side, without properly validating or restricting the destination. Because the request originates from the server itself, it can reach internal systems that would never be directly reachable from the public internet — internal admin panels, cloud metadata endpoints, or other backend services sitting behind a firewall.

This write-up documents two connected labs against a vulnerable "stock checker" feature: a product page that lets the server fetch live stock data from a `stockApi` parameter supplied in the request.

---

## 2. Lab Environment

| Component | Details |
|---|---|
| Platform | PortSwigger Web Security Academy (hosted lab instances) |
| Vulnerable feature | Product page "check stock" function — server-side fetch via a `stockApi` parameter |
| Tooling | Burp Suite Community Edition — Proxy (intercept), Repeater |
| Method | Intercept the legitimate stock-check request, then rewrite the `stockApi` parameter in Repeater and resend |

This was also my first hands-on session with Burp Suite — learning the Proxy → Intercept → Repeater workflow from scratch as part of this lab.

---

## 3. Lab 1 — Basic SSRF Against the Local Server (✅ Solved)

### 3.1 Baseline — Capturing the Legitimate Request

The normal "check stock" action was intercepted in Burp. The application's own server makes this request on the user's behalf:

```
POST /product/stock HTTP/2
Host: 0a26006503ad34ad8029b3ea007200b6.web-security-academy.net
Cookie: session=AjBTX6bJvbPSAjtWOTmx3NUQgjKTZndK
Content-Type: application/x-www-form-urlencoded

stockApi=http%3A%2F%2Fstock.weliketoshop.net%3A8080%2Fproduct%2Fstock%2Fcheck...
```

**Key observation:** `stockApi` is a full, attacker-controllable URL, sent from the client but *fetched by the server*. Nothing on the client side restricts what this value can be.

### 3.2 Exploitation — Redirecting the Request Internally

The value was rewritten in Repeater to point at the application's own internal admin path instead of the legitimate external stock API:

```
stockApi=http://localhost/admin/delete?username=carlos
```

**Result:**

```
HTTP/2 302 Found
Location: /admin
Set-Cookie: session=ZHqrlBUWIe9AcVGHzj5ATu4RSbRpVmVd; Secure; HttpOnly; SameSite=None
```

The `302 Found` with `Location: /admin` confirms the server accepted and processed the request as a legitimate internal admin action — the user `carlos` was deleted, solving the lab.

### 3.3 Why It Worked

The application trusted the `stockApi` value completely and performed the server-side fetch with no validation of the destination host, scheme, or path. Because the request came from the server's own network context, it was treated as an internal, implicitly trusted request — bypassing whatever access control would normally protect `/admin`. This is the core SSRF mechanism: **the attacker never touches the internal resource directly — they get the trusted server to touch it on their behalf.**

---

## 4. Lab 2 — SSRF Protected by a Blacklist / Input Filter (🔜 In Progress)

### 4.1 What Was Attempted

A second, more hardened instance of the same stock-checker feature was tested. The same technique from Lab 1 was tried first — pointing `stockApi` directly at an internal IP address:

```
stockApi=http://192.168.0.1:8080/admin
```

### 4.2 Result — Request Rejected by Server-Side Validation

```
HTTP/2 400 Bad Request
Content-Type: application/json; charset=utf-8

"Invalid external stock check url 'Illegal character in path at index 29: http://192.168.0.1:8080/admin"
```

**Analysis:** Unlike Lab 1, this instance performs server-side validation on the submitted URL and explicitly rejects it — the direct internal-IP payload that worked in Lab 1 is blocked here. This confirms the target application implements some form of blacklist or URL-parsing validation intended to stop obvious SSRF payloads.

### 4.3 Next Steps

This lab was not yet solved at the time of writing. The direct approach is blocked, so the next steps are to test standard SSRF blacklist-bypass techniques, including:

- Alternative representations of the loopback/internal address (e.g. decimal, octal, or IPv6-mapped IP notation) that a naive string-matching filter may not recognize
- Exploiting parser inconsistency between the validation logic and the actual HTTP client that performs the fetch (e.g. using credentials-in-URL syntax, or a redirect from an attacker-controlled external host to the internal target)
- Reviewing whether the filter checks the hostname only once, before any redirect is followed

This section will be updated once the bypass is confirmed and the lab is solved.

---

## 5. Impact Assessment

- **Lab 1** demonstrates full internal access-control bypass: an unauthenticated or low-privileged actor can reach and trigger internal admin functionality (here, deleting a user account) purely by controlling a server-side fetch target.
- **Lab 2** shows that a naive blacklist/validation approach can still leave SSRF exploitable — the presence of a filter is not the same as the absence of the vulnerability, which is why this is being worked through rather than marked complete.
- In a real environment, this class of vulnerability is frequently used to reach cloud metadata endpoints (e.g. AWS IMDS at `169.254.169.254`) to steal instance credentials — a well-documented real-world SSRF impact pattern beyond just internal admin panels.

---

## 6. Remediation & Fixes

| Finding | Recommended Fix |
|---|---|
| Server fetches an arbitrary, user-supplied URL with no validation (Lab 1) | Use an allow-list of permitted destination hosts, never a blacklist; reject anything not explicitly permitted |
| Blacklist filter can potentially be bypassed via alternate IP encodings or redirects (Lab 2, under investigation) | Validate the *resolved* destination IP after DNS resolution and after following any redirects, not just the literal string submitted — and disable automatic redirect-following on server-side fetch clients |
| Internal admin endpoints reachable from the same code path as external fetches | Segregate network access so the server component making external calls has no route to internal-only services in the first place (defense in depth, independent of input validation) |

---

## 7. Real-World Relevance

SSRF has been the root cause of several major real-world breaches, most notably as the initial access vector in large-scale cloud data breaches where attackers used SSRF to query cloud metadata services and steal temporary credentials. This lab series demonstrates why blacklist-only defenses are considered insufficient in real assessments — Lab 2 is a direct, hands-on illustration of that principle rather than an abstract warning.
