# Vulnerable and Outdated Components — CVE Mapping from a Discovered EOL Version

**OWASP Category:** A06:2021 – Vulnerable and Outdated Components
**Target:** DVWA's underlying PHP runtime (version disclosed via the [Security Misconfiguration](../security-misconfiguration) lab)
**Method:** Version fingerprinting → CVE research → real-world exploit path mapping (no live exploitation attempted — see note below)

---

## 1. Overview

A06 covers the risk of running software — frameworks, libraries, OS packages, language runtimes — with **known, publicly disclosed vulnerabilities**. The category isn't about age for its own sake; it's about the fact that once a CVE is published, the exact weaknesses in that version are documented and searchable by anyone, attacker included, while an unpatched server never received the fix.

This write-up doesn't introduce a new exploitation technique — it's a **root-cause follow-up** to a finding already made in the Security Misconfiguration lab, treated properly as its own OWASP category rather than a footnote.

---

## 2. Where the Finding Came From

The [Security Misconfiguration](../security-misconfiguration) lab's `phpinfo()` disclosure test revealed:

```
PHP Version 7.0.30-0+deb9u1
Configuration File (php.ini) Path    /etc/php/7.0/apache2
```

**PHP 7.0.x reached official end-of-life in January 2019** — meaning this server has been running unpatched, unsupported software for years, with zero further security fixes issued upstream since that date.

---

## 3. Step 1 — Mapping the Version to a Real CVE

Rather than stopping at "it's outdated," the version string was used to search the public CVE record directly (`cve.mitre.org` / `nvd.nist.gov`) for vulnerabilities affecting the PHP 7.0.x branch.

**Finding: CVE-2018-10549**

| Field | Detail |
|---|---|
| CVE ID | CVE-2018-10549 |
| Component | PHP's EXIF extension (`exif_read_data()` function) |
| Vulnerability type | Heap buffer over-read (out-of-bounds read) |
| Trigger | A specially crafted JPEG file with malformed EXIF metadata |
| Impact | Information disclosure and potential denial of service (crash); out-of-bounds reads can leak adjacent heap memory contents depending on memory layout |
| Affected versions | PHP before 7.0.31, 7.1.x before 7.1.18, 7.2.x before 7.2.6 |
| This server's version | **7.0.30 — directly inside the vulnerable range** |
| Patched in | 7.0.31 |

---

## 4. Step 2 — Mapping It to a Real Attack Surface

A CVE only matters in practice if there's a code path that reaches the vulnerable function. `exif_read_data()` is called whenever an application parses EXIF metadata from an uploaded image — a common pattern on any site with a profile-picture or file-upload feature.

DVWA ships exactly this kind of feature in its **File Upload** module. If that upload path (or any real application sharing this PHP version) processes EXIF data from user-submitted images, CVE-2018-10549 becomes a concrete, reachable attack surface rather than a theoretical version-number concern.

> **Note on scope:** this lab deliberately stopped at CVE identification and attack-surface mapping rather than attempting to trigger the memory-disclosure condition. Reliably triggering an out-of-bounds heap read for information disclosure requires crafting binary-level malformed EXIF structures and depends heavily on the exact memory allocator/build — there is no safe, reliable way to demonstrate this in a lab shell without risking an uncontrolled crash. Identifying the CVE, confirming the affected version, and mapping the reachable code path **is** the realistic deliverable a real assessment produces for this category — actual exploitation of memory-safety bugs is normally handled by dedicated fuzzing/exploit-dev work, not a general app-sec pass.

---

## 5. Why This Matters

The vulnerability here isn't in DVWA's own PHP application code — it's entirely inherited from the language runtime underneath it. No amount of secure coding in DVWA's own files closes this gap; only updating PHP itself does. This is the defining characteristic of A06: **the flaw lives in a dependency, not in code the team wrote**, which is exactly why component inventory and patch cadence are treated as a first-class security control, not an IT-operations afterthought.

---

## 6. Impact & Fix

| Finding | Fix |
|---|---|
| PHP 7.0.30 in use, 6+ years past end-of-life | Upgrade to a currently supported PHP release (8.x at time of writing) |
| No visible patch/version tracking process | Establish a defined patching cadence and subscribe to security advisories for every major runtime/framework in use |
| Vulnerable EXIF parsing reachable via file upload | Until upgraded, disable or restrict any feature that parses EXIF metadata from user-uploaded images |
| No component inventory | Maintain a software bill of materials (SBOM) so any newly disclosed CVE can be checked against running versions immediately, rather than discovered by fingerprinting after the fact |

---

## 7. Real-World Relevance

- Component-version fingerprinting is one of the first things a real attacker (or a legitimate pentester) does after finding *any* information-disclosure bug — a `phpinfo()` leak, a verbose error message, or an `X-Powered-By` header are all enough to pivot straight into CVE research.
- CVE-2018-10549 is a genuine, publicly catalogued vulnerability, not a hypothetical example — it demonstrates that "the software is old" is not an abstract risk but maps to specific, named, dated security advisories with concrete impact statements.
- This finding directly reuses evidence from the [Security Misconfiguration](../security-misconfiguration) lab, illustrating a realistic assessment workflow: one disclosure (verbose `phpinfo()`) doesn't just get logged once — it gets re-examined from every angle the OWASP Top 10 provides (here, both as a misconfiguration *and* as an outdated-component finding), which is exactly how a single weak control compounds into multiple reportable findings in a real audit.
