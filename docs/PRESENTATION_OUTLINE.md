# PowerPoint Presentation Outline: PhishAware
## Secure Phishing Awareness and URL Risk Checker
**Recommended Slides:** 12 Slides  
**Target Duration:** 10 to 15 Minutes + Q&A  

---

### Slide 1: Title & Project Overview
- **Title**: PhishAware: Secure Phishing Awareness & URL Risk Checker
- **Subtitle**: Transparent, Explainable Heuristic Analysis and Safe Browsing Education
- **Presenter**: Engineering Candidate / Project Lead
- **Tech Stack**: Python 3.14 | Flask | MySQL 8.0 / SQLite | HTML5 / CSS3 / Vanilla JS | Git

---

### Slide 2: Problem Statement & Motivation
- **The Threat Landscape**:
  - Phishing causes billions in global damages; attackers exploit RFC URL parsing rules.
  - Deceptive techniques: Credential `@` injection, lookalike homoglyphs, dword IP obfuscation.
- **The Problem with Existing Tools**:
  - Most scanners are "black boxes" that give a score without teaching users *why*.
  - Many naive scanners crawl target links, opening the backend to **SSRF** and malware.
- **Our Goal**: Build an educational, explainable, and intrinsically secure URL checker.

---

### Slide 3: Core Security Philosophy
- **Zero Outbound Requests Protocol**:
  - The server **NEVER** initiates an HTTP request or DNS lookup to target URLs.
  - Eliminates Server-Side Request Forgery (SSRF), internal port scans, and malware infections.
- **Transparent Heuristics $\neq$ Definitive Proof**:
  - Heuristics detect structural anomalies and warning signs.
  - Prominent disclaimers teach users that a clean score does not guarantee 100% safety.

---

### Slide 4: System Architecture & Workflow
- **Client**: Responsive web UI built with semantic HTML5, CSS3, and vanilla JavaScript.
- **Application Server**: Python/Flask with security middleware (CSP, `X-Frame-Options: DENY`).
- **Processing Flow**:
  1. User submits URL $\rightarrow$ 2. Input validation & normalization $\rightarrow$ 
  3. Static heuristic evaluation $\rightarrow$ 4. Parameterized DB storage $\rightarrow$ 
  5. Explainable JSON report rendered on UI.

---

### Slide 5: The 13 Heuristic Rules Catalog
- **Hostname Indicators**:
  - `HR-01`: Raw IP address (+35)
  - `HR-03`: Excessive subdomains $\ge 3$ (+20)
  - `HR-04`: Sensitive keywords in subdomain (+25)
  - `HR-05`: High-risk / burner TLDs (+15)
  - `HR-06`: Punycode `xn--` homoglyphs (+35)
  - `HR-09`: Multiple hyphens $\ge 3$ (+15)
  - `HR-10`: Dword / Hexadecimal IP encoding (+40)
- **Authority & Structure Indicators**:
  - `HR-02`: Credential `@` trick (+40)
  - `HR-07`: Non-standard web ports (+20)
  - `HR-08`: URL length $>100$ chars (+15)
  - `HR-11`: Open redirect parameters (+20)
  - `HR-12`: Brand name in path/query (+25)
  - `HR-13`: Plain HTTP for sensitive actions (+15)

---

### Slide 6: Risk Scoring & Tiers
- **Scoring Algorithm**:
  - Composite sum of activated rule weights, clamped to a maximum of 100.
- **Calibrated Tiers**:
  - 🟢 **Low Risk (0–24)**: Minimal structural anomalies detected.
  - 🟡 **Suspicious (25–59)**: Multiple warning signs present; proceed with caution.
  - 🔴 **High Risk (60–100)**: Strong indicators of credential harvesting or deception.
- **Actionable Guidance**: Every triggered card explains *what was found*, *why attackers use it*, and *what action to take*.

---

### Slide 7: Database Design (MySQL 8.0 & Resilient Dual-Engine)
- **Third Normal Form (3NF) Relational Schema**:
  - `assessments` table: Scan metadata, scores, timestamps, and normalized URLs.
  - `triggered_rules` table: Granular record of every activated rule linked via Foreign Key (`ON DELETE CASCADE`).
- **Zero-Config Resilient Dual-Engine**:
  - Connects to **MySQL 8.0** when credentials are configured.
  - Automatically activates local **SQLite** fallback if MySQL access is restricted.
- **100% Parameterized Queries**:
  - Eliminates SQL injection across all search and insertion queries.

---

### Slide 8: Web Interface & User Experience
- **Interactive Dashboard**:
  - Live URL input with instant synthetic sample chips (Benign, `@` Trick, Raw IP, Subdomain Spoof).
  - Dynamic risk gauge and color-coded status badge.
- **Audit Trail & History**:
  - Debounced search by domain name or URL string.
  - Risk tier filter buttons (`All`, `Low Risk`, `Suspicious`, `High Risk`).
- **Telemetry & Statistics**:
  - Total scans, average score, risk distribution bar, and Top 5 triggered rules leaderboard.
- **Educational Mini-Quiz**:
  - Interactive knowledge checks testing user ability to spot real-world phishing traps.

---

### Slide 9: Defense-in-Depth & Security Hardening
- **HTTP Security Headers**:
  - `Content-Security-Policy (CSP)`: Neutralizes client-side script injection.
  - `X-Frame-Options: DENY`: Prevents Clickjacking attacks.
  - `X-Content-Type-Options: nosniff`: Prevents MIME confusion exploits.
  - `Referrer-Policy: strict-origin-when-cross-origin`: Protects query privacy.
- **Application Hardening**:
  - Length cap (2,048 chars) protects against ReDoS.
  - Disallows non-web schemes (`javascript:`, `data:`, `file:`).

---

### Slide 10: Verification & Test Results
- **Automated Test Suite**:
  - **37 automated tests** running in `pytest`.
  - Normalization suite (14 tests): RFC compliance, edge cases, blocked schemes.
  - Heuristics suite (13 tests): Rule activation accuracy, score clamping.
  - Database suite (2 tests): Relational joins and SQL injection payload handling.
  - API suite (8 tests): Endpoints, JSON responses, error handling, and security headers.
- **Result**: 100% pass rate in 4.58 seconds.

---

### Slide 11: Limitations & Future Enhancements
- **Current Limitations**:
  - Offline heuristics cannot evaluate dynamic DOM content or follow live cloaking.
  - Legitimate sites with unusual structures may trigger false positives.
- **Future Roadmap**:
  - Integration of lightweight offline machine learning classifiers (Random Forest).
  - Offline Bloom filter integration for known malicious domain datasets.
  - Native browser extension for real-time link previewing.

---

### Slide 12: Conclusion & Q&A
- **Key Takeaway**: PhishAware proves that proactive security education can be combined with secure software architecture to build safe, explainable defensive tools.
- **Repository**: Managed with Git version control, modular code layout, and thorough documentation.
- **Open for Questions**: Thank you!
