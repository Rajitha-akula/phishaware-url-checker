# Software Requirements Specification (SRS)
## Project: PhishAware - Secure Phishing Awareness and URL Risk Checker
**Document Version:** 1.0.0  
**Standard Compliance:** IEEE Std 830-1998 Format  
**Author:** Engineering & Cybersecurity Team  

---

### 1. Introduction

#### 1.1 Purpose
This Software Requirements Specification (SRS) details the functional and non-functional requirements for the **PhishAware: Secure Phishing Awareness and URL Risk Checker** application. It serves as the definitive reference for developers, security reviewers, academic evaluators, and system architects.

#### 1.2 Scope of the System
The system is an educational cybersecurity web application built with Python, Flask, MySQL, and modern web standards. It enables users to submit target URLs to evaluate potential phishing and social engineering indicators through transparent, explainable heuristic analysis.
- **Key Boundary (Out-of-Scope)**: The system deliberately **does NOT crawl, fetch, or visit** user-submitted URLs. It operates purely as an offline static syntactic and structural analyzer to protect the server and internal infrastructure against Server-Side Request Forgery (SSRF) and drive-by exploitation.
- **Heuristic Disclaimer**: Heuristics detect anomalous structures and warning signs. They **do not provide definitive proof** that a URL is benign or malicious.

#### 1.3 Definitions, Acronyms, and Abbreviations
- **SSRF**: Server-Side Request Forgery.
- **XSS**: Cross-Site Scripting.
- **SQLi**: SQL Injection.
- **CSP**: Content Security Policy.
- **TLD**: Top-Level Domain (e.g., `.com`, `.org`, `.xyz`).
- **Punycode / IDN**: Internationalized Domain Names encoded with `xn--` prefixes.
- **3NF**: Third Normal Form (Relational Database Design).

---

### 2. Overall Description

#### 2.1 Product Perspective
PhishAware is a self-contained, lightweight web application operating in a standard client-server model:
- **Client**: Modern web browser (HTML5, responsive CSS3, vanilla JavaScript).
- **Server**: Python 3.10+ running Flask WSGI application with HTTP security middleware.
- **Database**: Relational DBMS (MySQL 8.0 with automatic SQLite fallback).

#### 2.2 User Characteristics
- **General Web Users & Students**: Seeking to verify suspicious links received via email, SMS, or messaging apps while learning how phishing links function.
- **Security Analysts & Educators**: Demonstrating URL deconstruction, credential obfuscation tactics, and defensive web architecture.

#### 2.3 Operating Environment
- Operating System: Windows 10/11, Linux (Ubuntu/Debian/RHEL), or macOS.
- Python Runtime: Python 3.10, 3.11, 3.12, 3.13, 3.14.
- Database: MySQL 8.0+ / SQLite 3.35+.

---

### 3. Specific Requirements

#### 3.1 Functional Requirements (FR)

##### **FR-1: Safe URL Input Validation & Normalization**
- **FR-1.1**: The system shall accept URL strings up to 2,048 characters in length. Any input exceeding this limit shall be rejected with an HTTP 400 Bad Request error.
- **FR-1.2**: The system shall strip leading/trailing whitespace, linebreaks (`\r`, `\n`), and reject inputs containing null bytes (`\x00`) or control characters.
- **FR-1.3**: The system shall explicitly block non-web pseudo-schemes (`javascript:`, `data:`, `file:`, `vbscript:`, `blob:`, `about:`).
- **FR-1.4**: If a scheme is omitted (e.g., `paypal.com/login`), the system shall infer `http://` for RFC-compliant parsing and set `scheme_was_inferred=True`.

##### **FR-2: Heuristic Analysis Engine**
The system shall evaluate all 13 defined heuristic rules against the normalized URL structure:
- **FR-2.1 (HR-01)**: Flag raw IPv4 and IPv6 hostnames (+35 risk points).
- **FR-2.2 (HR-02)**: Flag userinfo `@` characters in the authority section (+40 risk points).
- **FR-2.3 (HR-03)**: Flag hostnames with 3 or more nested subdomains (+20 risk points).
- **FR-2.4 (HR-04)**: Flag sensitive credentials/banking keywords in subdomains (+25 risk points).
- **FR-2.5 (HR-05)**: Flag historically abused or burner TLDs (+15 risk points).
- **FR-2.6 (HR-06)**: Flag Punycode (`xn--`) or non-ASCII homoglyph characters (+35 risk points).
- **FR-2.7 (HR-07)**: Flag non-standard web ports other than 80 and 443 (+20 risk points).
- **FR-2.8 (HR-08)**: Flag URLs exceeding 100 characters in length (+15 risk points).
- **FR-2.9 (HR-09)**: Flag hostnames containing 3 or more hyphens (+15 risk points).
- **FR-2.10 (HR-10)**: Flag decimal dword or hexadecimal IP address representations (+40 risk points).
- **FR-2.11 (HR-11)**: Flag query parameters containing secondary external URLs (+20 risk points).
- **FR-2.12 (HR-12)**: Flag trusted brand names in the path when the registered domain does not match (+25 risk points).
- **FR-2.13 (HR-13)**: Flag unencrypted HTTP for sensitive login actions (+15 risk points).

##### **FR-3: Scoring & Classification**
- **FR-3.1**: The system shall calculate a cumulative risk score clamped between 0 and 100.
- **FR-3.2**: The system shall classify the risk level:
  - `LOW_RISK`: Score 0 – 24 (Color: Green `#10b981`)
  - `SUSPICIOUS`: Score 25 – 59 (Color: Amber `#f59e0b`)
  - `HIGH_RISK`: Score 60 – 100 (Color: Red `#ef4444`)
- **FR-3.3**: Every evaluation result shall include the mandatory educational disclaimer.

##### **FR-4: Relational Persistence Layer**
- **FR-4.1**: Assessments shall be stored in an `assessments` table (raw URL, normalized URL, host, scheme, risk score, risk level, summary, timestamp).
- **FR-4.2**: Each triggered rule shall be stored in a relational `triggered_rules` table linked via foreign key with `ON DELETE CASCADE`.
- **FR-4.3**: All SQL queries shall execute via parameterized statements (`%s` / `?`) to guarantee SQL injection immunity.

##### **FR-5: History, Search & Filtering**
- **FR-5.1**: The system shall provide paginated retrieval of previous scans (`limit`, `offset`).
- **FR-5.2**: The system shall support live search matching hostnames or URL strings.
- **FR-5.3**: The system shall support filtering by risk tier (`LOW_RISK`, `SUSPICIOUS`, `HIGH_RISK`).

##### **FR-6: Telemetry & Aggregate Statistics**
- **FR-6.1**: The system shall compute total scans, average risk score, and risk tier counts.
- **FR-6.2**: The system shall identify the Top 5 most frequently triggered heuristic rules.
- **FR-6.3**: The system shall report the currently active database engine (`MySQL` or `SQLite`).

---

#### 3.2 Non-Functional Requirements (NFR)

- **NFR-1 (Security - SSRF Defense)**: The server shall NEVER initiate outbound HTTP requests or DNS resolutions to analyzed target URLs.
- **NFR-2 (Security - Injection Defense)**: No raw user input shall be interpolated or formatted directly into SQL strings.
- **NFR-3 (Security - HTTP Headers)**: Every response shall deliver CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy`.
- **NFR-4 (Performance)**: The static heuristic analysis and database insertion shall complete in under 50 milliseconds per URL under standard load.
- **NFR-5 (Reliability & Fault Tolerance)**: If the primary MySQL database is unreachable or access is denied, the system shall seamlessly fall back to local SQLite without application interruption.
- **NFR-6 (Usability & Accessibility)**: The web UI shall be responsive across mobile, tablet, and desktop viewports, with high-contrast color indicators and legible typography.
