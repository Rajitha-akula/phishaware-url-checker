# Technical & Security Interview Questions (Viva Guide)
## Project: PhishAware - Secure Phishing Awareness & URL Risk Checker
**Target Audience:** Job Interviews, University Project Viva, and Technical Defenses  
**Coverage:** Web Security, Python/Flask Architecture, Database Design, and Heuristics  

---

### Section 1: Security Architecture & Threat Defense

#### Q1: Why does PhishAware enforce a "Zero Outbound Requests" policy instead of crawling the URL?
**Model Answer:**  
If a backend web server crawls or fetches user-submitted URLs using libraries like `requests.get()` or resolves DNS records, it creates severe vulnerabilities:
1. **Server-Side Request Forgery (SSRF)**: An attacker could submit internal addresses such as `http://169.254.169.254/latest/meta-data/` (cloud credentials) or `http://localhost:3306` to probe internal networks.
2. **Denial of Service**: Malicious servers can execute slowloris or tar-pit attacks, keeping backend connections open and exhausting server threads.
3. **Malware Delivery**: Fetching unvetted payloads directly exposes server memory and disk to exploits.  
By keeping all analysis strictly static and offline, PhishAware completely eliminates SSRF and remote exploitation.

#### Q2: What is the purpose of the educational disclaimer, and why can't heuristics definitively prove a URL is safe or malicious?
**Model Answer:**  
Heuristic analysis evaluates syntactic and structural patterns (such as raw IPs, `@` symbols, and high-risk TLDs). While these patterns correlate strongly with phishing campaigns, they are not definitive proof:
- A sophisticated attacker might use a clean `.com` domain with standard structure, resulting in a low heuristic score (False Negative).
- A legitimate developer might run a local development server on a non-standard port or use multiple subdomains, resulting in a high heuristic score (False Positive).  
The disclaimer ensures users understand that structural heuristics are an educational warning system rather than an absolute guarantee.

#### Q3: How does the application prevent SQL Injection?
**Model Answer:**  
The application uses **parameterized queries** (prepared statements) for all database operations:
```python
cursor.execute("SELECT * FROM assessments WHERE host LIKE %s", (f"%{user_search}%",))
```
In parameterized queries, the database engine compiles the SQL command structure *before* substituting user data. Even if a user enters `' OR '1'='1`, the database treats it as literal string characters rather than executable SQL syntax. String formatting (`f"..."` or `%`) is strictly prohibited.

#### Q4: How is Cross-Site Scripting (XSS) mitigated in the application?
**Model Answer:**  
Defense-in-depth XSS mitigation is implemented across both backend and frontend:
1. **Backend**: Flask's Jinja2 template engine automatically applies contextual HTML escaping to all variable interpolations.
2. **Frontend**: Client-side JavaScript strictly uses `element.textContent` rather than `element.innerHTML` when injecting user-submitted URLs and hostnames into the DOM.
3. **HTTP Header**: A strict Content Security Policy (`CSP`) is injected on every response, restricting script execution to approved self-hosted sources.

#### Q5: What is Clickjacking, and what header prevents it?
**Model Answer:**  
Clickjacking is an attack where a malicious site embeds our application inside an invisible or transparent `<iframe>` and tricks users into clicking buttons without their knowledge.  
PhishAware blocks this using the HTTP header:
```http
X-Frame-Options: DENY
```
This instructs all modern browsers never to render the page within an `<iframe>`, `<frame>`, or `<object>`.

---

### Section 2: URL Parsing & Heuristics Engine

#### Q6: How does an attacker exploit the `@` symbol in a URL, and how does Rule HR-02 detect it?
**Model Answer:**  
According to RFC 3986, the authority component of a URL supports `userinfo@hostname`. The browser treats everything before the `@` symbol as user credentials and ignores it when navigating. An attacker crafts:
`https://paypal.com@evil-site.com/login`  
Unsuspecting users see `paypal.com` on the left and assume it is safe. Our normalizer checks for the presence of an `@` sign in `parsed.netloc`, isolates `userinfo`, and triggers **Rule HR-02** (+40 points), warning the user that their browser will actually navigate to the domain after the `@`.

#### Q7: What is an IP Dword or Hexadecimal obfuscation attack (Rule HR-10)?
**Model Answer:**  
IPv4 addresses are 32-bit integers typically written in dotted-quad notation (`127.0.0.1`). However, operating systems and browsers also accept raw decimal integers (Dword format, e.g., `2130706433`) or hex values (`0x7f000001`). Attackers use these formats to bypass simple regex filters that only check for dotted numbers. Rule HR-10 checks if the hostname is a pure integer or starts with `0x`, detects the 32-bit integer range, and flags it as a high-severity evasion indicator (+40 points).

#### Q8: What is an IDN Homoglyph attack, and how is it detected (Rule HR-06)?
**Model Answer:**  
Internationalized Domain Names allow non-Latin alphabets in domains, converted via Punycode (prefixed with `xn--`). Attackers substitute Latin characters with visually indistinguishable Cyrillic or Greek lookalikes (e.g., Cyrillic 'а' replacing Latin 'a'). Rule HR-06 checks if the hostname contains `xn--` or non-ASCII characters, alerting the user to potential homoglyph deception (+35 points).

#### Q9: What happens if a user submits a URL without an explicit scheme (e.g. `google.com`)?
**Model Answer:**  
Python's standard `urllib.parse.urlsplit` requires a scheme to properly decompose the authority component; without one, it mistakenly treats `google.com` as a path. Our normalizer inspects the string: if no scheme regex matches (`^[a-zA-Z][a-zA-Z0-9+\-.]*://`), it automatically prepends `http://` for RFC decomposition while setting `scheme_was_inferred=True`.

#### Q10: Why are non-web schemes like `javascript:` and `data:` blocked during normalization?
**Model Answer:**  
In web browsers, navigating to `javascript:alert(1)` executes arbitrary script in the current origin, while `data:text/html,...` can render rogue HTML pages. By blocking these pseudo-schemes at the normalizer stage with a descriptive `ValidationError`, the application prevents client-side execution attacks.

---

### Section 3: Database & Backend Architecture

#### Q11: Explain the relational database design and why 3NF was chosen.
**Model Answer:**  
The database uses two tables: `assessments` and `triggered_rules`.  
- `assessments` stores scan-level metadata (raw URL, normalized URL, host, composite score, risk level, timestamp).
- `triggered_rules` stores individual rule triggers linked by `assessment_id`.  
This 3NF design prevents multi-valued attributes in `assessments`, avoids data duplication, and enables aggregate analytics (e.g. calculating the Top 5 most frequently triggered rules across all scans via SQL `GROUP BY`).

#### Q12: Why is `ON DELETE CASCADE` used in the foreign key constraint?
**Model Answer:**  
`ON DELETE CASCADE` ensures referential integrity. When an assessment record is deleted from the `assessments` parent table, the database engine automatically removes all associated records in `triggered_rules`, preventing orphaned rows.

#### Q13: How does the "Resilient Dual-Engine" database adapter work in `db.py`?
**Model Answer:**  
`db.py` implements an abstraction layer that tests MySQL connectivity on startup. If MySQL credentials are valid, it executes queries using PyMySQL (`%s` placeholders). If MySQL credentials fail or access is denied, it gracefully switches to local SQLite (`?` placeholders) using the exact same relational table definitions. This ensures zero downtime and effortless deployment across diverse development environments.

#### Q14: What indexes were created on the database and why?
**Model Answer:**  
- `idx_host`: Accelerates text searches when querying scan history by domain name.
- `idx_risk_level`: Optimizes filtering by risk classification (`LOW_RISK`, `SUSPICIOUS`, `HIGH_RISK`).
- `idx_created_at`: Speeds up chronological sorting (`ORDER BY created_at DESC`) for pagination.
- `idx_assessment_id`: Enables fast relational joins when fetching triggered rules for a specific assessment.

---

### Section 4: Python & Flask Engineering

#### Q15: What is the Flask Application Factory pattern, and why did you use it?
**Model Answer:**  
Instead of creating a global `app = Flask(__name__)` instance at the module root, the Application Factory pattern encapsulates initialization inside a `create_app(config_class)` function. This enables:
1. Dynamic configuration switching (e.g., using a testing database during `pytest` runs).
2. Clean blueprint registration and middleware attachment.
3. Prevention of circular import issues between database models, routes, and views.

#### Q16: How does the application handle errors without disclosing sensitive system details?
**Model Answer:**  
Custom error handlers (`@app.errorhandler`) for 400, 404, 405, and 500 intercept HTTP exceptions. In production (`FLASK_DEBUG=False`), unexpected exceptions return a generic JSON error message (`{"error": "Internal Server Error"}`), preventing stack traces, file system paths, or database passwords from leaking to the client.

#### Q17: What is the purpose of Python's `@contextmanager` in `db.py`?
**Model Answer:**  
The `@contextmanager` decorator wraps database connections in a `try...except...finally` block. It yields the cursor to the calling function, commits the transaction on success, rolls back on error, and guarantees that cursors and connections are closed even if an unexpected exception occurs, preventing connection leaks.

---

### Section 5: Heuristics vs. Machine Learning

#### Q18: What are the advantages of Heuristics over Machine Learning for phishing awareness?
**Model Answer:**  
1. **Explainability**: Every rule provides clear, human-understandable reasoning ("Why was this flagged?"), which is essential for user education. Neural networks and complex ensemble trees often act as opaque "black boxes".
2. **Deterministic & Auditable**: Given the same URL, heuristic rules always yield the exact same score and triggered indicators.
3. **Zero Resource Overhead**: Heuristic rules run in microseconds using standard string parsing, requiring no GPU, large model files, or heavyweight inference pipelines.

#### Q19: What are the limitations of heuristic rules, and how can they be bypassed?
**Model Answer:**  
Attackers can bypass heuristics by registering legitimate-looking `.com` domains without hyphens or brand keywords, hosting benign decoy content initially, and switching to phishing only for targeted victims. This is why PhishAware reinforces that heuristics are an awareness guide rather than a definitive guarantee.

#### Q20: How would you enhance PhishAware in a production enterprise environment?
**Model Answer:**  
1. Add an offline Bloom filter matching local threat intelligence feeds (e.g., URLhaus or OpenPhish).
2. Train a lightweight Random Forest classifier on URL lexical features (vowel-to-consonant ratio, Shannon entropy) to complement the heuristic rules.
3. Package the analyzer as a browser extension to evaluate links client-side before the user clicks.
