/**
 * Secure Phishing Awareness & URL Risk Checker - Client Logic
 * Vanilla JavaScript (Zero external CDN dependencies for maximum security).
 * Implements strict contextual DOM sanitization to eliminate client-side XSS.
 */

document.addEventListener("DOMContentLoaded", () => {
    initAnalyzer();
    initHistoryTable();
    initStatsView();
});

// -------------------------------------------------------------
// 1. Analyzer Module
// -------------------------------------------------------------
function initAnalyzer() {
    const form = document.getElementById("analyze-form");
    const input = document.getElementById("url-input");
    const submitBtn = document.getElementById("submit-btn");
    const resultContainer = document.getElementById("result-container");
    const errorContainer = document.getElementById("error-container");

    if (!form || !input) return;

    // Quick Test Sample Chips
    document.querySelectorAll(".sample-chip").forEach(chip => {
        chip.addEventListener("click", () => {
            const sampleUrl = chip.getAttribute("data-sample");
            if (sampleUrl) {
                input.value = sampleUrl;
                submitURL(sampleUrl);
            }
        });
    });

    form.addEventListener("submit", (e) => {
        e.preventDefault();
        const urlValue = input.value.trim();
        if (!urlValue) return;
        submitURL(urlValue);
    });

    async function submitURL(targetUrl) {
        // UI Loading state
        submitBtn.disabled = true;
        const originalBtnText = submitBtn.innerHTML;
        submitBtn.innerHTML = '<span class="spinner"></span> Analyzing...';
        if (errorContainer) errorContainer.classList.add("hidden");
        if (resultContainer) resultContainer.classList.add("hidden");

        try {
            const response = await fetch("/api/analyze", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ url: targetUrl })
            });

            const data = await response.json();

            if (!response.ok || !data.success) {
                showError(data.message || data.error || "Analysis failed.");
                return;
            }

            renderAssessmentResult(data);
        } catch (err) {
            showError("Network error: Could not connect to the analyzer service.");
        } finally {
            submitBtn.disabled = false;
            submitBtn.innerHTML = originalBtnText;
        }
    }

    function showError(message) {
        if (!errorContainer) return;
        errorContainer.textContent = message;
        errorContainer.classList.remove("hidden");
    }

    function renderAssessmentResult(data) {
        if (!resultContainer) return;

        // 1. Risk Gauge & Badge
        const scoreElem = document.getElementById("result-score");
        const badgeElem = document.getElementById("result-badge");
        const circleElem = document.getElementById("result-circle");
        const summaryElem = document.getElementById("result-summary");

        if (scoreElem) scoreElem.textContent = data.risk_score;
        if (circleElem) {
            circleElem.style.borderColor = data.color;
            circleElem.style.color = data.color;
        }

        if (badgeElem) {
            badgeElem.textContent = data.risk_level.replace("_", " ");
            badgeElem.className = `risk-badge ${data.risk_level}`;
        }

        if (summaryElem) summaryElem.textContent = data.breakdown_summary;

        // 2. Structural Breakdown (safely using textContent)
        document.getElementById("bd-scheme").textContent = data.scheme || "N/A";
        document.getElementById("bd-host").textContent = data.host || "N/A";
        document.getElementById("bd-url").textContent = data.normalized_url;

        // 3. Disclaimer text
        const disclaimerElem = document.getElementById("result-disclaimer-text");
        if (disclaimerElem) disclaimerElem.textContent = data.disclaimer;

        // 4. Render Triggered Rules List
        const rulesList = document.getElementById("rules-list");
        const rulesEmpty = document.getElementById("rules-empty");
        if (rulesList) {
            rulesList.innerHTML = "";
            const rules = data.triggered_rules || [];

            if (rules.length === 0) {
                if (rulesEmpty) rulesEmpty.classList.remove("hidden");
            } else {
                if (rulesEmpty) rulesEmpty.classList.add("hidden");
                rules.forEach(rule => {
                    const card = createRuleCard(rule);
                    rulesList.appendChild(card);
                });
            }
        }

        resultContainer.classList.remove("hidden");
        resultContainer.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    function createRuleCard(rule) {
        const card = document.createElement("div");
        card.className = "rule-card";

        // Header
        const header = document.createElement("div");
        header.className = "rule-header";

        const titleGroup = document.createElement("div");
        titleGroup.className = "rule-title-group";

        const idSpan = document.createElement("span");
        idSpan.className = "rule-id-pill";
        idSpan.textContent = rule.rule_id;

        const nameSpan = document.createElement("span");
        nameSpan.className = "rule-name";
        nameSpan.textContent = rule.name;

        titleGroup.appendChild(idSpan);
        titleGroup.appendChild(nameSpan);

        const weightBadge = document.createElement("span");
        weightBadge.className = "rule-weight-badge";
        weightBadge.textContent = `+${rule.weight} Risk Weight`;

        header.appendChild(titleGroup);
        header.appendChild(weightBadge);

        // Details (What Was Found)
        const descDiv = document.createElement("div");
        descDiv.className = "rule-section";
        const descLabel = document.createElement("div");
        descLabel.className = "rule-section-label";
        descLabel.textContent = "Indicator Detected";
        const descText = document.createElement("div");
        descText.className = "rule-explanation";
        descText.textContent = rule.description;
        descDiv.appendChild(descLabel);
        descDiv.appendChild(descText);

        // Explanation (Why Attackers Use It)
        const expDiv = document.createElement("div");
        expDiv.className = "rule-section";
        const expLabel = document.createElement("div");
        expLabel.className = "rule-section-label";
        expLabel.textContent = "Security Context & Attacker Tactic";
        const expText = document.createElement("div");
        expText.className = "rule-explanation";
        expText.textContent = rule.explanation;
        expDiv.appendChild(expLabel);
        expDiv.appendChild(expText);

        // Guidance Box
        const guideBox = document.createElement("div");
        guideBox.className = "rule-guidance-box";
        guideBox.textContent = "💡 Safety Action: " + rule.guidance;

        card.appendChild(header);
        card.appendChild(descDiv);
        card.appendChild(expDiv);
        card.appendChild(guideBox);

        return card;
    }
}

// -------------------------------------------------------------
// 2. History Table Module
// -------------------------------------------------------------
function initHistoryTable() {
    const tableBody = document.getElementById("history-tbody");
    if (!tableBody) return;

    let currentOffset = 0;
    const limit = 15;
    let currentFilter = "";
    let currentSearch = "";

    const searchInput = document.getElementById("history-search");
    const prevBtn = document.getElementById("history-prev");
    const nextBtn = document.getElementById("history-next");
    const pageInfo = document.getElementById("history-page-info");

    async function loadHistory() {
        tableBody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding: 2rem;">Loading scan records...</td></tr>';
        try {
            const params = new URLSearchParams({
                limit: limit,
                offset: currentOffset,
                q: currentSearch,
                level: currentFilter
            });
            const res = await fetch(`/api/history?${params.toString()}`);
            const data = await res.json();

            if (!res.ok || !data.success) {
                tableBody.innerHTML = '<tr><td colspan="6" style="text-align:center; color: #ef4444; padding: 2rem;">Failed to load history.</td></tr>';
                return;
            }

            renderRows(data.items);
            updatePagination(data.total);
        } catch (err) {
            tableBody.innerHTML = '<tr><td colspan="6" style="text-align:center; color: #ef4444; padding: 2rem;">Error loading history.</td></tr>';
        }
    }

    function renderRows(items) {
        tableBody.innerHTML = "";
        if (!items || items.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="6" style="text-align:center; color: #94a3b8; padding: 2rem;">No assessment records found.</td></tr>';
            return;
        }

        items.forEach(item => {
            const tr = document.createElement("tr");

            // Timestamp
            const tdDate = document.createElement("td");
            tdDate.textContent = item.created_at ? item.created_at.replace("T", " ").substring(0, 19) : "Just now";
            tdDate.style.fontSize = "0.82rem";
            tdDate.style.color = "#94a3b8";

            // Host
            const tdHost = document.createElement("td");
            tdHost.textContent = item.host;
            tdHost.style.fontWeight = "600";

            // Normalized URL
            const tdUrl = document.createElement("td");
            tdUrl.textContent = item.normalized_url.length > 50 ? item.normalized_url.substring(0, 50) + "..." : item.normalized_url;
            tdUrl.style.fontFamily = "monospace";
            tdUrl.style.fontSize = "0.85rem";

            // Risk Score
            const tdScore = document.createElement("td");
            tdScore.textContent = `${item.risk_score} / 100`;
            tdScore.style.fontWeight = "700";
            tdScore.style.color = item.color;

            // Risk Level Badge
            const tdLevel = document.createElement("td");
            const badge = document.createElement("span");
            badge.className = `risk-badge ${item.risk_level}`;
            badge.textContent = item.risk_level.replace("_", " ");
            tdLevel.appendChild(badge);

            tr.appendChild(tdDate);
            tr.appendChild(tdHost);
            tr.appendChild(tdUrl);
            tr.appendChild(tdScore);
            tr.appendChild(tdLevel);

            tableBody.appendChild(tr);
        });
    }

    function updatePagination(total) {
        if (!pageInfo) return;
        const start = total === 0 ? 0 : currentOffset + 1;
        const end = Math.min(currentOffset + limit, total);
        pageInfo.textContent = `Showing ${start} - ${end} of ${total} records`;

        if (prevBtn) prevBtn.disabled = currentOffset === 0;
        if (nextBtn) nextBtn.disabled = currentOffset + limit >= total;
    }

    if (prevBtn) {
        prevBtn.addEventListener("click", () => {
            if (currentOffset >= limit) {
                currentOffset -= limit;
                loadHistory();
            }
        });
    }

    if (nextBtn) {
        nextBtn.addEventListener("click", () => {
            currentOffset += limit;
            loadHistory();
        });
    }

    // Filter Chips
    document.querySelectorAll(".history-filter-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".history-filter-btn").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            currentFilter = btn.getAttribute("data-filter") || "";
            currentOffset = 0;
            loadHistory();
        });
    });

    // Debounced Search Input
    let debounceTimer;
    if (searchInput) {
        searchInput.addEventListener("input", (e) => {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(() => {
                currentSearch = e.target.value.trim();
                currentOffset = 0;
                loadHistory();
            }, 300);
        });
    }

    loadHistory();
}

// -------------------------------------------------------------
// 3. Stats & Telemetry Module
// -------------------------------------------------------------
function initStatsView() {
    const totalScansElem = document.getElementById("stat-total-scans");
    if (!totalScansElem) return;

    async function loadStats() {
        try {
            const res = await fetch("/api/stats");
            const data = await res.json();
            if (!res.ok || !data.success) return;

            const stats = data.stats;
            document.getElementById("stat-total-scans").textContent = stats.total_scans;
            document.getElementById("stat-avg-score").textContent = stats.avg_risk_score;
            document.getElementById("stat-low-count").textContent = stats.low_risk_count;
            document.getElementById("stat-suspicious-count").textContent = stats.suspicious_count;
            document.getElementById("stat-high-count").textContent = stats.high_risk_count;

            const engineElem = document.getElementById("stat-db-engine");
            if (engineElem) engineElem.textContent = stats.database_engine;

            // Render distribution progress bar
            const total = stats.total_scans || 1;
            const pLow = (stats.low_risk_count / total) * 100;
            const pSusp = (stats.suspicious_count / total) * 100;
            const pHigh = (stats.high_risk_count / total) * 100;

            const barLow = document.getElementById("bar-low");
            const barSusp = document.getElementById("bar-suspicious");
            const barHigh = document.getElementById("bar-high");

            if (barLow) barLow.style.width = `${pLow}%`;
            if (barSusp) barSusp.style.width = `${pSusp}%`;
            if (barHigh) barHigh.style.width = `${pHigh}%`;

            // Top Rules Leaderboard
            const topRulesTbody = document.getElementById("top-rules-tbody");
            if (topRulesTbody) {
                topRulesTbody.innerHTML = "";
                const rules = stats.top_rules || [];
                if (rules.length === 0) {
                    topRulesTbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:#94a3b8; padding: 1.5rem;">No rules triggered yet.</td></tr>';
                } else {
                    rules.forEach((r, idx) => {
                        const tr = document.createElement("tr");
                        tr.innerHTML = `
                            <td><span class="rule-id-pill">${r.rule_id}</span></td>
                            <td><strong>${r.rule_name}</strong></td>
                            <td><span style="color: #94a3b8;">${r.category}</span></td>
                            <td><strong style="color: #38bdf8;">${r.trigger_count}</strong> times</td>
                        `;
                        topRulesTbody.appendChild(tr);
                    });
                }
            }
        } catch (err) {
            console.error("Failed to load telemetry stats:", err);
        }
    }

    loadStats();
}
