// Safe HTML escaping for dashboard values.
function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, function (char) {
        return {
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;"
        }[char];
    });
}

// ============================================================
// AUTHENTICATION
// ============================================================

const TOKEN_KEY = "cyber_digital_twin_access_token";

const ROLE_KEY =
    "cyber_digital_twin_user_role";


let currentUserRole = null;


function getUserRole() {

    return sessionStorage.getItem(
        ROLE_KEY
    );

}


function saveUserRole(
    role
) {

    sessionStorage.setItem(
        ROLE_KEY,
        role
    );

    currentUserRole =
        role;

}


function clearUserRole() {

    sessionStorage.removeItem(
        ROLE_KEY
    );

    currentUserRole =
        null;

}


function decodeJwtPayload(
    token
) {

    try {

        const payload =
            token.split(".")[1];


        const normalized =
            payload
                .replace(/-/g, "+")
                .replace(/_/g, "/");


        const decoded =
            atob(
                normalized
            );


        return JSON.parse(
            decoded
        );

    }

    catch (error) {

        console.error(
            "JWT PAYLOAD DECODE ERROR:",
            error
        );


        return null;

    }

}

let refreshIntervals = [];


let dashboardInitialized = false;

function getAccessToken() {

    return sessionStorage.getItem(
        TOKEN_KEY
    );

}


function saveAccessToken(
    token
) {

    sessionStorage.setItem(
        TOKEN_KEY,
        token
    );

}


function clearAccessToken() {

    sessionStorage.removeItem(
        TOKEN_KEY
    );

}


function lockDashboard() {

    document.body.classList.add(
        "auth-locked"
    );


    const loginScreen =
        document.getElementById(
            "loginScreen"
        );


    if (loginScreen) {

        loginScreen.style.display =
            "flex";

    }

}

function unlockDashboard() {

    document.body.classList.remove(
        "auth-locked"
    );


    const loginScreen =
        document.getElementById(
            "loginScreen"
        );


    if (loginScreen) {

        loginScreen.style.display =
            "none";

    }

}

function showLoginMessage(
    message
) {

    const element =
        document.getElementById(
            "loginMessage"
        );

    if (!element) {
        return;
    }

    element.textContent =
        message;

}

async function logout() {

    const token = getAccessToken();

    // Revoke the token on the backend
    if (token) {

        try {

            await fetch(
                `${API}/auth/logout`,
                {
                    method: "POST",
                    headers: {
                        "Authorization": `Bearer ${token}`
                    }
                }
            );

        }

        catch (error) {

            console.error(
                "Server logout request failed:",
                error
            );

        }

    }

    // Clear the browser session
    clearAccessToken();

    clearUserRole();

    refreshIntervals.forEach(
        (intervalId) => {
            clearInterval(intervalId);
        }
    );

    refreshIntervals = [];

    const logoutContainer =
        document.getElementById("logoutContainer");

    if (logoutContainer) {
        logoutContainer.remove();
    }

    dashboardInitialized = false;

    lockDashboard();

    showLoginMessage(
        "Session ended. Please login again."
    );
}

async function apiFetch(
    url,
    options = {}
) {

    const token =
        getAccessToken();


    const headers = new Headers(
        options.headers || {}
    );


    if (token) {

        headers.set(
            "Authorization",
            `Bearer ${token}`
        );

    }


    const response =
        await fetch(
            url,
            {
                ...options,
                headers
            }
        );


    if (response.status === 401) {

        logout();

        throw new Error(
            "Authentication required"
        );

    }


    return response;

}


async function login(
    username,
    password
) {

    const response =
        await fetch(
            `${API}/auth/login`,
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify(
                    {
                        username,
                        password
                    }
                )
            }
        );


    const data =
        await response.json();


    if (!response.ok) {

        throw new Error(
            data.detail ||
            "Login failed"
        );

    }


    if (!data.access_token) {

        throw new Error(
            "Authentication token not received"
        );

    }


saveAccessToken(
    data.access_token
);


const payload =
    decodeJwtPayload(
        data.access_token
    );


if (
    !payload ||
    !payload.role ||
    !payload.exp ||
    payload.exp <= Date.now() / 1000
) {

    clearAccessToken();
    clearUserRole();

    throw new Error(
        "Invalid or expired authentication token."
    );

}

saveUserRole(
    payload.role
);


console.log(
    "Authenticated role:",
    payload.role
);


return data;

}


async function handleLogin(
    event
) {

    event.preventDefault();


    const username =
        document.getElementById(
            "loginUsername"
        ).value.trim();


    const password =
        document.getElementById(
            "loginPassword"
        ).value;


    const button =
        document.getElementById(
            "loginButton"
        );


    if (!username || !password) {

        showLoginMessage(
            "Username and password are required."
        );

        return;

    }


    button.disabled = true;

    button.textContent =
        "Logging in...";


    showLoginMessage(
        ""
    );


    try {

        const data =
            await login(
                username,
                password
            );


        unlockDashboard();


        showLoginMessage(
            ""
        );


        addLogoutButton(
            data.username
        );


        initializeDashboard();


    }

    catch (error) {

        console.error(
            "LOGIN ERROR:",
            error
        );


        clearAccessToken();


        showLoginMessage(
            error.message ||
            "Invalid username or password."
        );

    }

    finally {

        button.disabled = false;

        button.textContent =
            "Login";

    }

}


function addLogoutButton(
    username
) {

    let logoutContainer =
        document.getElementById(
            "logoutContainer"
        );

    // Create the container only if it does not exist
    if (!logoutContainer) {

        logoutContainer =
            document.createElement(
                "div"
            );

        logoutContainer.id =
            "logoutContainer";

        document.body.prepend(
            logoutContainer
        );
    }

    // Always update the current user's identity
    logoutContainer.innerHTML = `

        <span>

            Logged in as:

            <strong>
                ${username}
            </strong>

            &nbsp; | &nbsp;

            Role:

            <strong>
                ${
                    currentUserRole
                        ? currentUserRole.toUpperCase()
                        : "UNKNOWN"
                }
            </strong>

        </span>

        <button
            id="logoutButton"
            type="button"
        >
            Logout
        </button>

    `;

    // Attach logout event listener
    document
        .getElementById(
            "logoutButton"
        )
        .addEventListener(
            "click",
            logout
        );

}

function initializeDashboard() {

    if (dashboardInitialized) {

        console.log(
            "=== DASHBOARD ALREADY INITIALIZED ==="
        );

        return;

    }


    dashboardInitialized = true;

    // ============================================================
// ROLE-BASED FRONTEND VISIBILITY
// ============================================================

const responseSection =
    document.getElementById(
        "securityResponseExecutionSection"
    );

if (responseSection) {

    responseSection.style.display =
        currentUserRole === "admin"
            ? ""
            : "none";

}

    console.log(
        "=== INITIALIZING AUTHENTICATED DASHBOARD ==="
    );

    loadDashboard();

    // Phase 27.2 - Fleet overview refresh
    loadFleetOverview();

    // Phase 27.3 - Individual host drill-down
    document.getElementById("fleetHostGrid")?.addEventListener(
        "click",
        event => {
            const button = event.target.closest("[data-fleet-host]");

            if (button) {
                openFleetHostDetails(button.dataset.fleetHost);
            }
        }
    );

    document.getElementById("fleetDetailClose")?.addEventListener(
        "click",
        () => {
            document.getElementById("fleetHostDetails").hidden = true;
        }
    );

    refreshIntervals.push(
        setInterval(
            loadFleetOverview,
            10000
        )
    );

    document.getElementById("fleetRefreshButton")?.addEventListener(
        "click",
        loadFleetOverview
    );

    document.getElementById("fleetSearch")?.addEventListener(
        "input",
        loadFleetOverview
    );

    document.getElementById("fleetStatusFilter")?.addEventListener(
        "change",
        loadFleetOverview
    );

document.getElementById("fleetGroupFilter")?.addEventListener(
    "change",
    loadFleetOverview
);

document.getElementById("fleetClassificationFilter")?.addEventListener(
    "change",
    loadFleetOverview
);

document.getElementById("fleetTagFilter")?.addEventListener(
    "change",
    loadFleetOverview
);

    refreshIntervals.push(
        setInterval(
            loadDashboard,
            5000
        )
    );

    // Infrastructure health refresh
    loadInfrastructureHealth();

    refreshIntervals.push(
        setInterval(
            loadInfrastructureHealth,
            5000
        )
    );

    refreshIntervals.push(
        setInterval(
            loadHistory,
            5000
        )
    );

    loadHistory();

    loadAnomalies();

    loadSSHEvents();

    loadThreatIntelligence();

    document.getElementById(
        "refreshThreatIntelligenceButton"
    )?.addEventListener(
        "click",
        loadThreatIntelligence
    );

    loadSecurityAlerts();

    loadNotificationHistory();

    loadDeliveryHealth();

    loadNotificationSettings();

    loadNotificationSettingsAudit();

    loadNotificationAnalytics();

    // Notification Policy Simulator

    loadNotificationSimulationHistory();

    document.getElementById(
        "runNotificationSimulationButton"
    )?.addEventListener(
        "click",
        runNotificationSimulation
    );

    document.getElementById(
        "refreshNotificationSimulationHistoryButton"
    )?.addEventListener(
        "click",
        loadNotificationSimulationHistory
    );

document.getElementById(
    "analyticsRefreshButton"
)?.addEventListener(
    "click",
    loadNotificationAnalytics
);

document.getElementById(
    "analyticsPeriod"
)?.addEventListener(
    "change",
    loadNotificationAnalytics
);

document.getElementById(
    "analyticsDays"
)?.addEventListener(
    "change",
    loadNotificationAnalytics
);

    loadIncidentReminders();

    loadSecurityIncidents();

    loadSecurityCampaigns();

    loadCrossServerCampaigns();

    loadSecurityResponses();

if (
    currentUserRole === "admin"
) {

    loadResponseExecution();

}
    loadSecurityDecisions();

// Phase 23: Predictive Security Analytics

loadPredictiveAnalytics();

refreshIntervals.push(
    setInterval(
        loadPredictiveAnalytics,
        30000
    )
);

    refreshIntervals.push(
        setInterval(
            loadCrossServerCampaigns,
            5000
        )
    );

    loadSecurityResponseAudit();

    // Phase 25: Process and Service Security Dashboard
    loadProcessServiceDashboard();

    refreshIntervals.push(
        setInterval(
            loadProcessServiceDashboard,
            30000
        )
    );

    // Phase 26: Network Security Dashboard
    loadNetworkSecurityDashboard();

    refreshIntervals.push(
        setInterval(
            loadNetworkSecurityDashboard,
            30000
        )
    );

    startAutoRefresh();


    console.log(
        "=== CYBER DIGITAL TWIN AUTO-REFRESH ENABLED ==="
    );

}


function startAutoRefresh() {

    refreshIntervals.forEach(
        (intervalId) => {

            clearInterval(
                intervalId
            );

        }
    );


    refreshIntervals = [];


    refreshIntervals.push(
        setInterval(
            loadDashboard,
            5000
        )
    );


    refreshIntervals.push(
        setInterval(
            loadDeliveryHealth,
            5000
        )
    );

    refreshIntervals.push(
        setInterval(
            loadInfrastructureHealth,
            5000
        )
    );

    refreshIntervals.push(
        setInterval(
            loadHistory,
            5000
        )
    );


    refreshIntervals.push(
        setInterval(
            loadAnomalies,
            5000
        )
    );


    refreshIntervals.push(
        setInterval(
            loadSSHEvents,
            5000
        )
    );


    refreshIntervals.push(
        setInterval(
            loadSecurityAlerts,
            5000
        )
    );

    refreshIntervals.push(
        setInterval(
            loadNotificationHistory,
            5000
        )
    );


    refreshIntervals.push(
        setInterval(
            loadIncidentReminders,
            5000
        )
    );


    refreshIntervals.push(
        setInterval(
            loadSecurityIncidents,
            5000
        )
    );


    refreshIntervals.push(
        setInterval(
            loadSecurityCampaigns,
            5000
        )
    );


    refreshIntervals.push(
        setInterval(
            loadSecurityResponses,
            5000
        )
    );


    if (currentUserRole === "admin") {

        refreshIntervals.push(
            setInterval(
                loadResponseExecution,
                5000
            )
        );

    }


    refreshIntervals.push(
        setInterval(
            loadSecurityResponseAudit,
            5000
        )
    );


    refreshIntervals.push(
        setInterval(
            loadSecurityDecisions,
            5000
        )
    );

    refreshIntervals.push(
        setInterval(
            loadThreatIntelligence,
            30000
        )
    );

}

document.addEventListener(
    "DOMContentLoaded",
    () => {

        lockDashboard();


        const loginForm =
            document.getElementById(
                "loginForm"
            );


        if (loginForm) {

            loginForm.addEventListener(
                "submit",
                handleLogin
            );

        }


        const existingToken =
            getAccessToken();


        if (existingToken) {

            const payload =
                decodeJwtPayload(existingToken);

            const role =
                payload?.role?.toLowerCase();

            const validRoles = [
                "admin",
                "analyst",
                "viewer"
            ];

if (
    !payload ||
    !validRoles.includes(role) ||
    !payload.exp ||
    payload.exp <= Date.now() / 1000
) {

                logout();
                return;
            }

            saveUserRole(role);

            unlockDashboard();

            addLogoutButton(
                payload.username || payload.sub || "user"
            );

            initializeDashboard();

        }

    }
);

console.log("=== CYBER DIGITAL TWIN APP.JS LOADED ===");

const API = "/api";

let cpuChart;
let memoryChart;
let diskChart;

let notificationEventTrendChart;
let notificationChannelChart;
let notificationSeverityChart;
let incidentDeliveryChart;
let incidentRetryChart;


// ============================================================
// PHASE 27.5 - CROSS-SERVER RESOURCE COMPARISON
// ============================================================

let fleetComparisonChart = null;

function renderFleetResourceComparison(hosts) {

    const canvas = document.getElementById("fleetComparisonChart");
    const rankingContainer = document.getElementById("fleetComparisonRanking");

    if (!canvas || !rankingContainer) {
        return;
    }

    const validHosts = hosts.filter(host =>
        host.cpu_usage !== null &&
        host.cpu_usage !== undefined &&
        host.memory_usage !== null &&
        host.memory_usage !== undefined &&
        host.disk_usage !== null &&
        host.disk_usage !== undefined
    );

    if (fleetComparisonChart) {
        fleetComparisonChart.destroy();
        fleetComparisonChart = null;
    }

    if (validHosts.length === 0) {
        rankingContainer.innerHTML =
            "<p>No complete resource metrics are available for comparison.</p>";
        return;
    }

    const labels = validHosts.map(host => host.hostname);

    fleetComparisonChart = new Chart(canvas, {
        type: "bar",
        data: {
            labels: labels,
            datasets: [
                {
                    label: "CPU (%)",
                    data: validHosts.map(host => Number(host.cpu_usage))
                },
                {
                    label: "Memory (%)",
                    data: validHosts.map(host => Number(host.memory_usage))
                },
                {
                    label: "Disk (%)",
                    data: validHosts.map(host => Number(host.disk_usage))
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    title: {
                        display: true,
                        text: "Usage (%)"
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: "Monitored Servers"
                    }
                }
            },
            plugins: {
                legend: {
                    display: true,
                    position: "top"
                }
            }
        }
    });

    const metrics = [
        { key: "cpu_usage", label: "CPU" },
        { key: "memory_usage", label: "Memory" },
        { key: "disk_usage", label: "Disk" }
    ];

    rankingContainer.innerHTML = metrics.map(metric => {

        const ranked = [...hosts]
            .filter(host =>
                host[metric.key] !== null &&
                host[metric.key] !== undefined
            )
            .sort((a, b) =>
                Number(b[metric.key]) - Number(a[metric.key])
            );

        const highest = ranked[0];

        return `
            <div class="fleet-ranking-item">
                <strong>${metric.label} – Highest usage</strong>
                <span>
                    ${highest
                        ? `${escapeHtml(highest.hostname)}: ${escapeHtml(highest[metric.key])}%`
                        : "No data"}
                </span>
            </div>
        `;
    }).join("");
}

// ============================================================
// PHASE 27.2 - MULTI-SERVER FLEET OVERVIEW
// ============================================================

async function loadFleetSecurityRisk() {
    const rows = document.getElementById("fleetRiskHostRows");
    if (!rows) return;

    try {
        const response = await apiFetch(`${API}/fleet/security-risk`, {
            method: "GET",
            cache: "no-store"
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        const fleet = data.fleet || {};
        const distribution = fleet.risk_distribution || {};

        const score = Number(fleet.fleet_risk_score ?? 0);
        const level = String(fleet.fleet_risk_level || "UNKNOWN").toUpperCase();

        document.getElementById("fleetRiskScore").textContent =
            Number.isFinite(score) ? score.toFixed(2) : "--";

        const levelElement = document.getElementById("fleetRiskLevel");
        levelElement.textContent = level;
        levelElement.className = `risk-level-${level.toLowerCase()}`;

        document.getElementById("fleetRiskIncidents").textContent =
            fleet.recent_incidents ?? 0;

        document.getElementById("fleetRiskCampaigns").textContent =
            fleet.active_cross_server_campaigns ?? 0;

        document.getElementById("fleetRiskDistribution").innerHTML =
            ["LOW", "MEDIUM", "HIGH", "CRITICAL"].map(name => `
                <div class="fleet-risk-distribution-item risk-border-${name.toLowerCase()}">
                    <span>${name}</span>
                    <strong>${Number(distribution[name] || 0)}</strong>
                </div>
            `).join("");

        const hosts = Array.isArray(data.hosts) ? data.hosts : [];

        if (!hosts.length) {
            rows.innerHTML = '<tr><td colspan="7">No monitored hosts available.</td></tr>';
        } else {
            rows.innerHTML = hosts
                .sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0))
                .map(host => {
                    const activity = host.security_activity || {};
                    const risk = String(host.risk_level || "UNKNOWN").toUpperCase();
                    const riskScore = Number(host.risk_score || 0);

                    return `
                        <tr>
                            <td>${escapeHtml(host.hostname || "Unknown")}</td>
                            <td>${escapeHtml(host.classification || "Unclassified")}</td>
                            <td>${Number.isFinite(riskScore) ? riskScore.toFixed(2) : "--"}</td>
                            <td><span class="risk-level-${risk.toLowerCase()}">${escapeHtml(risk)}</span></td>
                            <td>${Number(activity.attacks_24h || 0)}</td>
                            <td>${Number(activity.recent_incidents || 0)}</td>
                            <td>${Number(activity.active_campaigns || 0)}</td>
                        </tr>
                    `;
                }).join("");
        }

        const updated = data.generated_at
            ? new Date(data.generated_at).toLocaleString()
            : new Date().toLocaleString();

        document.getElementById("fleetRiskUpdated").textContent =
            `Updated: ${updated}`;

    } catch (error) {
        console.error("Fleet security risk error:", error);
        rows.innerHTML =
            '<tr><td colspan="7">Unable to load fleet security risk. Check API and login status.</td></tr>';
    }
}

async function loadFleetOverview() {

    const hostGrid = document.getElementById("fleetHostGrid");

    if (!hostGrid) {
        return;
    }

    try {

        const response = await apiFetch(
            `${API}/fleet/overview`,
            {
                method: "GET",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        loadFleetSecurityRisk();
        const summary = data.summary || {};

        document.getElementById("fleetTotal").innerText =
            summary.total ?? 0;

        document.getElementById("fleetOnline").innerText =
            summary.online ?? 0;

        document.getElementById("fleetHealthy").innerText =
            summary.healthy ?? 0;

        document.getElementById("fleetWarning").innerText =
            summary.warning ?? 0;

        document.getElementById("fleetCritical").innerText =
            summary.critical ?? 0;

        const hosts = Array.isArray(data.hosts) ? data.hosts : [];

        renderFleetResourceComparison(hosts);

// Populate unique group options from fleet data.
const groupFilter = document.getElementById("fleetGroupFilter");
const selectedGroup = groupFilter?.value || "ALL";

if (groupFilter) {
    const groups = [...new Set(
        hosts.map(host => host.group_name).filter(Boolean)
    )].sort();

    groupFilter.innerHTML =
        '<option value="ALL">All groups</option>' +
        groups.map(group =>
            `<option value="${escapeHtml(group)}">${escapeHtml(group)}</option>`
        ).join("");

    groupFilter.value = groups.includes(selectedGroup)
        ? selectedGroup
        : "ALL";
}

// Populate unique tag options from fleet data.
const tagFilter = document.getElementById("fleetTagFilter");
const selectedTag = tagFilter?.value || "ALL";

if (tagFilter) {
    const tags = [...new Set(
        hosts.flatMap(host =>
            Array.isArray(host.tags) ? host.tags : []
        )
    )].sort();

    tagFilter.innerHTML =
        '<option value="ALL">All tags</option>' +
        tags.map(tag =>
            `<option value="${escapeHtml(tag)}">${escapeHtml(tag)}</option>`
        ).join("");

    tagFilter.value = tags.includes(selectedTag)
        ? selectedTag
        : "ALL";
}

        function renderFleetHosts() {

            const searchValue =
                (document.getElementById("fleetSearch")?.value || "")
                    .trim()
                    .toLowerCase();

const statusValue =
    document.getElementById("fleetStatusFilter")?.value || "ALL";

const groupValue =
    document.getElementById("fleetGroupFilter")?.value || "ALL";

const classificationValue =
    document.getElementById("fleetClassificationFilter")?.value || "ALL";

const tagValue =
    document.getElementById("fleetTagFilter")?.value || "ALL";

const filteredHosts = hosts.filter(host => {

    const hostname = String(host.hostname || "").toLowerCase();
    const ipAddress = String(host.ip_address || "").toLowerCase();

    const matchesSearch =
        hostname.includes(searchValue) ||
        ipAddress.includes(searchValue);

    const matchesStatus =
        statusValue === "ALL" || host.status === statusValue;

    const matchesGroup =
        groupValue === "ALL" || host.group_name === groupValue;

    const matchesClassification =
        classificationValue === "ALL" ||
        host.classification === classificationValue;

    const hostTags = Array.isArray(host.tags) ? host.tags : [];

    const matchesTag =
        tagValue === "ALL" || hostTags.includes(tagValue);

    return (
        matchesSearch &&
        matchesStatus &&
        matchesGroup &&
        matchesClassification &&
        matchesTag
    );
});
            if (filteredHosts.length === 0) {
                hostGrid.innerHTML =
                    '<p class="fleet-empty">No servers match your filters.</p>';
                return;
            }

            hostGrid.innerHTML = filteredHosts.map(host => {

                const status = String(host.status || "Unknown");

                const statusClasses = {
                    "Healthy": "healthy",
                    "Warning": "warning",
                    "Critical": "critical",
                    "Stale": "stale",
                    "No Data": "no-data",
                    "Disabled": "disabled"
                };

                const statusClass =
                    statusClasses[status] || "unknown";

                const metricValue = value =>
                    value === null || value === undefined
                        ? "N/A"
                        : `${escapeHtml(value)}%`;

                const lastSeen = host.last_seen
                    ? new Date(host.last_seen).toLocaleString()
                    : "Never";

                return `
                    <article class="fleet-host-card">
                        <div class="fleet-host-title">
                            <div>
                                <h3>${escapeHtml(host.hostname || "Unknown host")}</h3>
                                <p>${escapeHtml(host.ip_address || "No IP address")}</p>
                            </div>

                            <span class="fleet-status ${statusClass}">
                                ${escapeHtml(status)}
                            </span>
                        </div>

                        <div class="fleet-organization">
                            <p><strong>Group:</strong> ${escapeHtml(host.group_name || "Unassigned")}</p>
                            <p><strong>Classification:</strong> ${escapeHtml(host.classification || "Unclassified")}</p>
                            <p><strong>Tags:</strong> ${escapeHtml(
                                Array.isArray(host.tags) && host.tags.length
                                    ? host.tags.join(", ")
                                    : "No tags"
                            )}</p>
                        </div>

                        <div class="fleet-metrics">
                            <div>
                                <span>CPU Usage</span>
                                <strong>${metricValue(host.cpu_usage)}</strong>
                            </div>

                            <div>
                                <span>Memory Usage</span>
                                <strong>${metricValue(host.memory_usage)}</strong>
                            </div>

                            <div>
                                <span>Disk Usage</span>
                                <strong>${metricValue(host.disk_usage)}</strong>
                            </div>
                        </div>

                        <div class="fleet-host-footer">
                            <span>Last seen: ${escapeHtml(lastSeen)}</span>
                        </div>

                        <button
                            type="button"
                            class="fleet-detail-button"
                            data-fleet-host="${escapeHtml(host.hostname || "")}"
                        >
                            View Details
                        </button>
                    </article>
                `;

            }).join("");
        }

        renderFleetHosts();

        const updated = new Date().toLocaleString();

        document.getElementById("fleetLastUpdated").innerText =
            `Last updated: ${updated}`;

    } catch (error) {

        console.error("Fleet overview error:", error);

        hostGrid.innerHTML =
            '<p class="fleet-error">Unable to load fleet information. Check API connectivity and login status.</p>';

    }
}



// ============================================================
// PHASE 27.3 - INDIVIDUAL SERVER DETAILS
// ============================================================

async function openFleetHostDetails(hostname) {

    const panel = document.getElementById("fleetHostDetails");
    const information = document.getElementById("fleetDetailInformation");
    const historyBody = document.getElementById("fleetDetailHistory");
    const message = document.getElementById("fleetDetailMessage");

    panel.hidden = false;
    panel.scrollIntoView({ behavior: "smooth", block: "start" });

    document.getElementById("fleetDetailTitle").innerText =
        `Server: ${hostname}`;

    document.getElementById("fleetDetailSubtitle").innerText =
        "Loading registered host information...";

    information.innerHTML = "<p>Loading host details...</p>";
    historyBody.innerHTML =
        '<tr><td colspan="4">Loading resource history...</td></tr>';
    message.innerText = "";

    try {

        const safeHostname = encodeURIComponent(hostname);

        const [hostResponse, metricsResponse] = await Promise.all([
            apiFetch(
                `${API}/inventory/hosts/${safeHostname}`,
                { method: "GET", cache: "no-store" }
            ),
            apiFetch(
                `${API}/inventory/hosts/${safeHostname}/metrics?limit=50`,
                { method: "GET", cache: "no-store" }
            )
        ]);

        if (!hostResponse.ok) {
            throw new Error(`Host details HTTP ${hostResponse.status}`);
        }

        if (!metricsResponse.ok) {
            throw new Error(`Metrics history HTTP ${metricsResponse.status}`);
        }

        const host = await hostResponse.json();
        const history = await metricsResponse.json();

        document.getElementById("fleetDetailTitle").innerText =
            `Server: ${host.hostname}`;

        document.getElementById("fleetDetailSubtitle").innerText =
            `${host.ip_address} | ${host.enabled ? "Enabled" : "Disabled"}`;

        const formatDate = value =>
            value ? new Date(value).toLocaleString() : "Not available";

        const fields = [
            ["Hostname", host.hostname],
            ["IP Address", host.ip_address],
            ["Username", host.username || "Not configured"],
            ["Authentication Method", host.auth_method || "Not available"],
            ["Registration Source", host.registration_source || "Not available"],
            ["Description", host.description || "No description"],
            ["Enabled", host.enabled ? "Yes" : "No"],
            ["Registered At", formatDate(host.registered_at)],
            ["Last Updated", formatDate(host.updated_at)],
            ["Last Seen", formatDate(host.last_seen)]
        ];

        information.innerHTML = fields.map(([label, value]) => `
            <div class="fleet-detail-item">
                <span>${escapeHtml(label)}</span>
                <strong>${escapeHtml(value)}</strong>
            </div>
        `).join("");

        const metrics = Array.isArray(history.metrics)
            ? history.metrics
            : [];

        if (metrics.length === 0) {

            historyBody.innerHTML =
                '<tr><td colspan="4">No historical metrics available.</td></tr>';

        } else {

            historyBody.innerHTML = metrics.map(metric => `
                <tr>
                    <td>${escapeHtml(formatDate(metric.collected_at))}</td>
                    <td>${escapeHtml(metric.cpu_usage ?? "N/A")}%</td>
                    <td>${escapeHtml(metric.memory_usage ?? "N/A")}%</td>
                    <td>${escapeHtml(metric.disk_usage ?? "N/A")}%</td>
                </tr>
            `).join("");

        }

        message.innerText =
            `Loaded ${metrics.length} historical metric records.`;

    } catch (error) {

        console.error("Host details error:", error);

        information.innerHTML =
            '<p class="fleet-error">Unable to load host details.</p>';

        historyBody.innerHTML =
            '<tr><td colspan="4">Unable to load resource history.</td></tr>';

        message.innerText = error.message;

    }
}


// ============================================================
// LOAD INFRASTRUCTURE HEALTH
// ============================================================

async function loadInfrastructureHealth() {

    try {

        const response = await apiFetch(
            `${API}/infrastructure/health`,
            {
                method: "GET",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();

        document.getElementById("infraScore").innerText =
            `${data.health_score}/100`;

        document.getElementById("infraStatus").innerText =
            data.overall_status;

        document.getElementById("infraApi").innerText =
            data.components.api;

        document.getElementById("infraDatabase").innerText =
            data.components.database;

        document.getElementById("infraCollector").innerText =
            data.components.collector;

        document.getElementById("infraDisk").innerText =
            `${data.components.controller_disk.usage_percent}% used`;

        document.getElementById("infraHosts").innerText =
            Object.entries(data.hosts)
                .map(([name, host]) =>
                    `${name}: ${host.status}`
                )
                .join("\n");

    } catch (error) {

        console.error(
            "INFRASTRUCTURE HEALTH ERROR:",
            error
        );

        document.getElementById("infraStatus").innerText =
            "Connection Error";
    }
}

// ============================================================
// LOAD CURRENT HEALTH
// ============================================================

async function loadDashboard() {

    try {

        const response = await apiFetch(
            `${API}/health`,
            {
                method: "GET",
                mode: "cors",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const server = await response.json();

        document.getElementById("hostname").innerText =
            server.hostname;

        document.getElementById("status").innerText =
            server.status;

        document.getElementById("cpu").innerText =
            `${server.cpu_usage} %`;

        document.getElementById("memory").innerText =
            `${server.memory_usage} %`;

        document.getElementById("disk").innerText =
            `${server.disk_usage} %`;

    } catch (error) {

        console.error("DASHBOARD ERROR:", error);

        document.getElementById("hostname").innerText =
            "Connection Error";

        document.getElementById("status").innerText =
            "Offline";

        document.getElementById("cpu").innerText = "--";
        document.getElementById("memory").innerText = "--";
        document.getElementById("disk").innerText = "--";
    }
}


// ============================================================
// LOAD HISTORICAL DATA
// ============================================================

async function loadHistory() {

    try {

        const response = await apiFetch(
            `${API}/metrics/history?limit=50`,
            {
                method: "GET",
                mode: "cors",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const history = await response.json();

        const orderedHistory = [...history].reverse();

        const labels = orderedHistory.map(
            item =>
                new Date(
                    item.collected_at
                ).toLocaleTimeString()
        );

        const cpuData = orderedHistory.map(
            item => item.cpu_usage
        );

        const memoryData = orderedHistory.map(
            item => item.memory_usage
        );

        const diskData = orderedHistory.map(
            item => item.disk_usage
        );

        updateCharts(
            labels,
            cpuData,
            memoryData,
            diskData
        );

    } catch (error) {

        console.error("HISTORY ERROR:", error);
    }
}


// ============================================================
// LOAD AI ANOMALIES
// ============================================================

async function loadAnomalies() {

    try {

        const response = await apiFetch(
            `${API}/anomalies`,
            {
                method: "GET",
                mode: "cors",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const anomalies = await response.json();

        updateAnomaly(
            "cpuAnomaly",
            anomalies.cpu
        );

        updateAnomaly(
            "memoryAnomaly",
            anomalies.memory
        );

        updateAnomaly(
            "diskAnomaly",
            anomalies.disk
        );

    } catch (error) {

        console.error("ANOMALY ERROR:", error);

        updateAnomalyError("cpuAnomaly");
        updateAnomalyError("memoryAnomaly");
        updateAnomalyError("diskAnomaly");
    }
}


function updateAnomaly(elementId, result) {

    const element =
        document.getElementById(elementId);

    if (!element || !result) {
        return;
    }

    element.className = "anomaly-status";

    if (result.reason) {

        element.innerText =
            result.reason;

        element.classList.add("unknown");

        return;
    }

    if (result.is_anomaly === true) {

        element.innerText =
            "Anomaly";

        element.classList.add("anomaly");

        return;
    }

    if (
        result.score !== undefined &&
        result.score >= 2
    ) {

        element.innerText =
            "Warning";

        element.classList.add("warning");

        return;
    }

    element.innerText =
        "Normal";

    element.classList.add("normal");
}


function updateAnomalyError(elementId) {

    const element =
        document.getElementById(elementId);

    if (!element) {
        return;
    }

    element.innerText =
        "Unavailable";

    element.className =
        "anomaly-status unknown";
}


// ============================================================
// CREATE / UPDATE CHARTS
// ============================================================

function updateCharts(
    labels,
    cpuData,
    memoryData,
    diskData
) {

    if (cpuChart) {
        cpuChart.destroy();
    }

    if (memoryChart) {
        memoryChart.destroy();
    }

    if (diskChart) {
        diskChart.destroy();
    }

    cpuChart = new Chart(
        document.getElementById("cpuChart"),
        {
            type: "line",

            data: {
                labels: labels,

                datasets: [
                    {
                        label: "CPU Usage (%)",
                        data: cpuData,
                        tension: 0.3
                    }
                ]
            },

            options: {
                responsive: true,

                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100
                    }
                }
            }
        }
    );

    memoryChart = new Chart(
        document.getElementById("memoryChart"),
        {
            type: "line",

            data: {
                labels: labels,

                datasets: [
                    {
                        label: "Memory Usage (%)",
                        data: memoryData,
                        tension: 0.3
                    }
                ]
            },

            options: {
                responsive: true,

                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100
                    }
                }
            }
        }
    );

    diskChart = new Chart(
        document.getElementById("diskChart"),
        {
            type: "line",

            data: {
                labels: labels,

                datasets: [
                    {
                        label: "Disk Usage (%)",
                        data: diskData,
                        tension: 0.3
                    }
                ]
            },

            options: {
                responsive: true,

                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100
                    }
                }
            }
        }
    );
}


// ============================================================
// SSH SECURITY EVENTS
// ============================================================

async function loadSSHEvents() {

    try {

        const eventsResponse = await apiFetch(
            `${API}/ssh/events?limit=20`,
            {
                method: "GET",
                mode: "cors",
                cache: "no-store"
            }
        );

        if (!eventsResponse.ok) {
            throw new Error(
                `SSH events HTTP ${eventsResponse.status}`
            );
        }

        const events =
            await eventsResponse.json();


        const alertsResponse = await apiFetch(
            `${API}/security/alerts`,
            {
                method: "GET",
                mode: "cors",
                cache: "no-store"
            }
        );

        if (!alertsResponse.ok) {
            throw new Error(
                `Security alerts HTTP ${alertsResponse.status}`
            );
        }

        const alerts =
            await alertsResponse.json();
        const riskResponse = await apiFetch(
            `${API}/security/risk`,
            {
                method: "GET",
                mode: "cors",
                cache: "no-store"
            }
        );

        if (!riskResponse.ok) {
            throw new Error(
                `Security risk HTTP ${riskResponse.status}`
            );
        }

        const riskEvents = await riskResponse.json();

        const riskMap = new Map();

        riskEvents.forEach(event => {
            riskMap.set(event.id, event);
        });


        const alertMap = new Map();

        alerts.forEach(alert => {

            alertMap.set(
                alert.event_id,
                alert
            );

        });


        const table =
            document.getElementById(
                "sshEventsTable"
            );


        if (!table) {
            return;
        }


        let failed = 0;
        let successful = 0;

        events.forEach(event => {

            if (
                event.event_type ===
                "FAILED_LOGIN"
            ) {
                failed++;
            }

            if (
                event.event_type ===
                "SUCCESSFUL_LOGIN"
            ) {
                successful++;
            }

        });


        const failedLogins =
            document.getElementById(
                "failedLogins"
            );

        const successfulLogins =
            document.getElementById(
                "successfulLogins"
            );

        const highRiskEvents =
            document.getElementById(
                "highRiskEvents"
            );

        const criticalEvents =
            document.getElementById(
                "criticalEvents"
            );


        if (failedLogins) {
            failedLogins.textContent = failed;
        }

        if (successfulLogins) {
            successfulLogins.textContent =
                successful;
        }


        const highRiskCount =
            riskEvents.filter(
                event =>
                    event.risk_level === "HIGH"
            ).length;

        const criticalCount =
            riskEvents.filter(
                event =>
                    event.risk_level === "CRITICAL"
            ).length;

        if (highRiskEvents) {
            highRiskEvents.textContent =
                highRiskCount;
        }

        if (criticalEvents) {
            criticalEvents.textContent =
                criticalCount;
        }


        table.innerHTML = "";


        if (events.length === 0) {

            table.innerHTML = `
                <tr>
                    <td colspan="7">
                        No SSH events found
                    </td>
                </tr>
            `;

            return;
        }


        events.forEach(event => {

            const alert =
                alertMap.get(event.id);
            const riskEvent =
                riskMap.get(event.id);


            const riskScore =
                riskEvent
                    ? riskEvent.risk_score
                    : "-";

            const riskLevel =
                riskEvent
                    ? riskEvent.risk_level
                    : "-";

            const correlation =
                riskEvent && riskEvent.correlation_type
                    ? riskEvent.correlation_type
                    : riskEvent && riskEvent.attack_type
                        ? riskEvent.attack_type
                        : "-";

            const row =
                document.createElement("tr");


            row.innerHTML = `
                <td>
                    ${new Date(
                        event.event_time
                    ).toLocaleString()}
                </td>

                <td>
                    ${event.event_type}
                </td>

                <td>
                    ${event.username || "-"}
                </td>

                <td>
                    ${event.source_ip || "-"}
                </td>

                <td>
                    ${riskScore}
                </td>

                <td>
                    ${riskLevel}
                </td>

                <td>
                    ${correlation}
                </td>
            `;


            table.appendChild(row);

        });

    } catch (error) {

        console.error(
            "SSH EVENT ERROR:",
            error
        );
    }
}



// ============================================================
// INCIDENT NOTIFICATION DELIVERY HISTORY
// ============================================================

async function loadNotificationHistory() {

    try {

        const response = await apiFetch(
            `${API}/security/notification-history?limit=50`,
            {
                method: "GET",
                mode: "cors",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const records = await response.json();

        const table = document.getElementById(
            "notificationHistoryTable"
        );

        if (!table) {
            return;
        }

        table.innerHTML = "";

        if (records.length === 0) {

            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.colSpan = 10;
            cell.textContent = "No notification history available.";

            row.appendChild(cell);
            table.appendChild(row);

            return;
        }

        function formatTime(value) {

            if (!value) {
                return "-";
            }

            const date = new Date(value);

            return Number.isNaN(date.getTime())
                ? "-"
                : date.toLocaleString();
        }

        records.forEach(record => {

            const row = document.createElement("tr");

            const showError =
                currentUserRole === "admin" ||
                currentUserRole === "analyst";

            const values = [
                formatTime(record.created_at),
                record.incident_id,
                record.severity,
                record.priority,
                record.notification_channel,
                record.delivery_status,
                record.attempt_count,
                formatTime(record.last_attempt_at),
                formatTime(record.sent_at),
                showError
                    ? (record.error_message || "-")
                    : "-"
            ];

            values.forEach(value => {

                const cell = document.createElement("td");

                cell.textContent =
                    value === null || value === undefined
                        ? "-"
                        : String(value);

                row.appendChild(cell);

            });

            table.appendChild(row);

        });

    } catch (error) {

        console.error(
            "NOTIFICATION HISTORY ERROR:",
            error
        );

    }
}



// ============================================================
// INCIDENT ASSIGNMENT & ACKNOWLEDGEMENT REMINDERS
// ============================================================

async function loadIncidentReminders() {

    const table = document.getElementById(
        "incidentRemindersTable"
    );

    if (!table) {
        return;
    }

    // Viewers do not receive operational reminders.
    if (currentUserRole === "viewer") {

        table.innerHTML = "";

        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 9;
        cell.textContent = "No operational reminders available.";

        row.appendChild(cell);
        table.appendChild(row);

        return;
    }

    try {

        const response = await apiFetch(
            `${API}/security/reminders?limit=50`,
            {
                method: "GET",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const records = await response.json();

        table.innerHTML = "";

        if (records.length === 0) {

            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.colSpan = 9;
            cell.textContent = "No incident reminders available.";

            row.appendChild(cell);
            table.appendChild(row);

            return;
        }

        function formatTime(value) {

            if (!value) {
                return "-";
            }

            const date = new Date(value);

            return Number.isNaN(date.getTime())
                ? "-"
                : date.toLocaleString();
        }

        records.forEach(record => {

            const row = document.createElement("tr");

            const values = [
                formatTime(record.created_at),
                record.incident_id,
                record.severity,
                record.reminder_type === "UNASSIGNED"
                    ? "Unassigned Incident"
                    : "Awaiting Acknowledgement",
                record.recipient_username || "-",
                `${record.reminder_after_minutes} minutes`,
                record.reminder_cycle,
                record.delivery_status
            ];

            values.forEach(value => {

                const cell = document.createElement("td");

                cell.textContent =
                    value === null || value === undefined
                        ? "-"
                        : String(value);

                row.appendChild(cell);

            });

            const actionCell = document.createElement("td");

            if (record.delivery_status === "CREATED") {

                const button = document.createElement("button");

                button.type = "button";
                button.textContent = "Mark as Read";
                button.className = "reminder-read-button";

                button.addEventListener("click", async () => {

                    button.disabled = true;
                    button.textContent = "Updating...";

                    try {

                        const readResponse = await apiFetch(
                            `${API}/security/reminders/${record.id}/read`,
                            {
                                method: "POST"
                            }
                        );

                        if (!readResponse.ok) {
                            throw new Error(
                                `HTTP ${readResponse.status}`
                            );
                        }

                        await loadIncidentReminders();

                    } catch (error) {

                        console.error(
                            "MARK REMINDER AS READ ERROR:",
                            error
                        );

                        button.disabled = false;
                        button.textContent = "Retry";

                    }

                });

                actionCell.appendChild(button);

            } else if (record.delivery_status === "READ") {

                actionCell.textContent = "Read";

            } else {

                actionCell.textContent = "-";

            }

            row.appendChild(actionCell);
            table.appendChild(row);

        });

    } catch (error) {

        console.error(
            "INCIDENT REMINDER ERROR:",
            error
        );

        table.innerHTML = "";

        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 9;
        cell.textContent = "Unable to load incident reminders.";

        row.appendChild(cell);
        table.appendChild(row);

    }

}


// ============================================================
// SECURITY ALERTS
// ============================================================

async function loadSecurityAlerts() {

    try {

        const response =
            await apiFetch(
                `${API}/security/alerts`,
                {
                    method: "GET",
                    mode: "cors",
                    cache: "no-store"
                }
            );


        if (!response.ok) {
            throw new Error(
                `HTTP ${response.status}`
            );
        }


        const alerts =
            await response.json();


        const table =
            document.getElementById(
                "securityAlertsTable"
            );


        if (!table) {
            return;
        }


        table.innerHTML = "";


        if (alerts.length === 0) {

            table.innerHTML = `
                <tr>
                    <td colspan="6">
                        No security alerts
                    </td>
                </tr>
            `;

            return;
        }


        alerts.forEach(alert => {

            const row =
                document.createElement("tr");


            row.innerHTML = `
                <td>
                    ${new Date(
                        alert.event_time
                    ).toLocaleString()}
                </td>

                <td>
                    ${alert.event_type}
                </td>

                <td>
                    ${alert.username || "-"}
                </td>

                <td>
                    ${alert.source_ip || "-"}
                </td>

                <td>
                    ${alert.risk_score}
                </td>

                <td>
                    ${alert.reason}
                </td>
            `;


            table.appendChild(row);

        });

    } catch (error) {

        console.error(
            "SECURITY ALERT ERROR:",
            error
        );
    }
}


// ============================================================
// INCIDENT LIFECYCLE MANAGEMENT — ADMIN ONLY
// ============================================================

function getNextIncidentStatuses(status) {

    const transitions = {
        OPEN: ["INVESTIGATING"],
        INVESTIGATING: ["CONTAINED"],
        CONTAINED: ["RESOLVED"],
        RESOLVED: ["CLOSED"],
        CLOSED: []
    };

    return transitions[
        String(status || "OPEN").toUpperCase()
    ] || [];

}


// ============================================================
// UPDATE INCIDENT LIFECYCLE STATUS
// ============================================================

async function updateIncidentLifecycle(
    incidentId,
    status,
    button
) {

    if (currentUserRole !== "admin") {
        alert("Only administrators can update incident status.");
        return;
    }

    if (!incidentId || !status) {
        alert("Incident ID and status are required.");
        return;
    }

    try {

        if (button) {
            button.disabled = true;
            button.textContent = "Updating...";
        }

        const params = new URLSearchParams({
            status: status,
            notes: "Incident status updated from dashboard by admin"
        });

        const response = await apiFetch(
            `${API}/security/incidents/${encodeURIComponent(incidentId)}/status?${params.toString()}`,
            {
                method: "POST"
            }
        );

        const data = await response.json().catch(() => ({}));

        if (!response.ok) {
            throw new Error(
                data.detail || `HTTP ${response.status}`
            );
        }

        alert(`Incident status updated to ${status}.`);

        await loadSecurityIncidents();

    }

    catch (error) {

        console.error(
            "INCIDENT STATUS UPDATE ERROR:",
            error
        );

        alert(
            `Unable to update incident status: ${error.message}`
        );

    }

    finally {

        if (button) {
            button.disabled = false;
            button.textContent = "Update";
        }

    }

}

// ============================================================
// SECURITY INCIDENTS
// ============================================================

async function loadSecurityIncidents() {

    try {

        const response = await apiFetch(
            `${API}/security/incidents`,
            {
                method: "GET",
                mode: "cors",
                cache: "no-store"
            }
        );


        // ----------------------------------------------------
        // CHECK HTTP RESPONSE
        // ----------------------------------------------------

        if (!response.ok) {

            throw new Error(
                `Security incidents HTTP ${response.status}`
            );

        }


        // ----------------------------------------------------
        // READ INCIDENT DATA
        // ----------------------------------------------------

        const incidents =
            await response.json();


        // ----------------------------------------------------
        // FIND INCIDENT TABLE
        // ----------------------------------------------------

        const table =
            document.getElementById(
                "securityIncidentsTable"
            );


        if (!table) {

            console.error(
                "securityIncidentsTable not found"
            );

            return;

        }


        // Clear old data

        table.innerHTML = "";


        // ----------------------------------------------------
        // NO INCIDENTS
        // ----------------------------------------------------

        if (
            !Array.isArray(incidents) ||
            incidents.length === 0
        ) {

            table.innerHTML = `
                <tr>
                    <td colspan="14">
                        No security incidents detected
                    </td>
                </tr>
            `;

            return;

        }


        // ----------------------------------------------------
        // PROCESS EACH INCIDENT
        // ----------------------------------------------------

        incidents.forEach(
            incident => {


                // =================================================
                // ATTACK RATE
                // =================================================

                let attackRate = 0;


                if (
                    incident.attack_rate !== undefined &&
                    incident.attack_rate !== null
                ) {

                    attackRate =
                        Number(
                            incident.attack_rate
                        ).toFixed(2);

                }

                else if (
                    incident.duration_seconds !== undefined &&
                    incident.duration_seconds > 0
                ) {

                    attackRate =
                        (
                            incident.total_attempts /
                            (
                                incident.duration_seconds /
                                60
                            )
                        ).toFixed(2);

                }

                else {

                    attackRate =
                        incident.total_attempts || 0;

                }


                // =================================================
                // FAILURE RATE
                // =================================================

                let failureRate = 0;


                if (
                    incident.failure_rate !== undefined &&
                    incident.failure_rate !== null
                ) {

                    failureRate =
                        Number(
                            incident.failure_rate
                        ).toFixed(2);

                }

                else if (
                    incident.total_attempts > 0
                ) {

                    failureRate =
                        (
                            (
                                incident.failed_logins /
                                incident.total_attempts
                            ) * 100
                        ).toFixed(2);

                }


                // =================================================
                // AI INCIDENT CONFIDENCE
                // =================================================
                //
                // IMPORTANT:
                //
                // The confidence is NOT calculated here.
                //
                // It comes directly from:
                //
                // backend/ai/incident_confidence.py
                //
                // Backend API:
                //
                // /security/incidents
                //
                // Fields:
                //
                // confidence_score
                // confidence_level
                // confidence_reasons
                //
                // =================================================


                const confidenceScore =
                    incident.confidence_score !== undefined
                        ? incident.confidence_score
                        : 0;


                const confidenceLevel =
                    incident.confidence_level ||
                    "UNKNOWN";


                const confidenceReasons =
                    Array.isArray(
                        incident.confidence_reasons
                    )
                        ? incident.confidence_reasons.join(
                            ", "
                        )
                        : "-";


                // =================================================
                // INCIDENT SEVERITY
                // =================================================

                const severity =
                    incident.severity ||
                    "UNKNOWN";


                // =================================================
                // INCIDENT TYPE
                // =================================================

                const incidentType =
                    incident.incident_type ||
                    incident.attack_pattern ||
                    "-";


                // =================================================
                // USERNAME
                // =================================================

                const username =
                    incident.username ||
                    "-";


                // =================================================
                // SOURCE IP
                // =================================================

                const sourceIP =
                    incident.source_ip ||
                    "-";


                // =================================================
                // CREATE TABLE ROW
                // =================================================

                const row =
                    document.createElement("tr");


                row.innerHTML = `

                    <td>
                        <strong>
                            ${severity}
                        </strong>
                    </td>


                    <td>
                        ${incidentType}
                    </td>


                    <td>
                        ${username}
                    </td>


                    <td>
                        ${sourceIP}
                    </td>


                    <td>
                        ${incident.total_attempts ?? 0}
                    </td>


                    <td>
                        ${incident.failed_logins ?? 0}
                    </td>


                    <td>
                        ${incident.invalid_users ?? 0}
                    </td>


                    <td>
                        ${attackRate}
                    </td>


                    <td>
                        ${failureRate}%
                    </td>


                    <td>

                        <strong>
                            ${confidenceScore}%
                        </strong>

                        <br>

                        <span>
                            ${confidenceLevel}
                        </span>

                        <br>

                        <small>
                            ${confidenceReasons}
                        </small>

                    </td>


                    <td>
                        ${
                            incident.start_time
                                ? new Date(
                                    incident.start_time
                                  ).toLocaleString()
                                : "-"
                        }
                    </td>


                    <td>
                        ${
                            incident.end_time
                                ? new Date(
                                    incident.end_time
                                  ).toLocaleString()
                                : "-"
                        }
                    </td>

                    <td>
                        ${incident.lifecycle_status || "OPEN"}
                    </td>

                    <td></td>
                `;


                // Add row to table

                // =====================================================
// ADMIN INCIDENT LIFECYCLE CONTROLS
// =====================================================

const actionCell = row.lastElementChild;

const incidentStatus = String(
    incident.lifecycle_status || "OPEN"
).toUpperCase();

if (currentUserRole === "admin") {

    const nextStatuses =
        getNextIncidentStatuses(incidentStatus);

    if (nextStatuses.length > 0 && incident.incident_id) {

        const statusSelect =
            document.createElement("select");

        statusSelect.style.marginRight = "8px";

        statusSelect.setAttribute(
            "aria-label",
            "Next incident lifecycle status"
        );

        nextStatuses.forEach((status) => {

            const option =
                document.createElement("option");

            option.value = status;
            option.textContent = status;

            statusSelect.appendChild(option);

        });

        const updateButton =
            document.createElement("button");

        updateButton.textContent = "Update";

        updateButton.addEventListener("click", () => {

            updateIncidentLifecycle(
                incident.incident_id,
                statusSelect.value,
                updateButton
            );

        });

        actionCell.appendChild(statusSelect);
        actionCell.appendChild(updateButton);

    } else {

        actionCell.textContent =
            incident.incident_id
                ? "No further transitions"
                : "Incident ID unavailable";

    }

} else {

    actionCell.textContent = "Read only";

}


// Add row to table

table.appendChild(row);

            }
        );


    }

    catch (error) {


        // =====================================================
        // ERROR HANDLING
        // =====================================================

        console.error(
            "SECURITY INCIDENT ERROR:",
            error
        );


        const table =
            document.getElementById(
                "securityIncidentsTable"
            );


        if (table) {

            table.innerHTML = `
                <tr>
                    <td colspan="14">
                        Unable to load security incident data
                    </td>
                </tr>
            `;

        }

    }

}


// ============================================================
// CORRELATED ATTACK CAMPAIGNS
// ============================================================

async function loadSecurityCampaigns() {

    try {

        const response =
            await apiFetch(
                `${API}/security/campaigns`,
                {
                    method: "GET",
                    mode: "cors",
                    cache: "no-store"
                }
            );

        if (!response.ok) {

            throw new Error(
                `Security campaigns HTTP ${response.status}`
            );

        }

        const campaigns =
            await response.json();

        const table =
            document.getElementById(
                "securityCampaignsTable"
            );

        if (!table) {
            return;
        }

        table.innerHTML = "";

        if (
            !Array.isArray(campaigns) ||
            campaigns.length === 0
        ) {

            table.innerHTML = `
                <tr>
                    <td colspan="10">
                        No correlated attack campaigns detected
                    </td>
                </tr>
            `;

            return;
        }

        campaigns.forEach(campaign => {

            const row =
                document.createElement("tr");

            row.innerHTML = `

                <td>
                    <strong>
                        ${campaign.correlation_id || "-"}
                    </strong>
                </td>

                <td>
                    ${campaign.source_ip || "-"}
                </td>

                <td>
                    ${campaign.target_hostname || "-"}
                </td>

                <td>
                   ${campaign.target_ip || "-"}
                </td>

                <td>
                    ${campaign.attack_pattern || "-"}
                </td>

                <td>
                    <strong>
                        ${campaign.severity || "UNKNOWN"}
                    </strong>
                </td>

                <td>
                    ${campaign.incident_count ?? 0}
                </td>

                <td>
                    ${campaign.total_attempts ?? 0}
                </td>

                <td>
                    ${campaign.failed_logins ?? 0}
                </td>

                <td>
                    ${campaign.invalid_users ?? 0}
                </td>

                <td>
                    ${
                        campaign.start_time
                            ? new Date(
                                campaign.start_time
                              ).toLocaleString()
                            : "-"
                    }
                </td>

                <td>
                    ${
                        campaign.end_time
                            ? new Date(
                                campaign.end_time
                              ).toLocaleString()
                            : "-"
                    }
                </td>

            `;

            table.appendChild(row);

        });

    }

    catch (error) {

        console.error(
            "SECURITY CAMPAIGN ERROR:",
            error
        );

        const table =
            document.getElementById(
                "securityCampaignsTable"
            );

        if (table) {

            table.innerHTML = `
                <tr>
                    <td colspan="10">
                        Unable to load correlated attack campaigns
                    </td>
                </tr>
            `;

        }

    }

}


// ============================================================
// PHASE 27.6 - CROSS-SERVER ATTACK CAMPAIGNS
// ============================================================

async function loadCrossServerCampaigns() {

    try {

        const response = await apiFetch(
            `${API}/security/cross-server-campaigns`,
            {
                method: "GET",
                mode: "cors",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(
                `Cross-server campaigns HTTP ${response.status}`
            );
        }

        const campaigns = await response.json();

        const table = document.getElementById(
            "crossServerCampaignsTable"
        );

        if (!table) {
            return;
        }

        table.innerHTML = "";

        if (!Array.isArray(campaigns) || campaigns.length === 0) {
            table.innerHTML = `
                <tr>
                    <td colspan="10">
                        No cross-server attack campaigns detected
                    </td>
                </tr>
            `;
            return;
        }

        campaigns.forEach(campaign => {

            const row = document.createElement("tr");

            const affectedHosts = Array.isArray(campaign.target_hosts)
                ? campaign.target_hosts.join(", ")
                : "-";

            const formatTime = value => {
                if (!value) return "-";

                const date = new Date(value);

                return Number.isNaN(date.getTime())
                    ? "-"
                    : date.toLocaleString();
            };

            const cells = [
                campaign.campaign_id || "-",
                campaign.source_ip || "-",
                affectedHosts,
                campaign.target_count ?? 0,
                campaign.severity || "UNKNOWN",
                campaign.total_attempts ?? 0,
                campaign.failed_logins ?? 0,
                campaign.invalid_users ?? 0,
                formatTime(campaign.start_time),
                formatTime(campaign.end_time)
            ];

            cells.forEach(value => {

                const cell = document.createElement("td");

                cell.textContent = String(value);

                row.appendChild(cell);

            });

            table.appendChild(row);

        });

    } catch (error) {

        console.error(
            "CROSS-SERVER CAMPAIGN ERROR:",
            error
        );

        const table = document.getElementById(
            "crossServerCampaignsTable"
        );

        if (table) {
            table.innerHTML = `
                <tr>
                    <td colspan="10">
                        Unable to load cross-server attack campaigns
                    </td>
                </tr>
            `;
        }

    }

}


// ============================================================
// SECURITY RESPONSE RECOMMENDATIONS
// ============================================================

async function loadSecurityResponses() {

    try {

        const response =
            await apiFetch(
                `${API}/security/incidents`,
                {
                    method: "GET",
                    mode: "cors",
                    cache: "no-store"
                }
            );


        if (!response.ok) {

            throw new Error(
                `Security response HTTP ${response.status}`
            );
        }


        const incidents =
            await response.json();


        const table =
            document.getElementById(
                "securityResponses"
            );


        if (!table) {
            return;
        }


        table.innerHTML = "";


        if (incidents.length === 0) {

            table.innerHTML = `
                <tr>
                    <td colspan="6">
                        No security response recommendations
                    </td>
                </tr>
            `;

            return;
        }


        incidents.forEach(incident => {

            const row =
                document.createElement("tr");


            row.innerHTML = `
                <td>
                    ${incident.severity}
                </td>

                <td>
                    ${incident.incident_type}
                </td>

                <td>
                    ${incident.source_ip}
                </td>

                <td>
                    ${incident.recommended_action || "-"}
                </td>

                <td>
                    ${incident.response_description || "-"}
                </td>

                <td>
                    ${incident.response_mode || "-"}
                </td>
            `;


            table.appendChild(row);

        });

    } catch (error) {

        console.error(
            "SECURITY RESPONSE ERROR:",
            error
        );
    }
}


// ============================================================
// SECURITY RESPONSE EXECUTION
// ============================================================

async function loadResponseExecution() {

    try {

        const response =
            await apiFetch(
                `${API}/security/responses`,
                {
                    method: "GET",
                    mode: "cors",
                    cache: "no-store"
                }
            );

        if (!response.ok) {

            throw new Error(
                `Response execution HTTP ${response.status}`
            );
        }

        const responses =
            await response.json();

        const table =
            document.getElementById(
                "responseExecution"
            );

        if (!table) {
            return;
        }

        table.innerHTML = "";

        if (
            !Array.isArray(responses) ||
            responses.length === 0
        ) {

            table.innerHTML = `
                <tr>
                    <td colspan="9">
                        No AI response actions available
                    </td>
                </tr>
            `;

            return;
        }

        responses.forEach(responseData => {

            const row =
                document.createElement("tr");

            const severity =
                responseData.severity || "-";

            const sourceIP =
                responseData.source_ip || "-";

            const threatScore =
                responseData.threat_score ?? "-";

            const priority =
                responseData.priority || "-";

            const aiDecision =
                responseData.ai_decision ||
                responseData.recommended_action ||
                "-";

            const confidenceScore =
                responseData.confidence_score ?? "-";

            const confidenceLevel =
                responseData.confidence_level || "-";

            const executionMode =
                responseData.execution_mode || "-";

            const executed =
                responseData.executed ? "YES" : "NO";

            const executionMessage =
                responseData.execution_message || "-";

            row.innerHTML = `

                <td>
                    <strong>
                        ${severity}
                    </strong>
                </td>

                <td>
                    ${sourceIP}
                </td>

                <td>
                    <strong>
                        ${threatScore}/100
                    </strong>
                </td>

                <td>
                    <strong>
                        ${priority}
                    </strong>
                </td>

                <td>
                    <strong>
                        ${aiDecision}
                    </strong>
                </td>

                <td>
                    <strong>
                        ${confidenceScore}%
                    </strong>
                    <br>
                    <small>
                        ${confidenceLevel}
                    </small>
                </td>

                <td>
                    ${executionMode}
                </td>

                <td>
                    <strong>
                        ${executed}
                    </strong>
                </td>

                <td>
                    ${executionMessage}
                </td>

            `;

            table.appendChild(row);

        });

    } catch (error) {

        console.error(
            "RESPONSE EXECUTION ERROR:",
            error
        );

        const table =
            document.getElementById(
                "responseExecution"
            );

        if (table) {

            table.innerHTML = `
                <tr>
                    <td colspan="9">
                        Unable to load AI response execution data
                    </td>
                </tr>
            `;

        }

    }

}

// ============================================================
// AI SECURITY INTELLIGENCE
// ============================================================

async function loadSecurityDecisions() {

    try {

        const response =
            await apiFetch(
                `${API}/security/decisions`,
                {
                    method: "GET",
                    mode: "cors",
                    cache: "no-store"
                }
            );

        if (!response.ok) {

            throw new Error(
                `Security decisions HTTP ${response.status}`
            );
        }

        const decisions =
            await response.json();

        const table =
            document.getElementById(
                "securityDecisionsTable"
            );

        if (!table) {
            return;
        }

        table.innerHTML = "";

        if (
            !Array.isArray(decisions) ||
            decisions.length === 0
        ) {

            table.innerHTML = `
                <tr>
                    <td colspan="8">
                        No AI security decisions available
                    </td>
                </tr>
            `;

            return;
        }

        decisions.forEach(decision => {

            const row =
                document.createElement("tr");

            const severity =
                decision.severity || "-";

            const sourceIP =
                decision.source_ip || "-";

            const threatScore =
                decision.threat_score ?? "-";

            const priority =
                decision.priority || "-";

            const confidenceScore =
                decision.confidence_score ?? "-";

            const confidenceLevel =
                decision.confidence_level || "-";

            const securityDecision =
                decision.decision ||
                decision.recommended_action ||
                "-";

            const explanation =
                decision.explanation || "-";

            const executionMode =
                decision.execution_mode || "-";

            row.innerHTML = `

                <td>
                    <strong>
                        ${severity}
                    </strong>
                </td>

                <td>
                    ${sourceIP}
                </td>

                <td>
                    <strong>
                        ${threatScore}/100
                    </strong>
                </td>

                <td>
                    <strong>
                        ${priority}
                    </strong>
                </td>

                <td>
                    <strong>
                        ${confidenceScore}%
                    </strong>
                    <br>
                    <small>
                        ${confidenceLevel}
                    </small>
                </td>

                <td>
                    <strong>
                        ${securityDecision}
                    </strong>
                </td>

                <td>
                    ${explanation}
                </td>

                <td>
                    ${executionMode}
                </td>

            `;

            table.appendChild(row);

        });

    }

    catch (error) {

        console.error(
            "AI SECURITY DECISION ERROR:",
            error
        );

        const table =
            document.getElementById(
                "securityDecisionsTable"
            );

        if (table) {

            table.innerHTML = `
                <tr>
                    <td colspan="8">
                        Unable to load AI security decisions
                    </td>
                </tr>
            `;

        }

    }

}

// ============================================================
// SECURITY RESPONSE AUDIT HISTORY
// ============================================================

async function loadSecurityResponseAudit() {

    try {

        const response = await apiFetch(
            `${API}/security/response-audit?limit=20`
        );

        const audits = await response.json();

        const table =
            document.getElementById(
                "responseAuditTable"
            );

        if (!table) {
            return;
        }

        table.innerHTML = "";

        if (!audits || audits.length === 0) {

            table.innerHTML = `
                <tr>
                    <td colspan="10">
                        No security response audit records found
                    </td>
                </tr>
            `;

            return;

        }

        audits.forEach(audit => {

            const row =
                document.createElement("tr");

            const createdAt =
                audit.created_at
                    ? new Date(
                        audit.created_at
                    ).toLocaleString()
                    : "-";

            const executed =
                audit.executed
                    ? "YES"
                    : "NO";

            row.innerHTML = `

                <td>
                    ${createdAt}
                </td>

                <td>
                    ${audit.incident_id || "-"}
                </td>

                <td>
                    <strong>
                        ${audit.severity || "-"}
                    </strong>
                </td>

                <td>
                    ${audit.source_ip || "-"}
                </td>

                <td>
                    <strong>
                        ${audit.threat_score ?? 0}/100
                    </strong>
                </td>

                <td>
                    <strong>
                        ${audit.priority || "-"}
                    </strong>
                </td>

                <td>
                    <strong>
                        ${audit.ai_decision || "-"}
                    </strong>
                </td>

                <td>
                    ${audit.execution_action || "-"}
                </td>

                <td>
                    ${audit.execution_mode || "-"}
                </td>

                <td>
                    ${executed}
                </td>

            `;

            table.appendChild(row);

        });

    }

    catch (error) {

        console.error(
            "SECURITY RESPONSE AUDIT ERROR:",
            error
        );

        const table =
            document.getElementById(
                "responseAuditTable"
            );

        if (table) {

            table.innerHTML = `
                <tr>
                    <td colspan="10">
                        Unable to load security response audit history
                    </td>
                </tr>
            `;

        }

    }

}

// ============================================================
// INITIAL LOAD
// ============================================================

// ============================================================
// AUTHENTICATED DASHBOARD INITIALIZATION
// ============================================================

console.log(
    "=== AUTHENTICATED DASHBOARD READY ==="
);



// ============================================================
// PHASE 21.6 FEATURE 7 - ADMIN NOTIFICATION SETTINGS
// ============================================================

function setNotificationSettingsMessage(message) {

    const element = document.getElementById(
        "notificationSettingsMessage"
    );

    if (element) {
        element.textContent = message;
    }

}


// ------------------------------------------------------------
// LOAD AND DISPLAY NOTIFICATION SETTINGS
// ------------------------------------------------------------

async function loadNotificationSettings() {

    const table = document.getElementById(
        "notificationSettingsTable"
    );

    if (!table) {
        return;
    }

    try {

        const response = await apiFetch(
            `${API}/security/notification-settings`,
            {
                method: "GET",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const settings = await response.json();

        table.textContent = "";

        const isAdmin =
            currentUserRole === "admin";

        const channels = [
            {
                name: "EMAIL",
                field: "email_enabled"
            },
            {
                name: "TELEGRAM",
                field: "telegram_enabled"
            },
            {
                name: "DASHBOARD",
                field: "dashboard_enabled"
            }
        ];

        settings.forEach(setting => {

            const row = document.createElement("tr");

            const severityCell = document.createElement("td");
            severityCell.textContent = setting.severity;
            row.appendChild(severityCell);

            const priorityCell = document.createElement("td");
            priorityCell.textContent = setting.priority || "-";
            row.appendChild(priorityCell);

            channels.forEach(channel => {

                const cell = document.createElement("td");

                const enabled = Boolean(
                    setting[channel.field]
                );

                const isCriticalDashboard =
                    setting.severity === "CRITICAL" &&
                    channel.name === "DASHBOARD";

                if (isAdmin) {

                    const button =
                        document.createElement("button");

                    button.type = "button";

                    button.className =
                        "notification-setting-button";

                    button.textContent = enabled
                        ? "ENABLED"
                        : "DISABLED";

                    button.classList.add(
                        enabled ? "setting-enabled" : "setting-disabled"
                    );

                    button.disabled = isCriticalDashboard;

                    if (isCriticalDashboard) {

                        button.title =
                            "Critical dashboard notifications cannot be disabled.";

                    } else {

                        button.addEventListener(
                            "click",
                            () => updateNotificationSetting(
                                setting.severity,
                                channel.name,
                                !enabled
                            )
                        );

                    }

                    cell.appendChild(button);

                } else {

                    cell.textContent = enabled
                        ? "ENABLED"
                        : "DISABLED";

                }

                row.appendChild(cell);

            });

            table.appendChild(row);

        });

        setNotificationSettingsMessage(
            isAdmin
                ? "Admin mode: You can update notification policies."
                : "Read-only mode: Only administrators can change notification policies."
        );

    } catch (error) {

        console.error(
            "NOTIFICATION SETTINGS LOAD ERROR:",
            error
        );

        table.textContent = "";

        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 5;
        cell.textContent =
            "Unable to load notification settings.";

        row.appendChild(cell);
        table.appendChild(row);

        setNotificationSettingsMessage(
            "Error loading notification settings."
        );

    }

}


// ------------------------------------------------------------
// UPDATE A NOTIFICATION POLICY
// ------------------------------------------------------------

async function updateNotificationSetting(
    severity,
    channel,
    enabled
) {

    if (currentUserRole !== "admin") {

        setNotificationSettingsMessage(
            "Permission denied: Admin access required."
        );

        return;

    }

    if (
        severity === "CRITICAL" &&
        channel === "DASHBOARD" &&
        !enabled
    ) {

        setNotificationSettingsMessage(
            "Critical dashboard notifications cannot be disabled."
        );

        return;

    }

    const action = enabled
        ? "enable"
        : "disable";

    const confirmed = window.confirm(
        `Are you sure you want to ${action} ${channel} notifications for ${severity} incidents?`
    );

    if (!confirmed) {
        return;
    }

    try {

        setNotificationSettingsMessage(
            `Updating ${severity} ${channel} policy...`
        );

        const response = await apiFetch(
            `${API}/security/notification-settings/${severity}/${channel}`,
            {
                method: "PUT",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    enabled: enabled
                })
            }
        );

        const data = await response.json();

        if (!response.ok) {

            throw new Error(
                data.detail || `HTTP ${response.status}`
            );

        }

        setNotificationSettingsMessage(
            data.status === "unchanged"
                ? "The notification policy was already set to that value."
                : `${severity} ${channel} notifications successfully ${action}d.`
        );

        await loadNotificationSettings();
        await loadNotificationSettingsAudit();

    } catch (error) {

        console.error(
            "NOTIFICATION SETTINGS UPDATE ERROR:",
            error
        );

        setNotificationSettingsMessage(
            `Update failed: ${error.message}`
        );

    }

}


// ------------------------------------------------------------
// LOAD NOTIFICATION SETTINGS AUDIT HISTORY
// ------------------------------------------------------------

async function loadNotificationSettingsAudit() {

    const table = document.getElementById(
        "notificationSettingsAuditTable"
    );

    if (!table) {
        return;
    }

    try {

        const response = await apiFetch(
            `${API}/security/notification-settings/audit?limit=100`,
            {
                method: "GET",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const records = await response.json();

        table.textContent = "";

        if (!records.length) {

            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.colSpan = 7;
            cell.textContent = "No settings changes recorded.";

            row.appendChild(cell);
            table.appendChild(row);

            return;

        }

        records.forEach(record => {

            const row = document.createElement("tr");

            const values = [
                record.id,
                record.severity,
                record.channel,
                record.old_enabled ? "ENABLED" : "DISABLED",
                record.new_enabled ? "ENABLED" : "DISABLED",
                record.changed_by_username,
                record.changed_at
                    ? new Date(record.changed_at).toLocaleString()
                    : "-"
            ];

            values.forEach(value => {

                const cell = document.createElement("td");

                cell.textContent =
                    value === null || value === undefined
                        ? "-"
                        : String(value);

                row.appendChild(cell);

            });

            table.appendChild(row);

        });

    } catch (error) {

        console.error(
            "NOTIFICATION SETTINGS AUDIT ERROR:",
            error
        );

        table.textContent = "";

        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 7;
        cell.textContent =
            "Unable to load notification settings audit history.";

        row.appendChild(cell);
        table.appendChild(row);

    }

}


// ============================================================
// NOTIFICATION DELIVERY HEALTH MONITOR
// ============================================================

async function loadDeliveryHealth() {

    try {

        const response = await apiFetch(
            `${API}/security/delivery-health`,
            {
                method: "GET",
                mode: "cors",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();

        const summary = data.summary || {};

        function updateText(id, value) {

            const element = document.getElementById(id);

            if (element) {
                element.textContent = value;
            }
        }

        updateText(
            "deliveryOverallHealth",
            data.overall_health || "UNKNOWN"
        );

        updateText(
            "deliveryTotalAttempts",
            summary.total_attempts ?? 0
        );

        updateText(
            "deliverySent",
            summary.sent ?? 0
        );

        updateText(
            "deliveryFailed",
            summary.failed ?? 0
        );

        updateText(
            "deliveryPending",
            summary.pending ?? 0
        );

        updateText(
            "deliveryOverdue",
            summary.overdue ?? 0
        );

        updateText(
            "deliverySuccessRate",
            summary.success_rate === null
                ? "N/A"
                : `${summary.success_rate}%`
        );

        updateText(
            "deliveryFailureRate",
            summary.failure_rate === null
                ? "N/A"
                : `${summary.failure_rate}%`
        );

        // ----------------------------------------------------
        // CHANNEL HEALTH TABLE
        // ----------------------------------------------------

        const table = document.getElementById(
            "deliveryChannelTable"
        );

        if (table) {

            table.innerHTML = "";

            const channels = data.channels || {};

            Object.entries(channels).forEach(
                ([name, channel]) => {

                    const row = document.createElement("tr");

                    const values = [
                        name.toUpperCase(),
                        channel.health,
                        channel.total,
                        channel.sent,
                        channel.failed,
                        channel.pending,
                        channel.total_attempts,
                        channel.success_rate === null
                            ? "N/A"
                            : `${channel.success_rate}%`
                    ];

                    values.forEach(value => {

                        const cell =
                            document.createElement("td");

                        cell.textContent =
                            value === null || value === undefined
                                ? "-"
                                : String(value);

                        row.appendChild(cell);

                    });

                    table.appendChild(row);

                }
            );

        }

        updateText(
            "deliveryHealthUpdated",
            `Last updated: ${new Date().toLocaleString()}`
        );

    } catch (error) {

        console.error(
            "DELIVERY HEALTH ERROR:",
            error
        );

        const healthElement = document.getElementById(
            "deliveryOverallHealth"
        );

        if (healthElement) {
            healthElement.textContent = "Unavailable";
        }

        const updatedElement = document.getElementById(
            "deliveryHealthUpdated"
        );

        if (updatedElement) {
            updatedElement.textContent =
                "Unable to retrieve delivery health.";
        }

    }

}


// ============================================================
// NOTIFICATION ANALYTICS AND REPORTING
// ============================================================

async function loadNotificationAnalytics() {

    const updateText = (id, value) => {

        const element = document.getElementById(id);

        if (element) {
            element.textContent = value;
        }

    };

    try {

        const period =
            document.getElementById("analyticsPeriod")?.value
            || "daily";

        const days =
            document.getElementById("analyticsDays")?.value
            || "90";

        updateText("analyticsUpdated", "Loading analytics...");

        const response = await apiFetch(
            `${API}/security/notification-analytics?days=${encodeURIComponent(days)}&period=${encodeURIComponent(period)}`,
            {
                method: "GET",
                mode: "cors",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();

        const events = data.event_notifications || {};
        const incidents = data.incident_deliveries || {};

        const eventSummary = events.summary || {};
        const incidentSummary = incidents.summary || {};

        // ----------------------------------------------------
        // SUMMARY CARDS
        // ----------------------------------------------------

        updateText(
            "analyticsEventTotal",
            eventSummary.total_recorded_successes ?? 0
        );

        updateText(
            "analyticsIncidentTotal",
            incidentSummary.total_records ?? 0
        );

        updateText(
            "analyticsIncidentSent",
            incidentSummary.sent ?? 0
        );

        updateText(
            "analyticsIncidentFailed",
            incidentSummary.failed ?? 0
        );

        updateText(
            "analyticsIncidentPending",
            incidentSummary.pending ?? 0
        );

        updateText(
            "analyticsIncidentAttempts",
            incidentSummary.total_attempts ?? 0
        );

        // ----------------------------------------------------
        // DESTROY PREVIOUS CHARTS
        // ----------------------------------------------------

        [
            notificationEventTrendChart,
            notificationChannelChart,
            notificationSeverityChart,
            incidentDeliveryChart,
            incidentRetryChart
        ].forEach(chart => {

            if (chart) {
                chart.destroy();
            }

        });

        // ----------------------------------------------------
        // EVENT NOTIFICATION TREND
        // ----------------------------------------------------

        const eventTrend = events.trend || [];

        const eventPeriods = [
            ...new Set(
                eventTrend.map(item => item.period_start)
            )
        ].sort();

        const eventChannels = [
            ...new Set(
                eventTrend.map(item => item.notification_channel)
            )
        ];

        const eventDatasets = eventChannels.map(channel => ({

            label: channel.toUpperCase(),

            data: eventPeriods.map(periodStart => {

                const record = eventTrend.find(
                    item =>
                        item.period_start === periodStart &&
                        item.notification_channel === channel
                );

                return record?.recorded_successes ?? 0;

            }),

            tension: 0.3

        }));

        notificationEventTrendChart = new Chart(
            document.getElementById("notificationEventTrendChart"),
            {
                type: "line",

                data: {
                    labels: eventPeriods.map(
                        value => new Date(value).toLocaleDateString()
                    ),
                    datasets: eventDatasets
                },

                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            }
        );

        // ----------------------------------------------------
        // EVENT CHANNEL COMPARISON
        // ----------------------------------------------------

        const channelRecords = events.by_channel || [];

        notificationChannelChart = new Chart(
            document.getElementById("notificationChannelChart"),
            {
                type: "bar",

                data: {
                    labels: channelRecords.map(
                        item => item.notification_channel.toUpperCase()
                    ),

                    datasets: [{
                        label: "Recorded Successful Event Notifications",

                        data: channelRecords.map(
                            item => item.recorded_successes
                        )
                    }]
                },

                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            }
        );

        // ----------------------------------------------------
        // EVENT SEVERITY DISTRIBUTION
        // ----------------------------------------------------

        const severityRecords = events.by_severity || [];

        notificationSeverityChart = new Chart(
            document.getElementById("notificationSeverityChart"),
            {
                type: "doughnut",

                data: {
                    labels: severityRecords.map(
                        item => item.alert_level
                    ),

                    datasets: [{
                        label: "Event Notification Successes",

                        data: severityRecords.map(
                            item => item.recorded_successes
                        )
                    }]
                },

                options: {
                    responsive: true
                }
            }
        );

        // ----------------------------------------------------
        // INCIDENT DELIVERY STATUS
        // ----------------------------------------------------

        incidentDeliveryChart = new Chart(
            document.getElementById("incidentDeliveryChart"),
            {
                type: "bar",

                data: {
                    labels: ["Sent", "Failed", "Pending"],

                    datasets: [{
                        label: "Incident Delivery Records",

                        data: [
                            incidentSummary.sent ?? 0,
                            incidentSummary.failed ?? 0,
                            incidentSummary.pending ?? 0
                        ]
                    }]
                },

                options: {
                    responsive: true,

                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            }
        );

        // ----------------------------------------------------
        // INCIDENT RETRY ATTEMPTS BY CHANNEL
        // ----------------------------------------------------

        const incidentChannels =
            incidents.by_channel || [];

        incidentRetryChart = new Chart(
            document.getElementById("incidentRetryChart"),
            {
                type: "bar",

                data: {
                    labels: incidentChannels.map(
                        item => item.notification_channel.toUpperCase()
                    ),

                    datasets: [{
                        label: "Total Delivery Attempts",

                        data: incidentChannels.map(
                            item => item.total_attempts
                        )
                    }]
                },

                options: {
                    responsive: true,

                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            }
        );

        updateText(
            "analyticsUpdated",
            `Last updated: ${new Date().toLocaleString()} | ${period.toUpperCase()} | Last ${days} days`
        );

    } catch (error) {

        console.error(
            "NOTIFICATION ANALYTICS ERROR:",
            error
        );

        updateText(
            "analyticsUpdated",
            "Unable to retrieve notification analytics."
        );

    }

}


// ============================================================
// PHASE 21.6 FEATURE 8 - NOTIFICATION POLICY SIMULATOR
// ============================================================


// RUN NOTIFICATION POLICY SIMULATION

async function runNotificationSimulation() {

    const severity =
        document.getElementById(
            "simulationSeverity"
        )?.value;

    const message =
        document.getElementById(
            "notificationSimulationMessage"
        );

    const resultsTable =
        document.getElementById(
            "notificationSimulationResults"
        );

    if (!severity || !message || !resultsTable) {
        return;
    }

    message.textContent = "Running simulation...";

    resultsTable.textContent = "";

    try {

        const response = await apiFetch(
            `${API}/security/notification-simulator`,
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    severity: severity
                })
            }
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const result = await response.json();

        message.textContent =
            `Simulation #${result.simulation_id} completed. ` +
            "DRY-RUN — NO NOTIFICATIONS SENT.";

        const channels = [
            {
                name: "Email",
                key: "email"
            },
            {
                name: "Telegram",
                key: "telegram"
            },
            {
                name: "Dashboard",
                key: "dashboard"
            }
        ];

        channels.forEach(channel => {

            const decision =
                result.channels[channel.key];

            const row = document.createElement("tr");

            const nameCell =
                document.createElement("td");

            nameCell.textContent = channel.name;

            const statusCell =
                document.createElement("td");

            statusCell.textContent =
                decision.allowed
                    ? "ALLOWED — NOT SENT"
                    : "BLOCKED BY POLICY";

            const reasonCell =
                document.createElement("td");

            reasonCell.textContent =
                decision.reason;

            row.appendChild(nameCell);
            row.appendChild(statusCell);
            row.appendChild(reasonCell);

            resultsTable.appendChild(row);

        });

        await loadNotificationSimulationHistory();

    } catch (error) {

        console.error(
            "NOTIFICATION SIMULATION ERROR:",
            error
        );

        message.textContent =
            "Unable to run notification simulation.";

        resultsTable.textContent = "";

        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 3;
        cell.textContent = "Simulation failed.";

        row.appendChild(cell);
        resultsTable.appendChild(row);

    }

}


// LOAD NOTIFICATION SIMULATION HISTORY

async function loadNotificationSimulationHistory() {

    const table =
        document.getElementById(
            "notificationSimulationHistoryTable"
        );

    if (!table) {
        return;
    }

    try {

        const response = await apiFetch(
            `${API}/security/notification-simulator/history?limit=50`,
            {
                method: "GET",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const records = await response.json();

        table.textContent = "";

        if (!records.length) {

            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.colSpan = 9;

            cell.textContent =
                "No simulation history available.";

            row.appendChild(cell);
            table.appendChild(row);

            return;

        }

        records.forEach(record => {

            const row = document.createElement("tr");

            const values = [
                record.id,
                record.severity,
                record.priority,
                record.email_allowed ? "ALLOWED" : "BLOCKED",
                record.telegram_allowed ? "ALLOWED" : "BLOCKED",
                record.dashboard_allowed ? "ALLOWED" : "BLOCKED",
                record.simulation_mode,
                record.simulated_by_username,
                record.created_at
                    ? new Date(record.created_at).toLocaleString()
                    : "-"
            ];

            values.forEach(value => {

                const cell = document.createElement("td");

                cell.textContent =
                    value === null || value === undefined
                        ? "-"
                        : String(value);

                row.appendChild(cell);

            });

            table.appendChild(row);

        });

    } catch (error) {

        console.error(
            "NOTIFICATION SIMULATION HISTORY ERROR:",
            error
        );

        table.textContent = "";

        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 9;

        cell.textContent =
            "Unable to load simulation history.";

        row.appendChild(cell);
        table.appendChild(row);

    }

}


// ============================================================
// PHASE 22 - THREAT INTELLIGENCE DASHBOARD
// ============================================================

async function loadThreatIntelligence() {

    const status =
        document.getElementById("threatDashboardStatus");

    const table =
        document.getElementById("threatMatchesTable");

    if (!table) return;

    try {

        const [activeIocResponse, inactiveIocResponse, riskResponse] =
            await Promise.all([

                apiFetch(
                    `${API}/threat-intelligence/indicators?active=true&limit=500`,
                    { method: "GET", cache: "no-store" }
                ),

                apiFetch(
                    `${API}/threat-intelligence/indicators?active=false&limit=500`,
                    { method: "GET", cache: "no-store" }
                ),

                apiFetch(
                    `${API}/security/risk`,
                    { method: "GET", cache: "no-store" }
                )

            ]);

        if (
            !activeIocResponse.ok ||
            !inactiveIocResponse.ok ||
            !riskResponse.ok
        ) {
            throw new Error("Threat intelligence API request failed");
        }

        const activeIocData = await activeIocResponse.json();
        const inactiveIocData = await inactiveIocResponse.json();
        const riskEvents = await riskResponse.json();

        const activeIndicators = activeIocData.indicators || [];
        const inactiveIndicators = inactiveIocData.indicators || [];

        const indicators = [
            ...activeIndicators,
            ...inactiveIndicators
        ];

        const setValue = (id, value) => {

            const element = document.getElementById(id);

            if (element) element.textContent = String(value);

        };

        setValue("threatTotalIndicators", indicators.length);
        setValue("threatActiveIndicators", activeIndicators.length);
        setValue("threatInactiveIndicators", inactiveIndicators.length);

        const severityCounts = {
            CRITICAL: 0,
            HIGH: 0,
            MEDIUM: 0,
            LOW: 0
        };

        activeIndicators.forEach(item => {

            const severity = String(item.severity || "").toUpperCase();

            if (severityCounts[severity] !== undefined) {
                severityCounts[severity]++;
            }

        });

        setValue("threatCriticalCount", severityCounts.CRITICAL);
        setValue("threatHighCount", severityCounts.HIGH);
        setValue("threatMediumCount", severityCounts.MEDIUM);
        setValue("threatLowCount", severityCounts.LOW);

        const maliciousEvents = riskEvents.filter(
            event =>
                event.threat_intelligence?.is_malicious === true
        );

        setValue("threatSSHMatches", maliciousEvents.length);

        table.textContent = "";

        if (maliciousEvents.length === 0) {

            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.colSpan = 7;
            cell.textContent = "No malicious SSH matches detected.";

            row.appendChild(cell);
            table.appendChild(row);

        } else {

            maliciousEvents.slice(0, 20).forEach(event => {

                const threat = event.threat_intelligence;

                const row = document.createElement("tr");

                const values = [
                    event.id,
                    event.event_type,
                    event.source_ip,
                    threat.threat_type || "-",
                    threat.severity || "-",
                    threat.confidence ?? "-",
                    event.risk_score
                ];

                values.forEach(value => {

                    const cell = document.createElement("td");

                    cell.textContent =
                        value === null || value === undefined
                            ? "-"
                            : String(value);

                    row.appendChild(cell);

                });

                table.appendChild(row);

            });

        }

        if (status) {
            status.textContent =
                `Updated successfully. ${indicators.length} indicators checked.`;
        }

    } catch (error) {

        console.error("THREAT INTELLIGENCE DASHBOARD ERROR:", error);

        if (status) {
            status.textContent =
                "Unable to load threat intelligence data.";
        }

    }

}


// ============================================================
// PHASE 23: PREDICTIVE SECURITY ANALYTICS
// ============================================================

let predictiveAnomalyChart = null;

async function loadPredictiveAnalytics() {

    const status = document.getElementById(
        "predictiveAnalyticsStatus"
    );

    try {

        const endpoints = [
            "/security/analytics/predictive-risk?days=30",
            "/security/analytics/anomaly-forecast",
            "/security/analytics/attack-patterns?days=30",
            "/security/analytics/predictive-alerts?days=30"
        ];

        const responses = await Promise.all(
            endpoints.map(async endpoint => {

                const response = await apiFetch(
                    `${API}${endpoint}`
                );

                if (!response.ok) {
                    throw new Error(
                        `API request failed: ${endpoint} (${response.status})`
                    );
                }

                return response.json();

            })
        );

        const [
            riskData,
            anomalyData,
            attackData,
            alertData
        ] = responses;

        // ----------------------------------------------------
        // 1. PREDICTIVE SECURITY RISK
        // ----------------------------------------------------

        const riskTable = document.getElementById(
            "predictiveRiskTable"
        );

        if (riskTable) {

            riskTable.textContent = "";

            const risk = riskData.predictive_risk || {};
            const prediction = riskData.prediction || {};

            const row = document.createElement("tr");

            [
                risk.score ?? "-",
                risk.level ?? "-",
                prediction.predicted_failed_logins ?? "-",
                prediction.predicted_invalid_users ?? "-"
            ].forEach(value => {

                const cell = document.createElement("td");
                cell.textContent = String(value);
                row.appendChild(cell);

            });

            riskTable.appendChild(row);

        }

        // ----------------------------------------------------
        // 2. INFRASTRUCTURE ANOMALY FORECAST
        // ----------------------------------------------------

        const metrics = anomalyData.metrics || {};

        const metricNames = ["cpu", "memory", "disk"];

        const metricLabels = [
            "CPU",
            "Memory",
            "Disk"
        ];

        const forecastValues = metricNames.map(metric => {

            const value = metrics[metric]
                ?.predicted_next_observation_average;

            return Number.isFinite(Number(value))
                ? Number(value)
                : null;

        });

        const canvas = document.getElementById(
            "predictiveAnomalyChart"
        );

        if (canvas && typeof Chart !== "undefined") {

            if (predictiveAnomalyChart) {
                predictiveAnomalyChart.destroy();
            }

            predictiveAnomalyChart = new Chart(
                canvas,
                {
                    type: "bar",

                    data: {
                        labels: metricLabels,

                        datasets: [{
                            label: "Predicted next observation (%)",
                            data: forecastValues,
                            backgroundColor: [
                                "#3498db",
                                "#9b59b6",
                                "#2ecc71"
                            ]
                        }]
                    },

                    options: {
                        responsive: true,

                        maintainAspectRatio: false,

                        scales: {
                            y: {
                                beginAtZero: true,
                                max: 100,
                                title: {
                                    display: true,
                                    text: "Predicted usage (%)"
                                }
                            }
                        }
                    }
                }
            );

        }

        // ----------------------------------------------------
        // 3. PREDICTED ATTACK PATTERNS
        // ----------------------------------------------------

        const attackTable = document.getElementById(
            "predictiveAttackTable"
        );

        if (attackTable) {

            attackTable.textContent = "";

            const patterns =
                attackData.predicted_attack_patterns || [];

            if (patterns.length === 0) {

                const row = document.createElement("tr");
                const cell = document.createElement("td");

                cell.colSpan = 5;
                cell.textContent = "No suspicious attack patterns found.";

                row.appendChild(cell);
                attackTable.appendChild(row);

            } else {

                patterns.forEach(pattern => {

                    const row = document.createElement("tr");

                    [
                        pattern.source_ip,
                        pattern.dominant_pattern,
                        pattern.failed_logins,
                        pattern.invalid_users,
                        pattern.recurrence_estimate
                    ].forEach(value => {

                        const cell = document.createElement("td");
                        cell.textContent = String(value ?? "-");
                        row.appendChild(cell);

                    });

                    attackTable.appendChild(row);

                });

            }

        }

        // ----------------------------------------------------
        // 4. PREDICTIVE SECURITY ALERTS
        // ----------------------------------------------------

        const alertTable = document.getElementById(
            "predictiveAlertsTable"
        );

        if (alertTable) {

            alertTable.textContent = "";

            const alerts =
                alertData.predictive_alerts || [];

            if (alerts.length === 0) {

                const row = document.createElement("tr");
                const cell = document.createElement("td");

                cell.colSpan = 4;
                cell.textContent = "No predictive alerts generated.";

                row.appendChild(cell);
                alertTable.appendChild(row);

            } else {

                alerts.forEach(alert => {

                    const row = document.createElement("tr");

                    [
                        alert.alert_type,
                        alert.severity,
                        alert.source_ip || alert.metric || "-",
                        alert.message
                    ].forEach(value => {

                        const cell = document.createElement("td");
                        cell.textContent = String(value ?? "-");
                        row.appendChild(cell);

                    });

                    alertTable.appendChild(row);

                });

            }

        }

        if (status) {

            status.textContent =
                `Predictive analytics updated successfully. ` +
                `${alertData.total_predictive_alerts ?? 0} predictive alerts found.`;

        }

    } catch (error) {

        console.error(
            "PREDICTIVE ANALYTICS ERROR:",
            error
        );

        if (status) {
            status.textContent =
                "Unable to load all predictive analytics. Check API availability.";
        }

    }

}


// ============================================================
// PHASE 24 - FILE INTEGRITY MONITORING
// ============================================================

async function loadFIMDashboard() {
    const status = document.getElementById("fimStatus");

    try {
        const [baselineResponse, eventResponse] = await Promise.all([
            apiFetch(`${API}/security/fim/baselines`),
            apiFetch(`${API}/security/fim/events?limit=100`)
        ]);

        if (!baselineResponse.ok || !eventResponse.ok) {
            throw new Error(
                `Baseline HTTP ${baselineResponse.status}; Events HTTP ${eventResponse.status}`
            );
        }

        const [baselines, events] = await Promise.all([
            baselineResponse.json(),
            eventResponse.json()
        ]);

        const baselineTable = document.getElementById("fimBaselineTable");
        const eventTable = document.getElementById("fimEventsTable");

        baselineTable.replaceChildren();
        eventTable.replaceChildren();

        if (!baselines.length) {
            baselineTable.innerHTML =
                '<tr><td colspan="5">No baselines found.</td></tr>';
        } else {
            baselines.forEach(item => {
                const row = document.createElement("tr");

                [
                    item.hostname,
                    item.file_path,
                    item.sha256,
                    item.updated_by,
                    item.updated_at
                ].forEach(value => {
                    const cell = document.createElement("td");
                    cell.textContent = String(value ?? "-");
                    row.appendChild(cell);
                });

                baselineTable.appendChild(row);
            });
        }

        if (!events.length) {
            eventTable.innerHTML =
                '<tr><td colspan="5">No integrity changes detected.</td></tr>';
        } else {
            events.forEach(item => {
                const row = document.createElement("tr");

                [
                    item.hostname,
                    item.file_path,
                    item.event_type,
                    item.severity,
                    item.detected_at
                ].forEach(value => {
                    const cell = document.createElement("td");
                    cell.textContent = String(value ?? "-");
                    row.appendChild(cell);
                });

                eventTable.appendChild(row);
            });
        }

        if (status) {
            status.textContent =
                `FIM loaded: ${baselines.length} baselines, ${events.length} events.`;
        }

    } catch (error) {
        console.error("FIM DASHBOARD ERROR:", error);

        if (status) {
            status.textContent = `Unable to load FIM records: ${error.message}`;
        }
    }
}


async function createFIMBaseline() {
    const status = document.getElementById("fimStatus");

    if (currentUserRole !== "admin") {
        status.textContent = "Only administrators can create or update baselines.";
        return;
    }

    if (!confirm("Create/update the FIM baseline for prac-server?")) {
        return;
    }

    try {
        status.textContent = "Creating FIM baseline...";

        const response = await apiFetch(
            `${API}/security/fim/baseline/prac-server`,
            { method: "POST" }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || `HTTP ${response.status}`);
        }

        status.textContent =
            `Baseline saved: ${data.baseline_files_saved} files; skipped: ${data.skipped_files.length}.`;

        await loadFIMDashboard();

    } catch (error) {
        status.textContent = `Baseline creation failed: ${error.message}`;
    }
}


async function runFIMScan() {
    const status = document.getElementById("fimStatus");

    if (!["admin", "analyst"].includes(currentUserRole)) {
        status.textContent = "Your role cannot run integrity scans.";
        return;
    }

    try {
        status.textContent = "Scanning protected files...";

        const response = await apiFetch(
            `${API}/security/fim/scan/prac-server`,
            { method: "POST" }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || `HTTP ${response.status}`);
        }

        await loadFIMDashboard();

        status.textContent =
            `Scan complete: ${data.files_checked} checked; ${data.changes_detected} changes detected. Baseline unchanged: ${!data.baseline_automatically_changed}.`;

    } catch (error) {
        status.textContent = `Integrity scan failed: ${error.message}`;
    }
}



// PHASE 24 - FIM SECURE EVENT LISTENERS
// No inline event handlers; compatible with strict CSP.

document.getElementById("fimBaselineBtn")
    ?.addEventListener("click", createFIMBaseline);

document.getElementById("fimScanBtn")
    ?.addEventListener("click", runFIMScan);

document.getElementById("fimRefreshBtn")
    ?.addEventListener("click", loadFIMDashboard);


// ============================================================
// PHASE 25 - PROCESS AND SERVICE SECURITY DASHBOARD
// ============================================================

async function loadProcessServiceDashboard() {
    const status = document.getElementById("processServiceStatus");
    if (!status) return;

    try {
        const responses = await Promise.all([
            apiFetch(`${API}/security/process-services/summary`),
            apiFetch(`${API}/security/process-services/detections?limit=50`),
            apiFetch(`${API}/security/process-services/service-changes?limit=50`),
            apiFetch(`${API}/security/process-services/alerts?limit=50`)
        ]);

        const [summary, detections, changes, alerts] = await Promise.all(
            responses.map(async (response) => {
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}`);
                }
                return response.json();
            })
        );

        document.getElementById("psProcessCount").textContent =
            summary.process_inventory_records ?? 0;
        document.getElementById("psServiceCount").textContent =
            summary.service_inventory_records ?? 0;
        document.getElementById("psDetectionCount").textContent =
            summary.open_process_detections ?? 0;
        document.getElementById("psAlertCount").textContent =
            summary.alerts_last_24_hours ?? 0;

        const detectionsBody = document.getElementById("psDetectionsTable");
        detectionsBody.innerHTML = detections.length
            ? detections.map(item => `<tr>
                <td>${escapeHtml(String(item.hostname ?? ""))}</td>
                <td>${escapeHtml(String(item.process_name ?? ""))}</td>
                <td>${escapeHtml(String(item.pid ?? ""))}</td>
                <td>${escapeHtml(String(item.username ?? ""))}</td>
                <td>${escapeHtml(String(item.severity ?? ""))}</td>
                <td>${escapeHtml(String(item.risk_score ?? ""))}</td>
                <td>${escapeHtml(String(item.occurrences ?? ""))}</td>
                <td>${escapeHtml(String(item.last_seen ?? ""))}</td>
            </tr>`).join("")
            : '<tr><td colspan="8">No suspicious processes detected.</td></tr>';

        const changesBody = document.getElementById("psServiceChangesTable");
        changesBody.innerHTML = changes.length
            ? changes.map(item => `<tr>
                <td>${escapeHtml(String(item.hostname ?? ""))}</td>
                <td>${escapeHtml(String(item.unit_name ?? ""))}</td>
                <td>${escapeHtml(String(item.previous_state ?? ""))}</td>
                <td>${escapeHtml(String(item.current_state ?? ""))}</td>
                <td>${escapeHtml(String(item.change_type ?? ""))}</td>
                <td>${escapeHtml(String(item.captured_at ?? ""))}</td>
            </tr>`).join("")
            : '<tr><td colspan="6">No service state changes recorded.</td></tr>';

        const alertsBody = document.getElementById("psAlertsTable");
        alertsBody.innerHTML = alerts.length
            ? alerts.map(item => `<tr>
                <td>${escapeHtml(String(item.hostname ?? ""))}</td>
                <td>${escapeHtml(String(item.alert_type ?? ""))}</td>
                <td>${escapeHtml(String(item.severity ?? ""))}</td>
                <td>${escapeHtml(String(item.risk_score ?? ""))}</td>
                <td>${escapeHtml(String(item.title ?? ""))}</td>
                <td>${escapeHtml(String(item.details ?? ""))}</td>
            </tr>`).join("")
            : '<tr><td colspan="6">No alerts recorded.</td></tr>';

        status.textContent = "Process/service monitoring data loaded.";
    } catch (error) {
        console.error("Phase 25 dashboard error:", error);
        status.textContent = `Unable to load Phase 25 data: ${error.message}`;
    }
}

document.getElementById("psRefreshBtn")
    ?.addEventListener("click", loadProcessServiceDashboard);



// ============================================================
// PHASE 26 - NETWORK SECURITY MONITORING
// ============================================================

async function loadNetworkSecurityDashboard() {
    const status = document.getElementById("networkSecurityStatus");
    if (!status) return;

    try {
        const paths = [
            `${API}/security/network/summary`,
            `${API}/security/network/interfaces?limit=100`,
            `${API}/security/network/listeners?limit=200`,
            `${API}/security/network/connections?limit=200`,
            `${API}/security/network/alerts?limit=100`
        ];

        const responses = await Promise.all(paths.map(path => apiFetch(path)));

        const data = await Promise.all(responses.map(async response => {
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            return response.json();
        }));

        const [summary, interfaces, listeners, connections, alerts] = data;

        document.getElementById("netInterfaceCount").textContent =
            summary.interface_count ?? 0;
        document.getElementById("netListenerCount").textContent =
            summary.listener_count ?? 0;
        document.getElementById("netConnectionCount").textContent =
            summary.connection_count ?? 0;
        document.getElementById("netAlertCount").textContent =
            summary.open_alerts ?? 0;

        document.getElementById("netInterfacesTable").innerHTML =
            interfaces.length
                ? interfaces.map(item => `<tr>
                    <td>${escapeHtml(item.hostname)}</td>
                    <td>${escapeHtml(item.interface_name)}</td>
                    <td>${escapeHtml(item.addresses)}</td>
                    <td>${escapeHtml(item.mac_address)}</td>
                    <td>${escapeHtml(item.state)}</td>
                    <td>${escapeHtml(item.mtu)}</td>
                </tr>`).join("")
                : '<tr><td colspan="6">No interface records.</td></tr>';

        document.getElementById("netListenersTable").innerHTML =
            listeners.length
                ? listeners.map(item => `<tr>
                    <td>${escapeHtml(item.hostname)}</td>
                    <td>${escapeHtml(item.protocol)}</td>
                    <td>${escapeHtml(item.local_address)}</td>
                    <td>${escapeHtml(item.local_port)}</td>
                    <td>${escapeHtml(item.state)}</td>
                    <td>${escapeHtml(item.process_info)}</td>
                </tr>`).join("")
                : '<tr><td colspan="6">No listening ports found.</td></tr>';

        document.getElementById("netConnectionsTable").innerHTML =
            connections.length
                ? connections.map(item => `<tr>
                    <td>${escapeHtml(item.hostname)}</td>
                    <td>${escapeHtml(item.protocol)}</td>
                    <td>${escapeHtml(item.state)}</td>
                    <td>${escapeHtml(item.local_address)}:${escapeHtml(item.local_port)}</td>
                    <td>${escapeHtml(item.peer_address)}:${escapeHtml(item.peer_port)}</td>
                    <td>${escapeHtml(item.process_info)}</td>
                </tr>`).join("")
                : '<tr><td colspan="6">No active connections found.</td></tr>';

        document.getElementById("netAlertsTable").innerHTML =
            alerts.length
                ? alerts.map(item => `<tr>
                    <td>${escapeHtml(item.hostname)}</td>
                    <td>${escapeHtml(item.alert_type)}</td>
                    <td>${escapeHtml(item.severity)}</td>
                    <td>${escapeHtml(item.risk_score)}</td>
                    <td>${escapeHtml(item.local_port)}</td>
                    <td>${escapeHtml(item.details)}</td>
                </tr>`).join("")
                : '<tr><td colspan="6">No network alerts recorded.</td></tr>';

        status.textContent = "Network security monitoring data loaded.";
    } catch (error) {
        console.error("Phase 26 dashboard error:", error);
        status.textContent = `Unable to load network data: ${error.message}`;
    }
}

document.getElementById("netRefreshBtn")
    ?.addEventListener("click", loadNetworkSecurityDashboard);
