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

    loadSecurityAlerts();

    loadNotificationHistory();

    loadIncidentReminders();

    loadSecurityIncidents();

    loadSecurityCampaigns();

    loadSecurityResponses();

if (
    currentUserRole === "admin"
) {

    loadResponseExecution();

}
    loadSecurityDecisions();

    loadSecurityResponseAudit();


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
            alerts.filter(
                alert =>
                    alert.alert_level === "HIGH"
            ).length;


        const criticalCount =
            alerts.filter(
                alert =>
                    alert.alert_level === "CRITICAL"
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
                    <td colspan="6">
                        No SSH events found
                    </td>
                </tr>
            `;

            return;
        }


        events.forEach(event => {

            const alert =
                alertMap.get(event.id);


            const riskScore =
                alert
                    ? alert.risk_score
                    : "-";


            const riskLevel =
                alert
                    ? alert.alert_level
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
