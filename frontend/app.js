console.log("=== CYBER DIGITAL TWIN APP.JS LOADED ===");

let cpuChart;
let memoryChart;
let diskChart;


// ============================================================
// LOAD CURRENT HEALTH
// ============================================================

async function loadDashboard() {

    console.log("Calling health API...");

    try {

        const response = await fetch(
            "http://192.168.38.146:8000/health",
            {
                method: "GET",
                mode: "cors",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error("HTTP error: " + response.status);
        }

        const server = await response.json();

        console.log("HEALTH DATA:", server);

        document.getElementById("hostname").innerText =
            server.hostname;

        document.getElementById("status").innerText =
            server.status;

        document.getElementById("cpu").innerText =
            server.cpu_usage + " %";

        document.getElementById("memory").innerText =
            server.memory_usage + " %";

        document.getElementById("disk").innerText =
            server.disk_usage + " %";

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

    console.log("Calling history API...");

    try {

        const response = await fetch(
            "http://192.168.38.146:8000/metrics/history?limit=50",
            {
                method: "GET",
                mode: "cors",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error("HTTP error: " + response.status);
        }

        const history = await response.json();

        console.log("HISTORY DATA:", history);

        const labels = history.map(
            item => new Date(item.collected_at).toLocaleTimeString()
        );

        const cpuData = history.map(
            item => item.cpu_usage
        );

        const memoryData = history.map(
            item => item.memory_usage
        );

        const diskData = history.map(
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

    console.log("Calling anomaly API...");

    try {

        const response = await fetch(
            "http://192.168.38.146:8000/anomalies",
            {
                method: "GET",
                mode: "cors",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error("HTTP error: " + response.status);
        }

        const anomalies = await response.json();

        console.log("ANOMALY DATA:", anomalies);

        updateAnomaly("cpuAnomaly", anomalies.cpu);
        updateAnomaly("memoryAnomaly", anomalies.memory);
        updateAnomaly("diskAnomaly", anomalies.disk);

    } catch (error) {

        console.error("ANOMALY ERROR:", error);

        updateAnomalyError("cpuAnomaly");
        updateAnomalyError("memoryAnomaly");
        updateAnomalyError("diskAnomaly");
    }
}


// ============================================================
// UPDATE ANOMALY STATUS
// ============================================================

function updateAnomaly(elementId, result) {

    const element = document.getElementById(elementId);

    if (!element || !result) {
        return;
    }

    element.innerText = result.status || result.reason || "Unknown";
    element.className = "anomaly-status";

    if (result.status === "Normal") {

        element.classList.add("normal");

    } else if (result.status === "Warning") {

        element.classList.add("warning");

    } else if (result.status === "Anomaly") {

        element.classList.add("anomaly");

    } else {

        element.classList.add("unknown");
    }
}


// ============================================================
// ANOMALY ERROR
// ============================================================

function updateAnomalyError(elementId) {

    const element = document.getElementById(elementId);

    if (!element) {
        return;
    }

    element.innerText = "Unavailable";
    element.className = "anomaly-status unknown";
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


    // ========================================================
    // CPU CHART
    // ========================================================

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


    // ========================================================
    // MEMORY CHART
    // ========================================================

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


    // ========================================================
    // DISK CHART
    // ========================================================

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
// INITIAL LOAD
// ============================================================

loadDashboard();
loadHistory();
loadAnomalies();


// ============================================================
// AUTO REFRESH EVERY 5 SECONDS
// ============================================================

setInterval(loadDashboard, 5000);
setInterval(loadHistory, 5000);
setInterval(loadAnomalies, 5000);

// ============================================================
// SSH SECURITY EVENTS
// ============================================================

async function loadSSHEvents() {

    try {

        const response = await fetch(
            "http://192.168.38.146:8000/ssh/events?limit=20"
        );

        const events = await response.json();

        const table = document.getElementById("sshEventsTable");
        const failedLogins = document.getElementById("failedLogins");
        const successfulLogins = document.getElementById("successfulLogins");

        let failed = 0;
        let successful = 0;

        table.innerHTML = "";

        events.forEach(event => {

            if (event.event_type === "FAILED_LOGIN") {
                failed++;
            }

            if (event.event_type === "SUCCESSFUL_LOGIN") {
                successful++;
            }

            const row = document.createElement("tr");

            row.innerHTML = `
                <td>${new Date(event.event_time).toLocaleString()}</td>
                <td>${event.event_type}</td>
                <td>${event.username}</td>
                <td>${event.source_ip}</td>
            `;

            table.appendChild(row);
        });

        failedLogins.textContent = failed;
        successfulLogins.textContent = successful;

        if (events.length === 0) {
            table.innerHTML = `
                <tr>
                    <td colspan="4">No SSH events found</td>
                </tr>
            `;
        }

    } catch (error) {

        console.error("SSH event loading failed:", error);

    }
}

loadSSHEvents();

setInterval(loadSSHEvents, 5000);

// ============================================================
// SECURITY ALERTS
// ============================================================

async function loadSecurityAlerts() {

    try {

        const response = await fetch(
            "http://192.168.38.146:8000/security/alerts",
            {
                method: "GET",
                mode: "cors",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error("HTTP error: " + response.status);
        }

        const alerts = await response.json();

// ========================================================
// UPDATE SECURITY RISK COUNTERS
// ========================================================

const highRiskEvents = document.getElementById("highRiskEvents");
const criticalEvents = document.getElementById("criticalEvents");

const highRiskCount = alerts.filter(
    alert => alert.alert_level === "HIGH"
).length;

const criticalCount = alerts.filter(
    alert => alert.alert_level === "CRITICAL"
).length;

if (highRiskEvents) {
    highRiskEvents.textContent = highRiskCount;
}

if (criticalEvents) {
    criticalEvents.textContent = criticalCount;
}

        console.log("SECURITY ALERT DATA:", alerts);

        const table = document.getElementById(
            "securityAlertsTable"
        );

        if (!table) {
            console.error("Security alerts table not found");
            return;
        }

        table.innerHTML = "";

        if (alerts.length === 0) {

            table.innerHTML = `
                <tr>
                    <td colspan="6">No security alerts</td>
                </tr>
            `;

            return;
        }

        alerts.forEach(alert => {

            const row = document.createElement("tr");

            row.innerHTML = `
                <td>${new Date(alert.event_time).toLocaleString()}</td>
                <td>${alert.event_type}</td>
                <td>${alert.username}</td>
                <td>${alert.source_ip}</td>
                <td>${alert.risk_score}</td>
                <td>${alert.reason}</td>
            `;

            table.appendChild(row);
        });

    } catch (error) {

        console.error(
            "SECURITY ALERT ERROR:",
            error
        );

        const table = document.getElementById(
            "securityAlertsTable"
        );

        if (table) {

            table.innerHTML = `
                <tr>
                    <td colspan="6">
                        Unable to load security alerts
                    </td>
                </tr>
            `;
        }
    }
}


// Initial security alert load
loadSecurityAlerts();


// Refresh security alerts every 5 seconds
setInterval(loadSecurityAlerts, 5000);
