console.log("=== CYBER DIGITAL TWIN APP.JS LOADED ===");

const API = "http://192.168.38.146:8000";

let cpuChart;
let memoryChart;
let diskChart;


// ============================================================
// LOAD CURRENT HEALTH
// ============================================================

async function loadDashboard() {

    try {

        const response = await fetch(
            `${API}/health`,
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

    try {

        const response = await fetch(
            `${API}/metrics/history?limit=50`,
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

    try {

        const response = await fetch(
            `${API}/anomalies`,
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

    element.innerText =
        result.status || result.reason || "Unknown";

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

        // Get SSH events
        const eventsResponse = await fetch(
            `${API}/ssh/events?limit=20`,
            {
                method: "GET",
                mode: "cors",
                cache: "no-store"
            }
        );

        if (!eventsResponse.ok) {
            throw new Error(
                "SSH events HTTP error: " +
                eventsResponse.status
            );
        }

        const events = await eventsResponse.json();


        // Get security alerts
        const alertsResponse = await fetch(
            `${API}/security/alerts`,
            {
                method: "GET",
                mode: "cors",
                cache: "no-store"
            }
        );

        if (!alertsResponse.ok) {
            throw new Error(
                "Security alerts HTTP error: " +
                alertsResponse.status
            );
        }

        const alerts = await alertsResponse.json();


        // ====================================================
        // CREATE ALERT LOOKUP
        // ====================================================

        const alertMap = new Map();

        alerts.forEach(alert => {

            alertMap.set(
                alert.event_id,
                alert
            );

        });


        // ====================================================
        // HTML ELEMENTS
        // ====================================================

        const table =
            document.getElementById("sshEventsTable");

        const failedLogins =
            document.getElementById("failedLogins");

        const successfulLogins =
            document.getElementById("successfulLogins");

        const highRiskEvents =
            document.getElementById("highRiskEvents");

        const criticalEvents =
            document.getElementById("criticalEvents");


        if (!table) {
            console.error("SSH events table not found");
            return;
        }


        // ====================================================
        // COUNTERS
        // ====================================================

        let failed = 0;
        let successful = 0;

        events.forEach(event => {

            if (event.event_type === "FAILED_LOGIN") {
                failed++;
            }

            if (event.event_type === "SUCCESSFUL_LOGIN") {
                successful++;
            }
        });


        if (failedLogins) {
            failedLogins.textContent = failed;
        }

        if (successfulLogins) {
            successfulLogins.textContent = successful;
        }


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


        // ====================================================
        // DISPLAY SSH EVENTS
        // ====================================================

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

            // Find matching security alert
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
                    ${event.username}
                </td>

                <td>
                    ${event.source_ip}
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
// SECURITY ALERTS TABLE
// ============================================================

async function loadSecurityAlerts() {

    try {

        const response = await fetch(
            `${API}/security/alerts`,
            {
                method: "GET",
                mode: "cors",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(
                "HTTP error: " +
                response.status
            );
        }

        const alerts =
            await response.json();


        console.log(
            "SECURITY ALERT DATA:",
            alerts
        );


        const table =
            document.getElementById(
                "securityAlertsTable"
            );


        if (!table) {
            console.error(
                "Security alerts table not found"
            );

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
                    ${alert.username}
                </td>

                <td>
                    ${alert.source_ip}
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


        const table =
            document.getElementById(
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


// ============================================================
// INITIAL LOAD
// ============================================================

loadDashboard();
loadHistory();
loadAnomalies();
loadSSHEvents();
loadSecurityAlerts();
loadSecurityIncidents();

// ============================================================
// AUTO REFRESH
// ============================================================

setInterval(
    loadDashboard,
    5000
);

setInterval(
    loadHistory,
    5000
);

setInterval(
    loadAnomalies,
    5000
);

setInterval(
    loadSSHEvents,
    5000
);

setInterval(
    loadSecurityAlerts,
    5000
);

setInterval(
    loadSecurityIncidents,
    5000
);

// ============================================================
// SECURITY INCIDENTS
// ============================================================

async function loadSecurityIncidents() {

    try {

        const response = await fetch(
            `${API}/security/incidents`,
            {
                method: "GET",
                mode: "cors",
                cache: "no-store"
            }
        );

        if (!response.ok) {

            throw new Error(
                "Security incidents HTTP error: " +
                response.status
            );

        }

        const incidents =
            await response.json();

        console.log(
            "SECURITY INCIDENT DATA:",
            incidents
        );


        const table =
            document.getElementById(
                "securityIncidentsTable"
            );


        if (!table) {

            console.error(
                "Security incidents table not found"
            );

            return;
        }


        table.innerHTML = "";


        if (incidents.length === 0) {

            table.innerHTML = `
                <tr>
                    <td colspan="9">
                        No security incidents detected
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
                    ${incident.username}
                </td>

                <td>
                    ${incident.source_ip}
                </td>

                <td>
                    ${incident.total_attempts}
                </td>

                <td>
                    ${incident.failed_logins}
                </td>

                <td>
                    ${incident.invalid_users}
                </td>

                <td>
                    ${new Date(
                        incident.start_time
                    ).toLocaleString()}
                </td>

                <td>
                    ${new Date(
                        incident.end_time
                    ).toLocaleString()}
                </td>
            `;


            table.appendChild(row);

        });

    } catch (error) {

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
                    <td colspan="9">
                        Unable to load security incidents
                    </td>
                </tr>
            `;

        }

    }

}
