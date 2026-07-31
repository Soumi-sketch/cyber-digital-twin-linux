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
            "http://127.0.0.1:8000/health",
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
            "http://127.0.0.1:8000/metrics/history?limit=50",
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
// INITIAL LOAD
// ============================================================

loadDashboard();
loadHistory();


// ============================================================
// AUTO REFRESH EVERY 5 SECONDS
// ============================================================

setInterval(loadDashboard, 5000);
setInterval(loadHistory, 5000);
