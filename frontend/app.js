console.log("=== CYBER DIGITAL TWIN APP.JS LOADED ===");

async function loadDashboard() {
    console.log("Calling API...");

    try {
        const response = await fetch(
            "http://192.168.38.146:8000/health",
            {
                method: "GET",
                mode: "cors",
                cache: "no-store"
            }
        );

        console.log("API response:", response.status);

        if (!response.ok) {
            throw new Error("HTTP error: " + response.status);
        }

        const server = await response.json();

        console.log("SERVER DATA:", server);

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

loadDashboard();

setInterval(loadDashboard, 2000);
