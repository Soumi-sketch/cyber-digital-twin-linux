async function loadDashboard() {

    const response = await fetch("http://127.0.0.1:8000/health");

    const data = await response.json();

    const server = data[0];

    document.getElementById("hostname").innerText = server.hostname;
    document.getElementById("status").innerText = server.status;
    document.getElementById("cpu").innerText = server.cpu_usage + " %";
    document.getElementById("memory").innerText = server.memory_usage + " %";
    document.getElementById("disk").innerText = server.disk_usage + " %";
}

loadDashboard();

// Refresh every 5 seconds
setInterval(loadDashboard, 5000);
