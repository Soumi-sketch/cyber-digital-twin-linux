import paramiko

from backend.operations import save_metrics

from backend.collector.parser import (
    parse_cpu,
    parse_memory,
    parse_disk
)

HOST = "192.168.38.145"
USERNAME = "root"
PASSWORD = os.getenv("PASSWORD")


def collect_remote_data():

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    client.connect(
        hostname=HOST,
        username=USERNAME,
        password=PASSWORD
    )

    commands = {
        "hostname": "hostname",
        "ip_address": "hostname -I | awk '{print $1}'",
        "operating_system": "uname -s",
        "kernel_version": "uname -r",
        "cpu_raw": "top -bn1 | grep 'Cpu(s)'",
        "memory_raw": "free -m",
        "disk_raw": "df -h /",
        "uptime": "uptime -p"
    }

    raw_data = {}

    for key, command in commands.items():
        stdin, stdout, stderr = client.exec_command(command)
        raw_data[key] = stdout.read().decode().strip()

    client.close()

    data = {
        "hostname": raw_data["hostname"],
        "ip_address": raw_data["ip_address"],
        "operating_system": raw_data["operating_system"],
        "kernel_version": raw_data["kernel_version"],
        "cpu_usage": parse_cpu(raw_data["cpu_raw"]),
        "memory_usage": parse_memory(raw_data["memory_raw"]),
        "disk_usage": parse_disk(raw_data["disk_raw"]),
        "uptime": raw_data["uptime"]
    }

    print(data)

    save_metrics(data)

    print("✅ Data stored successfully.")

    return data


if __name__ == "__main__":
    collect_remote_data()
