import psutil
import platform
import socket

def collect_system_info():
    data = {
        "hostname": socket.gethostname(),
        "operating_system": platform.system(),
        "os_version": platform.release(),
        "cpu_usage": psutil.cpu_percent(interval=1),
        "memory_usage": psutil.virtual_memory().percent,
        "disk_usage": psutil.disk_usage("/").percent,
        "boot_time": psutil.boot_time()
    }

    return data

if __name__ == "__main__":
    print(collect_system_info())
