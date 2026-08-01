import re


def parse_cpu(cpu_output):
    """
    Calculate total CPU usage from top output.

    CPU usage = 100 - idle - iowait
    """

    idle_match = re.search(r'([\d.]+)\s+id', cpu_output)
    iowait_match = re.search(r'([\d.]+)\s+wa', cpu_output)

    if idle_match:
        idle = float(idle_match.group(1))
        iowait = float(iowait_match.group(1)) if iowait_match else 0.0

        return round(100.0 - idle - iowait, 2)

    return 0.0


def parse_memory(memory_output):
    """
    Calculate memory usage percentage.
    """

    lines = memory_output.splitlines()

    for line in lines:
        if line.startswith("Mem:"):
            parts = line.split()

            total = float(parts[1])
            used = float(parts[2])

            return round((used / total) * 100, 2)

    return 0.0


def parse_disk(disk_output):
    """
    Extract disk usage percentage.
    """

    lines = disk_output.splitlines()

    if len(lines) >= 2:
        parts = lines[1].split()

        usage = parts[4].replace("%", "")

        return float(usage)

    return 0.0
