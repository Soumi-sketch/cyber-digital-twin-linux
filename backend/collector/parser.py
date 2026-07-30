import re

def parse_cpu(cpu_output):
    """
    Extract CPU system usage percentage.
    Example:
    %Cpu(s): 0.0 us, 7.7 sy, 92.3 id
    """

    match = re.search(r'([\d.]+)\s+sy', cpu_output)

    if match:
        return float(match.group(1))

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
