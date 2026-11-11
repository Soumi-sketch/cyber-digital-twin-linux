"""
Conservative suspicious-process detection for the Cyber Digital Twin.

This module analyses process inventory records. It does not execute,
terminate, or modify processes on monitored hosts.
"""

import logging

logger = logging.getLogger("cyber_process_detection")


# Exact process-name indicators.
# Dual-use tools are MEDIUM because they can be legitimate admin utilities.
PROCESS_INDICATORS = {
    "xmrig": {
        "severity": "CRITICAL",
        "risk_score": 95,
        "category": "CRYPTO_MINER",
        "reason": "Known cryptocurrency-mining process indicator"
    },
    "kinsing": {
        "severity": "CRITICAL",
        "risk_score": 95,
        "category": "MALWARE",
        "reason": "Known Linux malware process indicator"
    },
    "kdevtmpfsi": {
        "severity": "CRITICAL",
        "risk_score": 95,
        "category": "MALWARE",
        "reason": "Known Linux malware process indicator"
    },
    "meterpreter": {
        "severity": "HIGH",
        "risk_score": 85,
        "category": "POST_EXPLOITATION",
        "reason": "Metasploit Meterpreter process indicator"
    },
    "msfconsole": {
        "severity": "HIGH",
        "risk_score": 80,
        "category": "PENETRATION_TESTING",
        "reason": "Metasploit console process indicator"
    },
    "mimikatz": {
        "severity": "HIGH",
        "risk_score": 85,
        "category": "CREDENTIAL_ACCESS",
        "reason": "Credential-dumping tool process indicator"
    },
    "chisel": {
        "severity": "MEDIUM",
        "risk_score": 60,
        "category": "TUNNELING",
        "reason": "Tunneling utility requires investigation"
    },
    "socat": {
        "severity": "MEDIUM",
        "risk_score": 55,
        "category": "NETWORK_RELAY",
        "reason": "Network relay utility requires investigation"
    },
    "ncat": {
        "severity": "MEDIUM",
        "risk_score": 55,
        "category": "NETWORK_UTILITY",
        "reason": "Network utility requires investigation"
    },
    "nc": {
        "severity": "MEDIUM",
        "risk_score": 55,
        "category": "NETWORK_UTILITY",
        "reason": "Netcat process requires investigation"
    },
    "netcat": {
        "severity": "MEDIUM",
        "risk_score": 55,
        "category": "NETWORK_UTILITY",
        "reason": "Netcat process requires investigation"
    }
}


def detect_suspicious_processes(processes, hostname):
    """
    Evaluate process records against exact-name indicators.

    Returns findings only. No automatic response is performed.
    """

    findings = []

    for process in processes:
        process_name = str(
            process.get("process_name", "")
        ).strip().lower()

        indicator = PROCESS_INDICATORS.get(process_name)

        if not indicator:
            continue

        finding = {
            "hostname": hostname,
            "pid": process.get("pid"),
            "ppid": process.get("ppid"),
            "username": process.get("username"),
            "process_name": process_name,
            "cpu_percent": process.get("cpu_percent"),
            "memory_percent": process.get("memory_percent"),
            "severity": indicator["severity"],
            "risk_score": indicator["risk_score"],
            "category": indicator["category"],
            "reason": indicator["reason"],
            "detection_type": "PROCESS_NAME_INDICATOR"
        }

        findings.append(finding)

    logger.info(
        "Process detection completed for %s: %d findings from %d processes",
        hostname,
        len(findings),
        len(processes)
    )

    return findings
