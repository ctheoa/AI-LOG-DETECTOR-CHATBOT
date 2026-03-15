import json
import re
from collections import defaultdict
from datetime import datetime

OUTPUT = "/app/storage/detection_results.json"


def extract_ip(log):

    match = re.search(r'\d+\.\d+\.\d+\.\d+', log)

    if match:
        return match.group()

    return "unknown"


def detect_attacks(log):

    attacks = []

    if "union select" in log.lower():
        attacks.append("sql_injection")

    if "<script>" in log.lower():
        attacks.append("xss")

    if "../" in log:
        attacks.append("path_traversal")

    if "failed password" in log.lower():
        attacks.append("brute_force")

    if not attacks:
        attacks.append("normal")

    return attacks


def analyze_master_log(master_path):

    ip_data = defaultdict(lambda: {
        "requests": 0,
        "attacks": defaultdict(int)
    })

    with open(master_path, "r", errors="ignore") as f:

        for line in f:

            ip = extract_ip(line)

            attacks = detect_attacks(line)

            ip_data[ip]["requests"] += 1

            for a in attacks:
                ip_data[ip]["attacks"][a] += 1

    results = []

    for ip, d in ip_data.items():

        threat = sum(d["attacks"].values())

        results.append({
            "ip": ip,
            "threat_score": threat,
            "attacks": dict(d["attacks"]),
            "total_requests": d["requests"],
            "max_severity": min(10, threat)
        })

    results.sort(key=lambda x: x["threat_score"], reverse=True)

    output = {
        "generated_at": str(datetime.now()),
        "total_logs": sum(x["total_requests"] for x in results),
        "unique_ips": len(results),
        "suspicious_ips_count": len(results),
        "suspicious_ips": results
    }

    with open(OUTPUT, "w") as f:
        json.dump(output, f, indent=2)

    return output
