"""
SOC Attack Log Generator (IOC-Aware)
-----------------------------------
Generates realistic SOC attack logs including IOC hits.

✔ Normal traffic
✔ Multiple attack classes
✔ Random IOC-confirmed threats
✔ SOC-grade realism
"""

import random
from datetime import datetime, timedelta
from pathlib import Path

# ================= CONFIG =================

OUTPUT_DIR = Path("data/test_logs")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

TOTAL_LOGS = 800               # Increase to 5000 / 10000 for stress tests
IOC_HIT_RATIO = 0.12           # 🔥 12% of attack traffic = IOC-confirmed
START_TIME = datetime.utcnow()

# ================= IOC DATA =================
# These IPs SHOULD EXIST in your IOC feed
IOC_IPS = [
    "45.133.192.77",
    "185.234.219.12",
    "103.21.244.0",
    "172.67.88.9",
]

# ================= ATTACK PATTERNS =================

ATTACKS = [
    ("BRUTE_FORCE", [
        "POST /login HTTP/1.1 401",
        "POST /auth HTTP/1.1 403"
    ]),
    ("SQL_INJECTION", [
        "GET /login.php?user=admin'-- HTTP/1.1 500",
        "GET /index.php?id=1 UNION SELECT password FROM users HTTP/1.1 500"
    ]),
    ("XSS", [
        "GET /search?q=<script>alert(1)</script> HTTP/1.1 200",
        "GET /comment?msg=<img src=x onerror=alert(1)> HTTP/1.1 200"
    ]),
    ("DIR_TRAVERSAL", [
        "GET /../../etc/passwd HTTP/1.1 403",
        "GET /../../windows/system32/config HTTP/1.1 403"
    ]),
    ("MALWARE_C2", [
        "POST /beacon HTTP/1.1 200",
        "POST /api/update HTTP/1.1 200",
        "POST /command HTTP/1.1 200"
    ])
]

NORMAL_TRAFFIC = [
    "GET /index.html HTTP/1.1 200",
    "GET /assets/app.js HTTP/1.1 200",
    "GET /favicon.ico HTTP/1.1 200"
]

NORMAL_IPS = [
    "192.168.1.10",
    "10.0.0.5",
    "172.16.0.3"
]

# ================= GENERATOR =================

def generate_log_line(ts, ip, request):
    return f"{ts} {ip} {request}"

def generate_logs():
    logs = []
    current_time = START_TIME

    for _ in range(TOTAL_LOGS):
        current_time += timedelta(seconds=random.randint(1, 4))
        ts = current_time.strftime("%Y-%m-%d %H:%M:%S")

        # Normal traffic majority
        if random.random() < 0.60:
            ip = random.choice(NORMAL_IPS)
            req = random.choice(NORMAL_TRAFFIC)
        else:
            # Attack traffic
            attack_type, patterns = random.choice(ATTACKS)
            req = random.choice(patterns)

            # IOC hit logic
            if random.random() < IOC_HIT_RATIO:
                ip = random.choice(IOC_IPS)   # 🔥 IOC-confirmed
            else:
                ip = f"185.{random.randint(10,250)}.{random.randint(1,254)}.{random.randint(1,254)}"

        logs.append(generate_log_line(ts, ip, req))

    return logs

# ================= MAIN =================

def main():
    log_file = OUTPUT_DIR / "soc_attacks_with_ioc.log"
    logs = generate_logs()

    with open(log_file, "w", encoding="utf-8") as f:
        f.write("\n".join(logs))

    print("✅ SOC Attack Logs with IOC hits generated")
    print(f"📄 File: {log_file}")
    print(f"📊 Total Logs: {len(logs)}")
    print(f"🧠 IOC Hit Ratio: {int(IOC_HIT_RATIO * 100)}%")

if __name__ == "__main__":
    main()
