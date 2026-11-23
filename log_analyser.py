from collections import Counter

# Sample authentication log lines (simulating server login events)
SAMPLE_LOGS = [
    "2026-11-23 09:01:12 | IP: 192.168.1.15 | USER: admin | STATUS: FAILED",
    "2026-11-23 09:01:15 | IP: 192.168.1.15 | USER: admin | STATUS: FAILED",
    "2026-11-23 09:01:19 | IP: 192.168.1.15 | USER: admin | STATUS: FAILED",
    "2026-11-23 09:01:22 | IP: 192.168.1.15 | USER: admin | STATUS: FAILED",
    "2026-11-23 09:05:40 | IP: 10.0.0.8 | USER: joshua | STATUS: SUCCESS",
    "2026-11-23 09:12:03 | IP: 172.16.0.22 | USER: guest | STATUS: FAILED",
    "2026-11-23 09:14:51 | IP: 10.0.0.8 | USER: joshua | STATUS: SUCCESS",
]

ALERT_THRESHOLD = 3

def analyse_logs(log_lines, threshold=ALERT_THRESHOLD):
    failed_ips = Counter()

    for line in log_lines:
        if "STATUS: FAILED" in line:
            parts = [part.strip() for part in line.split("|")]
            ip_address = parts[1].replace("IP: ", "")
            failed_ips[ip_address] += 1

    print("=== Authentication Log Security Summary ===")
    print(f"Total log entries scanned: {len(log_lines)}")
    print(f"Total failed login attempts: {sum(failed_ips.values())}\n")

    suspicious_found = False
    for ip, count in failed_ips.items():
        if count >= threshold:
            suspicious_found = True
            print(f"[ALERT] Possible brute-force activity from {ip} ({count} failed attempts)")
        else:
            print(f"[INFO] {ip} had {count} failed attempt(s) (below alert threshold)")

    if not suspicious_found:
        print("No suspicious brute-force patterns detected.")

if __name__ == "__main__":
    analyse_logs(SAMPLE_LOGS)
  
