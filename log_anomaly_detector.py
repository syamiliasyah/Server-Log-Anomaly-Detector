from collections import defaultdict
from log_parser_rules import FAILED_LOGIN_PATTERN, WEB_FUZZ_PATTERN, match_pattern
from mock_logs_generator import SAMPLE_LOGS

def parse_logs(log_data):
    print("=== STARTING LOG ANOMALY INSPECTION ===")
    
    failed_logins = defaultdict(int)
    suspicious_paths = []

    for line in log_data.strip().split("\n"):
        # Detect Failed SSH Logins
        ip = match_pattern(FAILED_LOGIN_PATTERN, line)
        if ip:
            failed_logins[ip] += 1

        # Detect Web Probing
        path = match_pattern(WEB_FUZZ_PATTERN, line)
        if path:
            ip_addr = line.split()[2] if len(line.split()) > 2 else "UNKNOWN_IP"
            suspicious_paths.append((ip_addr, path))

    # Print Findings
    print("\n[!] SUSPICIOUS BRUTE-FORCE ACTIVITY:")
    for ip, count in failed_logins.items():
        if count >= 3:
            print(f" -> ALERT: IP {ip} exceeded failure threshold ({count} failed login attempts)")

    print("\n[!] SUSPICIOUS DIRECTORY PROBING:")
    for ip, path in suspicious_paths:
        print(f" -> ALERT: Potential probe from IP {ip} requesting sensitive path: {path}")

if __name__ == "__main__":
    parse_logs(SAMPLE_LOGS)
