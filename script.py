from typing import Dict, List, Tuple

import re
import csv
from collections import Counter

from config import LOG_FILE, OUTPUT_FILE, FAILED_LOGIN_THRESHOLD


def parse_log_file(file_path: str) -> List[str]:
    """Parses the log file and returns a list of log entries."""
    with open(file_path, "r") as file:
        return file.readlines()


def count_requests_per_ip(log_entries: List[str]) -> Counter:
    """Counts requests per IP address."""
    ip_counter: Counter = Counter()
    for entry in log_entries:
        match = re.match(r"(\d+\.\d+\.\d+\.\d+)", entry)
        if match:
            ip_counter[match.group(1)] += 1
    return ip_counter


def find_most_frequent_endpoint(log_entries: List[str]) -> Tuple[str, int]:
    """Finds the most frequently accessed endpoint."""
    endpoint_counter: Counter = Counter()
    for entry in log_entries:
        match = re.search(r"\"(?:GET|POST|PUT|DELETE|HEAD) (\S+) HTTP", entry)
        if match:
            endpoint_counter[match.group(1)] += 1
    return endpoint_counter.most_common(1)[0] if endpoint_counter else (None, 0)


def detect_suspicious_activity(
    log_entries: List[str], threshold: int
) -> Dict[str, int]:
    """Detects suspicious activity based on failed login attempts."""
    failed_attempts: Counter = Counter()
    for entry in log_entries:
        if "401" in entry or "Invalid credentials" in entry:
            match = re.match(r"(\d+\.\d+\.\d+\.\d+)", entry)
            if match:
                failed_attempts[match.group(1)] += 1
    return {ip: count for ip, count in failed_attempts.items() if count > threshold}


def save_results_to_csv(
    ip_counts: Counter,
    most_accessed: Tuple[str, int],
    suspicious_activities: Dict[str, int],
    output_file: str,
) -> None:
    """Saves results to a CSV file."""
    with open(output_file, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)

        # Write IP request counts
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])

        # Write most accessed endpoint
        writer.writerow([])  # Blank row
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(most_accessed)

        # Write suspicious activity
        writer.writerow([])  # Blank row
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activities.items():
            writer.writerow([ip, count])


def main() -> None:
    log_entries: List[str] = parse_log_file(LOG_FILE or "logs/sample.log")

    # Count requests per IP
    ip_counts: Counter = count_requests_per_ip(log_entries)

    # Find the most accessed endpoint
    most_accessed: Tuple[str, int] = find_most_frequent_endpoint(log_entries)

    # Detect suspicious activity
    suspicious_activities: Dict[str, int] = detect_suspicious_activity(
        log_entries, FAILED_LOGIN_THRESHOLD or 10
    )

    # Display results
    print("IP Address           Request Count")
    for ip, count in ip_counts.most_common():
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_activities.items():
        print(f"{ip:<20} {count}")

    # Save results to CSV
    save_results_to_csv(
        ip_counts,
        most_accessed,
        suspicious_activities,
        OUTPUT_FILE or "out/log_analysis_results.csv",
    )
    print(f"\nResults saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
