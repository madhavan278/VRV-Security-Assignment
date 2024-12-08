import re
import csv
from collections import Counter, defaultdict

# File paths
log_file_path = "sample.log"
output_csv = "log_analysis_results.csv"

# Threshold for suspicious activity
failed_login_threshold = 10


def parse_log_file(log_file_path):
    """Parse the log file and extract necessary information."""
    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_logins = defaultdict(int)

    # Regex patterns
    log_pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?"(?P<method>\w+)\s(?P<endpoint>/\S*).*?"\s(?P<status>\d+).*')
    failed_login_pattern = re.compile(r'401|Invalid credentials')

    with open(log_file_path, 'r') as log_file:
        for line in log_file:
            match = log_pattern.match(line)
            if match:
                ip = match.group("ip")
                endpoint = match.group("endpoint")
                status = match.group("status")

                # Count requests per IP and endpoint
                ip_requests[ip] += 1
                endpoint_requests[endpoint] += 1

                # Identify failed login attempts
                if failed_login_pattern.search(line):
                    failed_logins[ip] += 1

    return ip_requests, endpoint_requests, failed_logins


def detect_suspicious_activity(failed_logins, threshold):
    """Identify IPs with failed login attempts above the threshold."""
    return {ip: count for ip, count in failed_logins.items() if count > threshold}


def save_results_to_csv(ip_requests, most_accessed, suspicious_activity, output_csv):
    """Save analysis results to a CSV file."""
    with open(output_csv, mode='w', newline='') as csv_file:
        writer = csv.writer(csv_file)

        # Write Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])
        writer.writerow([])

        # Write Most Accessed Endpoint
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])
        writer.writerow([])

        # Write Suspicious Activity
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])


def main():
    # Parse log file
    ip_requests, endpoint_requests, failed_logins = parse_log_file(log_file_path)

    # Most accessed endpoint
    most_accessed_endpoint = endpoint_requests.most_common(1)[0]

    # Detect suspicious activity
    suspicious_activity = detect_suspicious_activity(failed_logins, failed_login_threshold)

    # Display results
    print("Requests per IP:")
    for ip, count in ip_requests.most_common():
        print(f"{ip:20} {count}")
    print()

    print(
        f"Most Frequently Accessed Endpoint:\n{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    print()

    print("Suspicious Activity Detected:")
    for ip, count in suspicious_activity.items():
        print(f"{ip:20} {count}")
    print()

    # Save results to CSV
    save_results_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity, output_csv)
    print(f"Results saved to {output_csv}")


if __name__ == "__main__":
    main()
