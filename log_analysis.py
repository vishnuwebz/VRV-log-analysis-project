import re
from collections import defaultdict, Counter
import csv


# Function to parse log file and return a list of log entries
def parse_log_file(file_path):
    with open(file_path, 'r') as file:
        logs = file.readlines()
    return logs


# Function to count requests per IP
def count_requests_per_ip(logs):
    ip_count = Counter()
    for log in logs:
        match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', log)
        if match:
            ip_count[match.group(1)] += 1
    return ip_count


# Function to identify the most frequently accessed endpoint
def most_frequent_endpoint(logs):
    endpoint_count = Counter()
    for log in logs:
        match = re.search(r'\"(?:GET|POST) (\/\S+)', log)
        if match:
            endpoint_count[match.group(1)] += 1
    most_common = endpoint_count.most_common(1)
    return most_common[0] if most_common else None


# Function to detect suspicious activity
def detect_suspicious_activity(logs, threshold=1):  # Set to 1 for detecting any failed login
    failed_attempts = defaultdict(int)
    for log in logs:
        if "401" in log or "Invalid credentials" in log:
            match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', log)
            if match:
                failed_attempts[match.group(1)] += 1
    suspicious_ips = {ip: count for ip, count in failed_attempts.items() if count > threshold}
    return suspicious_ips


# Function to save results to a CSV file
def save_to_csv(ip_requests, most_accessed, suspicious_activity, file_name='log_analysis_results.csv'):
    with open(file_name, 'w', newline='') as file:
        writer = csv.writer(file)

        # Write Requests per IP
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(['Endpoint', 'Access Count'])
        if most_accessed:
            writer.writerow(most_accessed)

        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])


# Main script execution
if __name__ == "__main__":
    log_file_path = 'sample.log'  # Actual path to the log file
    logs = parse_log_file(log_file_path)

    # Count requests per IP
    ip_requests = count_requests_per_ip(logs)
    print("IP Address     Request Count")
    for ip, count in ip_requests.most_common():
        print(f"{ip:<15} {count}")

    # Identify the most frequently accessed endpoint
    most_accessed = most_frequent_endpoint(logs)
    if most_accessed:
        print("\nMost Frequently Accessed Endpoint:")
        print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    # Detect suspicious activity
    suspicious_activity = detect_suspicious_activity(logs)
    print("\nSuspicious Activity Detected:")
    if suspicious_activity:
        print("IP Address     Failed Login Attempts")
        for ip, count in suspicious_activity.items():
            print(f"{ip:<15} {count}")
    else:
        print("No suspicious activity detected.")

    # Save results to CSV
    save_to_csv(ip_requests, most_accessed, suspicious_activity)
    print("\nResults saved to 'log_analysis_results.csv'")
