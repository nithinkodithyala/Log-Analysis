import re
import csv
from collections import defaultdict

LOG_FILE = "sample.log"
OUTPUT_CSV = "log_analysis_results.csv"
FAILED_LOGIN_THRESHOLD = 10
LOG_PATTERN = r'(?P<ip>\d+\.\d+\.\d+\.\d+).*"\s?(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s(?P<endpoint>/\S*)\sHTTP/\d+\.\d+"\s(?P<status>\d+)\s.*'

def parse_log_file(file_path):
    ip_requests = defaultdict(int)
    endpoint_accesses = defaultdict(int)
    failed_logins = defaultdict(int)

    with open(file_path, 'r') as file:
        for line in file:
            match = re.match(LOG_PATTERN, line)
            if match:
                ip = match.group('ip')
                endpoint = match.group('endpoint')
                status = int(match.group('status'))
                
                # Count requests per IP
                ip_requests[ip] += 1

                # Count endpoint accesses
                endpoint_accesses[endpoint] += 1

                # Count failed login attempts
                if status == 401:  # HTTP 401 Unauthorized
                    failed_logins[ip] += 1

    return ip_requests, endpoint_accesses, failed_logins

def count_requests_per_ip(ip_requests):
    return sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)

def most_frequently_accessed_endpoint(endpoint_accesses):
    return max(endpoint_accesses.items(), key=lambda x: x[1])

def detect_suspicious_activity(failed_logins, threshold):
    return {ip: count for ip, count in failed_logins.items() if count > threshold}

def save_results_to_csv(ip_requests, most_accessed_endpoint, suspicious_activities):
    with open(OUTPUT_CSV, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_requests)
        
        writer.writerow([])
        
        # Most Accessed Endpoint
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
        
        writer.writerow([])
        
        # Suspicious Activities
        writer.writerow(["Suspicious Activity - IP Address", "Failed Login Count"])
        writer.writerows(suspicious_activities.items())

def main():
    # Parse the log file
    ip_requests, endpoint_accesses, failed_logins = parse_log_file(LOG_FILE)
    
    # Analyze results
    ip_request_counts = count_requests_per_ip(ip_requests)
    most_accessed_endpoint = most_frequently_accessed_endpoint(endpoint_accesses)
    suspicious_activities = detect_suspicious_activity(failed_logins, FAILED_LOGIN_THRESHOLD)
    
    # Display results
    print("IP Address           Request Count")
    for ip, count in ip_request_counts:
        print(f"{ip:<20}{count}")
    print()
    
    print(f"Most Frequently Accessed Endpoint:\n{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    print()
    
    print("Suspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_activities.items():
        print(f"{ip:<20}{count}")
    
    # Save results to CSV
    save_results_to_csv(ip_request_counts, most_accessed_endpoint, suspicious_activities)

if __name__ == "__main__":
    main()
