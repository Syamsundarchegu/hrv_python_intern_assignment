import re
import csv
from collections import defaultdict

# Define thresholds
FAILED_LOGIN_THRESHOLD = 10

# Function to count requests per IP address
def count_requests_per_ip(log_file):
    ip_request_count = defaultdict(int)
    
    with open(log_file, 'r') as file:
        for line in file:
            # Extract IP address using regex
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            if ip_match:
                ip_address = ip_match.group(0)
                ip_request_count[ip_address] += 1

    return ip_request_count

# Function to identify the most frequently accessed endpoint
def most_accessed_endpoint(log_file):
    endpoint_count = defaultdict(int)
    
    with open(log_file, 'r') as file:
        for line in file:
            # Extract endpoint using regex
            endpoint_match = re.search(r'\"[A-Z]+\s(/[^"]+)', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_count[endpoint] += 1
    
    if endpoint_count:
        most_accessed = max(endpoint_count, key=endpoint_count.get)
        return most_accessed, endpoint_count[most_accessed]
    else:
        return None, 0

# Function to detect suspicious activity (failed login attempts)
def detect_suspicious_activity(log_file):
    failed_logins = defaultdict(int)
    failed_login_pattern = r'401|Invalid credentials|Failed login'

    with open(log_file, 'r') as file:
        for line in file:
            if re.search(failed_login_pattern, line):
                # Extract IP address of failed login attempt
                ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                if ip_match:
                    ip_address = ip_match.group(0)
                    failed_logins[ip_address] += 1
    
    # Filter out IPs with failed login attempts exceeding the threshold
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}
    return suspicious_ips

# Function to write the results to a CSV file
def write_to_csv(ip_request_count, most_accessed, suspicious_activity):
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write Requests per IP
        writer.writerow(["# Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_request_count.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])
        
        # Write Most Accessed Endpoint
        writer.writerow(["\n# Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]]) if most_accessed else writer.writerow(["No data available", 0])
        
        # Write Suspicious Activity
        writer.writerow(["\n# Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

# Function to display the results
def display_results(ip_request_count, most_accessed, suspicious_activity):
    # Display Requests per IP
    print("# Requests per IP")
    for ip, count in sorted(ip_request_count.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip}: {count} requests")
    
    # Display Most Accessed Endpoint
    print("\n# Most Accessed Endpoint")
    if most_accessed:
        print(f"{most_accessed[0]}: {most_accessed[1]} accesses")
    else:
        print("No endpoint data available.")
    
    # Display Suspicious Activity
    print("\n# Suspicious Activity")
    if suspicious_activity:
        for ip, count in suspicious_activity.items():
            print(f"{ip}: {count} failed login attempts")
    else:
        print("No suspicious activity detected.")

# Main function to run the script
def main():
    log_file = 'sample.log'  # Replace with your log file path
    
    # Count requests per IP
    ip_request_count = count_requests_per_ip(log_file)
    
    # Identify the most frequently accessed endpoint
    most_accessed, access_count = most_accessed_endpoint(log_file)
    
    # Detect suspicious activity (failed logins)
    suspicious_activity = detect_suspicious_activity(log_file)
    
    # Display the results
    display_results(ip_request_count, (most_accessed, access_count), suspicious_activity)
    
    # Write the results to a CSV file
    write_to_csv(ip_request_count, (most_accessed, access_count), suspicious_activity)

if __name__ == "__main__":
    main()

