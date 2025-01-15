import argparse
import re
import json
from datetime import datetime, timedelta, timezone
import time

DEFAULT_LOGFILE = "/var/log/nginx/mapsurfer_ssl_access.log"

# Function to load and parse logs from the file
def load_logs(logfile):
    logs = []
    with open(logfile, 'r') as f:
        for line in f:
            # Regular expression to match the log format
            match = re.match(r'^(\S+) \S+ \S+ \[(.*?)\] "(.*?)" (\d{3}) \S+ "(.*?)" "(.*?)"$', line)
            if match:
                log_date = datetime.strptime(match.group(2), "%d/%b/%Y:%H:%M:%S %z")
                request_parts = match.group(3).split(' ')
                # Extract method and URL, defaulting to "UNKNOWN" if missing
                request_url = request_parts[1] if len(request_parts) > 1 else "UNKNOWN"
                logs.append({
                    'ip': match.group(1),
                    'date': log_date,
                    'request': request_url,
                    'method': request_parts[0] if len(request_parts) > 0 else "UNKNOWN",
                    'status': int(match.group(4)),
                    'referer': match.group(5),
                    'user_agent': match.group(6)
                })
    return logs

# Filter logs based on time interval
def filter_by_time(logs, start_time, end_time):
    if start_time or end_time:
        return [
            log for log in logs
            if (not start_time or log['date'] >= start_time) and (not end_time or log['date'] <= end_time)
        ]
    return logs

# Filter logs based on HTTP status codes
def filter_by_status(logs, statuses):
    if statuses:
        return [log for log in logs if log['status'] in statuses]
    return logs

# Filter logs based on IP addresses
def filter_by_ip(logs, ips):
    if ips:
        return [log for log in logs if log['ip'] in ips]
    return logs

# Filter logs based on HTTP methods
def filter_by_method(logs, methods):
    if methods:
        return [log for log in logs if log['method'] in methods]
    return logs

# Normalize URLs by removing query parameters
def normalize_urls(logs):
    for log in logs:
        log['request'] = re.sub(r'\?.*', '', log['request'])
    return logs

# Get top N requested URLs
def get_top_urls(logs, top_n):
    url_counts = {}
    for log in logs:
        url = log['request']
        url_counts[url] = url_counts.get(url, 0) + 1
    sorted_urls = sorted(url_counts.items(), key=lambda x: x[1], reverse=True)
    return sorted_urls[:top_n]

# Get top N IP addresses
def get_top_ips(logs, top_n):
    ip_counts = {}
    for log in logs:
        ip = log['ip']
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    return sorted_ips[:top_n]

# Generate a JSON report from logs
def generate_json_report(logs, output_file):
    with open(output_file, 'w') as f:
        json.dump(logs, f, default=str, indent=4)
    print(f"JSON report saved to {output_file}")

# Analyze response times if available
def analyze_response_times(logs):
    if not logs or 'response_time' not in logs[0]:
        print("No response time data available in logs.")
        return
    response_times = [log['response_time'] for log in logs if 'response_time' in log]
    print(f"Average response time: {sum(response_times) / len(response_times):.2f} ms")
    print(f"Min response time: {min(response_times):.2f} ms")
    print(f"Max response time: {max(response_times):.2f} ms")

# Main script execution
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""
        NGINX Log Analyzer

        Example usage:
        1. Filter by time range:
            python log_analyzer.py --start_time "2025-01-10 09:00:00" --end_time "2025-01-10 10:00:00"
        2. Filter by status codes:
            python log_analyzer.py --statuses 500,502 --top 10
        3. Analyze last N hours:
            python log_analyzer.py --last_hours 1
        """,
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Define command-line arguments
    parser.add_argument("-l", "--logfile", type=str, default=DEFAULT_LOGFILE,
                        help="Path to the NGINX log file (default: /var/log/nginx/mapsurfer_ssl_access.log)")
    parser.add_argument("-s", "--start_time", type=str,
                        help="Start time in format HH:MM or YYYY-MM-DD HH:MM:SS")
    parser.add_argument("-e", "--end_time", type=str,
                        help="End time in format HH:MM or YYYY-MM-DD HH:MM:SS")
    parser.add_argument("-H", "--last_hours", type=int,
                        help="Filter logs from the last N hours")
    parser.add_argument("-S", "--statuses", type=str,
                        help="Comma-separated list of HTTP status codes (e.g., 500,502,404)")
    parser.add_argument("-t", "--top", type=int, default=10,
                        help="Number of top URLs to display (default: 10)")
    parser.add_argument("-m", "--methods", type=str,
                        help="Comma-separated list of HTTP methods (e.g., GET,POST)")
    parser.add_argument("-I", "--ips", type=str,
                        help="Comma-separated list of IP addresses for filtering")
    parser.add_argument("-r", "--response_time", action="store_true",
                        help="Analyze response times if available in logs")
    parser.add_argument("-j", "--json_output", type=str,
                        help="Path to save the JSON report")

    args = parser.parse_args()

    # Load logs from the specified file
    logs = load_logs(args.logfile)

    # Handle time-based filtering
    start_time = None
    end_time = None
    now = datetime.now(timezone.utc)
    if args.start_time:
        try:
            start_time = datetime.strptime(args.start_time, "%H:%M").replace(year=now.year, month=now.month, day=now.day, tzinfo=timezone.utc)
        except ValueError:
            start_time = datetime.strptime(args.start_time, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    if args.end_time:
        try:
            end_time = datetime.strptime(args.end_time, "%H:%M").replace(year=now.year, month=now.month, day=now.day, tzinfo=timezone.utc)
        except ValueError:
            end_time = datetime.strptime(args.end_time, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    if args.last_hours:
        end_time = now
        start_time = end_time - timedelta(hours=args.last_hours)
    else:
        # If no time is specified, process all logs
        start_time = None
        end_time = None

    logs = filter_by_time(logs, start_time, end_time)

    if start_time and end_time:
        print(f"Analyzing logs for the period: {start_time.strftime('%H:%M')} - {end_time.strftime('%H:%M')}")
    else:
        print("Analyzing all logs")

    # Filter by status codes if specified
    if args.statuses:
        statuses = list(map(int, args.statuses.split(",")))
        logs = filter_by_status(logs, statuses)

    # Filter by HTTP methods if specified
    if args.methods:
        methods = args.methods.split(",")
        logs = filter_by_method(logs, methods)

    # Filter by IP addresses if specified
    if args.ips:
        ips = args.ips.split(",")
        logs = filter_by_ip(logs, ips)

    # Normalize URLs by removing query parameters
    logs = normalize_urls(logs)

    # Analyze response times if requested
    if args.response_time:
        analyze_response_times(logs)

    # Generate a JSON report if specified
    if args.json_output:
        generate_json_report(logs, args.json_output)

    # Display top N requested URLs
    if args.top > 0:
        top_urls = get_top_urls(logs, args.top)
        print("Top {} URLs:".format(args.top))
        for url, count in top_urls:
            print(f"{url}: {count}")

    # Display top N IP addresses
    if args.top > 0:
        top_ips = get_top_ips(logs, args.top)
        print("Top {} IPs:".format(args.top))
        for ip, count in top_ips:
            print(f"{ip}: {count}")

    # Display the total number of processed requests
    print(f"Total number of requests: {len(logs)}")
