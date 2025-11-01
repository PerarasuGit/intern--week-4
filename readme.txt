🧠 Cybersecurity Internship – Week 4
🕵️‍♂️ Network Monitoring (Anomaly Detection and Reporting)
🔍 Task Summary

This week’s task focuses on analyzing network traffic logs to identify security anomalies such as:

Repeated failed login attempts (possible brute-force attacks)

Port scanning or enumeration activity

Unusually high traffic from specific IPs

The Python script reads a log file named network_logs.csv, detects abnormal behaviors, and produces both:

A detailed report (suspicious_activity_report.csv)

A visual chart (active_ips_chart.png) showing the most active IP addresses.

This helps identify potential intrusions or suspicious activities in a network environment.

⚙️ Steps to Use the Script

Prepare Input File

Create or download a file named network_logs.csv

The file should have these columns:

source_ip, destination_ip, action, status


Example:

192.168.1.10, 192.168.1.20, failed_login, denied
10.0.0.2, 10.0.0.5, port_scan, open
172.16.0.3, 172.16.0.4, login, success


Run the Script
Open a terminal or command prompt in the folder where your script is saved and type:

python network_monitor.py


Output Files Generated

✅ suspicious_activity_report.csv → Summary of all suspicious IPs

📊 active_ips_chart.png → Graph of top 10 most active IPs

Sample Console Output

Saved suspicious_activity_report.csv rows: 10
Saved active_ips_chart.png

🧩 Key Features

Detects failed login and port scan attempts

Counts unique target IPs for each source

Handles missing columns or errors gracefully

Produces clear visual and CSV reports

Helps in early detection of cyber threats and network anomalies

📚 Skills Learned

Data cleaning and analysis with Pandas

Network anomaly detection techniques

Python automation for log monitoring

Data visualization using Matplotlib