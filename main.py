"""
 Copyright (c) 2023 Bryan Hunter (TheModdersDen) | https://github.com/TheModdersDen

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """

# This script imports the latest list of cloudflare proxy IPs, and allows them to be used in a firewall rule on Linux and UNIX systems.
# This script is intended to be run as a cron job, and will automatically update the firewall rules every 30 days.
# This script is intended to be run as root.

# Import modules
import os
from os import path
import sys
from time import sleep
import urllib.request
import shutil
import subprocess
import datetime

# Whether or not to print debug messages (A value of True will print debug messages, a value of False will not print debug messages)
# NOTE: This will significantly increase the size of the output of your console, and should only be used for debugging purposes.
DEBUG = False

# The 'ports.txt' file will be used to store the ports that should be allowed for cloudflare IPs.
# The user should edit this file to include the ports that they want to allow for cloudflare IPs.
# It should be formatted in a way that each port is on a new line, followed by a colon and the port type (either TCP or UDP).
ports_file = "ports.txt"

# Set variables
cloudflare_ipv4_url = "https://www.cloudflare.com/ips-v4/#"
cloudflare_ipv6_url = "https://www.cloudflare.com/ips-v6/#"

# Set the directory to store the cloudflare IP lists
cloudflare_dir = "/etc/cloudflare"

# Set the file names for the cloudflare IP lists
cloudflare_ipv4_file = "cloudflare-ipv4.txt"
cloudflare_ipv6_file = "cloudflare-ipv6.txt"

# Set the file names for the cloudflare IP lists
cloudflare_ipv4_rule_file = "cloudflare-ipv4.rule"
cloudflare_ipv6_rule_file = "cloudflare-ipv6.rule"

# Get the allowed ports
def get_allowed_ports() -> dict:
    try: 
        # Generate a dictionary of allowed ports based on the input of the 'ports.txt' file
        # It should be formatted like this: 80:TCP
        allowed_ports = {}
        with open(ports_file, 'r') as in_file:
            for line in in_file:
                # Split the line into a list
                line = line.split(':')
                # Add the port to the dictionary
                allowed_ports[line[0]] = line[1].strip()
        # Return the dictionary      
        return allowed_ports
    except OSError:
        print("Failed to get the allowed ports from the 'ports.txt' file. Please check the file for errors.")
        return False

def create_cloudflare_dir() -> bool:
    # Check if the cloudflare directory exists
    try:
        if not os.path.exists(cloudflare_dir):
            print("Creating the cloudflare directory")
            os.makedirs(cloudflare_dir)
            return True
    except OSError:
        print("Creation of the cloudflare directory failed")
        return False

def download_cloudflare_ipv4() -> bool:
    try:
        print("Downloading the cloudflare IPv4 list")
        with urllib.request.urlopen(cloudflare_ipv4_url) as response, open(cloudflare_dir + path.sep + cloudflare_ipv4_file, 'wb') as out_file:
            shutil.copyfileobj(response, out_file)
            return True
    except OSError:
        print("Download of the cloudflare IPv4 list failed")
        return False
    
def download_cloudflare_ipv6() -> bool:
    try:
        print("Downloading the cloudflare IPv6 list")
        with urllib.request.urlopen(cloudflare_ipv6_url) as response, open(cloudflare_dir + path.sep + cloudflare_ipv6_file, 'wb') as out_file:
            shutil.copyfileobj(response, out_file)
            return True
    except OSError:
        print("Download of the cloudflare IPv6 list failed")
        return False

# Create a file to store the cloudflare IPv4 firewall rules with the allowed ports.
def create_cloudflare_ipv4_rule_file(allowed_ports: list) -> bool:
    # Create a file to store the cloudflare IPv4 firewall rule with the allowed ports.
    try:
        # Iterate through the allowed ports dictionary and create a rule for each port (TCP or UDP), then input the IP addresses from the cloudflare IPv4 list.
        print("Creating the cloudflare IPv4 rule file")
        with open(cloudflare_dir + path.sep + cloudflare_ipv4_rule_file, 'w') as out_file:
            for port, port_type in allowed_ports.items():
                with open(cloudflare_dir + path.sep + cloudflare_ipv4_file, 'r') as in_file:
                    for line in in_file:
                        out_file.write(f"iptables -A INPUT -p {port_type} --dport {port} -s {line.strip()} -j ACCEPT\n")
            return True
    except OSError:
        print("Creation of the cloudflare IPv4 rule file failed")
        return False

# Create a file to store the cloudflare IPv6 firewall rules with the allowed ports.
def create_cloudflare_ipv6_rule_file(allowed_ports: list) -> bool:
    # Create a file to store the cloudflare IPv6 firewall rule with the allowed ports.
    try:
        # Iterate through the allowed ports dictionary and create a rule for each port (TCP or UDP), then input the IP addresses from the cloudflare IPv6 list.
        print("Creating the cloudflare IPv6 rule file")
        with open(cloudflare_dir + path.sep + cloudflare_ipv6_rule_file, 'w') as out_file:
            for port, port_type in allowed_ports.items():
                with open(cloudflare_dir + path.sep + cloudflare_ipv6_file, 'r') as in_file:
                    for line in in_file:
                        out_file.write(f"ip6tables -A INPUT -p {port_type} --dport {port} -s {line.strip()} -j ACCEPT\n")
            return True
    except OSError:
        print("Creation of the cloudflare IPv6 rule file failed")
        return False

# Spawn a subprocess to execute each of the lines of the cloudflare IPv4 rule file using iptables.
def spawn_cloudflare_ipv4_rule_file() -> bool:
    # Spawn a subprocess using the cloudflare IPv4 rule file.
    try:
        with open(cloudflare_dir + path.sep + cloudflare_ipv4_rule_file, 'r') as in_file:
            for line in in_file:
                subprocess.run(line, shell=True)
            return True
    except OSError:
        print("Execution of the cloudflare IPv4 rule file failed. Please check the file for errors.")
        return False

# Spawn a subprocess to execute each of the lines of the cloudflare IPv6 rule file using ip6tables.
def spawn_cloudflare_ipv6_rule_file() -> bool:
    # Spawn a subprocess using the cloudflare IPv6 rule file.
    try:
        with open(cloudflare_dir + path.sep + cloudflare_ipv6_rule_file, 'r') as in_file:
            for line in in_file:
                subprocess.run(line, shell=True)
            return True
    except OSError:
        print("Execution of the cloudflare IPv6 rule file failed. Please check the file for errors.")
        return False

def elevate_script() -> bool:
    # Elevate the script to root
    try:
        # If the platform does not contain the string 'linux', then the script is not running on a Linux system.
        if "linux" not in sys.platform:
            print("The script is not running on a Linux system. Please run the script on a Linux system.")
            sleep(1)
            print("Exiting the script...")
            exit(1)
        elif (os.geteuid() == 0):
            return True
        elif (os.geteuid() != 0):
            print("Elevating the script to root")
            os.execvp("sudo", ["sudo", "python3"] + sys.argv)
        else:
            print("Elevation of the script to root failed")
            return False
    except OSError:
        print("Elevation of the script to root failed")
        return False

# Run the script

# Greet the user
print("Starting Cloudflare Firewall IP Updater")

# Get the current date
current_date = datetime.datetime.now()

# Print the current date
print(f"Current date and time: {current_date.strftime('%Y-%m-%d %H:%M:%S')}")

# Get the date of the last update
last_update = datetime.datetime.fromtimestamp(path.getmtime(cloudflare_dir + path.sep + cloudflare_ipv4_file))

# Elevate the script to root
root = elevate_script()
if (root and DEBUG):
    print("The script is running as root")

# Create the cloudflare directory
if (create_cloudflare_dir() and DEBUG):
    print("The cloudflare directory was created successfully")

# Download the cloudflare IPv4 list
if (download_cloudflare_ipv4() and DEBUG):
    print("The cloudflare IPv4 list was downloaded successfully")
    
# Download the cloudflare IPv6 list
if (download_cloudflare_ipv6() and DEBUG):
    print("The cloudflare IPv6 list was downloaded successfully")
    
# Get the allowed ports
allowed_ports = get_allowed_ports()
if (allowed_ports and DEBUG):
    print("The allowed ports were retrieved successfully")
    
# Create the cloudflare IPv4 rule file
if (create_cloudflare_ipv4_rule_file(allowed_ports) and DEBUG):
    print("The cloudflare IPv4 rule file was created successfully")
    
# Create the cloudflare IPv6 rule file
if (create_cloudflare_ipv6_rule_file(allowed_ports) and DEBUG):
    print("The cloudflare IPv6 rule file was created successfully")
    
# Spawn the cloudflare IPv4 rule file
if (spawn_cloudflare_ipv4_rule_file() and DEBUG):
    print("The cloudflare IPv4 rule file was spawned successfully")
    
# Spawn the cloudflare IPv6 rule file
if (spawn_cloudflare_ipv6_rule_file() and DEBUG):
    print("The cloudflare IPv6 rule file was spawned successfully")

# Print the date of the last update
print(f"Date of last update: {last_update.strftime('%Y-%m-%d %H:%M:%S')}")

# Print the date of the next scheduled update
print(f"Date of next scheduled update: {(last_update + datetime.timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')}")

# Print a final message to the user
print("Cloudflare Firewall IP Updater has finished running")
sleep(3)
exit(0)