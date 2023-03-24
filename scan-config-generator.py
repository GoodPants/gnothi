# TODO: Write function to check dependencies (nmap, masscan, and psutil)
# TODO: Write function to use masscan to create initial inventory and populate database with it.
# TODO: Unit tests for everything
# TODO: Use pycve to compare identified service versions with public CVEs in the NVD
# TODO: Rework config file generator functions to build scanner configuration files based on the entries in its local database
# TODO: Explore what it would take to integrate with some common IT management tools like snipeit.
# TODO: Explore database encryption option

import os
import ipaddress
import psutil
import json
import subprocess
import sqlite3

def initialize_database(database_filename):
    conn = sqlite3.connect(database_filename)
    cursor = conn.cursor()

    # Create the 'hosts' table
# Create the hosts table if it doesn't exist
    cursor.execute('''CREATE TABLE IF NOT EXISTS hosts
                 (ip_address TEXT, timestamp INTEGER, port INTEGER, protocol TEXT, status TEXT, reason TEXT, ttl INTEGER, service TEXT, version TEXT)''')

    # Create an index on the 'ip_address' column for faster lookups
    cursor.execute('''CREATE INDEX IF NOT EXISTS ip_index ON hosts (ip_address)''')

    # Save the changes
    conn.commit()

    # Close the connection
    conn.close()


# Used to populate the database with the results from the masscan inventory scan.
def add_masscan_output_file_to_db(masscan_output_json_file, database_filename):
    # Open the JSON file
    with open(masscan_output_json_file) as file:
        data = json.load(file)

    # Connect to the database
    conn = sqlite3.connect(database_filename)
    cursor = conn.cursor()

    # Create the hosts table if it doesn't exist
    cursor.execute('''CREATE TABLE IF NOT EXISTS hosts
                 (ip_address TEXT, timestamp INTEGER, port INTEGER, protocol TEXT, status TEXT, reason TEXT, ttl INTEGER, service TEXT, version TEXT)''')
    
    # Add each host to the database
    for host in data:
        ip_address = host["ip"]
        timestamp = int(host["timestamp"])
        ports = host["ports"]
        
        for port in ports:
            port_number = port["port"]
            protocol = port["proto"]
            status = port["status"]
            reason = port["reason"]
            ttl = port["ttl"]
            service = ""  # You can add service detection here
            version = ""  # You can add version detection here

            # Insert the host into the database
            cursor.execute('''
                      INSERT INTO hosts (ip_address, timestamp, port, protocol, status, reason, ttl, service, version)
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                      ''',
                      (ip_address, timestamp, port_number, protocol, status, reason, ttl, service, version))

    # Commit changes and close the connection
    conn.commit()
    conn.close()


# Function to add hosts ad-hoc to the database
def add_host(ip_address, ports, statuses, software, version):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Check if a matching row already exists
    cursor.execute('''SELECT id FROM hosts WHERE ip_address = ?''', (ip_address,))
    row = cursor.fetchone()

    if row:
        # A matching row exists, so update it
        cursor.execute('''UPDATE hosts SET ports = ?, statuses = ?, software = ?, version = ?
                     WHERE ip_address = ?''', (ports, statuses, software, version, ip_address))
    else:
        # No matching row, so insert a new one
        cursor.execute('''INSERT INTO hosts (ip_address, ports, statuses, software, version)
                     VALUES (?, ?, ?, ?, ?)''', (ip_address, ports, statuses, software, version))

    # Save the changes
    conn.commit()

    # Close the connection
    conn.close()


def list_private_subnets():
    private_subnets = []
    private_ranges = [ipaddress.ip_network(net) for net in ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']]

    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == 2:
                try:
                    ip = ipaddress.ip_address(addr.address)
                except ValueError:
                    continue
                if any(ip in net for net in private_ranges):
                    private_subnets.append(str(ipaddress.ip_network(f'{ip}/{addr.netmask}', strict=False)))

    for subnet in private_subnets:
        if not isinstance(subnet, str) and ipaddress.ip_network(subnet, strict=False):
            return []

    return private_subnets


def create_scan_nets_file(subnets, config_filename):
    scan_nets = {}
    # Some common port numbers for some frequently targeted services
    ports = [21, 22, 23, 80, 443, 990, 3389, 5900]

    if not os.path.isfile(config_filename):
        with open(config_filename, "r") as file:
            file.close()
    
    for subnet in subnets:
        if "/" in subnet:
            try:
                prefix, length = subnet.split("/")
                prefix = prefix.split(".")
                length = int(length)

                if len(prefix) == 4 and all(0 <= int(i) <= 255 for i in prefix) and 0 <= length <= 32:
                    scan_nets[subnet] = ports
            except:
                continue
    
    with open(config_filename, "w") as file:
        json.dump(scan_nets, file)
        file.close()


def check_scan_nets_config(file_path):
    # Returns true if the file exists and is well formed.

    try:
        with open(file_path, "r") as file:
            scan_nets = json.load(file)
    except FileNotFoundError:
        print("File not found: " + file_path)
        return False
    except json.JSONDecodeError:
        print("Invalid JSON syntax in file: " + file_path)
        return False

    if not scan_nets:
        print("No data found in file: " + file_path)
        return False

    for subnet, ports in scan_nets.items():
        if "/" not in subnet:
            print("Invalid subnet format in file: " + file_path)
            return False
        if not ports or not all(isinstance(i, int) for i in ports):
            print("Invalid port format in file: " + file_path)
            return False

    return True


def create_masscan_config_file(json_file_path, config_file_path):
    # Load the JSON data from the input file
    # NOTE: need to rewrite to use database entries instead
    with open(json_file_path, 'r') as json_file:
        json_data = json.load(json_file)

    # Create a new file for the masscan configuration
    with open(config_file_path, 'w') as config_file:        
        # Write the global options to the file
        config_file.write("rate = 10000\nshuffle-ports = true\nmax-retries = 3\wait = 0.05\noutput-format = JSON\noutput-filename = scan_results.json\n\n")

        # Loop through the IP ranges and port numbers and write the scan blocks to the file
        for ip_range, ports in json_data.items():
            config_file.write(f"[{ip_range}]\n")
            config_file.write(f"range = " + ip_range + "\n")
            config_file.write(f"ports = {','.join(map(str, ports))}\n")
            config_file.write("\n")


def create_nmap_config_file(json_file_path, config_file_path):
    # Load the JSON data from the input file
    # NOTE: need to rewrite to use database entries instead
    with open(json_file_path, 'r') as json_file:
        json_data = json.load(json_file)

    # Create a new file for the Nmap configuration
    with open(config_file_path, 'w') as config_file:
        # Write the global options to the file
        config_file.write("# This config was created by scan configurator to allow users to replicate scans manually.\n")
        config_file.write("# It also be edited to perform different types of scans against the same target set.\n")
        config_file.write("# Note that the file will be recreated from scratch if the scan configurator is run again.\n")
        config_file.write("# Make a separate copy if you wish to keep your changes.\n\n")
        config_file.write("# Basic configuration options\n")
        config_file.write("# Scan all ports\n")
        config_file.write("portscan = -p-\n")
        config_file.write("# Perform version detection\n")
        config_file.write("versionscan = true\n\n")

        # Loop through the IP ranges and port numbers and write the scan blocks to the file
        for ip_range, ports in json_data.items():
            config_file.write(f"# Scan options for {ip_range}\n")
            config_file.write(f"[{ip_range}]\n")
            config_file.write("scan_type = SYN\n")
            config_file.write(f"target = {ip_range}\n")
            config_file.write(f"ports = {','.join(map(str, ports))}\n\n")


def create_nessus_config_file(json_file_path, config_file_path):
    # Load the JSON file
    with open(json_file_path, 'r') as json_file:
        data = json.load(json_file)

    # Create the nessusd.conf file
    with open(config_file_path, 'w') as config_file:
        # Write a named subnet and port range for each entry in the JSON file
        for subnet, ports in data.items():
            subnet_name = subnet.replace('/', '_').replace('.', '_')
            port_range = ','.join(str(p) for p in ports)
            config_file.write(f"{subnet_name} = {subnet}\n")
            config_file.write(f"port_range_{subnet_name} = {port_range}\n\n")


def run_masscan(scan_targets_json):
    # TODO: Refactor to call masscan, but use the masscan_config_file created by the 
    # create_masscan_config_file function above instead of the json file.
    with open(scan_targets_json, "r") as scan_targets:
        subnets_data = json.load(scan_targets)

    for subnet, ports in subnets_data.items():
        port_list = ",".join(str(port) for port in ports)
        subprocess.run(["sudo", "masscan", subnet, "-p", port_list, "--rate=1000", "--exclude", "255.255.255.255"])


def main():
    # Database check & init
    # TODO: The rest of the code isn't using the database yet. Fix this.
    database_file = "inventory.db"
    inventory_DB = initialize_database(database_file)
    
    # Define the name of the scan networks configuration file.
    scan_nets_configuration_file = "scan_nets_config.json"

    # Define the name of the masscan config file to create
    masscan_config_file = "masscan.conf"

    # Define the name of the nmap config file to create
    nmap_config_file = "nmap.conf"

    # Define the name of the nessus config file to create
    nessus_config_file = "nessus.conf"

    # If the config file does not check out, it should call list_private_subnets()
    # and then pass its output to create_scan_nets_file()
    # This checks, then stores a bool result for the outcome of this check.
    config_check_result = check_scan_nets_config(scan_nets_configuration_file)

    # Get a list of private networks the host has an IP on
    subnets = list_private_subnets()

    # Define the name of a configuration backup file and create it on filesystem.
    config_backup_file = scan_nets_configuration_file + ".bak"
    print(config_backup_file)

    # Create both config and config backup files if they don't already exist, then close them.
    if not os.path.exists(scan_nets_configuration_file):
        with open(scan_nets_configuration_file, "w") as file:
            file.close()
    if not os.path.exists(config_backup_file):
        with open(config_backup_file, "w") as file:
            file.close()

    # Create a .json file to store the subnets that were found.
    create_scan_nets_file(subnets, scan_nets_configuration_file)

    # Create a config file for masscan that takes data from the .json file.
    create_masscan_config_file(scan_nets_configuration_file, masscan_config_file)
    
    # Create a config file for nmap that takes data from the .json file.
    # TODO: make this something you can set with a flag or option.
    create_nmap_config_file(scan_nets_configuration_file, nmap_config_file)

    # Create a config file for Nessus that takes data from the .json file.
    create_nessus_config_file(scan_nets_configuration_file, nessus_config_file)

    # Run inventory scan
    # TODO: Make this something you can set with a flag or option.
    run_masscan(scan_nets_configuration_file)

    # Parse scanner output and write the results to the database

if __name__ == "__main__":
    main()
