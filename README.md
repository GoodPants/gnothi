# gnothi
Know thy internal networks

This project is an attempt to create a tool which can generate configuration files for various network scanners and optionally allow a user to use the scans defined in the files to update a local inventory database. Ultimately, the objective is to be able to plop a simple box on a network and be able to do basic network asset discovery, inventory management, and vulnerability tracking from a single (simple) tool for the network on that machine. Any other features like synchronizing with enterprise vuln tracking, IT asset management, vulnerability scanners, or whatever else I find valuable may get added later as additional scripts and tools.

When it's finished, it should be able to do the following:

    ALWAYS: 
    1. Create a list of private subnets the host currently has an IP address on.
    2. Create the masscan configuration file for the first scan to identify active hosts on the subnets.
    3. Prompt user to execute the scan configured in step 2. If they confirm, then from scan output, create two configuration files:
        3.a. A masscan config file to scan the full list of hosts identified in step 2 for commonly attacked port numbers.
        3.b. An nmap config file to scan and fingerprint hosts identified in step 2.

    OPTIONAL:
    1. Run the scans defined in the config files from step 3 under ALWAYS
        1.a. Masscan scan to identify hosts and ports, then store the findings in the inventory database.
        1.b. Nmap to attempt to fingerprint specific services and software versions, then store the findings in the inventory database.
    2. Generate a report from the inventory database
    3. Check NIST NVD for known vulnerabilities in the service versions identified in the database and store records of CVE numbers and URLs in the database.

Feature wishlist:
* Use pycve to compare identified service versions with public CVEs in the NVD and store basic CVE data for services identified in the local database.
* Build scanner configuration files based on the existing entries in the local database instead of on the scan_nets_config.json file.
