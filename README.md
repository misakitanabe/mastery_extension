# Metasploit Resource Script to Automate Finding Relevant Exploits for Penetration Tests

## Background

Metasploit is a powerful and widely used opensource framework designed for penetration testing, cybersecurity research, and ethical hacking. It provides tools to identify, exploit, and test vulnerabilities in computer systems. At its core, Metasploit helps security professionals simulate real world attacks to assess the security posture of networks and applications. When used manually, Metasploit operates through a command line interface or a graphical interface, where the user selects or searches for specific exploits prepackaged code designed to take advantage of known vulnerabilities.

The process typically involves four steps:

1. loading an exploit module based on the target's vulnerabilities
2. configuring the exploit with required parameters like the target's IP address and port
3. selecting a payload, which is the code that runs after the exploit succeeds (e.g., opening a backdoor or providing shell access)
4. executing the exploit to test if the system is vulnerable.

## Motivation

One of the key benefits of using resource scripts in Metasploit is the ability to automate repetitive tasks, like the first step of finding relevant exploits for a target system. Resource scripts are files that can include embedded Ruby code along with Metasploit commands, allowing for dynamic and customizable automation.

For example, instead of manually searching through the vast library of exploits to match specific vulnerabilities or CVEs, a resource script can use Ruby logic to automatically load the database, filter vulnerabilities based on specific criteria, and crossreference them with known exploits. This automation streamlines the workflow, allowing penetration testers to focus more on analyzing results and refining attack strategies rather than spending time on manual searches.

Additionally, resource scripts ensure consistency in multistep processes, making it easier to replicate tests across multiple systems or teams. By combining the powerful exploit matching capabilities of Metasploit with the flexibility and logic of embedded Ruby code in resource scripts, security professionals can quickly and accurately identify exploitable weaknesses in a network.

## Contribution

My resource script aims to automate the first step outlined in the background, "loading an exploit module based on the target's vulnerabilities". Here are the general steps it takes in the script:

1. Uses Nmap to scan the target IP
   - Finds open ports and the services they are running
   - Scans for vulnerabilities
2. For each vulnerability found, collects list of CVEs that are associated
3. Maps found CVEs to exploits
   - Iterates through every single exploit in Metasploit's Database, and stores exploits that have a reference to any CVE found in previous step
4. Outputs description of any exploits found

Example portion of output:

```

[*] Trying to find exploit for vuln: 'cpe:/a:apache:http_server:2.2.8', port: '192.168.64.4:80', service: 'http'
[*]     Found exploit module multi/http/apache_normalize_path_rce for CVE: https://nvd.nist.gov/vuln/detail/CVE-2021-41773
[*]
          This module exploit an unauthenticated RCE vulnerability which exists in Apache version 2.4.49 (CVE-2021-41773).
          If files outside of the document root are not protected by ‘require all denied’ and CGI has been explicitly enabled,
          it can be used to execute arbitrary commands (Remote Command Execution).
          This vulnerability has been reintroduced in Apache 2.4.50 fix (CVE-2021-42013).
```

## How to get Started (instructions only for Mac OS X)

1. Install Metasploit
   - https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html#installing-metasploit-on-linux--macos
2. Install Nmap
   - With Homebrew:
     - `brew install nmap`
   - From Nmap website:
     - https://nmap.org/download.html#macosx
3. In terminal, run msfconsole
   - `/opt/metasploit-framework/bin/msfconsole`
   - Enter 'y' for both questions to add msfconsole to default PATH and to automatically set up database.
4. Ensure Msf DB is connected to PostgreSQL:
   - `db_status`
     - Output should say: "Connected to msf. Connection type: postgresql"
   - `exit`
5. In normal terminal, clone repo
   - `git clone `
