I used a VMware virtual machine running on my host system

Identified my local network range as 192.168.110.0/24

Ran the command: nmap -sS 192.168.110.0/24

Used TCP SYN scan (-sS) 

Scanned all hosts in the 192.168.110.0/24 subnet

Result :- Task 1.txt

Most interesting host: 192.168.110.135 with multiple open ports

Other hosts showed limited or filtered ports

Analysis of Open Ports on 192.168.110.135 

Open Ports and Their Potential Risks:

SSH (Port 22)
Service: Secure Shell
Risk: If using weak credentials or outdated SSH version, could allow brute force attacks

HTTP (Port 80)
Service: Web server
Risk: Potential web application vulnerabilities (XSS, SQLi, etc.)

NetBIOS (Ports 139/445)
Service: Windows file sharing (SMB)
Risk: Vulnerable to exploits like EternalBlue, allows enumeration of shares

IMAP (Port 143)
Service: Email access
Risk: Clear-text protocol, susceptible to sniffing

HTTPS (Port 443)
Service: Secure web server
Risk: Potential SSL/TLS vulnerabilities if misconfigured

Custom Ports (5001, 8080, 8081)
Services: commplex-link, http-proxy, blackice-icecap
Risk: Unknown services may contain vulnerabilities

And the wireshark scan result is given in png format 
(wireshark scan.png)

