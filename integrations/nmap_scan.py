import nmap
from utils.logger import logger
from urllib.parse import urlparse

def scan(target_url):
    results = []
    try:
        domain = urlparse(target_url).netloc
        if not domain:
            # Fallback if netloc is empty (e.g., just an IP or partial URL)
            domain = target_url.split('/')[0]
            
        nm = nmap.PortScanner()
        logger.info(f"Starting advanced Nmap scan for {domain}")
        
        # Scan common ports with version detection (-sV)
        nm.scan(domain, '21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443')
        
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    port_data = nm[host][proto][port]
                    state = port_data['state']
                    service = port_data['name']
                    version = port_data.get('version', 'Unknown')
                    product = port_data.get('product', 'Unknown')
                    
                    if state == 'open':
                        severity = 'Info'
                        # Elevate severity for dangerous services if open
                        if port in [21, 23, 445, 3389]:
                            severity = 'Medium'
                            
                        results.append({
                            'name': f'Open Network Port Detected: {port} ({service})',
                            'severity': severity,
                            'url': host,
                            'description': (
                                f"The network port {port} is open on host {host}. "
                                f"The service identified is '{service}' (Product: {product}, Version: {version}). "
                                "Open ports represent potential entry points into the system's network infrastructure."
                            ),
                            'impact': (
                                "Each open port increases the attack surface. If the service running on this port "
                                "is unpatched or misconfigured, an attacker could exploit it to gain unauthorized access, "
                                "perform denial-of-service, or intercept network traffic."
                            ),
                            'steps_to_reproduce': f"1. Use a network scanner like Nmap: 'nmap -sV {host}'\n2. Observe that port {port} is listed as 'open'.",
                            'proof_of_concept': f"Nmap Scan Result:\nHost: {host}\nPort: {port}/{proto}\nState: {state}\nService: {service}\nProduct: {product}\nVersion: {version}",
                            'recommendation': (
                                "Evaluate whether this service needs to be exposed to the internet. "
                                "If not, close the port using a firewall (e.g., iptables, ufw, Windows Firewall). "
                                "If the service must remain open, ensure it is fully patched and uses strong authentication."
                            ),
                            'technical_fix': (
                                "Example (Ubuntu/UFW): 'ufw deny {port}'\n"
                                "Example (CentOS/firewalld): 'firewall-cmd --permanent --remove-port={port}/tcp'"
                            )
                        })
                        
    except Exception as e:
        logger.warning(f"Nmap scan failed (Nmap might not be installed or permission denied): {e}")
        
    return results
