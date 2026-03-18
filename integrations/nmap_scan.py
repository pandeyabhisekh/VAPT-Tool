import nmap
from utils.logger import logger
from urllib.parse import urlparse

def scan(target_url):
    results = []
    try:
        domain = urlparse(target_url).netloc
        if not domain:
            return results
            
        nm = nmap.PortScanner()
        logger.info(f"Starting Nmap scan for {domain}")
        
        # Basic TCP port scan
        nm.scan(domain, '21,22,25,53,80,443,3306,3389,8080')
        
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port]['name']
                    
                    if state == 'open':
                        results.append({
                            'name': f'Open Port Detected: {port}',
                            'severity': 'Info',
                            'description': f"Port {port} ({service}) is open on {host}",
                            'poc': f"Nmap scan output: {port}/{proto} {state} {service}",
                            'recommendation': "Close unnecessary ports and ensure services are secure."
                        })
                        
    except Exception as e:
        logger.warning(f"Nmap scan failed (Nmap might not be installed): {e}")
        
    return results
