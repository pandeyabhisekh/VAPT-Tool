import requests

def scan(url, session=None):
    results = []
    try:
        if session:
            response = session.get(url, timeout=10)
        else:
            response = requests.get(url, timeout=10)
            
        server_header = response.headers.get('Server', '')
        
        # 1. Detect IIS
        if 'IIS' in server_header:
            results.append({
                'name': 'IIS Server Version Disclosure',
                'severity': 'Info',
                'url': url,
                'description': f"The web server identifies itself as {server_header}. Disclosing specific server versions can assist an attacker in tailoring exploits for known vulnerabilities in that version.",
                'impact': "Information leakage regarding the backend infrastructure, simplifying the reconnaissance phase for an attacker.",
                'steps_to_reproduce': f"1. Send an HTTP request to {url}\n2. Analyze the 'Server' response header.",
                'proof_of_concept': f"Response Header: Server: {server_header}",
                'recommendation': "Configure the web server to suppress the 'Server' header or provide generic information only.",
                'technical_fix': "In IIS, use the URL Rewrite module to remove the 'Server' header or set 'removeServerHeader' to true in web.config for IIS 10.0+."
            })
            
            # 2. Check TRACE method
            try:
                if session:
                    trace_resp = session.request('TRACE', url, timeout=10)
                else:
                    trace_resp = requests.request('TRACE', url, timeout=10)
                
                if trace_resp.status_code == 200:
                    results.append({
                        'name': 'HTTP TRACE Method Enabled',
                        'severity': 'Medium',
                        'url': url,
                        'description': (
                            "The HTTP TRACE method is enabled on the server. This method is intended for debugging and "
                            "simply echoes the received request back to the client, including any headers (like Cookies or Authorization)."
                        ),
                        'impact': (
                            "Attackers can use this to perform Cross-Site Tracing (XST) attacks, "
                            "allowing them to bypass the 'HttpOnly' flag on cookies and steal sensitive session information."
                        ),
                        'steps_to_reproduce': f"1. Send a TRACE request to {url}\n2. Observe that the server returns the request headers in the response body.",
                        'proof_of_concept': f"TRACE {url} HTTP/1.1\nResponse Status: {trace_resp.status_code}\nResponse Body Snippet: {trace_resp.text[:200]}",
                        'recommendation': "Disable the TRACE method in the web server configuration.",
                        'technical_fix': "In IIS, use the 'Request Filtering' module to deny the 'TRACE' verb."
                    })
            except: pass
                
            # 3. Check PUT/WebDAV
            try:
                test_file_url = url.rstrip('/') + "/vapt_test_file.txt"
                if session:
                    put_resp = session.put(test_file_url, data="VAPT Scan Test", timeout=10)
                else:
                    put_resp = requests.put(test_file_url, data="VAPT Scan Test", timeout=10)
                
                if put_resp.status_code in [200, 201, 204]:
                    results.append({
                        'name': 'Insecure HTTP Method (PUT) Enabled',
                        'severity': 'High',
                        'url': test_file_url,
                        'description': (
                            "The server allows the use of the HTTP PUT method, which can be used to upload files to the server's file system. "
                            "In many cases, this indicates an insecurely configured WebDAV service."
                        ),
                        'impact': (
                            "An attacker could upload a malicious file (e.g., a web shell) to the server, "
                            "leading to full system compromise or defacement."
                        ),
                        'steps_to_reproduce': f"1. Attempt to upload a file using the PUT method to {test_file_url}\n2. Verify the file exists by sending a GET request.",
                        'proof_of_concept': f"PUT request to {test_file_url} returned status {put_resp.status_code}",
                        'recommendation': "Disable the PUT and DELETE methods unless explicitly required and properly secured with strong authentication.",
                        'technical_fix': "In IIS, ensure the WebDAV module is disabled or configured to require authentication and restrict write access to authorized users."
                    })
            except: pass

    except Exception as e:
        pass
        
    return results
