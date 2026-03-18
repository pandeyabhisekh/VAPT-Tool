def scan(url, session=None):
    results = []
    try:
        if session:
            response = session.get(url, timeout=10)
        else:
            import requests
            response = requests.get(url, timeout=10)
            
        server_header = response.headers.get('Server', '')
        
        # 1. Detect IIS
        if 'IIS' in server_header:
            results.append({
                'name': 'IIS Server Detected',
                'severity': 'Info',
                'description': f"Server identified as {server_header}",
                'poc': f"Server Header: {server_header}",
                'recommendation': "Ensure the IIS server is patched and hardened."
            })
            
            # 2. Check TRACE method
            if session:
                trace_resp = session.request('TRACE', url, timeout=10)
            else:
                trace_resp = requests.request('TRACE', url, timeout=10)
            if trace_resp.status_code == 200:
                results.append({
                    'name': 'HTTP TRACE Method Enabled',
                    'severity': 'Medium',
                    'description': "The TRACE method is enabled on the server, which can lead to Cross-Site Tracing (XST) attacks.",
                    'poc': f"TRACE {url} returned 200 OK",
                    'recommendation': "Disable the TRACE method in the server configuration."
                })
                
            # 3. Check PUT/WebDAV (basic check)
            if session:
                put_resp = session.put(url + "/test_vapt.txt", data="test", timeout=10)
            else:
                put_resp = requests.put(url + "/test_vapt.txt", data="test", timeout=10)
            if put_resp.status_code in [200, 201, 204]:
                results.append({
                    'name': 'Insecure HTTP Methods (PUT) Enabled',
                    'severity': 'High',
                    'description': "The PUT method is enabled, allowing files to be uploaded to the server.",
                    'poc': f"PUT {url}/test_vapt.txt returned {put_resp.status_code}",
                    'recommendation': "Disable insecure HTTP methods like PUT, DELETE, and WebDAV."
                })

    except Exception as e:
        pass
        
    return results
