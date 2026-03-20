from bs4 import BeautifulSoup
import requests
import urllib.parse

def scan(url, session=None):
    results = []
    try:
        if session:
            response = session.get(url, timeout=10)
        else:
            response = requests.get(url, timeout=10)
            
        if not response or response.status_code != 200:
            return results

        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 1. Check Links
        links = soup.find_all('a', href=True)
        for link in links:
            href = link.get('href')
            if not href or href.startswith('#') or href.startswith('javascript:'):
                continue
                
            full_url = urllib.parse.urljoin(url, href)
            try:
                if session:
                    l_resp = session.head(full_url, timeout=5, allow_redirects=True)
                else:
                    l_resp = requests.head(full_url, timeout=5, allow_redirects=True)
                
                if l_resp.status_code >= 400:
                    results.append({
                        'name': 'Broken Link / Functional Failure',
                        'severity': 'Low',
                        'url': url,
                        'description': f"The link pointing to {full_url} returned a {l_resp.status_code} status code, indicating a broken resource.",
                        'impact': "Users may experience frustration or be unable to access parts of the application, leading to poor user experience and potential business loss.",
                        'steps_to_reproduce': f"1. Open {url}\n2. Find the link: {link.text.strip() or href}\n3. Click the link.\n4. Observe the {l_resp.status_code} error page.",
                        'proof_of_concept': f"Source: {url}\nBroken Target: {full_url}\nStatus Code: {l_resp.status_code}",
                        'recommendation': "Remove the broken link or update the URL to point to a valid resource.",
                        'technical_fix': "Verify all internal and external links periodically using automated tools like this one or 'LinkChecker'."
                    })
            except:
                continue

        # 2. Check Buttons (Interactive elements)
        buttons = soup.find_all(['button', 'input'], type=['submit', 'button'])
        for btn in buttons:
            btn_text = btn.text.strip() or btn.get('value') or btn.get('name') or 'Unnamed Button'
            # For buttons, we primarily check if they are inside a valid form or have an onclick handler
            parent_form = btn.find_parent('form')
            has_onclick = btn.has_attr('onclick')
            
            if not parent_form and not has_onclick:
                 results.append({
                    'name': 'Non-Functional / Dead Button Detected',
                    'severity': 'Info',
                    'url': url,
                    'description': f"The button '{btn_text}' does not appear to be associated with a form or a JavaScript event handler.",
                    'impact': "Users may click the button expecting an action that never occurs, causing confusion.",
                    'steps_to_reproduce': f"1. Open {url}\n2. Find button '{btn_text}'\n3. Observe lack of functional response.",
                    'proof_of_concept': f"Element: {btn}",
                    'recommendation': "Ensure all buttons are either part of a functional form or have appropriate event handlers attached.",
                    'technical_fix': "Use semantic HTML <button type='submit'> inside <form> or attach event listeners via JavaScript."
                })

    except Exception as e:
        pass
        
    return results
