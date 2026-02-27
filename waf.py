import re
import requests
import urllib.parse

def get_country(ip):
    """
    Resolves an IP address to a Country Name using a free API.
    """
    try:
        if ip in ['127.0.0.1', '::1', 'localhost']:
            return "Local Network"
        
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country", timeout=2)
        data = response.json()
        
        if data.get('status') == 'success':
            return data.get('country')
    except Exception:
        pass
    return "Unknown"

def inspect_request(request, domain_rules):
    """
    Analyzes the incoming request for malicious patterns.
    """
    
    # 1. Extract ONLY the raw values
    payloads = []
    
    # Get URL parameters (?id=...)
    payloads.extend(request.args.values())
    
    # Get Form data (POST requests)
    if request.method in ["POST", "PUT"]:
        payloads.extend(request.form.values())
        
    # Get Cookies and User-Agent
    payloads.extend(request.cookies.values())
    payloads.append(request.headers.get('User-Agent', ''))

    # 2. Join, lowercase, and decode (turns %3C back into <)
    raw_payload = " ".join(str(p) for p in payloads).lower()
    decoded_payload = urllib.parse.unquote(raw_payload)
    
    full_payload = raw_payload + " " + decoded_payload

    # 3. Check rules strictly
    block_sqli = int(domain_rules.get('block_sqli', 0))
    block_xss = int(domain_rules.get('block_xss', 0))

    # --- SQL INJECTION DETECTION ---
    if block_sqli == 1:
        sqli_patterns = [
            r"or\s+['\"]?1['\"]?=['\"]?1",  
            r"union\s+select",              
            r"drop\s+table",                
            r"waitfor\s+delay",             
            r"--",                          
            r";\s*select",                  
            r"'\s*or\s+",                   
            r"\"\s*or\s+"                   
        ]
        for pattern in sqli_patterns:
            if re.search(pattern, full_payload):
                return "SQL Injection"

    # --- CROSS-SITE SCRIPTING (XSS) DETECTION ---
    if block_xss == 1:
        xss_patterns = [
            r"<script>",                    
            r"javascript:",                 
            r"onload\s*=",                  
            r"onerror\s*=",                 
            r"alert\(",                     
            r"prompt\(",                    
            r"document\.cookie",            
            r"<img\s+src",                  
            r"<svg"                         
        ]
        for pattern in xss_patterns:
            if re.search(pattern, full_payload):
                return "XSS Attack"

    return None