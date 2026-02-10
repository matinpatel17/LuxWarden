import re

def inspect_request(request, domain_rules):
    """
    Analyzes the incoming request for malicious patterns.
    
    Args:
        request: The Flask request object (contains args, form, headers)
        domain_rules: A dictionary containing 'block_sqli', 'block_xss' keys.
        
    Returns:
        String: Name of the attack (e.g., "SQL Injection") if found.
        None: If the request is safe.
    """
    
    # 1. Aggregate all user input into one large string for scanning
    payloads = [
        str(request.args),          # ?id=1 OR 1=1
        str(request.form),          # <input name="user">
        str(request.cookies),       # Cookie: session_id=...
        str(request.headers.get('User-Agent', '')) 
    ]
    
    full_payload = " ".join(payloads).lower()

    # 2. Check SQL Injection (SQLi)
    # FIX: Use dictionary syntax ['key'] instead of object syntax .key
    if domain_rules.get('block_sqli'): 
        sqli_patterns = [
            r"or\s+['\"]?1['\"]?=['\"]?1",  
            r"union\s+select",              
            r"drop\s+table",                
            r"waitfor\s+delay",             
            r"--",                          
            r";\s*select"                   
        ]
        for pattern in sqli_patterns:
            if re.search(pattern, full_payload):
                return "SQL Injection"

    # 3. Check Cross-Site Scripting (XSS)
    # FIX: Use dictionary syntax ['key'] instead of object syntax .key
    if domain_rules.get('block_xss'):
        xss_patterns = [
            r"<script>",                    
            r"javascript:",                 
            r"onload=",                     
            r"onerror=",                    
            r"alert\(",                     
            r"document\.cookie"             
        ]
        for pattern in xss_patterns:
            if re.search(pattern, full_payload):
                return "XSS Attack"

    return None # Request is Safe