import re

def inspect_request(request, domain_rules):
    """
    Analyzes the incoming request for malicious patterns.
    
    Args:
        request: The Flask request object (contains args, form, headers)
        domain_rules: An object/dict containing 'block_sqli', 'block_xss' booleans.
        
    Returns:
        String: Name of the attack (e.g., "SQL Injection") if found.
        None: If the request is safe.
    """
    
    # 1. Aggregate all user input into one large string for scanning
    # We look at URL parameters, Form data, and Cookies
    payloads = [
        str(request.args),          # ?id=1 OR 1=1
        str(request.form),          # <input name="user">
        str(request.cookies),       # Cookie: session_id=...
        str(request.headers.get('User-Agent', '')) 
    ]
    
    # Convert to lowercase for easier matching (e.g., "SELECT" -> "select")
    full_payload = " ".join(payloads).lower()

    # 2. Check SQL Injection (SQLi)
    if domain_rules.block_sqli:
        # Common SQLi Signatures
        sqli_patterns = [
            r"or\s+['\"]?1['\"]?=['\"]?1",  # OR 1=1
            r"union\s+select",              # UNION SELECT
            r"drop\s+table",                # DROP TABLE
            r"waitfor\s+delay",             # Time-based blind
            r"--",                          # SQL Comment
            r";\s*select"                   # Chained query
        ]
        for pattern in sqli_patterns:
            if re.search(pattern, full_payload):
                return "SQL Injection"

    # 3. Check Cross-Site Scripting (XSS)
    if domain_rules.block_xss:
        # Common XSS Signatures
        xss_patterns = [
            r"<script>",                    # Basic script tag
            r"javascript:",                 # Protocol handler
            r"onload=",                     # Event handler
            r"onerror=",                    # Event handler
            r"alert\(",                     # Alert function
            r"document\.cookie"             # Cookie stealing
        ]
        for pattern in xss_patterns:
            if re.search(pattern, full_payload):
                return "XSS Attack"

    return None # Request is Safe