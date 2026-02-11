from flask import Flask, flash, render_template, request, redirect, url_for, session, make_response, Response
import mysql.connector
import re, os, requests
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import base64, hashlib
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect
from datetime import datetime
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from email_validator import validate_email, EmailNotValidError
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from bs4 import BeautifulSoup
from fpdf import FPDF
import io

# --- IMPORT FIREWALL LOGIC ---
# Ensure 'waf.py' is in the same folder
try:
    from waf import inspect_request
except ImportError:
    print("WARNING: waf.py not found. Firewall engine will not work.")
    def inspect_request(req, rules): return None

load_dotenv()

app = Flask(__name__)

# 🔐 Secret key
app.secret_key = os.getenv("FLASK_SECRET_KEY")

# --- CSRF CONFIG ---
# We must exempt the proxy route because external hackers won't send a CSRF token
csrf = CSRFProtect(app)
app.config['WTF_CSRF_EXEMPT_LIST'] = ['proxy_handler']

# 📧 Mail Configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

mail = Mail(app)

# 🔐 Token Serializer
s = URLSafeTimedSerializer(app.secret_key)

# 🔐 Encryption key
fernet_key_str = os.getenv("FERNET_KEY")
if not fernet_key_str:
    raise ValueError("No FERNET_KEY found in .env file")

cipher = Fernet(fernet_key_str.encode())

# --- LIMITER ---
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["2000 per day", "500 per hour"]
)

def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME")
    )

@app.route("/")
def index():
    return render_template("index.html")

# --- AUTH ROUTES ---

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower() 
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        old = {
            "full_name": full_name,
            "email": email,
            "phone": phone
        }

        # --- Validations ---
        if not full_name or not email or not phone or not password or not confirm_password:
            return render_template("register.html", error="All fields are required", old=old)

        if len(full_name) < 2 or len(full_name) > 50:
            return render_template("register.html", error="Name must be between 2 and 50 characters", old=old)
        
        if re.search(r'\d', full_name):
            return render_template("register.html", error="Name cannot contain numbers", old=old)

        try:
            valid = validate_email(email, check_deliverability=True)
            email = valid.normalized
        except EmailNotValidError as e:
            return render_template("register.html", error=str(e), old=old)

        if not phone.isdigit() or len(phone) != 10:
            return render_template("register.html", error="Mobile number must be exactly 10 digits", old=old)

        if password != confirm_password:
            return render_template("register.html", error="Passwords do not match", old=old)

        if len(password) < 8:
            return render_template("register.html", error="Password must be at least 8 characters long", old=old)

        password_pattern = r'^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])'
        if not re.search(password_pattern, password):
            return render_template(
                "register.html",
                error="Password must contain at least one uppercase letter, one number, and one special character",
                old=old
            )

        hashed_password = generate_password_hash(password)

        try:
            db = get_db_connection()
            cursor = db.cursor()

            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                cursor.close()
                db.close()
                return render_template("register.html", error="Email already registered", old=old)

            cursor.execute(
                "INSERT INTO users (full_name, email, phone_number, password) VALUES (%s, %s, %s, %s)",
                (full_name, email, phone, hashed_password)
            )
            db.commit()
            cursor.close()
            db.close()

            session["success_message"] = "Registration successful! Please sign in to continue."
            return redirect(url_for("signin"))

        except Exception as e:
            return render_template("register.html", error="An error occurred during registration.", old=old)

    return render_template("register.html", old={})

@app.route("/signin", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def signin():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        old = {"email": email}

        if not email or not password:
            return render_template("signin.html", error="Email and password are required", old=old)

        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute(
            "SELECT id, full_name, password, is_paid FROM users WHERE email = %s",
            (email,)
        )
        user = cursor.fetchone()

        cursor.close()
        db.close()

        if not user:
            return render_template("signin.html", error="Email not registered. Please register first.", old=old)

        if not check_password_hash(user["password"], password):
            return render_template("signin.html", error="Incorrect password. Try again.", old=old)

        # --- LOGIN SUCCESS ---
        session.clear()
        session["user_id"] = user["id"]
        session["user_name"] = user["full_name"]
        session["logged_in"] = True
        
        is_paid = bool(user["is_paid"])
        session["is_paid"] = is_paid

        if is_paid:
            return redirect(url_for("dashboard"))
        else:
            session["error_message"] = "Please complete your payment to access the dashboard."
            return redirect(url_for("payment"))

    success_msg = session.pop("success_message", None)
    error_msg = session.pop("error_message", None)
    
    # FIX: old={} prevents UndefinedError on page load
    return render_template(
        "signin.html", 
        success=success_msg, 
        error=error_msg, 
        old={}
    )

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out successfully")
    return redirect(url_for("signin"))

# --- 📄 PDF REPORT GENERATOR ---
# --- 📄 PDF REPORT GENERATOR (With Date Filtering) ---
@app.route("/generate_report")
def generate_report():
    if "user_id" not in session: return redirect(url_for("signin"))
    
    # 1. Get the filter from the URL (default to 'all' if missing)
    period = request.args.get('period', 'all')
    
    # 2. Build the SQL Query based on the period
    base_query = """
        SELECT l.timestamp, d.domain_name, l.attack_type, l.attacker_ip, l.payload 
        FROM attack_logs l 
        JOIN domains d ON l.domain_id = d.id 
        WHERE d.user_id = %s 
    """
    
    params = [session["user_id"]]
    period_text = "All Time History" # Title for the PDF

    if period == 'day':
        base_query += " AND l.timestamp >= CURDATE()" # Since midnight today
        period_text = "Report: Today"
    elif period == 'week':
        base_query += " AND l.timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)"
        period_text = "Report: Last 7 Days"
    elif period == 'month':
        base_query += " AND l.timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)"
        period_text = "Report: Last 30 Days"
    
    base_query += " ORDER BY l.timestamp DESC"

    # 3. Execute Query
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute(base_query, tuple(params))
    logs = cursor.fetchall()
    db.close()

    # 4. Create PDF (Updated with Dynamic Title)
    class PDF(FPDF):
        def header(self):
            self.set_font('Arial', 'B', 15)
            self.cell(0, 10, 'LuxWarden Security Report', 0, 1, 'C')
            self.set_font('Arial', 'I', 10)
            self.cell(0, 10, f'Period: {period_text}', 0, 1, 'C') # Show the period in header
            self.ln(5)

        def footer(self):
            self.set_y(-15)
            self.set_font('Arial', 'I', 8)
            self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    pdf = PDF()
    pdf.add_page()
    pdf.set_font("Arial", size=10)

    # 5. Add Summary Section
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, f"Total Incidents Found: {len(logs)}", 0, 1)
    
    if not logs:
        pdf.set_font("Arial", 'I', 10)
        pdf.cell(0, 10, "Great news! No attacks were detected during this period.", 0, 1)
    
    pdf.ln(5)

    if logs:
        # Table Header
        pdf.set_fill_color(200, 220, 255)
        pdf.set_font("Arial", 'B', 9)
        pdf.cell(40, 8, "Time", 1, 0, 'C', True)
        pdf.cell(40, 8, "Domain", 1, 0, 'C', True)
        pdf.cell(30, 8, "Type", 1, 0, 'C', True)
        pdf.cell(30, 8, "Attacker IP", 1, 0, 'C', True)
        pdf.cell(50, 8, "Payload (Snippet)", 1, 1, 'C', True)

        # Table Rows
        pdf.set_font("Arial", size=8)
        for log in logs:
            time_str = str(log['timestamp'])[0:16]
            payload_short = log['payload'][0:25] + "..." if len(log['payload']) > 25 else log['payload']
            
            pdf.cell(40, 8, time_str, 1)
            pdf.cell(40, 8, log['domain_name'], 1)
            pdf.cell(30, 8, log['attack_type'], 1)
            pdf.cell(30, 8, log['attacker_ip'], 1)
            pdf.cell(50, 8, payload_short, 1)
            pdf.ln()

    # 6. Output
    try:
        pdf_output = pdf.output(dest='S').encode('latin-1', 'replace') 
    except:
        pdf_output = pdf.output(dest='S').encode('latin-1', 'ignore')

    filename = f"security_report_{period}.pdf"
    
    return Response(pdf_output, mimetype='application/pdf', 
                    headers={'Content-Disposition': f'attachment;filename={filename}'})

# --- 🛡️ NEW DASHBOARD & FIREWALL ROUTES ---

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session: return redirect(url_for("signin"))
    # Note: We removed the strict payment check for testing, 
    # but if you want it back, uncomment the next line:
    # if not session.get("is_paid", False): return redirect(url_for("payment"))

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    
    # 1. Fetch Domains
    cursor.execute("""
        SELECT d.*, r.block_sqli, r.block_xss, r.block_ip 
        FROM domains d 
        LEFT JOIN firewall_rules r ON d.id = r.domain_id 
        WHERE d.user_id = %s
    """, (session["user_id"],))
    domains = cursor.fetchall()

    # 2. Fetch Recent Attacks (Logs)
    cursor.execute("""
        SELECT l.*, d.domain_name 
        FROM attack_logs l
        JOIN domains d ON l.domain_id = d.id
        WHERE d.user_id = %s
        ORDER BY l.timestamp DESC LIMIT 10
    """, (session["user_id"],))
    logs = cursor.fetchall()

    # 3. Fetch Blocked IPs
    cursor.execute("""
        SELECT b.*, d.domain_name 
        FROM blocked_ips b
        JOIN domains d ON b.domain_id = d.id
        WHERE d.user_id = %s
        ORDER BY b.added_at DESC
    """, (session["user_id"],))
    blocked_ips = cursor.fetchall()

    # 4. Fetch Stats for Chart.js
    cursor.execute("""
        SELECT attack_type, COUNT(*) as count 
        FROM attack_logs l
        JOIN domains d ON l.domain_id = d.id
        WHERE d.user_id = %s
        GROUP BY attack_type
    """, (session["user_id"],))
    stats_data = cursor.fetchall()
    
    chart_labels = [row['attack_type'] for row in stats_data]
    chart_values = [row['count'] for row in stats_data]

    # 5. NEW: Fetch Support Tickets
    cursor.execute("""
        SELECT * FROM support_tickets 
        WHERE user_id = %s 
        ORDER BY created_at DESC LIMIT 5
    """, (session["user_id"],))
    tickets = cursor.fetchall()
    
    cursor.close()
    db.close()

    return render_template("dashboard.html", 
                           domains=domains, 
                           logs=logs, 
                           blocked_ips=blocked_ips,
                           chart_labels=chart_labels, 
                           chart_values=chart_values,
                           tickets=tickets)

# --- 🎫 SUPPORT TICKET SYSTEM ---
@app.route("/create_ticket", methods=["POST"])
def create_ticket():
    if "user_id" not in session: return redirect(url_for("signin"))
    
    subject = request.form.get("subject")
    message = request.form.get("message")
    
    if not subject or not message:
        flash("❌ Subject and Message are required.")
        return redirect(url_for("dashboard"))

    try:
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO support_tickets (user_id, subject, message) 
            VALUES (%s, %s, %s)
        """, (session["user_id"], subject, message))
        db.commit()
        cursor.close()
        db.close()
        flash("✅ Support ticket created! We will reply soon.")
    except Exception as e:
        flash(f"Error creating ticket: {str(e)}")
        
    return redirect(url_for("dashboard"))

@app.route("/add_domain", methods=["POST"])
def add_domain():
    if "user_id" not in session: return redirect(url_for("signin"))
    
    domain_name = request.form.get("domain_name")
    target_url = request.form.get("target_url")
    
    # Generate a unique proxy slug
    proxy_slug = f"{session['user_id']}-{secrets.token_hex(4)}"

    try:
        db = get_db_connection()
        cursor = db.cursor()
        
        # 1. Insert Domain
        cursor.execute(
            "INSERT INTO domains (user_id, domain_name, target_url, proxy_url) VALUES (%s, %s, %s, %s)",
            (session["user_id"], domain_name, target_url, proxy_slug)
        )
        domain_id = cursor.lastrowid
        
        # 2. Insert Default Rules
        cursor.execute(
            "INSERT INTO firewall_rules (domain_id, block_sqli, block_xss) VALUES (%s, 0, 0)",
            (domain_id,)
        )
        
        db.commit()
        cursor.close()
        db.close()
        flash("Domain added successfully!")
    except Exception as e:
        flash(f"Error adding domain: {str(e)}")
        
    return redirect(url_for("dashboard"))

@app.route("/delete_domain/<int:domain_id>")
def delete_domain(domain_id):
    if "user_id" not in session: return redirect(url_for("signin"))
    
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("DELETE FROM domains WHERE id = %s AND user_id = %s", (domain_id, session["user_id"]))
    db.commit()
    db.close()
    flash("Domain deleted.")
    return redirect(url_for("dashboard"))

@app.route("/update_rules/<int:domain_id>", methods=["POST"])
def update_rules(domain_id):
    if "user_id" not in session: return redirect(url_for("signin"))
    
    block_sqli = 1 if request.form.get("block_sqli") else 0
    block_xss = 1 if request.form.get("block_xss") else 0
    
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("""
        UPDATE firewall_rules 
        SET block_sqli = %s, block_xss = %s 
        WHERE domain_id = %s
    """, (block_sqli, block_xss, domain_id))
    db.commit()
    db.close()
    flash("Security rules updated.")
    return redirect(url_for("dashboard"))

# --- 🚫 IP BLOCKING ROUTES ---

@app.route("/block_ip/<int:domain_id>", methods=["POST"])
def block_ip(domain_id):
    if "user_id" not in session: return redirect(url_for("signin"))
    
    ip_address = request.form.get("ip_address", "").strip()
    
    # Basic IP validation regex
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_address):
        flash("Invalid IP Address format.")
        return redirect(url_for("dashboard"))

    try:
        db = get_db_connection()
        cursor = db.cursor()
        # Check if already blocked
        cursor.execute("SELECT id FROM blocked_ips WHERE domain_id = %s AND ip_address = %s", (domain_id, ip_address))
        if cursor.fetchone():
            flash("IP is already blocked.")
        else:
            cursor.execute("INSERT INTO blocked_ips (domain_id, ip_address) VALUES (%s, %s)", (domain_id, ip_address))
            db.commit()
            flash(f"IP {ip_address} has been blocked.")
        
        cursor.close()
        db.close()
    except Exception as e:
        flash(f"Error blocking IP: {str(e)}")

    return redirect(url_for("dashboard"))

@app.route("/unblock_ip/<int:ip_id>")
def unblock_ip(ip_id):
    if "user_id" not in session: return redirect(url_for("signin"))
    
    try:
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("DELETE FROM blocked_ips WHERE id = %s", (ip_id,))
        db.commit()
        cursor.close()
        db.close()
        flash("IP unblocked successfully.")
    except Exception as e:
        flash(f"Error unblocking IP: {str(e)}")
        
    return redirect(url_for("dashboard"))

@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template("blocked.html", attack_type="Rate Limit Exceeded (Too many requests)"), 429

# --- 🔥 THE CORE FIREWALL PROXY ---
@app.route("/proxy/<int:domain_id>/", defaults={'subpath': ''}, methods=["GET", "POST", "PUT", "DELETE"])
@app.route("/proxy/<int:domain_id>/<path:subpath>", methods=["GET", "POST", "PUT", "DELETE"])
@csrf.exempt 
@limiter.limit("60 per minute") # <--- NEW: Rate Limit (1 request per second)
def proxy_handler(domain_id, subpath):
    # 1. Fetch Domain
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT d.target_url, r.block_sqli, r.block_xss FROM domains d JOIN firewall_rules r ON d.id = r.domain_id WHERE d.id = %s", (domain_id,))
    domain = cursor.fetchone()

    # --- NEW: Check IP Blocklist ---
    cursor.execute("SELECT ip_address FROM blocked_ips WHERE domain_id = %s", (domain_id,))
    blocked_list = [row['ip_address'] for row in cursor.fetchall()]
    
    if request.remote_addr in blocked_list:
        db.close()
        return render_template("blocked.html", attack_type="IP Blacklisted"), 403
    # -------------------------------

    db.close()
    
    if not domain: return "Domain not configured", 404

    # 2. INSPECT TRAFFIC (Firewall Check)
    # Note: We pass 'domain' as the rules object since it has the block_sqli/xss keys
    attack_type = inspect_request(request, domain) 
    
    if attack_type:
        # Log and Block
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("INSERT INTO attack_logs (domain_id, attacker_ip, attack_type, payload) VALUES (%s, %s, %s, %s)", 
                       (domain_id, request.remote_addr, attack_type, str(request.args)))
        db.commit()
        db.close()
        return render_template("blocked.html", attack_type=attack_type), 403

    # 3. FORWARD TRAFFIC
    # Construct the destination URL
    if subpath:
        target_url = f"{domain['target_url']}/{subpath}"
    else:
        target_url = domain['target_url']

    # Clean headers
    req_headers = {k: v for k, v in request.headers if k.lower() not in ['host', 'accept-encoding']}
    
    try:
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=req_headers,
            data=request.get_data(),
            params=request.args,
            allow_redirects=True
        )

        # 4. REWRITE LINKS (The Fix for "Not Found")
        # We only rewrite HTML pages, not images or JSON
        content = resp.content
        if 'text/html' in resp.headers.get('Content-Type', ''):
            soup = BeautifulSoup(content, 'html.parser')
            
            # This is the prefix we want to add to all links
            proxy_prefix = f"/proxy/{domain_id}"

            # Fix <a href="..."> links
            for tag in soup.find_all(['a', 'link'], href=True):
                if tag['href'].startswith('/'):
                    tag['href'] = proxy_prefix + tag['href']

            # Fix <form action="..."> (This fixes the Google Search button!)
            for tag in soup.find_all('form', action=True):
                if tag['action'].startswith('/'):
                    tag['action'] = proxy_prefix + tag['action']
            
            # Fix <img src="..."> and <script src="...">
            for tag in soup.find_all(['img', 'script'], src=True):
                if tag['src'].startswith('/'):
                    tag['src'] = proxy_prefix + tag['src']

            content = str(soup)

        # Return the modified response
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in resp.raw.headers.items()
                   if name.lower() not in excluded_headers]

        return Response(content, resp.status_code, headers)

    except Exception as e:
        return f"Error connecting to protected server: {e}", 502

# --- EXISTING PAYMENT & CONTACT ---

@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        phone_number = request.form.get("phone_number", "").strip()
        message = request.form.get("message", "").strip()

        form_data = request.form.to_dict() 

        # 1. Required Fields Check
        if not first_name or not email or not message:
            session["error"] = "Please fill First name, Email & Message"
            session["old"] = form_data
            return redirect(url_for("contact"))

        # 2. Name Validation
        if len(first_name) < 2 or len(first_name) > 50:
            session["error"] = "First Name must be between 2 and 50 characters"
            session["old"] = form_data
            return redirect(url_for("contact"))
            
        if last_name and (len(last_name) < 2 or len(last_name) > 50):
            session["error"] = "Last Name must be between 2 and 50 characters"
            session["old"] = form_data
            return redirect(url_for("contact"))

        if re.search(r'\d', first_name) or (last_name and re.search(r'\d', last_name)):
            session["error"] = "Names cannot contain numbers"
            session["old"] = form_data
            return redirect(url_for("contact"))

        # 3. Phone Validation (Only if provided)
        if phone_number:
            if not phone_number.isdigit() or len(phone_number) != 10:
                session["error"] = "Phone number must be exactly 10 digits"
                session["old"] = form_data
                return redirect(url_for("contact"))

        # 4. Email Validation
        try:
            valid = validate_email(email, check_deliverability=True)
            email = valid.normalized
        except EmailNotValidError as e:
            session["error"] = str(e)
            session["old"] = form_data
            return redirect(url_for("contact"))

        # 5. Save to DB
        try:
            db = get_db_connection()
            cursor = db.cursor()

            cursor.execute("""
                INSERT INTO contact_messages
                (first_name, last_name, email, phone_number, message)
                VALUES (%s, %s, %s, %s, %s)
            """, (first_name, last_name, email, phone_number, message))

            db.commit()
            cursor.close()
            db.close()

            session["success"] = True
            return redirect(url_for("contact"))

        except Exception as e:
            print(f"Error saving message: {e}")
            session["error"] = "Something went wrong. Please try again."
            session["old"] = form_data
            return redirect(url_for("contact"))

    success = session.pop("success", False)
    error = session.pop("error", None)
    old = session.pop("old", {})

    return render_template("contact.html", success=success, error=error, old=old)

@app.route("/payment", methods=["GET", "POST"])
def payment():
    if "user_id" not in session:
        return redirect(url_for("signin"))

    if request.method == "POST":
        try:
            user_id = session["user_id"]
            
            full_name = request.form.get("full_name", "").strip()
            dob = request.form.get("date_of_birth")
            email = request.form.get("email", "").strip().lower()
            phone = request.form.get("phone", "").strip()
            billing_address = request.form.get("billing_address", "").strip()
            card_holder_name = request.form.get("card_holder_name", "").strip()
            card_number = request.form.get("card_number", "").replace(" ", "")
            card_expiry = request.form.get("card_expiry")
            cvv = request.form.get("cvv", "").strip()

            # 1. Required Fields Check
            if not all([full_name, dob, email, phone, billing_address, card_holder_name, card_number, card_expiry, cvv]):
                session["error"] = "All fields are required"
                session["old"] = request.form.to_dict()
                return redirect(url_for("payment"))

            # 2. Name Validation
            if not (2 <= len(full_name) <= 50) or not (2 <= len(card_holder_name) <= 50):
                session["error"] = "Names must be between 2 and 50 characters"
                session["old"] = request.form.to_dict()
                return redirect(url_for("payment"))

            if re.search(r'\d', full_name) or re.search(r'\d', card_holder_name):
                session["error"] = "Names cannot contain numbers"
                session["old"] = request.form.to_dict()
                return redirect(url_for("payment"))

            # 3. Phone Validation
            if not phone.isdigit() or len(phone) != 10:
                session["error"] = "Phone number must be exactly 10 digits"
                session["old"] = request.form.to_dict()
                return redirect(url_for("payment"))

            # 4. Email Validation
            try:
                valid = validate_email(email, check_deliverability=True)
                email = valid.normalized
            except EmailNotValidError as e:
                session["error"] = str(e)
                session["old"] = request.form.to_dict()
                return redirect(url_for("payment"))

            # 5. Card & CVV Validation
            if not card_number.isdigit() or len(card_number) != 16:
                session["error"] = "Card number must be exactly 16 digits"
                session["old"] = request.form.to_dict()
                return redirect(url_for("payment"))

            if not cvv.isdigit() or len(cvv) not in [3, 4]:
                session["error"] = "CVV must be 3 or 4 digits"
                session["old"] = request.form.to_dict()
                return redirect(url_for("payment"))

            # 6. Security & DB Logic
            encrypted_card = cipher.encrypt(card_number.encode()).decode()
            cvv_hash = hashlib.sha256(cvv.encode()).hexdigest()

            db = get_db_connection()
            cursor = db.cursor()

            cursor.execute("""
                INSERT INTO payments (
                    user_id, full_name, date_of_birth, email, phone,
                    billing_address, card_holder_name, card_number_encrypted,
                    card_expiry, cvv_hash
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (
                user_id, full_name, dob, email, phone,
                billing_address, card_holder_name, encrypted_card,
                card_expiry, cvv_hash
            ))

            cursor.execute("UPDATE users SET is_paid = 1 WHERE id = %s", (user_id,))

            db.commit()
            cursor.close()
            db.close()

            session["is_paid"] = True
            return redirect(url_for("dashboard"))

        except Exception as e:
            print("❌ PAYMENT ERROR:", e)
            session["error"] = "Payment failed. Please try again."
            session["old"] = request.form.to_dict()
            return redirect(url_for("payment"))

    success = session.pop("success", False)
    error = session.pop("error", None)
    
    if not error:
        error = session.pop("error_message", None)
    
    old = session.pop("old", {})

    return render_template("payment.html", success=success, error=error, old=old)

# --- PASSWORD RESET ROUTES ---

@app.route("/reset_request", methods=["GET", "POST"])
def reset_request():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        if not email:
            flash("Please enter your email address.")
            return redirect(url_for("reset_request"))

        try:
            db = get_db_connection()
            cursor = db.cursor()
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            cursor.close()
            db.close()

            if user:
                token = s.dumps(email, salt='password-reset-salt')
                link = url_for('reset_token', token=token, _external=True)
                
                msg = Message('Password Reset Request', 
                              sender=os.getenv('MAIL_USERNAME'), 
                              recipients=[email])
                msg.body = f'Click the link to reset your password: {link}\n\nIf you did not make this request, ignore this email.'
                
                try:
                    mail.send(msg)
                    flash("An email has been sent.")
                    return redirect(url_for("signin"))
                except Exception as e:
                    flash("Error sending email.")
                    return redirect(url_for("reset_request"))

            else:
                flash("Email does not exist in our records.")
                return redirect(url_for("reset_request"))

        except Exception as e:
            flash("An error occurred.")
            return redirect(url_for("reset_request"))

    return render_template("reset_request.html")

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_token(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except Exception:
        flash("The reset link is invalid or has expired.")
        return redirect(url_for("reset_request"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if password != confirm_password:
            flash("Passwords do not match")
            return redirect(url_for("reset_token", token=token))
            
        hashed_password = generate_password_hash(password)
        
        try:
            db = get_db_connection()
            cursor = db.cursor()
            cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_password, email))
            db.commit()
            cursor.close()
            db.close()

            flash("Your password has been updated!")
            return redirect(url_for("signin"))
            
        except Exception as e:
            flash("An error occurred.")
            return redirect(url_for("reset_token", token=token))

    return render_template("reset_token.html", token=token)

# --- ⚙️ SETTINGS & PROFILE MANAGEMENT ---
@app.route("/settings", methods=["POST"])
def settings():
    if "user_id" not in session: return redirect(url_for("signin"))
    
    action = request.form.get("action")
    db = get_db_connection()
    cursor = db.cursor()

    try:
        if action == "change_password":
            new_pass = request.form.get("new_password")
            confirm_pass = request.form.get("confirm_password") # Added Confirm Field

            # --- 1. Basic Check ---
            if not new_pass or not confirm_pass:
                flash("❌ All password fields are required.")
                return redirect(url_for("dashboard"))

            # --- 2. Match Check ---
            if new_pass != confirm_pass:
                flash("❌ Passwords do not match.")
                return redirect(url_for("dashboard"))

            # --- 3. Length Check ---
            if len(new_pass) < 8:
                flash("❌ Password must be at least 8 characters long.")
                return redirect(url_for("dashboard"))

            # --- 4. Complexity Check (Regex) ---
            password_pattern = r'^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])'
            if not re.search(password_pattern, new_pass):
                flash("❌ Password must contain at least one uppercase letter, one number, and one special character.")
                return redirect(url_for("dashboard"))

            # --- 5. Success: Hash and Update ---
            hashed_pass = generate_password_hash(new_pass)
            cursor.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_pass, session["user_id"]))
            flash("✅ Password updated successfully.")
        
        elif action == "delete_account":
            cursor.execute("DELETE FROM users WHERE id = %s", (session["user_id"],))
            db.commit()
            session.clear()
            flash("Account deleted. Goodbye!")
            return redirect(url_for("home"))

        db.commit()
    except Exception as e:
        flash(f"Error updating settings: {str(e)}")
    finally:
        db.close()

    return redirect(url_for("dashboard"))

# --- 🛡️ GLOBAL CACHE BUSTER ---
@app.after_request
def add_header(response):
    if "Cache-Control" not in response.headers:
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

if __name__ == "__main__":
    app.run(debug=True)

