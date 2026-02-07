from flask import Flask, flash, render_template, request, redirect, url_for, session, make_response
import mysql.connector
import re, os
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

load_dotenv()

app = Flask(__name__)

# 🔐 Secret key
app.secret_key = os.getenv("FLASK_SECRET_KEY")

# This is what causes the auth error if HTML is missing the token
csrf = CSRFProtect(app)

# 📧 Mail Configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

mail = Mail(app)

# 🔐 Token Serializer (for generating secure links)
s = URLSafeTimedSerializer(app.secret_key)

# 🔐 Encryption key
fernet_key_str = os.getenv("FERNET_KEY")
if not fernet_key_str:
    raise ValueError("No FERNET_KEY found in .env file")

cipher = Fernet(fernet_key_str.encode())

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
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
            # FIX: Added message so user knows why they are redirected
            session["error_message"] = "Please complete your payment to access the dashboard."
            return redirect(url_for("payment"))

    success_msg = session.pop("success_message", None)
    error_msg = session.pop("error_message", None)

    return render_template(
        "signin.html", 
        success=success_msg, 
        error=error_msg, 
        old={}
    )

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    # 1. Check if logged in
    if "user_id" not in session:
        return redirect(url_for("signin"))
    
    # 2. Check if paid
    if not session.get("is_paid", False):
        session["error_message"] = "You must complete payment to access the dashboard."
        return redirect(url_for("payment"))
    
    # 3. Success (Global Cache Buster handles the headers now)
    return render_template("dashboard.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out successfully")
    return redirect(url_for("signin"))

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

# Forgot and reset password

@app.route("/reset_request", methods=["GET", "POST"])
def reset_request():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        # 1. Validation: Check if empty
        if not email:
            flash("Please enter your email address.")
            return redirect(url_for("reset_request"))

        # 2. Validation: Check Syntax & DNS (Real Domain Check)
        try:
            valid = validate_email(email, check_deliverability=True)
            email = valid.normalized
        except EmailNotValidError as e:
            flash(str(e)) # e.g., "The domain gmailll.com does not exist"
            return redirect(url_for("reset_request"))

        # 3. Database Check
        try:
            db = get_db_connection()
            cursor = db.cursor()
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            cursor.close()
            db.close()

            if user:
                # ✅ User Found - Send Email
                token = s.dumps(email, salt='password-reset-salt')
                link = url_for('reset_token', token=token, _external=True)
                
                msg = Message('Password Reset Request', 
                              sender=os.getenv('MAIL_USERNAME'), 
                              recipients=[email])
                msg.body = f'Click the link to reset your password: {link}\n\nIf you did not make this request, ignore this email.'
                
                try:
                    mail.send(msg)
                    flash("An email has been sent with instructions to reset your password.")
                    return redirect(url_for("signin"))
                except Exception as e:
                    print(f"Mail Error: {e}")
                    flash("Error sending email. Please try again later.")
                    return redirect(url_for("reset_request"))

            else:
                # ❌ User Not Found - Show Explicit Error
                flash("Email does not exist in our records.")
                return redirect(url_for("reset_request"))

        except Exception as e:
            print(f"Database Error: {e}")
            flash("An error occurred. Please try again.")
            return redirect(url_for("reset_request"))

    return render_template("reset_request.html")

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_token(token):
    try:
        # Verify Token (Expires in 1 hour = 3600 seconds)
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except Exception:
        flash("The reset link is invalid or has expired.")
        return redirect(url_for("reset_request"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # 1. Check Matching
        if password != confirm_password:
            flash("Passwords do not match")
            return redirect(url_for("reset_token", token=token))
            
        # 2. Check Length
        if len(password) < 8:
            flash("Password must be at least 8 characters long")
            return redirect(url_for("reset_token", token=token))

        # 3. Check Complexity (Uppercase + Number + Special Char)
        password_pattern = r'^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])'
        if not re.search(password_pattern, password):
            flash("Password must contain at least one uppercase letter, one number, and one special character")
            return redirect(url_for("reset_token", token=token))

        # 4. Update Password in DB
        hashed_password = generate_password_hash(password)
        
        try:
            db = get_db_connection()
            cursor = db.cursor()
            cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_password, email))
            db.commit()
            cursor.close()
            db.close()

            flash("Your password has been updated! You can now log in.")
            return redirect(url_for("signin"))
            
        except Exception as e:
            print(f"Database Error: {e}")
            flash("An error occurred while updating your password.")
            return redirect(url_for("reset_token", token=token))

    return render_template("reset_token.html", token=token)

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
