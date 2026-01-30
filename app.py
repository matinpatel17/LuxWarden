from flask import Flask, flash, render_template, request, redirect, url_for, session
import mysql.connector
import re
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import base64, hashlib
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect
from datetime import datetime
from cryptography.fernet import Fernet

app = Flask(__name__)

# 🔐 Secret key (required for flash & sessions)
app.secret_key = secrets.token_hex(32)

csrf = CSRFProtect(app)

# 🔐 Encryption key (store securely in env variable in production)
FERNET_KEY = Fernet.generate_key()
cipher = Fernet(FERNET_KEY)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="matin",
        password="matin@777",
        database="luxwarden"
    )

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Get form data
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip()
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
            return render_template(
                "register.html",
                error="All fields are required",
                old=old
            )

        if not phone.isdigit() or len(phone) != 10:
            return render_template(
                "register.html",
                error="Mobile number must be exactly 10 digits",
                old=old
            )

        if password != confirm_password:
            return render_template(
                "register.html",
                error="Passwords do not match",
                old=old
            )

        if len(password) < 8:
            return render_template(
                "register.html",
                error="Password must be at least 8 characters long",
                old=old
            )

        password_pattern = r'^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])'
        if not re.search(password_pattern, password):
            return render_template(
                "register.html",
                error=(
                    "Password must contain at least one uppercase letter, "
                    "one number, and one special character"
                ),
                old=old
            )

        hashed_password = generate_password_hash(password)

        db = get_db_connection()
        cursor = db.cursor()

        # Check if email exists
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            cursor.close()
            db.close()
            return render_template(
                "register.html",
                error="Email already registered",
                old=old
            )

        # Insert user
        cursor.execute(
            """
            INSERT INTO users (full_name, email, phone_number, password)
            VALUES (%s, %s, %s, %s)
            """,
            (full_name, email, phone, hashed_password)
        )
        db.commit()

        cursor.close()
        db.close()

        return render_template(
            "register.html",
            success=True,
            old = old
        )

    # GET request
    return render_template("register.html", old={})

@app.route("/signin", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def signin():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        old = {
            "email": email
        }

        # Required fields
        if not email or not password:
            return render_template(
                "signin.html",
                error="Email and password are required",
                old=old
            )

        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute(
            "SELECT id, full_name, password FROM users WHERE email = %s",
            (email,)
        )
        user = cursor.fetchone()

        cursor.close()
        db.close()

        if not user:
            return render_template(
                "signin.html",
                error="Email not registered. Please register first.",
                old=old
            )

        if not check_password_hash(user["password"], password):
            return render_template(
                "signin.html",
                error="Incorrect password. Try again.",
                old=old
            )

        # SUCCESS → create session
        session.clear()
        session["user_id"] = user["id"]
        session["user_name"] = user["full_name"]
        session["logged_in"] = True

        # Pass empty old dict on success
        return render_template(
            "dashboard.html",
            #success=f"Welcome back, {user['full_name']}!",
            old={}
        )

    # GET request
    return render_template("signin.html", old={})

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user_id" not in session:
        flash("Please login first")
        return redirect(url_for("signin"))
    
    return render_template("dashboard.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out successfully")
    return redirect(url_for("signin"))

@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":

        # 1️⃣ Validation
        if (
            not request.form.get("first_name") or 
            not request.form.get("email") or 
            not request.form.get("message")
        ):
            session["error"] = "Please fill First name, Email & Message"
            session["old"] = request.form
            return redirect(url_for("contact"))

        # 2️⃣ Save to DB
        db = get_db_connection()
        cursor = db.cursor()

        cursor.execute("""
            INSERT INTO contact_messages
            (first_name, last_name, email, phone_number, message)
            VALUES (%s, %s, %s, %s, %s)
        """, (
            request.form.get("first_name"),
            request.form.get("last_name"),
            request.form.get("email"),
            request.form.get("phone_number"),
            request.form.get("message")
        ))

        db.commit()
        cursor.close()
        db.close()

        # 3️⃣ Success
        session["success"] = True
        return redirect(url_for("contact"))

    # 4️⃣ GET request (THIS is where values are sent to HTML)
    success = session.pop("success", False)
    error = session.pop("error", None)
    old = session.pop("old", {})

    return render_template(
        "contact.html",
        success=success,
        error=error,
        old=old
    )

# Updated Flask Payment Route
@app.route("/payment", methods=["GET", "POST"])
def payment():
    # 🔐 Login required
    if "user_id" not in session:
        return redirect(url_for("signin"))

    if request.method == "POST":
        try:
            user_id = session["user_id"]

            # -------- FORM DATA -------- #
            full_name = request.form.get("full_name", "").strip()
            dob = request.form.get("date_of_birth")
            email = request.form.get("email", "").strip().lower()
            phone = request.form.get("phone", "").strip()
            billing_address = request.form.get("billing_address", "").strip()
            card_holder_name = request.form.get("card_holder_name", "").strip()
            card_number = request.form.get("card_number", "").replace(" ", "")
            card_expiry = request.form.get("card_expiry")
            cvv = request.form.get("cvv")

            # -------- VALIDATION -------- #
            if not all([
                full_name, dob, email, phone,
                billing_address, card_holder_name,
                card_number, card_expiry, cvv
            ]):
                session["error"] = "All fields are required"
                session["old"] = request.form.to_dict()
                return redirect(url_for("payment"))

            # -------- SECURITY PROCESSING -------- #
            encrypted_card = cipher.encrypt(card_number.encode()).decode()
            cvv_hash = hashlib.sha256(cvv.encode()).hexdigest()

            # -------- DB INSERT -------- #
            db = get_db_connection()
            cursor = db.cursor()

            cursor.execute("""
                INSERT INTO payments (
                    user_id,
                    full_name,
                    date_of_birth,
                    email,
                    phone,
                    billing_address,
                    card_holder_name,
                    card_number_encrypted,
                    card_expiry,
                    cvv_hash
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (
                user_id,
                full_name,
                dob,
                email,
                phone,
                billing_address,
                card_holder_name,
                encrypted_card,
                card_expiry,
                cvv_hash
            ))

            db.commit()
            cursor.close()
            db.close()

            print("✅ PAYMENT SAVED SUCCESSFULLY")

            # Success - store in session and redirect
            session["success"] = True
            return redirect(url_for("payment"))

        except Exception as e:
            print("❌ PAYMENT ERROR:", e)
            session["error"] = "Payment failed. Please try again."
            session["old"] = request.form.to_dict()
            return redirect(url_for("payment"))

    # GET request - retrieve messages from session
    success = session.pop("success", False)
    error = session.pop("error", None)
    old = session.pop("old", {})

    return render_template(
        "payment.html",
        success=success,
        error=error,
        old=old
    )
    
if __name__ == "__main__":
    app.run(debug=True)
