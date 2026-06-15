"""
Secure Login System
Features: bcrypt hashing, SQL injection protection, session management, 2FA (TOTP)
"""

import os
import re
import sqlite3
import pyotp
import qrcode
import io
import base64
from datetime import timedelta
from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, g)
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = os.urandom(32)
app.permanent_session_lifetime = timedelta(minutes=30)
bcrypt = Bcrypt(app)

DB_PATH = "users.db"

# ── Database ──────────────────────────────────────────────────────────────────
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_database", None)
    if db: db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                username    TEXT    UNIQUE NOT NULL,
                email       TEXT    UNIQUE NOT NULL,
                password    TEXT    NOT NULL,
                totp_secret TEXT,
                is_2fa_enabled INTEGER DEFAULT 0,
                created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login  DATETIME
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                username   TEXT,
                ip_address TEXT,
                success    INTEGER,
                attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.commit()

# ── Validation ────────────────────────────────────────────────────────────────
def validate_username(u):
    if not u or len(u) < 3 or len(u) > 20:
        return "Username must be 3–20 characters."
    if not re.match(r"^[a-zA-Z0-9_]+$", u):
        return "Username can only contain letters, numbers, underscores."
    return None

def validate_password(p):
    if len(p) < 8:
        return "Password must be at least 8 characters."
    if not re.search(r"[A-Z]", p):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[0-9]", p):
        return "Password must contain at least one number."
    return None

def validate_email(e):
    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", e):
        return "Please enter a valid email address."
    return None

def is_rate_limited(username, ip):
    db = get_db()
    row = db.execute("""
        SELECT COUNT(*) as cnt FROM login_attempts
        WHERE (username=? OR ip_address=?) AND success=0
        AND attempted_at > datetime('now', '-15 minutes')
    """, (username, ip)).fetchone()
    return row["cnt"] >= 5

def log_attempt(username, ip, success):
    db = get_db()
    db.execute(
        "INSERT INTO login_attempts (username, ip_address, success) VALUES (?,?,?)",
        (username, ip, 1 if success else 0)
    )
    db.commit()

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        # Validate
        err = validate_username(username) or validate_email(email) or validate_password(password)
        if err:
            flash(err, "error"); return render_template("register.html")
        if password != confirm:
            flash("Passwords do not match.", "error"); return render_template("register.html")

        # Hash password with bcrypt (cost factor 12)
        hashed = bcrypt.generate_password_hash(password, rounds=12).decode("utf-8")

        db = get_db()
        try:
            # Parameterised query — SQL injection proof
            db.execute(
                "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                (username, email, hashed)
            )
            db.commit()
            flash("Account created! Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username or email already exists.", "error")

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip       = request.remote_addr

        # Rate limit check
        if is_rate_limited(username, ip):
            flash("Too many failed attempts. Please wait 15 minutes.", "error")
            return render_template("login.html")

        db = get_db()
        # Parameterised query — SQL injection proof
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user and bcrypt.check_password_hash(user["password"], password):
            log_attempt(username, ip, True)
            # 2FA required?
            if user["is_2fa_enabled"]:
                session["2fa_pending_user_id"] = user["id"]
                return redirect(url_for("verify_2fa"))
            # Full login
            session.permanent = True
            session["user_id"]  = user["id"]
            session["username"] = user["username"]
            db.execute("UPDATE users SET last_login=datetime('now') WHERE id=?", (user["id"],))
            db.commit()
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for("dashboard"))
        else:
            log_attempt(username, ip, False)
            flash("Invalid username or password.", "error")

    return render_template("login.html")

@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    if "2fa_pending_user_id" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        db   = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE id = ?", (session["2fa_pending_user_id"],)
        ).fetchone()
        totp = pyotp.TOTP(user["totp_secret"])
        if totp.verify(code, valid_window=1):
            session.pop("2fa_pending_user_id")
            session.permanent = True
            session["user_id"]  = user["id"]
            session["username"] = user["username"]
            db.execute("UPDATE users SET last_login=datetime('now') WHERE id=?", (user["id"],))
            db.commit()
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid 2FA code. Try again.", "error")
    return render_template("verify_2fa.html")

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Please log in to continue.", "error")
        return redirect(url_for("login"))
    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    return render_template("dashboard.html", user=user)

@app.route("/setup-2fa", methods=["GET", "POST"])
def setup_2fa():
    if "user_id" not in session:
        return redirect(url_for("login"))
    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()

    if request.method == "POST":
        code   = request.form.get("code", "").strip()
        secret = session.get("totp_secret_temp")
        if not secret:
            flash("Session expired. Try again.", "error")
            return redirect(url_for("setup_2fa"))
        totp = pyotp.TOTP(secret)
        if totp.verify(code, valid_window=1):
            db.execute(
                "UPDATE users SET totp_secret=?, is_2fa_enabled=1 WHERE id=?",
                (secret, session["user_id"])
            )
            db.commit()
            session.pop("totp_secret_temp", None)
            flash("2FA enabled successfully!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid code. Make sure your authenticator is synced.", "error")

    # Generate new secret + QR code
    secret = pyotp.random_base32()
    session["totp_secret_temp"] = secret
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user["email"], issuer_name="SecureLogin"
    )
    img = qrcode.make(totp_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    return render_template("setup_2fa.html", qr_b64=qr_b64, secret=secret)

@app.route("/disable-2fa", methods=["POST"])
def disable_2fa():
    if "user_id" not in session:
        return redirect(url_for("login"))
    db = get_db()
    db.execute(
        "UPDATE users SET totp_secret=NULL, is_2fa_enabled=0 WHERE id=?",
        (session["user_id"],)
    )
    db.commit()
    flash("2FA has been disabled.", "success")
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)
