# 🔐 Secure Login System

A full-stack secure web application built with Flask featuring bcrypt password hashing, SQL injection protection, session management, and optional TOTP-based Two-Factor Authentication.

---

## 📋 Table of Contents
- [Features](#features)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [How to Run](#how-to-run)
- [Security Features Explained](#security-features-explained)
- [Screenshots / Pages](#pages)
- [Technologies Used](#technologies-used)
- [Learning Outcomes](#learning-outcomes)

---

## ✅ Features

- **User Registration** with real-time password strength meter
- **bcrypt Password Hashing** with cost factor 12 (never stored as plain text)
- **SQL Injection Protection** via parameterised queries throughout
- **Input Validation** — username regex, email format, password complexity
- **Rate Limiting** — 5 failed attempts = 15-minute lockout per IP/username
- **Session Management** — secure sessions, 30-minute auto-expiry
- **Logout** — clears all session data instantly
- **2FA (TOTP)** — QR code setup, works with Google Authenticator / Authy
- **Login Attempt Logging** — all attempts (success/fail) recorded in DB

---

## 📁 Project Structure

```
secure-login/
├── app.py                  # Main Flask application
├── requirements.txt        # Python dependencies
├── users.db                # SQLite database (auto-created on first run)
├── README.md
└── templates/
    ├── base.html           # Shared layout + CSS
    ├── register.html       # Registration page
    ├── login.html          # Login page
    ├── dashboard.html      # User dashboard
    ├── setup_2fa.html      # 2FA QR code setup
    └── verify_2fa.html     # 2FA code entry
```

---

## ⚙️ Installation

**Step 1 — Clone the repository**
```bash
git clone https://github.com/KrishSingh06/secure-login.git
cd secure-login
```

**Step 2 — Install dependencies**
```bash
pip install -r requirements.txt
```

---

## 🚀 How to Run

```bash
python3 app.py
```

Then open your browser and go to:
```
http://localhost:5000
```

The SQLite database (`users.db`) is created automatically on first run.

---

## 🛡️ Security Features Explained

### 1. bcrypt Password Hashing
Passwords are never stored as plain text. bcrypt adds a random salt and runs 2^12 (4096) hashing rounds:
```python
hashed = bcrypt.generate_password_hash(password, rounds=12)
bcrypt.check_password_hash(hashed, password)  # on login
```

### 2. SQL Injection Protection
Every database query uses parameterised placeholders (`?`) — user input is never interpolated directly:
```python
# SAFE — parameterised
user = db.execute("SELECT * FROM users WHERE username = ?", (username,))

# DANGEROUS — never done this way
user = db.execute(f"SELECT * FROM users WHERE username = '{username}'")
```

### 3. Input Validation
- Username: 3–20 chars, alphanumeric + underscores only (regex enforced)
- Email: standard format check
- Password: min 8 chars, must include uppercase + number

### 4. Rate Limiting
Tracks failed login attempts by username AND IP address in the database:
```
5 failed attempts within 15 minutes → locked out for 15 minutes
```

### 5. Session Management
- Sessions use a random 32-byte secret key
- Sessions expire after 30 minutes of inactivity
- Logout clears the entire session immediately

### 6. Two-Factor Authentication (TOTP)
Uses RFC 6238 Time-based One-Time Passwords:
- Scan QR code with Google Authenticator or Authy
- 6-digit code refreshes every 30 seconds
- Verified server-side with ±1 window tolerance

---

## 📄 Pages

| Page | URL | Description |
|---|---|---|
| Register | `/register` | Create account with password strength meter |
| Login | `/login` | Sign in with rate-limit protection |
| Dashboard | `/dashboard` | View account info, manage 2FA |
| Setup 2FA | `/setup-2fa` | Scan QR code, verify, enable |
| Verify 2FA | `/verify-2fa` | Enter TOTP code after login |
| Logout | `/logout` | Clear session and redirect |

---

## 🛠️ Technologies Used

| Tool | Purpose |
|---|---|
| **Flask** | Web framework |
| **flask-bcrypt** | Password hashing (bcrypt, cost 12) |
| **pyotp** | TOTP 2FA (RFC 6238) |
| **qrcode + Pillow** | QR code generation for 2FA setup |
| **SQLite** | Database (via Python's built-in sqlite3) |
| **HTML/CSS** | Dark security-themed UI (no frameworks) |

---

## 📚 Learning Outcomes

- How bcrypt salting and hashing protects passwords
- Why parameterised queries prevent SQL injection
- How TOTP-based 2FA works (time-based shared secret)
- Session lifecycle management in web apps
- Rate limiting to prevent brute-force attacks
- Input validation on both client and server side

---

## ⚠️ Note

This is an educational project. For production use, add:
- HTTPS (SSL certificate)
- CSRF protection (flask-wtf)
- Email verification on registration
- Password reset flow

---

## 👨‍💻 Author

**Krish Singh**
GitHub: [@KrishSingh06](https://github.com/KrishSingh06)
