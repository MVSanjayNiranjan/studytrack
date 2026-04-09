import os
import random
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage

import httpx
import psycopg2
import bcrypt
from groq import Groq
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, static_folder="static", static_url_path="")
CORS(app)

app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
jwt = JWTManager(app)

# ─────────────────────────────────────────────
# Database connection helper
# ─────────────────────────────────────────────
def get_db():
    return psycopg2.connect(os.getenv("DATABASE_URL"))


def generate_verification_code():
    return f"{random.randint(100000, 999999)}"


def is_valid_email(email):
    return "@" in email and "." in email.rsplit("@", 1)[-1]


def send_email(to_email, subject, body):
    brevo_api_key = os.getenv("BREVO_API_KEY")
    from_email = os.getenv("FROM_EMAIL")
    from_name = os.getenv("FROM_NAME", "StudyTrack")

    if brevo_api_key and from_email:
        response = httpx.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={
                "api-key": brevo_api_key,
                "Content-Type": "application/json",
                "accept": "application/json",
            },
            json={
                "sender": {"name": from_name, "email": from_email},
                "to": [{"email": to_email}],
                "subject": subject,
                "textContent": body,
            },
            timeout=20.0,
        )
        if response.status_code >= 400:
            raise RuntimeError(f"Brevo error: {response.text}")
        return

    smtp_email = os.getenv("SMTP_EMAIL")
    smtp_app_password = os.getenv("SMTP_APP_PASSWORD")

    if not smtp_email or not smtp_app_password:
        raise RuntimeError(
            "Email sending is not configured. Add BREVO_API_KEY and FROM_EMAIL in Railway, or use SMTP_EMAIL and SMTP_APP_PASSWORD."
        )

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = smtp_email
    msg["To"] = to_email
    msg.set_content(body)

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(smtp_email, smtp_app_password)
        server.send_message(msg)


def send_verification_email(to_email, username, code):
    send_email(
        to_email,
        "StudyTrack verification code",
        (
            f"Hi {username},\n\n"
            f"Your StudyTrack verification code is: {code}\n\n"
            "It expires in 10 minutes.\n\n"
            "If you did not create this account, you can ignore this email."
        ),
    )


def send_password_reset_email(to_email, username, code):
    send_email(
        to_email,
        "StudyTrack password reset code",
        (
            f"Hi {username},\n\n"
            f"Your StudyTrack password reset code is: {code}\n\n"
            "It expires in 10 minutes.\n\n"
            "If you did not request a password reset, you can ignore this email."
        ),
    )


def send_username_reminder_email(to_email, code):
    send_email(
        to_email,
        "StudyTrack username reminder code",
        (
            f"Hi,\n\n"
            f"Your StudyTrack username reminder code is: {code}\n\n"
            "It expires in 10 minutes.\n\n"
            "If you did not request this, you can ignore this email."
        ),
    )


def ensure_user_email_verification_columns():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT")
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT TRUE")
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_code TEXT")
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_expires_at TIMESTAMPTZ")
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_code TEXT")
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_expires_at TIMESTAMPTZ")
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS username_reminder_code TEXT")
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS username_reminder_expires_at TIMESTAMPTZ")
    cur.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique_idx "
        "ON users (email) WHERE email IS NOT NULL"
    )
    conn.commit()
    cur.close()
    conn.close()


ensure_user_email_verification_columns()


def ensure_coach_memory_column():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS coach_memory TEXT DEFAULT ''")
    conn.commit()
    cur.close()
    conn.close()


try:
    ensure_coach_memory_column()
except Exception:
    pass


def ensure_chat_tables():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS chat_sessions (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS chat_messages (
            id SERIAL PRIMARY KEY,
            session_id INTEGER NOT NULL REFERENCES chat_sessions(id) ON DELETE CASCADE,
            role TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
            content TEXT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    """)
    conn.commit()
    cur.close()
    conn.close()


try:
    ensure_chat_tables()
except Exception:
    pass


# ─────────────────────────────────────────────
# Serve frontend
# ─────────────────────────────────────────────
@app.route("/")
def index():
    return app.send_static_file("index.html")


# ─────────────────────────────────────────────
# POST /api/register
# Body: { "username": "...", "email": "...", "password": "..." }
# ─────────────────────────────────────────────
@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not username or not email or not password:
        return jsonify({"error": "Username, email, and password required"}), 400

    if not is_valid_email(email):
        return jsonify({"error": "Enter a valid email address"}), 400

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    verification_code = generate_verification_code()
    expires_at = datetime.utcnow() + timedelta(minutes=10)

    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()

        cur.execute("SELECT 1 FROM users WHERE username = %s", (username,))
        if cur.fetchone():
            cur.close()
            conn.close()
            return jsonify({"error": "Username already taken"}), 409

        cur.execute("SELECT 1 FROM users WHERE email = %s", (email,))
        if cur.fetchone():
            cur.close()
            conn.close()
            return jsonify({"error": "Email already registered"}), 409

        cur.execute(
            "INSERT INTO users (username, email, password_hash, is_verified, verification_code, verification_expires_at) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (username, email, hashed, False, verification_code, expires_at)
        )

        send_verification_email(email, username, verification_code)

        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"message": "Account created. Check your email for the verification code."}), 201
    except Exception as e:
        if conn:
            conn.rollback()
            conn.close()
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# POST /api/resend-verification
# Body: { "username": "...", "email": "..." }
# ─────────────────────────────────────────────
@app.route("/api/resend-verification", methods=["POST"])
def resend_verification():
    data = request.get_json()
    username = data.get("username", "").strip()
    email = data.get("email", "").strip().lower()

    if not username or not email:
        return jsonify({"error": "Username and email required"}), 400

    code = generate_verification_code()
    expires_at = datetime.utcnow() + timedelta(minutes=10)

    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, COALESCE(is_verified, TRUE) FROM users WHERE username = %s AND email = %s",
            (username, email)
        )
        row = cur.fetchone()

        if row is None:
            cur.close()
            conn.close()
            return jsonify({"error": "Account not found"}), 404

        if row[1]:
            cur.close()
            conn.close()
            return jsonify({"message": "Email is already verified. Please log in."}), 200

        cur.execute(
            "UPDATE users SET verification_code = %s, verification_expires_at = %s WHERE id = %s",
            (code, expires_at, row[0])
        )

        send_verification_email(email, username, code)

        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"message": "A new verification code has been sent."}), 200
    except Exception as e:
        if conn:
            conn.rollback()
            conn.close()
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# POST /api/verify-email
# Body: { "username": "...", "email": "...", "code": "123456" }
# ─────────────────────────────────────────────
@app.route("/api/verify-email", methods=["POST"])
def verify_email():
    data = request.get_json()
    username = data.get("username", "").strip()
    email = data.get("email", "").strip().lower()
    code = data.get("code", "").strip()

    if not username or not email or not code:
        return jsonify({"error": "Username, email, and verification code required"}), 400

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, verification_code, verification_expires_at, COALESCE(is_verified, TRUE) "
            "FROM users WHERE username = %s AND email = %s",
            (username, email)
        )
        row = cur.fetchone()

        if row is None:
            cur.close()
            conn.close()
            return jsonify({"error": "Account not found"}), 404

        user_id, stored_code, expires_at, is_verified = row

        if is_verified:
            cur.close()
            conn.close()
            return jsonify({"message": "Email already verified. Please log in."}), 200

        if stored_code != code:
            cur.close()
            conn.close()
            return jsonify({"error": "Invalid verification code"}), 400

        now = datetime.now(expires_at.tzinfo) if expires_at and getattr(expires_at, "tzinfo", None) else datetime.utcnow()
        if expires_at is None or expires_at < now:
            cur.close()
            conn.close()
            return jsonify({"error": "Verification code expired. Request a new one."}), 400

        cur.execute(
            "UPDATE users SET is_verified = TRUE, verification_code = NULL, verification_expires_at = NULL WHERE id = %s",
            (user_id,)
        )
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"message": "Email verified. You can now log in."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# POST /api/forgot-password
# Body: { "email": "..." }
# ─────────────────────────────────────────────
@app.route("/api/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json()
    email = data.get("email", "").strip().lower()

    if not email:
        return jsonify({"error": "Email required"}), 400

    if not is_valid_email(email):
        return jsonify({"error": "Enter a valid email address"}), 400

    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username FROM users WHERE email = %s",
            (email,)
        )
        row = cur.fetchone()

        if row:
            user_id, username = row
            reset_code = generate_verification_code()
            expires_at = datetime.utcnow() + timedelta(minutes=10)
            cur.execute(
                "UPDATE users SET password_reset_code = %s, password_reset_expires_at = %s WHERE id = %s",
                (reset_code, expires_at, user_id)
            )
            send_password_reset_email(email, username, reset_code)
            conn.commit()

        cur.close()
        conn.close()
        return jsonify({"message": "If an account exists for that email, a reset code has been sent."}), 200
    except Exception as e:
        if conn:
            conn.rollback()
            conn.close()
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# POST /api/reset-password
# Body: { "email": "...", "code": "123456", "new_password": "..." }
# ─────────────────────────────────────────────
@app.route("/api/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json()
    email = data.get("email", "").strip().lower()
    code = data.get("code", "").strip()
    new_password = data.get("new_password", "")

    if not email or not code or not new_password:
        return jsonify({"error": "Email, reset code, and new password required"}), 400

    if len(new_password) < 6:
        return jsonify({"error": "New password must be at least 6 characters"}), 400

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, password_reset_code, password_reset_expires_at FROM users WHERE email = %s",
            (email,)
        )
        row = cur.fetchone()

        if row is None:
            cur.close()
            conn.close()
            return jsonify({"error": "Invalid reset request"}), 400

        user_id, stored_code, expires_at = row

        if stored_code != code:
            cur.close()
            conn.close()
            return jsonify({"error": "Invalid reset code"}), 400

        now = datetime.now(expires_at.tzinfo) if expires_at and getattr(expires_at, "tzinfo", None) else datetime.utcnow()
        if expires_at is None or expires_at < now:
            cur.close()
            conn.close()
            return jsonify({"error": "Reset code expired. Request a new one."}), 400

        new_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
        cur.execute(
            "UPDATE users SET password_hash = %s, password_reset_code = NULL, password_reset_expires_at = NULL WHERE id = %s",
            (new_hash, user_id)
        )
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"message": "Password reset successful. You can now log in."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# POST /api/forgot-username
# Body: { "email": "..." }
# ─────────────────────────────────────────────
@app.route("/api/forgot-username", methods=["POST"])
def forgot_username():
    data = request.get_json()
    email = data.get("email", "").strip().lower()

    if not email:
        return jsonify({"error": "Email required"}), 400

    if not is_valid_email(email):
        return jsonify({"error": "Enter a valid email address"}), 400

    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        row = cur.fetchone()

        if row:
            user_id = row[0]
            reminder_code = generate_verification_code()
            expires_at = datetime.utcnow() + timedelta(minutes=10)
            cur.execute(
                "UPDATE users SET username_reminder_code = %s, username_reminder_expires_at = %s WHERE id = %s",
                (reminder_code, expires_at, user_id)
            )
            send_username_reminder_email(email, reminder_code)
            conn.commit()

        cur.close()
        conn.close()
        return jsonify({"message": "If an account exists for that email, a code has been sent."}), 200
    except Exception as e:
        if conn:
            conn.rollback()
            conn.close()
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# POST /api/verify-forgot-username
# Body: { "email": "...", "code": "123456" }
# Returns: { "username": "..." }
# ─────────────────────────────────────────────
@app.route("/api/verify-forgot-username", methods=["POST"])
def verify_forgot_username():
    data = request.get_json()
    email = data.get("email", "").strip().lower()
    code = data.get("code", "").strip()

    if not email or not code:
        return jsonify({"error": "Email and code required"}), 400

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT username, username_reminder_code, username_reminder_expires_at FROM users WHERE email = %s",
            (email,)
        )
        row = cur.fetchone()

        if row is None:
            cur.close()
            conn.close()
            return jsonify({"error": "Invalid request"}), 400

        username, stored_code, expires_at = row

        if stored_code != code:
            cur.close()
            conn.close()
            return jsonify({"error": "Invalid code"}), 400

        now = datetime.now(expires_at.tzinfo) if expires_at and getattr(expires_at, "tzinfo", None) else datetime.utcnow()
        if expires_at is None or expires_at < now:
            cur.close()
            conn.close()
            return jsonify({"error": "Code expired. Request a new one."}), 400

        cur.execute(
            "UPDATE users SET username_reminder_code = NULL, username_reminder_expires_at = NULL WHERE email = %s",
            (email,)
        )
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"username": username}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# POST /api/login
# Body: { "username": "...", "password": "..." }
# Returns: { "token": "..." }
# ─────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, password_hash, COALESCE(is_verified, TRUE) FROM users WHERE username = %s",
            (username,)
        )
        row = cur.fetchone()
        cur.close()
        conn.close()

        if row is None:
            return jsonify({"error": "Invalid credentials"}), 401

        user_id, stored_hash, is_verified = row
        if not bcrypt.checkpw(password.encode(), stored_hash.encode()):
            return jsonify({"error": "Invalid credentials"}), 401

        if not is_verified:
            return jsonify({"error": "Please verify your email before logging in."}), 403

        token = create_access_token(identity=str(user_id))
        return jsonify({"token": token, "username": username}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# GET  /api/attendance          → list records for the logged-in user
# POST /api/attendance          → mark attendance for a date
# Body: { "date": "2024-01-15", "subject": "Math", "status": "Present" }
# ─────────────────────────────────────────────
@app.route("/api/attendance", methods=["GET", "POST"])
@jwt_required()
def attendance():
    user_id = int(get_jwt_identity())

    if request.method == "GET":
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute(
                "SELECT id, date, subject, status FROM attendance "
                "WHERE user_id = %s ORDER BY date DESC",
                (user_id,)
            )
            rows = cur.fetchall()
            cur.close()
            conn.close()
            records = [
                {"id": r[0], "date": str(r[1]), "subject": r[2], "status": r[3]}
                for r in rows
            ]
            return jsonify(records), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    if request.method == "POST":
        data = request.get_json()
        date = data.get("date")
        subject = data.get("subject", "").strip()
        status = data.get("status", "").strip()

        if not date or not subject or status not in ("Present", "Late", "Absent"):
            return jsonify({"error": "date, subject, and status (Present/Late/Absent) required"}), 400

        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO attendance (user_id, date, subject, status) "
                "VALUES (%s, %s, %s, %s) "
                "ON CONFLICT (user_id, date, subject) "
                "DO UPDATE SET status = EXCLUDED.status "
                "RETURNING id",
                (user_id, date, subject, status)
            )
            new_id = cur.fetchone()[0]
            conn.commit()
            cur.close()
            conn.close()
            return jsonify({"id": new_id, "message": "Attendance saved"}), 201
        except Exception as e:
            return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# GET  /api/study_logs          → list study sessions for the logged-in user
# POST /api/study_logs          → log a completed Pomodoro session
# Body: { "subject": "Math", "duration_minutes": 25, "date": "2024-01-15" }
# ─────────────────────────────────────────────
@app.route("/api/study_logs", methods=["GET", "POST"])
@jwt_required()
def study_logs():
    user_id = int(get_jwt_identity())

    if request.method == "GET":
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute(
                "SELECT id, subject, duration_minutes, date "
                "FROM study_logs WHERE user_id = %s ORDER BY date DESC",
                (user_id,)
            )
            rows = cur.fetchall()
            cur.close()
            conn.close()
            records = [
                {"id": r[0], "subject": r[1], "duration_minutes": r[2], "date": str(r[3])}
                for r in rows
            ]
            return jsonify(records), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    if request.method == "POST":
        data = request.get_json()
        subject = data.get("subject", "").strip()
        duration = data.get("duration_minutes")
        date = data.get("date")

        if not subject or not duration or not date:
            return jsonify({"error": "subject, duration_minutes, and date required"}), 400

        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO study_logs (user_id, subject, duration_minutes, date) "
                "VALUES (%s, %s, %s, %s) RETURNING id",
                (user_id, subject, duration, date)
            )
            new_id = cur.fetchone()[0]
            conn.commit()
            cur.close()
            conn.close()
            return jsonify({"id": new_id, "message": "Study session logged"}), 201
        except Exception as e:
            return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# GET /api/streak
# Returns: { "streak": int, "last_date": "YYYY-MM-DD"|null }
# ─────────────────────────────────────────────
@app.route("/api/streak", methods=["GET"])
@jwt_required()
def get_streak():
    user_id = int(get_jwt_identity())
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT DISTINCT date FROM study_logs "
            "WHERE user_id = %s ORDER BY date DESC",
            (user_id,)
        )
        rows = cur.fetchall()
        cur.close()
        conn.close()

        if not rows:
            return jsonify({"streak": 0, "last_date": None}), 200

        from datetime import date as date_type
        dates = [r[0] if isinstance(r[0], date_type) else date_type.fromisoformat(str(r[0])) for r in rows]
        today = date_type.today()
        # Allow streak to continue if last log was today or yesterday
        if dates[0] < today - timedelta(days=1):
            return jsonify({"streak": 0, "last_date": str(dates[0])}), 200
        streak = 0
        expected = today
        for d in dates:
            if d == expected or (streak == 0 and d == today - timedelta(days=1)):
                streak += 1
                expected = d - timedelta(days=1)
            else:
                break
        return jsonify({"streak": streak, "last_date": str(dates[0])}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# GET  /api/coach_memory  → { "memory": "..." }
# POST /api/coach_memory  → save { "memory": "..." }
# ─────────────────────────────────────────────
@app.route("/api/coach_memory", methods=["GET", "POST"])
@jwt_required()
def coach_memory():
    user_id = int(get_jwt_identity())
    if request.method == "GET":
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT COALESCE(coach_memory,'') FROM users WHERE id = %s", (user_id,))
            row = cur.fetchone()
            cur.close()
            conn.close()
            return jsonify({"memory": row[0] if row else ""}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    data = request.get_json()
    memory = data.get("memory", "")
    if len(memory) > 2000:
        return jsonify({"error": "Notes too long (max 2000 chars)"}), 400
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("UPDATE users SET coach_memory = %s WHERE id = %s", (memory, user_id))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"message": "Saved"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# GET   /api/tasks              → list tasks for the logged-in user
# POST  /api/tasks              → create a new task
# PATCH /api/tasks/<id>         → update a task (complete or delete)
# POST  Body:  { "title": "...", "subject": "Math" }
# PATCH Body:  { "completed": true }  OR  { "deleted": true }
# ─────────────────────────────────────────────
@app.route("/api/tasks", methods=["GET", "POST"])
@jwt_required()
def tasks():
    user_id = int(get_jwt_identity())

    if request.method == "GET":
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute(
                "SELECT id, title, subject, completed, created_at "
                "FROM tasks WHERE user_id = %s AND deleted = FALSE "
                "ORDER BY created_at DESC",
                (user_id,)
            )
            rows = cur.fetchall()
            cur.close()
            conn.close()
            records = [
                {
                    "id": r[0], "title": r[1], "subject": r[2],
                    "completed": r[3], "created_at": str(r[4])
                }
                for r in rows
            ]
            return jsonify(records), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    if request.method == "POST":
        data = request.get_json()
        title = data.get("title", "").strip()
        subject = data.get("subject", "General").strip()

        if not title:
            return jsonify({"error": "title required"}), 400

        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO tasks (user_id, title, subject) VALUES (%s, %s, %s) RETURNING id",
                (user_id, title, subject)
            )
            new_id = cur.fetchone()[0]
            conn.commit()
            cur.close()
            conn.close()
            return jsonify({"id": new_id, "message": "Task created"}), 201
        except Exception as e:
            return jsonify({"error": str(e)}), 500


@app.route("/api/tasks/<int:task_id>", methods=["PATCH", "DELETE"])
@jwt_required()
def update_task(task_id):
    user_id = int(get_jwt_identity())

    if request.method == "DELETE":
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute(
                "UPDATE tasks SET deleted = TRUE "
                "WHERE id = %s AND user_id = %s",
                (task_id, user_id)
            )
            conn.commit()
            cur.close()
            conn.close()
            return jsonify({"message": "Task deleted"}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    data = request.get_json()
    completed = data.get("completed")

    if completed is None:
        return jsonify({"error": "completed field required"}), 400

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "UPDATE tasks SET completed = %s WHERE id = %s AND user_id = %s",
            (completed, task_id, user_id)
        )
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"message": "Task updated"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# GET  /api/chat/sessions       – list sessions
# POST /api/chat/sessions       – create session
# ─────────────────────────────────────────────
@app.route("/api/chat/sessions", methods=["GET", "POST"])
@jwt_required()
def chat_sessions():
    user_id = int(get_jwt_identity())

    if request.method == "GET":
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute(
                "SELECT id, title, created_at FROM chat_sessions "
                "WHERE user_id = %s ORDER BY created_at DESC",
                (user_id,)
            )
            rows = cur.fetchall()
            cur.close()
            conn.close()
            return jsonify([
                {"id": r[0], "title": r[1], "created_at": str(r[2])}
                for r in rows
            ]), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    data = request.get_json()
    title = (data.get("title", "") or "New Chat").strip() or "New Chat"
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO chat_sessions (user_id, title) VALUES (%s, %s) RETURNING id, created_at",
            (user_id, title)
        )
        row = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"id": row[0], "title": title, "created_at": str(row[1])}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# DELETE /api/chat/sessions/<id>
# ─────────────────────────────────────────────
@app.route("/api/chat/sessions/<int:session_id>", methods=["DELETE"])
@jwt_required()
def delete_chat_session(session_id):
    user_id = int(get_jwt_identity())
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM chat_sessions WHERE id = %s AND user_id = %s",
            (session_id, user_id)
        )
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"message": "Deleted"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# GET /api/chat/sessions/<id>/messages
# ─────────────────────────────────────────────
@app.route("/api/chat/sessions/<int:session_id>/messages", methods=["GET"])
@jwt_required()
def chat_session_messages(session_id):
    user_id = int(get_jwt_identity())
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT id FROM chat_sessions WHERE id = %s AND user_id = %s",
            (session_id, user_id)
        )
        if not cur.fetchone():
            cur.close()
            conn.close()
            return jsonify({"error": "Not found"}), 404
        cur.execute(
            "SELECT role, content FROM chat_messages "
            "WHERE session_id = %s ORDER BY created_at ASC",
            (session_id,)
        )
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify([{"role": r[0], "content": r[1]} for r in rows]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# POST /api/ai_coach
# Body: { "message": "...", "session_id": null|int }
# Returns: { "reply": "...", "session_id": int }
# ─────────────────────────────────────────────
@app.route("/api/ai_coach", methods=["POST"])
@jwt_required()
def ai_coach():
    user_id = int(get_jwt_identity())
    data = request.get_json()
    user_message = data.get("message", "").strip()
    session_id = data.get("session_id")

    if not user_message:
        return jsonify({"error": "message required"}), 400

    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return jsonify({"reply": "AI coach is not configured. Add GROQ_API_KEY.", "session_id": session_id}), 200

    try:
        conn = get_db()
        cur = conn.cursor()

        # Create a new session automatically on first message
        if not session_id:
            title = user_message[:60]
            cur.execute(
                "INSERT INTO chat_sessions (user_id, title) VALUES (%s, %s) RETURNING id",
                (user_id, title)
            )
            session_id = cur.fetchone()[0]
            conn.commit()

        # Load conversation history for context
        cur.execute(
            "SELECT role, content FROM chat_messages "
            "WHERE session_id = %s ORDER BY created_at ASC",
            (session_id,)
        )
        history = [{"role": r[0], "content": r[1]} for r in cur.fetchall()]

        # Fetch user's personal coach notes
        cur.execute("SELECT COALESCE(coach_memory,'') FROM users WHERE id = %s", (user_id,))
        mem_row = cur.fetchone()
        coach_mem = mem_row[0].strip() if mem_row and mem_row[0] else ""

        # Save the user message
        cur.execute(
            "INSERT INTO chat_messages (session_id, role, content) VALUES (%s, 'user', %s)",
            (session_id, user_message)
        )
        conn.commit()

        system_prompt = (
            "You are StudyCoach, a knowledgeable AI assistant for students. "
            "You can help with: study techniques, time management, exam prep, motivation, "
            "mathematics, science, coding and programming (any language), writing, and any academic subject. "
            "Format every response for readability:\n"
            "- Use numbered lists (1. 2. 3.) or bullet points (-) for multiple steps or tips, each on its own line.\n"
            "- Use **bold** for key terms or important points.\n"
            "- For code, wrap it in triple backticks with the language name.\n"
            "- Separate distinct sections with a blank line.\n"
            "Be clear, practical, and thorough. Do not cram everything into one paragraph."
        )
        if coach_mem:
            system_prompt += f"\n\nPersonal context about this student (always keep this in mind): {coach_mem}"

        client = Groq(api_key=api_key)
        chat = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            max_tokens=1024,
            messages=[{"role": "system", "content": system_prompt}] + history + [{"role": "user", "content": user_message}]
        )
        reply = chat.choices[0].message.content

        # Save the assistant reply
        cur.execute(
            "INSERT INTO chat_messages (session_id, role, content) VALUES (%s, 'assistant', %s)",
            (session_id, reply)
        )
        conn.commit()
        cur.close()
        conn.close()

        return jsonify({"reply": reply, "session_id": session_id}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# Run
# ─────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
