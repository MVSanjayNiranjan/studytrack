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
    resend_api_key = os.getenv("RESEND_API_KEY")
    from_email = os.getenv("FROM_EMAIL")

    if resend_api_key and from_email:
        response = httpx.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {resend_api_key}",
                "Content-Type": "application/json",
            },
            json={
                "from": from_email,
                "to": [to_email],
                "subject": subject,
                "text": body,
            },
            timeout=20.0,
        )
        if response.status_code >= 400:
            raise RuntimeError(f"Resend error: {response.text}")
        return

    smtp_email = os.getenv("SMTP_EMAIL")
    smtp_app_password = os.getenv("SMTP_APP_PASSWORD")

    if not smtp_email or not smtp_app_password:
        raise RuntimeError(
            "Email sending is not configured. Add RESEND_API_KEY and FROM_EMAIL in Railway, or use SMTP_EMAIL and SMTP_APP_PASSWORD."
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


def ensure_user_email_verification_columns():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT")
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT TRUE")
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_code TEXT")
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_expires_at TIMESTAMPTZ")
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_code TEXT")
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_expires_at TIMESTAMPTZ")
    cur.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique_idx "
        "ON users (email) WHERE email IS NOT NULL"
    )
    conn.commit()
    cur.close()
    conn.close()


ensure_user_email_verification_columns()


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
# POST /api/ai_coach
# Body: { "message": "How should I study for my Math exam?" }
# Returns: { "reply": "..." }
# ─────────────────────────────────────────────
@app.route("/api/ai_coach", methods=["POST"])
@jwt_required()
def ai_coach():
    data = request.get_json()
    user_message = data.get("message", "").strip()

    if not user_message:
        return jsonify({"error": "message required"}), 400

    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return jsonify({"reply": "AI coach is not configured yet. Add your GROQ_API_KEY in Render environment variables."}), 200

    try:
        client = Groq(api_key=api_key)
        chat = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            max_tokens=512,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are StudyCoach, a friendly AI assistant for students. "
                        "Give concise, practical study advice. "
                        "Focus on study techniques, time management, and motivation. "
                        "Keep responses under 150 words."
                    )
                },
                {"role": "user", "content": user_message}
            ]
        )
        reply = chat.choices[0].message.content
        return jsonify({"reply": reply}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# Run
# ─────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
