import os
import psycopg2
import bcrypt
import anthropic
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


# ─────────────────────────────────────────────
# Serve frontend
# ─────────────────────────────────────────────
@app.route("/")
def index():
    return app.send_static_file("index.html")


# ─────────────────────────────────────────────
# POST /api/register
# Body: { "username": "...", "password": "..." }
# ─────────────────────────────────────────────
@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
            (username, hashed)
        )
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"message": "User created"}), 201
    except psycopg2.errors.UniqueViolation:
        return jsonify({"error": "Username already taken"}), 409
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
            "SELECT id, password_hash FROM users WHERE username = %s",
            (username,)
        )
        row = cur.fetchone()
        cur.close()
        conn.close()

        if row is None:
            return jsonify({"error": "Invalid credentials"}), 401

        user_id, stored_hash = row
        if not bcrypt.checkpw(password.encode(), stored_hash.encode()):
            return jsonify({"error": "Invalid credentials"}), 401

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

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key or api_key == "your-anthropic-api-key-here":
        return jsonify({"reply": "AI coach is not configured yet. Add your ANTHROPIC_API_KEY to the .env file."}), 200

    try:
        client = anthropic.Anthropic(api_key=api_key)
        message = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=512,
            system=(
                "You are StudyCoach, a friendly AI assistant for students. "
                "Give concise, practical study advice. "
                "Focus on study techniques, time management, and motivation. "
                "Keep responses under 150 words."
            ),
            messages=[{"role": "user", "content": user_message}]
        )
        reply = message.content[0].text
        return jsonify({"reply": reply}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# Run
# ─────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
