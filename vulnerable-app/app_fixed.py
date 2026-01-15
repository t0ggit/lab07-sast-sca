from flask import Flask, request, make_response
import sqlite3
import os
import subprocess
import json  # заменяет pickle
import re   # для валидации
import ast   # для безопасного eval
from markupsafe import escape  # для XSS protection
import logging

app = Flask(__name__)

# ИСПРАВЛЕНИЕ: Используем переменные окружения вместо hardcoded credentials
DB_USER = os.environ.get("DB_USER", "admin")
DB_PASSWORD = os.environ.get("DB_PASSWORD")  # без значения по умолчанию для безопасности
DB_PATH = "app.db"

# ИСПРАВЛЕНИЕ: DEBUG отключен в продакшене
app.config["DEBUG"] = False

# ИСПРАВЛЕНИЕ: Logging только WARNING и выше, чтобы не логировать чувствительные данные
logging.basicConfig(level=logging.WARNING)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    return conn


@app.route("/")
def index():
    # ИСПРАВЛЕНИЕ: не раскрываем версию приложения
    return "Application is running"


@app.route("/user")
def get_user():
    username = request.args.get("name", "")
    conn = get_db()
    cur = conn.cursor()

    # ИСПРАВЛЕНИЕ: Параметризованный запрос вместо f-string (защита от SQL Injection)
    query = "SELECT id, name, email FROM users WHERE name = ?"
    app.logger.info("Executing query for user lookup")
    rows = cur.execute(query, (username,)).fetchall()
    conn.close()
    return {"result": rows}


@app.route("/search")
def search():
    q = request.args.get("q", "")

    # ИСПРАВЛЕНИЕ: escape() для защиты от XSS
    html = f"<h1>Results for: {escape(q)}</h1>"
    return make_response(html, 200)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")

    # ИСПРАВЛЕНИЕ: Валидация host (только alphanumeric, точки, дефисы)
    if not re.match(r'^[\w\.\-]+$', host):
        return "Invalid host format", 400

    # ИСПРАВЛЕНИЕ: subprocess.run с массивом аргументов (защита от Command Injection)
    try:
        result = subprocess.run(
            ['ping', '-c', '1', host],
            capture_output=True,
            text=True,
            timeout=5,
            check=False
        )
        return f"Pinged {host}: {result.returncode == 0}"
    except subprocess.TimeoutExpired:
        return f"Ping timeout for {host}", 408
    except Exception as e:
        app.logger.error(f"Ping error: {type(e).__name__}")
        return "Ping failed", 500


@app.route("/backup")
def backup():
    target = request.args.get("target", "/tmp/backup.sql")

    # ИСПРАВЛЕНИЕ: Валидация пути (только /tmp/ директория)
    if not target.startswith('/tmp/'):
        return "Invalid backup path", 400

    # ИСПРАВЛЕНИЕ: subprocess.run с массивом аргументов, без sh -c
    try:
        result = subprocess.run(
            ['pg_dump', 'mydb', '-f', target],
            capture_output=True,
            timeout=30,
            check=False
        )
        return f"Backup to {target} completed: {result.returncode == 0}"
    except Exception as e:
        app.logger.error(f"Backup error: {type(e).__name__}")
        return f"Backup failed", 500


@app.route("/read")
def read_file():
    path = request.args.get("path", "")

    # ИСПРАВЛЕНИЕ: Защита от Path Traversal (LFI)
    safe_base = '/app/data/'

    try:
        # Проверяем, что путь находится внутри safe_base
        full_path = os.path.join(safe_base, path)
        real_path = os.path.realpath(full_path)

        if not real_path.startswith(os.path.realpath(safe_base)):
            return "Access denied: path traversal detected", 403

        with open(real_path, "r") as f:
            data = f.read()
        return f"<pre>{escape(data)}</pre>"
    except FileNotFoundError:
        return "File not found", 404
    except Exception as e:
        app.logger.error(f"File read error: {type(e).__name__}")
        return "Error reading file", 500


@app.route("/load")
def load():
    data = request.args.get("data", "")

    # ИСПРАВЛЕНИЕ: JSON вместо pickle (защита от deserialization RCE)
    try:
        obj = json.loads(data)
        return f"Loaded object: {obj}"
    except json.JSONDecodeError:
        return "Invalid JSON format", 400
    except Exception as e:
        app.logger.error(f"Load error: {type(e).__name__}")
        return f"Error loading data", 500


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "1+1")

    # ИСПРАВЛЕНИЕ: ast.literal_eval вместо eval (защита от code injection)
    # Поддерживает только literals: strings, bytes, numbers, tuples, lists, dicts, sets, booleans, None
    try:
        result = ast.literal_eval(expr)
        return str(result)
    except (ValueError, SyntaxError):
        return "Invalid expression: only literals allowed", 400
    except Exception as e:
        app.logger.error(f"Calc error: {type(e).__name__}")
        return "Calculation error", 500


# ИСПРАВЛЕНИЕ: Debug endpoint удален (не раскрываем env и headers)
# @app.route("/debug") - REMOVED FOR SECURITY

if __name__ == "__main__":
    # ИСПРАВЛЕНИЕ: host="0.0.0.0" оставлен для работы в Docker
    # В продакшене использовать за reverse proxy (nginx/Traefik) с HTTPS
    app.run(host="0.0.0.0", port=8080)
