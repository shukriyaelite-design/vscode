from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import base64
import time
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("SHUKRIYA_DB", ROOT / "shukriya.db"))
PRIVATE_STORAGE = Path(os.environ.get("SHUKRIYA_PRIVATE_STORAGE", ROOT / "private_storage"))
MAX_DOCUMENT_BYTES = 10 * 1024 * 1024
MAX_USERS = int(os.environ.get("SHUKRIYA_MAX_USERS", "5"))
LOGIN_MAX_ATTEMPTS = int(os.environ.get("SHUKRIYA_LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_LOCK_SECONDS = int(os.environ.get("SHUKRIYA_LOGIN_LOCK_SECONDS", "900"))
RATE_LIMIT_COUNT = int(os.environ.get("SHUKRIYA_RATE_LIMIT_COUNT", "60"))
RATE_LIMIT_WINDOW = int(os.environ.get("SHUKRIYA_RATE_LIMIT_WINDOW", "60"))
COOKIE_SECURE = os.environ.get("SHUKRIYA_COOKIE_SECURE", "true").lower() == "true"
SESSIONS: dict[str, int] = {}
CSRF_TOKENS: dict[str, str] = {}
LOGIN_FAILURES: dict[str, tuple[int, float]] = {}
RATE_BUCKETS: dict[str, list[float]] = {}


def connection() -> sqlite3.Connection:
    database = sqlite3.connect(DATABASE)
    database.row_factory = sqlite3.Row
    return database


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
    return f"pbkdf2_sha256$260000${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, rounds, salt_hex, digest_hex = encoded.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds))
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def initialise() -> None:
    PRIVATE_STORAGE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with connection() as database:
        database.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'staff',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY,
                reference TEXT UNIQUE NOT NULL,
                service TEXT NOT NULL,
                applicant_name TEXT NOT NULL,
                mobile TEXT,
                status TEXT NOT NULL,
                notes TEXT DEFAULT '',
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY,
                case_reference TEXT NOT NULL,
                filename TEXT NOT NULL,
                storage_key TEXT NOT NULL,
                review_status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS invoices (
                id INTEGER PRIMARY KEY,
                invoice_number TEXT UNIQUE NOT NULL,
                case_reference TEXT NOT NULL,
                amount_paise INTEGER NOT NULL,
                currency TEXT NOT NULL DEFAULT 'INR',
                status TEXT NOT NULL DEFAULT 'draft',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY,
                actor_email TEXT,
                action TEXT NOT NULL,
                target TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        columns = {row[1] for row in database.execute("PRAGMA table_info(invoices)")}
        if "gst_number" not in columns:
            database.execute("ALTER TABLE invoices ADD COLUMN gst_number TEXT DEFAULT ''")
        if "gst_amount_paise" not in columns:
            database.execute("ALTER TABLE invoices ADD COLUMN gst_amount_paise INTEGER NOT NULL DEFAULT 0")


def seed_admin() -> None:
    email = os.environ.get("SHUKRIYA_ADMIN_EMAIL")
    password = os.environ.get("SHUKRIYA_ADMIN_PASSWORD")
    if not email or not password:
        return
    with connection() as database:
        database.execute(
            "INSERT OR IGNORE INTO users (email, password_hash, role) VALUES (?, ?, 'admin')",
            (email.lower(), hash_password(password)),
        )


def seed_users() -> None:
    raw_users = os.environ.get("SHUKRIYA_USERS_JSON", "[]")
    try:
        users = json.loads(raw_users)
    except json.JSONDecodeError:
        raise ValueError("SHUKRIYA_USERS_JSON must contain valid JSON") from None
    if not isinstance(users, list) or len(users) > MAX_USERS:
        raise ValueError(f"SHUKRIYA_USERS_JSON must contain at most {MAX_USERS} users")
    with connection() as database:
        for user in users:
            email = str(user.get("email", "")).strip().lower()
            password = str(user.get("password", ""))
            role = str(user.get("role", "staff")).strip().lower()
            if email and password and role in {"admin", "manager", "staff"}:
                database.execute("INSERT OR IGNORE INTO users (email, password_hash, role) VALUES (?, ?, ?)", (email, hash_password(password), role))


def body(request: BaseHTTPRequestHandler) -> dict:
    length = int(request.headers.get("Content-Length", "0"))
    if length > 14_000_000:
        raise ValueError("Request body too large")
    raw = request.rfile.read(length)
    return json.loads(raw or b"{}")


def clean_filename(filename: str) -> str:
    name = Path(filename).name.strip()
    if not name or len(name) > 180:
        raise ValueError("A valid filename is required")
    return name


def document_bytes(payload: dict) -> tuple[str, bytes]:
    filename = clean_filename(str(payload.get("filename", "")))
    extension = Path(filename).suffix.lower()
    if extension not in {".pdf", ".jpg", ".jpeg", ".png", ".webp"}:
        raise ValueError("Only PDF, JPG, PNG and WEBP documents are accepted")
    try:
        content = base64.b64decode(str(payload.get("content_base64", "")), validate=True)
    except (ValueError, TypeError):
        raise ValueError("content_base64 must be valid base64") from None
    if not content or len(content) > MAX_DOCUMENT_BYTES:
        raise ValueError("Document must be between 1 byte and 10 MB")
    return filename, content


class API(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def send_json(self, status: int, payload: dict) -> None:
        encoded = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.end_headers()
        self.wfile.write(encoded)

    def client_key(self) -> str:
        return self.headers.get("X-Forwarded-For", self.client_address[0]).split(",", 1)[0].strip()

    def rate_allowed(self) -> bool:
        now = time.time()
        recent = [stamp for stamp in RATE_BUCKETS.get(self.client_key(), []) if now - stamp < RATE_LIMIT_WINDOW]
        if len(recent) >= RATE_LIMIT_COUNT:
            RATE_BUCKETS[self.client_key()] = recent
            self.send_json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "Too many requests"})
            return False
        recent.append(now)
        RATE_BUCKETS[self.client_key()] = recent
        return True

    def current_user(self) -> sqlite3.Row | None:
        token = self.headers.get("Cookie", "").replace("shukriya_session=", "").split(";", 1)[0]
        user_id = SESSIONS.get(token)
        if not user_id:
            return None
        with connection() as database:
            return database.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    def csrf_valid(self) -> bool:
        token = self.headers.get("X-CSRF-Token", "")
        session = self.headers.get("Cookie", "").replace("shukriya_session=", "").split(";", 1)[0]
        return bool(token and hmac.compare_digest(token, CSRF_TOKENS.get(session, "")))

    def require_user(self) -> bool:
        if self.current_user() is None:
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Authentication required"})
            return False
        return True

    def do_GET(self) -> None:
        if not self.rate_allowed():
            return
        path = urlparse(self.path).path
        if path == "/api/health":
            self.send_json(HTTPStatus.OK, {"ok": True, "environment": "development"})
            return
        if path == "/api/me":
            user = self.current_user()
            self.send_json(HTTPStatus.OK, {"authenticated": bool(user), "user": dict(user) if user else None})
            return
        if path == "/api/csrf":
            session = self.headers.get("Cookie", "").replace("shukriya_session=", "").split(";", 1)[0]
            if session not in SESSIONS:
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Authentication required"})
                return
            self.send_json(HTTPStatus.OK, {"csrf_token": CSRF_TOKENS[session]})
            return
        if path == "/api/users":
            user = self.current_user()
            if not user or user["role"] != "admin":
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Admin access required"})
                return
            with connection() as database:
                users = database.execute("SELECT id, email, role, created_at FROM users ORDER BY id").fetchall()
            self.send_json(HTTPStatus.OK, {"users": [dict(item) for item in users], "count": len(users), "max_users": MAX_USERS})
            return
        if path == "/api/cases":
            if not self.require_user():
                return
            with connection() as database:
                cases = database.execute("SELECT * FROM cases ORDER BY updated_at DESC").fetchall()
            self.send_json(HTTPStatus.OK, {"cases": [dict(case) for case in cases]})
            return
        if path == "/api/documents":
            if not self.require_user():
                return
            reference = urlparse(self.path).query
            query_reference = reference.removeprefix("case_reference=") if reference.startswith("case_reference=") else ""
            with connection() as database:
                if query_reference:
                    documents = database.execute("SELECT id, case_reference, filename, review_status, created_at FROM documents WHERE case_reference = ? ORDER BY created_at DESC", (query_reference,)).fetchall()
                else:
                    documents = database.execute("SELECT id, case_reference, filename, review_status, created_at FROM documents ORDER BY created_at DESC").fetchall()
            self.send_json(HTTPStatus.OK, {"documents": [dict(document) for document in documents]})
            return
        if path == "/api/invoices":
            if not self.require_user():
                return
            with connection() as database:
                invoices = database.execute("SELECT id, invoice_number, case_reference, amount_paise, currency, status, created_at FROM invoices ORDER BY created_at DESC").fetchall()
            self.send_json(HTTPStatus.OK, {"invoices": [dict(invoice) for invoice in invoices]})
            return
        self.send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

    def do_POST(self) -> None:
        if not self.rate_allowed():
            return
        path = urlparse(self.path).path
        try:
            payload = body(self)
        except (ValueError, json.JSONDecodeError):
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid JSON request"})
            return
        if path == "/api/login":
            email = str(payload.get("email", "")).strip().lower()
            password = str(payload.get("password", ""))
            attempts, locked_until = LOGIN_FAILURES.get(email, (0, 0))
            if locked_until > time.time():
                self.send_json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "Account temporarily locked"})
                return
            with connection() as database:
                user = database.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if not user or not verify_password(password, user["password_hash"]):
                attempts += 1
                LOGIN_FAILURES[email] = (0, time.time() + LOGIN_LOCK_SECONDS) if attempts >= LOGIN_MAX_ATTEMPTS else (attempts, 0)
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Invalid credentials"})
                return
            LOGIN_FAILURES.pop(email, None)
            token = secrets.token_urlsafe(32)
            SESSIONS[token] = user["id"]
            CSRF_TOKENS[token] = secrets.token_urlsafe(32)
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json")
            secure = "; Secure" if COOKIE_SECURE else ""
            self.send_header("Set-Cookie", f"shukriya_session={token}; HttpOnly; SameSite=Strict{secure}; Path=/")
            self.end_headers()
            self.wfile.write(json.dumps({"authenticated": True, "role": user["role"]}).encode())
            return
        if path == "/api/logout":
            if not self.csrf_valid():
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "CSRF validation failed"})
                return
            token = self.headers.get("Cookie", "").replace("shukriya_session=", "").split(";", 1)[0]
            SESSIONS.pop(token, None)
            CSRF_TOKENS.pop(token, None)
            self.send_json(HTTPStatus.OK, {"authenticated": False})
            return
        if path == "/api/users":
            if not self.csrf_valid():
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "CSRF validation failed"})
                return
            user = self.current_user()
            if not user or user["role"] != "admin":
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Admin access required"})
                return
            email = str(payload.get("email", "")).strip().lower()
            password = str(payload.get("password", ""))
            role = str(payload.get("role", "staff")).strip().lower()
            if not email or len(password) < 12 or role not in {"admin", "manager", "staff"}:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "email, a password of at least 12 characters, and a valid role are required"})
                return
            with connection() as database:
                count = database.execute("SELECT COUNT(*) FROM users").fetchone()[0]
                if count >= MAX_USERS:
                    self.send_json(HTTPStatus.CONFLICT, {"error": f"The CRM user limit of {MAX_USERS} has been reached"})
                    return
                try:
                    database.execute("INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)", (email, hash_password(password), role))
                except sqlite3.IntegrityError:
                    self.send_json(HTTPStatus.CONFLICT, {"error": "A user with that email already exists"})
                    return
            self.send_json(HTTPStatus.CREATED, {"created": True, "email": email, "role": role})
            return
        if path == "/api/cases":
            if not self.csrf_valid():
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "CSRF validation failed"})
                return
            if not self.require_user():
                return
            required = ("reference", "service", "applicant_name", "status")
            if any(not payload.get(field) for field in required):
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "reference, service, applicant_name and status are required"})
                return
            with connection() as database:
                database.execute("INSERT INTO cases (reference, service, applicant_name, mobile, status, notes) VALUES (?, ?, ?, ?, ?, ?)", tuple(payload.get(field, "") for field in ("reference", "service", "applicant_name", "mobile", "status", "notes")))
            self.send_json(HTTPStatus.CREATED, {"created": True, "reference": payload["reference"]})
            return
        if path == "/api/documents":
            if not self.csrf_valid():
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "CSRF validation failed"})
                return
            if not self.require_user():
                return
            try:
                filename, content = document_bytes(payload)
            except ValueError as error:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            case_reference = str(payload.get("case_reference", "")).strip()
            if not case_reference:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "case_reference is required"})
                return
            storage_key = f"{secrets.token_urlsafe(18)}{Path(filename).suffix.lower()}"
            (PRIVATE_STORAGE / storage_key).write_bytes(content)
            with connection() as database:
                database.execute("INSERT INTO documents (case_reference, filename, storage_key) VALUES (?, ?, ?)", (case_reference, filename, storage_key))
            self.send_json(HTTPStatus.CREATED, {"uploaded": True, "case_reference": case_reference, "filename": filename})
            return
        if path == "/api/invoices":
            if not self.csrf_valid():
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "CSRF validation failed"})
                return
            if not self.require_user():
                return
            case_reference = str(payload.get("case_reference", "")).strip()
            amount_paise = int(payload.get("amount_paise", 0))
            if not case_reference or amount_paise <= 0:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "case_reference and a positive amount_paise are required"})
                return
            invoice_number = f"SHK-{secrets.token_hex(4).upper()}"
            with connection() as database:
                database.execute("INSERT INTO invoices (invoice_number, case_reference, amount_paise, currency, status, gst_number, gst_amount_paise) VALUES (?, ?, ?, ?, 'draft', ?, ?)", (invoice_number, case_reference, amount_paise, str(payload.get("currency", "INR")).upper(), str(payload.get("gst_number", "")), int(payload.get("gst_amount_paise", 0))))
            self.send_json(HTTPStatus.CREATED, {"created": True, "invoice_number": invoice_number, "status": "draft"})
            return
        if path == "/api/payments/status":
            if not self.csrf_valid():
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "CSRF validation failed"})
                return
            if not self.require_user():
                return
            invoice_number = str(payload.get("invoice_number", "")).strip()
            status = str(payload.get("status", "")).strip().lower()
            if status not in {"draft", "pending", "paid", "failed", "refunded"} or not invoice_number:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "invoice_number and a valid payment status are required"})
                return
            with connection() as database:
                result = database.execute("UPDATE invoices SET status = ? WHERE invoice_number = ?", (status, invoice_number))
            self.send_json(HTTPStatus.OK, {"updated": result.rowcount == 1, "invoice_number": invoice_number, "status": status, "provider": os.environ.get("SHUKRIYA_PAYMENT_PROVIDER", "unconfigured")})
            return
        if path == "/api/whatsapp/status":
            if not self.csrf_valid():
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "CSRF validation failed"})
                return
            if not self.require_user():
                return
            configured = bool(os.environ.get("WHATSAPP_ACCESS_TOKEN") and os.environ.get("WHATSAPP_PHONE_NUMBER_ID"))
            self.send_json(HTTPStatus.OK, {"configured": configured, "provider": "whatsapp-cloud-api" if configured else "unconfigured", "message": "Configure WhatsApp environment variables before enabling automated messages."})
            return
        if path == "/api/payments/webhook":
            secret = os.environ.get("PAYMENT_WEBHOOK_SECRET", "")
            signature = self.headers.get("X-Payment-Signature", "")
            raw = json.dumps(payload, separators=(",", ":")).encode()
            expected = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest() if secret else ""
            if not secret or not signature or not hmac.compare_digest(signature, expected):
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Invalid webhook signature"})
                return
            self.send_json(HTTPStatus.OK, {"accepted": True, "provider": os.environ.get("SHUKRIYA_PAYMENT_PROVIDER", "unconfigured")})
            return
        self.send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})


if __name__ == "__main__":
    initialise()
    seed_admin()
    seed_users()
    port = int(os.environ.get("PORT", "8010"))
    print(f"Shukriya development API listening on http://127.0.0.1:{port}")
    ThreadingHTTPServer(("127.0.0.1", port), API).serve_forever()
