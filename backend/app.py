from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import base64
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("SHUKRIYA_DB", ROOT / "shukriya.db"))
PRIVATE_STORAGE = Path(os.environ.get("SHUKRIYA_PRIVATE_STORAGE", ROOT / "private_storage"))
MAX_DOCUMENT_BYTES = 10 * 1024 * 1024
SESSIONS: dict[str, int] = {}


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
            """
        )


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
        self.end_headers()
        self.wfile.write(encoded)

    def current_user(self) -> sqlite3.Row | None:
        token = self.headers.get("Cookie", "").replace("shukriya_session=", "").split(";", 1)[0]
        user_id = SESSIONS.get(token)
        if not user_id:
            return None
        with connection() as database:
            return database.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    def require_user(self) -> bool:
        if self.current_user() is None:
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Authentication required"})
            return False
        return True

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/health":
            self.send_json(HTTPStatus.OK, {"ok": True, "environment": "development"})
            return
        if path == "/api/me":
            user = self.current_user()
            self.send_json(HTTPStatus.OK, {"authenticated": bool(user), "user": dict(user) if user else None})
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
        path = urlparse(self.path).path
        try:
            payload = body(self)
        except (ValueError, json.JSONDecodeError):
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid JSON request"})
            return
        if path == "/api/login":
            email = str(payload.get("email", "")).strip().lower()
            password = str(payload.get("password", ""))
            with connection() as database:
                user = database.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if not user or not verify_password(password, user["password_hash"]):
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Invalid credentials"})
                return
            token = secrets.token_urlsafe(32)
            SESSIONS[token] = user["id"]
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", f"shukriya_session={token}; HttpOnly; SameSite=Strict; Path=/")
            self.end_headers()
            self.wfile.write(json.dumps({"authenticated": True, "role": user["role"]}).encode())
            return
        if path == "/api/logout":
            token = self.headers.get("Cookie", "").replace("shukriya_session=", "").split(";", 1)[0]
            SESSIONS.pop(token, None)
            self.send_json(HTTPStatus.OK, {"authenticated": False})
            return
        if path == "/api/cases":
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
            if not self.require_user():
                return
            case_reference = str(payload.get("case_reference", "")).strip()
            amount_paise = int(payload.get("amount_paise", 0))
            if not case_reference or amount_paise <= 0:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "case_reference and a positive amount_paise are required"})
                return
            invoice_number = f"SHK-{secrets.token_hex(4).upper()}"
            with connection() as database:
                database.execute("INSERT INTO invoices (invoice_number, case_reference, amount_paise, currency, status) VALUES (?, ?, ?, ?, 'draft')", (invoice_number, case_reference, amount_paise, str(payload.get("currency", "INR")).upper()))
            self.send_json(HTTPStatus.CREATED, {"created": True, "invoice_number": invoice_number, "status": "draft"})
            return
        if path == "/api/payments/status":
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
            if not self.require_user():
                return
            configured = bool(os.environ.get("WHATSAPP_ACCESS_TOKEN") and os.environ.get("WHATSAPP_PHONE_NUMBER_ID"))
            self.send_json(HTTPStatus.OK, {"configured": configured, "provider": "whatsapp-cloud-api" if configured else "unconfigured", "message": "Configure WhatsApp environment variables before enabling automated messages."})
            return
        self.send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})


if __name__ == "__main__":
    initialise()
    seed_admin()
    port = int(os.environ.get("PORT", "8010"))
    print(f"Shukriya development API listening on http://127.0.0.1:{port}")
    ThreadingHTTPServer(("127.0.0.1", port), API).serve_forever()
