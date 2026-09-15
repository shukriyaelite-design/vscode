from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import base64
import urllib.request
import time
import urllib.parse
import shutil
import subprocess
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("SHUKRIYA_DB", ROOT / "shukriya.db"))
PRIVATE_STORAGE = Path(os.environ.get("SHUKRIYA_PRIVATE_STORAGE", ROOT / "private_storage"))
QUARANTINE_STORAGE = Path(os.environ.get("SHUKRIYA_QUARANTINE_STORAGE", ROOT / "quarantine_storage"))
MAX_DOCUMENT_BYTES = 10 * 1024 * 1024
MAX_USERS = int(os.environ.get("SHUKRIYA_MAX_USERS", "5"))
LOGIN_MAX_ATTEMPTS = int(os.environ.get("SHUKRIYA_LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_LOCK_SECONDS = int(os.environ.get("SHUKRIYA_LOGIN_LOCK_SECONDS", "900"))
RATE_LIMIT_COUNT = int(os.environ.get("SHUKRIYA_RATE_LIMIT_COUNT", "60"))
RATE_LIMIT_WINDOW = int(os.environ.get("SHUKRIYA_RATE_LIMIT_WINDOW", "60"))
COOKIE_SECURE = os.environ.get("SHUKRIYA_COOKIE_SECURE", "true").lower() == "true"
ENVIRONMENT = os.environ.get("SHUKRIYA_ENVIRONMENT", "development")
SESSIONS: dict[str, int] = {}
CSRF_TOKENS: dict[str, str] = {}
LOGIN_FAILURES: dict[str, tuple[int, float]] = {}
RATE_BUCKETS: dict[str, list[float]] = {}
DOWNLOAD_TOKENS: dict[str, tuple[int, float]] = {}


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
    QUARANTINE_STORAGE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with connection() as database:
        database.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'staff',
                status TEXT NOT NULL DEFAULT 'active',
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
                agency_id INTEGER,
                filename TEXT NOT NULL,
                storage_key TEXT NOT NULL,
                review_status TEXT NOT NULL DEFAULT 'pending',
                scan_status TEXT NOT NULL DEFAULT 'quarantine',
                deleted_at TEXT DEFAULT '',
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
            CREATE TABLE IF NOT EXISTS agencies (
                id INTEGER PRIMARY KEY,
                legal_name TEXT NOT NULL,
                business_email TEXT UNIQUE NOT NULL,
                mobile TEXT NOT NULL,
                gst_number TEXT DEFAULT '',
                status TEXT NOT NULL DEFAULT 'pending',
                credit_limit_paise INTEGER NOT NULL DEFAULT 0,
                wallet_paise INTEGER NOT NULL DEFAULT 0,
                pricing_json TEXT NOT NULL DEFAULT '{}',
                approved_by TEXT DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS agency_members (
                user_id INTEGER PRIMARY KEY,
                agency_id INTEGER NOT NULL,
                agency_role TEXT NOT NULL DEFAULT 'owner'
            );
            CREATE TABLE IF NOT EXISTS agency_invitations (
                id INTEGER PRIMARY KEY,
                agency_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'agent_staff',
                token_hash TEXT UNIQUE NOT NULL,
                expires_at REAL NOT NULL,
                accepted_at TEXT DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS agency_applications (
                id INTEGER PRIMARY KEY,
                reference TEXT UNIQUE NOT NULL,
                agency_id INTEGER NOT NULL,
                service TEXT NOT NULL,
                passenger_name TEXT NOT NULL,
                passenger_count INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL DEFAULT 'submitted',
                notes TEXT DEFAULT '',
                assigned_to TEXT DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY,
                actor_email TEXT,
                action TEXT NOT NULL,
                target TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS customers (
                id INTEGER PRIMARY KEY,
                full_name TEXT NOT NULL,
                mobile TEXT NOT NULL,
                email TEXT DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS followups (
                id INTEGER PRIMARY KEY,
                case_reference TEXT NOT NULL,
                due_at TEXT NOT NULL,
                note TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                assigned_to TEXT DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS whatsapp_messages (
                id INTEGER PRIMARY KEY,
                mobile TEXT NOT NULL,
                template_name TEXT NOT NULL,
                body TEXT DEFAULT '',
                status TEXT NOT NULL DEFAULT 'queued',
                provider_message_id TEXT DEFAULT '',
                error TEXT DEFAULT '',
                attempts INTEGER NOT NULL DEFAULT 0,
                consent_at TEXT DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        columns = {row[1] for row in database.execute("PRAGMA table_info(invoices)")}
        if "gst_number" not in columns:
            database.execute("ALTER TABLE invoices ADD COLUMN gst_number TEXT DEFAULT ''")
        if "gst_amount_paise" not in columns:
            database.execute("ALTER TABLE invoices ADD COLUMN gst_amount_paise INTEGER NOT NULL DEFAULT 0")
        document_columns = {row[1] for row in database.execute("PRAGMA table_info(documents)")}
        if "agency_id" not in document_columns:
            database.execute("ALTER TABLE documents ADD COLUMN agency_id INTEGER")
        if "scan_status" not in document_columns:
            database.execute("ALTER TABLE documents ADD COLUMN scan_status TEXT NOT NULL DEFAULT 'quarantine'")
        if "deleted_at" not in document_columns:
            database.execute("ALTER TABLE documents ADD COLUMN deleted_at TEXT DEFAULT ''")
        user_columns = {row[1] for row in database.execute("PRAGMA table_info(users)")}
        if "status" not in user_columns:
            database.execute("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")


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
            if email and password and role in {"admin", "manager", "staff", "agent_owner", "agent_staff", "applicant"}:
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
    if filename.count(".") != 1:
        raise ValueError("Double extensions are not accepted")
    extension = Path(filename).suffix.lower()
    if extension not in {".pdf", ".jpg", ".jpeg", ".png", ".webp"}:
        raise ValueError("Only PDF, JPG, PNG and WEBP documents are accepted")
    try:
        content = base64.b64decode(str(payload.get("content_base64", "")), validate=True)
    except (ValueError, TypeError):
        raise ValueError("content_base64 must be valid base64") from None
    if not content or len(content) > MAX_DOCUMENT_BYTES:
        raise ValueError("Document must be between 1 byte and 10 MB")
    signatures = {".pdf": content.startswith(b"%PDF-"), ".jpg": content.startswith(b"\xff\xd8\xff"), ".jpeg": content.startswith(b"\xff\xd8\xff"), ".png": content.startswith(b"\x89PNG\r\n\x1a\n"), ".webp": content.startswith(b"RIFF") and content[8:12] == b"WEBP"}
    if not signatures[extension] or b"<svg" in content[:2048].lower():
        raise ValueError("File content does not match the allowed document type")
    return filename, content


def scan_file(path: Path) -> str:
    scanner = shutil.which("clamscan")
    if not scanner:
        return "quarantine"
    result = subprocess.run([scanner, "--no-summary", str(path)], capture_output=True, timeout=60, check=False)
    return "clean" if result.returncode == 0 else "infected"


def audit(actor_email: str, action: str, target: str = "") -> None:
    with connection() as database:
        database.execute("INSERT INTO audit_log (actor_email, action, target) VALUES (?, ?, ?)", (actor_email, action, target))


SITE_CONTEXT = """You are Shukriya Visa Services assistant. Answer only from this context and be concise.
Shukriya has supported visa and documentation enquiries from Mumbai since 1977.
Services: Saudi Employment Visa, Wakala support, Musaned services, Saudi Umrah Visa guidance, Kuwait Visa Services, Saudi visa guidance, document attestation, translation, application tracking and invoices.
Wakala and Musaned support covers document guidance, employer coordination and submission preparation. Shukriya Travels Wakala details must be confirmed before use.
Visa approval, processing time and entry decisions are made only by competent authorities. Never promise approval or invent requirements, prices, case statuses, legal advice or payment instructions.
For a personal case, ask the visitor to use the public tracking page with their reference and registered mobile, or contact contact@shukriya.net / +91 70397 81830. Never request passwords, full passport numbers or payment card details in chat.
"""


def model_reply(message: str) -> dict:
    api_key = os.environ.get("AI_API_KEY")
    if not api_key:
        return {"configured": False, "reply": "AI chat is not configured yet. Please contact Shukriya at contact@shukriya.net or WhatsApp +91 70397 81830."}
    endpoint = os.environ.get("AI_API_URL", "https://api.openai.com/v1/chat/completions")
    model = os.environ.get("AI_MODEL", "gpt-4o-mini")
    request_body = json.dumps({"model": model, "temperature": 0.2, "messages": [{"role": "system", "content": SITE_CONTEXT}, {"role": "user", "content": message[:4000]}]}).encode()
    request = urllib.request.Request(endpoint, data=request_body, headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            result = json.loads(response.read())
        reply = result["choices"][0]["message"]["content"]
        return {"configured": True, "reply": str(reply)}
    except (OSError, KeyError, IndexError, TypeError, json.JSONDecodeError):
        return {"configured": True, "reply": "The AI assistant is temporarily unavailable. Please contact contact@shukriya.net or WhatsApp +91 70397 81830."}


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
            return database.execute("SELECT * FROM users WHERE id = ? AND status = 'active'", (user_id,)).fetchone()

    def csrf_valid(self) -> bool:
        token = self.headers.get("X-CSRF-Token", "")
        session = self.headers.get("Cookie", "").replace("shukriya_session=", "").split(";", 1)[0]
        return bool(token and hmac.compare_digest(token, CSRF_TOKENS.get(session, "")))

    def require_user(self) -> bool:
        if self.current_user() is None:
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Authentication required"})
            return False
        return True

    def agency_for_user(self) -> sqlite3.Row | None:
        user = self.current_user()
        if not user:
            return None
        with connection() as database:
            return database.execute("SELECT a.*, am.agency_role FROM agencies a JOIN agency_members am ON am.agency_id = a.id WHERE am.user_id = ?", (user["id"],)).fetchone()

    def authorized_document(self, document_id: int) -> sqlite3.Row | None:
        user = self.current_user()
        if not user:
            return None
        with connection() as database:
            document = database.execute("SELECT * FROM documents WHERE id = ? AND deleted_at = ''", (document_id,)).fetchone()
        if not document:
            return None
        if user["role"] in {"admin", "manager", "staff"}:
            return document
        agency = self.agency_for_user()
        if user["role"] in {"agent_owner", "agent_staff"} and agency and agency["status"] == "approved" and document["agency_id"] == agency["id"]:
            return document
        return None

    def do_GET(self) -> None:
        if not self.rate_allowed():
            return
        parsed = urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        if path == "/api/health":
            self.send_json(HTTPStatus.OK, {"ok": True, "environment": ENVIRONMENT})
            return
        if path == "/api/public/track":
            reference = query.get("reference", [""])[0].strip()
            mobile = query.get("mobile", [""])[0].strip()
            if len(reference) < 5 or len(mobile) < 8:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "A valid reference and registered mobile are required"})
                return
            with connection() as database:
                case = database.execute("SELECT reference, service, status, updated_at FROM cases WHERE reference = ? AND mobile = ?", (reference, mobile)).fetchone()
            if not case:
                self.send_json(HTTPStatus.NOT_FOUND, {"error": "No application matched those details"})
                return
            self.send_json(HTTPStatus.OK, {"application": dict(case)})
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
                users = database.execute("SELECT id, email, role, status, created_at FROM users ORDER BY id").fetchall()
            self.send_json(HTTPStatus.OK, {"users": [dict(item) for item in users], "count": len(users), "max_users": MAX_USERS})
            return
        if path == "/api/audit":
            user = self.current_user()
            if not user or user["role"] != "admin":
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Admin access required"})
                return
            with connection() as database:
                events = database.execute("SELECT actor_email, action, target, created_at FROM audit_log ORDER BY id DESC LIMIT 200").fetchall()
            self.send_json(HTTPStatus.OK, {"events": [dict(event) for event in events]})
            return
        if path == "/api/agencies":
            user = self.current_user()
            if not user or user["role"] not in {"admin", "manager"}:
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Manager access required"})
                return
            with connection() as database:
                agencies = database.execute("SELECT id, legal_name, business_email, mobile, gst_number, status, credit_limit_paise, wallet_paise, approved_by, created_at FROM agencies ORDER BY created_at DESC").fetchall()
            self.send_json(HTTPStatus.OK, {"agencies": [dict(item) for item in agencies]})
            return
        if path == "/api/agency/me":
            if not self.require_user():
                return
            agency = self.agency_for_user()
            self.send_json(HTTPStatus.OK, {"agency": dict(agency) if agency else None})
            return
        if path == "/api/agency/applications":
            agency = self.agency_for_user()
            if not agency or agency["status"] != "approved":
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Approved agency access required"})
                return
            with connection() as database:
                applications = database.execute("SELECT * FROM agency_applications WHERE agency_id = ? ORDER BY updated_at DESC", (agency["id"],)).fetchall()
            self.send_json(HTTPStatus.OK, {"applications": [dict(item) for item in applications]})
            return
        if path == "/api/cases":
            if not self.require_user():
                return
            with connection() as database:
                cases = database.execute("SELECT * FROM cases ORDER BY updated_at DESC").fetchall()
            self.send_json(HTTPStatus.OK, {"cases": [dict(case) for case in cases]})
            return
        if path == "/api/customers":
            user = self.current_user()
            if not user or user["role"] not in {"admin", "manager", "staff"}:
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Staff access required"})
                return
            with connection() as database:
                customers = database.execute("SELECT id, full_name, mobile, email, created_at FROM customers ORDER BY created_at DESC").fetchall()
            self.send_json(HTTPStatus.OK, {"customers": [dict(customer) for customer in customers]})
            return
        if path == "/api/followups":
            user = self.current_user()
            if not user or user["role"] not in {"admin", "manager", "staff"}:
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Staff access required"})
                return
            with connection() as database:
                followups = database.execute("SELECT * FROM followups WHERE status != 'completed' ORDER BY due_at ASC").fetchall()
            self.send_json(HTTPStatus.OK, {"followups": [dict(followup) for followup in followups]})
            return
        if path == "/api/whatsapp/messages":
            user = self.current_user()
            if not user or user["role"] != "admin":
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Admin access required"})
                return
            with connection() as database:
                messages = database.execute("SELECT id, mobile, template_name, status, provider_message_id, error, attempts, consent_at, created_at FROM whatsapp_messages ORDER BY created_at DESC LIMIT 200").fetchall()
            self.send_json(HTTPStatus.OK, {"messages": [dict(message) for message in messages]})
            return
        if path == "/api/whatsapp/webhook":
            verify_token = os.environ.get("WHATSAPP_VERIFY_TOKEN", "")
            if query.get("hub.verify_token", [""])[0] != verify_token or not verify_token:
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Webhook verification failed"})
                return
            challenge = query.get("hub.challenge", [""])[0]
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(challenge.encode())
            return
        if path == "/api/documents":
            if not self.require_user():
                return
            user = self.current_user()
            reference = urlparse(self.path).query
            query_reference = reference.removeprefix("case_reference=") if reference.startswith("case_reference=") else ""
            with connection() as database:
                agency = self.agency_for_user() if user["role"] in {"agent_owner", "agent_staff"} else None
                if user["role"] in {"agent_owner", "agent_staff"} and not agency:
                    self.send_json(HTTPStatus.FORBIDDEN, {"error": "Agency membership required"})
                    return
                if query_reference and agency:
                    documents = database.execute("SELECT id, case_reference, filename, review_status, scan_status, created_at FROM documents WHERE case_reference = ? AND agency_id = ? AND deleted_at = '' ORDER BY created_at DESC", (query_reference, agency["id"])).fetchall()
                elif query_reference:
                    documents = database.execute("SELECT id, case_reference, filename, review_status, scan_status, created_at FROM documents WHERE case_reference = ? AND deleted_at = '' ORDER BY created_at DESC", (query_reference,)).fetchall()
                elif agency:
                    documents = database.execute("SELECT id, case_reference, filename, review_status, scan_status, created_at FROM documents WHERE agency_id = ? AND deleted_at = '' ORDER BY created_at DESC", (agency["id"],)).fetchall()
                else:
                    documents = database.execute("SELECT id, case_reference, filename, review_status, scan_status, created_at FROM documents WHERE deleted_at = '' ORDER BY created_at DESC").fetchall()
            self.send_json(HTTPStatus.OK, {"documents": [dict(document) for document in documents]})
            return
        if path == "/api/documents/download":
            token = urlparse(self.path).query.removeprefix("token=")
            token_data = DOWNLOAD_TOKENS.pop(token, None)
            if not token_data or token_data[1] < time.time():
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Download link expired or invalid"})
                return
            document = self.authorized_document(token_data[0])
            if not document or document["scan_status"] != "clean" or document["review_status"] == "rejected":
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Document is not available"})
                return
            file_path = PRIVATE_STORAGE / document["storage_key"]
            if not file_path.is_file():
                self.send_json(HTTPStatus.NOT_FOUND, {"error": "Document file not found"})
                return
            content = file_path.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f"attachment; filename*=UTF-8''{urllib.parse.quote(document['filename'])}")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return
        if path == "/api/invoices":
            if not self.require_user():
                return
            with connection() as database:
                invoices = database.execute("SELECT id, invoice_number, case_reference, amount_paise, currency, status, created_at FROM invoices ORDER BY created_at DESC").fetchall()
            self.send_json(HTTPStatus.OK, {"invoices": [dict(invoice) for invoice in invoices]})
            return
        if path == "/api/invoice-profile":
            if not self.require_user():
                return
            self.send_json(HTTPStatus.OK, {"company_name": os.environ.get("INVOICE_COMPANY_NAME", "Shukriya Travels"), "address": os.environ.get("INVOICE_ADDRESS", "Ali Raza Castle, 486/488, Sir J. J. Road, Byculla, Mumbai - 400008"), "gstin": os.environ.get("INVOICE_GSTIN", "27AACPK5284E1ZR"), "pan": os.environ.get("INVOICE_PAN", "AACPK5284E"), "state_code": os.environ.get("INVOICE_STATE_CODE", "27"), "phone": os.environ.get("INVOICE_PHONE", ""), "email": os.environ.get("INVOICE_EMAIL", ""), "bank_details": os.environ.get("INVOICE_BANK_DETAILS", "")})
            return
        if path == "/api/chat":
            try:
                payload = body(self)
                message = str(payload.get("message", "")).strip()
                if not message:
                    raise ValueError("message is required")
                self.send_json(HTTPStatus.OK, model_reply(message))
            except (ValueError, json.JSONDecodeError):
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "A message is required"})
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
        if path == "/api/agents/register":
            legal_name = str(payload.get("agency_name", "")).strip()
            email = str(payload.get("email", "")).strip().lower()
            mobile = str(payload.get("mobile", "")).strip()
            password = str(payload.get("password", ""))
            if not legal_name or not email or not mobile or len(password) < 12:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "agency_name, email, mobile and a password of at least 12 characters are required"})
                return
            try:
                with connection() as database:
                    duplicate = database.execute("SELECT id FROM agencies WHERE business_email = ? OR mobile = ? OR (? <> '' AND gst_number = ?)", (email, mobile, str(payload.get("gst_number", "")).strip(), str(payload.get("gst_number", "")).strip())).fetchone()
                    if duplicate:
                        self.send_json(HTTPStatus.CONFLICT, {"error": "An agency with that email, mobile or GST number already exists"})
                        return
                    agency = database.execute("INSERT INTO agencies (legal_name, business_email, mobile, gst_number) VALUES (?, ?, ?, ?) RETURNING id", (legal_name, email, mobile, str(payload.get("gst_number", "")))).fetchone()
                    user = database.execute("INSERT INTO users (email, password_hash, role) VALUES (?, ?, 'agent_owner') RETURNING id", (email, hash_password(password))).fetchone()
                    database.execute("INSERT INTO agency_members (user_id, agency_id, agency_role) VALUES (?, ?, 'owner')", (user["id"], agency["id"]))
                audit(email, "agency.registered", str(agency["id"]))
            except sqlite3.IntegrityError:
                self.send_json(HTTPStatus.CONFLICT, {"error": "An agency or account with that email already exists"})
                return
            self.send_json(HTTPStatus.CREATED, {"registered": True, "agency_id": agency["id"], "status": "pending"})
            return
        if path == "/api/customers":
            if not self.csrf_valid():
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "CSRF validation failed"})
                return
            user = self.current_user()
            if not user or user["role"] not in {"admin", "manager", "staff"}:
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Staff access required"})
                return
            full_name = str(payload.get("full_name", "")).strip()
            mobile = str(payload.get("mobile", "")).strip()
            if not full_name or len(mobile) < 8:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "full_name and a valid mobile are required"})
                return
            with connection() as database:
                database.execute("INSERT INTO customers (full_name, mobile, email) VALUES (?, ?, ?)", (full_name, mobile, str(payload.get("email", "")).strip().lower()))
            audit(user["email"], "customer.created", mobile)
            self.send_json(HTTPStatus.CREATED, {"created": True})
            return
        if path == "/api/followups":
            if not self.csrf_valid():
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "CSRF validation failed"})
                return
            user = self.current_user()
            if not user or user["role"] not in {"admin", "manager", "staff"}:
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Staff access required"})
                return
            case_reference = str(payload.get("case_reference", "")).strip()
            due_at = str(payload.get("due_at", "")).strip()
            note = str(payload.get("note", "")).strip()
            if not case_reference or not due_at or not note:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "case_reference, due_at and note are required"})
                return
            with connection() as database:
                database.execute("INSERT INTO followups (case_reference, due_at, note, assigned_to) VALUES (?, ?, ?, ?)", (case_reference, due_at, note, str(payload.get("assigned_to", "")).strip()))
            audit(user["email"], "followup.created", case_reference)
            self.send_json(HTTPStatus.CREATED, {"created": True})
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
            audit(user["email"], "user.created", email)
            self.send_json(HTTPStatus.CREATED, {"created": True, "email": email, "role": role})
            return
        if path == "/api/users/status":
            if not self.csrf_valid():
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "CSRF validation failed"})
                return
            user = self.current_user()
            if not user or user["role"] != "admin":
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Admin access required"})
                return
            user_id = int(payload.get("user_id", 0))
            status = str(payload.get("status", "")).lower()
            if user_id <= 0 or status not in {"active", "suspended"}:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "user_id and active/suspended status are required"})
                return
            with connection() as database:
                result = database.execute("UPDATE users SET status = ? WHERE id = ?", (status, user_id))
            audit(user["email"], f"user.{status}", str(user_id))
            self.send_json(HTTPStatus.OK, {"updated": result.rowcount == 1, "user_id": user_id, "status": status})
            return
        if path == "/api/agencies/approve":
            if not self.csrf_valid():
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "CSRF validation failed"})
                return
            user = self.current_user()
            if not user or user["role"] != "admin":
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Admin access required"})
                return
            agency_id = int(payload.get("agency_id", 0))
            status = str(payload.get("status", "approved")).lower()
            if status not in {"approved", "rejected", "pending"} or agency_id <= 0:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "agency_id and valid status are required"})
                return
            with connection() as database:
                result = database.execute("UPDATE agencies SET status = ?, approved_by = ? WHERE id = ?", (status, user["email"], agency_id))
            audit(user["email"], f"agency.{status}", str(agency_id))
            self.send_json(HTTPStatus.OK, {"updated": result.rowcount == 1, "agency_id": agency_id, "status": status})
            return
        if path == "/api/agency/invitations":
            if not self.csrf_valid():
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "CSRF validation failed"})
                return
            user = self.current_user()
            agency = self.agency_for_user()
            if not user or not agency or agency["status"] != "approved" or user["role"] not in {"agent_owner", "admin"}:
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Agency owner access required"})
                return
            email = str(payload.get("email", "")).strip().lower()
            if "@" not in email:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "A valid staff email is required"})
                return
            token = secrets.token_urlsafe(32)
            with connection() as database:
                database.execute("INSERT INTO agency_invitations (agency_id, email, token_hash, expires_at) VALUES (?, ?, ?, ?)", (agency["id"], email, hash_password(token), time.time() + 604800))
            audit(user["email"], "agency.staff_invited", email)
            response = {"created": True, "email": email, "expires_in_days": 7}
            if os.environ.get("SHUKRIYA_DEVELOPMENT_MODE", "false").lower() == "true":
                response["development_invitation_token"] = token
            self.send_json(HTTPStatus.CREATED, response)
            return
        if path == "/api/agency/invitations/accept":
            email = str(payload.get("email", "")).strip().lower()
            token = str(payload.get("token", ""))
            password = str(payload.get("password", ""))
            if not email or len(password) < 12 or not token:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "email, invitation token and a password of at least 12 characters are required"})
                return
            with connection() as database:
                invitation = database.execute("SELECT * FROM agency_invitations WHERE email = ? AND accepted_at = '' ORDER BY id DESC", (email,)).fetchone()
                if not invitation or invitation["expires_at"] < time.time() or not verify_password(token, invitation["token_hash"]):
                    self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid or expired invitation"})
                    return
                try:
                    user = database.execute("INSERT INTO users (email, password_hash, role) VALUES (?, ?, 'agent_staff') RETURNING id", (email, hash_password(password))).fetchone()
                    database.execute("INSERT INTO agency_members (user_id, agency_id, agency_role) VALUES (?, ?, 'staff')", (user["id"], invitation["agency_id"]))
                    database.execute("UPDATE agency_invitations SET accepted_at = CURRENT_TIMESTAMP WHERE id = ?", (invitation["id"],))
                except sqlite3.IntegrityError:
                    self.send_json(HTTPStatus.CONFLICT, {"error": "A user with that email already exists"})
                    return
            audit(email, "agency.staff_joined", str(invitation["agency_id"]))
            self.send_json(HTTPStatus.CREATED, {"accepted": True, "role": "agent_staff"})
            return
        if path == "/api/agency/applications":
            if not self.csrf_valid():
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "CSRF validation failed"})
                return
            agency = self.agency_for_user()
            if not agency or agency["status"] != "approved":
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Approved agency access required"})
                return
            required = ("service", "passenger_name")
            if any(not payload.get(field) for field in required):
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "service and passenger_name are required"})
                return
            reference = f"B2B-{secrets.token_hex(4).upper()}"
            with connection() as database:
                database.execute("INSERT INTO agency_applications (reference, agency_id, service, passenger_name, passenger_count, notes) VALUES (?, ?, ?, ?, ?, ?)", (reference, agency["id"], payload["service"], payload["passenger_name"], max(1, int(payload.get("passenger_count", 1))), str(payload.get("notes", ""))))
            audit(self.current_user()["email"], "agency.application_created", reference)
            self.send_json(HTTPStatus.CREATED, {"created": True, "reference": reference, "agency_id": agency["id"]})
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
            user = self.current_user()
            agency = self.agency_for_user() if user["role"] in {"agent_owner", "agent_staff"} else None
            if user["role"] in {"agent_owner", "agent_staff"}:
                if not agency or agency["status"] != "approved":
                    self.send_json(HTTPStatus.FORBIDDEN, {"error": "Approved agency access required"})
                    return
                with connection() as database:
                    application = database.execute("SELECT id FROM agency_applications WHERE reference = ? AND agency_id = ?", (case_reference, agency["id"])).fetchone()
                if not application:
                    self.send_json(HTTPStatus.NOT_FOUND, {"error": "Application not found for this agency"})
                    return
            storage_key = f"{secrets.token_urlsafe(18)}{Path(filename).suffix.lower()}"
            quarantine_path = QUARANTINE_STORAGE / storage_key
            quarantine_path.write_bytes(content)
            scan_status = scan_file(quarantine_path)
            if scan_status == "infected":
                quarantine_path.unlink(missing_ok=True)
            with connection() as database:
                database.execute("INSERT INTO documents (case_reference, agency_id, filename, storage_key, scan_status) VALUES (?, ?, ?, ?, ?)", (case_reference, agency["id"] if agency else None, filename, storage_key, scan_status))
            if scan_status == "clean":
                shutil.move(str(quarantine_path), str(PRIVATE_STORAGE / storage_key))
            audit(user["email"], "document.uploaded", case_reference)
            self.send_json(HTTPStatus.CREATED, {"uploaded": True, "case_reference": case_reference, "filename": filename, "scan_status": scan_status})
            return
        if path == "/api/documents/link":
            if not self.csrf_valid() or not self.require_user():
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Authentication and CSRF validation required"})
                return
            document = self.authorized_document(int(payload.get("document_id", 0)))
            if not document or document["scan_status"] != "clean" or document["review_status"] == "rejected":
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Document is not available"})
                return
            token = secrets.token_urlsafe(32)
            DOWNLOAD_TOKENS[token] = (document["id"], time.time() + 300)
            self.send_json(HTTPStatus.CREATED, {"expires_in_seconds": 300, "download_path": f"/api/documents/download?token={token}"})
            return
        if path == "/api/documents/review":
            if not self.csrf_valid():
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "CSRF validation failed"})
                return
            user = self.current_user()
            if not user or user["role"] not in {"admin", "manager", "staff"}:
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Staff access required"})
                return
            document_id = int(payload.get("document_id", 0))
            status = str(payload.get("review_status", "")).lower()
            if document_id <= 0 or status not in {"pending", "approved", "rejected"}:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "document_id and a valid review_status are required"})
                return
            with connection() as database:
                document = database.execute("SELECT scan_status FROM documents WHERE id = ? AND deleted_at = ''", (document_id,)).fetchone()
            if not document or document["scan_status"] != "clean":
                self.send_json(HTTPStatus.CONFLICT, {"error": "Document must pass malware scanning before review"})
                return
            with connection() as database:
                result = database.execute("UPDATE documents SET review_status = ? WHERE id = ?", (status, document_id))
            audit(user["email"], f"document.{status}", str(document_id))
            self.send_json(HTTPStatus.OK, {"updated": result.rowcount == 1, "document_id": document_id, "review_status": status})
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
            audit(self.current_user()["email"], "invoice.created", invoice_number)
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
            audit(self.current_user()["email"], "invoice.payment_status_changed", invoice_number)
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
