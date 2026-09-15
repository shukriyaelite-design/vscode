# Shukriya development API

This is a dependency-free development backend for the CRM foundation. It provides:

- PBKDF2 password verification and HttpOnly session cookies
- Staff/admin login and logout
- CRM case listing and creation
- Private base64 document upload and metadata listing for PDF/JPG/PNG/WEBP files up to 10 MB
- Invoice creation/listing and payment-status records
- WhatsApp Cloud API configuration status endpoint
- Health and current-user endpoints

Development endpoints:

- `GET /api/health`
- `POST /api/login`, `POST /api/logout`, `GET /api/me`
- `GET/POST /api/cases`
- `GET/POST /api/documents`
- `GET/POST /api/invoices`
- `POST /api/payments/status`
- `POST /api/whatsapp/status`

Document uploads use JSON `content_base64` in development and are stored under `private_storage/`, outside `dist`. This is intentionally not a public download route.

## Run on Windows

Set development credentials in the current PowerShell session, then start the API:

```powershell
$env:SHUKRIYA_ADMIN_EMAIL = "admin@example.com"
$env:SHUKRIYA_ADMIN_PASSWORD = "replace-with-a-long-development-password"
& "C:/Users/ADMIN/.local/bin/python3.14.exe" backend/app.py
```

The API listens on `http://127.0.0.1:8010`.

This is not production-ready. Before deployment, add HTTPS, a persistent session store, CSRF protection, rate limiting, audit logs, private object storage, malware scanning, database backups, secrets management, a real payment provider and WhatsApp Cloud API credentials. Never store real passports or applicant documents in the public `dist` folder. Do not enable automated payments or WhatsApp messages until provider webhooks and consent handling are implemented.
