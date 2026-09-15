# Shukriya development API

This is a dependency-free development backend for the CRM foundation. It provides:

- PBKDF2 password verification and HttpOnly session cookies
- Staff/admin login and logout
- Five-user CRM limit by default, configurable with `SHUKRIYA_MAX_USERS`
- Admin-only user list and user creation
- CRM case listing and creation
- Private base64 document upload and metadata listing for PDF/JPG/PNG/WEBP files up to 10 MB
- Invoice creation/listing and payment-status records
- WhatsApp Cloud API configuration status endpoint
- Health and current-user endpoints

Development endpoints:

- `GET /api/health`
- `POST /api/login`, `POST /api/logout`, `GET /api/me`
- `GET/POST /api/cases`
- `GET/POST /api/users` (admin only; maximum five users by default)
- `GET/POST /api/documents`
- `GET/POST /api/invoices`
- `POST /api/payments/status`
- `POST /api/payments/webhook` (HMAC signature required)
- `POST /api/whatsapp/status`

Security controls included in the development foundation:

- `X-CSRF-Token` required for authenticated state-changing requests; fetch it from `GET /api/csrf` after login
- Per-client API rate limiting
- Temporary login lockout after repeated failures
- Secure cookies by default; set `SHUKRIYA_COOKIE_SECURE=false` only for local HTTP development
- Payment webhook HMAC verification using `PAYMENT_WEBHOOK_SECRET`
- Role checks for admin user management

Document uploads use JSON `content_base64` in development and are stored under `private_storage/`, outside `dist`. This is intentionally not a public download route.

## Run on Windows

Set development credentials in the current PowerShell session, then start the API:

```powershell
$env:SHUKRIYA_ADMIN_EMAIL = "contact@shukriya.net"
$env:SHUKRIYA_ADMIN_PASSWORD = "replace-with-a-long-development-password"
& "C:/Users/ADMIN/.local/bin/python3.14.exe" backend/app.py
```

To seed additional users later, set `SHUKRIYA_USERS_JSON` to a JSON array containing `email`, `password` and `role` (`admin`, `manager` or `staff`). Keep passwords in environment variables or a secrets manager, not in GitHub.

The API listens on `http://127.0.0.1:8010`.

## HostGator deployment shape

1. Upload the contents of `dist` to `public_html`.
2. Use cPanel **Setup Python App** for `backend/app.py`; use the Python version supported by the HostGator account.
3. Keep `SHUKRIYA_DB` and `SHUKRIYA_PRIVATE_STORAGE` outside `public_html`.
4. Set `SHUKRIYA_COOKIE_SECURE=true` because SSL is enabled.
5. Set all values from `.env.example` in the Python App environment-variable panel, never in HTML or GitHub.
6. Put the API behind the HostGator HTTPS reverse proxy and restrict `/api` access as required by the deployment.
7. Configure daily database/private-storage backups, error logs, uptime monitoring and provider webhooks.

The static website and Python API are separate processes. The live frontend must call the production API URL only after HTTPS, CORS policy, authentication and reverse-proxy routing have been configured.

This is not production-ready. Before deployment, add HTTPS, a persistent session store, CSRF protection, rate limiting, audit logs, private object storage, malware scanning, database backups, secrets management, a real payment provider and WhatsApp Cloud API credentials. Never store real passports or applicant documents in the public `dist` folder. Do not enable automated payments or WhatsApp messages until provider webhooks and consent handling are implemented.
