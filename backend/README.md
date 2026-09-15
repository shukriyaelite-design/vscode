# Shukriya development API

This is a dependency-free development backend for the CRM foundation. It provides:

- PBKDF2 password verification and HttpOnly session cookies
- Staff/admin login and logout
- Five-user CRM limit by default, configurable with `SHUKRIYA_MAX_USERS`
- Admin-only user list and user creation
- CRM case listing and creation
- Private base64 document upload and metadata listing for PDF/JPG/PNG/WEBP files up to 10 MB
- Quarantine-first uploads with signature checks and optional ClamAV scanning
- Five-minute authorization-bound document download links
- Invoice creation/listing and payment-status records
- WhatsApp Cloud API configuration status endpoint
- Travel-agent registration, approval and agency profile endpoints
- Agency owner/staff roles and multi-passenger B2B application records
- Health and current-user endpoints

Development endpoints:

- `GET /api/health`
- `POST /api/login`, `POST /api/logout`, `GET /api/me`
- `GET/POST /api/cases`
- `GET/POST /api/users` (admin only; maximum five users by default)
- `GET/POST /api/documents`
- `POST /api/documents/review` (staff/manager/admin review status)
- `POST /api/documents/link` and `GET /api/documents/download?token=...`
- `GET/POST /api/invoices`
- `POST /api/payments/status`
- `POST /api/payments/webhook` (HMAC signature required)
- `POST /api/whatsapp/status`
- `POST /api/chat` (server-side AI provider proxy with Shukriya service context)
- `POST /api/agents/register` (creates a pending agency owner account)
- `GET /api/agencies` (admin/manager) and `POST /api/agencies/approve` (admin only)
- `GET /api/agency/me`
- `GET/POST /api/agency/applications` (approved agency users)
- `POST /api/agency/invitations` (approved agency owner)
- `POST /api/agency/invitations/accept`

Security controls included in the development foundation:

- `X-CSRF-Token` required for authenticated state-changing requests; fetch it from `GET /api/csrf` after login
- Per-client API rate limiting
- Temporary login lockout after repeated failures
- Secure cookies by default; set `SHUKRIYA_COOKIE_SECURE=false` only for local HTTP development
- Payment webhook HMAC verification using `PAYMENT_WEBHOOK_SECRET`
- Role checks for admin user management
- Agency data isolation by agency membership
- Suspended-user session rejection
- Audit records for agency, user, application and invoice events

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

## Separate cloud-server deployment shape

1. Upload the contents of `dist` to `/var/www/shukriya/dist` on the separate cloud server.
2. Run `backend/app.py` as a managed Python service on `127.0.0.1:8010`.
3. Keep `SHUKRIYA_DB` and `SHUKRIYA_PRIVATE_STORAGE` outside the public web root.
4. Set `SHUKRIYA_COOKIE_SECURE=true` because SSL is enabled.
5. Set all values from `.env.example` in the cloud server secret/environment manager, never in HTML or GitHub.
6. Install the provided `deploy/nginx/shukriya.net.conf` configuration. It serves the static site and reverse-proxies `/api/` to the private Python service, so the site, CRM, AI chat and uploads all use `https://shukriya.net/`.
7. Configure daily database/private-storage backups, error logs, uptime monitoring and provider webhooks.

The static website and Python API remain separate processes behind one HTTPS domain. Because the browser calls relative `/api/...` paths, no second public API domain or browser CORS configuration is required.

## B2B delivery status

Completed: agent dashboard presentation, owner/staff role foundation, admin-only agency approval, pending/suspended access restriction, duplicate mobile/email/GST protection, staff invitation creation, basic audit logging foundation and live API hydration hooks.

Needs verification: ClamAV/malware scanning on the production cloud server, password reset, two-factor authentication, GST PDF invoices, payment webhooks, WhatsApp/email notifications and deployment to the separate cloud server. Invitation acceptance/reuse, duplicate email/GST, two-approved-agency isolation and suspended-session tests have been exercised in the isolated development suite.

Private document upload and review workflow implemented; malware scanning and production hardening pending.

Production readiness still requires HTTPS deployment on the separate cloud server, a persistent session store, private object storage, backups, secrets management and a full security review. Never store real passports or applicant documents in the public `dist` folder.
