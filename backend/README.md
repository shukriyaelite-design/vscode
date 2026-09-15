# Shukriya development API

This is a dependency-free development backend for the CRM foundation. It provides:

- PBKDF2 password verification and HttpOnly session cookies
- Staff/admin login and logout
- CRM case listing and creation
- SQLite storage for cases, document metadata and invoices
- Health and current-user endpoints

## Run on Windows

Set development credentials in the current PowerShell session, then start the API:

```powershell
$env:SHUKRIYA_ADMIN_EMAIL = "admin@example.com"
$env:SHUKRIYA_ADMIN_PASSWORD = "replace-with-a-long-development-password"
& "C:/Users/ADMIN/.local/bin/python3.14.exe" backend/app.py
```

The API listens on `http://127.0.0.1:8010`.

This is not production-ready. Before deployment, add HTTPS, a persistent session store, CSRF protection, rate limiting, audit logs, private object storage, malware scanning, database backups, secrets management and a payment provider. Never store real passports or applicant documents in the public `dist` folder.
