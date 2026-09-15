# One-domain deployment

The production layout is:

```text
https://shukriya.net/          -> static files in /var/www/shukriya/dist
https://shukriya.net/api/*     -> Python API on 127.0.0.1:8010
```

1. Copy `dist` to `/var/www/shukriya/dist`.
2. Run `backend/app.py` as a managed service bound to `127.0.0.1:8010`.
3. Set environment variables from `backend/.env.example` in the cloud secret manager.
4. Install `deploy/nginx/shukriya.net.conf` and replace the certificate paths with the cloud server's SSL certificate paths.
5. Reload Nginx and test `/`, `/api/health`, `/travel-agent-portal.html`, `/crm.html` and `/ai-chat.html`.

Do not expose port `8010` publicly. Do not place the database, private storage or quarantine storage inside the public `dist` directory.
