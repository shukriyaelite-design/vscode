# Shukriya.net staged website package

This package contains a responsive multi-page front-end staging site for Shukriya visa and documentation services.

## Files

- `dist/index.html` – staged homepage and service navigation
- `dist/assets/css/styles.css` – full desktop, tablet and mobile styling
- `dist/assets/js/main.js` – mobile menu, FAQ, tracking demo and enquiry validation
- `dist/*.html` – service, support, company and legal pages
- `dist/robots.txt` and `dist/sitemap.xml` – production crawler controls and URL inventory

## Preview

Run the preview from the project root with the configured Python executable:

```powershell
& "C:/Users/ADMIN/.local/bin/python3.14.exe" -m http.server 8000
```

Then open `http://localhost:8000/`. The root entry redirects to `dist/index.html`.

## Before production deployment

1. Replace the temporary logo mark with the approved Shukriya logo.
2. Verify the phone, email, office address and business hours.
3. Connect the enquiry form to a secure server-side handler.
4. Connect application tracking to the protected production database.
5. Verify all claims, authorisations, requirements and disclaimers.
6. Replace placeholder section links with final page URLs.
7. Confirm the production host serves the contents of `dist` at `https://shukriya.net/`.
8. Submit `https://shukriya.net/sitemap.xml` to Google Search Console after deployment.

## Important

The forms included in this visual package demonstrate front-end behaviour only. They do not submit or store personal information.
