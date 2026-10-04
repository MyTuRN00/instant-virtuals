# Instant Virtuals — Production Hardened Deployment

This package is prepared for a public PostgreSQL-backed deployment on Render.

## Security and production features
- PostgreSQL persistence with connection pooling
- Email ownership verification before analyzer access
- Single-use, expiring verification tokens
- Password reset with single-use, expiring tokens
- Password reset responses that do not reveal whether an account exists
- bcrypt password hashing
- JWT authentication
- Server-side daily analysis quota
- PostgreSQL-backed request throttling for auth and analysis endpoints
- Helmet security headers
- Admin role and admin dashboard
- Admin user enable/disable controls
- Health endpoint for Render
- Temporary screenshot storage; images are deleted after processing
- OpenAI API key remains server-side
- Render Blueprint with managed PostgreSQL
- Custom domain setup guide below

## Required environment variables
`DATABASE_URL`, `JWT_SECRET`, `OPENAI_API_KEY`, `APP_URL`, `ADMIN_EMAIL`, and SMTP settings are required for the full production feature set.

Set `DAILY_ANALYSIS_LIMIT` to the number of analyses a user may perform per UTC day.

### Email provider
Use any SMTP provider that gives you an SMTP host, port, username and password. Do not put SMTP credentials into source control.

## Local setup
1. Install Node.js 20+.
2. Create a PostgreSQL database.
3. Copy `.env.example` to `.env` and fill every value.
4. Run `npm install`.
5. Run `npm run db:init`.
6. Run `npm start`.
7. Open `http://localhost:3000`.
8. Use an SMTP mailbox you control so registration verification and password reset emails can be tested.

## Render deployment
1. Push this folder to a private GitHub repository.
2. In Render, create a new Blueprint and select the repository.
3. Render will provision the web service and PostgreSQL database from `render.yaml`.
4. In the web service Environment settings, enter `OPENAI_API_KEY`, `APP_URL`, `ADMIN_EMAIL`, and SMTP values.
5. Deploy and wait for `/health` to become healthy.
6. Create the admin account using the exact `ADMIN_EMAIL` value. The initialization process assigns that account the `admin` role.
7. Open `/admin` after signing in as the admin.

Render recommends environment variables for secrets rather than committing credentials to the repository. The included Blueprint uses Render's generated secret support for `JWT_SECRET`. See the official environment-variable documentation.

## Custom domain
1. Deploy the service first and confirm its `onrender.com` address works.
2. In Render, open the web service and go to **Settings → Custom Domains → Add Custom Domain**.
3. Enter your domain, such as `instantvirtuals.com`.
4. At your domain registrar/DNS provider, create the DNS record Render shows. For a `www` subdomain, Render uses a CNAME pointing to the service's `onrender.com` hostname. For root domains, use the record type Render recommends for your DNS provider.
5. Remove conflicting `AAAA` records while configuring the domain.
6. Return to Render and click **Verify**.
7. After verification, Render automatically provisions and renews TLS and redirects HTTP traffic to HTTPS.
8. Set `APP_URL` to the final HTTPS address, for example `https://instantvirtuals.com`, then redeploy so verification/reset email links use your real domain.

Official Render custom-domain instructions: https://render.com/docs/custom-domains

## Admin dashboard
After the admin email has been verified and the account is active, sign in and visit `/admin`.

The dashboard shows user count, verified users, today's analyses, total analyses, and a user list. Admins can enable/disable accounts.

## Usage limits
The default is 10 analyses per user per UTC day. Change `DAILY_ANALYSIS_LIMIT` in Render environment variables and redeploy. The quota is enforced in PostgreSQL, so it is not bypassed by refreshing the browser or changing devices.

## Important production checklist
- Use a real domain and HTTPS.
- Configure a reputable SMTP provider and verify the sending domain if your provider supports it.
- Keep `OPENAI_API_KEY`, SMTP credentials and database credentials only in Render environment variables.
- Set `APP_URL` to the exact HTTPS domain users will visit.
- Enable database backups/retention appropriate for your needs.
- Review privacy/retention requirements before storing user information.
- Consider adding MFA for administrator accounts before exposing `/admin` to a large audience.
- Monitor rate-limit events, failed logins, password resets and analysis usage.
- Predictions are probabilistic and are not guaranteed outcomes. This service does not place bets or create betting balances.
