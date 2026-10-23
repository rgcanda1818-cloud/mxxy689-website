# Baranggay San Isidro — Barangay Service Desk

A responsive static website prototype for resident requests and barangay staff workflows. GitHub Pages can host the site for free; Supabase Auth stores resident accounts in a separate hosted project.

## Configure free Supabase account storage

1. Create a Supabase project on the free plan.
2. In **Project Settings → API**, copy the **Project URL** and **Publishable key**. The publishable key is intended for browser use. Never use a `service_role` or secret key in this website.
3. Replace the two example values in `supabase-config.js`:

   ```js
   export const SUPABASE_URL = "https://YOUR_PROJECT_ID.supabase.co";
   export const SUPABASE_PUBLISHABLE_KEY = "YOUR_SUPABASE_PUBLISHABLE_KEY";
   ```

4. In **Authentication → Providers**, enable Email sign-in.
   - To log in immediately after registration, disable email confirmation in the Email provider settings. If you leave it enabled, Supabase saves the account but the resident must confirm their email before logging in.
5. In **Authentication → URL Configuration**, set the site URL and add the local development address and your deployed GitHub Pages address to the allowed redirect URLs. For example:
   - `http://localhost:8080/**`
   - `https://YOUR-GITHUB-USERNAME.github.io/YOUR-REPOSITORY/**`
6. Publish the website. Open its **Account** page and register an account.

Supabase Auth saves registered users in the project's managed Auth user store, including their name as user metadata. Supabase JS persists the sign-in session in the user's browser and refreshes it. If email confirmation is enabled, a new resident must confirm the email before logging in. Email delivery behavior and usage limits depend on the Supabase project's current plan and settings.

The Project URL and publishable key are public configuration, not passwords. Keep server-side keys private. Do not commit real personal information or credentials to GitHub.

## Free chat support

The floating chat widget uses prepared, rule-based answers in the browser for common questions about creating accounts, submitting or tracking requests, and general document guidance. It is not a generative AI model, does not call an AI provider, and needs no API key or chat-specific subscription. Messages are not sent to an AI service. It cannot access or change accounts or request records, and it does not have verified local office hours, fees, or document requirements. Do not enter personal or sensitive information.

## Included

- Public landing page with account and request navigation.
- Supabase-backed account creation, login, and logout.
- Free browser-based chat support for common service-desk questions (not generative AI).
- Resident request form with keyword-based category and urgency suggestions.
- Request-reference tracking, staff queue, assignment and status updates.
- Category/status reports and CSV export.

## Current limitations

- Supabase Auth stores accounts, but **service requests remain in the current browser's local storage**. They are not shared between devices or users.
- For free registration without confirmation-email problems, turn off **Confirm email** in Supabase Authentication > Providers > Email. This skips email ownership verification; use custom SMTP for a public service that requires verified addresses.
- Accounts made in the old browser-only prototype can be migrated on this device by logging in with the same email and original password. The app verifies the old salted password hash locally, then creates the account in Supabase; if the legacy record is unavailable, register again or use the password reset flow.
- If Supabase email confirmation is enabled, an unconfirmed account cannot log in yet. After a login attempt, the account page offers a resend-confirmation action; residents should confirm from their email before retrying.
- Supabase's built-in email sender is limited to 2 emails per hour per project. If it responds with an email rate-limit error, the app pauses email requests for up to an hour to avoid repeated failed attempts. Wait for the limit to reset, or configure a custom SMTP provider in Supabase **Authentication → SMTP Settings** for more reliable delivery and a higher configurable limit.
- The app's rate-limit pause is only stored in the current browser. The two-emails-per-hour limit is project-wide; wait for Supabase's quota to reset or configure custom SMTP to increase email capacity.
- All workspace pages (overview, submit request, track request, request queue, and reports) require a signed-in Supabase account. Visitors are redirected to login and returned to the selected page after signing in. This is only a client-side navigation guard; the project does not yet use server-side authorization or database row-level security for requests.
- The workspace currently has no staff-role authorization. Hiding the workspace until sign-in does not make browser-local request data confidential. Do not use it to process real sensitive resident requests.
- The request classifier uses example keyword rules; it is not a trained or validated AI model.
- Supabase and GitHub free plans have limits and plan terms may change. Check the providers' current terms before deployment.
- The reports are not a classification-accuracy or usability study. A real evaluation needs a labeled test set and representative user testing against an agreed standard such as ISO/IEC 25010.

## Run locally

Run a local static server from this folder (for example, `py -m http.server 8080`) and open `http://localhost:8080`. A local server is needed for JavaScript modules and secure browser APIs.
