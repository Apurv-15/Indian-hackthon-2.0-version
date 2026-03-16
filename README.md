# AegisAI - Gmail Threat Email Dashboard

This project is a Next.js (App Router) dashboard that reads emails from a Gmail inbox using the Gmail API and displays them as threat-monitoring cards.

## Features

- Fetches latest 10 emails from Gmail inbox via backend route
- Uses Google OAuth2 (refresh token flow) on the server side
- Shows sender, subject, preview snippet, and received time
- Dashboard auto-refreshes every 10 seconds
- Tailwind-styled email cards and dashboard UI

## Project Structure

```text
src/
	app/
		api/
			emails/
				route.js          # Gmail API backend endpoint
		dashboard/
			page.js             # Frontend dashboard
	components/
		EmailCard.js          # Reusable email card UI
```

## 1. Prerequisites

- Node.js 18+
- pnpm (recommended) or npm
- A Google account (example: cyberthreatscanner@gmail.com)
- Google Cloud project with Gmail API enabled

## 2. Install Dependencies

From project root:

```bash
pnpm install
```

If you use npm instead:

```bash
npm install
```

The project requires `googleapis` for Gmail integration.

## 3. Google Cloud Setup (Gmail API)

1. Go to Google Cloud Console.
2. Create or select a project.
3. Enable **Gmail API** for that project.
4. Configure OAuth consent screen.
5. Create OAuth 2.0 Client ID credentials.
6. Add a redirect URI (for example: `http://localhost:3000/oauth2callback`).
7. Generate a refresh token for your Gmail account.

You need these values:

- `GMAIL_CLIENT_ID`
- `GMAIL_CLIENT_SECRET`
- `GMAIL_REDIRECT_URI`
- `GMAIL_REFRESH_TOKEN`
- `GMAIL_USER_EMAIL`

## 4. Create Environment Variables

Create a `.env.local` file in the root:

```env
GMAIL_CLIENT_ID=your_google_client_id
GMAIL_CLIENT_SECRET=your_google_client_secret
GMAIL_REDIRECT_URI=http://localhost:3000/oauth2callback
GMAIL_REFRESH_TOKEN=your_refresh_token
GMAIL_USER_EMAIL=cyberthreatscanner@gmail.com
```

Important:

- Do not commit `.env.local` to git.
- Values must match the same Google Cloud OAuth client setup.

## 5. Run the App

```bash
pnpm dev
```

Open:

- `http://localhost:3000/dashboard`

## 6. API Endpoint

Backend route:

- `GET /api/emails`

Returns JSON like:

```json
[
	{
		"from": "example@gmail.com",
		"subject": "Verify your account",
		"snippet": "Click this link to verify...",
		"time": "2026-03-16T10:00:00.000Z"
	}
]
```

## 7. How Auto-Refresh Works

The dashboard page polls `/api/emails` every 10 seconds using `setInterval`, so new inbox emails appear automatically without manual refresh.

## 8. Troubleshooting

### `Missing Gmail OAuth environment variables`

- Confirm `.env.local` exists at project root.
- Restart dev server after changing environment variables.

### `Failed to fetch emails from Gmail API`

- Verify Gmail API is enabled in Google Cloud.
- Verify refresh token is valid and not revoked.
- Ensure `GMAIL_USER_EMAIL` is the same account used in OAuth consent.

### Dependency install issues

- Prefer `pnpm install` in this repo because it already uses `pnpm-lock.yaml`.
- If a package install fails, remove `node_modules` and reinstall.

## 9. Security Notes

- Keep OAuth secrets private.
- Rotate refresh tokens if exposure is suspected.
- For production, store secrets in a secure secret manager, not in source files.

## 10. Quick Start Summary

1. `pnpm install`
2. Configure Gmail API in Google Cloud
3. Add `.env.local` with Gmail OAuth values
4. `pnpm dev`
5. Open `/dashboard`

