# Aman (آمن) — Signaling Server

Signaling + accounts server for the Aman encrypted 1:1 voice calling app.
Node.js + WebSocket (`ws`), JSON-file storage, and a built-in admin web page.

- Username accounts (passwords stored as scrypt hashes in `data.json`, auto-created)
- User search, friend requests, friends list, online presence
- Relays WebRTC call signaling (SDP/ICE) between two friends only — it never sees call audio
- Admin page at `/admin` (list users, see who is online, delete users), protected by `ADMIN_TOKEN`
- Health check at `/health`

## Run locally

```
npm install
ADMIN_TOKEN="pick-a-strong-secret" PORT=3000 npm start
```

## Deploy on Render

1. Push this repo to GitHub (public is fine — it contains no secrets).
2. In Render: New > Web Service > paste this repo's public Git URL.
3. Settings:
   - Runtime: Node
   - Build command: `npm install`
   - Start command: `npm start`
   - Instance type: Free
4. Environment variables:
   - `ADMIN_TOKEN` = a strong secret of your choice (used to log into /admin)
   - Do NOT set `PORT` yourself — Render assigns it and the server reads it automatically.
5. Deploy. Your server URL is the `https://<name>.onrender.com` address Render shows.
   Check `https://<name>.onrender.com/health` says `ok`.

Note: Render's URL is HTTPS. This server speaks plain HTTP/WebSocket internally;
Render terminates TLS for you, so the app should use
`wss://<name>.onrender.com` as its server address (set it in the app under
"⚙ إعدادات السيرفر" on the login screen).

Keep it awake: Render's free tier sleeps after inactivity; the first connection
after sleep takes ~30-60 seconds. A free uptime pinger (e.g. UptimeRobot hitting
/health every 5 minutes) keeps it warm.

## Part of the Aman app

The Android app source lives separately (delivered as its own project). This
repo is only the server the app connects to.
