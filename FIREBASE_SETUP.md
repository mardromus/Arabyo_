# Firebase Auth Setup

## 1. Firebase Console

1. Go to [Firebase Console](https://console.firebase.google.com/) > your project (arabyo-b703f).
2. **Authentication** > Sign-in method:
   - Enable **Email/Password**
   - Enable **Google** (add support email if prompted)

## 2. Service Account (backend)

1. **Project Settings** (gear icon) > **Service accounts**
2. Click **Generate new private key**
3. Save the JSON file as `credentials/firebase-adminsdk.json` in this project
4. Ensure `credentials/` is in `.gitignore` (done)

## 3. Environment Variables

Add to `.env`:

```env
# Admin users (comma-separated emails)
ADMIN_EMAILS=you@company.com,admin@company.com

# Optional: risk_manager and auditor
# RISK_MANAGER_EMAILS=risk@company.com
# AUDITOR_EMAILS=auditor@company.com
```

## 4. Roles

- **admin**: Ingest data, run scan, approve policies
- **risk_manager**: Approve policies, generate reports
- **auditor**: Read-only audit trail
- **analyst** (default): Review alerts, export reports

Emails in `ADMIN_EMAILS` get admin. Others get analyst unless listed in `RISK_MANAGER_EMAILS` or `AUDITOR_EMAILS`.

## 5. Local Dev (skip auth)

To use the old `?role=` switcher without Firebase:

```env
FIREBASE_AUTH_DISABLED=1
```
