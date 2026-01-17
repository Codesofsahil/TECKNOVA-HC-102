# Google OAuth Setup Guide for SOC Platform

## 🔐 Gmail Authentication Integration

### Step 1: Create Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable the **Google+ API** and **Gmail API**

### Step 2: Configure OAuth Consent Screen

1. Go to **APIs & Services** > **OAuth consent screen**
2. Choose **External** user type
3. Fill in required fields:
   - App name: `SOC Platform`
   - User support email: Your email
   - Developer contact: Your email
4. Add scopes: `email`, `profile`, `openid`
5. Add test users (Gmail addresses that can access)

### Step 3: Create OAuth Credentials

1. Go to **APIs & Services** > **Credentials**
2. Click **Create Credentials** > **OAuth 2.0 Client IDs**
3. Application type: **Web application**
4. Name: `SOC Platform Web Client`
5. Authorized JavaScript origins:
   - `http://localhost:5000`
   - `https://yourdomain.com` (for production)
6. Authorized redirect URIs:
   - `http://localhost:5000/dashboard`
7. Copy the **Client ID**

### Step 4: Update Configuration

1. Replace `YOUR_GOOGLE_CLIENT_ID` in `app.py`:
   ```python
   GOOGLE_CLIENT_ID = "your-actual-client-id.apps.googleusercontent.com"
   ```

2. Replace `YOUR_GOOGLE_CLIENT_ID` in `login.html`:
   ```html
   data-client_id="your-actual-client-id.apps.googleusercontent.com"
   ```

### Step 5: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 6: Test Authentication

1. Start the application: `python app.py`
2. Go to `http://localhost:5000`
3. Try both authentication methods:
   - **Google Sign-In**: Click the Google button
   - **Email/Password**: Use `admin@gmail.com` / `admin123`

## 🛡️ Security Features

- **Domain Restriction**: Only `@gmail.com` addresses allowed
- **Token Verification**: Google ID tokens are verified server-side
- **Secure Authentication**: OAuth 2.0 standard implementation
- **User Information**: Name, email, and profile picture from Google

## 📧 Allowed Email Domains

Currently configured for Gmail only. To add more domains, update:

```python
ALLOWED_DOMAINS = ["gmail.com", "yourdomain.com"]
```

## 🔧 Production Deployment

1. Update JavaScript origins and redirect URIs in Google Console
2. Use HTTPS for production domains
3. Set proper CORS policies
4. Store client secrets securely (environment variables)

## 🚨 Important Notes

- Keep your Client ID secure
- Never expose Client Secret in frontend code
- Test with multiple Gmail accounts
- Monitor authentication logs for security

---
**Status**: Ready for Gmail Authentication 🚀