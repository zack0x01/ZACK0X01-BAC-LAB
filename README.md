# 🔓 Broken Access Control (BAC) Lab

A hands-on bug bounty lab for practicing Broken Access Control vulnerabilities. Learn to identify and exploit common access control issues including IDOR, privilege escalation, and missing authorization checks.

## 🎯 About

This lab is designed to help security researchers and bug bounty hunters practice finding and exploiting Broken Access Control vulnerabilities. The application contains multiple intentionally vulnerable endpoints that demonstrate common access control flaws found in real-world applications.

**Created by:** [@zack0X01](https://twitter.com/zack0X01)

## 🚀 Quick Start

### Easy Installation (3 Steps)

**Step 1: Install Python**
- Make sure you have Python 3.7+ installed
- Check: `python3 --version` or `python --version`

**Step 2: Install Dependencies**
```bash
pip install -r requirements.txt
```
Or if that doesn't work:
```bash
pip3 install -r requirements.txt
```

**Step 3: Run the Lab**
```bash
python3 app.py
```

**Access the Lab:**
- Open browser: `http://127.0.0.1:5000`
- From another device: `http://YOUR_IP:5000`

That's it! The database will be created automatically on first run.

### Default Credentials

- **Admin:** `admin` / `admin123`
- **User:** `user1` / `user123`

You can also register your own account!

## 🎯 Challenge Objectives

As a **low-level user**, your mission is to:

1. ✅ **Intercept Admin Requests** - Use Burp Suite or browser DevTools to intercept admin's network traffic
2. ✅ **Discover Hidden API Endpoints** - Find admin API endpoint paths from intercepted requests
3. ✅ **Retrieve API Keys** - Access `/api/admin/keys` to get organization API keys and secrets
4. ✅ **Access All Users' Data** - Access `/api/admin/users/all` to retrieve all organization users' sensitive data
5. ✅ **Find and Capture All Flags** - Discover all hidden flags

**Important:** Admin endpoints are hidden (not advertised to regular users). If you can intercept admin requests and discover these endpoint paths, you can access sensitive data.

## 🐛 Vulnerabilities Included

### 1. Hidden API Endpoint Discovery ⭐ MAIN VULNERABILITY
- Admin API endpoints are not advertised to regular users (not linked anywhere)
- **But** if you intercept admin's network requests, you can discover these hidden endpoints
- Endpoints like `/api/admin/keys` and `/api/admin/users/all` are revealed in intercepted admin traffic
- Discovery of hidden admin endpoints via request interception is a real-world vulnerability

### 2. Information Disclosure via Request Interception
- Admin panel (`/admin`) and API endpoints (`/api/admin/*`) are hidden from regular users
- If you capture admin's network traffic, you can see what endpoints admin is calling
- This reveals sensitive API structure and endpoint paths

### 3. IDOR Protection (For Regular Users)
- User data endpoints check ownership
- Regular users can only access their own data
- Admins can access all users' data

### 4. Sensitive Data Exposure
- API keys endpoint: `/api/admin/keys` - Contains organization API keys
- All users endpoint: `/api/admin/users/all` - Contains all organization users' sensitive data
- These endpoints exist but are not advertised - discoverable via request interception

## 🔍 Tools You'll Need

### Option 1: Burp Suite (Recommended)
1. Download Burp Suite Community Edition (free)
2. Configure browser proxy: `127.0.0.1:8080`
3. Install Burp's CA certificate in browser
4. Start intercepting requests!

### Option 2: Browser DevTools (Easy)
1. Open browser DevTools (F12)
2. Go to **Network** tab
3. Login as admin and watch the requests
4. See admin API endpoints being called
5. Copy and try accessing them!

## 💡 Quick Tips

- **Admin automatically calls API endpoints** when visiting `/admin` panel
- **Intercept those requests** to see the endpoint paths
- **Try accessing them** as a regular user - they work!
- **For payment bypass:** Intercept `/api/user/paid-status` and modify the response

## 📋 Flags to Find

- `BAC_LAB_USER_DATA` - Found in your own user data
- `BAC_LAB_ADMIN_PANEL_ACCESSED` - Found in admin settings (requires admin access)
- `ADMIN_API_KEY_2024_SECRET` - Found in admin API keys endpoint
- Organization API Keys:
  - `ORG_ALPHA_API_KEY_XYZ123`
  - `ORG_BETA_API_KEY_ABC456`
  - `ORG_GAMMA_API_KEY_DEF789`

## 🛠️ Testing Tools

You can use any of these tools to test:
- **Browser DevTools** - Inspect network requests and responses
- **Burp Suite** - Intercept and modify requests
- **Postman/Insomnia** - Test API endpoints directly
- **cURL** - Command-line testing
- **Python requests** - Write custom exploitation scripts

## 📚 Learning Resources

- **Bug Bounty Course:** [lureo.shop](https://lureo.shop) - Learn advanced bug bounty techniques
- **OWASP Top 10:** [owasp.org](https://owasp.org/www-project-top-ten/) - Understand Broken Access Control

## ☕ Support

If you find this lab helpful, consider:
- ☕ [Buy Me a Coffee](https://buymeacoffee.com/zack0X01)
- 🐦 Follow [@zack0X01](https://twitter.com/zack0X01) on Twitter
- 💻 Check out my [GitHub](https://github.com/zack0X01)

## 📱 Connect with zack0X01

- **Twitter:** [@zack0X01](https://twitter.com/zack0X01)
- **GitHub:** [zack0X01](https://github.com/zack0X01)
- **LinkedIn:** [zack0X01](https://linkedin.com/in/zack0X01)
- **Instagram:** [@zack0X01](https://instagram.com/zack0X01)

## ⚠️ Disclaimer

This lab is for **EDUCATIONAL PURPOSES ONLY**. Use it responsibly and only on systems you own or have explicit permission to test. Do not use these techniques on systems without authorization.

## 📝 Endpoints Summary

### Protected Admin Endpoints (Require Admin Session Cookie)
1. `/admin` - Admin panel (properly protected, but vulnerable to cookie theft)
2. `/api/admin/settings` - Admin settings API (properly protected, but vulnerable to cookie theft)
3. `/api/admin/keys` - Organization API keys (properly protected, but vulnerable to cookie theft)
4. `/api/admin/users/all` - All users' sensitive data (properly protected, but vulnerable to cookie theft)

### Regular User Endpoints
1. `/api/user/<user_id>` - User data API (ownership checked - regular users can only access their own)
2. `/profile/<user_id>` - User profiles (can view basic info, but sensitive data protected)
3. `/dashboard` - User dashboard

**Key Insight:** All admin endpoints return `403 Forbidden` for regular users, but can be accessed by stealing and replaying an admin's session cookie!

## 🎓 Solution Guide

<details>
<summary>Click to reveal solutions (try yourself first!)</summary>

### Solution #1: Hidden Admin API Endpoints

#### Step 1: Set Up Burp Suite or DevTools
1. **Burp Suite:** Configure browser proxy to `127.0.0.1:8080`
2. **DevTools:** Open browser DevTools (F12) → Network tab

#### Step 2: Intercept Admin Requests
1. Login as admin: `admin` / `admin123`
2. Visit `/admin` panel - it automatically makes API calls
3. In Burp Suite or DevTools, see these requests:
   - `GET /api/admin/settings`
   - `GET /api/admin/keys`
   - `GET /api/admin/users/all`

#### Step 3: Access as Regular User
1. Login as regular user: `user1` / `user123`
2. Access the discovered endpoints directly:
   ```
   GET /api/admin/users/all HTTP/1.1
   Host: 127.0.0.1:5000
   Cookie: session=YOUR_REGULAR_USER_SESSION_COOKIE
   ```
3. **Success!** You can access admin data because endpoints only check authentication, not admin role!

### Solution #2: Payment Bypass (Course Videos)

#### Step 1: Intercept Payment Status API
1. Login as regular user: `user1` / `user123`
2. Visit `/course` page
3. Intercept the request to `/api/user/paid-status` using Burp Suite or DevTools

#### Step 2: Modify the Response
1. The API returns: `{"paid": false, "message": "Upgrade to premium..."}`
2. In Burp Suite:
   - Go to Proxy → Options → Match and Replace
   - Add rule: Response body, Match: `"paid": false`, Replace: `"paid": true`
   - Or manually intercept and modify the response
3. In DevTools:
   - Network tab → Find `/api/user/paid-status` request
   - Right-click → Copy as cURL
   - Modify response using browser extension or manual intercept

#### Step 3: Unlock Premium Videos
1. After modifying response to `{"paid": true}`
2. Refresh the `/course` page
3. **Success!** All premium course videos from zack0X01 are now unlocked!

**Why it works:** The frontend trusts the API response without server-side verification. Changing `paid: false` to `paid: true` in the intercepted response unlocks premium content.

</details>

## 📄 License

This project is for educational purposes. Feel free to use and modify for learning.

---

**Happy Hacking! 🎉**

Remember: The goal is to learn and improve security. Always practice responsibly!

## 📺 YouTube Channel

Check out my YouTube channel for more bug bounty tutorials and security content:

🔗 **[Subscribe to zack0X01 on YouTube](https://www.youtube.com/@zack0X01)**

Watch the premium course videos included in this lab after you bypass the payment check! 😉

