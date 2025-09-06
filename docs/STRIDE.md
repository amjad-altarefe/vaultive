# STRIDE Threat Modeling Report (Microsoft Approach)

## Application Name: Vaultive – Secure Web Agency Platform
## Author: Amjad Qandeel – Cybersecurity Expert

---

## 1. Define

- **Objective:** Build a secure web platform for showcasing services, user registration/login, profile management, and role-based access (User/Admin).
- **Assets to protect:** User credentials and profile data, Session tokens (sessions / JWTs), admin panel access and Database and configuration files.
- **Security goals:** Ensure only authenticated users can access protected areas,Restrict admin dashboard access to authorized administrators only, Protect sensitive data against tampering or disclosure and Prevent exploitation through common web attacks (XSS, CSRF, SQL/NoSQL injection).

---

## 2. Diagram

> *Data Flow Diagram (DFD)*
- User → Browser → Vaultive Server (Node.js + Express) → MongoDB Database
- Key flows:
  - Registration form (POST /register)
  - Login form (POST /login)
  - Session creation (server-based sessions)
  - Admin panel (GET /admin, POST /admin/actions)
  - Password reset with secure tokens (POST /reset-password)

---

## 3. Identify (STRIDE Threats)

| Threat Category            | Description                                | Example in App                             |
|----------------------------|--------------------------------------------|--------------------------------------------|
| **Spoofing**               | Pretending to be another user              | Session ID reuse or stolen session cookie  |
| **Tampering**              | Modifying session data                     | Editing cookies to gain privileges         |
| **Repudiation**            | Denying user actions                       | No logs of account changes or logins       |
| **Information Disclosure** | Leaking sensitive data                     | Detailed error messages expose data        |
| **Denial of Service**      | Flooding login or register forms           | Service slowdown or app crash              |
| **Elevation of Privilege** | Gaining admin access without authorization | Bypassing role check to access admin panel |

---

## 4. Mitigate

| Threat Category            | Mitigation Strategy                                                                  |
|----------------------------|--------------------------------------------------------------------------------------|
| **Spoofing**               | Use server sessions with secure, HttpOnly, and SameSite cookies                      |
| **Tampering**              | Sign and verify session cookies; avoid storing sensitive data in client-side cookies |
| **Repudiation**            | Implement detailed logging of login, logout, and account-related actions             |
| **Information Disclosure** | Use generic error messages and avoid stack trace exposure                            |
| **Denial of Service**      | Apply rate-limiting and CAPTCHA to sensitive endpoints                               |
| **Elevation of Privilege** | Check roles server-side on each sensitive route (e.g., /admin)                       |

---

## 5. Validate

- Manual review of threat model against application routes and flows
- Verified secure cookie configuration (HttpOnly, Secure, SameSite)
- Performed code scanning and verified mitigation is in place
- Used checklists and peer review to validate all risks are handled