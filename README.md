## ⚡ Quick Access Navigation
* [🚀 Getting Started](#-getting-started) — Requirements & Local Setup
* [🔓 1. 🔓 Insecure Direct Object Reference (IDOR) / Broken Access Control](#1-broken-access-control-idor) — IDOR & URL Manipulation
* [🔐 02. Default Credentials](#2-default-credentials-misconfiguration) — Administrative Access
* [📁 03. Unrestricted File Upload](#3-unrestricted-file-upload-vulnerability) — XSS & Phishing
* [⚠️ 04. Supply Chain Failure](#4-software-supply-chain-failure) — Dependency Confusion
* [📌 Summary Table](#-summary-of-security-issues) — Severity & Impact Matrix
* 
# 🚀 Getting Started

This guide explains how to set up and run the web application locally.

---

# 📦 Prerequisites

Before running the project, make sure you have installed:

- Node.js (v16 or higher)
- npm (comes with Node.js)
- Git
- A modern web browser (Chrome, Firefox, Edge)

---

# 📥 Installation

## 1. Clone the repository

```bash
git clone https://github.com/MoeinShahi/InsecureApp-OWASP-Top10-2025.git
```
# 🐞 Web Application Security Vulnerability Report (Research Lab)

> ⚠️ Educational / Research Use Only  
> This document describes security weaknesses in a controlled web application environment for learning and defensive security analysis.

## 2.Navigate to the project folder
```bash
cd InsecureApp-OWASP-Top10-2025
```

## 3. Install dependencies
```bash
npm install
```
## 4.Run the app
```bash
node app.js
```
## 5.Visit the app on browser
http://localhost:3000/

---

# 1. 🔓 Insecure Direct Object Reference (IDOR) / Broken Access Control

## 📖 Description
The application incorrectly uses **URL parameters (e.g., `?user=`)** to determine which account data is displayed. The system does not properly validate whether the authenticated user is authorized to access the requested resource.

This allows attackers to manipulate the URL to access other users’ accounts and data.

---

## ⚠️ Risks

### 👤 Normal User Impact
- Access to other users’ dashboards by modifying URL parameters
- Unauthorized viewing of private documents and uploaded files
- Ability to perform actions (upload/delete/view) on other user accounts

---

## 🧪 Attack Scenario

After login, the application redirects users to a URL such as:
http://localhost:3000/dashboard?user=john
An attacker modifies the parameter:
http://localhost:3000/dashboard?user=victim
no server-side authorization check exists, the system loads the victim’s account data.
## 🧑‍💼 Admin Panel Abuse

### Description
The admin dashboard is accessible by URL manipulation:
http://localhost:3000/admin.html?user=admin

The system does not verify roles or authentication properly and relies only on URL parameters.

---

## 💥 Impact
- Unauthorized access to admin dashboard
- Deletion or modification of users in the database
- Full administrative privilege escalation

---

## 🛡️ Root Cause
- No server-side authorization checks
- Trusting client-side URL parameters
- Missing role-based access control (RBAC)

---

# 2. 🔐 Default Credentials Misconfiguration

## 📖 Description
The application retains default credentials (e.g., admin/admin) from development or deployment.

---

## 🧪 Attack Scenario
Username: admin
Password: admin
An attacker gains immediate admin access.
---

## 💥 Impact
- Full system compromise
- Access to all user data
- Database manipulation or deletion
- Administrative control of application

---

## 🛡️ Root Cause
- Failure to remove default credentials
- Lack of forced password reset on first login

---

# 3. 📁 Unrestricted File Upload Vulnerability

## 📖 Description
The application allows file uploads without validating file type, content, or safety restrictions.

Uploaded files are accessible directly via the web server.

---

## 🧪 Attack Scenario

1. User uploads an HTML file:
malicious.html
2. Server stores and serves the file publicly
3. When accessed, embedded JavaScript executes in the browser
---

## 💥 Impact
- Cross-Site Scripting (XSS)
- Session hijacking
- Phishing page creation
- Potential Remote Code Execution (RCE) depending on server configuration

---

## 🛡️ Root Cause
- No file type validation
- No MIME type checking
- Unsafe direct file serving

---

# 4. ⚠️ Software Supply Chain Failure (Dependency Confusion / Malicious Package Risk)

## 📖 Description
The application uses internal packages (e.g., `internal-logic`) without proper registry isolation or namespace protection.

If the package name is exposed publicly, attackers can publish malicious versions with the same name.

---

## 🧪 Attack Scenario

1. Internal dependency:
internal-logic

2. Package name becomes publicly known

3. Attacker publishes malicious package:
internal-logic@2.0.0
4. Developer runs update:
npm update

5. Package manager installs attacker-controlled version due to higher version priority.

---

## 💥 Impact
- Execution of malicious code during install/runtime
- Theft of environment variables and secrets
- Database credential exposure
- Persistent backdoor in application logic

---

## 🛡️ Root Cause
- Non-unique package naming
- No private registry enforcement
- No dependency integrity verification
- Unsafe automatic updates

---

# 📌 Summary of Security Issues

| Category | Severity | Impact |
|----------|----------|--------|
| Broken Access Control (IDOR) | Critical | Full account/admin takeover |
| Default Credentials | Critical | Immediate admin access |
| File Upload Vulnerability | High | XSS / RCE / phishing |
| Supply Chain Failure | Critical | Full system compromise |

---

# ⚠️ Final Note

These vulnerabilities demonstrate how real-world systems can fail due to:

- Broken authorization logic
- Misconfiguration
- Unsafe file handling
- Weak dependency management

This document is intended strictly for **security research, education, and defensive improvement of systems in controlled environments only**.
