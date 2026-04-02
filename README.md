# Dispatch - Tor File Sharing Platform

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Security: Headers](https://img.shields.io/badge/Security-Headers-brightgreen)](https://securityheaders.com)
[![Tor: Hidden Service](https://img.shields.io/badge/Tor-Hidden%20Service-8A2BE2)](https://www.torproject.org)

**Dispatch is a privacy-focused file sharing and communication platform accessible only as a Tor hidden service.**

## 🔒 Official Service

**The only official Dispatch instance:**
https://pladaibgpkuswvqosgdszdtbgmxkfz55co66c4pmxg3ldmvyw2w45zyd.onion

⚠️ **Always verify you're at the correct .onion address before logging in.**

## 📋 Purpose of This Repository

This source code is published for **transparency and security audit** purposes only. You can verify:

- How your data is handled
- What security measures are in place
- That no backdoors, trackers, or ads exist
- That encryption works as described

**This code is NOT provided for you to run your own instance.** If you run a modified version, you cannot claim it's Dispatch. Only trust the official .onion address above.

## ✨ Features

### File Sharing
- AES-256-GCM client-side encryption
- Files up to 10 GB (Premium users)
- Custom expiration (1-7 days for Pro/Premium)
- Password protection (Pro/Premium)
- Automatic cleanup of expired files

### Private Chat (Pro and Premium)
- End-to-end encrypted messages
- Auto-delete after 24 hours
- Read receipts (Premium can disable)
- Typing indicators
- Message search (Pro+)

### Group Chats (Premium)
- Create groups with unlimited members
- Promote members to admin
- Remove members
- Edit group description

### Security Features
- Tor-only access (real IP never exposed)
- Two-factor authentication (TOTP)
- Account lockout: 5 failed logins = 30 minutes
- Argon2id password hashing
- HTTP-only cookies, CSRF protection
- Rate limiting: login (5/min), registration (5/hour)
- Security headers (CSP, HSTS, X-Frame-Options)
- Session revocation on password change

### User Roles

| Feature | Free | Pro | Premium |
|---------|------|-----|---------|
| Max File Size | 1 GB | 5 GB | 10 GB |
| Concurrent Files | 10 | 50 | 100 |
| History Retention | 30 days | 60 days | 90 days |
| Private Chat | ❌ | ✅ (100 char) | ✅ (200 char) |
| Group Chats | ❌ | ❌ | ✅ |
| Custom Expiry | ❌ | ✅ | ✅ |
| Password Protection | ❌ | ✅ | ✅ |
| Subscription | - | 30 days | 30 days |

## 🛡️ Security Verification

Independent security researchers have verified:

| Security Measure | Status |
|-----------------|--------|
| HTTPS with strong ciphers | ✅ Enabled |
| Argon2id password hashing | ✅ Implemented |
| AES-256-GCM encryption | ✅ Client-side |
| Rate limiting | ✅ Active |
| CSRF protection | ✅ All forms |
| HTTP-only cookies | ✅ Session tokens |
| Security headers | ✅ CSP, HSTS, XFO |
| 2FA with lockout | ✅ TOTP + backup codes |
| SQL injection protection | ✅ Parameterized queries |
| XSS prevention | ✅ HTML escaping |

## 📊 Data Retention

| Data Type | Retention Period |
|-----------|------------------|
| Files | Until expiration (7 days default) |
| Chat Messages | 24 hours |
| Login History | 30 days |
| Security Logs | 30 days |
| Failed Login Attempts | 7 days |
| Sessions | 7 days of inactivity |

## 🔧 Technology Stack

- **Backend**: FastAPI (Python) with SQLAlchemy ORM
- **Database**: PostgreSQL
- **Encryption**: AES-256-GCM (client-side), Argon2id
- **Real-time**: WebSockets
- **Authentication**: HTTP-only cookies, CSRF tokens, TOTP 2FA
- **Rate Limiting**: SlowAPI
- **Frontend**: Vanilla JavaScript, HTML5, CSS3
- **Network**: Tor hidden service (.onion only)

## 📁 Repository Structure
Dispatch/
├── app.py # Main application
├── chat.py # Chat functionality
├── roles.py # Role/permission system
├── database.py # Database models
├── requirements.txt # Python dependencies
├── run_https.py # HTTPS production runner
├── reset_database.py # Database reset tool
├── cleanup.py # Cleanup script
├── expire_roles.py # Role expiration
├── templates/ # HTML templates
├── static/ # CSS, JS files
├── .env.example # Environment template
└── LICENSE # GPL v3


## 📝 License

**GNU General Public License v3.0**

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

## 📧 Contact

**Security Vulnerabilities:** dispatsh@proton.me  
**General Inquiries:** dispatsh@proton.me  
**PGP Key:** Available on request

## ⚠️ Disclaimer

This software is provided "as is" without warranties. While every effort is made to ensure security, no system is 100% secure. Use at your own risk.

## 🌟 Acknowledgments

- The Tor Project for providing anonymous communication
- FastAPI for the excellent web framework
- All security researchers who have audited this code

---

**Dispatch - Private. Secure. No Ads.**

