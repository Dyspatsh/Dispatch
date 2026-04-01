# Dispatch - Personal Tor File Sharing Platform

This is my personal file sharing and communication platform running as a Tor hidden service. I am sharing the source code for transparency and trust, not as a turnkey solution for others to deploy.

## What This Is

A Tor-only platform where I can:
- Send and receive encrypted files
- Chat privately with end-to-end encryption
- Manage user accounts with roles (Free, Pro, Premium, Owner)
- Monitor system health and user activity

The platform has no advertisements, popups, or sponsored content.

## Important Disclosures

In the interest of transparency, here is how the platform actually works:

- **File Encryption Keys**: Files are encrypted in the browser with AES-256-GCM. The encryption key is then encrypted with the recipient's password hash and stored on the server. As the server owner, I have access to the encrypted key and the recipient's password hash. Decryption would require both.
- **IP Logging**: The server logs Tor exit node IP addresses for security purposes (rate limiting, login lockouts, security logs). These are stored for 30 days and automatically deleted. Your real IP never reaches the server because all traffic goes through Tor.
- **No Perfect Forward Secrecy**: If the server is compromised, stored encrypted keys could potentially be decrypted if user passwords are also compromised.
- **No Warranty**: This software is provided "as is" without warranties.

## Current Features

### File Sharing
- AES-256-GCM client-side encryption
- Drag and drop upload with queue management
- File preview for images
- Custom expiration (Pro/Premium, 1-7 days)
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
- Leave or delete group (owner only)

### Security Features
- Tor-only access (real IP never exposed)
- Two-factor authentication (TOTP) with backup codes
- Account lockout: 5 failed logins = 30 minutes, 5 failed 2FA = 15 minutes
- Argon2id password hashing
- HTTP-only cookies, CSRF protection
- HTML escaping for XSS prevention
- Rate limiting: login (5/min), registration (5/hour), uploads (20/hour), search (10/min)
- Security headers (CSP, X-Frame-Options, etc.)
- Session revocation on password change
- Security logs stored for 30 days

### User Profiles (Pro/Premium)
- Bio (200 character limit)
- File statistics (sent/received, storage used, active files)
- Clickable usernames showing profile info

### Admin Dashboard (Owner only)
- User growth charts
- System health monitoring (CPU, memory, disk)
- Activity heatmap
- User management (search, filter, ban, unban, role change, delete)
- Batch actions for multiple users
- Failed login monitoring

### Account Management
- Light/Dark theme
- Change password and PIN
- Delete account (permanent)
- Login history (30 days)
- Security logs (30 days)
- Blocked users list

## Role Limits

| Feature | Free | Pro | Premium |
|---------|------|-----|---------|
| Max File Size | 1 GB | 5 GB | 10 GB |
| Concurrent Files | 10 | 50 | 100 |
| History Retention | 30 days | 60 days | 90 days |
| Private Chat | No | Yes (100 char) | Yes (200 char) |
| Group Chats | No | No | Yes |
| Custom Expiry | No | Yes | Yes |
| Password Protection | No | Yes | Yes |
| Bio | No | Yes | Yes |
| Read Receipts Toggle | No | No | Yes |
| Subscription Duration | - | 30 days | 30 days |

## Data Retention

| Data Type | Retention Period |
|-----------|------------------|
| Files | Until expiration (7 days default) or manual deletion |
| Chat Messages | 24 hours |
| Login History | 30 days |
| Security Logs | 30 days |
| Failed Login Attempts | 7 days |
| Sessions | 7 days of inactivity |

## Technology Stack

- **Backend**: FastAPI (Python) with SQLAlchemy ORM
- **Database**: PostgreSQL
- **Encryption**: AES-256-GCM (client-side), Argon2id (password hashing)
- **Real-time**: WebSockets
- **Authentication**: HTTP-only cookies, CSRF tokens, TOTP 2FA
- **Rate Limiting**: SlowAPI
- **Frontend**: Vanilla JavaScript, HTML5, CSS3
- **Network**: Tor hidden service (.onion only)

## My Setup

This runs on my own server with:
- Ubuntu 22.04
- Python 3.12
- PostgreSQL 16
- Tor service

## License

GNU General Public License v3.0

## Contact

dispatsh@proton.me
