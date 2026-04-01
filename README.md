# Dispatch - Tor Privacy-Focused File Sharing Platform

Dispatch is a Tor-only, privacy-focused file sharing and communication platform where users can send encrypted files, engage in private and group chats, and manage their digital presence with complete anonymity.

## Features

### File Sharing
- **Client-side AES-256-GCM encryption** - Files encrypted before upload, keys never leave your browser
- **Drag & drop upload** with queue management and progress bars
- **Multiple file selection** with individual cancel and retry
- **File preview** - Thumbnails for images, file-type icons for documents
- **Custom expiration** (Pro/Premium) - Set files to expire in 1-7 days
- **Password protection** (Pro/Premium) - Add password to files
- **Automatic cleanup** - Expired files auto-delete

### Private Chat
- **End-to-end encrypted messages** - Auto-delete after 24 hours
- **Read receipts** - Sent, Delivered, Read status (Premium can disable)
- **Typing indicators** - Real-time typing status
- **Message search** (Pro+) - Search through conversation history
- **Message reactions** - [Like], [Thanks], [Agree], [Helpful]

### Group Chats (Premium)
- **Create groups** with unlimited members
- **Group management** - Promote members to admin, remove users, edit description
- **Member list** with role indicators (Owner, Admin, Member)
- **Leave group** or **delete group** (owner only)
- **Group invitations** with accept/decline/cancel

### Security
- **Tor-only access** - No IP logging, complete anonymity
- **Two-factor authentication** (TOTP) with backup codes
- **Account lockout** - 5 failed attempts = 30-minute lockout
- **Argon2id password hashing** - Most secure password hashing algorithm
- **HTTP-only cookies** - Protected against XSS attacks
- **HTML escaping** - All user input sanitized
- **Session management** - View and terminate active sessions

### User Profiles
- **Bio** (Pro/Premium) - 200 character limit
- **File statistics** - Files sent/received, storage used, active files
- **Clickable usernames** - View any user's profile from chat
- **Join date** and account age display

### Admin Dashboard (Owner only)
- **Real-time charts** - User growth, file activity, storage by role
- **System health gauges** - CPU, memory, disk usage
- **Activity heatmap** - Visual user activity tracking
- **User management** - Search, filter, ban, unban, role change, delete
- **Batch actions** - Select multiple users for bulk operations
- **Data export** - Export users and files to CSV
- **Failed login monitoring**

### Account Management
- **Theme selection** - Light/Dark mode
- **Change password and PIN**
- **Delete account** - Permanent deletion with confirmation
- **Login history** - Last 30 days of activity
- **Blocked users** - Manage blocked contacts
- **2FA management** - Enable/disable with backup codes

## Requirements

- Ubuntu 22.04/24.04
- Python 3.12+
- PostgreSQL 16+
- Tor

## Installation

```bash
# Clone the repository
git clone https://github.com/Dyspatsh/Dispatch.git
cd Dispatch

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy environment configuration
cp .env.example .env
# Edit .env with your database credentials

# Initialize database
python3 -c "from database import init_db; init_db()"

# Configure Tor hidden service
sudo nano /etc/tor/torrc
# Add:
# HiddenServiceDir /var/lib/tor/dispatch/
# HiddenServicePort 80 127.0.0.1:8000

# Restart Tor
sudo systemctl restart tor

# Run the application
python3 app.py
