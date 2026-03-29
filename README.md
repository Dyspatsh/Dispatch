# Dispatch - Tor Privacy-Focused File Sharing Platform

## Features

- Client-side AES-256-GCM encryption
- Tor-only .onion access
- Role-based access (Free, Pro, Premium)
- Two-factor authentication (TOTP)
- Private encrypted chat with WebSocket
- Account recovery with 64-character recovery phrase
- Automatic file cleanup (expired files)
- Dark/Light theme

## Requirements

- Ubuntu 22.04/24.04
- Python 3.12+
- PostgreSQL 16+
- Tor

## Installation

1. Clone the repository
2. Create virtual environment: `python3 -m venv venv`
3. Activate: `source venv/bin/activate`
4. Install dependencies: `pip install -r requirements.txt`
5. Copy `.env.example` to `.env` and configure
6. Initialize database: `python3 -c "from database import init_db; init_db()"`
7. Configure Tor hidden service
8. Run: `python3 app.py`

## Security

- Argon2 password hashing
- XSS protection (HTML escaping)
- Account lockout (5 attempts = 30 min)
- Session management with HTTP-only cookies
- No IP logging
- Client-side encryption

## License

Private - All rights reserved
