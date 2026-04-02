from fastapi import Request, Cookie, Depends
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import html
import hashlib
import os
import secrets
from passlib.context import CryptContext
from dotenv import load_dotenv

load_dotenv()

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
IP_SALT = os.getenv("IP_SALT", secrets.token_hex(32))

def hash_ip_address(ip_address: str) -> str:
    if not ip_address or ip_address == "unknown":
        return None
    return hashlib.sha256(f"{IP_SALT}{ip_address}".encode()).hexdigest()

def escape_html(text: str) -> str:
    if not text:
        return ""
    return html.escape(text)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_client_ip(request: Request) -> str:
    if "x-forwarded-for" in request.headers:
        return request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def get_current_user(db, session_token: str = None):
    from database import Session as DBSession, User
    if not session_token:
        return None
    db_session = db.query(DBSession).filter(
        DBSession.session_token == session_token, 
        DBSession.expires_at > datetime.utcnow()
    ).first()
    if not db_session:
        return None
    
    db_session.last_activity = datetime.utcnow()
    db.commit()
    
    user = db_session.user
    if not user:
        return None
    if user and user.totp_enabled and not db_session.twofa_verified:
        return None
    if user and user.subscription_expires_at and user.subscription_expires_at < datetime.utcnow():
        user.role = "user"
        user.subscription_expires_at = None
        db.commit()
    return user

async def get_user_from_session(request: Request, db = Depends(), session_token: str = Cookie(None)):
    return get_current_user(db, session_token)

def log_security_event(db, user_id: int, action: str, action_type: str, details: str = None, request: Request = None):
    from database import SecurityLog
    ip_hash = None
    user_agent = None
    if request:
        client_ip = get_client_ip(request)
        ip_hash = hash_ip_address(client_ip) if client_ip != "unknown" else None
        user_agent = request.headers.get("user-agent")
    
    log = SecurityLog(
        user_id=user_id,
        action=action,
        action_type=action_type,
        details=details,
        ip_hash=ip_hash,
        user_agent=user_agent
    )
    db.add(log)
    db.commit()

def is_user_blocked(db, user_id: int, target_id: int) -> bool:
    from database import BlockedUser
    block = db.query(BlockedUser).filter(
        BlockedUser.user_id == target_id, 
        BlockedUser.blocked_user_id == user_id
    ).first()
    return block is not None
