from fastapi import FastAPI, Request, Form, Depends, File as FastAPIFile, UploadFile, Cookie, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, and_
from passlib.context import CryptContext
from datetime import datetime, timedelta
import secrets
import os
import json
import re
import pyotp
import qrcode
import io
import base64
import psutil
import logging
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from database import get_db, User, File, Payment, Session as DBSession, ChatConversation, ChatMessage, BlockedUser, LoginHistory, SecurityLog, CSRFToken, FailedLoginAttempt
from chat import router as chat_router
from roles import router as roles_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY must be set in .env file")

app = FastAPI(title="Dispatch")

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' ws: wss:"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Onion-Location"] = "http://pladaibgpkuswvqosgdszdtbgmxkfz55co66c4pmxg3ldmvyw2w45zyd.onion/"
    return response

app.include_router(chat_router)
app.include_router(roles_router)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/home/dispatch/dyspatch/uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_EXTENSIONS = {
    'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mp3', 'zip', '7z', 'tar', 'gz',
    'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'rtf', 'csv', 'json',
    'xml', 'md', 'log', 'py', 'c', 'cpp', 'h', 'java', 'js', 'css', 'html'
}

ALLOWED_MIME_TYPES = {
    'image/jpeg', 'image/png', 'image/gif', 'application/pdf', 'text/plain',
    'video/mp4', 'audio/mpeg', 'application/zip', 'application/x-7z-compressed',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/msword', 'application/vnd.ms-excel', 'text/csv', 'application/json',
    'text/xml', 'text/markdown', 'text/x-python', 'text/javascript', 'text/css'
}

def validate_file_type(filename: str, content_type: str = None) -> tuple:
    ext = filename.split('.')[-1].lower() if '.' in filename else ''
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"File type .{ext} is not allowed"
    if content_type and content_type not in ALLOWED_MIME_TYPES:
        return False, "File type not allowed"
    return True, ""

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def generate_recovery_phrase() -> str:
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return ''.join(secrets.choice(chars) for _ in range(64))

def escape_html(text: str) -> str:
    if not text:
        return ""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_aes_key(aes_key: bytes, user_password: str) -> tuple:
    salt = secrets.token_bytes(16)
    derived_key = derive_key_from_password(user_password, salt)
    iv = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_key = encryptor.update(aes_key) + encryptor.finalize()
    return salt, iv, encrypted_key, encryptor.tag

def decrypt_aes_key(encrypted_key_data: bytes, user_password: str, salt: bytes, iv: bytes, tag: bytes) -> bytes:
    derived_key = derive_key_from_password(user_password, salt)
    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_key_data) + decryptor.finalize()

def sanitize_filename(filename: str) -> str:
    return "".join(c for c in filename if c.isalnum() or c in "._- ")

def validate_username(username: str) -> tuple:
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    if len(username) > 16:
        return False, "Username cannot exceed 16 characters"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores"
    return True, ""

def validate_password(password: str) -> tuple:
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if len(password) > 16:
        return False, "Password cannot exceed 16 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one capital letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>/?\\|]', password):
        return False, "Password must contain at least one symbol (!@#$%^&* etc.)"
    return True, ""

def validate_pin(pin: str) -> tuple:
    if len(pin) != 6:
        return False, "PIN must be exactly 6 digits"
    if not pin.isdigit():
        return False, "PIN must contain only numbers"
    sequential = ['123456', '234567', '345678', '456789', '567890', '098765', '987654', '876543', '765432', '654321']
    if pin in sequential:
        return False, "PIN cannot be sequential numbers"
    if len(set(pin)) == 1:
        return False, "PIN cannot have all the same digit"
    return True, ""

def generate_csrf_token(user_id: int, db: Session) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=1)
    csrf = CSRFToken(token=token, user_id=user_id, expires_at=expires_at)
    db.add(csrf)
    db.commit()
    return token

def validate_csrf_token(token: str, user_id: int, db: Session) -> bool:
    csrf = db.query(CSRFToken).filter(
        CSRFToken.token == token,
        CSRFToken.user_id == user_id,
        CSRFToken.expires_at > datetime.utcnow()
    ).first()
    if csrf:
        db.delete(csrf)
        db.commit()
        return True
    return False

def log_security_event(db: Session, user_id: int, action: str, action_type: str, details: str = None, request: Request = None):
    ip_address = None
    user_agent = None
    if request:
        if "x-forwarded-for" in request.headers:
            ip_address = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        else:
            ip_address = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")
    
    log = SecurityLog(
        user_id=user_id,
        action=action,
        action_type=action_type,
        details=details,
        ip_address=ip_address,
        user_agent=user_agent
    )
    db.add(log)
    db.commit()

def record_failed_login(db: Session, username: str):
    now = datetime.utcnow()
    attempt = db.query(FailedLoginAttempt).filter(FailedLoginAttempt.username == username).first()
    if not attempt:
        attempt = FailedLoginAttempt(username=username, attempt_count=1, last_attempt=now)
        db.add(attempt)
    else:
        attempt.attempt_count += 1
        attempt.last_attempt = now
        if attempt.attempt_count >= 5:
            attempt.lock_until = now + timedelta(minutes=30)
    db.commit()

def reset_login_attempts(db: Session, username: str):
    attempt = db.query(FailedLoginAttempt).filter(FailedLoginAttempt.username == username).first()
    if attempt:
        db.delete(attempt)
        db.commit()

def check_login_lockout(db: Session, username: str) -> tuple:
    attempt = db.query(FailedLoginAttempt).filter(FailedLoginAttempt.username == username).first()
    if attempt and attempt.lock_until and datetime.utcnow() < attempt.lock_until:
        remaining = int((attempt.lock_until - datetime.utcnow()).total_seconds() / 60)
        return True, f"Account locked. Try again in {remaining} minutes"
    return False, ""

def is_user_blocked(db: Session, user_id: int, target_id: int) -> bool:
    block = db.query(BlockedUser).filter(BlockedUser.user_id == target_id, BlockedUser.blocked_user_id == user_id).first()
    return block is not None

def create_session(db: Session, user_id: int, twofa_verified: bool = False) -> str:
    session_token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(days=7)
    db_session = DBSession(session_token=session_token, user_id=user_id, expires_at=expires_at, twofa_verified=twofa_verified)
    db.add(db_session)
    db.commit()
    return session_token

def get_current_user(db: Session, session_token: str = None):
    if not session_token:
        return None
    db_session = db.query(DBSession).filter(DBSession.session_token == session_token, DBSession.expires_at > datetime.utcnow()).first()
    if not db_session:
        return None
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

async def get_user_from_session(request: Request, db: Session = Depends(get_db), session_token: str = Cookie(None)):
    return get_current_user(db, session_token)

def generate_recovery_codes() -> list:
    return [secrets.token_hex(4).upper() for _ in range(10)]

def hash_recovery_codes(codes: list) -> list:
    return [hash_password(code) for code in codes]

def verify_recovery_code(db: Session, user_id: int, code: str) -> bool:
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.recovery_codes_hash:
        return False
    hashed_codes = json.loads(user.recovery_codes_hash)
    code_upper = code.upper()
    for hashed_code in hashed_codes:
        if verify_password(code_upper, hashed_code):
            hashed_codes.remove(hashed_code)
            user.recovery_codes_hash = json.dumps(hashed_codes)
            db.commit()
            return True
    return False

@app.get("/")
async def root():
    return RedirectResponse(url="/home", status_code=303)

@app.get("/upgrade")
async def upgrade_redirect():
    return RedirectResponse(url="/roles/upgrade", status_code=303)

@app.get("/home", response_class=HTMLResponse)
async def home_page(request: Request, user = Depends(get_user_from_session)):
    return templates.TemplateResponse("home.html", {"request": request, "user": user})

@app.get("/foryou", response_class=HTMLResponse)
async def foryou_page(request: Request, user = Depends(get_user_from_session), db: Session = Depends(get_db)):
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    from sqlalchemy.orm import joinedload
    pending_files = db.query(File).options(joinedload(File.sender)).filter(File.recipient_id == user.id, File.status == "pending").all()
    return templates.TemplateResponse("foryou.html", {"request": request, "user": user, "pending_files": pending_files})

@app.get("/history", response_class=HTMLResponse)
async def history_page(request: Request, user = Depends(get_user_from_session), db: Session = Depends(get_db)):
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    from sqlalchemy.orm import joinedload
    from roles import get_history_retention_days
    
    retention_days = get_history_retention_days(user.role)
    cutoff_date = datetime.utcnow() - timedelta(days=retention_days) if retention_days != float("inf") else None
    if cutoff_date:
        received_files = db.query(File).options(joinedload(File.sender)).filter(File.recipient_id == user.id, File.created_at >= cutoff_date).order_by(desc(File.created_at)).all()
        sent_files = db.query(File).options(joinedload(File.recipient)).filter(File.sender_id == user.id, File.created_at >= cutoff_date).order_by(desc(File.created_at)).all()
    else:
        received_files = db.query(File).options(joinedload(File.sender)).filter(File.recipient_id == user.id).order_by(desc(File.created_at)).all()
        sent_files = db.query(File).options(joinedload(File.recipient)).filter(File.sender_id == user.id).order_by(desc(File.created_at)).all()
    return templates.TemplateResponse("history.html", {"request": request, "user": user, "received_files": received_files, "sent_files": sent_files})

@app.get("/about", response_class=HTMLResponse)
async def about(request: Request, user = Depends(get_user_from_session)):
    return templates.TemplateResponse("about.html", {"request": request, "user": user})

@app.get("/thecreator", response_class=HTMLResponse)
async def thecreator_page(request: Request, user = Depends(get_user_from_session)):
    return templates.TemplateResponse("thecreator.html", {"request": request, "user": user})

@app.get("/terms", response_class=HTMLResponse)
async def terms(request: Request, user = Depends(get_user_from_session)):
    return templates.TemplateResponse("terms.html", {"request": request, "user": user})

@app.get("/recovery", response_class=HTMLResponse)
async def recovery_page(request: Request, user = Depends(get_user_from_session)):
    if user:
        return RedirectResponse(url="/home", status_code=303)
    return templates.TemplateResponse("recovery.html", {"request": request, "user": user})

@app.post("/recovery")
# @limiter.limit("3/hour")
async def recovery_submit(request: Request, recovery_phrase: str = Form(...), new_username: str = Form(None), new_password: str = Form(...), confirm_password: str = Form(...), new_pin: str = Form(...), confirm_pin: str = Form(...), db: Session = Depends(get_db)):

    recovery_phrase = escape_html(recovery_phrase)
    new_username = escape_html(new_username) if new_username else None
    
    users = db.query(User).all()
    user = None
    for u in users:
        if verify_password(recovery_phrase, u.recovery_phrase_hash):
            user = u
            break
    
    if not user:
        return templates.TemplateResponse("recovery.html", {"request": request, "error": "Recovery failed"})
    
    if new_password != confirm_password:
        return templates.TemplateResponse("recovery.html", {"request": request, "error": "New passwords do not match"})
    
    valid, error = validate_password(new_password)
    if not valid:
        return templates.TemplateResponse("recovery.html", {"request": request, "error": error})
    
    if new_pin != confirm_pin:
        return templates.TemplateResponse("recovery.html", {"request": request, "error": "New PINs do not match"})
    
    valid, error = validate_pin(new_pin)
    if not valid:
        return templates.TemplateResponse("recovery.html", {"request": request, "error": error})
    
    user.password_hash = hash_password(new_password)
    user.pin_hash = hash_password(new_pin)
    
    if new_username and new_username != user.username:
        valid, error = validate_username(new_username)
        if not valid:
            return templates.TemplateResponse("recovery.html", {"request": request, "error": error})
        
        existing = db.query(User).filter(func.lower(User.username) == new_username.lower()).first()
        if existing:
            return templates.TemplateResponse("recovery.html", {"request": request, "error": "Username already taken"})
        
        user.username = new_username
    
    db.commit()
    
    log_security_event(db, user.id, "Account recovered", "account_recovery", f"Password and PIN reset", request)
    
    return templates.TemplateResponse("recovery.html", {"request": request, "success": "Account recovered successfully! You can now log in with your new credentials."})

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
# @limiter.limit("5/hour")
async def register(request: Request, username: str = Form(...), password: str = Form(...), pin: str = Form(...), terms: bool = Form(False), db: Session = Depends(get_db)):

    username = escape_html(username)
    
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"
    
    if not terms:
        if is_ajax:
            return {"success": False, "error": "You must accept the Terms of Service"}
        return templates.TemplateResponse("register.html", {"request": request, "error": "You must accept the Terms of Service"})
    
    valid, error = validate_username(username)
    if not valid:
        if is_ajax:
            return {"success": False, "error": error}
        return templates.TemplateResponse("register.html", {"request": request, "error": error})
    
    valid, error = validate_password(password)
    if not valid:
        if is_ajax:
            return {"success": False, "error": error}
        return templates.TemplateResponse("register.html", {"request": request, "error": error})
    
    valid, error = validate_pin(pin)
    if not valid:
        if is_ajax:
            return {"success": False, "error": error}
        return templates.TemplateResponse("register.html", {"request": request, "error": error})
    
    existing_user = db.query(User).filter(func.lower(User.username) == username.lower()).first()
    if existing_user:
        if is_ajax:
            return {"success": False, "error": "Username already exists"}
        return templates.TemplateResponse("register.html", {"request": request, "error": "Username already exists"})
    
    recovery_phrase = generate_recovery_phrase()
    user_count = db.query(User).count()
    role = "owner" if user_count == 0 else "user"
    
    new_user = User(
        username=username,
        password_hash=hash_password(password),
        pin_hash=hash_password(pin),
        recovery_phrase_hash=hash_password(recovery_phrase),
        role=role,
        read_receipts_enabled=True
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    log_security_event(db, new_user.id, "Account created", "account_creation", f"New account registered", request)
    
    if is_ajax:
        return {"success": True, "message": "Account created!", "recovery_phrase": recovery_phrase}
    
    return templates.TemplateResponse("register.html", {"request": request, "success": "Account created!", "recovery_phrase": recovery_phrase})

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, user = Depends(get_user_from_session)):
    if user:
        return RedirectResponse(url="/home", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
# @limiter.limit("5/minute")
async def login(request: Request, username: str = Form(...), password: str = Form(...), pin: str = Form(...), db: Session = Depends(get_db)):

    username = escape_html(username)
    
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"
    
    locked, message = check_login_lockout(db, username)
    if locked:
        if is_ajax:
            return {"success": False, "error": message}
        return templates.TemplateResponse("login.html", {"request": request, "error": message})
    
    user = db.query(User).filter(func.lower(User.username) == username.lower()).first()
    if not user:
        record_failed_login(db, username)
        log_security_event(db, 0, f"Failed login attempt for {username}", "login_failed", "Invalid username", request)
        if is_ajax:
            return {"success": False, "error": "Invalid credentials"}
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})
    
    if not verify_password(password, user.password_hash):
        record_failed_login(db, username)
        log_security_event(db, user.id, "Failed login attempt", "login_failed", "Invalid password", request)
        if is_ajax:
            return {"success": False, "error": "Invalid credentials"}
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})
    
    if not verify_password(pin, user.pin_hash):
        record_failed_login(db, username)
        log_security_event(db, user.id, "Failed login attempt", "login_failed", "Invalid PIN", request)
        if is_ajax:
            return {"success": False, "error": "Invalid credentials"}
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})
    
    if user.is_banned:
        log_security_event(db, user.id, "Blocked login attempt", "login_blocked", f"Account is banned: {user.ban_reason}", request)
        if is_ajax:
            return {"success": False, "error": "Account disabled"}
        return templates.TemplateResponse("login.html", {"request": request, "error": "Account disabled"})
    
    reset_login_attempts(db, username)
    
    login_record = LoginHistory(user_id=user.id)
    db.add(login_record)
    db.commit()
    
    if user.totp_enabled:
        log_security_event(db, user.id, "2FA required", "twofa_required", "User has 2FA enabled", request)
        if is_ajax:
            return {"success": True, "redirect": "/2fa-verify", "twofa": True}
        response = RedirectResponse(url="/2fa-verify", status_code=303)
        response.set_cookie(key="session_token", value="", httponly=True, secure=True, samesite="lax", max_age=300)
        db.commit()
        return response
    
    user.last_login = datetime.utcnow()
    db.commit()
    
    session_token = create_session(db, user.id, twofa_verified=True)
    
    log_security_event(db, user.id, "Login successful", "login_success", None, request)
    
    if is_ajax:
        return {"success": True, "redirect": "/home"}
    
    response = RedirectResponse(url="/home", status_code=303)
    response.set_cookie(key="session_token", value=session_token, httponly=True, secure=True, samesite="lax", max_age=604800)
    return response

@app.get("/2fa-verify", response_class=HTMLResponse)
async def verify_2fa_page(request: Request, session_token: str = Cookie(None), db: Session = Depends(get_db)):
    db_session = db.query(DBSession).filter(DBSession.session_token == session_token).first()
    if not db_session:
        return RedirectResponse(url="/login", status_code=303)
    if db_session.twofa_verified:
        return RedirectResponse(url="/home", status_code=303)
    return templates.TemplateResponse("2fa_verify.html", {"request": request})

@app.post("/2fa-verify")
# @limiter.limit("5/minute")
async def verify_2fa_submit(request: Request, code: str = Form(...), db: Session = Depends(get_db), session_token: str = Cookie(None)):
    db_session = db.query(DBSession).filter(DBSession.session_token == session_token).first()
    if not db_session:
        return RedirectResponse(url="/login", status_code=303)
    user = db_session.user
    
    if not user.totp_enabled:
        db_session.twofa_verified = True
        db.commit()
        return RedirectResponse(url="/home", status_code=303)
    
    attempt = db.query(FailedLoginAttempt).filter(FailedLoginAttempt.username == user.username).first()
    if attempt and attempt.lock_until and datetime.utcnow() < attempt.lock_until:
        remaining = int((attempt.lock_until - datetime.utcnow()).total_seconds() / 60)
        return templates.TemplateResponse("2fa_verify.html", {"request": request, "error": f"Too many failed attempts. Try again in {remaining} minutes"})
    
    totp = pyotp.TOTP(user.totp_secret)
    if totp.verify(code):
        if attempt:
            attempt.twofa_failures = 0
            db.commit()
        db_session.twofa_verified = True
        db_session.expires_at = datetime.utcnow() + timedelta(days=7)
        db.commit()
        user.last_login = datetime.utcnow()
        db.commit()
        log_security_event(db, user.id, "2FA verified", "twofa_success", None, request)
        response = RedirectResponse(url="/home", status_code=303)
        new_session_token = create_session(db, user.id, twofa_verified=True)
        response.set_cookie(key="session_token", value=new_session_token, httponly=True, secure=True, samesite="lax", max_age=604800)
        return response
    
    if verify_recovery_code(db, user.id, code):
        if attempt:
            attempt.twofa_failures = 0
            db.commit()
        db_session.twofa_verified = True
        db_session.expires_at = datetime.utcnow() + timedelta(days=7)
        db.commit()
        user.last_login = datetime.utcnow()
        db.commit()
        log_security_event(db, user.id, "2FA verified with recovery code", "twofa_recovery", None, request)
        response = RedirectResponse(url="/home", status_code=303)
        new_session_token = create_session(db, user.id, twofa_verified=True)
        response.set_cookie(key="session_token", value=new_session_token, httponly=True, secure=True, samesite="lax", max_age=604800)
        return response
    
    if not attempt:
        attempt = FailedLoginAttempt(username=user.username, twofa_failures=1, last_attempt=datetime.utcnow())
        db.add(attempt)
    else:
        attempt.twofa_failures += 1
        attempt.last_attempt = datetime.utcnow()
        if attempt.twofa_failures >= 5:
            attempt.lock_until = datetime.utcnow() + timedelta(minutes=15)
    db.commit()
    
    log_security_event(db, user.id, "Failed 2FA attempt", "twofa_failed", f"Attempt {attempt.twofa_failures}/5", request)
    
    return templates.TemplateResponse("2fa_verify.html", {"request": request, "error": "Invalid verification code"})

@app.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request, user = Depends(get_user_from_session), db: Session = Depends(get_db)):
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse("profile.html", {"request": request, "user": user, "now": datetime.utcnow()})

@app.get("/profile/enable-2fa", response_class=HTMLResponse)
async def enable_2fa_page(request: Request, user = Depends(get_user_from_session), db: Session = Depends(get_db)):
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        db.commit()
    totp = pyotp.TOTP(user.totp_secret)
    provisioning_uri = totp.provisioning_uri(user.username, issuer_name="Dispatch")
    qr = qrcode.make(provisioning_uri)
    img_buffer = io.BytesIO()
    qr.save(img_buffer, format='PNG')
    img_buffer.seek(0)
    qr_base64 = base64.b64encode(img_buffer.getvalue()).decode()
    recovery_codes = generate_recovery_codes()
    return templates.TemplateResponse("enable_2fa.html", {"request": request, "user": user, "qr_code": qr_base64, "recovery_codes": recovery_codes, "totp_secret": user.totp_secret})

@app.post("/profile/enable-2fa")
async def enable_2fa_submit(request: Request, code: str = Form(...), user = Depends(get_user_from_session), db: Session = Depends(get_db)):
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    totp = pyotp.TOTP(user.totp_secret)
    if totp.verify(code):
        user.totp_enabled = True
        recovery_codes = generate_recovery_codes()
        hashed_codes = hash_recovery_codes(recovery_codes)
        user.recovery_codes_hash = json.dumps(hashed_codes)
        db.commit()
        log_security_event(db, user.id, "2FA enabled", "twofa_enabled", None, request)
        return templates.TemplateResponse("enable_2fa.html", {"request": request, "user": user, "success": "2FA enabled successfully!", "recovery_codes": recovery_codes})
    else:
        return templates.TemplateResponse("enable_2fa.html", {"request": request, "user": user, "error": "Invalid verification code. Please try again."})

@app.post("/profile/disable-2fa")
async def disable_2fa(request: Request, user = Depends(get_user_from_session), db: Session = Depends(get_db)):
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    user.totp_enabled = False
    user.totp_secret = None
    user.recovery_codes_hash = None
    db.commit()
    log_security_event(db, user.id, "2FA disabled", "twofa_disabled", None, request)
    return RedirectResponse(url="/profile", status_code=303)

@app.get("/profile/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request, user = Depends(get_user_from_session)):
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse("change_password.html", {"request": request, "user": user})

@app.post("/profile/change-password")
async def change_password_submit(request: Request, current_password: str = Form(...), new_password: str = Form(...), confirm_password: str = Form(...), user = Depends(get_user_from_session), db: Session = Depends(get_db), session_token: str = Cookie(None)):
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    valid, error = validate_password(new_password)
    if not valid:
        return templates.TemplateResponse("change_password.html", {"request": request, "user": user, "error": error})
    if new_password != confirm_password:
        return templates.TemplateResponse("change_password.html", {"request": request, "user": user, "error": "New passwords do not match"})
    if not verify_password(current_password, user.password_hash):
        log_security_event(db, user.id, "Failed password change", "password_change_failed", "Incorrect current password", request)
        return templates.TemplateResponse("change_password.html", {"request": request, "user": user, "error": "Current password is incorrect"})
    
    user.password_hash = hash_password(new_password)
    db.commit()
    
    other_sessions = db.query(DBSession).filter(DBSession.user_id == user.id, DBSession.session_token != session_token).all()
    for s in other_sessions:
        db.delete(s)
    db.commit()
    
    log_security_event(db, user.id, "Password changed", "password_changed", "All other sessions terminated", request)
    
    return templates.TemplateResponse("change_password.html", {"request": request, "user": user, "success": "Password changed successfully"})

@app.get("/profile/change-pin", response_class=HTMLResponse)
async def change_pin_page(request: Request, user = Depends(get_user_from_session)):
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse("change_pin.html", {"request": request, "user": user})

@app.post("/profile/change-pin")
async def change_pin_submit(request: Request, current_pin: str = Form(...), new_pin: str = Form(...), confirm_pin: str = Form(...), user = Depends(get_user_from_session), db: Session = Depends(get_db)):
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    valid, error = validate_pin(new_pin)
    if not valid:
        return templates.TemplateResponse("change_pin.html", {"request": request, "user": user, "error": error})
    if new_pin != confirm_pin:
        return templates.TemplateResponse("change_pin.html", {"request": request, "user": user, "error": "New PINs do not match"})
    if not verify_password(current_pin, user.pin_hash):
        log_security_event(db, user.id, "Failed PIN change", "pin_change_failed", "Incorrect current PIN", request)
        return templates.TemplateResponse("change_pin.html", {"request": request, "user": user, "error": "Current PIN is incorrect"})
    user.pin_hash = hash_password(new_pin)
    db.commit()
    log_security_event(db, user.id, "PIN changed", "pin_changed", None, request)
    return templates.TemplateResponse("change_pin.html", {"request": request, "user": user, "success": "PIN changed successfully"})

@app.get("/profile/delete-account", response_class=HTMLResponse)
async def delete_account_page(request: Request, user = Depends(get_user_from_session)):
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse("delete_account.html", {"request": request, "user": user})

@app.post("/profile/delete-account")
async def delete_account_submit(request: Request, password: str = Form(...), confirm: str = Form(...), user = Depends(get_user_from_session), db: Session = Depends(get_db)):
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    if confirm != "DELETE":
        return templates.TemplateResponse("delete_account.html", {"request": request, "user": user, "error": "Type DELETE to confirm"})
    if not verify_password(password, user.password_hash):
        log_security_event(db, user.id, "Failed account deletion", "account_deletion_failed", "Incorrect password", request)
        return templates.TemplateResponse("delete_account.html", {"request": request, "user": user, "error": "Password is incorrect"})
    
    files = db.query(File).filter((File.sender_id == user.id) | (File.recipient_id == user.id)).all()
    for file in files:
        file_path = os.path.join(UPLOAD_DIR, file.encrypted_filename)
        if os.path.exists(file_path):
            os.remove(file_path)
    
    log_security_event(db, user.id, "Account deleted", "account_deleted", "User deleted their account", request)
    db.delete(user)
    db.commit()
    response = RedirectResponse(url="/home", status_code=303)
    response.delete_cookie("session_token")
    return response

@app.post("/profile/change-theme")
async def change_theme(theme: str = Form(...), user = Depends(get_user_from_session), db: Session = Depends(get_db)):
    if user and theme in ["light", "dark"]:
        user.theme = theme
        db.commit()
    return {"success": True}

@app.post("/profile/read-receipts")
async def update_read_receipts(
    request: Request,
    enabled: bool = Form(...),
    user = Depends(get_user_from_session),
    db: Session = Depends(get_db)
):
    if not user:
        return {"success": False, "error": "Not authenticated"}
    
    if not enabled and user.role not in ["premium", "owner"]:
        return {"success": False, "error": "Read receipts can only be disabled by Premium users"}
    
    user.read_receipts_enabled = enabled
    db.commit()
    
    log_security_event(db, user.id, f"Read receipts {'disabled' if not enabled else 'enabled'}", "read_receipts", None, request)
    
    return {"success": True, "message": f"Read receipts {'enabled' if enabled else 'disabled'}"}

@app.get("/send", response_class=HTMLResponse)
async def send_page(request: Request, user = Depends(get_user_from_session)):
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse("send.html", {"request": request, "user": user})

@app.post("/send/submit")
# @limiter.limit("20/hour")
async def submit_file(request: Request, recipient: str = Form(...), filename: str = Form(...), file_size: str = Form(...), options: str = Form(...), encrypted_file: UploadFile = FastAPIFile(...), encryption_key: str = Form(...), user = Depends(get_user_from_session), db: Session = Depends(get_db)):
    if not user:
        return {"success": False, "error": "Not authenticated"}
    
    recipient = escape_html(recipient)
    filename = escape_html(filename)
    
    try:
        file_size_int = int(file_size)
    except:
        file_size_int = 0
    
    encrypted_data = await encrypted_file.read()
    actual_size = len(encrypted_data)
    
    from roles import get_file_limits
    limits = get_file_limits(user)
    if actual_size > limits["max_file_size"]:
        return {"success": False, "error": f"File too large. Max {limits['max_file_size']/1073741824}GB"}
    
    valid, error = validate_file_type(filename, encrypted_file.content_type)
    if not valid:
        return {"success": False, "error": error}
    
    recipient_user = db.query(User).filter(func.lower(User.username) == recipient.lower()).first()
    if not recipient_user:
        return {"success": False, "error": "Recipient not found"}
    
    if recipient_user.id == user.id:
        return {"success": False, "error": "You cannot send files to yourself"}
    
    if is_user_blocked(db, user.id, recipient_user.id):
        return {"success": False, "error": "You are blocked by this user"}
    
    if is_user_blocked(db, recipient_user.id, user.id):
        return {"success": False, "error": "You have blocked this user"}
    
    active_files = db.query(File).filter(File.sender_id == user.id, File.status.in_(["pending", "accepted"])).count()
    if active_files >= limits["max_concurrent_files"]:
        return {"success": False, "error": f"Concurrent file limit reached. Max {limits['max_concurrent_files']}"}
    
    try:
        opts = json.loads(options)
    except:
        opts = {}
    if opts.get("password_protected") and opts.get("file_password"):
        opts["file_password_hash"] = hash_password(escape_html(opts["file_password"]))
        del opts["file_password"]
    
    pending_expiry = datetime.utcnow() + timedelta(hours=72)
    encrypted_filename = f"{secrets.token_hex(32)}.enc"
    file_path = os.path.join(UPLOAD_DIR, encrypted_filename)
    with open(file_path, "wb") as f:
        f.write(encrypted_data)
    
    try:
        aes_key = base64.b64decode(encryption_key)
        salt, iv, encrypted_key, tag = encrypt_aes_key(aes_key, recipient_user.password_hash)
        encrypted_key_data = base64.b64encode(salt + iv + encrypted_key + tag).decode('utf-8')
    except Exception as e:
        logger.error(f"Failed to encrypt key for file {filename}: {str(e)}")
        return {"success": False, "error": "Failed to encrypt file"}
    
    new_file = File(
        sender_id=user.id,
        recipient_id=recipient_user.id,
        filename=filename,
        encrypted_filename=encrypted_filename,
        encrypted_file_key=encrypted_key_data,
        file_size=actual_size,
        status="pending",
        options=json.dumps(opts),
        expires_at=pending_expiry
    )
    db.add(new_file)
    db.commit()
    
    log_security_event(db, user.id, f"File uploaded: {filename}", "file_upload", f"Sent to {recipient_user.username}, size: {actual_size} bytes", request)
    
    return {"success": True, "file_id": new_file.id}

@app.get("/files/accept/{file_id}")
async def accept_file(request: Request, file_id: int, user = Depends(get_user_from_session), db: Session = Depends(get_db)):
    if not user:
        return {"success": False, "error": "Not authenticated"}
    
    file = db.query(File).filter(
        File.id == file_id,
        File.recipient_id == user.id,
        File.status == "pending"
    ).with_for_update().first()
    
    if not file:
        return {"success": False, "error": "File not found"}
    
    file_path = os.path.join(UPLOAD_DIR, file.encrypted_filename)
    if not os.path.exists(file_path):
        return {"success": False, "error": "File no longer exists on server"}
    
    opts = json.loads(file.options) if file.options else {}
    if opts.get("custom_expiry"):
        expiry_days = min(opts["custom_expiry"], 7)
        file.expires_at = datetime.utcnow() + timedelta(days=expiry_days)
    else:
        file.expires_at = datetime.utcnow() + timedelta(days=7)
    file.status = "accepted"
    file.accepted_at = datetime.utcnow()
    db.commit()
    
    log_security_event(db, user.id, f"File accepted: {file.filename}", "file_accept", f"From user {file.sender.username}", request)
    
    return {"success": True, "file_id": file.id, "filename": file.filename}

@app.get("/files/decline/{file_id}")
async def decline_file(request: Request, file_id: int, user = Depends(get_user_from_session), db: Session = Depends(get_db)):
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    file = db.query(File).filter(File.id == file_id, File.recipient_id == user.id, File.status == "pending").first()
    if not file:
        return RedirectResponse(url="/foryou", status_code=303)
    file_path = os.path.join(UPLOAD_DIR, file.encrypted_filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    file.status = "declined"
    db.commit()
    
    log_security_event(db, user.id, f"File declined: {file.filename}", "file_decline", f"From user {file.sender.username}", request)
    
    return RedirectResponse(url="/foryou", status_code=303)

@app.get("/files/cancel/{file_id}")
async def cancel_file(request: Request, file_id: int, user = Depends(get_user_from_session), db: Session = Depends(get_db)):
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    file = db.query(File).filter(File.id == file_id, File.sender_id == user.id, File.status == "pending").first()
    if not file:
        return RedirectResponse(url="/history", status_code=303)
    file_path = os.path.join(UPLOAD_DIR, file.encrypted_filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    file.status = "cancelled"
    db.commit()
    
    log_security_event(db, user.id, f"File cancelled: {file.filename}", "file_cancel", f"To user {file.recipient.username}", request)
    
    return RedirectResponse(url="/history", status_code=303)

@app.get("/files/download/{file_id}")
async def download_file(
    request: Request,
    file_id: int,
    user = Depends(get_user_from_session),
    db: Session = Depends(get_db),
    password: str = None
):
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    
    file = db.query(File).filter(File.id == file_id, File.recipient_id == user.id, File.status == "accepted").first()
    if not file:
        return RedirectResponse(url="/history", status_code=303)
    
    file_path = os.path.join(UPLOAD_DIR, file.encrypted_filename)
    if not os.path.exists(file_path):
        file.status = "expired"
        db.commit()
        return RedirectResponse(url="/history", status_code=303)
    
    opts = json.loads(file.options) if file.options else {}
    if opts.get("password_protected"):
        if not password:
            return templates.TemplateResponse("password_form.html", {"request": request, "file_id": file_id, "filename": file.filename, "user": user})
        elif not verify_password(password, opts.get("file_password_hash")):
            return templates.TemplateResponse("password_form.html", {"request": request, "file_id": file_id, "filename": file.filename, "user": user, "error": "Incorrect password"})
    
    if file.encrypted_file_key:
        try:
            encrypted_key_data = base64.b64decode(file.encrypted_file_key)
            salt = encrypted_key_data[:16]
            iv = encrypted_key_data[16:28]
            tag = encrypted_key_data[-16:]
            encrypted_key = encrypted_key_data[28:-16]
            
            aes_key = decrypt_aes_key(encrypted_key, user.password_hash, salt, iv, tag)
            
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            file_iv = encrypted_data[:12]
            file_tag = encrypted_data[-16:]
            encrypted_content = encrypted_data[12:-16]
            
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(file_iv, file_tag), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_content) + decryptor.finalize()
            
            safe_filename = sanitize_filename(file.filename)
            
            log_security_event(db, user.id, f"File downloaded: {file.filename}", "file_download", f"From user {file.sender.username}", request)
            
            return Response(
                content=decrypted_data,
                media_type="application/octet-stream",
                headers={"Content-Disposition": f'attachment; filename="{safe_filename}"'}
            )
        except Exception as e:
            logger.error(f"Decryption failed for file {file_id}: {str(e)}")
            return templates.TemplateResponse("password_form.html", {"request": request, "file_id": file_id, "filename": file.filename, "user": user, "error": "Decryption failed"})
    
    safe_filename = sanitize_filename(file.filename)
    return FileResponse(file_path, media_type="application/octet-stream", filename=file.filename, headers={"Content-Disposition": f'attachment; filename="{safe_filename}"'})

@app.get("/search")
# @limiter.limit("10/minute")
async def search_users(request: Request, q: str, user = Depends(get_user_from_session), db: Session = Depends(get_db)):
    if not user:
        return {"users": []}
    q = escape_html(q)
    users = db.query(User).filter(
        func.lower(User.username).contains(q.lower()),
        User.id != user.id,
        User.is_banned == False,
        User.role.in_(['user', 'pro', 'premium', 'owner'])
    ).limit(10).all()
    return {"users": [{"id": u.id, "username": u.username} for u in users]}

@app.get("/logout")
async def logout(request: Request, session_token: str = Cookie(None), db: Session = Depends(get_db)):
    if session_token:
        db_session = db.query(DBSession).filter(DBSession.session_token == session_token).first()
        if db_session and db_session.user:
            log_security_event(db, db_session.user.id, "Logout", "logout", None, request)
        db.delete(db_session) if db_session else None
        db.commit()
    response = RedirectResponse(url="/home", status_code=303)
    response.delete_cookie("session_token")
    return response

@app.get("/api/user/{username}")
async def get_user_profile(username: str, session_token: str = Cookie(None), db: Session = Depends(get_db)):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}
    
    target_user = db.query(User).filter(func.lower(User.username) == username.lower()).first()
    if not target_user:
        return {"success": False, "error": "User not found"}
    
    files_sent = db.query(File).filter(File.sender_id == target_user.id).all()
    files_received = db.query(File).filter(File.recipient_id == target_user.id).all()
    
    files_sent_count = len(files_sent)
    files_received_count = len(files_received)
    total_storage = sum(f.file_size for f in files_sent) + sum(f.file_size for f in files_received)
    total_storage_gb = round(total_storage / (1024 * 1024 * 1024), 2)
    
    active_files = db.query(File).filter(
        File.sender_id == target_user.id,
        File.status.in_(["pending", "accepted"])
    ).count()
    
    return {
        "success": True,
        "user": {
            "id": target_user.id,
            "username": target_user.username,
            "role": target_user.role,
            "created_at": target_user.created_at.isoformat(),
            "bio": target_user.bio or None,
            "subscription_expires_at": target_user.subscription_expires_at.isoformat() if target_user.subscription_expires_at else None
        },
        "file_stats": {
            "files_sent": files_sent_count,
            "files_received": files_received_count,
            "storage_used_gb": total_storage_gb,
            "active_files": active_files
        }
    }

@app.post("/api/user/bio")
async def update_bio(
    bio: str = Form(""),
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}
    
    if user.role not in ['pro', 'premium', 'owner']:
        return {"success": False, "error": "Bio requires Pro or Premium subscription"}
    
    if len(bio) > 200:
        return {"success": False, "error": "Bio must be 200 characters or less"}
    
    user.bio = escape_html(bio) if bio else None
    db.commit()
    
    return {"success": True, "message": "Bio updated"}

@app.get("/api/sessions")
async def get_sessions(session_token: str = Cookie(None), db: Session = Depends(get_db)):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}
    
    cutoff_date = datetime.utcnow() - timedelta(days=30)
    sessions = db.query(LoginHistory).filter(
        LoginHistory.user_id == user.id,
        LoginHistory.login_time >= cutoff_date
    ).order_by(LoginHistory.login_time.desc()).all()
    
    return {
        "success": True,
        "sessions": [{"login_time": s.login_time.isoformat()} for s in sessions]
    }

@app.get("/api/security-logs")
async def get_security_logs(session_token: str = Cookie(None), db: Session = Depends(get_db)):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}
    
    cutoff_date = datetime.utcnow() - timedelta(days=30)
    logs = db.query(SecurityLog).filter(
        SecurityLog.user_id == user.id,
        SecurityLog.created_at >= cutoff_date
    ).order_by(SecurityLog.created_at.desc()).limit(50).all()
    
    return {
        "success": True,
        "logs": [
            {
                "action": log.action,
                "action_type": log.action_type,
                "details": log.details,
                "created_at": log.created_at.isoformat()
            } for log in logs
        ]
    }

@app.get("/admin", response_class=HTMLResponse)
async def admin_panel(request: Request, user = Depends(get_user_from_session), db: Session = Depends(get_db)):
    if not user or user.role != "owner":
        return RedirectResponse(url="/home", status_code=303)
    
    csrf_token = generate_csrf_token(user.id, db)
    
    return templates.TemplateResponse("admin_simple.html", {
        "request": request,
        "user": user,
        "now": datetime.utcnow(),
        "csrf_token": csrf_token
    })

@app.get("/admin/stats")
async def admin_stats(user = Depends(get_user_from_session), db: Session = Depends(get_db)):
    if not user or user.role != "owner":
        return {"success": False, "error": "Unauthorized"}
    
    total_users = db.query(User).count()
    active_users = db.query(User).filter(User.last_login > datetime.utcnow() - timedelta(days=7)).count()
    total_files = db.query(File).count()
    total_storage = db.query(func.sum(File.file_size)).scalar() or 0
    total_storage_gb = round(total_storage / (1024 * 1024 * 1024), 1)
    
    return {
        "success": True,
        "total_users": total_users,
        "active_users": active_users,
        "total_files": total_files,
        "total_storage": total_storage_gb,
        "cpu": psutil.cpu_percent(interval=1),
        "memory": psutil.virtual_memory().percent,
        "disk": psutil.disk_usage('/').percent,
        "uptime": str(datetime.utcnow() - datetime.fromtimestamp(psutil.boot_time())).split('.')[0]
    }

@app.get("/admin/search-users")
async def admin_search_users(q: str = "", role: str = "all", status: str = "all", user = Depends(get_user_from_session), db: Session = Depends(get_db)):
    if not user or user.role != "owner":
        return {"success": False, "error": "Unauthorized"}
    
    query = db.query(User)
    if q:
        query = query.filter(func.lower(User.username).contains(q.lower()))
    if role != "all":
        query = query.filter(User.role == role, User.is_banned == False)
    if status == "banned":
        query = query.filter(User.is_banned == True)
    elif status == "active":
        query = query.filter(User.is_banned == False)
    
    users = query.order_by(desc(User.created_at)).limit(50).all()
    
    result = []
    for u in users:
        days_left = None
        if u.subscription_expires_at and u.role in ["pro", "premium"]:
            days = (u.subscription_expires_at - datetime.utcnow()).days
            days_left = days if days > 0 else 0
        
        result.append({
            "id": u.id,
            "username": u.username,
            "role": u.role,
            "files": db.query(File).filter(File.sender_id == u.id).count(),
            "storage_gb": round((db.query(func.sum(File.file_size)).filter(File.sender_id == u.id).scalar() or 0) / (1024 * 1024 * 1024), 2),
            "created_at": u.created_at.strftime("%Y-%m-%d") if u.created_at else "Unknown",
            "last_login": u.last_login.strftime("%Y-%m-%d") if u.last_login else "Never",
            "is_banned": u.is_banned,
            "ban_reason": u.ban_reason,
            "days_left": days_left,
            "subscription_expires_at": u.subscription_expires_at.isoformat() if u.subscription_expires_at else None
        })
    
    return {"success": True, "users": result}

@app.post("/admin/user/ban/{user_id}")
async def admin_ban_user(
    request: Request,
    user_id: int,
    reason: str = Form(...),
    csrf_token: str = Form(...),
    user = Depends(get_user_from_session),
    db: Session = Depends(get_db)
):
    if not user or user.role != "owner":
        return {"success": False, "error": "Unauthorized"}
    
    if not validate_csrf_token(csrf_token, user.id, db):
        return {"success": False, "error": "Invalid CSRF token"}
    
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        return {"success": False, "error": "User not found"}
    
    sessions = db.query(DBSession).filter(DBSession.user_id == target.id).all()
    session_count = len(sessions)
    for s in sessions:
        db.delete(s)
    
    target.is_banned = True
    target.ban_reason = reason
    db.commit()
    
    log_security_event(db, user.id, f"User banned: {target.username}", "admin_ban", f"Reason: {reason}, {session_count} sessions terminated", request)
    log_security_event(db, target.id, f"Account banned by admin", "account_banned", f"Reason: {reason}", request)
    
    return {"success": True, "message": f"User {target.username} banned, {session_count} sessions terminated"}

@app.post("/admin/user/unban/{user_id}")
async def admin_unban_user(
    request: Request,
    user_id: int,
    csrf_token: str = Form(...),
    user = Depends(get_user_from_session),
    db: Session = Depends(get_db)
):
    if not user or user.role != "owner":
        return {"success": False, "error": "Unauthorized"}
    
    if not validate_csrf_token(csrf_token, user.id, db):
        return {"success": False, "error": "Invalid CSRF token"}
    
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        return {"success": False, "error": "User not found"}
    
    target.is_banned = False
    target.ban_reason = None
    db.commit()
    
    log_security_event(db, user.id, f"User unbanned: {target.username}", "admin_unban", None, request)
    log_security_event(db, target.id, f"Account unbanned by admin", "account_unbanned", None, request)
    
    return {"success": True, "message": f"User {target.username} unbanned"}

@app.post("/admin/user/role/{user_id}")
async def admin_change_role(
    request: Request,
    user_id: int,
    role: str = Form(...),
    csrf_token: str = Form(...),
    user = Depends(get_user_from_session),
    db: Session = Depends(get_db)
):
    if not user or user.role != "owner":
        return {"success": False, "error": "Unauthorized"}
    
    if not validate_csrf_token(csrf_token, user.id, db):
        return {"success": False, "error": "Invalid CSRF token"}
    
    if role not in ["user", "pro", "premium"]:
        return {"success": False, "error": "Invalid role"}
    
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        return {"success": False, "error": "User not found"}
    
    old_role = target.role
    target.role = role
    
    if role in ["pro", "premium"]:
        target.subscription_expires_at = datetime.utcnow() + timedelta(days=30)
    else:
        target.subscription_expires_at = None
    
    db.commit()
    
    log_security_event(db, user.id, f"User role changed: {target.username}", "admin_role_change", f"From {old_role} to {role}", request)
    log_security_event(db, target.id, f"Account role changed to {role}", "role_changed", f"Expires in 30 days", request)
    
    return {"success": True, "message": f"User {target.username} role changed to {role} (expires in 30 days)"}

@app.post("/admin/user/delete/{user_id}")
async def admin_delete_user(
    request: Request,
    user_id: int,
    csrf_token: str = Form(...),
    user = Depends(get_user_from_session),
    db: Session = Depends(get_db)
):
    if not user or user.role != "owner":
        return {"success": False, "error": "Unauthorized"}
    
    if not validate_csrf_token(csrf_token, user.id, db):
        return {"success": False, "error": "Invalid CSRF token"}
    
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        return {"success": False, "error": "User not found"}
    
    files = db.query(File).filter((File.sender_id == target.id) | (File.recipient_id == target.id)).all()
    for f in files:
        file_path = os.path.join(UPLOAD_DIR, f.encrypted_filename)
        if os.path.exists(file_path):
            os.remove(file_path)
    
    log_security_event(db, user.id, f"User deleted: {target.username}", "admin_delete", f"All associated data removed", request)
    
    db.delete(target)
    db.commit()
    
    return {"success": True, "message": f"User {target.username} and all associated data deleted", "redirect": "/home"}

@app.get("/admin/user/{user_id}")
async def admin_user_details(user_id: int, user = Depends(get_user_from_session), db: Session = Depends(get_db)):
    if not user or user.role != "owner":
        return {"success": False, "error": "Unauthorized"}
    
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        return {"success": False, "error": "User not found"}
    
    files_sent = db.query(File).filter(File.sender_id == target.id).all()
    files_received = db.query(File).filter(File.recipient_id == target.id).all()
    
    files_sent_count = len(files_sent)
    files_received_count = len(files_received)
    storage_sent = sum(f.file_size for f in files_sent)
    storage_received = sum(f.file_size for f in files_received)
    
    files_by_status = {
        "pending": len([f for f in files_sent if f.status == "pending"]),
        "accepted": len([f for f in files_sent if f.status == "accepted"]),
        "declined": len([f for f in files_sent if f.status == "declined"]),
        "downloaded": len([f for f in files_sent if f.status == "downloaded"])
    }
    
    active_chats = db.query(ChatConversation).filter(
        ((ChatConversation.user1_id == target.id) | (ChatConversation.user2_id == target.id)),
        ChatConversation.status == "active"
    ).count()
    messages_sent = db.query(ChatMessage).filter(ChatMessage.sender_id == target.id).count()
    
    return {
        "success": True,
        "user": {
            "id": target.id,
            "username": target.username,
            "role": target.role,
            "twofa_enabled": target.totp_enabled,
            "created_at": target.created_at.isoformat(),
            "last_login": target.last_login.isoformat() if target.last_login else None,
            "is_banned": target.is_banned,
            "ban_reason": target.ban_reason,
            "subscription_expires_at": target.subscription_expires_at.isoformat() if target.subscription_expires_at else None
        },
        "file_stats": {
            "files_sent": files_sent_count,
            "files_received": files_received_count,
            "storage_sent_gb": round(storage_sent / (1024 * 1024 * 1024), 2),
            "storage_received_gb": round(storage_received / (1024 * 1024 * 1024), 2),
            "by_status": files_by_status
        },
        "chat_stats": {
            "active_chats": active_chats,
            "messages_sent": messages_sent
        }
    }

@app.get("/admin/chart/user-growth")
async def chart_user_growth(days: int = 30, session_token: str = Cookie(None), db: Session = Depends(get_db)):
    user = get_current_user(db, session_token)
    if not user or user.role != "owner":
        return {"success": False, "error": "Unauthorized"}
    
    labels = []
    values = []
    
    for i in range(days):
        day_start = datetime.utcnow() - timedelta(days=days-i-1)
        day_end = day_start + timedelta(days=1)
        count = db.query(User).filter(User.created_at >= day_start, User.created_at < day_end).count()
        labels.append(day_start.strftime("%m/%d"))
        values.append(count)
    
    return {"success": True, "labels": labels, "values": values}

@app.get("/admin/chart/file-activity")
async def chart_file_activity(days: int = 30, type: str = "uploads", session_token: str = Cookie(None), db: Session = Depends(get_db)):
    user = get_current_user(db, session_token)
    if not user or user.role != "owner":
        return {"success": False, "error": "Unauthorized"}
    
    labels = []
    values = []
    
    for i in range(days):
        day_start = datetime.utcnow() - timedelta(days=days-i-1)
        day_end = day_start + timedelta(days=1)
        
        if type == "uploads":
            count = db.query(File).filter(File.created_at >= day_start, File.created_at < day_end).count()
        else:
            count = db.query(File).filter(File.downloaded_at >= day_start, File.downloaded_at < day_end).count()
        
        labels.append(day_start.strftime("%m/%d"))
        values.append(count)
    
    return {"success": True, "labels": labels, "values": values}

@app.get("/admin/chart/storage-by-role")
async def chart_storage_by_role(session_token: str = Cookie(None), db: Session = Depends(get_db)):
    user = get_current_user(db, session_token)
    if not user or user.role != "owner":
        return {"success": False, "error": "Unauthorized"}
    
    free_result = db.query(func.sum(File.file_size)).join(User, File.sender_id == User.id).filter(User.role == "user", User.is_banned == False).scalar()
    pro_result = db.query(func.sum(File.file_size)).join(User, File.sender_id == User.id).filter(User.role == "pro", User.is_banned == False).scalar()
    premium_result = db.query(func.sum(File.file_size)).join(User, File.sender_id == User.id).filter(User.role == "premium", User.is_banned == False).scalar()
    
    free_storage = float(free_result) if free_result else 0
    pro_storage = float(pro_result) if pro_result else 0
    premium_storage = float(premium_result) if premium_result else 0
    
    return {
        "success": True,
        "free": round(free_storage / (1024 * 1024 * 1024), 1),
        "pro": round(pro_storage / (1024 * 1024 * 1024), 1),
        "premium": round(premium_storage / (1024 * 1024 * 1024), 1)
    }

@app.get("/admin/chart/storage-trend")
async def chart_storage_trend(days: int = 30, session_token: str = Cookie(None), db: Session = Depends(get_db)):
    user = get_current_user(db, session_token)
    if not user or user.role != "owner":
        return {"success": False, "error": "Unauthorized"}
    
    labels = []
    values = []
    
    for i in range(days):
        day_end = datetime.utcnow() - timedelta(days=days-i-1)
        storage_result = db.query(func.sum(File.file_size)).filter(File.created_at <= day_end).scalar()
        storage = float(storage_result) if storage_result else 0
        labels.append(day_end.strftime("%m/%d"))
        values.append(round(storage / (1024 * 1024 * 1024), 1))
    
    start_value = values[0] if values else 0
    end_value = values[-1] if values else 0
    growth = end_value - start_value
    growth_percent = round((growth / start_value * 100), 1) if start_value > 0 else 0
    
    return {
        "success": True,
        "labels": labels,
        "values": values,
        "start_value": start_value,
        "end_value": end_value,
        "growth": round(growth, 1),
        "growth_percent": growth_percent
    }

@app.get("/admin/chart/activity-heatmap")
async def chart_activity_heatmap(days: int = 30, session_token: str = Cookie(None), db: Session = Depends(get_db)):
    user = get_current_user(db, session_token)
    if not user or user.role != "owner":
        return {"success": False, "error": "Unauthorized"}
    
    activities = []
    
    for i in range(days):
        day_start = datetime.utcnow() - timedelta(days=days-i-1)
        day_end = day_start + timedelta(days=1)
        
        login_count = db.query(LoginHistory).filter(LoginHistory.login_time >= day_start, LoginHistory.login_time < day_end).count()
        upload_count = db.query(File).filter(File.created_at >= day_start, File.created_at < day_end).count()
        download_count = db.query(File).filter(File.downloaded_at >= day_start, File.downloaded_at < day_end).count()
        
        total = login_count + upload_count + download_count
        
        activities.append({
            "date": day_start.strftime("%Y-%m-%d"),
            "count": total
        })
    
    return {"success": True, "activities": activities}

@app.get("/files/raw/{file_id}")
async def download_raw_file(
    file_id: int,
    user = Depends(get_user_from_session),
    db: Session = Depends(get_db)
):
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    
    file = db.query(File).filter(File.id == file_id, File.recipient_id == user.id, File.status == "accepted").first()
    if not file:
        return RedirectResponse(url="/history", status_code=303)
    
    file_path = os.path.join(UPLOAD_DIR, file.encrypted_filename)
    if not os.path.exists(file_path):
        return RedirectResponse(url="/history", status_code=303)
    
    return FileResponse(file_path, media_type="application/octet-stream", filename=f"{file.filename}.encrypted")

@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    user = await get_user_from_session(request)
    return templates.TemplateResponse("404.html", {"request": request, "user": user}, status_code=404)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
