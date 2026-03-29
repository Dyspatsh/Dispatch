from fastapi import FastAPI, Request, Form, Depends, File as FastAPIFile, UploadFile, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
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
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy import func, desc

from database import get_db, User, File, Payment, Session as DBSession, ChatConversation, ChatMessage, BlockedUser
from chat import router as chat_router
from roles import router as roles_router

load_dotenv()

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-this")

app = FastAPI(title="Dispatch")

# Account lockout tracking
login_attempts = {}

class HTTPSRedirectMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        forwarded_proto = request.headers.get("x-forwarded-proto")
        if forwarded_proto == "https" or request.url.scheme == "https":
            url = str(request.url).replace("https://", "http://", 1)
            response = RedirectResponse(url, status_code=307)
            response.headers["Upgrade-Insecure-Requests"] = "0"
            response.headers["Strict-Transport-Security"] = "max-age=0"
            return response
        return await call_next(request)

app.add_middleware(HTTPSRedirectMiddleware)
app.include_router(chat_router)
app.include_router(roles_router)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

UPLOAD_DIR = "/home/dispatch/dyspatch/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def generate_recovery_phrase() -> str:
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return ''.join(secrets.choice(chars) for _ in range(64))

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
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one symbol (!@#$%^&* etc.)"
    return True, ""

def validate_pin(pin: str) -> tuple:
    if len(pin) != 6:
        return False, "PIN must be exactly 6 digits"
    if not pin.isdigit():
        return False, "PIN must contain only numbers"
    return True, ""

def check_login_lockout(username: str) -> tuple:
    if username in login_attempts:
        attempt = login_attempts[username]
        if attempt["lock_until"] and datetime.utcnow() < attempt["lock_until"]:
            remaining = int((attempt["lock_until"] - datetime.utcnow()).total_seconds() / 60)
            return True, f"Account locked. Try again in {remaining} minutes"
    return False, ""

def record_failed_login(username: str):
    now = datetime.utcnow()
    if username not in login_attempts:
        login_attempts[username] = {"count": 1, "lock_until": None}
    else:
        login_attempts[username]["count"] += 1
        if login_attempts[username]["count"] >= 5:
            login_attempts[username]["lock_until"] = now + timedelta(minutes=30)

def reset_login_attempts(username: str):
    if username in login_attempts:
        del login_attempts[username]

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

def escape_html(text: str) -> str:
    if not text:
        return ""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")

# Routes
@app.get("/")
async def root():
    response = RedirectResponse(url="/home", status_code=303)
    response.headers["Upgrade-Insecure-Requests"] = "0"
    return response

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

@app.get("/terms", response_class=HTMLResponse)
async def terms(request: Request, user = Depends(get_user_from_session)):
    return templates.TemplateResponse("terms.html", {"request": request, "user": user})

@app.get("/recovery", response_class=HTMLResponse)
async def recovery_page(request: Request, user = Depends(get_user_from_session)):
    if user:
        return RedirectResponse(url="/home", status_code=303)
    return templates.TemplateResponse("recovery.html", {"request": request, "user": user})

@app.post("/recovery")
async def recovery_submit(request: Request, recovery_phrase: str = Form(...), new_password: str = Form(...), new_pin: str = Form(...), db: Session = Depends(get_db)):
    users = db.query(User).all()
    user = None
    for u in users:
        if verify_password(recovery_phrase, u.recovery_phrase_hash):
            user = u
            break
    if not user:
        return templates.TemplateResponse("recovery.html", {"request": request, "error": "Invalid recovery phrase"})
    valid, error = validate_pin(new_pin)
    if not valid:
        return templates.TemplateResponse("recovery.html", {"request": request, "error": error})
    valid, error = validate_password(new_password)
    if not valid:
        return templates.TemplateResponse("recovery.html", {"request": request, "error": error})
    user.password_hash = hash_password(new_password)
    user.pin_hash = hash_password(new_pin)
    db.commit()
    return templates.TemplateResponse("recovery.html", {"request": request, "success": "Account recovered successfully! You can now log in with your new credentials."})

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
async def register(request: Request, username: str = Form(...), password: str = Form(...), pin: str = Form(...), terms: bool = Form(False), db: Session = Depends(get_db)):
    if not terms:
        return templates.TemplateResponse("register.html", {"request": request, "error": "You must accept the Terms of Service"})
    valid, error = validate_username(username)
    if not valid:
        return templates.TemplateResponse("register.html", {"request": request, "error": error})
    valid, error = validate_password(password)
    if not valid:
        return templates.TemplateResponse("register.html", {"request": request, "error": error})
    valid, error = validate_pin(pin)
    if not valid:
        return templates.TemplateResponse("register.html", {"request": request, "error": error})
    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        return templates.TemplateResponse("register.html", {"request": request, "error": "Username already exists"})
    recovery_phrase = generate_recovery_phrase()
    user_count = db.query(User).count()
    role = "owner" if user_count == 0 else "user"
    new_user = User(username=username, password_hash=hash_password(password), pin_hash=hash_password(pin), recovery_phrase_hash=hash_password(recovery_phrase), role=role)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return templates.TemplateResponse("register.html", {"request": request, "success": "Account created!", "recovery_phrase": recovery_phrase})

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...), pin: str = Form(...), db: Session = Depends(get_db)):
    locked, message = check_login_lockout(username)
    if locked:
        return templates.TemplateResponse("login.html", {"request": request, "error": message})
    user = db.query(User).filter(User.username == username).first()
    if not user:
        record_failed_login(username)
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})
    if not verify_password(password, user.password_hash):
        record_failed_login(username)
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})
    if not verify_password(pin, user.pin_hash):
        record_failed_login(username)
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})
    if user.is_banned:
        return templates.TemplateResponse("login.html", {"request": request, "error": f"Account banned: {user.ban_reason}"})
    reset_login_attempts(username)
    if user.totp_enabled:
        session_token = create_session(db, user.id, twofa_verified=False)
        response = RedirectResponse(url="/2fa-verify", status_code=303)
        response.set_cookie(key="session_token", value=session_token, httponly=True, secure=False, samesite="lax", max_age=300)
        return response
    user.last_login = datetime.utcnow()
    db.commit()
    session_token = create_session(db, user.id, twofa_verified=True)
    response = RedirectResponse(url="/home", status_code=303)
    response.set_cookie(key="session_token", value=session_token, httponly=True, secure=False, samesite="lax", max_age=604800)
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
async def verify_2fa_submit(request: Request, code: str = Form(...), db: Session = Depends(get_db), session_token: str = Cookie(None)):
    db_session = db.query(DBSession).filter(DBSession.session_token == session_token).first()
    if not db_session:
        return RedirectResponse(url="/login", status_code=303)
    user = db_session.user
    if not user.totp_enabled:
        db_session.twofa_verified = True
        db.commit()
        return RedirectResponse(url="/home", status_code=303)
    totp = pyotp.TOTP(user.totp_secret)
    if totp.verify(code):
        db_session.twofa_verified = True
        db_session.expires_at = datetime.utcnow() + timedelta(days=7)
        db.commit()
        user.last_login = datetime.utcnow()
        db.commit()
        response = RedirectResponse(url="/home", status_code=303)
        response.set_cookie(key="session_token", value=session_token, httponly=True, secure=False, samesite="lax", max_age=604800)
        return response
    if verify_recovery_code(db, user.id, code):
        db_session.twofa_verified = True
        db_session.expires_at = datetime.utcnow() + timedelta(days=7)
        db.commit()
        user.last_login = datetime.utcnow()
        db.commit()
        response = RedirectResponse(url="/home", status_code=303)
        response.set_cookie(key="session_token", value=session_token, httponly=True, secure=False, samesite="lax", max_age=604800)
        return response
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
    return RedirectResponse(url="/profile", status_code=303)

@app.get("/profile/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request, user = Depends(get_user_from_session)):
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse("change_password.html", {"request": request, "user": user})

@app.post("/profile/change-password")
async def change_password_submit(request: Request, current_password: str = Form(...), new_password: str = Form(...), confirm_password: str = Form(...), user = Depends(get_user_from_session), db: Session = Depends(get_db)):
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    valid, error = validate_password(new_password)
    if not valid:
        return templates.TemplateResponse("change_password.html", {"request": request, "user": user, "error": error})
    if new_password != confirm_password:
        return templates.TemplateResponse("change_password.html", {"request": request, "user": user, "error": "New passwords do not match"})
    if not verify_password(current_password, user.password_hash):
        return templates.TemplateResponse("change_password.html", {"request": request, "user": user, "error": "Current password is incorrect"})
    user.password_hash = hash_password(new_password)
    db.commit()
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
        return templates.TemplateResponse("change_pin.html", {"request": request, "user": user, "error": "Current PIN is incorrect"})
    user.pin_hash = hash_password(new_pin)
    db.commit()
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
        return templates.TemplateResponse("delete_account.html", {"request": request, "user": user, "error": "Password is incorrect"})
    files = db.query(File).filter((File.sender_id == user.id) | (File.recipient_id == user.id)).all()
    for file in files:
        file_path = os.path.join(UPLOAD_DIR, file.encrypted_filename)
        if os.path.exists(file_path):
            os.remove(file_path)
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

@app.get("/send", response_class=HTMLResponse)
async def send_page(request: Request, user = Depends(get_user_from_session)):
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse("send.html", {"request": request, "user": user})

@app.post("/send/submit")
async def submit_file(recipient: str = Form(...), filename: str = Form(...), file_size: str = Form(...), options: str = Form(...), encrypted_file: UploadFile = FastAPIFile(...), encryption_key: str = Form(...), user = Depends(get_user_from_session), db: Session = Depends(get_db)):
    if not user:
        return {"success": False, "error": "Not authenticated"}
    filename = escape_html(filename)
    try:
        file_size_int = int(file_size)
    except:
        file_size_int = 0
    recipient_user = db.query(User).filter(User.username == recipient).first()
    if not recipient_user:
        return {"success": False, "error": "Recipient not found"}
    
    from roles import get_file_limits
    limits = get_file_limits(user)
    if file_size_int > limits["max_file_size"]:
        return {"success": False, "error": f"File too large. Max {limits['max_file_size']/1073741824}GB"}
    
    active_files = db.query(File).filter(File.sender_id == user.id, File.status.in_(["pending", "accepted"])).count()
    if active_files >= limits["max_concurrent_files"]:
        return {"success": False, "error": f"Concurrent file limit reached. Max {limits['max_concurrent_files']}"}
    
    try:
        opts = json.loads(options)
    except:
        opts = {}
    if opts.get("password_protected") and opts.get("file_password"):
        opts["file_password_hash"] = hash_password(opts["file_password"])
        del opts["file_password"]
    
    pending_expiry = datetime.utcnow() + timedelta(hours=72)
    encrypted_data = await encrypted_file.read()
    encrypted_filename = f"{secrets.token_hex(32)}.enc"
    file_path = os.path.join(UPLOAD_DIR, encrypted_filename)
    with open(file_path, "wb") as f:
        f.write(encrypted_data)
    new_file = File(sender_id=user.id, recipient_id=recipient_user.id, filename=filename, encrypted_filename=encrypted_filename, file_size=file_size_int, status="pending", options=json.dumps(opts), expires_at=pending_expiry, stealth_mode=False)
    db.add(new_file)
    db.commit()
    return {"success": True, "file_id": new_file.id}

@app.get("/files/accept/{file_id}")
async def accept_file(file_id: int, user = Depends(get_user_from_session), db: Session = Depends(get_db)):
    if not user:
        return {"success": False, "error": "Not authenticated"}
    file = db.query(File).filter(File.id == file_id, File.recipient_id == user.id, File.status == "pending").first()
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
    return {"success": True, "file_id": file.id, "filename": file.filename}

@app.get("/files/decline/{file_id}")
async def decline_file(file_id: int, user = Depends(get_user_from_session), db: Session = Depends(get_db)):
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
    return RedirectResponse(url="/foryou", status_code=303)

@app.get("/files/cancel/{file_id}")
async def cancel_file(file_id: int, user = Depends(get_user_from_session), db: Session = Depends(get_db)):
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
    return RedirectResponse(url="/history", status_code=303)

@app.get("/files/download/{file_id}")
async def download_file(request: Request, file_id: int, user = Depends(get_user_from_session), db: Session = Depends(get_db), password: str = None):
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
    response = FileResponse(file_path, media_type="application/octet-stream", filename=file.filename, headers={"Content-Disposition": f"attachment; filename=\"{file.filename}\""})
    return response

@app.get("/search")
async def search_users(q: str, user = Depends(get_user_from_session), db: Session = Depends(get_db)):
    if not user:
        return {"users": []}
    q = escape_html(q)
    users = db.query(User).filter(User.username.ilike(f"%{q}%"), User.id != user.id).limit(10).all()
    return {"users": [{"id": u.id, "username": escape_html(u.username)} for u in users]}

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/home", status_code=303)
    response.delete_cookie("session_token")
    return response

# Admin Panel Routes
@app.get("/admin", response_class=HTMLResponse)
async def admin_panel(request: Request, user = Depends(get_user_from_session), db: Session = Depends(get_db)):
    if not user or user.role != "owner":
        return RedirectResponse(url="/home", status_code=303)
    
    # Stats
    total_users = db.query(User).count()
    active_users = db.query(User).filter(User.last_login > datetime.utcnow() - timedelta(days=7)).count()
    total_files = db.query(File).count()
    total_storage = db.query(func.sum(File.file_size)).scalar() or 0
    total_storage_gb = round(total_storage / (1024 * 1024 * 1024), 1)
    
    # Users by role
    users_by_role = {
        "free": db.query(User).filter(User.role == "user", User.is_banned == False).count(),
        "pro": db.query(User).filter(User.role == "pro", User.is_banned == False).count(),
        "premium": db.query(User).filter(User.role == "premium", User.is_banned == False).count(),
        "owner": db.query(User).filter(User.role == "owner").count(),
        "banned": db.query(User).filter(User.is_banned == True).count()
    }
    
    # Files by status
    files_by_status = {
        "pending": db.query(File).filter(File.status == "pending").count(),
        "accepted": db.query(File).filter(File.status == "accepted").count(),
        "declined": db.query(File).filter(File.status == "declined").count(),
        "downloaded": db.query(File).filter(File.status == "downloaded").count(),
        "expired": db.query(File).filter(File.expires_at < datetime.utcnow()).count()
    }
    
    # Users with file counts
    users = db.query(
        User.id, User.username, User.role, User.created_at, User.last_login, 
        User.is_banned, User.ban_reason, User.subscription_expires_at,
        func.count(File.id).label("file_count")
    ).outerjoin(File, File.sender_id == User.id).group_by(User.id).order_by(desc("file_count")).limit(50).all()
    
    # Recent files
    files = db.query(File).order_by(desc(File.created_at)).limit(30).all()
    
    # System health
    system_health = {
        "cpu_percent": psutil.cpu_percent(interval=1),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_usage": psutil.disk_usage('/').percent,
        "uptime": str(datetime.utcnow() - datetime.fromtimestamp(psutil.boot_time())).split('.')[0]
    }
    
    # Active logs
    active_logs = []
    recent_logins = db.query(User).filter(User.last_login > datetime.utcnow() - timedelta(hours=24)).order_by(desc(User.last_login)).limit(10).all()
    for log in recent_logins:
        active_logs.append({"type": "login", "username": log.username, "time": log.last_login, "details": "User logged in"})
    recent_uploads = db.query(File).order_by(desc(File.created_at)).limit(10).all()
    for file in recent_uploads:
        active_logs.append({"type": "upload", "username": file.sender.username, "time": file.created_at, "details": f"Uploaded file: {file.filename}"})
    recent_downloads = db.query(File).filter(File.downloaded_at != None).order_by(desc(File.downloaded_at)).limit(10).all()
    for file in recent_downloads:
        active_logs.append({"type": "download", "username": file.recipient.username, "time": file.downloaded_at, "details": f"Downloaded file: {file.filename}"})
    active_logs.sort(key=lambda x: x["time"], reverse=True)
    active_logs = active_logs[:30]
    
    # Failed login attempts
    failed_logins = db.query(User).filter(User.failed_login_attempts > 0).order_by(desc(User.last_failed_login)).limit(20).all()
    
    return templates.TemplateResponse("admin_simple.html", {
        "request": request,
        "user": user,
        "total_users": total_users,
        "active_users": active_users,
        "total_files": total_files,
        "total_storage": total_storage_gb,
        "users_by_role": users_by_role,
        "files_by_status": files_by_status,
        "users": users,
        "files": files,
        "system_health": system_health,
        "failed_logins": failed_logins,
        "active_logs": active_logs,
        "now": datetime.utcnow()
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
    
    free = db.query(User).filter(User.role == "user", User.is_banned == False).count()
    pro = db.query(User).filter(User.role == "pro", User.is_banned == False).count()
    premium = db.query(User).filter(User.role == "premium", User.is_banned == False).count()
    banned = db.query(User).filter(User.is_banned == True).count()
    
    pending = db.query(File).filter(File.status == "pending").count()
    expired = db.query(File).filter(File.expires_at < datetime.utcnow()).count()
    
    return {
        "success": True,
        "total_users": total_users,
        "active_users": active_users,
        "total_files": total_files,
        "total_storage": total_storage_gb,
        "free": free,
        "pro": pro,
        "premium": premium,
        "banned": banned,
        "pending": pending,
        "expired": expired,
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
        query = query.filter(User.username.ilike(f"%{q}%"))
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
            "days_left": days_left
        })
    
    return {"success": True, "users": result}

@app.get("/admin/search-files")
async def admin_search_files(q: str = "", status: str = "all", user = Depends(get_user_from_session), db: Session = Depends(get_db)):
    if not user or user.role != "owner":
        return {"success": False, "error": "Unauthorized"}
    
    query = db.query(File)
    if q:
        query = query.filter(File.filename.ilike(f"%{q}%"))
    if status != "all":
        query = query.filter(File.status == status)
    
    files = query.order_by(desc(File.created_at)).limit(30).all()
    
    result = []
    for f in files:
        result.append({
            "id": f.id,
            "filename": f.filename,
            "size_mb": round(f.file_size / (1024 * 1024), 1),
            "status": f.status,
            "sender": f.sender.username,
            "recipient": f.recipient.username,
            "created_at": f.created_at.strftime("%Y-%m-%d") if f.created_at else "Unknown",
            "expires_at": f.expires_at.strftime("%Y-%m-%d") if f.expires_at else "Unknown"
        })
    
    return {"success": True, "files": result}

@app.post("/admin/user/ban/{user_id}")
async def admin_ban_user(user_id: int, reason: str = Form(...), user = Depends(get_user_from_session), db: Session = Depends(get_db)):
    if not user or user.role != "owner":
        return {"success": False, "error": "Unauthorized"}
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        return {"success": False, "error": "User not found"}
    target.is_banned = True
    target.ban_reason = reason
    db.commit()
    return {"success": True, "message": f"User {target.username} banned"}

@app.post("/admin/user/unban/{user_id}")
async def admin_unban_user(user_id: int, user = Depends(get_user_from_session), db: Session = Depends(get_db)):
    if not user or user.role != "owner":
        return {"success": False, "error": "Unauthorized"}
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        return {"success": False, "error": "User not found"}
    target.is_banned = False
    target.ban_reason = None
    db.commit()
    return {"success": True, "message": f"User {target.username} unbanned"}

@app.post("/admin/user/role/{user_id}")
async def admin_change_role(user_id: int, role: str = Form(...), user = Depends(get_user_from_session), db: Session = Depends(get_db)):
    if not user or user.role != "owner":
        return {"success": False, "error": "Unauthorized"}
    if role not in ["user", "pro", "premium"]:
        return {"success": False, "error": "Invalid role"}
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        return {"success": False, "error": "User not found"}
    target.role = role
    db.commit()
    return {"success": True, "message": f"User {target.username} role changed to {role}"}

@app.post("/admin/user/delete/{user_id}")
async def admin_delete_user(user_id: int, user = Depends(get_user_from_session), db: Session = Depends(get_db)):
    if not user or user.role != "owner":
        return {"success": False, "error": "Unauthorized"}
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        return {"success": False, "error": "User not found"}
    files = db.query(File).filter((File.sender_id == target.id) | (File.recipient_id == target.id)).all()
    for f in files:
        file_path = os.path.join(UPLOAD_DIR, f.encrypted_filename)
        if os.path.exists(file_path):
            os.remove(file_path)
    db.delete(target)
    db.commit()
    return {"success": True, "message": f"User {target.username} deleted"}

@app.post("/admin/file/delete/{file_id}")
async def admin_delete_file(file_id: int, user = Depends(get_user_from_session), db: Session = Depends(get_db)):
    if not user or user.role != "owner":
        return {"success": False, "error": "Unauthorized"}
    file = db.query(File).filter(File.id == file_id).first()
    if not file:
        return {"success": False, "error": "File not found"}
    file_path = os.path.join(UPLOAD_DIR, file.encrypted_filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    db.delete(file)
    db.commit()
    return {"success": True, "message": f"File {file.filename} deleted"}

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
    
    recent_files = db.query(File).filter(
        (File.sender_id == target.id) | (File.recipient_id == target.id)
    ).order_by(desc(File.created_at)).limit(10).all()
    
    return {
        "success": True,
        "user": {
            "id": target.id,
            "username": target.username,
            "role": target.role,
            "twofa_enabled": target.totp_enabled,
            "created_at": target.created_at.isoformat(),
            "last_login": target.last_login.isoformat(),
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
        },
        "recent_files": [
            {
                "id": f.id,
                "filename": f.filename,
                "size_mb": round(f.file_size / (1024 * 1024), 1),
                "status": f.status,
                "sender": f.sender.username,
                "recipient": f.recipient.username,
                "created_at": f.created_at.isoformat(),
                "expires_at": f.expires_at.isoformat()
            } for f in recent_files
        ]
    }

# 404 handler
@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    user = await get_user_from_session(request)
    return templates.TemplateResponse("404.html", {"request": request, "user": user}, status_code=404)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
