from fastapi import APIRouter, Request, Form, Depends, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import secrets
import json
import os

from database import get_db, User, Payment

router = APIRouter(prefix="/roles", tags=["roles"])
templates = Jinja2Templates(directory="templates")

def get_current_user(db: Session, session_token: str = None):
    from database import Session as DBSession
    if not session_token:
        return None
    
    db_session = db.query(DBSession).filter(
        DBSession.session_token == session_token,
        DBSession.expires_at > datetime.utcnow()
    ).first()
    
    if not db_session:
        return None
    
    user = db_session.user
    if user and user.totp_enabled and not db_session.twofa_verified:
        return None
    
    # Check subscription expiry
    if user and user.subscription_expires_at and user.subscription_expires_at < datetime.utcnow():
        user.role = "user"
        user.subscription_expires_at = None
        db.commit()
    
    return user

ROLE_LIMITS = {
    "user": {
        "max_file_size": 1073741824,
        "max_concurrent_files": 10,
        "file_retention_days": 7,
        "history_retention_days": 30,
        "chat_enabled": False,
        "chat_char_limit": 0,
        "custom_expiry": False,
        "password_protection": False
    },
    "pro": {
        "max_file_size": 5368709120,
        "max_concurrent_files": 50,
        "file_retention_days": 7,
        "history_retention_days": 60,
        "chat_enabled": True,
        "chat_char_limit": 100,
        "custom_expiry": True,
        "password_protection": True
    },
    "premium": {
        "max_file_size": 10737418240,
        "max_concurrent_files": 100,
        "file_retention_days": 7,
        "history_retention_days": 90,
        "chat_enabled": True,
        "chat_char_limit": 200,
        "custom_expiry": True,
        "password_protection": True
    },
    "owner": {
        "max_file_size": float("inf"),
        "max_concurrent_files": float("inf"),
        "file_retention_days": 7,
        "history_retention_days": float("inf"),
        "chat_enabled": True,
        "chat_char_limit": 500,
        "custom_expiry": True,
        "password_protection": True
    }
}

def get_role_limits(role):
    return ROLE_LIMITS.get(role, ROLE_LIMITS["user"])

def get_history_retention_days(role):
    limits = get_role_limits(role)
    return limits["history_retention_days"]

def check_chat_access(user):
    if not user:
        return False
    limits = get_role_limits(user.role)
    return limits["chat_enabled"]

def get_chat_char_limit(user):
    if not user:
        return 0
    limits = get_role_limits(user.role)
    return limits["chat_char_limit"]

def get_file_limits(user):
    if not user:
        return get_role_limits("user")
    return get_role_limits(user.role)

def can_use_feature(user, feature):
    if not user:
        return False
    limits = get_role_limits(user.role)
    return limits.get(feature, False)

@router.get("/upgrade", response_class=HTMLResponse)
async def upgrade_page(request: Request, session_token: str = Cookie(None), db: Session = Depends(get_db)):
    user = get_current_user(db, session_token)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse("upgrade.html", {"request": request, "user": user})

@router.post("/upgrade/request")
async def upgrade_request(
    plan: str = Form(...),
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}
    
    if user.role == plan:
        return {"success": False, "error": f"You are already a {plan} member"}
    
    if plan not in ["pro", "premium"]:
        return {"success": False, "error": "Invalid plan"}
    
    return {
        "success": True, 
        "message": f"To upgrade to {plan}, please email dispatsh@proton.me with your username: {user.username}"
    }
