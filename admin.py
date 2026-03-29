from fastapi import APIRouter, Request, Form, Depends, HTTPException, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from datetime import datetime, timedelta
import json
import os

from database import get_db, User, File, ChatMessage, ChatConversation, Session as DBSession

router = APIRouter(prefix="/admin", tags=["admin"])
templates = Jinja2Templates(directory="templates")

def get_current_user(db: Session, session_token: str = None):
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
    return user

def escape_html(text: str) -> str:
    if not text:
        return ""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")

@router.get("/", response_class=HTMLResponse)
async def admin_panel(request: Request, session_token: str = Cookie(None), db: Session = Depends(get_db)):
    user = get_current_user(db, session_token)
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
        "free": db.query(User).filter(User.role == "user").count(),
        "pro": db.query(User).filter(User.role == "pro").count(),
        "premium": db.query(User).filter(User.role == "premium").count(),
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
    
    # Top active users (by file count)
    top_users = db.query(
        User.id, User.username, User.role, User.created_at, User.last_login,
        func.count(File.id).label("file_count"),
        func.sum(File.file_size).label("total_storage")
    ).outerjoin(File, File.sender_id == User.id).group_by(User.id).order_by(desc("file_count")).limit(10).all()
    
    # Recent files
    recent_files = db.query(File).order_by(desc(File.created_at)).limit(20).all()
    
    # System health
    import psutil
    system_health = {
        "cpu_percent": psutil.cpu_percent(interval=1),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_usage": psutil.disk_usage('/').percent,
        "uptime": datetime.utcnow() - datetime.fromtimestamp(psutil.boot_time())
    }
    
    # Failed login attempts
    failed_logins = db.query(User).filter(User.failed_login_attempts > 0).order_by(desc(User.last_failed_login)).limit(20).all()
    
    return templates.TemplateResponse("admin.html", {
        "request": request,
        "user": user,
        "stats": {
            "total_users": total_users,
            "active_users": active_users,
            "total_files": total_files,
            "total_storage": total_storage_gb
        },
        "users_by_role": users_by_role,
        "files_by_status": files_by_status,
        "top_users": top_users,
        "recent_files": recent_files,
        "system_health": system_health,
        "failed_logins": failed_logins
    })

@router.post("/user/ban/{user_id}")
async def ban_user(
    user_id: int,
    reason: str = Form(...),
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    admin = get_current_user(db, session_token)
    if not admin or admin.role != "owner":
        return {"success": False, "error": "Unauthorized"}
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return {"success": False, "error": "User not found"}
    
    user.is_banned = True
    user.ban_reason = escape_html(reason)
    db.commit()
    
    return {"success": True, "message": f"User {user.username} banned"}

@router.post("/user/unban/{user_id}")
async def unban_user(
    user_id: int,
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    admin = get_current_user(db, session_token)
    if not admin or admin.role != "owner":
        return {"success": False, "error": "Unauthorized"}
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return {"success": False, "error": "User not found"}
    
    user.is_banned = False
    user.ban_reason = None
    db.commit()
    
    return {"success": True, "message": f"User {user.username} unbanned"}

@router.post("/user/role/{user_id}")
async def change_user_role(
    user_id: int,
    role: str = Form(...),
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    admin = get_current_user(db, session_token)
    if not admin or admin.role != "owner":
        return {"success": False, "error": "Unauthorized"}
    
    if role not in ["user", "pro", "premium"]:
        return {"success": False, "error": "Invalid role"}
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return {"success": False, "error": "User not found"}
    
    user.role = role
    db.commit()
    
    return {"success": True, "message": f"User {user.username} role changed to {role}"}

@router.post("/user/delete/{user_id}")
async def delete_user(
    user_id: int,
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    admin = get_current_user(db, session_token)
    if not admin or admin.role != "owner":
        return {"success": False, "error": "Unauthorized"}
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return {"success": False, "error": "User not found"}
    
    # Delete user's files
    files = db.query(File).filter((File.sender_id == user.id) | (File.recipient_id == user.id)).all()
    upload_dir = "/home/dispatch/dyspatch/uploads"
    for file in files:
        file_path = os.path.join(upload_dir, file.encrypted_filename)
        if os.path.exists(file_path):
            os.remove(file_path)
    
    db.delete(user)
    db.commit()
    
    return {"success": True, "message": f"User {user.username} deleted"}

@router.post("/file/delete/{file_id}")
async def delete_file(
    file_id: int,
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    admin = get_current_user(db, session_token)
    if not admin or admin.role != "owner":
        return {"success": False, "error": "Unauthorized"}
    
    file = db.query(File).filter(File.id == file_id).first()
    if not file:
        return {"success": False, "error": "File not found"}
    
    file_path = os.path.join("/home/dispatch/dyspatch/uploads", file.encrypted_filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    
    db.delete(file)
    db.commit()
    
    return {"success": True, "message": f"File {file.filename} deleted"}

@router.get("/user/{user_id}")
async def get_user_details(
    user_id: int,
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    admin = get_current_user(db, session_token)
    if not admin or admin.role != "owner":
        return {"success": False, "error": "Unauthorized"}
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return {"success": False, "error": "User not found"}
    
    # File statistics
    files_sent = db.query(File).filter(File.sender_id == user.id).all()
    files_received = db.query(File).filter(File.recipient_id == user.id).all()
    
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
    
    # Chat statistics
    active_chats = db.query(ChatConversation).filter(
        ((ChatConversation.user1_id == user.id) | (ChatConversation.user2_id == user.id)),
        ChatConversation.status == "active"
    ).count()
    
    messages_sent = db.query(ChatMessage).filter(ChatMessage.sender_id == user.id).count()
    
    # Recent files
    recent_files = db.query(File).filter(
        (File.sender_id == user.id) | (File.recipient_id == user.id)
    ).order_by(desc(File.created_at)).limit(10).all()
    
    return {
        "success": True,
        "user": {
            "id": user.id,
            "username": escape_html(user.username),
            "role": user.role,
            "twofa_enabled": user.totp_enabled,
            "created_at": user.created_at.isoformat(),
            "last_login": user.last_login.isoformat(),
            "is_banned": user.is_banned,
            "ban_reason": user.ban_reason,
            "subscription_expires_at": user.subscription_expires_at.isoformat() if user.subscription_expires_at else None
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
                "filename": escape_html(f.filename),
                "size_mb": round(f.file_size / (1024 * 1024), 1),
                "status": f.status,
                "sender": escape_html(f.sender.username),
                "recipient": escape_html(f.recipient.username),
                "created_at": f.created_at.isoformat(),
                "expires_at": f.expires_at.isoformat()
            } for f in recent_files
        ]
    }

@router.get("/search")
async def admin_search_users(
    q: str = "",
    role: str = "all",
    status: str = "all",
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    admin = get_current_user(db, session_token)
    if not admin or admin.role != "owner":
        return {"success": False, "error": "Unauthorized"}
    
    query = db.query(User)
    
    if q:
        query = query.filter(User.username.ilike(f"%{q}%"))
    if role != "all":
        if role == "banned":
            query = query.filter(User.is_banned == True)
        else:
            query = query.filter(User.role == role, User.is_banned == False)
    if status == "banned":
        query = query.filter(User.is_banned == True)
    elif status == "active":
        query = query.filter(User.is_banned == False)
    
    users = query.order_by(desc(User.created_at)).limit(50).all()
    
    return {
        "success": True,
        "users": [
            {
                "id": u.id,
                "username": escape_html(u.username),
                "role": u.role,
                "files": db.query(File).filter(File.sender_id == u.id).count(),
                "storage_gb": round((db.query(func.sum(File.file_size)).filter(File.sender_id == u.id).scalar() or 0) / (1024 * 1024 * 1024), 2),
                "created_at": u.created_at.strftime("%Y-%m-%d"),
                "last_login": u.last_login.strftime("%Y-%m-%d"),
                "is_banned": u.is_banned,
                "ban_reason": u.ban_reason
            } for u in users
        ]
    }
