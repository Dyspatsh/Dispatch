from fastapi import APIRouter, Request, Form, Depends, HTTPException, WebSocket, WebSocketDisconnect, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import json
import secrets
import asyncio

from database import get_db, User, ChatConversation, ChatMessage, BlockedUser, Session as DBSession
from roles import check_chat_access, get_chat_char_limit

router = APIRouter(prefix="/chat", tags=["chat"])
templates = Jinja2Templates(directory="templates")

online_users = {}
user_unread_counts = {}

def get_current_user(db: Session, session_token: str = None):
    if not session_token:
        return None
    db_session = db.query(DBSession).filter(DBSession.session_token == session_token, DBSession.expires_at > datetime.utcnow()).first()
    if not db_session:
        return None
    user = db_session.user
    if user and user.totp_enabled and not db_session.twofa_verified:
        return None
    return user

def get_conversation(db: Session, user1_id: int, user2_id: int):
    conv = db.query(ChatConversation).filter(((ChatConversation.user1_id == user1_id) & (ChatConversation.user2_id == user2_id)) | ((ChatConversation.user1_id == user2_id) & (ChatConversation.user2_id == user1_id))).first()
    return conv

def is_blocked(db: Session, user_id: int, target_id: int) -> bool:
    block = db.query(BlockedUser).filter(BlockedUser.user_id == target_id, BlockedUser.blocked_user_id == user_id).first()
    return block is not None

def is_blocking(db: Session, user_id: int, target_id: int) -> bool:
    block = db.query(BlockedUser).filter(BlockedUser.user_id == user_id, BlockedUser.blocked_user_id == target_id).first()
    return block is not None

def get_unread_count(db: Session, user_id: int, conversation_id: int) -> int:
    count = db.query(ChatMessage).filter(ChatMessage.conversation_id == conversation_id, ChatMessage.sender_id != user_id, ChatMessage.read_at.is_(None)).count()
    return count if count else 0

def increment_unread_count(user_id: int, conversation_id: int):
    key = f"{user_id}_{conversation_id}"
    user_unread_counts[key] = user_unread_counts.get(key, 0) + 1

def reset_unread_count(user_id: int, conversation_id: int):
    key = f"{user_id}_{conversation_id}"
    if key in user_unread_counts:
        user_unread_counts[key] = 0

class ConnectionManager:
    def __init__(self):
        self.active_connections: dict = {}

    async def connect(self, websocket: WebSocket, user_id: int):
        await websocket.accept()
        self.active_connections[user_id] = websocket
        online_users[user_id] = True
        await self.broadcast_status(user_id, "online")

    def disconnect(self, user_id: int):
        if user_id in self.active_connections:
            del self.active_connections[user_id]
        if user_id in online_users:
            del online_users[user_id]
        asyncio.create_task(self.broadcast_status(user_id, "offline"))

    async def send_message(self, user_id: int, message: dict):
        if user_id in self.active_connections:
            try:
                await self.active_connections[user_id].send_json(message)
                return True
            except:
                pass
        return False

    async def broadcast_status(self, user_id: int, status: str):
        from database import SessionLocal
        db = SessionLocal()
        try:
            convs = db.query(ChatConversation).filter(((ChatConversation.user1_id == user_id) | (ChatConversation.user2_id == user_id)), ChatConversation.status == "active").all()
            for conv in convs:
                other_id = conv.user1_id if conv.user2_id == user_id else conv.user2_id
                await self.send_message(other_id, {"type": "status", "user_id": user_id, "status": status})
        finally:
            db.close()

manager = ConnectionManager()

@router.get("/")
async def messages_page(request: Request, session_token: str = Cookie(None), db: Session = Depends(get_db)):
    user = get_current_user(db, session_token)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    if not check_chat_access(user):
        return templates.TemplateResponse("no_access.html", {"request": request, "user": user, "required_role": "Pro", "feature": "private chat"})
    
    pending_invitations = db.query(ChatConversation).filter(((ChatConversation.user1_id == user.id) | (ChatConversation.user2_id == user.id)), ChatConversation.status == "pending", ChatConversation.initiator_id != user.id).all()
    sent_invitations = db.query(ChatConversation).filter(((ChatConversation.user1_id == user.id) | (ChatConversation.user2_id == user.id)), ChatConversation.status == "pending", ChatConversation.initiator_id == user.id).all()
    active_conversations = db.query(ChatConversation).filter(((ChatConversation.user1_id == user.id) | (ChatConversation.user2_id == user.id)), ChatConversation.status == "active").order_by(ChatConversation.updated_at.desc()).all()
    
    for conv in active_conversations:
        conv.unread_count = get_unread_count(db, user.id, conv.id)
        if conv.unread_count > 0:
            user_unread_counts[f"{user.id}_{conv.id}"] = conv.unread_count
    
    return templates.TemplateResponse("messages.html", {"request": request, "user": user, "pending_invitations": pending_invitations, "sent_invitations": sent_invitations, "active_conversations": active_conversations, "online_users": online_users})

@router.get("/{other_user_id}")
async def chat_page(request: Request, other_user_id: int, session_token: str = Cookie(None), db: Session = Depends(get_db)):
    user = get_current_user(db, session_token)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    if not check_chat_access(user):
        return templates.TemplateResponse("no_access.html", {"request": request, "user": user, "required_role": "Pro", "feature": "private chat"})
    
    other_user = db.query(User).filter(User.id == other_user_id).first()
    if not other_user:
        return RedirectResponse(url="/chat", status_code=303)
    
    conv = get_conversation(db, user.id, other_user_id)
    if not conv or conv.status != "active":
        return RedirectResponse(url="/chat", status_code=303)
    
    reset_unread_count(user.id, conv.id)
    unread_messages = db.query(ChatMessage).filter(ChatMessage.conversation_id == conv.id, ChatMessage.sender_id != user.id, ChatMessage.read_at.is_(None)).all()
    for msg in unread_messages:
        msg.read_at = datetime.utcnow()
    db.commit()
    
    blocked_by_other = is_blocked(db, user.id, other_user_id)
    blocked_other = is_blocking(db, user.id, other_user_id)
    
    active_conversations = db.query(ChatConversation).filter(((ChatConversation.user1_id == user.id) | (ChatConversation.user2_id == user.id)), ChatConversation.status == "active").order_by(ChatConversation.updated_at.desc()).all()
    for conv_item in active_conversations:
        conv_item.unread_count = user_unread_counts.get(f"{user.id}_{conv_item.id}", 0)
    
    messages = db.query(ChatMessage).filter(ChatMessage.conversation_id == conv.id).order_by(ChatMessage.created_at.asc()).all()
    other_user_online = other_user_id in online_users
    
    return templates.TemplateResponse("chat.html", {"request": request, "user": user, "other_user": other_user, "other_user_online": other_user_online, "conversation_id": conv.id, "active_conversations": active_conversations, "messages": messages, "blocked_by_other": blocked_by_other, "blocked_other": blocked_other})

@router.post("/send")
async def send_message(recipient_id: int = Form(...), content: str = Form(...), session_token: str = Cookie(None), db: Session = Depends(get_db)):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}
    if not check_chat_access(user):
        return {"success": False, "error": "Chat access requires Pro or Premium subscription"}
    
    char_limit = get_chat_char_limit(user)
    if char_limit > 0 and len(content) > char_limit:
        return {"success": False, "error": f"Message exceeds {char_limit} character limit"}
    if not content or len(content.strip()) == 0:
        return {"success": False, "error": "Message cannot be empty"}
    
    recipient = db.query(User).filter(User.id == recipient_id).first()
    if not recipient:
        return {"success": False, "error": "Recipient not found"}
    
    conv = get_conversation(db, user.id, recipient_id)
    if not conv or conv.status != "active":
        return {"success": False, "error": "No active conversation with this user"}
    if is_blocked(db, user.id, recipient_id) or is_blocking(db, user.id, recipient_id):
        return {"success": False, "error": "You cannot message this user"}
    
    expires_at = datetime.utcnow() + timedelta(hours=24)
    new_message = ChatMessage(conversation_id=conv.id, sender_id=user.id, encrypted_content=content, expires_at=expires_at, delivered_at=datetime.utcnow())
    db.add(new_message)
    db.commit()
    db.refresh(new_message)
    conv.updated_at = datetime.utcnow()
    db.commit()
    
    increment_unread_count(recipient_id, conv.id)
    await manager.send_message(recipient_id, {"type": "new_message", "message": {"id": new_message.id, "sender_id": user.id, "sender_username": user.username, "content": content, "created_at": new_message.created_at.isoformat(), "expires_at": expires_at.isoformat()}, "unread_count": user_unread_counts.get(f"{recipient_id}_{conv.id}", 1)})
    return {"success": True, "message": {"id": new_message.id, "content": content, "created_at": new_message.created_at.isoformat(), "expires_at": expires_at.isoformat()}}

@router.post("/block/{user_id}")
async def block_user(user_id: int, session_token: str = Cookie(None), db: Session = Depends(get_db)):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}
    if user_id == user.id:
        return {"success": False, "error": "Cannot block yourself"}
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        return {"success": False, "error": "User not found"}
    
    existing = db.query(BlockedUser).filter(BlockedUser.user_id == user.id, BlockedUser.blocked_user_id == user_id).first()
    if not existing:
        new_block = BlockedUser(user_id=user.id, blocked_user_id=user_id)
        db.add(new_block)
        db.commit()
    return {"success": True}

@router.post("/unblock/{user_id}")
async def unblock_user(user_id: int, session_token: str = Cookie(None), db: Session = Depends(get_db)):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}
    block = db.query(BlockedUser).filter(BlockedUser.user_id == user.id, BlockedUser.blocked_user_id == user_id).first()
    if block:
        db.delete(block)
        db.commit()
    return {"success": True}

@router.get("/blocked/list")
async def get_blocked_list(session_token: str = Cookie(None), db: Session = Depends(get_db)):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}
    blocks = db.query(BlockedUser).filter(BlockedUser.user_id == user.id).all()
    blocked_users = []
    for block in blocks:
        blocked_user = db.query(User).filter(User.id == block.blocked_user_id).first()
        if blocked_user:
            blocked_users.append({"id": blocked_user.id, "username": blocked_user.username})
    return {"success": True, "blocked_users": blocked_users}

@router.websocket("/ws/{conversation_id}")
async def websocket_endpoint(websocket: WebSocket, conversation_id: int, session_token: str = Cookie(None), db: Session = Depends(get_db)):
    user = get_current_user(db, session_token)
    if not user:
        await websocket.close(code=1008)
        return
    if not check_chat_access(user):
        await websocket.close(code=1008)
        return
    
    conv = db.query(ChatConversation).filter(ChatConversation.id == conversation_id).first()
    if not conv or (conv.user1_id != user.id and conv.user2_id != user.id):
        await websocket.close(code=1008)
        return
    if conv.status != "active":
        await websocket.close(code=1008)
        return
    
    other_user_id = conv.user1_id if conv.user2_id == user.id else conv.user2_id
    if is_blocked(db, user.id, other_user_id) or is_blocking(db, user.id, other_user_id):
        await websocket.close(code=1008)
        return
    
    await manager.connect(websocket, user.id)
    await websocket.send_json({"type": "status", "user_id": other_user_id, "status": "online" if other_user_id in online_users else "offline"})
    
    try:
        while True:
            data = await websocket.receive_text()
            message_data = json.loads(data)
            if message_data.get("type") == "message":
                content = message_data.get("content", "")
                char_limit = get_chat_char_limit(user)
                if char_limit > 0 and len(content) > char_limit:
                    await websocket.send_json({"type": "error", "message": f"Message exceeds {char_limit} character limit"})
                    continue
                
                expires_at = datetime.utcnow() + timedelta(hours=24)
                new_message = ChatMessage(conversation_id=conversation_id, sender_id=user.id, encrypted_content=content, expires_at=expires_at, delivered_at=datetime.utcnow())
                db.add(new_message)
                db.commit()
                conv.updated_at = datetime.utcnow()
                db.commit()
                
                increment_unread_count(other_user_id, conversation_id)
                await manager.send_message(other_user_id, {"type": "new_message", "message": {"id": new_message.id, "sender_id": user.id, "sender_username": user.username, "content": content, "created_at": new_message.created_at.isoformat(), "expires_at": expires_at.isoformat()}, "unread_count": user_unread_counts.get(f"{other_user_id}_{conversation_id}", 1)})
                await websocket.send_json({"type": "message_sent", "message": {"id": new_message.id, "content": content, "created_at": new_message.created_at.isoformat(), "expires_at": expires_at.isoformat()}})
    except WebSocketDisconnect:
        manager.disconnect(user.id)
