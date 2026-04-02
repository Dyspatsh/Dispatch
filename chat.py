from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, Cookie, Request, Form
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import or_, and_, func, desc
from datetime import datetime, timedelta
import json
import secrets
import asyncio
import time
from typing import Dict, Set, Optional

from database import get_db, User, ChatConversation, ChatMessage, BlockedUser
from database import ChatGroup, GroupMember, GroupChatMessage, MessageReaction, MessageReadReceipt, GroupInvitation
from utils import get_current_user, escape_html, log_security_event, is_user_blocked

router = APIRouter(prefix="/chat", tags=["chat"])
templates = Jinja2Templates(directory="templates")

active_connections: Dict[int, Set[WebSocket]] = {}
group_active_connections: Dict[int, Set[WebSocket]] = {}

def generate_csrf_token(user_id: int, db: Session) -> str:
    from database import CSRFToken
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=1)
    csrf = CSRFToken(token=token, user_id=user_id, expires_at=expires_at)
    db.add(csrf)
    db.commit()
    return token

# ============================================
# PRIVATE CHAT - MAIN PAGE
# ============================================

@router.get("")
async def chat_index(request: Request, db: Session = Depends(get_db), session_token: Optional[str] = Cookie(None)):
    user = get_current_user(db, session_token)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    
    # Get pending invitations (where current user is the recipient)
    pending_invitations = db.query(ChatConversation).filter(
        or_(
            ChatConversation.user2_id == user.id,
            ChatConversation.user1_id == user.id
        ),
        ChatConversation.status == "pending"
    ).all()
    pending_invitations = [inv for inv in pending_invitations if inv.initiator_id != user.id]
    
    # Get sent invitations
    sent_invitations = db.query(ChatConversation).filter(
        or_(
            ChatConversation.user1_id == user.id,
            ChatConversation.user2_id == user.id
        ),
        ChatConversation.status == "pending",
        ChatConversation.initiator_id == user.id
    ).all()
    
    # Get active conversations
    active_conversations = db.query(ChatConversation).filter(
        or_(
            ChatConversation.user1_id == user.id,
            ChatConversation.user2_id == user.id
        ),
        ChatConversation.status == "active"
    ).order_by(ChatConversation.updated_at.desc()).all()
    
    for conv in active_conversations:
        other_id = conv.user2_id if conv.user1_id == user.id else conv.user1_id
        unread = db.query(ChatMessage).filter(
            ChatMessage.conversation_id == conv.id,
            ChatMessage.sender_id == other_id,
            ChatMessage.read_at.is_(None)
        ).count()
        conv.unread_count = unread
    
    # Get pending group invitations
    pending_group_invites = db.query(GroupInvitation).filter(
        GroupInvitation.invited_user_id == user.id,
        GroupInvitation.status == "pending"
    ).options(joinedload(GroupInvitation.group), joinedload(GroupInvitation.inviter)).all()
    
    # Get sent group invitations
    sent_group_invites = db.query(GroupInvitation).filter(
        GroupInvitation.inviter_id == user.id,
        GroupInvitation.status == "pending"
    ).options(joinedload(GroupInvitation.group), joinedload(GroupInvitation.invited_user)).all()
    
    csrf_token = generate_csrf_token(user.id, db)
    
    return templates.TemplateResponse("messages.html", {
        "request": request,
        "user": user,
        "pending_invitations": pending_invitations,
        "sent_invitations": sent_invitations,
        "active_conversations": active_conversations,
        "pending_group_invites": pending_group_invites,
        "sent_group_invites": sent_group_invites,
        "csrf_token": csrf_token
    })

# ============================================
# PRIVATE CHAT - WEBSOCKET
# ============================================

@router.websocket("/ws/{conversation_id}")
async def websocket_chat(
    websocket: WebSocket,
    conversation_id: int,
    session_token: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
):
    user = get_current_user(db, session_token)
    if not user:
        await websocket.close(code=1008, reason="Unauthorized")
        return

    conversation = db.query(ChatConversation).filter(
        ChatConversation.id == conversation_id,
        or_(
            ChatConversation.user1_id == user.id,
            ChatConversation.user2_id == user.id
        ),
        ChatConversation.status == "active"
    ).first()

    if not conversation:
        await websocket.close(code=1008, reason="Conversation not found")
        return

    other_user_id = conversation.user2_id if conversation.user1_id == user.id else conversation.user1_id

    if is_user_blocked(db, user.id, other_user_id) or is_user_blocked(db, other_user_id, user.id):
        await websocket.close(code=1008, reason="User blocked")
        return

    await websocket.accept()

    if conversation_id not in active_connections:
        active_connections[conversation_id] = set()
    active_connections[conversation_id].add(websocket)

    try:
        while True:
            data = await websocket.receive_text()
            message_data = json.loads(data)

            if message_data.get("type") == "message":
                content = message_data.get("content", "").strip()
                if not content:
                    continue

                expires_at = datetime.utcnow() + timedelta(hours=24)
                new_message = ChatMessage(
                    conversation_id=conversation_id,
                    sender_id=user.id,
                    encrypted_content=escape_html(content),
                    expires_at=expires_at,
                    delivered_at=datetime.utcnow()
                )
                db.add(new_message)
                db.commit()

                message_response = {
                    "id": new_message.id,
                    "sender_id": user.id,
                    "content": content,
                    "created_at": new_message.created_at.isoformat()
                }

                for conn in active_connections.get(conversation_id, set()):
                    try:
                        await conn.send_text(json.dumps({
                            "type": "new_message",
                            "message": message_response
                        }))
                    except:
                        pass

    except WebSocketDisconnect:
        if conversation_id in active_connections:
            active_connections[conversation_id].discard(websocket)
            if not active_connections[conversation_id]:
                del active_connections[conversation_id]

# ============================================
# PRIVATE CHAT - PAGES
# ============================================

@router.get("/{other_user_id}")
async def chat_page(
    request: Request,
    other_user_id: int,
    db: Session = Depends(get_db),
    session_token: Optional[str] = Cookie(None)
):
    user = get_current_user(db, session_token)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    if user.role not in ["pro", "premium", "owner"]:
        return templates.TemplateResponse("no_access.html", {
            "request": request,
            "user": user,
            "required_role": "Pro",
            "feature": "private chat"
        })

    other_user = db.query(User).filter(User.id == other_user_id, User.is_banned == False).first()
    if not other_user:
        return RedirectResponse(url="/chat", status_code=303)

    blocked_by_other = is_user_blocked(db, user.id, other_user_id)
    blocked_other = is_user_blocked(db, other_user_id, user.id)

    conversation = db.query(ChatConversation).filter(
        or_(
            and_(ChatConversation.user1_id == user.id, ChatConversation.user2_id == other_user_id),
            and_(ChatConversation.user1_id == other_user_id, ChatConversation.user2_id == user.id)
        )
    ).first()

    if not conversation:
        conversation = ChatConversation(
            user1_id=min(user.id, other_user_id),
            user2_id=max(user.id, other_user_id),
            initiator_id=user.id,
            status="active"
        )
        db.add(conversation)
        db.commit()
        db.refresh(conversation)

    cutoff = datetime.utcnow() - timedelta(hours=24)
    messages = db.query(ChatMessage).filter(
        ChatMessage.conversation_id == conversation.id,
        ChatMessage.created_at >= cutoff
    ).order_by(ChatMessage.created_at).all()

    active_conversations = db.query(ChatConversation).filter(
        or_(
            ChatConversation.user1_id == user.id,
            ChatConversation.user2_id == user.id
        ),
        ChatConversation.status == "active"
    ).order_by(ChatConversation.updated_at.desc()).limit(20).all()

    for conv in active_conversations:
        conv_other_id = conv.user2_id if conv.user1_id == user.id else conv.user1_id
        unread = db.query(ChatMessage).filter(
            ChatMessage.conversation_id == conv.id,
            ChatMessage.sender_id == conv_other_id,
            ChatMessage.read_at.is_(None)
        ).count()
        conv.unread_count = unread

    csrf_token = generate_csrf_token(user.id, db)

    return templates.TemplateResponse("chat.html", {
        "request": request,
        "user": user,
        "other_user": other_user,
        "conversation_id": conversation.id,
        "messages": messages,
        "active_conversations": active_conversations,
        "blocked_other": blocked_other,
        "blocked_by_other": blocked_by_other,
        "csrf_token": csrf_token
    })

# ============================================
# PRIVATE CHAT - ACTIONS
# ============================================

@router.post("/invite")
async def send_invite(
    username: str = Form(...),
    db: Session = Depends(get_db),
    session_token: Optional[str] = Cookie(None)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}

    if user.role not in ["pro", "premium", "owner"]:
        return {"success": False, "error": "Private chat requires Pro or Premium subscription"}

    target = db.query(User).filter(func.lower(User.username) == username.lower(), User.is_banned == False).first()
    if not target:
        return {"success": False, "error": "User not found"}

    if target.id == user.id:
        return {"success": False, "error": "You cannot invite yourself"}

    if target.is_banned:
        return {"success": False, "error": "Cannot invite this user"}

    if is_user_blocked(db, user.id, target.id):
        return {"success": False, "error": "This user has blocked you"}

    if is_user_blocked(db, target.id, user.id):
        return {"success": False, "error": "You have blocked this user"}

    existing = db.query(ChatConversation).filter(
        or_(
            and_(ChatConversation.user1_id == user.id, ChatConversation.user2_id == target.id),
            and_(ChatConversation.user1_id == target.id, ChatConversation.user2_id == user.id)
        )
    ).first()

    if existing:
        if existing.status == "active":
            return {"success": False, "error": "You already have an active chat with this user"}
        elif existing.status == "pending":
            if existing.initiator_id == user.id:
                return {"success": False, "error": "Invitation already sent"}
            else:
                existing.status = "active"
                db.commit()
                return {"success": True, "message": "Invitation accepted! You can now chat."}

    conversation = ChatConversation(
        user1_id=min(user.id, target.id),
        user2_id=max(user.id, target.id),
        initiator_id=user.id,
        status="pending"
    )
    db.add(conversation)
    db.commit()

    return {"success": True, "message": f"Invitation sent to {target.username}"}

@router.post("/invite/accept/{invite_id}")
async def accept_invite(invite_id: int, db: Session = Depends(get_db), session_token: Optional[str] = Cookie(None)):
    user = get_current_user(db, session_token)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    invitation = db.query(ChatConversation).filter(ChatConversation.id == invite_id, ChatConversation.status == "pending").first()
    if not invitation or (invitation.user1_id != user.id and invitation.user2_id != user.id):
        return RedirectResponse(url="/chat", status_code=303)

    if invitation.initiator_id == user.id:
        return RedirectResponse(url="/chat", status_code=303)

    invitation.status = "active"
    db.commit()

    return RedirectResponse(url=f"/chat/{invitation.user1_id if invitation.user2_id == user.id else invitation.user2_id}", status_code=303)

@router.post("/invite/decline/{invite_id}")
async def decline_invite(invite_id: int, db: Session = Depends(get_db), session_token: Optional[str] = Cookie(None)):
    user = get_current_user(db, session_token)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    invitation = db.query(ChatConversation).filter(ChatConversation.id == invite_id, ChatConversation.status == "pending").first()
    if not invitation or (invitation.user1_id != user.id and invitation.user2_id != user.id):
        return RedirectResponse(url="/chat", status_code=303)

    if invitation.initiator_id == user.id:
        return RedirectResponse(url="/chat", status_code=303)

    db.delete(invitation)
    db.commit()

    return RedirectResponse(url="/chat", status_code=303)

@router.post("/invite/cancel/{invite_id}")
async def cancel_invite(invite_id: int, db: Session = Depends(get_db), session_token: Optional[str] = Cookie(None)):
    user = get_current_user(db, session_token)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    invitation = db.query(ChatConversation).filter(ChatConversation.id == invite_id, ChatConversation.status == "pending", ChatConversation.initiator_id == user.id).first()
    if not invitation:
        return RedirectResponse(url="/chat", status_code=303)

    db.delete(invitation)
    db.commit()

    return RedirectResponse(url="/chat", status_code=303)

@router.post("/send")
async def send_message(
    recipient_id: int = Form(...),
    content: str = Form(...),
    db: Session = Depends(get_db),
    session_token: Optional[str] = Cookie(None)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}

    if user.role not in ["pro", "premium", "owner"]:
        return {"success": False, "error": "Chat requires Pro or Premium subscription"}

    recipient = db.query(User).filter(User.id == recipient_id, User.is_banned == False).first()
    if not recipient:
        return {"success": False, "error": "Recipient not found"}

    if is_user_blocked(db, user.id, recipient.id) or is_user_blocked(db, recipient.id, user.id):
        return {"success": False, "error": "Cannot send message"}

    conversation = db.query(ChatConversation).filter(
        or_(
            and_(ChatConversation.user1_id == user.id, ChatConversation.user2_id == recipient.id),
            and_(ChatConversation.user1_id == recipient.id, ChatConversation.user2_id == user.id)
        )
    ).first()

    if not conversation:
        conversation = ChatConversation(
            user1_id=min(user.id, recipient.id),
            user2_id=max(user.id, recipient.id),
            initiator_id=user.id,
            status="active"
        )
        db.add(conversation)
        db.commit()
        db.refresh(conversation)

    expires_at = datetime.utcnow() + timedelta(hours=24)
    new_message = ChatMessage(
        conversation_id=conversation.id,
        sender_id=user.id,
        encrypted_content=escape_html(content),
        expires_at=expires_at,
        delivered_at=datetime.utcnow()
    )
    db.add(new_message)
    db.commit()

    return {"success": True, "message": {"id": new_message.id}}

@router.post("/block/{user_id}")
async def block_user(
    user_id: int,
    db: Session = Depends(get_db),
    session_token: Optional[str] = Cookie(None)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}

    if user.id == user_id:
        return {"success": False, "error": "Cannot block yourself"}

    existing = db.query(BlockedUser).filter(
        BlockedUser.user_id == user.id,
        BlockedUser.blocked_user_id == user_id
    ).first()

    if existing:
        return {"success": True, "message": "User already blocked"}

    block = BlockedUser(user_id=user.id, blocked_user_id=user_id)
    db.add(block)
    db.commit()

    return {"success": True, "message": "User blocked"}

@router.post("/unblock/{user_id}")
async def unblock_user(
    user_id: int,
    db: Session = Depends(get_db),
    session_token: Optional[str] = Cookie(None)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}

    block = db.query(BlockedUser).filter(
        BlockedUser.user_id == user.id,
        BlockedUser.blocked_user_id == user_id
    ).first()

    if not block:
        return {"success": False, "error": "User not blocked"}

    db.delete(block)
    db.commit()

    return {"success": True, "message": "User unblocked"}

@router.get("/blocked/list")
async def get_blocked_users(
    db: Session = Depends(get_db),
    session_token: Optional[str] = Cookie(None)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}

    blocked = db.query(BlockedUser).filter(BlockedUser.user_id == user.id).all()
    blocked_users = []
    for b in blocked:
        target = db.query(User).filter(User.id == b.blocked_user_id).first()
        if target:
            blocked_users.append({"id": target.id, "username": target.username})

    return {"success": True, "blocked_users": blocked_users}

@router.get("/search/global")
async def global_search_messages(
    q: str,
    db: Session = Depends(get_db),
    session_token: Optional[str] = Cookie(None)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}

    if user.role not in ["pro", "premium", "owner"]:
        return {"success": False, "error": "Search requires Pro or Premium subscription"}

    conversations = db.query(ChatConversation).filter(
        or_(
            ChatConversation.user1_id == user.id,
            ChatConversation.user2_id == user.id
        ),
        ChatConversation.status == "active"
    ).all()

    conversation_ids = [c.id for c in conversations]

    results = db.query(ChatMessage).filter(
        ChatMessage.conversation_id.in_(conversation_ids),
        ChatMessage.encrypted_content.ilike(f"%{q}%"),
        ChatMessage.created_at >= datetime.utcnow() - timedelta(days=30)
    ).order_by(ChatMessage.created_at.desc()).limit(50).all()

    result_list = []
    for msg in results:
        conversation = next((c for c in conversations if c.id == msg.conversation_id), None)
        if conversation:
            other_user_id = conversation.user2_id if conversation.user1_id == user.id else conversation.user1_id
            other_user = db.query(User).filter(User.id == other_user_id).first()
            sender = db.query(User).filter(User.id == msg.sender_id).first()
            result_list.append({
                "id": msg.id,
                "conversation_id": msg.conversation_id,
                "other_user_id": other_user_id,
                "other_user": other_user.username if other_user else "Unknown",
                "sender": sender.username if sender else "Unknown",
                "content": msg.encrypted_content[:200],
                "created_at": msg.created_at.isoformat()
            })

    return {"success": True, "results": result_list}

@router.post("/settings/read_receipts")
async def update_read_receipts_setting(
    enabled: bool = Form(...),
    db: Session = Depends(get_db),
    session_token: Optional[str] = Cookie(None)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}

    if user.role not in ["premium", "owner"]:
        return {"success": False, "error": "Read receipts setting requires Premium subscription"}

    user.read_receipts_enabled = enabled
    db.commit()

    return {"success": True, "message": f"Read receipts {'enabled' if enabled else 'disabled'}"}

# ============================================
# GROUP CHAT - WEBSOCKET
# ============================================

@router.websocket("/ws/group/{group_id}")
async def websocket_group_chat(
    websocket: WebSocket,
    group_id: int,
    session_token: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
):
    user = get_current_user(db, session_token)
    if not user:
        await websocket.close(code=1008, reason="Unauthorized")
        return

    membership = db.query(GroupMember).filter(
        GroupMember.group_id == group_id,
        GroupMember.user_id == user.id
    ).first()

    if not membership:
        await websocket.close(code=1008, reason="Not a member of this group")
        return

    await websocket.accept()

    if group_id not in group_active_connections:
        group_active_connections[group_id] = set()
    group_active_connections[group_id].add(websocket)

    try:
        while True:
            data = await websocket.receive_text()
            message_data = json.loads(data)

            if message_data.get("type") == "message":
                content = message_data.get("content", "").strip()
                if not content:
                    continue

                if len(content) > 500:
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": "Message exceeds 500 character limit"
                    }))
                    continue

                expires_at = datetime.utcnow() + timedelta(hours=24)
                new_message = GroupChatMessage(
                    group_id=group_id,
                    sender_id=user.id,
                    encrypted_content=escape_html(content),
                    expires_at=expires_at,
                    delivered_at=datetime.utcnow()
                )
                db.add(new_message)
                db.commit()
                db.refresh(new_message)

                message_response = {
                    "id": new_message.id,
                    "sender_id": user.id,
                    "sender_username": user.username,
                    "content": content,
                    "created_at": new_message.created_at.isoformat(),
                    "reactions": []
                }

                for conn in group_active_connections.get(group_id, set()):
                    try:
                        await conn.send_text(json.dumps({
                            "type": "new_group_message",
                            "message": message_response
                        }))
                    except:
                        pass

    except WebSocketDisconnect:
        if group_id in group_active_connections:
            group_active_connections[group_id].discard(websocket)
            if not group_active_connections[group_id]:
                del group_active_connections[group_id]

# ============================================
# GROUP CHAT - PAGES & ACTIONS
# ============================================

@router.get("/groups")
async def groups_page(request: Request, db: Session = Depends(get_db), session_token: Optional[str] = Cookie(None)):
    user = get_current_user(db, session_token)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    if user.role not in ["premium", "owner"]:
        return templates.TemplateResponse("no_access.html", {
            "request": request,
            "user": user,
            "required_role": "Premium",
            "feature": "group chats"
        })

    groups = db.query(ChatGroup).join(GroupMember, ChatGroup.id == GroupMember.group_id).filter(GroupMember.user_id == user.id).all()

    return templates.TemplateResponse("groups.html", {"request": request, "user": user, "groups": groups})

@router.get("/group/{group_id}")
async def get_group_chat(
    group_id: int,
    db: Session = Depends(get_db),
    session_token: Optional[str] = Cookie(None)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}

    group = db.query(ChatGroup).filter(ChatGroup.id == group_id).first()
    if not group:
        return {"success": False, "error": "Group not found"}

    membership = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == user.id).first()
    if not membership:
        return {"success": False, "error": "You are not a member of this group"}

    cutoff = datetime.utcnow() - timedelta(hours=24)
    messages = db.query(GroupChatMessage).filter(
        GroupChatMessage.group_id == group_id,
        GroupChatMessage.created_at >= cutoff
    ).order_by(GroupChatMessage.created_at).all()

    members = db.query(GroupMember).filter(GroupMember.group_id == group_id).options(joinedload(GroupMember.user)).all()

    messages_data = []
    for msg in messages:
        messages_data.append({
            "id": msg.id,
            "sender_id": msg.sender_id,
            "sender_username": msg.sender.username if msg.sender else "Unknown",
            "content": msg.encrypted_content,
            "created_at": msg.created_at.isoformat()
        })

    members_data = []
    for m in members:
        members_data.append({
            "id": m.user.id,
            "username": m.user.username,
            "role": m.role
        })

    return {
        "success": True,
        "group": {
            "id": group.id,
            "name": group.name,
            "description": group.description,
            "created_at": group.created_at.isoformat(),
            "created_by": group.created_by.username if group.created_by else "Unknown"
        },
        "messages": messages_data,
        "members": members_data,
        "user_role": membership.role
    }

@router.post("/group/create")
async def create_group(
    name: str = Form(...),
    description: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    session_token: Optional[str] = Cookie(None)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}

    if user.role not in ["premium", "owner"]:
        return {"success": False, "error": "Group chats require Premium subscription"}

    if len(name) < 3 or len(name) > 50:
        return {"success": False, "error": "Group name must be 3-50 characters"}

    group = ChatGroup(
        name=escape_html(name),
        description=escape_html(description) if description else None,
        created_by_id=user.id
    )
    db.add(group)
    db.commit()
    db.refresh(group)

    membership = GroupMember(
        group_id=group.id,
        user_id=user.id,
        role="owner"
    )
    db.add(membership)
    db.commit()

    return {"success": True, "name": group.name, "group_id": group.id}

@router.post("/group/invite/{group_id}")
async def invite_to_group(
    group_id: int,
    username: str = Form(...),
    db: Session = Depends(get_db),
    session_token: Optional[str] = Cookie(None)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}

    membership = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == user.id).first()
    if not membership or membership.role not in ["owner", "admin"]:
        return {"success": False, "error": "You don't have permission to invite users"}

    invited_user = db.query(User).filter(func.lower(User.username) == username.lower(), User.is_banned == False).first()
    if not invited_user:
        return {"success": False, "error": "User not found"}

    if invited_user.id == user.id:
        return {"success": False, "error": "You cannot invite yourself"}

    existing_member = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == invited_user.id).first()
    if existing_member:
        return {"success": False, "error": "User is already a member"}

    existing_invite = db.query(GroupInvitation).filter(
        GroupInvitation.group_id == group_id,
        GroupInvitation.invited_user_id == invited_user.id,
        GroupInvitation.status == "pending"
    ).first()

    if existing_invite:
        return {"success": False, "error": "Invitation already sent"}

    invite = GroupInvitation(
        group_id=group_id,
        inviter_id=user.id,
        invited_user_id=invited_user.id,
        status="pending"
    )
    db.add(invite)
    db.commit()

    return {"success": True, "message": f"Invitation sent to {invited_user.username}"}

@router.post("/group/invite/accept/{invite_id}")
async def accept_group_invite(
    invite_id: int,
    db: Session = Depends(get_db),
    session_token: Optional[str] = Cookie(None)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}

    invite = db.query(GroupInvitation).filter(GroupInvitation.id == invite_id, GroupInvitation.invited_user_id == user.id, GroupInvitation.status == "pending").first()
    if not invite:
        return {"success": False, "error": "Invitation not found"}

    membership = GroupMember(
        group_id=invite.group_id,
        user_id=user.id,
        role="member"
    )
    db.add(membership)

    invite.status = "accepted"
    db.commit()

    return {"success": True, "message": "You have joined the group"}

@router.post("/group/leave/{group_id}")
async def leave_group(
    group_id: int,
    db: Session = Depends(get_db),
    session_token: Optional[str] = Cookie(None)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}

    membership = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == user.id).first()
    if not membership:
        return {"success": False, "error": "You are not a member of this group"}

    db.delete(membership)
    db.commit()

    return {"success": True, "message": "You have left the group"}

@router.post("/group/delete/{group_id}")
async def delete_group(
    group_id: int,
    db: Session = Depends(get_db),
    session_token: Optional[str] = Cookie(None)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}

    membership = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == user.id, GroupMember.role == "owner").first()
    if not membership:
        return {"success": False, "error": "Only the group owner can delete the group"}

    group = db.query(ChatGroup).filter(ChatGroup.id == group_id).first()
    if not group:
        return {"success": False, "error": "Group not found"}

    db.query(GroupMember).filter(GroupMember.group_id == group_id).delete()
    db.query(GroupInvitation).filter(GroupInvitation.group_id == group_id).delete()
    db.delete(group)
    db.commit()

    return {"success": True, "message": "Group deleted"}

@router.post("/group/promote_member/{group_id}")
async def promote_member(
    group_id: int,
    user_id: int = Form(...),
    db: Session = Depends(get_db),
    session_token: Optional[str] = Cookie(None)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}

    membership = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == user.id).first()
    if not membership or membership.role not in ["owner", "admin"]:
        return {"success": False, "error": "You don't have permission to promote members"}

    target_membership = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == user_id).first()
    if not target_membership:
        return {"success": False, "error": "User is not a member of this group"}

    if target_membership.role == "owner":
        return {"success": False, "error": "Cannot promote the owner"}

    target_membership.role = "admin"
    db.commit()

    return {"success": True, "message": "User promoted to admin"}

@router.post("/group/remove_member/{group_id}")
async def remove_member(
    group_id: int,
    user_id: int = Form(...),
    db: Session = Depends(get_db),
    session_token: Optional[str] = Cookie(None)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}

    membership = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == user.id).first()
    if not membership or membership.role not in ["owner", "admin"]:
        return {"success": False, "error": "You don't have permission to remove members"}

    target_membership = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == user_id).first()
    if not target_membership:
        return {"success": False, "error": "User is not a member of this group"}

    if target_membership.role == "owner":
        return {"success": False, "error": "Cannot remove the owner"}

    db.delete(target_membership)
    db.commit()

    return {"success": True, "message": "User removed from group"}

@router.post("/group/update_bio/{group_id}")
async def update_group_bio(
    group_id: int,
    description: str = Form(""),
    db: Session = Depends(get_db),
    session_token: Optional[str] = Cookie(None)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}

    membership = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == user.id).first()
    if not membership or membership.role not in ["owner", "admin"]:
        return {"success": False, "error": "You don't have permission to edit the group description"}

    group = db.query(ChatGroup).filter(ChatGroup.id == group_id).first()
    if not group:
        return {"success": False, "error": "Group not found"}

    group.description = escape_html(description) if description else None
    db.commit()

    return {"success": True, "message": "Group description updated"}
