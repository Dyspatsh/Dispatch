from fastapi import APIRouter, Request, Form, Depends, HTTPException, WebSocket, WebSocketDisconnect, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import func, or_, and_
from datetime import datetime, timedelta
import json
import secrets
import asyncio
import os
import logging
import re

from database import get_db, User, ChatConversation, ChatMessage, BlockedUser, Session as DBSession, ChatGroup, GroupMember, GroupChatMessage, MessageReaction, MessageReadReceipt, GroupInvitation, SecurityLog
from roles import check_chat_access, get_chat_char_limit

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/chat", tags=["chat"])
templates = Jinja2Templates(directory="templates")

online_users = {}
user_unread_counts = {}

def escape_html(text: str) -> str:
    if not text:
        return ""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")

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

def can_create_group(user) -> bool:
    return user.role in ['premium', 'owner']

def validate_group_name(name: str) -> tuple:
    if len(name) < 3:
        return False, "Group name must be at least 3 characters"
    if len(name) > 50:
        return False, "Group name cannot exceed 50 characters"
    if not re.match(r'^[a-zA-Z0-9_\-\s]+$', name):
        return False, "Group name can only contain letters, numbers, spaces, underscores, and hyphens"
    return True, ""

class ConnectionManager:
    def __init__(self):
        self.active_connections: dict = {}
        self.group_connections: dict = {}

    async def connect(self, websocket: WebSocket, user_id: int, group_id: int = None):
        await websocket.accept()
        if group_id:
            if group_id not in self.group_connections:
                self.group_connections[group_id] = {}
            self.group_connections[group_id][user_id] = websocket
        else:
            self.active_connections[user_id] = websocket
            online_users[user_id] = True
            await self.broadcast_status(user_id, "online")

    def disconnect(self, user_id: int, group_id: int = None):
        if group_id:
            if group_id in self.group_connections and user_id in self.group_connections[group_id]:
                del self.group_connections[group_id][user_id]
        else:
            if user_id in self.active_connections:
                del self.active_connections[user_id]
            if user_id in online_users:
                del online_users[user_id]
            asyncio.create_task(self.broadcast_status(user_id, "offline"))

    async def send_message(self, user_id: int, message: dict, group_id: int = None):
        if group_id:
            if group_id in self.group_connections and user_id in self.group_connections[group_id]:
                try:
                    await self.group_connections[group_id][user_id].send_json(message)
                    return True
                except:
                    pass
        else:
            if user_id in self.active_connections:
                try:
                    await self.active_connections[user_id].send_json(message)
                    return True
                except:
                    pass
        return False

    async def broadcast_to_group(self, group_id: int, message: dict, exclude_user_id: int = None):
        if group_id in self.group_connections:
            for user_id, connection in self.group_connections[group_id].items():
                if user_id != exclude_user_id:
                    try:
                        await connection.send_json(message)
                    except:
                        pass

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

@router.post("/settings/read_receipts")
async def update_read_receipts_setting(
    request: Request,
    enabled: bool = Form(...),
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}
    
    if not enabled and user.role not in ["premium", "owner"]:
        return {"success": False, "error": "Read receipts can only be disabled by Premium users"}
    
    user.read_receipts_enabled = enabled
    db.commit()
    log_security_event(db, user.id, f"Read receipts {'disabled' if not enabled else 'enabled'}", "read_receipts", None, request)
    
    return {"success": True, "message": f"Read receipts {'enabled' if enabled else 'disabled'}"}

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
    
    pending_group_invites = db.query(GroupInvitation).filter(
        GroupInvitation.invited_user_id == user.id,
        GroupInvitation.status == "pending"
    ).all()
    
    sent_group_invites = db.query(GroupInvitation).filter(
        GroupInvitation.inviter_id == user.id,
        GroupInvitation.status == "pending"
    ).all()
    
    for conv in active_conversations:
        conv.unread_count = get_unread_count(db, user.id, conv.id)
        if conv.unread_count > 0:
            user_unread_counts[f"{user.id}_{conv.id}"] = conv.unread_count
    
    return templates.TemplateResponse("messages.html", {
        "request": request,
        "user": user,
        "pending_invitations": pending_invitations,
        "sent_invitations": sent_invitations,
        "active_conversations": active_conversations,
        "online_users": online_users,
        "pending_group_invites": pending_group_invites,
        "sent_group_invites": sent_group_invites
    })

@router.get("/groups")
async def groups_page(request: Request, session_token: str = Cookie(None), db: Session = Depends(get_db)):
    user = get_current_user(db, session_token)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    
    groups = db.query(GroupMember).filter(GroupMember.user_id == user.id).options(joinedload(GroupMember.group)).all()
    user_groups = [gm.group for gm in groups]
    
    return templates.TemplateResponse("groups.html", {
        "request": request,
        "user": user,
        "groups": user_groups
    })

@router.post("/group/update_bio/{group_id}")
async def update_group_bio(
    request: Request,
    group_id: int,
    description: str = Form(""),
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}
    
    group = db.query(ChatGroup).filter(ChatGroup.id == group_id).first()
    if not group:
        return {"success": False, "error": "Group not found"}
    
    membership = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == user.id).first()
    if not membership or membership.role not in ["owner", "admin"]:
        return {"success": False, "error": "Only group owners and admins can edit the description"}
    
    group.description = escape_html(description) if description else None
    db.commit()
    log_security_event(db, user.id, f"Group description updated: {group.name}", "group_update", None, request)
    
    return {"success": True, "message": "Description updated"}

@router.get("/group/{group_id}")
async def get_group_data(group_id: int, session_token: str = Cookie(None), db: Session = Depends(get_db)):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}
    
    group = db.query(ChatGroup).filter(ChatGroup.id == group_id).first()
    if not group:
        return {"success": False, "error": "Group not found"}
    
    membership = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == user.id).first()
    if not membership:
        return {"success": False, "error": "You are not a member of this group"}
    
    messages = db.query(GroupChatMessage).filter(GroupChatMessage.group_id == group_id).order_by(GroupChatMessage.created_at).all()
    
    members = db.query(GroupMember).filter(GroupMember.group_id == group_id).options(joinedload(GroupMember.user)).all()
    members_list = []
    for m in members:
        members_list.append({
            "id": m.user.id,
            "username": m.user.username,
            "role": m.role
        })
    
    messages_list = []
    for msg in messages:
        read_count = db.query(MessageReadReceipt).filter(MessageReadReceipt.message_id == msg.id).count()
        messages_list.append({
            "id": msg.id,
            "sender_id": msg.sender_id,
            "sender_username": msg.sender.username,
            "content": msg.encrypted_content,
            "created_at": msg.created_at.isoformat(),
            "expires_at": msg.expires_at.isoformat(),
            "read_count": read_count,
            "member_count": len(members_list),
            "reactions": []
        })
    
    return {
        "success": True,
        "group": {
            "id": group.id,
            "name": group.name,
            "description": group.description,
            "created_at": group.created_at.isoformat(),
            "created_by": group.created_by.username
        },
        "members": members_list,
        "messages": messages_list,
        "user_role": membership.role
    }

@router.post("/group/create")
async def create_group(
    request: Request,
    name: str = Form(...),
    description: str = Form(None),
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}
    
    if not can_create_group(user):
        return {"success": False, "error": "Group creation requires Premium subscription"}
    
    name = escape_html(name)
    if description:
        description = escape_html(description)
    
    valid, error = validate_group_name(name)
    if not valid:
        return {"success": False, "error": error}
    
    new_group = ChatGroup(
        name=name,
        description=description,
        created_by_id=user.id
    )
    db.add(new_group)
    db.commit()
    db.refresh(new_group)
    
    member = GroupMember(
        group_id=new_group.id,
        user_id=user.id,
        role="owner"
    )
    db.add(member)
    db.commit()
    
    log_security_event(db, user.id, f"Group created: {name}", "group_create", None, request)
    
    return {"success": True, "group_id": new_group.id, "name": new_group.name}

@router.post("/group/invite/{group_id}")
async def invite_to_group(
    request: Request,
    group_id: int,
    username: str = Form(...),
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}
    
    group = db.query(ChatGroup).filter(ChatGroup.id == group_id).first()
    if not group:
        return {"success": False, "error": "Group not found"}
    
    membership = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == user.id).first()
    if not membership or membership.role not in ["owner", "admin"]:
        return {"success": False, "error": "Only group owners and admins can invite users"}
    
    username = escape_html(username)
    target_user = db.query(User).filter(func.lower(User.username) == username.lower()).first()
    if not target_user:
        return {"success": False, "error": "User not found"}
    
    existing = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == target_user.id).first()
    if existing:
        return {"success": False, "error": "User already in group"}
    
    existing_invite = db.query(GroupInvitation).filter(
        GroupInvitation.group_id == group_id,
        GroupInvitation.invited_user_id == target_user.id,
        GroupInvitation.status == "pending"
    ).first()
    if existing_invite:
        return {"success": False, "error": "Invitation already pending"}
    
    new_invite = GroupInvitation(
        group_id=group_id,
        inviter_id=user.id,
        invited_user_id=target_user.id,
        status="pending"
    )
    db.add(new_invite)
    db.commit()
    
    log_security_event(db, user.id, f"Invited {target_user.username} to group {group.name}", "group_invite", None, request)
    
    return {"success": True, "message": f"Invitation sent to {target_user.username}"}

@router.post("/group/invite/accept/{invitation_id}")
async def accept_group_invitation(
    request: Request,
    invitation_id: int,
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}
    
    invitation = db.query(GroupInvitation).filter(GroupInvitation.id == invitation_id).first()
    if not invitation or invitation.invited_user_id != user.id or invitation.status != "pending":
        return {"success": False, "error": "Invalid invitation"}
    
    new_member = GroupMember(
        group_id=invitation.group_id,
        user_id=user.id,
        role="member"
    )
    db.add(new_member)
    
    invitation.status = "accepted"
    db.commit()
    
    log_security_event(db, user.id, f"Accepted invitation to group {invitation.group.name}", "group_join", None, request)
    
    return {"success": True, "group_id": invitation.group_id}

@router.post("/group/invite/decline/{invitation_id}")
async def decline_group_invitation(
    request: Request,
    invitation_id: int,
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}
    
    invitation = db.query(GroupInvitation).filter(GroupInvitation.id == invitation_id).first()
    if not invitation or invitation.invited_user_id != user.id or invitation.status != "pending":
        return {"success": False, "error": "Invalid invitation"}
    
    invitation.status = "declined"
    db.commit()
    
    log_security_event(db, user.id, f"Declined invitation to group {invitation.group.name}", "group_decline", None, request)
    
    return {"success": True}

@router.post("/group/invite/cancel/{invitation_id}")
async def cancel_group_invitation(
    request: Request,
    invitation_id: int,
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}
    
    invitation = db.query(GroupInvitation).filter(GroupInvitation.id == invitation_id).first()
    if not invitation or invitation.inviter_id != user.id or invitation.status != "pending":
        return {"success": False, "error": "Invalid invitation"}
    
    db.delete(invitation)
    db.commit()
    
    log_security_event(db, user.id, f"Cancelled invitation to group {invitation.group.name}", "group_cancel_invite", None, request)
    
    return {"success": True}

@router.post("/group/send/{group_id}")
async def send_group_message(
    request: Request,
    group_id: int,
    content: str = Form(...),
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}
    
    membership = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == user.id).first()
    if not membership:
        return {"success": False, "error": "You are not a member of this group"}
    
    content = escape_html(content)
    
    char_limit = get_chat_char_limit(user)
    if char_limit > 0 and len(content) > char_limit:
        return {"success": False, "error": f"Message exceeds {char_limit} character limit"}
    if not content or len(content.strip()) == 0:
        return {"success": False, "error": "Message cannot be empty"}
    
    expires_at = datetime.utcnow() + timedelta(hours=24)
    new_message = GroupChatMessage(
        group_id=group_id,
        sender_id=user.id,
        encrypted_content=content,
        expires_at=expires_at,
        delivered_at=datetime.utcnow()
    )
    db.add(new_message)
    db.commit()
    
    await manager.broadcast_to_group(group_id, {
        "type": "new_group_message",
        "message": {
            "id": new_message.id,
            "sender_id": user.id,
            "sender_username": user.username,
            "content": content,
            "created_at": new_message.created_at.isoformat(),
            "expires_at": expires_at.isoformat()
        }
    })
    
    return {"success": True, "message": {"id": new_message.id, "content": content, "created_at": new_message.created_at.isoformat()}}

@router.post("/group/mark_read/{message_id}")
async def mark_group_message_read(
    request: Request,
    message_id: int,
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}
    
    if not user.read_receipts_enabled:
        return {"success": True}
    
    message = db.query(GroupChatMessage).filter(GroupChatMessage.id == message_id).first()
    if not message:
        return {"success": False, "error": "Message not found"}
    
    existing = db.query(MessageReadReceipt).filter(
        MessageReadReceipt.message_id == message_id,
        MessageReadReceipt.user_id == user.id
    ).first()
    
    if not existing:
        receipt = MessageReadReceipt(
            message_id=message_id,
            user_id=user.id
        )
        db.add(receipt)
        db.commit()
        
        read_count = db.query(MessageReadReceipt).filter(MessageReadReceipt.message_id == message_id).count()
        member_count = db.query(GroupMember).filter(GroupMember.group_id == message.group_id).count()
        
        await manager.broadcast_to_group(message.group_id, {
            "type": "message_read",
            "message_id": message_id,
            "user_id": user.id,
            "read_count": read_count,
            "total_members": member_count
        })
    
    return {"success": True}

@router.post("/group/react/{message_id}")
async def add_group_reaction(
    message_id: int,
    reaction_type: str = Form(...),
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}
    
    allowed_reactions = ["like", "thanks", "agree", "helpful"]
    if reaction_type not in allowed_reactions:
        return {"success": False, "error": "Invalid reaction type"}
    
    message = db.query(GroupChatMessage).filter(GroupChatMessage.id == message_id).first()
    if not message:
        return {"success": False, "error": "Message not found"}
    
    existing = db.query(MessageReaction).filter(
        MessageReaction.message_id == message_id,
        MessageReaction.user_id == user.id
    ).first()
    
    if existing:
        if existing.reaction_type == reaction_type:
            db.delete(existing)
            db.commit()
            await manager.broadcast_to_group(message.group_id, {
                "type": "message_reaction",
                "message_id": message_id,
                "user_id": user.id,
                "reaction_type": reaction_type,
                "action": "removed"
            })
            return {"success": True, "action": "removed"}
        else:
            existing.reaction_type = reaction_type
            db.commit()
            await manager.broadcast_to_group(message.group_id, {
                "type": "message_reaction",
                "message_id": message_id,
                "user_id": user.id,
                "reaction_type": reaction_type,
                "action": "updated"
            })
            return {"success": True, "action": "updated"}
    else:
        new_reaction = MessageReaction(
            message_id=message_id,
            user_id=user.id,
            reaction_type=reaction_type
        )
        db.add(new_reaction)
        db.commit()
        
        await manager.broadcast_to_group(message.group_id, {
            "type": "message_reaction",
            "message_id": message_id,
            "user_id": user.id,
            "reaction_type": reaction_type,
            "action": "added"
        })
        
        return {"success": True, "action": "added"}

@router.post("/group/remove_member/{group_id}")
async def remove_group_member(
    request: Request,
    group_id: int,
    user_id: int = Form(...),
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    admin = get_current_user(db, session_token)
    if not admin:
        return {"success": False, "error": "Not authenticated"}
    
    group = db.query(ChatGroup).filter(ChatGroup.id == group_id).first()
    if not group:
        return {"success": False, "error": "Group not found"}
    
    admin_membership = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == admin.id).first()
    if not admin_membership or admin_membership.role not in ["owner", "admin"]:
        return {"success": False, "error": "Only group owners and admins can remove members"}
    
    target_membership = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == user_id).first()
    if not target_membership:
        return {"success": False, "error": "User is not a member of this group"}
    
    if target_membership.role == "owner":
        return {"success": False, "error": "Cannot remove group owner"}
    
    if target_membership.role == "admin" and admin_membership.role != "owner":
        return {"success": False, "error": "Only group owner can remove admins"}
    
    db.delete(target_membership)
    db.commit()
    
    log_security_event(db, admin.id, f"Removed user {user_id} from group {group.name}", "group_remove_member", None, request)
    
    return {"success": True, "message": "User removed from group"}

@router.post("/group/promote_member/{group_id}")
async def promote_group_member(
    request: Request,
    group_id: int,
    user_id: int = Form(...),
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    admin = get_current_user(db, session_token)
    if not admin:
        return {"success": False, "error": "Not authenticated"}
    
    group = db.query(ChatGroup).filter(ChatGroup.id == group_id).first()
    if not group:
        return {"success": False, "error": "Group not found"}
    
    admin_membership = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == admin.id).first()
    if not admin_membership or admin_membership.role not in ["owner", "admin"]:
        return {"success": False, "error": "Only group owners and admins can promote members"}
    
    target_membership = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == user_id).first()
    if not target_membership:
        return {"success": False, "error": "User is not a member of this group"}
    
    if target_membership.role == "owner":
        return {"success": False, "error": "Cannot promote group owner"}
    
    if target_membership.role == "admin" and admin_membership.role != "owner":
        return {"success": False, "error": "Only group owner can promote admins"}
    
    target_membership.role = "admin"
    db.commit()
    
    log_security_event(db, admin.id, f"Promoted user {user_id} to admin in group {group.name}", "group_promote", None, request)
    
    return {"success": True, "message": "User promoted to admin"}

@router.post("/group/leave/{group_id}")
async def leave_group(
    request: Request,
    group_id: int,
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}
    
    membership = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == user.id).first()
    if not membership:
        return {"success": False, "error": "You are not a member of this group"}
    
    if membership.role == "owner":
        oldest_admin = db.query(GroupMember).filter(
            GroupMember.group_id == group_id,
            GroupMember.role == "admin"
        ).order_by(GroupMember.joined_at).first()
        
        if oldest_admin:
            oldest_admin.role = "owner"
            db.delete(membership)
            db.commit()
            log_security_event(db, user.id, f"Left group {group_id}, ownership transferred", "group_leave", None, request)
            return {"success": True, "message": "You left the group. Ownership transferred to another admin."}
        else:
            db.delete(membership)
            group = db.query(ChatGroup).filter(ChatGroup.id == group_id).first()
            if group:
                db.delete(group)
            db.commit()
            log_security_event(db, user.id, f"Left and deleted group {group_id} (last member)", "group_delete", None, request)
            return {"success": True, "message": "You left the group. Group was deleted as you were the only member."}
    else:
        db.delete(membership)
        db.commit()
        log_security_event(db, user.id, f"Left group {group_id}", "group_leave", None, request)
        return {"success": True, "message": "You left the group"}

@router.post("/group/delete/{group_id}")
async def delete_group(
    request: Request,
    group_id: int,
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}
    
    membership = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == user.id).first()
    if not membership or membership.role != "owner":
        return {"success": False, "error": "Only group owner can delete the group"}
    
    group = db.query(ChatGroup).filter(ChatGroup.id == group_id).first()
    if group:
        group_name = group.name
        db.delete(group)
        db.commit()
        log_security_event(db, user.id, f"Deleted group {group_name}", "group_delete", None, request)
    
    return {"success": True, "message": "Group deleted"}

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
    
    return templates.TemplateResponse("chat.html", {
        "request": request,
        "user": user,
        "other_user": other_user,
        "other_user_online": other_user_online,
        "conversation_id": conv.id,
        "active_conversations": active_conversations,
        "messages": messages,
        "blocked_by_other": blocked_by_other,
        "blocked_other": blocked_other
    })

@router.post("/send")
async def send_message(
    request: Request,
    recipient_id: int = Form(...),
    content: str = Form(...),
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}
    if not check_chat_access(user):
        return {"success": False, "error": "Chat access requires Pro or Premium subscription"}
    
    content = escape_html(content)
    
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
    await manager.send_message(recipient_id, {
        "type": "new_message",
        "message": {
            "id": new_message.id,
            "sender_id": user.id,
            "sender_username": user.username,
            "content": content,
            "created_at": new_message.created_at.isoformat(),
            "expires_at": expires_at.isoformat()
        },
        "unread_count": user_unread_counts.get(f"{recipient_id}_{conv.id}", 1)
    })
    return {"success": True, "message": {"id": new_message.id, "content": content, "created_at": new_message.created_at.isoformat(), "expires_at": expires_at.isoformat()}}

@router.post("/mark_read/{message_id}")
async def mark_message_read(
    request: Request,
    message_id: int,
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}
    
    if not user.read_receipts_enabled:
        return {"success": True}
    
    message = db.query(ChatMessage).filter(ChatMessage.id == message_id).first()
    if not message:
        return {"success": False, "error": "Message not found"}
    
    if message.read_at is None:
        message.read_at = datetime.utcnow()
        db.commit()
        
        conv = db.query(ChatConversation).filter(ChatConversation.id == message.conversation_id).first()
        if conv:
            other_user_id = conv.user1_id if conv.user2_id == user.id else conv.user2_id
            await manager.send_message(other_user_id, {
                "type": "message_read",
                "message_id": message_id,
                "user_id": user.id
            })
    
    return {"success": True}

@router.post("/invite")
async def send_invitation(
    request: Request,
    username: str = Form(...),
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}
    
    username = escape_html(username)
    
    if username == user.username:
        return {"success": False, "error": "Cannot invite yourself"}
    
    recipient = db.query(User).filter(func.lower(User.username) == username.lower()).first()
    if not recipient:
        return {"success": False, "error": "User not found"}
    
    if is_blocked(db, user.id, recipient.id):
        return {"success": False, "error": "You are blocked by this user"}
    
    if is_blocked(db, recipient.id, user.id):
        return {"success": False, "error": "You have blocked this user"}
    
    existing = get_conversation(db, user.id, recipient.id)
    if existing:
        if existing.status == "active":
            return {"success": False, "error": "You already have an active chat"}
        elif existing.status == "pending":
            return {"success": False, "error": "Invitation already pending"}
    
    new_conv = ChatConversation(
        user1_id=user.id,
        user2_id=recipient.id,
        status="pending",
        initiator_id=user.id
    )
    db.add(new_conv)
    db.commit()
    
    log_security_event(db, user.id, f"Sent chat invitation to {recipient.username}", "chat_invite", None, request)
    
    return {"success": True, "message": f"Invitation sent to {recipient.username}"}

@router.post("/invite/accept/{conversation_id}")
async def accept_invitation(
    request: Request,
    conversation_id: int,
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    user = get_current_user(db, session_token)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    
    conv = db.query(ChatConversation).filter(ChatConversation.id == conversation_id).first()
    if not conv:
        return RedirectResponse(url="/chat", status_code=303)
    
    if conv.user1_id != user.id and conv.user2_id != user.id:
        return RedirectResponse(url="/chat", status_code=303)
    
    if conv.initiator_id == user.id:
        return RedirectResponse(url="/chat", status_code=303)
    
    conv.status = "active"
    conv.updated_at = datetime.utcnow()
    db.commit()
    
    other_user_id = conv.user1_id if conv.user2_id == user.id else conv.user2_id
    
    log_security_event(db, user.id, f"Accepted chat invitation from user {other_user_id}", "chat_accept", None, request)
    
    return RedirectResponse(url=f"/chat/{other_user_id}", status_code=303)

@router.post("/invite/decline/{conversation_id}")
async def decline_invitation(
    request: Request,
    conversation_id: int,
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    user = get_current_user(db, session_token)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    
    conv = db.query(ChatConversation).filter(ChatConversation.id == conversation_id).first()
    if not conv:
        return RedirectResponse(url="/chat", status_code=303)
    
    if conv.user1_id != user.id and conv.user2_id != user.id:
        return RedirectResponse(url="/chat", status_code=303)
    
    db.delete(conv)
    db.commit()
    
    log_security_event(db, user.id, "Declined chat invitation", "chat_decline", None, request)
    
    return RedirectResponse(url="/chat", status_code=303)

@router.post("/invite/cancel/{conversation_id}")
async def cancel_invitation(
    request: Request,
    conversation_id: int,
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    user = get_current_user(db, session_token)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    
    conv = db.query(ChatConversation).filter(ChatConversation.id == conversation_id).first()
    if not conv:
        return RedirectResponse(url="/chat", status_code=303)
    
    if conv.user1_id != user.id and conv.user2_id != user.id:
        return RedirectResponse(url="/chat", status_code=303)
    
    if conv.initiator_id != user.id:
        return RedirectResponse(url="/chat", status_code=303)
    
    db.delete(conv)
    db.commit()
    
    log_security_event(db, user.id, "Cancelled chat invitation", "chat_cancel", None, request)
    
    return RedirectResponse(url="/chat", status_code=303)

@router.post("/block/{user_id}")
async def block_user(
    request: Request,
    user_id: int,
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
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
        log_security_event(db, user.id, f"Blocked user {target.username}", "user_block", None, request)
    return {"success": True, "message": "User blocked"}

@router.post("/unblock/{user_id}")
async def unblock_user(
    request: Request,
    user_id: int,
    session_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}
    block = db.query(BlockedUser).filter(BlockedUser.user_id == user.id, BlockedUser.blocked_user_id == user_id).first()
    if block:
        db.delete(block)
        db.commit()
        log_security_event(db, user.id, f"Unblocked user {user_id}", "user_unblock", None, request)
    return {"success": True, "message": "User unblocked"}

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

@router.get("/search/global")
async def search_global_messages(q: str, session_token: str = Cookie(None), db: Session = Depends(get_db)):
    user = get_current_user(db, session_token)
    if not user:
        return {"success": False, "error": "Not authenticated"}
    
    conversations = db.query(ChatConversation).filter(
        ((ChatConversation.user1_id == user.id) | (ChatConversation.user2_id == user.id)),
        ChatConversation.status == "active"
    ).all()
    
    conversation_ids = [conv.id for conv in conversations]
    
    messages = db.query(ChatMessage).filter(
        ChatMessage.conversation_id.in_(conversation_ids),
        ChatMessage.encrypted_content.contains(q.lower())
    ).order_by(ChatMessage.created_at.desc()).limit(50).all()
    
    results = []
    for msg in messages:
        conv = db.query(ChatConversation).filter(ChatConversation.id == msg.conversation_id).first()
        other_user_id = conv.user1_id if conv.user2_id == user.id else conv.user2_id
        other_user = db.query(User).filter(User.id == other_user_id).first()
        
        results.append({
            "id": msg.id,
            "content": msg.encrypted_content,
            "sender": msg.sender.username,
            "created_at": msg.created_at.isoformat(),
            "other_user_id": other_user_id,
            "other_user": other_user.username if other_user else "Unknown"
        })
    
    return {"success": True, "results": results}

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
                content = escape_html(content)
                
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
                await manager.send_message(other_user_id, {
                    "type": "new_message",
                    "message": {
                        "id": new_message.id,
                        "sender_id": user.id,
                        "sender_username": user.username,
                        "content": content,
                        "created_at": new_message.created_at.isoformat(),
                        "expires_at": expires_at.isoformat()
                    },
                    "unread_count": user_unread_counts.get(f"{other_user_id}_{conversation_id}", 1)
                })
                await websocket.send_json({"type": "message_sent", "message": {"id": new_message.id, "content": content, "created_at": new_message.created_at.isoformat(), "expires_at": expires_at.isoformat()}})
                
            elif message_data.get("type") == "typing":
                await manager.send_message(other_user_id, {"type": "typing", "user_id": user.id, "username": user.username, "is_typing": message_data.get("is_typing", True)})
                
    except WebSocketDisconnect:
        manager.disconnect(user.id)

@router.websocket("/group/ws/{group_id}")
async def group_websocket_endpoint(websocket: WebSocket, group_id: int, session_token: str = Cookie(None), db: Session = Depends(get_db)):
    user = get_current_user(db, session_token)
    if not user:
        await websocket.close(code=1008)
        return
    
    membership = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == user.id).first()
    if not membership:
        await websocket.close(code=1008)
        return
    
    await manager.connect(websocket, user.id, group_id)
    
    try:
        while True:
            data = await websocket.receive_text()
            message_data = json.loads(data)
            
            if message_data.get("type") == "message":
                content = message_data.get("content", "")
                content = escape_html(content)
                
                char_limit = get_chat_char_limit(user)
                if char_limit > 0 and len(content) > char_limit:
                    await websocket.send_json({"type": "error", "message": f"Message exceeds {char_limit} character limit"})
                    continue
                
                expires_at = datetime.utcnow() + timedelta(hours=24)
                new_message = GroupChatMessage(
                    group_id=group_id,
                    sender_id=user.id,
                    encrypted_content=content,
                    expires_at=expires_at,
                    delivered_at=datetime.utcnow()
                )
                db.add(new_message)
                db.commit()
                
                await manager.broadcast_to_group(group_id, {
                    "type": "new_group_message",
                    "message": {
                        "id": new_message.id,
                        "sender_id": user.id,
                        "sender_username": user.username,
                        "content": content,
                        "created_at": new_message.created_at.isoformat(),
                        "expires_at": expires_at.isoformat()
                    }
                })
                
            elif message_data.get("type") == "typing":
                await manager.broadcast_to_group(group_id, {
                    "type": "typing",
                    "user_id": user.id,
                    "username": user.username,
                    "is_typing": message_data.get("is_typing", True)
                }, exclude_user_id=user.id)
                
    except WebSocketDisconnect:
        manager.disconnect(user.id, group_id)
