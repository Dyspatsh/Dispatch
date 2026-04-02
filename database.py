from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text, ForeignKey, BigInteger, Enum, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime, timedelta
import os
import hashlib
import secrets
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL must be set in .env file")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# IP hashing salt - stored in env, not in code
IP_SALT = os.getenv("IP_SALT", secrets.token_hex(32))

def hash_ip_address(ip_address: str) -> str:
    """Hash IP address for privacy while preserving rate limiting capability"""
    if not ip_address or ip_address == "unknown":
        return None
    return hashlib.sha256(f"{IP_SALT}{ip_address}".encode()).hexdigest()

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(16), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    pin_hash = Column(String(255), nullable=False)
    recovery_phrase_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="user")  # user, pro, premium, owner
    is_banned = Column(Boolean, default=False)
    ban_reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    totp_secret = Column(String(32), nullable=True)
    totp_enabled = Column(Boolean, default=False)
    recovery_codes_hash = Column(Text, nullable=True)
    subscription_expires_at = Column(DateTime, nullable=True)
    bio = Column(Text, nullable=True)
    read_receipts_enabled = Column(Boolean, default=True)
    
    # NEW: libsodium key pairs for file encryption
    public_key = Column(String(255), nullable=True)   # Base64 encoded
    private_key = Column(String(255), nullable=True)  # Base64 encoded - NEVER exposed to client
    
    # Relationships
    files_sent = relationship("File", foreign_keys="File.sender_id", back_populates="sender")
    files_received = relationship("File", foreign_keys="File.recipient_id", back_populates="recipient")
    sessions = relationship("Session", back_populates="user")
    login_history = relationship("LoginHistory", back_populates="user")
    security_logs = relationship("SecurityLog", back_populates="user")
    blocked_users = relationship("BlockedUser", foreign_keys="BlockedUser.user_id", back_populates="user")
    blocked_by = relationship("BlockedUser", foreign_keys="BlockedUser.blocked_user_id")
    chat_messages = relationship("ChatMessage", back_populates="sender")
    group_messages = relationship("GroupChatMessage", back_populates="sender")
    group_memberships = relationship("GroupMember", back_populates="user")
    groups_created = relationship("ChatGroup", back_populates="created_by")
    group_invites_sent = relationship("GroupInvitation", foreign_keys="GroupInvitation.inviter_id", back_populates="inviter")
    group_invites_received = relationship("GroupInvitation", foreign_keys="GroupInvitation.invited_user_id", back_populates="invited_user")
    message_reactions = relationship("MessageReaction", back_populates="user")
    message_reads = relationship("MessageReadReceipt", back_populates="user")

class Session(Base):
    __tablename__ = "sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    session_token = Column(String(64), unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    twofa_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_activity = Column(DateTime, default=datetime.utcnow)  # NEW: track activity
    
    user = relationship("User", back_populates="sessions")

class File(Base):
    __tablename__ = "files"
    
    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    recipient_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    filename = Column(String(255), nullable=False)
    encrypted_filename = Column(String(255), nullable=False)
    # REPLACED: encrypted_file_key removed, using sealed box
    file_key_sealed = Column(Text, nullable=False)  # Sealed box encrypted with recipient's public key
    file_size = Column(BigInteger, nullable=False)
    status = Column(String(20), default="pending")  # pending, accepted, declined, downloaded, expired, cancelled
    options = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    accepted_at = Column(DateTime, nullable=True)
    downloaded_at = Column(DateTime, nullable=True)
    
    sender = relationship("User", foreign_keys=[sender_id], back_populates="files_sent")
    recipient = relationship("User", foreign_keys=[recipient_id], back_populates="files_received")

class Payment(Base):
    __tablename__ = "payments"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    amount = Column(Integer, nullable=False)
    currency = Column(String(10), default="XMR")
    status = Column(String(20), default="pending")
    tx_id = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    confirmed_at = Column(DateTime, nullable=True)

class ChatConversation(Base):
    __tablename__ = "chat_conversations"
    
    id = Column(Integer, primary_key=True, index=True)
    user1_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    user2_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    status = Column(String(20), default="pending")  # pending, active, blocked
    initiator_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    user1 = relationship("User", foreign_keys=[user1_id])
    user2 = relationship("User", foreign_keys=[user2_id])
    initiator = relationship("User", foreign_keys=[initiator_id])
    messages = relationship("ChatMessage", back_populates="conversation")

class ChatMessage(Base):
    __tablename__ = "chat_messages"
    
    id = Column(Integer, primary_key=True, index=True)
    conversation_id = Column(Integer, ForeignKey("chat_conversations.id"), nullable=False)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    encrypted_content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    read_at = Column(DateTime, nullable=True)
    delivered_at = Column(DateTime, nullable=True)
    
    conversation = relationship("ChatConversation", back_populates="messages")
    sender = relationship("User", foreign_keys=[sender_id], back_populates="chat_messages")

class BlockedUser(Base):
    __tablename__ = "blocked_users"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    blocked_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User", foreign_keys=[user_id], back_populates="blocked_users")
    blocked_user = relationship("User", foreign_keys=[blocked_user_id])

class LoginHistory(Base):
    __tablename__ = "login_history"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    login_time = Column(DateTime, default=datetime.utcnow)
    ip_hash = Column(String(64), nullable=True)
    
    user = relationship("User", back_populates="login_history")

class SecurityLog(Base):
    __tablename__ = "security_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    action = Column(String(255), nullable=False)
    action_type = Column(String(50), nullable=False)
    details = Column(Text, nullable=True)
    ip_hash = Column(String(64), nullable=True)
    user_agent = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User", back_populates="security_logs")

class FailedLoginAttempt(Base):
    __tablename__ = "failed_login_attempts"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(16), nullable=False, index=True)
    attempt_count = Column(Integer, default=0)
    twofa_failures = Column(Integer, default=0)
    last_attempt = Column(DateTime, default=datetime.utcnow)
    lock_until = Column(DateTime, nullable=True)
    ip_hash = Column(String(64), nullable=True)
    
    __table_args__ = (
        Index('ix_failed_attempts_username_ip', 'username', 'ip_hash'),
    )

class CSRFToken(Base):
    __tablename__ = "csrf_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String(64), unique=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class ChatGroup(Base):
    __tablename__ = "chat_groups"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), nullable=False)
    description = Column(Text, nullable=True)
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    created_by = relationship("User", foreign_keys=[created_by_id], back_populates="groups_created")
    members = relationship("GroupMember", back_populates="group")
    messages = relationship("GroupChatMessage", back_populates="group")
    invitations = relationship("GroupInvitation", back_populates="group")

class GroupMember(Base):
    __tablename__ = "group_members"
    
    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, ForeignKey("chat_groups.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    role = Column(String(20), default="member")  # owner, admin, member
    joined_at = Column(DateTime, default=datetime.utcnow)
    
    group = relationship("ChatGroup", back_populates="members")
    user = relationship("User", back_populates="group_memberships")

class GroupChatMessage(Base):
    __tablename__ = "group_chat_messages"
    
    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, ForeignKey("chat_groups.id"), nullable=False)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    encrypted_content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    delivered_at = Column(DateTime, nullable=True)
    
    group = relationship("ChatGroup", back_populates="messages")
    sender = relationship("User", foreign_keys=[sender_id], back_populates="group_messages")
    reactions = relationship("MessageReaction", back_populates="message")
    read_receipts = relationship("MessageReadReceipt", back_populates="message")

class MessageReaction(Base):
    __tablename__ = "message_reactions"
    
    id = Column(Integer, primary_key=True, index=True)
    message_id = Column(Integer, ForeignKey("group_chat_messages.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    reaction_type = Column(String(20), nullable=False)  # like, thanks, agree, helpful
    created_at = Column(DateTime, default=datetime.utcnow)
    
    message = relationship("GroupChatMessage", back_populates="reactions")
    user = relationship("User", back_populates="message_reactions")

class MessageReadReceipt(Base):
    __tablename__ = "message_read_receipts"
    
    id = Column(Integer, primary_key=True, index=True)
    message_id = Column(Integer, ForeignKey("group_chat_messages.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    read_at = Column(DateTime, default=datetime.utcnow)
    
    message = relationship("GroupChatMessage", back_populates="read_receipts")
    user = relationship("User", back_populates="message_reads")

class GroupInvitation(Base):
    __tablename__ = "group_invitations"
    
    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, ForeignKey("chat_groups.id"), nullable=False)
    inviter_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    invited_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    status = Column(String(20), default="pending")  # pending, accepted, declined
    created_at = Column(DateTime, default=datetime.utcnow)
    
    group = relationship("ChatGroup", back_populates="invitations")
    inviter = relationship("User", foreign_keys=[inviter_id], back_populates="group_invites_sent")
    invited_user = relationship("User", foreign_keys=[invited_user_id], back_populates="group_invites_received")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    Base.metadata.create_all(bind=engine)
