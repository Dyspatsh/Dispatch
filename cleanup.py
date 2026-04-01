#!/usr/bin/env python3
import os
import sys
from datetime import datetime, timezone
from dotenv import load_dotenv

sys.path.append('/home/dispatch/dyspatch')
load_dotenv()

from database import SessionLocal, File, ChatMessage, GroupChatMessage, ChatGroup, GroupMember
from sqlalchemy import func

UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/home/dispatch/dyspatch/uploads")

def cleanup_expired_files():
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        expired_files = db.query(File).filter(File.expires_at < now).all()
        deleted_files = 0
        for file in expired_files:
            file_path = os.path.join(UPLOAD_DIR, file.encrypted_filename)
            if os.path.exists(file_path):
                os.remove(file_path)
            db.delete(file)
            deleted_files += 1
        
        db.commit()
        print(f"[{datetime.now(timezone.utc)}] Deleted {deleted_files} expired files")
        return deleted_files
    except Exception as e:
        print(f"Error deleting files: {e}")
        db.rollback()
        return 0
    finally:
        db.close()

def cleanup_expired_chat_messages():
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        
        # Delete expired private messages
        expired_messages = db.query(ChatMessage).filter(ChatMessage.expires_at < now).all()
        deleted_messages = 0
        for msg in expired_messages:
            db.delete(msg)
            deleted_messages += 1
        
        # Delete expired group messages
        expired_group_messages = db.query(GroupChatMessage).filter(GroupChatMessage.expires_at < now).all()
        for msg in expired_group_messages:
            db.delete(msg)
            deleted_messages += 1
        
        db.commit()
        print(f"[{datetime.now(timezone.utc)}] Deleted {deleted_messages} expired chat messages")
        return deleted_messages
    except Exception as e:
        print(f"Error deleting chat messages: {e}")
        db.rollback()
        return 0
    finally:
        db.close()

def cleanup_empty_groups():
    db = SessionLocal()
    try:
        # Find groups with no members
        groups_without_members = db.query(ChatGroup).outerjoin(GroupMember).group_by(ChatGroup.id).having(func.count(GroupMember.id) == 0).all()
        deleted_groups = 0
        for group in groups_without_members:
            db.delete(group)
            deleted_groups += 1
        
        db.commit()
        if deleted_groups > 0:
            print(f"[{datetime.now(timezone.utc)}] Deleted {deleted_groups} empty groups")
        return deleted_groups
    except Exception as e:
        print(f"Error deleting empty groups: {e}")
        db.rollback()
        return 0
    finally:
        db.close()

def main():
    cleanup_expired_files()
    cleanup_expired_chat_messages()
    cleanup_empty_groups()

if __name__ == "__main__":
    main()
