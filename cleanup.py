#!/usr/bin/env python3
"""
Cleanup Script - Removes expired files, messages, and logs
Runs daily: 0 2 * * * cd /home/dispatch/dyspatch && venv/bin/python cleanup.py >> /var/log/dispatch/cleanup.log 2>&1
"""

import sys
import os
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

sys.path.append('/home/dispatch/dyspatch')
load_dotenv()

from database import SessionLocal, File, ChatMessage, GroupChatMessage, ChatGroup, GroupMember, SecurityLog, LoginHistory, FailedLoginAttempt
from sqlalchemy import func

UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/home/dispatch/dyspatch/uploads")

def cleanup_expired_files(db) -> int:
    """Delete expired files from database and filesystem"""
    try:
        now = datetime.now(timezone.utc)
        
        # Find expired files
        expired_files = db.query(File).filter(File.expires_at < now).all()
        deleted_files = 0
        
        for file in expired_files:
            # Delete from filesystem
            file_path = os.path.join(UPLOAD_DIR, file.encrypted_filename)
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"[{datetime.now(timezone.utc)}] Deleted file: {file_path}")
            
            # Delete from database
            db.delete(file)
            deleted_files += 1
        
        db.commit()
        print(f"[{datetime.now(timezone.utc)}] Deleted {deleted_files} expired files")
        return deleted_files
        
    except Exception as e:
        print(f"Error deleting expired files: {e}")
        db.rollback()
        return 0

def cleanup_expired_messages(db) -> int:
    """Delete expired chat messages (private and group)"""
    try:
        now = datetime.now(timezone.utc)
        deleted_count = 0
        
        # Delete expired private messages
        expired_private = db.query(ChatMessage).filter(ChatMessage.expires_at < now).all()
        for msg in expired_private:
            db.delete(msg)
            deleted_count += 1
        
        # Delete expired group messages
        expired_group = db.query(GroupChatMessage).filter(GroupChatMessage.expires_at < now).all()
        for msg in expired_group:
            db.delete(msg)
            deleted_count += 1
        
        db.commit()
        print(f"[{datetime.now(timezone.utc)}] Deleted {deleted_count} expired chat messages")
        return deleted_count
        
    except Exception as e:
        print(f"Error deleting expired messages: {e}")
        db.rollback()
        return 0

def cleanup_empty_groups(db) -> int:
    """Delete groups that have no members"""
    try:
        # Find groups with no members
        groups_without_members = db.query(ChatGroup).outerjoin(GroupMember).group_by(ChatGroup.id).having(func.count(GroupMember.id) == 0).all()
        deleted_count = 0
        
        for group in groups_without_members:
            print(f"[{datetime.now(timezone.utc)}] Deleting empty group: {group.name} (ID: {group.id})")
            db.delete(group)
            deleted_count += 1
        
        db.commit()
        
        if deleted_count > 0:
            print(f"[{datetime.now(timezone.utc)}] Deleted {deleted_count} empty groups")
        
        return deleted_count
        
    except Exception as e:
        print(f"Error deleting empty groups: {e}")
        db.rollback()
        return 0

def cleanup_old_logs(db) -> int:
    """Delete security logs and login history older than 30 days"""
    try:
        now = datetime.now(timezone.utc)
        cutoff_date = now - timedelta(days=30)
        
        # Delete old security logs
        old_logs = db.query(SecurityLog).filter(SecurityLog.created_at < cutoff_date).all()
        logs_deleted = len(old_logs)
        for log in old_logs:
            db.delete(log)
        
        # Delete old login history
        old_history = db.query(LoginHistory).filter(LoginHistory.login_time < cutoff_date).all()
        history_deleted = len(old_history)
        for hist in old_history:
            db.delete(hist)
        
        # Delete old failed login attempts (older than 7 days)
        failed_cutoff = now - timedelta(days=7)
        old_failed = db.query(FailedLoginAttempt).filter(FailedLoginAttempt.last_attempt < failed_cutoff).all()
        failed_deleted = len(old_failed)
        for attempt in old_failed:
            db.delete(attempt)
        
        db.commit()
        
        print(f"[{datetime.now(timezone.utc)}] Cleaned up {logs_deleted} security logs, {history_deleted} login records, {failed_deleted} failed attempts")
        return logs_deleted + history_deleted + failed_deleted
        
    except Exception as e:
        print(f"Error cleaning old logs: {e}")
        db.rollback()
        return 0

def main():
    """Main entry point for cron job"""
    print(f"=== Cleanup Started at {datetime.now(timezone.utc)} ===")
    
    db = SessionLocal()
    
    try:
        files_deleted = cleanup_expired_files(db)
        messages_deleted = cleanup_expired_messages(db)
        groups_deleted = cleanup_empty_groups(db)
        logs_deleted = cleanup_old_logs(db)
        
        total = files_deleted + messages_deleted + groups_deleted + logs_deleted
        
        print(f"=== Cleanup Completed: {total} items removed ===")
        print(f"   - Files: {files_deleted}")
        print(f"   - Messages: {messages_deleted}")
        print(f"   - Groups: {groups_deleted}")
        print(f"   - Logs: {logs_deleted}")
        
    except Exception as e:
        print(f"Fatal error during cleanup: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    main()
