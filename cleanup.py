#!/usr/bin/env python3
import os
import sys
from datetime import datetime
sys.path.append('/home/dispatch/dyspatch')

from database import SessionLocal, File, ChatMessage

def cleanup_expired_files():
    db = SessionLocal()
    try:
        expired_files = db.query(File).filter(File.expires_at < datetime.utcnow()).all()
        deleted_files = 0
        for file in expired_files:
            file_path = f"/home/dispatch/dyspatch/uploads/{file.encrypted_filename}"
            if os.path.exists(file_path):
                os.remove(file_path)
            db.delete(file)
            deleted_files += 1
        
        db.commit()
        print(f"[{datetime.utcnow()}] Deleted {deleted_files} expired files")
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
        expired_messages = db.query(ChatMessage).filter(ChatMessage.expires_at < datetime.utcnow()).all()
        deleted_messages = 0
        for msg in expired_messages:
            db.delete(msg)
            deleted_messages += 1
        
        db.commit()
        print(f"[{datetime.utcnow()}] Deleted {deleted_messages} expired chat messages")
        return deleted_messages
    except Exception as e:
        print(f"Error deleting chat messages: {e}")
        db.rollback()
        return 0
    finally:
        db.close()

def main():
    cleanup_expired_files()
    cleanup_expired_chat_messages()

if __name__ == "__main__":
    main()
