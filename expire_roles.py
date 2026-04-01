#!/usr/bin/env python3
import sys
import os
from datetime import datetime, timezone
from dotenv import load_dotenv

sys.path.append('/home/dispatch/dyspatch')
load_dotenv()

from database import SessionLocal, User

def expire_roles():
    db = SessionLocal()
    try:
        # Use timezone-aware UTC datetime
        now = datetime.now(timezone.utc)
        expired_users = db.query(User).filter(
            User.subscription_expires_at != None,
            User.subscription_expires_at < now,
            User.role.in_(['pro', 'premium'])
        ).all()
        
        for user in expired_users:
            old_role = user.role
            user.role = "user"
            user.subscription_expires_at = None
            print(f"[{datetime.now(timezone.utc)}] User {user.username} downgraded from {old_role} to user")
        
        db.commit()
        print(f"[{datetime.now(timezone.utc)}] Expired {len(expired_users)} subscriptions")
        return len(expired_users)
    except Exception as e:
        print(f"Error: {e}")
        db.rollback()
        return 0
    finally:
        db.close()

if __name__ == "__main__":
    expire_roles()
