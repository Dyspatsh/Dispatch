#!/usr/bin/env python3
import sys
import os
from datetime import datetime
sys.path.append('/home/dispatch/dyspatch')

from database import SessionLocal, User

def expire_roles():
    db = SessionLocal()
    try:
        expired_users = db.query(User).filter(
            User.subscription_expires_at != None,
            User.subscription_expires_at < datetime.utcnow(),
            User.role.in_(['pro', 'premium'])
        ).all()
        
        for user in expired_users:
            old_role = user.role
            user.role = "user"
            user.subscription_expires_at = None
            print(f"[{datetime.utcnow()}] User {user.username} downgraded from {old_role} to user")
        
        db.commit()
        print(f"[{datetime.utcnow()}] Expired {len(expired_users)} subscriptions")
        return len(expired_users)
    except Exception as e:
        print(f"Error: {e}")
        db.rollback()
        return 0
    finally:
        db.close()

if __name__ == "__main__":
    expire_roles()
