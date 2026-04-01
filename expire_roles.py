#!/usr/bin/env python3
"""
Role Expiration Script - Runs via cron to downgrade expired subscriptions
Run every hour: 0 * * * * cd /home/dispatch/dyspatch && venv/bin/python expire_roles.py >> /var/log/dispatch/expire.log 2>&1
"""

import sys
import os
from datetime import datetime, timezone
from dotenv import load_dotenv

sys.path.append('/home/dispatch/dyspatch')
load_dotenv()

from database import SessionLocal, User
from sqlalchemy.orm import Session

def expire_roles(db: Session = None) -> int:
    """Expire user roles and log the action"""
    if db is None:
        db = SessionLocal()
        should_close = True
    else:
        should_close = False
    
    try:
        now = datetime.now(timezone.utc)
        
        # Find users with expired subscriptions
        expired_users = db.query(User).filter(
            User.subscription_expires_at != None,
            User.subscription_expires_at < now,
            User.role.in_(['pro', 'premium'])
        ).all()
        
        expired_count = 0
        for user in expired_users:
            old_role = user.role
            user.role = "user"
            user.subscription_expires_at = None
            expired_count += 1
            print(f"[{datetime.now(timezone.utc)}] User {user.username} (ID: {user.id}) downgraded from {old_role} to user")
        
        db.commit()
        
        if expired_count > 0:
            print(f"[{datetime.now(timezone.utc)}] Expired {expired_count} subscriptions")
        else:
            print(f"[{datetime.now(timezone.utc)}] No expired subscriptions found")
        
        return expired_count
        
    except Exception as e:
        print(f"Error in expire_roles: {e}")
        db.rollback()
        return 0
    finally:
        if should_close:
            db.close()

def main():
    """Main entry point for cron job"""
    print(f"=== Role Expiration Check Started at {datetime.now(timezone.utc)} ===")
    count = expire_roles()
    print(f"=== Role Expiration Check Completed: {count} users expired ===")

if __name__ == "__main__":
    main()
