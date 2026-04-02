# migrate_ip_hashing.py
import sys
import os
from dotenv import load_dotenv

sys.path.append('/home/dispatch/dyspatch')
load_dotenv()

from database import engine, Base, LoginHistory, SecurityLog, FailedLoginAttempt
from sqlalchemy import text

def migrate():
    print("Starting IP hashing migration...")
    
    with engine.connect() as conn:
        # Add ip_hash column to login_history if not exists
        try:
            conn.execute(text("ALTER TABLE login_history ADD COLUMN ip_hash VARCHAR(64)"))
            print("Added ip_hash to login_history")
        except Exception as e:
            if "duplicate column" in str(e).lower():
                print("ip_hash already exists in login_history")
            else:
                print(f"Error adding ip_hash to login_history: {e}")
        
        # Add ip_hash column to security_logs if not exists
        try:
            conn.execute(text("ALTER TABLE security_logs ADD COLUMN ip_hash VARCHAR(64)"))
            print("Added ip_hash to security_logs")
        except Exception as e:
            if "duplicate column" in str(e).lower():
                print("ip_hash already exists in security_logs")
            else:
                print(f"Error adding ip_hash to security_logs: {e}")
        
        # Add ip_hash column to failed_login_attempts if not exists
        try:
            conn.execute(text("ALTER TABLE failed_login_attempts ADD COLUMN ip_hash VARCHAR(64)"))
            print("Added ip_hash to failed_login_attempts")
        except Exception as e:
            if "duplicate column" in str(e).lower():
                print("ip_hash already exists in failed_login_attempts")
            else:
                print(f"Error adding ip_hash to failed_login_attempts: {e}")
        
        # Add index for faster lookups
        try:
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_failed_attempts_username_ip ON failed_login_attempts(username, ip_hash)"))
            print("Created index on failed_login_attempts")
        except Exception as e:
            print(f"Error creating index: {e}")
        
        conn.commit()
    
    print("Migration complete!")

if __name__ == "__main__":
    migrate()
