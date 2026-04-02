#!/usr/bin/env python3
"""
Migration script to add libsodium key pairs to existing users.
Run this ONCE after updating your database schema.

Usage: python migrate_keys.py
"""

import sys
import os
from dotenv import load_dotenv

sys.path.append('/home/dispatch/dyspatch')
load_dotenv()

from nacl.public import PrivateKey
import base64
from database import SessionLocal, User, File
from sqlalchemy import text

def migrate_keys():
    print("Starting key migration for existing users...")
    
    db = SessionLocal()
    
    try:
        # Check if public_key column exists
        try:
            db.execute(text("SELECT public_key FROM users LIMIT 1"))
        except Exception as e:
            print("ERROR: public_key column not found. Run database migration first!")
            print("Add columns to users table:")
            print("ALTER TABLE users ADD COLUMN public_key VARCHAR(255);")
            print("ALTER TABLE users ADD COLUMN private_key VARCHAR(255);")
            print("ALTER TABLE files DROP COLUMN encrypted_file_key;")
            print("ALTER TABLE files ADD COLUMN file_key_sealed TEXT;")
            return
        
        # Get users without key pairs
        users = db.query(User).filter(User.public_key.is_(None)).all()
        
        if not users:
            print("All users already have key pairs. No migration needed.")
            return
        
        print(f"Found {len(users)} users without key pairs. Generating keys...")
        
        for user in users:
            # Generate new key pair
            private_key = PrivateKey.generate()
            public_key = private_key.public_key
            
            user.public_key = base64.b64encode(bytes(public_key)).decode('utf-8')
            user.private_key = base64.b64encode(bytes(private_key)).decode('utf-8')
            
            db.commit()
            print(f"  ✓ Generated keys for {user.username}")
        
        print("\n⚠️  WARNING: Existing files use the old encryption scheme!")
        print("Those files CANNOT be decrypted with the new key system.")
        print("Options:")
        print("  1. Mark old files as expired (they will auto-delete)")
        print("  2. Create a migration to re-encrypt old files (complex)")
        print("  3. Accept that old files are lost after this migration")
        
        # Option 1: Expire old files that use the old scheme
        choice = input("\nExpire all existing files? (y/n): ")
        if choice.lower() == 'y':
            # Check if old column exists
            try:
                db.execute(text("SELECT encrypted_file_key FROM files LIMIT 1"))
                files = db.query(File).filter(File.file_key_sealed.is_(None)).all()
                for file in files:
                    file.status = "expired"
                    file.expires_at = datetime.utcnow() - timedelta(days=1)
                db.commit()
                print(f"  ✓ Expired {len(files)} old files")
            except:
                print("  No old files found or column doesn't exist")
        
        print("\nMigration complete!")
        
    except Exception as e:
        print(f"ERROR: {str(e)}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    from datetime import datetime, timedelta
    migrate_keys()
