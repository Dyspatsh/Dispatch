#!/usr/bin/env python3
"""
Database Reset Script for Dispatch
WARNING: This will delete ALL data from the database!
Run with: python3 reset_database.py
"""

import os
import sys
from datetime import datetime
from dotenv import load_dotenv

# Add current directory to path
sys.path.append('/home/dispatch/dyspatch')
load_dotenv()

from database import engine, Base
from sqlalchemy import text

# Use environment variable for upload directory
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/home/dispatch/dyspatch/uploads")

def confirm_reset():
    """Ask for confirmation before resetting"""
    print("\n" + "="*60)
    print("WARNING: This will delete ALL data from the Dispatch database!")
    print("This includes:")
    print("  - All users and their accounts")
    print("  - All files and uploads")
    print("  - All chat messages and conversations")
    print("  - All sessions and 2FA settings")
    print("  - All payments records")
    print("="*60)
    print("\nThis action CANNOT be undone!")
    
    response = input("\nType 'DELETE ALL' to confirm: ")
    if response != "DELETE ALL":
        print("Reset cancelled.")
        return False
    return True

def get_owner_credentials():
    """Get owner credentials from user"""
    print("\n" + "-"*40)
    print("CREATE OWNER ACCOUNT")
    print("-"*40)
    
    while True:
        username = input("Username (min 3 chars, max 16): ").strip()
        if 3 <= len(username) <= 16:
            break
        print("Username must be between 3 and 16 characters")
    
    while True:
        password = input("Password (min 8 chars, at least 1 capital, 1 number, 1 symbol): ").strip()
        if len(password) >= 8:
            import re
            if re.search(r'[A-Z]', password) and re.search(r'[0-9]', password) and re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                break
        print("Password must have at least 8 chars, 1 capital letter, 1 number, and 1 symbol")
    
    while True:
        pin = input("6-Digit PIN: ").strip()
        if len(pin) == 6 and pin.isdigit():
            break
        print("PIN must be exactly 6 digits")
    
    return username, password, pin

def delete_uploaded_files():
    """Delete all uploaded files from the uploads directory"""
    deleted_count = 0
    
    if os.path.exists(UPLOAD_DIR):
        for filename in os.listdir(UPLOAD_DIR):
            file_path = os.path.join(UPLOAD_DIR, filename)
            if os.path.isfile(file_path):
                os.remove(file_path)
                deleted_count += 1
        print(f"Deleted {deleted_count} uploaded files")
    else:
        print("Uploads directory not found, creating it...")
        os.makedirs(UPLOAD_DIR, exist_ok=True)
    
    return deleted_count

def reset_database():
    """Drop and recreate all tables using CASCADE"""
    print("\n[1/3] Dropping all tables with CASCADE...")
    
    with engine.connect() as conn:
        # Disable foreign key checks temporarily
        conn.execute(text("DROP SCHEMA public CASCADE;"))
        conn.execute(text("CREATE SCHEMA public;"))
        conn.commit()
    
    print("All tables dropped successfully")
    
    print("\n[2/3] Recreating tables...")
    # Recreate all tables
    Base.metadata.create_all(bind=engine)
    print("All tables recreated successfully")
    
    return True

def create_owner_user(username, password, pin):
    """Create the initial owner user"""
    from passlib.context import CryptContext
    from database import SessionLocal, User
    import secrets
    import re
    
    pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
    db = SessionLocal()
    
    try:
        # Hash password and PIN
        password_hash = pwd_context.hash(password)
        pin_hash = pwd_context.hash(pin)
        
        # Generate recovery phrase
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        recovery_phrase = ''.join(secrets.choice(chars) for _ in range(64))
        recovery_phrase_hash = pwd_context.hash(recovery_phrase)
        
        # Create owner
        new_owner = User(
            username=username,
            password_hash=password_hash,
            pin_hash=pin_hash,
            recovery_phrase_hash=recovery_phrase_hash,
            role="owner"
        )
        db.add(new_owner)
        db.commit()
        
        print(f"\n" + "="*60)
        print("OWNER ACCOUNT CREATED SUCCESSFULLY!")
        print("="*60)
        print(f"Username: {username}")
        print(f"Password: {password}")
        print(f"PIN: {pin}")
        print("-"*60)
        print("RECOVERY PHRASE (SAVE THIS):")
        print("="*60)
        print(recovery_phrase)
        print("="*60)
        print("\nYou will need this recovery phrase if you forget your password.")
        
    except Exception as e:
        print(f"Error creating owner: {e}")
        db.rollback()
    finally:
        db.close()

def main():
    print("\n" + "="*60)
    print("DISPATCH DATABASE RESET TOOL")
    print("="*60)
    
    if not confirm_reset():
        return
    
    print("\nStarting database reset...")
    
    # Step 1: Delete uploaded files
    print("\n[1/4] Deleting uploaded files...")
    delete_uploaded_files()
    
    # Step 2: Reset database
    print("\n[2/4] Resetting database...")
    reset_database()
    
    # Step 3: Get owner credentials
    print("\n[3/4] Setting up owner account...")
    username, password, pin = get_owner_credentials()
    
    # Step 4: Create owner user
    print("\n[4/4] Creating owner user...")
    create_owner_user(username, password, pin)
    
    # Summary
    print("\n" + "="*60)
    print("DATABASE RESET COMPLETED SUCCESSFULLY")
    print("="*60)
    print("\nNext steps:")
    print("1. Restart the dispatch service: sudo systemctl restart dispatch")
    print("2. Login with your owner account")
    print("3. Register new users as needed")
    print("\n")

if __name__ == "__main__":
    main()
