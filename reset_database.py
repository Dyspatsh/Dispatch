#!/usr/bin/env python3
"""
Database Reset Script for Dispatch
WARNING: This will delete ALL data from the database!
Run with: python3 reset_database.py
"""

import os
import sys
import re
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
            if re.match(r'^[a-zA-Z0-9_]+$', username):
                break
            print("Username can only contain letters, numbers, and underscores")
        else:
            print("Username must be between 3 and 16 characters")
    
    while True:
        print("\nPassword requirements:")
        print("  - At least 12 characters (no maximum)")
        print("  - At least 3 of: uppercase, lowercase, numbers, symbols")
        print("  - No common weak patterns")
        print("  - No 4+ repeated characters in a row")
        password = input("Password: ").strip()
        
        # Validate password strength
        if len(password) < 12:
            print("Password must be at least 12 characters")
            continue
        
        common_patterns = ['password', '123456', 'qwerty', 'abc123', 'admin', 'welcome']
        if any(pattern in password.lower() for pattern in common_patterns):
            print("Password contains common weak pattern")
            continue
        
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>/?\\|]', password))
        
        types_found = sum([has_upper, has_lower, has_digit, has_special])
        
        if types_found < 3:
            print("Password must contain at least 3 of: uppercase, lowercase, numbers, symbols")
            continue
        
        if re.search(r'(.)\1{3,}', password):
            print("Password cannot have 4+ repeated characters in a row")
            continue
        
        break
    
    while True:
        pin = input("6-Digit PIN (cannot be sequential or all same digit): ").strip()
        if len(pin) != 6:
            print("PIN must be exactly 6 digits")
            continue
        if not pin.isdigit():
            print("PIN must contain only numbers")
            continue
        sequential = ['123456', '234567', '345678', '456789', '567890', '098765', '987654', '876543', '765432', '654321']
        if pin in sequential:
            print("PIN cannot be sequential numbers")
            continue
        if len(set(pin)) == 1:
            print("PIN cannot have all the same digit")
            continue
        break
    
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
        
        # Create owner - USING USER-PROVIDED CREDENTIALS (NOT HARDCODED)
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
        print("\n⚠️  WARNING: Save this recovery phrase immediately!")
        print("   You will NOT be able to recover your account without it.")
        
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
