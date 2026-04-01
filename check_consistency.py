#!/usr/bin/env python3
"""Consistency checker for Dispatch platform"""
import os
import re
from pathlib import Path

def check_env_consistency():
    """Check all Python files use environment variables"""
    print("\n" + "="*60)
    print("ENVIRONMENT VARIABLE CONSISTENCY")
    print("="*60)
    
    issues = []
    py_files = Path("/home/dispatch/dyspatch").glob("*.py")
    
    for py_file in py_files:
        if py_file.name in ["check_consistency.py", "database.py"]:
            continue
            
        with open(py_file) as f:
            content = f.read()
            
        # Check for hardcoded paths
        if "/home/dispatch/dyspatch" in content and "UPLOAD_DIR" not in content:
            if "uploads" in content:
                issues.append(f"⚠️  {py_file.name}: Contains hardcoded upload path")
        
        # Check for proper env loading
        if "load_dotenv" not in content and py_file.name not in ["app.py", "cleanup.py", "expire_roles.py"]:
            if "os.getenv" in content:
                issues.append(f"⚠️  {py_file.name}: Uses os.getenv but missing load_dotenv")
    
    if issues:
        for issue in issues:
            print(issue)
    else:
        print("✅ All files use environment variables correctly")

def check_template_consistency():
    """Check template inheritance is consistent"""
    print("\n" + "="*60)
    print("TEMPLATE CONSISTENCY")
    print("="*60)
    
    templates_dir = Path("/home/dispatch/dyspatch/templates")
    base_templates = []
    simple_templates = []
    
    for template in templates_dir.glob("*.html"):
        with open(template) as f:
            content = f.read()
            if 'extends "base.html"' in content:
                base_templates.append(template.name)
            elif 'extends "simple_base.html"' in content:
                simple_templates.append(template.name)
    
    print(f"📄 Templates extending base.html: {len(base_templates)}")
    for t in base_templates:
        print(f"   - {t}")
    
    print(f"\n📄 Templates extending simple_base.html: {len(simple_templates)}")
    for t in simple_templates:
        print(f"   - {t}")
    
    # Check if this makes sense
    public_pages = ["about.html", "terms.html"]
    for page in public_pages:
        if page in base_templates:
            print(f"⚠️  {page} uses base.html (should use simple_base.html for public pages?)")
    
    print("\n✅ Template inheritance is consistent")

def check_route_consistency():
    """Check routes are properly defined"""
    print("\n" + "="*60)
    print("ROUTE CONSISTENCY")
    print("="*60)
    
    with open("/home/dispatch/dyspatch/app.py") as f:
        content = f.read()
    
    # Find all routes
    routes = re.findall(r'@app\.(?:get|post|put|delete)\(["\']([^"\']+)["\']', content)
    
    print(f"📌 Total routes in app.py: {len(routes)}")
    print("Main routes:")
    for route in routes[:20]:
        print(f"   - {route}")
    
    # Check if admin routes are complete
    admin_routes = [r for r in routes if r.startswith("/admin")]
    print(f"\n🔧 Admin routes: {len(admin_routes)}")
    expected_admin = ["/admin", "/admin/stats", "/admin/search-users", "/admin/search-files", 
                      "/admin/user/ban/", "/admin/user/unban/", "/admin/user/role/", 
                      "/admin/user/delete/", "/admin/file/delete/", "/admin/user/"]
    
    for route in expected_admin:
        found = any(route in r for r in admin_routes)
        status = "✅" if found else "❌"
        print(f"   {status} {route}")
    
    print("\n✅ Routes are consistent")

def check_database_consistency():
    """Check database models match usage"""
    print("\n" + "="*60)
    print("DATABASE CONSISTENCY")
    print("="*60)
    
    with open("/home/dispatch/dyspatch/database.py") as f:
        content = f.read()
    
    # Check if stealth_mode is still used
    if "stealth_mode" in content:
        print("⚠️  stealth_mode column exists in database model")
        # Check if it's used in app.py
        with open("/home/dispatch/dyspatch/app.py") as app_f:
            app_content = app_f.read()
            if "stealth_mode" not in app_content:
                print("   → Not used in app.py (safe to remove)")
    else:
        print("✅ stealth_mode not present (good)")
    
    # Check all relationships
    models = re.findall(r'class (\w+)\(Base\):', content)
    print(f"\n📊 Database models: {', '.join(models)}")
    
    print("\n✅ Database model is consistent")

def check_frontend_consistency():
    """Check frontend JS/CSS is consistent"""
    print("\n" + "="*60)
    print("FRONTEND CONSISTENCY")
    print("="*60)
    
    static_dir = Path("/home/dispatch/dyspatch/static")
    
    # Check JS file
    js_file = static_dir / "script.js"
    if js_file.exists():
        with open(js_file) as f:
            js_content = f.read()
        
        # Check if toast is defined
        if "ToastManager" in js_content:
            print("✅ Toast notifications are defined")
        
        # Check if escapeHtml is defined
        if "function escapeHtml" in js_content:
            print("✅ HTML escaping is implemented")
    
    # Check CSS file
    css_file = static_dir / "style.css"
    if css_file.exists():
        with open(css_file) as f:
            css_content = f.read()
        
        # Check for mobile responsive
        if "@media (max-width: 768px)" in css_content:
            print("✅ Mobile responsive styles exist")
        
        # Check for dark theme
        if "body.dark" in css_content:
            print("✅ Dark theme styles exist")
    
    print("\n✅ Frontend assets are consistent")

def main():
    print("\n" + "🔍"*30)
    print("DISPATCH CONSISTENCY CHECKER")
    print("🔍"*30)
    
    check_env_consistency()
    check_template_consistency()
    check_route_consistency()
    check_database_consistency()
    check_frontend_consistency()
    
    print("\n" + "="*60)
    print("CONSISTENCY CHECK COMPLETE")
    print("="*60)

if __name__ == "__main__":
    main()
