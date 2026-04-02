#!/usr/bin/env python3
"""
Dispatch HTTPS Production Runner
This is the actual file running on the Dispatch server
Paths use environment variables for security and flexibility
"""
import uvicorn
import os
import sys

# Add the current directory to path
sys.path.append('/home/dispatch/dyspatch')

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

if __name__ == "__main__":
    # Get configuration from environment variables
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", 8443))
    ssl_keyfile = os.getenv("SSL_KEYFILE")
    ssl_certfile = os.getenv("SSL_CERTFILE")
    
    # Verify SSL files exist
    if not ssl_keyfile or not ssl_certfile:
        print("ERROR: SSL_KEYFILE and SSL_CERTFILE must be set in .env")
        sys.exit(1)
    
    if not os.path.exists(ssl_keyfile):
        print(f"ERROR: SSL key file not found: {ssl_keyfile}")
        sys.exit(1)
    
    if not os.path.exists(ssl_certfile):
        print(f"ERROR: SSL certificate file not found: {ssl_certfile}")
        sys.exit(1)
    
    print(f"Starting Dispatch HTTPS server on {host}:{port}")
    print(f"SSL Key: {ssl_keyfile}")
    print(f"SSL Cert: {ssl_certfile}")
    
    uvicorn.run(
        "app:app",
        host=host,
        port=port,
        ssl_keyfile=ssl_keyfile,
        ssl_certfile=ssl_certfile,
        proxy_headers=True,
        forwarded_allow_ips="*",
        log_level="warning"
    )
