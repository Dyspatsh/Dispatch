#!/usr/bin/env python3
"""
Example production runner - Copy to run_https.py and configure for your server
"""
import uvicorn
import os

if __name__ == "__main__":
    # For HTTPS (recommended)
    # uvicorn.run(
    #     "app:app",
    #     host="127.0.0.1",
    #     port=8443,
    #     ssl_keyfile="/path/to/your/key.pem",
    #     ssl_certfile="/path/to/your/cert.pem"
    # )
    
    # For HTTP (development only)
    uvicorn.run(
        "app:app",
        host="127.0.0.1",
        port=8000
    )
