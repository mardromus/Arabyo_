"""
Vercel WSGI entry point for Arabyo Flask app.

This file is required by Vercel's Python runtime.
It initializes the Flask app and handles all incoming requests.

NOTE: Vercel is a stateless serverless platform.
- SQLite data does NOT persist between cold starts
- The first request will auto-initialize the schema and seed demo data
- For persistent data, migrate to PostgreSQL (Railway, Supabase, etc.)
"""
import os
import sys

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Vercel sets this - use in-memory or /tmp for DB on Vercel
if os.environ.get("VERCEL"):
    # On Vercel, /tmp is the only writable directory
    os.environ.setdefault("DB_PATH", "/tmp/compliance.db")

# Load env vars (Vercel provides them from dashboard settings)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Disable auth for Vercel demo deployments (override in Vercel dashboard if needed)
os.environ.setdefault("FIREBASE_AUTH_DISABLED", "true")

# Import and create the Flask app
from run import app

# Expose 'app' as the WSGI handler (Vercel Python runtime looks for this)
# Also expose as 'handler' for some Vercel configurations
handler = app
