"""Bootstrap script: initialize the SQLite compliance database and schema.

SQLite requires no server — the database file is created automatically.
"""
import sys
import os

# Load .env
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

print("Initializing SQLite database schema...")
try:
    from app.db import init_db, DB_PATH
    init_db()
    print(f"✅ Schema initialized at: {DB_PATH}")
except Exception as e:
    print(f"❌ Schema init failed: {e}")
    import traceback; traceback.print_exc()
    sys.exit(1)

print("\n✅ Database is ready!")
print("   Next steps:")
print("   1. python run.py")
print("   2. POST http://localhost:5000/api/ingest?role=admin   (load CSV data)")
print("   3. POST http://localhost:5000/api/scan                (run compliance scan)")
