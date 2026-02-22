import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from app.db import get_connection

conn = get_connection()
try:
    with conn.cursor() as cur:
        cur.execute('SELECT simulation_id FROM simulation_runs ORDER BY created_at DESC LIMIT 1')
        r = cur.fetchone()
        if r:
            print(f"LATEST_SIM_ID={r['simulation_id']}")
        else:
            print("LATEST_SIM_ID=NONE")
finally:
    conn.close()
