#!/usr/bin/env python
"""One-time database setup script. Run this first to load the dataset."""
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.data_layer.loader import setup_database


if __name__ == "__main__":
    # Use --limit N to load only N rows (for quick testing)
    limit = None
    if len(sys.argv) > 1:
        try:
            limit = int(sys.argv[1].replace("--limit=", "").replace("--limit", "").strip())
        except ValueError:
            pass

    if limit:
        print(f"Loading with limit: {limit:,} rows")
    else:
        print("Loading full dataset (this may take a few minutes)...")

    setup_database(limit=limit)
