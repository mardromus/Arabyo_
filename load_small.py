import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from app.data_layer.loader import setup_database

def main():
    print("=========================================================================")
    print("  LOADING HI-SMALL & LI-SMALL DATASETS INTO SQLITE")
    print("=========================================================================")
    print("This script will clear the database, load HI-Small, and then APPEND LI-Small.")
    print("The total processing size is roughly ~1.1 GB (5 million+ transactions).")
    print("=========================================================================\n")
    
    # Paths for HI-Small
    hi_txn_csv = os.path.join(os.path.dirname(__file__), "Dataset", "HI-Small_Trans.csv")
    hi_acc_csv = os.path.join(os.path.dirname(__file__), "Dataset", "HI-Small_accounts.csv")
    
    # Paths for LI-Small
    li_txn_csv = os.path.join(os.path.dirname(__file__), "Dataset", "LI-Small_Trans.csv")
    li_acc_csv = os.path.join(os.path.dirname(__file__), "Dataset", "LI-Small_accounts.csv")
    
    # Validate files
    for f in [hi_txn_csv, hi_acc_csv, li_txn_csv, li_acc_csv]:
        if not os.path.exists(f):
            print(f"Error: {f} not found.")
            sys.exit(1)
            
    print("\n--- PHASE 1/2: LOADING HI-SMALL (TRUNCATING EXISTING DATA) ---")
    setup_database(
        limit=None, 
        truncate_first=True, 
        transactions_csv=hi_txn_csv, 
        accounts_csv=hi_acc_csv
    )
    
    print("\n--- PHASE 2/2: LOADING LI-SMALL (APPENDING) ---")
    setup_database(
        limit=None, 
        truncate_first=False, 
        transactions_csv=li_txn_csv, 
        accounts_csv=li_acc_csv
    )
    
    print("\nAll small datasets loaded successfully!")

if __name__ == "__main__":
    main()
