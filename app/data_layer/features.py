"""Feature engineering for ML models — extracts behavioral features per account."""
import pandas as pd
import numpy as np
from sqlalchemy import create_engine
from app.config import DATABASE_URL


def _get_engine():
    return create_engine(DATABASE_URL, pool_pre_ping=True)


def compute_account_features(limit=None):
    """Compute features per account for ML models.
    
    Returns a DataFrame with one row per unique account, containing:
    - Velocity features (transaction counts in time windows)
    - Amount features (mean, max, std, sum)
    - Behavioral features (unique counterparties, currency diversity)
    - Time features (hour distribution, weekend ratio)
    - Label (max is_laundering flag for the account)
    """
    engine = _get_engine()

    # Load transactions into pandas via SQLAlchemy
    sql = "SELECT * FROM transactions"
    if limit:
        sql += f" LIMIT {limit}"

    print("[Features] Loading transactions from database...")
    df = pd.read_sql_query(sql, engine)

    if df.empty:
        print("[Features] No transactions found!")
        return pd.DataFrame()

    print(f"[Features] Computing features for {len(df):,} transactions...")

    # Parse timestamps
    df['timestamp'] = pd.to_datetime(df['timestamp'], format='mixed', errors='coerce')
    df['hour'] = df['timestamp'].dt.hour
    df['day_of_week'] = df['timestamp'].dt.dayofweek
    df['is_weekend'] = (df['day_of_week'] >= 5).astype(int)

    # Create unique account identifier (bank + account)
    df['sender_id'] = df['from_bank'].astype(str) + '_' + df['from_account'].astype(str)
    df['receiver_id'] = df['to_bank'].astype(str) + '_' + df['to_account'].astype(str)

    # --- Compute sender-side features ---
    sender_features = df.groupby('sender_id').agg(
        # Count features
        txn_count_out=('id', 'count'),
        
        # Amount features
        amt_mean_out=('amount_paid', 'mean'),
        amt_max_out=('amount_paid', 'max'),
        amt_std_out=('amount_paid', lambda x: x.std() if len(x) > 1 else 0),
        amt_sum_out=('amount_paid', 'sum'),
        amt_median_out=('amount_paid', 'median'),
        
        # Behavioral features
        unique_recipients=('receiver_id', 'nunique'),
        unique_currencies_out=('payment_currency', 'nunique'),
        unique_formats_out=('payment_format', 'nunique'),
        
        # Time features
        avg_hour_out=('hour', 'mean'),
        weekend_ratio_out=('is_weekend', 'mean'),
        
        # Label
        is_laundering_max=('is_laundering', 'max'),
        is_laundering_sum=('is_laundering', 'sum'),
    ).reset_index()

    sender_features = sender_features.rename(columns={'sender_id': 'account_id'})

    # --- Compute receiver-side features ---
    receiver_features = df.groupby('receiver_id').agg(
        txn_count_in=('id', 'count'),
        amt_mean_in=('amount_received', 'mean'),
        amt_max_in=('amount_received', 'max'),
        amt_sum_in=('amount_received', 'sum'),
        unique_senders=('sender_id', 'nunique'),
        unique_currencies_in=('receiving_currency', 'nunique'),
    ).reset_index()

    receiver_features = receiver_features.rename(columns={'receiver_id': 'account_id'})

    # --- Merge ---
    features = pd.merge(sender_features, receiver_features, on='account_id', how='outer')

    # Fill NaN with 0 for accounts that only send or only receive
    features = features.fillna(0)

    # --- Derived features ---
    features['txn_count_total'] = features['txn_count_out'] + features['txn_count_in']
    features['amt_total'] = features['amt_sum_out'] + features['amt_sum_in']
    features['in_out_ratio'] = np.where(
        features['txn_count_out'] > 0,
        features['txn_count_in'] / features['txn_count_out'],
        features['txn_count_in']
    )
    features['amt_in_out_ratio'] = np.where(
        features['amt_sum_out'] > 0,
        features['amt_sum_in'] / features['amt_sum_out'],
        features['amt_sum_in']
    )

    # Compute cross-border: transactions where from_bank != to_bank
    cross_border = df[df['from_bank'] != df['to_bank']].groupby('sender_id').size().reset_index(name='cross_border_out')
    cross_border = cross_border.rename(columns={'sender_id': 'account_id'})
    features = features.merge(cross_border, on='account_id', how='left')
    features['cross_border_out'] = features['cross_border_out'].fillna(0)

    # Self-transfer feature
    self_txn = df[df['sender_id'] == df['receiver_id']].groupby('sender_id').size().reset_index(name='self_transfer_count')
    self_txn = self_txn.rename(columns={'sender_id': 'account_id'})
    features = features.merge(self_txn, on='account_id', how='left')
    features['self_transfer_count'] = features['self_transfer_count'].fillna(0)

    print(f"[Features] Computed {len(features.columns)} features for {len(features):,} accounts")
    return features


def get_feature_columns():
    """Return the list of feature columns used for ML (excludes account_id and labels)."""
    return [
        'txn_count_out', 'amt_mean_out', 'amt_max_out', 'amt_std_out',
        'amt_sum_out', 'amt_median_out', 'unique_recipients',
        'unique_currencies_out', 'unique_formats_out', 'avg_hour_out',
        'weekend_ratio_out', 'txn_count_in', 'amt_mean_in', 'amt_max_in',
        'amt_sum_in', 'unique_senders', 'unique_currencies_in',
        'txn_count_total', 'amt_total', 'in_out_ratio', 'amt_in_out_ratio',
        'cross_border_out', 'self_transfer_count',
    ]
