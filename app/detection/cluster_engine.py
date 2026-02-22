"""Cluster intelligence engine — groups accounts by behavior + graph features for risk boosting."""
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler


class ClusterEngine:
    """Cluster accounts by behavioral + graph features and compute cluster-level risk."""

    def __init__(self, n_clusters=50):
        self.n_clusters = n_clusters
        self.scaler = StandardScaler()
        self.kmeans = None
        self.cluster_risks = {}
        self.account_clusters = {}

    def fit(self, features_df, graph_risks=None):
        """Cluster accounts and compute cluster-level risk scores.

        Args:
            features_df: DataFrame with account_id + computed features
            graph_risks: dict {account_id: {risk_score: float, ...}}

        Returns:
            DataFrame with cluster_id, cluster_risk, cluster_size, network_flag columns added
        """
        if features_df is None or features_df.empty:
            return features_df

        df = features_df.copy()

        # Select clustering features (behavioral)
        cluster_features = []
        for col in ['txn_count_total', 'amt_total', 'amt_mean', 'amt_max',
                     'unique_counterparties', 'txn_count_in', 'txn_count_out',
                     'amt_std', 'iso_risk', 'lgbm_risk', 'ml_risk']:
            if col in df.columns:
                cluster_features.append(col)

        if len(cluster_features) < 3:
            # Fallback: use whatever numeric columns are available
            cluster_features = [c for c in df.select_dtypes(include=[np.number]).columns
                                if c != 'account_id'][:8]

        if len(cluster_features) < 2 or len(df) < self.n_clusters:
            # Not enough data for meaningful clustering
            df['cluster_id'] = 0
            df['cluster_risk'] = 0.0
            df['cluster_size'] = len(df)
            df['network_flag'] = False
            return df

        X = df[cluster_features].fillna(0)
        X_scaled = self.scaler.fit_transform(X)

        # KMeans clustering
        actual_k = min(self.n_clusters, len(df) // 5)
        self.kmeans = KMeans(n_clusters=actual_k, random_state=42, n_init=10, max_iter=300)
        df['cluster_id'] = self.kmeans.fit_predict(X_scaled)

        print(f"[ClusterEngine] Clustered {len(df):,} accounts into {actual_k} clusters")

        # Compute per-cluster risk metrics
        risk_col = 'ml_risk' if 'ml_risk' in df.columns else None

        for cid in range(actual_k):
            mask = df['cluster_id'] == cid
            cluster_df = df[mask]
            size = len(cluster_df)

            if risk_col and risk_col in cluster_df.columns:
                mean_risk = cluster_df[risk_col].mean()
                high_risk_ratio = (cluster_df[risk_col] > 0.5).sum() / max(size, 1)
            else:
                mean_risk = 0.0
                high_risk_ratio = 0.0

            # Graph enrichment
            graph_scores = []
            if graph_risks:
                for acct in cluster_df['account_id']:
                    gdata = graph_risks.get(acct)
                    if isinstance(gdata, dict):
                        graph_scores.append(gdata.get('risk_score', 0))
                    elif isinstance(gdata, (int, float)):
                        graph_scores.append(float(gdata))

            avg_graph = np.mean(graph_scores) if graph_scores else 0.0

            # Cluster risk = weighted combo of mean ML risk + high-risk ratio + graph signal
            cluster_risk = 0.4 * mean_risk + 0.3 * high_risk_ratio + 0.3 * avg_graph
            cluster_risk = min(1.0, cluster_risk)

            self.cluster_risks[cid] = {
                'risk': round(cluster_risk, 4),
                'size': size,
                'mean_ml_risk': round(mean_risk, 4),
                'high_risk_ratio': round(high_risk_ratio, 4),
                'avg_graph_score': round(avg_graph, 4),
            }

        # Map back to accounts
        df['cluster_risk'] = df['cluster_id'].map(lambda c: self.cluster_risks.get(c, {}).get('risk', 0))
        df['cluster_size'] = df['cluster_id'].map(lambda c: self.cluster_risks.get(c, {}).get('size', 0))
        df['network_flag'] = df['cluster_risk'] > 0.4

        # Store mapping
        for _, row in df[['account_id', 'cluster_id']].iterrows():
            self.account_clusters[row['account_id']] = int(row['cluster_id'])

        # Summary
        high_risk_clusters = sum(1 for v in self.cluster_risks.values() if v['risk'] > 0.4)
        flagged = df['network_flag'].sum()
        print(f"[ClusterEngine] {high_risk_clusters} high-risk clusters, {flagged:,} network-flagged accounts")

        return df

    def get_account_cluster_info(self, account_id):
        """Get cluster context for an account."""
        cid = self.account_clusters.get(account_id)
        if cid is None:
            return {}
        info = self.cluster_risks.get(cid, {})
        return {
            'cluster_id': cid,
            'cluster_risk': info.get('risk', 0),
            'cluster_size': info.get('size', 0),
            'network_flag': info.get('risk', 0) > 0.4,
        }

    def get_cluster_summary(self):
        """Get summary of all clusters."""
        return self.cluster_risks
