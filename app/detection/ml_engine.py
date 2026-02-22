"""ML-based risk and anomaly detection using Isolation Forest + LightGBM."""
import os
import json
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score, classification_report
from app.config import MODELS_DIR, ML_TEST_SIZE, ML_RANDOM_STATE
from app.data_layer.features import compute_account_features, get_feature_columns

try:
    import lightgbm as lgb
    HAS_LIGHTGBM = True
except ImportError:
    HAS_LIGHTGBM = False
    print("[MLEngine] LightGBM not available, using Isolation Forest only")

try:
    import shap
    HAS_SHAP = True
except ImportError:
    HAS_SHAP = False
    print("[MLEngine] SHAP not available, explanations will be limited")


class MLEngine:
    """ML-based anomaly and risk detection."""

    def __init__(self):
        self.iso_forest = None
        self.lgbm_model = None
        self.shap_explainer = None
        self.feature_cols = get_feature_columns()
        self.features_df = None
        self.is_trained = False

    def train(self, features_df=None):
        """Train both models on account features."""
        if features_df is None:
            features_df = compute_account_features()

        self.features_df = features_df

        if features_df.empty:
            print("[MLEngine] No data to train on!")
            return

        X = features_df[self.feature_cols].fillna(0)
        y = (features_df['is_laundering_max'] > 0).astype(int)

        print(f"[MLEngine] Training on {len(X):,} accounts, {y.sum():,} positive labels")
        print(f"[MLEngine] Positive rate: {y.mean()*100:.2f}%")

        # --- Isolation Forest (unsupervised) ---
        print("[MLEngine] Training Isolation Forest...")
        self.iso_forest = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=ML_RANDOM_STATE,
            n_jobs=-1,
        )
        self.iso_forest.fit(X)

        # Anomaly scores (-1 = anomaly, 1 = normal) → convert to 0-1 risk
        iso_scores = self.iso_forest.decision_function(X)
        iso_risk = 1 - (iso_scores - iso_scores.min()) / (iso_scores.max() - iso_scores.min() + 1e-8)
        features_df['iso_risk'] = iso_risk

        # --- LightGBM (supervised) ---
        if HAS_LIGHTGBM and y.sum() > 10:
            print("[MLEngine] Training LightGBM classifier...")
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=ML_TEST_SIZE, random_state=ML_RANDOM_STATE, stratify=y
            )

            self.lgbm_model = lgb.LGBMClassifier(
                n_estimators=200,
                max_depth=6,
                learning_rate=0.05,
                num_leaves=31,
                min_child_samples=20,
                class_weight='balanced',
                random_state=ML_RANDOM_STATE,
                verbose=-1,
            )
            self.lgbm_model.fit(X_train, y_train)

            # Evaluate
            y_pred_proba = self.lgbm_model.predict_proba(X_test)[:, 1]
            auc = roc_auc_score(y_test, y_pred_proba)
            print(f"[MLEngine] LightGBM AUC: {auc:.4f}")

            # Full dataset predictions
            features_df['lgbm_risk'] = self.lgbm_model.predict_proba(X)[:, 1]

            # SHAP explainer
            if HAS_SHAP:
                print("[MLEngine] Computing SHAP values...")
                self.shap_explainer = shap.TreeExplainer(self.lgbm_model)

        else:
            features_df['lgbm_risk'] = iso_risk  # Fallback

        # Combined ML risk
        features_df['ml_risk'] = (features_df['iso_risk'] * 0.4 + features_df['lgbm_risk'] * 0.6)

        self.features_df = features_df
        self.is_trained = True

        # Save models
        self._save_models()

        print(f"[MLEngine] Training complete. Top risk accounts: {(features_df['ml_risk'] > 0.7).sum():,}")
        return features_df

    def predict(self, features_df=None):
        """Get risk scores for accounts."""
        if features_df is None:
            features_df = self.features_df

        if not self.is_trained:
            self._load_models()

        X = features_df[self.feature_cols].fillna(0)

        iso_scores = self.iso_forest.decision_function(X)
        iso_risk = 1 - (iso_scores - iso_scores.min()) / (iso_scores.max() - iso_scores.min() + 1e-8)

        if self.lgbm_model:
            lgbm_risk = self.lgbm_model.predict_proba(X)[:, 1]
        else:
            lgbm_risk = iso_risk

        ml_risk = iso_risk * 0.4 + lgbm_risk * 0.6
        return ml_risk

    def explain(self, account_idx):
        """Get SHAP explanation for a specific account.
        
        Returns:
            dict with feature importances
        """
        if not HAS_SHAP or not self.shap_explainer or self.features_df is None:
            return {"error": "SHAP not available"}

        X = self.features_df[self.feature_cols].fillna(0)
        if account_idx >= len(X):
            return {"error": "Invalid index"}

        shap_values = self.shap_explainer.shap_values(X.iloc[[account_idx]])

        # Handle binary classification SHAP output
        if isinstance(shap_values, list):
            sv = shap_values[1][0]  # Class 1 (positive)
        else:
            sv = shap_values[0]

        # Build feature importance dict
        importances = {}
        for feat, val in zip(self.feature_cols, sv):
            importances[feat] = round(float(val), 4)

        # Sort by absolute importance
        importances = dict(sorted(importances.items(), key=lambda x: abs(x[1]), reverse=True))

        return {
            "account_id": self.features_df.iloc[account_idx]['account_id'],
            "ml_risk": float(self.features_df.iloc[account_idx].get('ml_risk', 0)),
            "shap_values": importances,
            "top_features": dict(list(importances.items())[:5]),
        }

    def get_high_risk_accounts(self, threshold=0.7):
        """Get accounts above the risk threshold."""
        if self.features_df is None:
            return []

        high_risk = self.features_df[self.features_df['ml_risk'] > threshold].copy()
        high_risk = high_risk.sort_values('ml_risk', ascending=False)

        return high_risk[['account_id', 'ml_risk', 'iso_risk', 'lgbm_risk',
                          'txn_count_total', 'amt_total']].to_dict('records')

    def _save_models(self):
        """Save trained models to disk."""
        os.makedirs(MODELS_DIR, exist_ok=True)

        with open(os.path.join(MODELS_DIR, 'iso_forest.pkl'), 'wb') as f:
            pickle.dump(self.iso_forest, f)

        if self.lgbm_model:
            with open(os.path.join(MODELS_DIR, 'lgbm_model.pkl'), 'wb') as f:
                pickle.dump(self.lgbm_model, f)

        if self.features_df is not None:
            self.features_df.to_parquet(os.path.join(MODELS_DIR, 'features.parquet'), index=False)

        print(f"[MLEngine] Models saved to {MODELS_DIR}")

    def _load_models(self):
        """Load pre-trained models from disk."""
        iso_path = os.path.join(MODELS_DIR, 'iso_forest.pkl')
        lgbm_path = os.path.join(MODELS_DIR, 'lgbm_model.pkl')
        feat_path = os.path.join(MODELS_DIR, 'features.parquet')

        if os.path.exists(iso_path):
            with open(iso_path, 'rb') as f:
                self.iso_forest = pickle.load(f)

        if os.path.exists(lgbm_path):
            with open(lgbm_path, 'rb') as f:
                self.lgbm_model = pickle.load(f)

        if os.path.exists(feat_path):
            self.features_df = pd.read_parquet(feat_path)

        if self.iso_forest:
            self.is_trained = True
            if HAS_SHAP and self.lgbm_model:
                self.shap_explainer = shap.TreeExplainer(self.lgbm_model)

    # ── Public convenience methods for scan orchestration ──────────────

    def load_model(self) -> bool:
        """Public alias: load saved models. Returns True if successful."""
        self._load_models()
        return self.is_trained

    def predict_risks(self):
        """Public alias: compute account features and return risk DataFrame."""
        if self.features_df is None:
            self.features_df = compute_account_features()
        if self.features_df.empty:
            import pandas as pd
            return pd.DataFrame()
        risk_scores = self.predict(self.features_df)
        result = self.features_df[['account_id']].copy()
        result['ml_risk'] = risk_scores
        return result

    def evaluate(self):
        """Return AUC score on test set."""
        if self.features_df is None or not self.is_trained:
            return 0

        X = self.features_df[self.feature_cols].fillna(0)
        y = (self.features_df['is_laundering_max'] > 0).astype(int)

        if self.lgbm_model and y.sum() > 0:
            y_pred = self.lgbm_model.predict_proba(X)[:, 1]
            return roc_auc_score(y, y_pred)
        return 0
