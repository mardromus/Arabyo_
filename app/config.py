import os
from dotenv import load_dotenv

load_dotenv()  # Reads .env at project root
os.environ['LOKY_MAX_CPU_COUNT'] = str(os.cpu_count() or 4)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
DATASET_DIR = os.path.join(BASE_DIR, "Dataset")
POLICIES_DIR = os.path.join(BASE_DIR, "policies")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
MODELS_DIR = os.path.join(BASE_DIR, "models")

# ── Database (SQLite — works on any architecture including ARM) ────────────
# Override via env: DB_PATH, TRANSACTIONS_CSV, ACCOUNTS_CSV
DB_PATH = os.environ.get("DB_PATH") or os.path.join(DATA_DIR, "compliance.db")
DB_PATH = os.path.abspath(os.path.expanduser(DB_PATH))
# SQLAlchemy URL — use forward slashes for cross-platform compatibility
DATABASE_URL = "sqlite:///" + str(DB_PATH).replace("\\", "/")

# Dataset files (HI-Small default; override via env)
_default_txn_csv = os.path.join(DATASET_DIR, "HI-Small_Trans.csv")
_default_acc_csv = os.path.join(DATASET_DIR, "HI-Small_accounts.csv")
TRANSACTIONS_CSV = os.path.abspath(os.path.expanduser(
    os.environ.get("TRANSACTIONS_CSV") or _default_txn_csv
))
ACCOUNTS_CSV = os.path.abspath(os.path.expanduser(
    os.environ.get("ACCOUNTS_CSV") or _default_acc_csv
))
PATTERNS_FILE = os.path.join(DATASET_DIR, "HI-Small_Patterns.txt")

# Rules storage (JSON sidecar — still file-based)
RULES_FILE = os.path.join(DATA_DIR, "rules.json")

# Flask
SECRET_KEY = os.environ.get("SECRET_KEY", "compliance-agent-dev-key-2024")
DEBUG = True

# ML
ML_TEST_SIZE = 0.2
ML_RANDOM_STATE = 42

# Detection thresholds
ALERT_THRESHOLD = 0.15  # Minimum fusion score to generate an alert (risk floor)
TARGET_ALERT_VOLUME = 10000  # Desired number of alerts
CLUSTER_RISK_BOOST = 0.15  # Risk uplift for high-risk cluster membership

# Chunk size for loading large CSVs
CHUNK_SIZE = 50000

# ── Kafka (real-time streaming) ─────────────────────────────────────────────
KAFKA_BOOTSTRAP_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
KAFKA_TOPIC_INCOMING = os.environ.get("KAFKA_TOPIC_INCOMING", "transactions.incoming")
KAFKA_TOPIC_SCORED = os.environ.get("KAFKA_TOPIC_SCORED", "transactions.scored")
KAFKA_TOPIC_ALERTS = os.environ.get("KAFKA_TOPIC_ALERTS", "alerts.generated")
KAFKA_CONSUMER_GROUP = os.environ.get("KAFKA_CONSUMER_GROUP", "compliance-consumer-group")
KAFKA_GROUP_ID = os.environ.get("KAFKA_GROUP_ID", KAFKA_CONSUMER_GROUP)

# ── Firebase Auth ───────────────────────────────────────────────────────────
FIREBASE_CONFIG = {
    "apiKey": "AIzaSyAPHZIjIEurZWs9a982tjB3VScXjwvgqTI",
    "authDomain": "arabyo-b703f.firebaseapp.com",
    "projectId": "arabyo-b703f",
    "storageBucket": "arabyo-b703f.firebasestorage.app",
    "messagingSenderId": "890494805409",
    "appId": "1:890494805409:web:07a83ae254e7c47b3617e0",
    "measurementId": "G-724NRP4ED7",
}
# Path to Firebase Admin SDK service account JSON (download from Firebase Console)
FIREBASE_SERVICE_ACCOUNT_PATH = os.environ.get(
    "FIREBASE_SERVICE_ACCOUNT_PATH",
    os.path.join(BASE_DIR, "credentials", "firebase-adminsdk.json"),
)
# Comma-separated emails that get admin role; others get analyst
ADMIN_EMAILS = set(
    e.strip().lower()
    for e in os.environ.get("ADMIN_EMAILS", "").split(",")
    if e.strip()
)
RISK_MANAGER_EMAILS = set(
    e.strip().lower()
    for e in os.environ.get("RISK_MANAGER_EMAILS", "").split(",")
    if e.strip()
)
AUDITOR_EMAILS = set(
    e.strip().lower()
    for e in os.environ.get("AUDITOR_EMAILS", "").split(",")
    if e.strip()
)
# When True, skip Firebase auth and use ?role= for local dev
FIREBASE_AUTH_DISABLED = os.environ.get("FIREBASE_AUTH_DISABLED", "").lower() in ("1", "true", "yes")

# Ensure directories exist
for d in [DATA_DIR, POLICIES_DIR, REPORTS_DIR, MODELS_DIR]:
    os.makedirs(d, exist_ok=True)
