"""Main entry point — run the Flask compliance dashboard."""
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.web.routes import create_app

app = create_app()

if __name__ == '__main__':
    print("=" * 60)
    print("  Arabyo - Explainable AML Compliance Agent")
    print("=" * 60)
    print()
    print("  Dashboard: http://localhost:5000")
    print("  Alerts:    http://localhost:5000/alerts")
    print("  Policies:  http://localhost:5000/policies")
    print("  Reports:   http://localhost:5000/reports")
    print()
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=True)
