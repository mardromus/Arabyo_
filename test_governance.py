import sys
import os
import json

# Add project root to Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.db import init_schema, get_connection
from app.policy_engine.rule_service import RuleService
from app.policy_engine.policy_governance import PolicyGovernance
from app.policy_engine.approval_workflow import ApprovalWorkflow

def test_hard_fail_standalone_rules():
    print('Testing strict standalone rule prevention...')
    try:
        # Pass empty version_id
        RuleService.create_rules("", [{"name": "Test Rule", "conditions": []}])
        print('FAILED: RuleService created rule with no version_id.')
        return False
    except ValueError as e:
        print(f"PASSED: Blocked empty version_id -> {e}")
        
    try:
        # Pass non-existent version_id
        RuleService.create_rules("invalid-version", [{"name": "Test Rule", "conditions": []}])
        print('FAILED: RuleService created rule with invalid version_id.')
        return False
    except ValueError as e:
        print(f"PASSED: Blocked invalid version_id -> {e}")
    
    return True

def test_maker_checker():
    print('\nTesting Maker-Checker logic...')
    
    # Create test version
    policy_id = "POL-TEST-001"
    version_id = PolicyGovernance.create_version(
        policy_id=policy_id, 
        created_by='alice@example.com'
    )
    
    # Submit for review
    res = PolicyGovernance.submit_for_review(version_id, "alice@example.com")
    print(f"Submit for review by maker: {res}")
    
    # Try self-approve
    try:
        res = PolicyGovernance.approve(version_id, "alice@example.com")
        if not res.get('success'):
            print(f"PASSED: Prevented self-approval -> {res.get('error')}")
        else:
            print("FAILED: Self-approval succeeded.")
            return False
    except PermissionError as e:
        print(f"PASSED: Prevented self-approval via Exception -> {e}")
        
    # Valid approve by someone else
    res = PolicyGovernance.approve(version_id, "bob@example.com")
    if res.get('success'):
        print(f"PASSED: Checked approved -> {res}")
    else:
        print(f"FAILED: Checker approval failed -> {res}")
        return False
        
    return True

if __name__ == '__main__':
    # Initialize DB (creates sqlite if missing)
    # init_schema()  # Already initialized
    
    res1 = test_hard_fail_standalone_rules()
    res2 = test_maker_checker()
    
    if res1 and res2:
        print('\nSUCCESS: All constraints successfully verified.')
        sys.exit(0)
    else:
        print('\nFAILURE: One or more constraints failed.')
        sys.exit(1)
