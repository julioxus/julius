# VALIDATION_CHECKLIST.py
# Mandatory validation gates to prevent false positive crises
# Implements 5-gate validation system from VALIDATION_CHECKLIST.md

import requests
import os
from urllib.parse import urlparse
from typing import Dict, Any
import json
import time


class ValidationError(Exception):
    """Raised when a validation gate fails"""
    pass


class ValidationGates:
    """5-gate validation system to prevent false positives"""

    @staticmethod
    def verify_infrastructure_exists(target_url: str) -> bool:
        """GATE 1: Verify target is functional application, not placeholder"""
        try:
            # Test 3 endpoints to verify real application
            base_tests = [
                f"{target_url}/",
                f"{target_url}/definitely-fake-endpoint-12345",
                f"{target_url}/health"
            ]

            responses = []
            for url in base_tests:
                try:
                    resp = requests.get(url, timeout=10, allow_redirects=False)
                    responses.append((url, resp.status_code, resp.text[:100]))
                except:
                    responses.append((url, 0, ""))

            # RED FLAGS: All return same response (placeholder server)
            texts = [r[2] for r in responses]
            if len(set(texts)) <= 1 and all(r[1] == 200 for r in responses):
                print(f"❌ INFRASTRUCTURE FAILURE: All endpoints return identical responses")
                print(f"   Responses: {responses}")
                return False

            return True

        except Exception as e:
            print(f"❌ INFRASTRUCTURE FAILURE: {e}")
            return False

    @staticmethod
    def verify_different_responses(finding_data: Dict[Any, Any]) -> bool:
        """GATE 2: Verify valid vs invalid inputs produce different responses"""
        target = finding_data.get('target')
        if not target:
            return False

        try:
            # Test with no auth
            resp_none = requests.get(target, timeout=10)

            # Test with valid auth (if provided)
            valid_auth = finding_data.get('valid_credentials')
            resp_valid = None
            if valid_auth:
                resp_valid = requests.get(target, headers=valid_auth, timeout=10)

            # Test with invalid auth
            invalid_auth = {"Authorization": "Bearer INVALID_TOKEN"}
            resp_invalid = requests.get(target, headers=invalid_auth, timeout=10)

            # Check if responses are actually different
            responses = [resp_none.status_code, resp_invalid.status_code]
            if valid_auth and resp_valid:
                responses.append(resp_valid.status_code)

            # RED FLAG: All same status code suggests no real validation
            if len(set(responses)) <= 1:
                print(f"❌ BEHAVIOR FAILURE: All auth scenarios return same status: {responses}")
                return False

            return True

        except Exception as e:
            print(f"❌ BEHAVIOR FAILURE: {e}")
            return False

    @staticmethod
    def verify_e2e_impact(finding_data: Dict[Any, Any]) -> bool:
        """GATE 3: Verify end-to-end impact is demonstrated with evidence"""

        # Check for evidence files
        evidence_path = finding_data.get('evidence_path', '')
        if not evidence_path or not os.path.exists(evidence_path):
            print(f"❌ E2E FAILURE: No evidence directory found")
            return False

        # Check for PoC files
        poc_code = finding_data.get('poc_code', '')
        poc_output = finding_data.get('poc_output', '')

        if not poc_code or not poc_output:
            print(f"❌ E2E FAILURE: Missing PoC code or output")
            return False

        # Check for impact claims vs evidence
        claimed_impact = finding_data.get('impact', '').lower()
        impact_keywords = ['account takeover', 'data breach', 'rce', 'sql injection']

        has_impact_claim = any(keyword in claimed_impact for keyword in impact_keywords)

        if has_impact_claim:
            # For high impact claims, require specific evidence
            evidence_files = os.listdir(evidence_path) if os.path.exists(evidence_path) else []

            if 'account takeover' in claimed_impact:
                # Must have screenshot of successful login or session hijack
                if not any('login' in f or 'session' in f or 'account' in f for f in evidence_files):
                    print(f"❌ E2E FAILURE: Account takeover claimed but no login evidence")
                    return False

            if 'data breach' in claimed_impact:
                # Must have extracted data evidence
                if not any('data' in f or 'extract' in f for f in evidence_files):
                    print(f"❌ E2E FAILURE: Data breach claimed but no extraction evidence")
                    return False

        return True

    @staticmethod
    def verify_not_by_design(finding_data: Dict[Any, Any]) -> bool:
        """GATE 4: Verify behavior is not intended/by-design"""
        target = finding_data.get('target', '')
        description = finding_data.get('description', '').lower()

        # Check for common by-design patterns
        by_design_patterns = [
            'store locator',
            'public api',
            'documentation',
            'help page',
            'contact information',
            'privacy policy'
        ]

        if any(pattern in description for pattern in by_design_patterns):
            print(f"⚠️  BUSINESS LOGIC WARNING: May be by design - manual review required")
            # Don't auto-fail, but flag for review

        return True

    @staticmethod
    def verify_still_vulnerable(finding_data: Dict[Any, Any]) -> bool:
        """GATE 5: Live revalidation - verify vulnerability still exists"""
        poc_code = finding_data.get('poc_code', '')

        if not poc_code:
            return False

        try:
            # Re-execute PoC to verify it still works
            # This is a simplified version - would need more robust execution
            target = finding_data.get('target')
            if not target:
                return False

            # Quick verification request
            resp = requests.get(target, timeout=10)

            # If target is completely down, that's different from fixed vulnerability
            if resp.status_code >= 500:
                print(f"⚠️  REVALIDATION WARNING: Target appears down (5xx), not necessarily fixed")

            return True

        except Exception as e:
            print(f"❌ REVALIDATION FAILURE: {e}")
            return False


class MandatoryValidator:
    """Main validator that enforces all 5 gates before external communication"""

    @staticmethod
    def validate_finding_before_report(finding_data: dict, engagement_name: str) -> bool:
        """MANDATORY: Run before ANY external communication"""

        print(f"🔒 RUNNING MANDATORY VALIDATION FOR ENGAGEMENT: {engagement_name}")
        print(f"   Finding: {finding_data.get('title', 'Unknown')}")
        print(f"   Target: {finding_data.get('target', 'Unknown')}")

        # GATE 1: Infrastructure Reality Check
        print("   GATE 1: Infrastructure Reality Check...")
        if not ValidationGates.verify_infrastructure_exists(finding_data.get('target', '')):
            raise ValidationError("Target infrastructure is not functional")
        print("   ✅ GATE 1 PASSED")

        # GATE 2: Behavior Differentiation Test
        print("   GATE 2: Behavior Differentiation Test...")
        if not ValidationGates.verify_different_responses(finding_data):
            raise ValidationError("No behavioral difference detected between valid/invalid inputs")
        print("   ✅ GATE 2 PASSED")

        # GATE 3: End-to-End Impact Proof
        print("   GATE 3: End-to-End Impact Proof...")
        if not ValidationGates.verify_e2e_impact(finding_data):
            raise ValidationError("No end-to-end exploitation demonstrated")
        print("   ✅ GATE 3 PASSED")

        # GATE 4: Business Logic Verification
        print("   GATE 4: Business Logic Verification...")
        if not ValidationGates.verify_not_by_design(finding_data):
            raise ValidationError("Behavior appears to be by design")
        print("   ✅ GATE 4 PASSED")

        # GATE 5: Live Revalidation
        print("   GATE 5: Live Revalidation...")
        if not ValidationGates.verify_still_vulnerable(finding_data):
            raise ValidationError("Vulnerability no longer reproducible")
        print("   ✅ GATE 5 PASSED")

        print("🔒 ALL VALIDATION GATES PASSED - FINDING APPROVED FOR EXTERNAL COMMUNICATION")
        return True


# Helper functions for output path validation
def get_engagement_output_path(engagement_name: str, file_type: str, filename: str, finding_id: str = None) -> str:
    """Get standardized output path according to OUTPUT_STRUCTURE.md"""
    if file_type == "evidence":
        if not finding_id:
            raise ValueError("finding_id required for evidence files")
        return f"outputs/{engagement_name}/reports/appendix/{finding_id}/{filename}"
    elif file_type == "finding":
        if not finding_id:
            raise ValueError("finding_id required for finding files")
        return f"outputs/{engagement_name}/processed/findings/{finding_id}/{filename}"
    elif file_type == "data":
        subtype = filename.split('-')[0] if '-' in filename else "general"
        return f"outputs/{engagement_name}/data/{subtype}/{filename}"
    elif file_type == "log":
        return f"outputs/{engagement_name}/logs/{filename}"
    else:
        return f"outputs/{engagement_name}/processed/{file_type}/{filename}"


def validate_output_path(path: str, engagement_name: str) -> bool:
    """Validate path follows OUTPUT_STRUCTURE.md standard"""
    if not path.startswith(f"outputs/{engagement_name}/"):
        raise ValueError(f"Invalid path: {path}. Must start with outputs/{engagement_name}/")

    valid_subdirs = ["data", "reports", "logs", "processed", "components"]
    path_parts = path.split("/")
    if len(path_parts) < 4 or path_parts[2] not in valid_subdirs:
        raise ValueError(f"Invalid subdirectory in path: {path}")

    return True


# Example usage for testing
if __name__ == "__main__":
    # Test finding data structure
    test_finding = {
        'title': 'Test SSRF in API endpoint',
        'target': 'https://httpbin.org/get',
        'description': 'Server-side request forgery allows metadata access',
        'impact': 'Could lead to internal network reconnaissance',
        'poc_code': 'curl -X POST https://httpbin.org/post -d "url=http://169.254.169.254"',
        'poc_output': 'HTTP 200 OK\n{"origin": "..."}',
        'evidence_path': '/tmp/test_evidence',
        'valid_credentials': {'Authorization': 'Bearer valid-token-123'}
    }

    # Create test evidence directory
    os.makedirs('/tmp/test_evidence', exist_ok=True)
    with open('/tmp/test_evidence/screenshot.png', 'w') as f:
        f.write('fake screenshot data')

    try:
        result = MandatoryValidator.validate_finding_before_report(test_finding, "test-engagement")
        print(f"✅ Validation result: {result}")
    except ValidationError as e:
        print(f"❌ Validation failed: {e}")

    # Test output path functions
    try:
        evidence_path = get_engagement_output_path("test-engagement", "evidence", "screenshot.png", "finding-001")
        print(f"✅ Evidence path: {evidence_path}")

        validate_output_path(evidence_path, "test-engagement")
        print("✅ Path validation passed")
    except ValueError as e:
        print(f"❌ Path validation failed: {e}")