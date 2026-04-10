#!/usr/bin/env python3
"""
Bugcrowd MCP Bridge
Temporary bridge until MCP server picks up new Bugcrowd tool registrations.
Provides direct access to Bugcrowd functions in MCP-compatible format.
"""

from bounty_intel.platforms import (
    search_bugcrowd_programs,
    get_bugcrowd_program_detail,
    get_bugcrowd_program_scope
)


def bounty_search_bugcrowd_programs(status: str = "", limit: int = 50) -> dict:
    """Search Bugcrowd programs via browser automation or fallback methods.

    Returns programs with name, status, bounty info. Uses browser scraping.
    Equivalent to: mcp__bounty-intel__bounty_search_bugcrowd_programs
    """
    try:
        programs = search_bugcrowd_programs(status=status, limit=limit)
        return {"result": programs}
    except Exception as e:
        return {"error": str(e), "result": []}


def bounty_get_bugcrowd_program_detail(program_code: str) -> dict:
    """Get full Bugcrowd program detail including scope and rules.

    program_code is the Bugcrowd program handle. Returns scope targets with priorities.
    Equivalent to: mcp__bounty-intel__bounty_get_bugcrowd_program_detail
    """
    try:
        result = get_bugcrowd_program_detail(program_code)
        return result or {"error": "not found or scraping failed"}
    except Exception as e:
        return {"error": str(e)}


def bounty_get_bugcrowd_program_scope(program_code: str) -> list:
    """Get Bugcrowd program scope (targets).

    Returns list of in-scope targets with type, name, priority, and bounty eligibility.
    Equivalent to: mcp__bounty-intel__bounty_get_bugcrowd_program_scope
    """
    try:
        result = get_bugcrowd_program_scope(program_code)
        return result or []
    except Exception as e:
        print(f"Error getting Bugcrowd scope for {program_code}: {e}")
        return []


# Convenience functions for direct use
def search_programs(status: str = "", limit: int = 50):
    """Direct search function"""
    return bounty_search_bugcrowd_programs(status=status, limit=limit)


def get_program_detail(program_code: str):
    """Direct program detail function"""
    return bounty_get_bugcrowd_program_detail(program_code)


def get_program_scope(program_code: str):
    """Direct scope function"""
    return bounty_get_bugcrowd_program_scope(program_code)


# Test functions
def test_bugcrowd_mcp_bridge():
    """Test all bridge functions"""
    print("🧪 Testing Bugcrowd MCP Bridge")
    print("=" * 40)

    # Test search
    print("✓ Testing program search...")
    search_result = bounty_search_bugcrowd_programs(limit=3)
    programs = search_result.get("result", [])
    print(f"  Found: {len(programs)} programs")

    # Test detail extraction
    if programs:
        test_handle = programs[0]["handle"]
        print(f"✓ Testing program detail for '{test_handle}'...")
        detail = bounty_get_bugcrowd_program_detail(test_handle)
        print(f"  Result: {detail.get('name', 'Unknown')}")

    print("🎯 Bridge tests completed")


if __name__ == "__main__":
    test_bugcrowd_mcp_bridge()