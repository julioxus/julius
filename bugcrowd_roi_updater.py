#!/usr/bin/env python3
"""
Bugcrowd ROI Analysis Updater
Actualiza los datos de programas y métricas ROI/saturación
"""

import json
import sys
import os
from datetime import datetime
from pathlib import Path

def load_bounty_intel_client():
    """Load BountyIntel client for data access."""
    try:
        sys.path.append(str(Path(__file__).parent / "bounty_intel"))
        from bounty_intel.client import BountyIntelClient
        return BountyIntelClient()
    except ImportError:
        print("BountyIntel client not available")
        return None

def analyze_current_portfolio():
    """Analyze current submission portfolio distribution."""
    client = load_bounty_intel_client()
    if not client:
        return {}

    try:
        stats = client.get_stats()
        submissions = client.get_submissions()

        platform_distribution = {}
        total_submissions = len(submissions.get('result', []))

        for submission in submissions.get('result', []):
            platform = submission.get('platform', 'unknown')
            platform_distribution[platform] = platform_distribution.get(platform, 0) + 1

        # Convert to percentages
        for platform in platform_distribution:
            platform_distribution[platform] = round(
                (platform_distribution[platform] / total_submissions) * 100, 1
            )

        return {
            'total_submissions': total_submissions,
            'platform_distribution': platform_distribution,
            'last_updated': datetime.now().isoformat()
        }

    except Exception as e:
        print(f"Error analyzing portfolio: {e}")
        return {}

def get_bugcrowd_programs():
    """Get current Bugcrowd programs from API."""
    client = load_bounty_intel_client()
    if not client:
        return []

    try:
        programs = client.search_bugcrowd_programs(limit=100)
        return programs.get('result', [])
    except Exception as e:
        print(f"Error fetching Bugcrowd programs: {e}")
        return []

def calculate_roi_metrics(programs, historical_data=None):
    """Calculate ROI metrics for programs."""
    roi_analysis = []

    for program in programs:
        handle = program.get('handle', '')
        name = program.get('name', '')

        # Mock calculation - replace with real data when available
        base_score = 5.0

        # Adjust based on program characteristics
        if 'tesla' in handle.lower():
            roi_score = 8.0
            saturation_score = 6.0
            avg_bounty = 8500
        elif 'crowdstrike' in handle.lower():
            roi_score = 9.0
            saturation_score = 5.0
            avg_bounty = 12000
        else:
            roi_score = base_score
            saturation_score = 5.0
            avg_bounty = 3000

        roi_analysis.append({
            'handle': handle,
            'name': name,
            'roi_score': roi_score,
            'saturation_score': saturation_score,
            'estimated_avg_bounty_usd': avg_bounty,
            'final_score': round((roi_score * 0.6) + ((10 - saturation_score) * 0.4), 1)
        })

    # Sort by final score (highest first)
    return sorted(roi_analysis, key=lambda x: x['final_score'], reverse=True)

def generate_recommendations(roi_analysis, portfolio_data):
    """Generate strategic recommendations."""
    recommendations = []

    current_bugcrowd_pct = portfolio_data.get('platform_distribution', {}).get('bugcrowd', 0)

    if current_bugcrowd_pct < 10:
        recommendations.append({
            'priority': 'high',
            'category': 'portfolio_rebalancing',
            'description': f'Increase Bugcrowd allocation from {current_bugcrowd_pct}% to 25%',
            'expected_impact': 'diversification_risk_reduction'
        })

    # Recommend top programs
    top_programs = roi_analysis[:3]
    for i, program in enumerate(top_programs):
        recommendations.append({
            'priority': 'high' if i == 0 else 'medium',
            'category': 'target_program',
            'description': f'Focus on {program["name"]} (ROI: {program["roi_score"]}, Saturation: {program["saturation_score"]})',
            'expected_monthly_eur': program['estimated_avg_bounty_usd'] * 0.87  # USD to EUR conversion
        })

    return recommendations

def main():
    """Main analysis function."""
    print("🔍 Bugcrowd ROI Analysis Updater")
    print("=" * 50)

    # Get current portfolio data
    print("📊 Analyzing current portfolio...")
    portfolio_data = analyze_current_portfolio()

    if portfolio_data:
        print(f"Total submissions: {portfolio_data['total_submissions']}")
        for platform, pct in portfolio_data['platform_distribution'].items():
            print(f"  {platform.capitalize()}: {pct}%")

    # Get Bugcrowd programs
    print("\n🎯 Fetching Bugcrowd programs...")
    programs = get_bugcrowd_programs()
    print(f"Found {len(programs)} programs")

    # Calculate ROI metrics
    print("\n💰 Calculating ROI metrics...")
    roi_analysis = calculate_roi_metrics(programs)

    print("\nTop 5 Programs by ROI Score:")
    for i, program in enumerate(roi_analysis[:5]):
        print(f"{i+1}. {program['name']} (Score: {program['final_score']})")
        print(f"   ROI: {program['roi_score']}/10, Saturation: {program['saturation_score']}/10")
        print(f"   Est. Avg Bounty: ${program['estimated_avg_bounty_usd']}")

    # Generate recommendations
    print("\n📋 Strategic Recommendations:")
    recommendations = generate_recommendations(roi_analysis, portfolio_data)

    for rec in recommendations:
        priority_emoji = "🔴" if rec['priority'] == 'high' else "🟡"
        print(f"{priority_emoji} {rec['description']}")

    # Save results
    results = {
        'analysis_date': datetime.now().isoformat(),
        'portfolio_data': portfolio_data,
        'roi_analysis': roi_analysis,
        'recommendations': recommendations,
        'next_update_actions': [
            'Install Playwright: pip install playwright && playwright install chromium',
            'Refresh Bugcrowd session for private program access',
            'Run comprehensive program discovery',
            'Update Bounty Intel database with new programs'
        ]
    }

    output_file = Path(__file__).parent / "bugcrowd_roi_analysis_latest.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\n💾 Results saved to: {output_file}")
    print("\n🚀 Next Steps:")
    for step in results['next_update_actions']:
        print(f"  • {step}")

if __name__ == "__main__":
    main()