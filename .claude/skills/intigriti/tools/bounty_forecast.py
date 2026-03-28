#!/usr/bin/env python3
"""
Intigriti Bounty Forecaster
Reads inbox export and projects earnings under different scenarios.
All amounts normalized to EUR.

Usage:
  python3 bounty_forecast.py outputs/intigriti-inbox/report_latest.json
  python3 bounty_forecast.py outputs/intigriti-inbox/report_latest.json --eur-rates '{"USD":0.93,"GBP":1.18}'
"""

import argparse
import json
import sys
import urllib.request
import urllib.error
from datetime import date
from pathlib import Path

# Fallback rates if Frankfurter API is unavailable
FALLBACK_EUR_RATES = {"EUR": 1.0, "USD": 0.93, "GBP": 1.18}

# Cache for historical rates: {("2026-03-20", "USD"): 0.92, ...}
_rate_cache = {}


def fetch_ecb_rate(currency, on_date):
    """Fetch historical EUR rate from Frankfurter API (ECB data).
    Returns how many EUR 1 unit of `currency` is worth on `on_date`."""
    if currency == "EUR":
        return 1.0
    cache_key = (on_date, currency)
    if cache_key in _rate_cache:
        return _rate_cache[cache_key]
    try:
        url = f"https://api.frankfurter.dev/{on_date}?from={currency}&to=EUR&amount=1"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "IntiForecaster/1.0")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            rate = data.get("rates", {}).get("EUR", FALLBACK_EUR_RATES.get(currency, 1.0))
            _rate_cache[cache_key] = rate
            return rate
    except (urllib.error.URLError, json.JSONDecodeError, KeyError):
        fallback = FALLBACK_EUR_RATES.get(currency, 1.0)
        _rate_cache[cache_key] = fallback
        return fallback


def get_current_rates(currencies):
    """Fetch today's rates for a set of currencies."""
    today = date.today().isoformat()
    rates = {"EUR": 1.0}
    for cur in currencies:
        if cur != "EUR":
            rates[cur] = fetch_ecb_rate(cur, today)
    return rates


# Acceptance probability by disposition + severity
ACCEPTANCE_PROBS = {
    # Already triaged = company looked at it, good sign
    "triaged": {"Exceptional": 0.70, "Critical": 0.65, "High": 0.60, "Medium": 0.50, "Low": 0.40},
    # New = not yet looked at
    "new": {"Exceptional": 0.50, "Critical": 0.45, "High": 0.35, "Medium": 0.25, "Low": 0.15},
}

# VDP programs rarely pay bounties (but sometimes bonuses)
VDP_BONUS_PROB = 0.15


def to_eur(amount, currency, rates):
    return amount * rates.get(currency, 1.0)


def classify_program_type(sub):
    if sub["listed_bounty"] == 0:
        return "vdp"
    return "bounty"


def score_submission(sub, historical_rate=None):
    disposition = sub["disposition"]
    severity = sub["severity"]
    prog_type = classify_program_type(sub)

    base_prob = ACCEPTANCE_PROBS.get(disposition, {}).get(severity, 0.20)

    if prog_type == "vdp":
        base_prob *= VDP_BONUS_PROB

    if historical_rate is not None:
        base_prob = (base_prob + historical_rate) / 2

    return {
        "probability": round(base_prob, 2),
        "program_type": prog_type,
    }


def forecast(report, current_rates, historical_rate=None, ai_evaluations=None):
    pending = report.get("pending_submissions", [])
    paid = report.get("paid_submissions", [])

    # Index AI evaluations by submission ID
    ai_by_id = {}
    if ai_evaluations:
        for ev in ai_evaluations:
            if ev.get("ai_evaluation"):
                ai_by_id[ev["id"]] = ev["ai_evaluation"]

    total_closed = report["breakdown"]["paid"] + report["breakdown"]["rejected"]
    if total_closed > 0 and historical_rate is None:
        historical_rate = report["breakdown"]["paid"] / total_closed

    scored = []
    for sub in pending:
        heuristic = score_submission(sub, historical_rate)
        prog_type = heuristic["program_type"]
        expected_bounty = sub["listed_bounty"]

        if prog_type == "vdp":
            severity_bonus_map = {
                "Exceptional": 2000, "Critical": 1500, "High": 1000,
                "Medium": 500, "Low": 200,
            }
            expected_bounty = severity_bonus_map.get(sub["severity"], 300)

        # Use AI evaluation if available, otherwise fall back to heuristic
        # Blend AI probability with researcher's historical acceptance rate.
        # More closed submissions = more weight on history; fewer = trust AI more.
        # Weight: history_weight = min(total_closed / 20, 0.5)
        #   0 closed  → 100% AI (no data to calibrate against)
        #   10 closed → 75% AI / 25% history
        #   20+ closed → 50% AI / 50% history
        ai_eval = ai_by_id.get(sub.get("id"))
        if ai_eval:
            raw_prob = ai_eval["acceptance_probability"]
            if historical_rate is not None and total_closed > 0:
                history_weight = min(total_closed / 20, 0.5)
                prob = round(raw_prob * (1 - history_weight) + historical_rate * history_weight, 2)
            else:
                prob = raw_prob
            prob_source = "ai"
            ai_data = {
                "likely_outcome": ai_eval.get("likely_outcome"),
                "severity_assessment": ai_eval.get("severity_assessment"),
                "strengths": ai_eval.get("strengths", []),
                "weaknesses": ai_eval.get("weaknesses", []),
                "triager_reasoning": ai_eval.get("triager_reasoning"),
                "suggested_improvements": ai_eval.get("suggested_improvements", []),
                "ai_confidence": ai_eval.get("confidence", 0),
            }
        else:
            prob = heuristic["probability"]
            prob_source = "heuristic"
            ai_data = {}

        expected_eur = to_eur(expected_bounty, sub["listed_currency"], current_rates)
        ev = expected_eur * prob

        scored.append({
            **sub,
            "acceptance_prob": prob,
            "prob_source": prob_source,
            "program_type": prog_type,
            "expected_bounty_eur": round(expected_eur, 2),
            "expected_value_eur": round(ev, 2),
            **ai_data,
        })

    scored.sort(key=lambda x: x["expected_value_eur"], reverse=True)

    total_ev = sum(s["expected_value_eur"] for s in scored)
    total_potential = sum(s["expected_bounty_eur"] for s in scored)

    # Confirmed earnings — use historical exchange rate at payout date
    confirmed_eur = 0
    payout_conversions = []
    for sub in paid:
        if sub["total_paid"] > 0 and sub["total_paid_currency"]:
            cur = sub["total_paid_currency"]
            if cur == "EUR":
                eur_amount = sub["total_paid"]
                rate_used = 1.0
                rate_date = "N/A"
            else:
                # Find the payout date from the payout entries
                payout_date = None
                for p in sub.get("payouts", []):
                    if p.get("paid_date"):
                        payout_date = p["paid_date"]
                        break
                if not payout_date:
                    payout_date = date.today().isoformat()
                rate_used = fetch_ecb_rate(cur, payout_date)
                eur_amount = sub["total_paid"] * rate_used
                rate_date = payout_date

            confirmed_eur += eur_amount
            payout_conversions.append({
                "id": sub.get("id"),
                "program": sub.get("program"),
                "original_amount": sub["total_paid"],
                "original_currency": cur,
                "eur_amount": round(eur_amount, 2),
                "exchange_rate": round(rate_used, 4),
                "rate_date": rate_date,
            })

    # Scenario calculations using probability-weighted values
    # Pessimistic: only triaged/confirmed submissions (triager already validated)
    pessimistic = sum(s["expected_value_eur"] for s in scored
                      if s.get("status", "").lower() == "triaged")
    # Expected: full probability-weighted sum (already calculated as total_ev)
    # Optimistic: assume top half of submissions beat their probability by 50%
    optimistic = sum(
        min(s["expected_bounty_eur"], s["expected_value_eur"] * 1.5)
        for s in scored
    )

    return {
        "historical_acceptance_rate": round(historical_rate, 2) if historical_rate else None,
        "confirmed_earnings_eur": round(confirmed_eur, 2),
        "payout_conversions": payout_conversions,
        "pending_count": len(scored),
        "scenarios": {
            "pessimistic": {
                "description": "Only triaged submissions pay (triager-confirmed)",
                "additional_eur": round(pessimistic, 2),
                "total_eur": round(confirmed_eur + pessimistic, 2),
            },
            "expected": {
                "description": "Probability-weighted expected value",
                "additional_eur": round(total_ev, 2),
                "total_eur": round(confirmed_eur + total_ev, 2),
            },
            "optimistic": {
                "description": "Submissions outperform probability estimates by 50%",
                "additional_eur": round(optimistic, 2),
                "total_eur": round(confirmed_eur + optimistic, 2),
            },
            "maximum": {
                "description": "Every pending submission pays (unrealistic ceiling)",
                "additional_eur": round(total_potential, 2),
                "total_eur": round(confirmed_eur + total_potential, 2),
            },
        },
        "ranked_submissions": scored,
    }


def print_forecast(fc):
    print(f"\n{'='*65}")
    print(f"INTIGRITI BOUNTY FORECAST (EUR)")
    print(f"{'='*65}")
    if fc['historical_acceptance_rate']:
        print(f"Historical acceptance rate: {fc['historical_acceptance_rate']:.0%}")
    print(f"Confirmed earnings: \u20ac{fc['confirmed_earnings_eur']:,.2f}")
    print(f"Pending submissions: {fc['pending_count']}")

    if fc.get("payout_conversions"):
        print(f"\n{'─'*65}")
        print("PAYOUT CONVERSIONS (historical ECB rates):")
        for pc in fc["payout_conversions"]:
            if pc["original_currency"] == "EUR":
                print(f"  {pc['program']}: \u20ac{pc['eur_amount']:,.2f}")
            else:
                print(f"  {pc['program']}: {pc['original_currency']} {pc['original_amount']:,.2f} "
                      f"\u00d7 {pc['exchange_rate']:.4f} ({pc['rate_date']}) = \u20ac{pc['eur_amount']:,.2f}")

    print(f"\n{'─'*65}")
    print(f"{'SCENARIO':<25} {'ADDITIONAL':>12} {'TOTAL':>12}")
    print(f"{'─'*65}")
    for name, sc in fc["scenarios"].items():
        print(f"{name.upper():<25} \u20ac{sc['additional_eur']:>10,.0f}  \u20ac{sc['total_eur']:>10,.0f}")

    print(f"\n{'─'*65}")
    print(f"{'RANK':<4} {'PROB':>5} {'EV(\u20ac)':>8} {'POT(\u20ac)':>8} {'PROGRAM':<15} {'TITLE':<30}")
    print(f"{'─'*65}")
    for i, s in enumerate(fc["ranked_submissions"], 1):
        prob_str = f"{s['acceptance_prob']:.0%}"
        print(
            f"{i:<4} {prob_str:>5} {s['expected_value_eur']:>8,.0f} "
            f"{s['expected_bounty_eur']:>8,.0f} "
            f"{s['company'][:15]:<15} "
            f"{s['title'][:30]}..."
        )

    print(f"\nTOP 5 BEST BETS (highest expected value):")
    for i, s in enumerate(fc["ranked_submissions"][:5], 1):
        source = f" [{s['prob_source']}]" if s.get("prob_source") == "ai" else ""
        print(f"  {i}. [{s['severity']}] {s['company']} - {s['title'][:50]}")
        print(f"     {s['acceptance_prob']:.0%} chance{source} \u00d7 \u20ac{s['expected_bounty_eur']:,.0f} = EV \u20ac{s['expected_value_eur']:,.0f}")
        if s.get("triager_reasoning"):
            print(f"     AI: {s['triager_reasoning'][:100]}...")


def main():
    parser = argparse.ArgumentParser(description="Forecast Intigriti bounty earnings (EUR)")
    parser.add_argument("report", help="Path to report_latest.json from inbox_exporter")
    parser.add_argument("--eur-rates", help="JSON with currency->EUR rates", default=None)
    parser.add_argument("--ai-evaluations", help="Path to ai_evaluation.json from ai_triager.py")
    parser.add_argument("--output", help="Save forecast JSON to file")
    args = parser.parse_args()

    report = json.loads(Path(args.report).read_text())

    # Collect all currencies used in pending submissions
    pending_currencies = set()
    for sub in report.get("pending_submissions", []):
        pending_currencies.add(sub.get("listed_currency", "EUR"))

    # Fetch current rates for pending, historical rates are fetched per-payout inside forecast()
    print("[*] Fetching current ECB exchange rates...")
    current_rates = get_current_rates(pending_currencies)
    if args.eur_rates:
        current_rates.update(json.loads(args.eur_rates))
    print(f"[+] Rates: {current_rates}")

    ai_evals = None
    if args.ai_evaluations:
        ai_evals = json.loads(Path(args.ai_evaluations).read_text())
        print(f"[+] Loaded {len([e for e in ai_evals if e.get('ai_evaluation')])} AI evaluations")

    fc = forecast(report, current_rates, ai_evaluations=ai_evals)
    print_forecast(fc)

    if args.output:
        Path(args.output).write_text(json.dumps(fc, indent=2))
        print(f"\n[+] Forecast saved to {args.output}")


if __name__ == "__main__":
    main()
