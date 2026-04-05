#!/usr/bin/env python3
"""
Bounty Forecaster
Reads inbox export (Intigriti + HackerOne) and projects earnings under different scenarios.
All amounts normalized to EUR.

Usage:
  python3 bounty_forecast.py outputs/combined-inbox/report_latest.json
  python3 bounty_forecast.py outputs/combined-inbox/report_latest.json --eur-rates '{"USD":0.93,"GBP":1.18}'
"""

import argparse
import json
import sys
import urllib.request
import urllib.error
from datetime import date, timedelta
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
        url = f"https://api.frankfurter.app/{on_date}?from={currency}&to=EUR&amount=1"
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


def month_label(ym):
    """Convert 'YYYY-MM' to 'Jan 2026' style label."""
    y, m = ym.split("-")
    names = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
             "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    return f"{names[int(m)-1]} {y}"


def add_months(ym, n):
    """Add n months to a 'YYYY-MM' string."""
    y, m = int(ym[:4]), int(ym[5:7])
    m += n
    while m > 12:
        m -= 12
        y += 1
    return f"{y:04d}-{m:02d}"


# Intigriti default validation times (working days) by severity.
# Source: programs referencing go.intigriti.com/triage-standards
# Multiplied by 1.4 to convert working days → calendar days.
INTIGRITI_DEFAULT_VALIDATION_DAYS = {
    "Exceptional": round(3 * 1.4),   # 4 calendar days
    "Critical": round(3 * 1.4),      # 4
    "High": round(7 * 1.4),          # 10
    "Medium": round(15 * 1.4),       # 21
    "Low": round(15 * 1.4),          # 21
}

# HackerOne default validation times (calendar days) by severity.
# Company-managed triage (not platform-managed like Intigriti).
HACKERONE_DEFAULT_VALIDATION_DAYS = {
    "Critical": 5,
    "High": 7,
    "Medium": 14,
    "Low": 21,
}

# Extra buffer: time from submission to platform picking it up (before validation starts)
TRIAGE_PICKUP_BUFFER_DAYS = 3


def parse_validation_times(severity_assessment_content):
    """Parse validation times from a program's severityAssessments markdown.
    Returns dict like {"Exceptional": 4, "Critical": 4, "High": 10, ...} in calendar days,
    or None if no table found."""
    import re
    if not severity_assessment_content:
        return None

    # Look for markdown table rows with severity + days
    # Format: | Exceptional | 3 Working days |
    pattern = re.compile(
        r'\|\s*(Exceptional|Critical|High|Medium|Low)\s*\|\s*(\d+)\s*[Ww]orking\s*days?\s*\|',
        re.IGNORECASE
    )
    times = {}
    for match in pattern.finditer(severity_assessment_content):
        sev = match.group(1).capitalize()
        working_days = int(match.group(2))
        calendar_days = round(working_days * 1.4)
        times[sev] = calendar_days

    return times if times else None


def fetch_program_validation_times(programs_handles, cookie_path=None):
    """Fetch validation times for programs from Intigriti API.
    programs_handles: dict of {company_name: "companyHandle/programHandle"}
    Returns: {company_name: {severity: calendar_days}} """
    cookie = None
    if cookie_path is None:
        cookie_path = Path.home() / ".intigriti" / "session_cookie.txt"
    if cookie_path.exists():
        cookie = cookie_path.read_text().strip()
    if not cookie:
        return {}

    result = {}
    for company, handle in programs_handles.items():
        try:
            url = f"https://app.intigriti.com/api/core/researcher/programs/{handle}"
            req = urllib.request.Request(url)
            req.add_header("Cookie", f"__Host-Intigriti.Web.Researcher={cookie}")
            req.add_header("Accept", "application/json")
            req.add_header("User-Agent", "IntiForecaster/1.0")
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            sa = data.get("severityAssessments", [])
            if sa:
                content = sa[0].get("content", {}).get("content", "")
                times = parse_validation_times(content)
                if times:
                    result[company] = times
        except (urllib.error.URLError, json.JSONDecodeError, KeyError, IndexError):
            pass

    return result


def _empty_month():
    return {
        "confirmed_eur": 0, "pending_ev_eur": 0,
        "submitted": 0, "paid": 0, "rejected": 0, "pending": 0,
        "submissions": [],
    }


def build_monthly_breakdown(payout_conversions, scored_pending, report, today=None):
    """Build month-by-month breakdown with KPIs: earnings, submissions, acceptance rate."""
    if today is None:
        today = date.today()
    current_ym = today.strftime("%Y-%m")

    months = {}  # "YYYY-MM" -> month data

    # --- Activity metrics: group ALL submissions by created_at month ---
    for sub in report.get("paid_submissions", []):
        ym = (sub.get("created_at") or "")[:7]
        if not ym:
            continue
        if ym not in months:
            months[ym] = _empty_month()
        months[ym]["submitted"] += 1
        months[ym]["paid"] += 1

    for sub in report.get("pending_submissions", []):
        ym = (sub.get("created_at") or "")[:7]
        if not ym:
            continue
        if ym not in months:
            months[ym] = _empty_month()
        months[ym]["submitted"] += 1
        months[ym]["pending"] += 1

    for sub in report.get("rejected_submissions", []):
        ym = (sub.get("created_at") or "")[:7]
        if not ym:
            continue
        if ym not in months:
            months[ym] = _empty_month()
        months[ym]["submitted"] += 1
        months[ym]["rejected"] += 1

    # --- Confirmed payouts by paid_date month ---
    for pc in payout_conversions:
        for p in pc.get("payouts", []):
            rd = p.get("rate_date") or ""
            ym = rd[:7] if rd and rd != "N/A" else current_ym
            if ym not in months:
                months[ym] = _empty_month()
            months[ym]["confirmed_eur"] += p.get("eur_amount", 0)
            months[ym]["submissions"].append({
                "id": pc.get("id"),
                "program": pc.get("program"),
                "amount_eur": round(p.get("eur_amount", 0), 2),
                "type": "paid",
            })

    # --- Fetch program validation times (from API or defaults) ---
    # Collect unique Intigriti program handles from pending submissions
    # (HackerOne programs don't use the Intigriti API for validation times)
    program_handles = {}
    for s in scored_pending:
        company = s.get("company", "")
        handle = s.get("program_handle", "")
        platform = s.get("platform", "intigriti")
        if company and handle and company not in program_handles and platform == "intigriti":
            program_handles[company] = handle

    # Fetch custom validation times from programs that publish them
    print("[*] Fetching program validation times...")
    custom_times = fetch_program_validation_times(program_handles)
    if custom_times:
        print(f"[+] Custom validation times from: {', '.join(custom_times.keys())}")

    # --- Distribute pending EV by estimated resolution date ---
    triage_details = {}  # company -> {severity: days, source}
    for s in scored_pending:
        ev = s.get("expected_value_eur", 0)
        if ev <= 0:
            continue

        company = s.get("company", s.get("program", ""))
        severity = s.get("severity", "Medium")
        created = s.get("created_at", "")
        try:
            d_created = date.fromisoformat(created[:10]) if created else today
        except (ValueError, TypeError):
            d_created = today

        # Use program-specific times if available, else platform defaults
        platform = s.get("platform", "intigriti")
        if company in custom_times and severity in custom_times[company]:
            validation_days = custom_times[company][severity]
            source = "program"
        elif platform == "hackerone":
            validation_days = HACKERONE_DEFAULT_VALIDATION_DAYS.get(severity, 14)
            source = "hackerone-default"
        else:
            validation_days = INTIGRITI_DEFAULT_VALIDATION_DAYS.get(severity, 21)
            source = "intigriti-default"

        total_days = validation_days + TRIAGE_PICKUP_BUFFER_DAYS
        est_resolve = d_created + timedelta(days=total_days)

        # Track for display
        if company not in triage_details:
            triage_details[company] = {"source": source}
        triage_details[company][severity] = total_days

        # If estimated resolution is in the past, assume it resolves this month
        if est_resolve < today:
            est_resolve = today

        target_ym = est_resolve.strftime("%Y-%m")
        if target_ym not in months:
            months[target_ym] = _empty_month()
        months[target_ym]["pending_ev_eur"] += ev
        months[target_ym]["submissions"].append({
            "id": s.get("id"),
            "program": company,
            "amount_eur": round(ev, 2),
            "type": "pending" if target_ym == current_ym else "projected",
            "est_resolve": est_resolve.isoformat(),
            "validation_days": total_days,
            "source": source,
        })

    # --- Fill gaps and build result ---
    all_yms = sorted(months.keys())
    if not all_yms:
        return []

    first_ym = min(all_yms[0], current_ym)
    last_ym = max(all_yms[-1], current_ym)

    result = []
    ym = first_ym
    while ym <= last_ym:
        entry = months.get(ym, _empty_month())
        if ym < current_ym:
            mtype = "past"
        elif ym == current_ym:
            mtype = "current"
        else:
            mtype = "future"

        total = entry["confirmed_eur"] + entry["pending_ev_eur"]
        resolved = entry["paid"] + entry["rejected"]
        acc_rate = round(entry["paid"] / resolved, 2) if resolved > 0 else None

        result.append({
            "month": ym,
            "label": month_label(ym),
            "type": mtype,
            "confirmed_eur": round(entry["confirmed_eur"], 2),
            "pending_ev_eur": round(entry["pending_ev_eur"], 2),
            "total_eur": round(total, 2),
            "submitted": entry["submitted"],
            "paid": entry["paid"],
            "rejected": entry["rejected"],
            "pending": entry["pending"],
            "acceptance_rate": acc_rate,
            "submissions": entry["submissions"],
        })
        ym = add_months(ym, 1)

    # Build triage stats summary for display
    triage_stats = {
        "default_validation_days": {
            "intigriti": INTIGRITI_DEFAULT_VALIDATION_DAYS,
            "hackerone": HACKERONE_DEFAULT_VALIDATION_DAYS,
        },
        "pickup_buffer_days": TRIAGE_PICKUP_BUFFER_DAYS,
        "programs": {
            company: info
            for company, info in sorted(triage_details.items())
        },
    }

    return result, triage_stats


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


def forecast(report, current_rates, historical_rate=None, ai_evaluations=None, pending_reports=None):
    pending = report.get("pending_submissions", [])
    paid = report.get("paid_submissions", [])

    # Index AI evaluations by submission ID
    ai_by_id = {}
    if ai_evaluations:
        for ev in ai_evaluations:
            if ev.get("ai_evaluation"):
                # Nested format: {"id": "...", "ai_evaluation": {...}}
                ai_by_id[ev["id"]] = ev["ai_evaluation"]
            elif ev.get("acceptance_probability") is not None:
                # Flat format: {"id": "...", "acceptance_probability": 0.65, ...}
                ai_by_id[ev["id"]] = ev

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

    # Add estimated resolution deadline per submission (based on program validation times)
    today = date.today()
    for s in scored:
        severity = s.get("severity", "Medium")
        platform = s.get("platform", "intigriti")
        if platform == "hackerone":
            validation_days = HACKERONE_DEFAULT_VALIDATION_DAYS.get(severity, 14)
        else:
            validation_days = INTIGRITI_DEFAULT_VALIDATION_DAYS.get(severity, 21)
        total_days = validation_days + TRIAGE_PICKUP_BUFFER_DAYS
        created = s.get("created_at", "")
        try:
            d_created = date.fromisoformat(created[:10]) if created else today
        except (ValueError, TypeError):
            d_created = today
        est = d_created + timedelta(days=total_days)
        s["est_resolve_date"] = est.isoformat()
        s["est_overdue"] = est < today

    total_ev = sum(s["expected_value_eur"] for s in scored)
    total_potential = sum(s["expected_bounty_eur"] for s in scored)

    # Confirmed earnings — convert each payout individually at its own date's rate
    confirmed_eur = 0
    payout_conversions = []
    for sub in paid:
        payouts = sub.get("payouts", [])
        if not payouts:
            continue
        sub_eur = 0
        sub_details = []
        for p in payouts:
            amount = p.get("amount", 0)
            cur = p.get("currency", sub.get("total_paid_currency", "EUR"))
            if amount <= 0:
                continue
            if cur == "EUR":
                eur_amount = amount
                rate_used = 1.0
                rate_date = "N/A"
            else:
                payout_date = p.get("paid_date") or date.today().isoformat()
                rate_used = fetch_ecb_rate(cur, payout_date)
                eur_amount = amount * rate_used
                rate_date = payout_date
            sub_eur += eur_amount
            sub_details.append({
                "amount": amount,
                "currency": cur,
                "type": p.get("type", "Bounty"),
                "eur_amount": round(eur_amount, 2),
                "exchange_rate": round(rate_used, 4),
                "rate_date": rate_date,
            })
        confirmed_eur += sub_eur
        payout_conversions.append({
            "id": sub.get("id"),
            "program": sub.get("program"),
            "original_amount": sub["total_paid"],
            "original_currency": sub.get("total_paid_currency", "EUR"),
            "eur_amount": round(sub_eur, 2),
            "exchange_rate_method": "per_payout",
            "payouts": sub_details,
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

    # Monthly breakdown
    monthly, triage_stats = build_monthly_breakdown(payout_conversions, scored, report)

    return {
        "historical_acceptance_rate": round(historical_rate, 2) if historical_rate else None,
        "confirmed_earnings_eur": round(confirmed_eur, 2),
        "payout_conversions": payout_conversions,
        "monthly_breakdown": monthly,
        "triage_stats": triage_stats,
        "pending_reports": pending_reports or {"pending": [], "programs": {}},
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
    print(f"BOUNTY FORECAST (EUR)")
    print(f"{'='*65}")
    if fc['historical_acceptance_rate']:
        print(f"Historical acceptance rate: {fc['historical_acceptance_rate']:.0%}")
    print(f"Confirmed earnings: \u20ac{fc['confirmed_earnings_eur']:,.2f}")
    print(f"Pending submissions: {fc['pending_count']}")

    if fc.get("payout_conversions"):
        print(f"\n{'─'*65}")
        print("PAYOUT CONVERSIONS (historical ECB rates):")
        for pc in fc["payout_conversions"]:
            print(f"  {pc['program']}: \u20ac{pc['eur_amount']:,.2f}")
            for p in pc.get("payouts", []):
                if p["currency"] == "EUR":
                    print(f"    \u2514 {p['type']}: \u20ac{p['eur_amount']:,.2f}")
                else:
                    print(f"    \u2514 {p['type']}: {p['currency']} {p['amount']:,.2f} "
                          f"\u00d7 {p['exchange_rate']:.4f} ({p['rate_date']}) = \u20ac{p['eur_amount']:,.2f}")

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
    parser = argparse.ArgumentParser(description="Forecast bounty earnings across platforms (EUR)")
    parser.add_argument("report", help="Path to report_latest.json from inbox_exporter")
    parser.add_argument("--eur-rates", help="JSON with currency->EUR rates", default=None)
    parser.add_argument("--ai-evaluations", help="Path to ai_evaluation.json from ai_triager.py")
    parser.add_argument("--pending-reports", help="Path to pending_reports.json from pending_reports_scanner.py")
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

    pending_reps = None
    if args.pending_reports:
        pending_reps = json.loads(Path(args.pending_reports).read_text())
        print(f"[+] Loaded {pending_reps.get('pending_count', 0)} pending local reports")

    fc = forecast(report, current_rates, ai_evaluations=ai_evals, pending_reports=pending_reps)
    print_forecast(fc)

    if args.output:
        Path(args.output).write_text(json.dumps(fc, indent=2))
        print(f"\n[+] Forecast saved to {args.output}")


if __name__ == "__main__":
    main()
