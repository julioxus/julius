"""Forecast engine — computes earnings projections from database.

Ports the logic from bounty_forecast.py but reads from PostgreSQL instead of JSON.
"""

from __future__ import annotations

from datetime import date, timedelta
from decimal import Decimal

from sqlalchemy import func, select

from bounty_intel.db import (
    AIEvaluation,
    EngagementSnapshot,
    Payout,
    Submission,
    get_session,
)
from bounty_intel.forecast.fx import fetch_ecb_rate, get_current_rates, to_eur

# Acceptance probability by disposition + severity
ACCEPTANCE_PROBS = {
    "triaged": {"Exceptional": 0.70, "Critical": 0.65, "High": 0.60, "Medium": 0.50, "Low": 0.40},
    "new": {"Exceptional": 0.50, "Critical": 0.45, "High": 0.35, "Medium": 0.25, "Low": 0.15},
    "needs_more_info": {"Exceptional": 0.40, "Critical": 0.35, "High": 0.25, "Medium": 0.15, "Low": 0.10},
    "accepted": {"Exceptional": 0.85, "Critical": 0.80, "High": 0.75, "Medium": 0.70, "Low": 0.60},
}

VDP_BONUS_PROB = 0.15

HACKERONE_VALIDATION_DAYS = {"Critical": 5, "High": 7, "Medium": 14, "Low": 21}
INTIGRITI_VALIDATION_DAYS = {"Exceptional": 4, "Critical": 4, "High": 10, "Medium": 21, "Low": 21}
TRIAGE_PICKUP_BUFFER = 3

H1_ESTIMATED_BOUNTY = {"Critical": 3000, "High": 1500, "Medium": 500, "Low": 150, "None": 0}

SEVERITY_BONUS_MAP = {"Exceptional": 2000, "Critical": 1500, "High": 1000, "Medium": 500, "Low": 200}


def _month_label(ym: str) -> str:
    y, m = ym.split("-")
    names = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    return f"{names[int(m) - 1]} {y}"


def _add_months(ym: str, n: int) -> str:
    y, m = int(ym[:4]), int(ym[5:7])
    m += n
    while m > 12:
        m -= 12
        y += 1
    return f"{y:04d}-{m:02d}"


def compute_forecast(today: date | None = None) -> dict:
    """Compute full forecast from DB data. Returns the same structure as bounty_forecast.py."""
    if today is None:
        today = date.today()
    current_ym = today.strftime("%Y-%m")

    session = get_session()

    # --- Load all submissions ---
    all_subs = session.scalars(select(Submission).order_by(Submission.created_at.desc())).all()

    paid_subs = [s for s in all_subs if s.disposition == "resolved" or _has_payouts(session, s.id)]
    pending_subs = [s for s in all_subs if s.disposition in ("new", "triaged", "needs_more_info", "accepted")]
    rejected_subs = [s for s in all_subs if s.disposition in ("duplicate", "informative", "not_applicable", "wont_fix", "out_of_scope")]

    total_closed = len(paid_subs) + len(rejected_subs)
    historical_rate = len(paid_subs) / total_closed if total_closed > 0 else None

    # --- Collect currencies for rate fetching ---
    currencies = {s.listed_currency or "EUR" for s in pending_subs}
    current_rates = get_current_rates(currencies)

    # --- Score pending submissions ---
    scored = []
    for sub in pending_subs:
        severity = sub.severity or "Medium"
        disposition = sub.disposition or "new"
        listed_bounty = float(sub.listed_bounty or 0)
        listed_currency = sub.listed_currency or "EUR"
        is_vdp = listed_bounty == 0
        platform = sub.platform or "intigriti"

        # Base probability
        base_prob = ACCEPTANCE_PROBS.get(disposition, {}).get(severity, 0.20)
        if is_vdp:
            base_prob *= VDP_BONUS_PROB

        if historical_rate is not None:
            base_prob = (base_prob + historical_rate) / 2

        # AI evaluation override
        ai_eval = session.scalar(select(AIEvaluation).where(AIEvaluation.submission_id == sub.id))
        prob_source = "heuristic"
        ai_data = {}

        if ai_eval and ai_eval.acceptance_probability is not None:
            raw_prob = float(ai_eval.acceptance_probability)
            if historical_rate is not None and total_closed > 0:
                history_weight = min(total_closed / 20, 0.5)
                prob = round(raw_prob * (1 - history_weight) + historical_rate * history_weight, 2)
            else:
                prob = raw_prob
            prob_source = "ai"
            ai_data = {
                "likely_outcome": ai_eval.likely_outcome,
                "severity_assessment": ai_eval.severity_assessment,
                "strengths": ai_eval.strengths or [],
                "weaknesses": ai_eval.weaknesses or [],
                "triager_reasoning": ai_eval.triager_reasoning or "",
                "suggested_improvements": ai_eval.suggested_improvements or [],
                "ai_confidence": float(ai_eval.confidence or 0),
            }
        else:
            prob = round(base_prob, 2)

        # Expected bounty
        if is_vdp:
            expected_bounty = SEVERITY_BONUS_MAP.get(severity, 300)
        else:
            expected_bounty = listed_bounty

        expected_eur = to_eur(expected_bounty, listed_currency, current_rates)
        ev = expected_eur * prob

        # Estimated resolution date
        if platform == "hackerone":
            val_days = HACKERONE_VALIDATION_DAYS.get(severity, 14)
        else:
            val_days = INTIGRITI_VALIDATION_DAYS.get(severity, 21)
        total_days = val_days + TRIAGE_PICKUP_BUFFER

        created = sub.created_at.date() if sub.created_at else today
        est_resolve = created + timedelta(days=total_days)
        if est_resolve < today:
            est_resolve = today

        # Get program name
        program_name = ""
        if sub.program:
            program_name = sub.program.company_name

        scored.append({
            "id": sub.platform_id,
            "db_id": sub.id,
            "program": program_name,
            "title": sub.title or "",
            "severity": severity,
            "platform": platform,
            "disposition": disposition,
            "listed_bounty": listed_bounty,
            "listed_currency": listed_currency,
            "acceptance_prob": prob,
            "prob_source": prob_source,
            "program_type": "vdp" if is_vdp else "bounty",
            "expected_bounty_eur": round(expected_eur, 2),
            "expected_value_eur": round(ev, 2),
            "est_resolve_date": est_resolve.isoformat(),
            "est_overdue": est_resolve < today,
            "created_at": sub.created_at.isoformat() if sub.created_at else "",
            **ai_data,
        })

    scored.sort(key=lambda x: x["expected_value_eur"], reverse=True)

    # --- Confirmed earnings ---
    confirmed_eur = 0.0
    payout_conversions = []

    for sub in paid_subs:
        payouts = session.scalars(select(Payout).where(Payout.submission_id == sub.id)).all()
        if not payouts:
            continue

        sub_eur = 0.0
        sub_details = []
        program_name = sub.program.company_name if sub.program else ""

        for p in payouts:
            amount = float(p.amount or 0)
            cur = p.currency or "EUR"
            if amount <= 0:
                continue
            if cur == "EUR":
                eur_amount = amount
                rate = 1.0
                rate_date = "N/A"
            else:
                pdate = p.paid_date.isoformat() if p.paid_date else today.isoformat()
                rate = fetch_ecb_rate(cur, pdate)
                eur_amount = amount * rate
                rate_date = pdate

            sub_eur += eur_amount
            sub_details.append({
                "amount": amount,
                "currency": cur,
                "type": p.payout_type or "Bounty",
                "eur_amount": round(eur_amount, 2),
                "exchange_rate": round(rate, 4),
                "rate_date": rate_date,
            })

        confirmed_eur += sub_eur
        payout_conversions.append({
            "id": sub.platform_id,
            "program": program_name,
            "eur_amount": round(sub_eur, 2),
            "payouts": sub_details,
        })

    # --- Scenarios ---
    total_ev = sum(s["expected_value_eur"] for s in scored)
    total_potential = sum(s["expected_bounty_eur"] for s in scored)
    pessimistic = sum(s["expected_value_eur"] for s in scored if s["disposition"] == "triaged")
    optimistic = sum(min(s["expected_bounty_eur"], s["expected_value_eur"] * 1.5) for s in scored)

    # --- Monthly breakdown ---
    months: dict[str, dict] = {}

    def _ensure_month(ym):
        if ym not in months:
            months[ym] = {"confirmed_eur": 0, "pending_ev_eur": 0, "submitted": 0, "paid": 0, "rejected": 0, "pending": 0, "submissions": []}

    for sub in all_subs:
        ym = sub.created_at.strftime("%Y-%m") if sub.created_at else current_ym
        _ensure_month(ym)
        months[ym]["submitted"] += 1
        if sub in paid_subs:
            months[ym]["paid"] += 1
        elif sub in rejected_subs:
            months[ym]["rejected"] += 1
        elif sub in pending_subs:
            months[ym]["pending"] += 1

    for pc in payout_conversions:
        for p in pc["payouts"]:
            rd = p.get("rate_date", "")
            ym = rd[:7] if rd and rd != "N/A" else current_ym
            _ensure_month(ym)
            months[ym]["confirmed_eur"] += p["eur_amount"]

    for s in scored:
        if s["expected_value_eur"] <= 0:
            continue
        target_ym = s["est_resolve_date"][:7]
        _ensure_month(target_ym)
        months[target_ym]["pending_ev_eur"] += s["expected_value_eur"]

    # Fill gaps
    all_yms = sorted(months.keys())
    if all_yms:
        ym = min(all_yms[0], current_ym)
        last_ym = max(all_yms[-1], current_ym)
        monthly_result = []
        while ym <= last_ym:
            entry = months.get(ym, {"confirmed_eur": 0, "pending_ev_eur": 0, "submitted": 0, "paid": 0, "rejected": 0, "pending": 0})
            mtype = "past" if ym < current_ym else ("current" if ym == current_ym else "future")
            resolved = entry["paid"] + entry["rejected"]
            monthly_result.append({
                "month": ym,
                "label": _month_label(ym),
                "type": mtype,
                "confirmed_eur": round(entry["confirmed_eur"], 2),
                "pending_ev_eur": round(entry["pending_ev_eur"], 2),
                "total_eur": round(entry["confirmed_eur"] + entry["pending_ev_eur"], 2),
                "submitted": entry["submitted"],
                "paid": entry["paid"],
                "rejected": entry["rejected"],
                "pending": entry["pending"],
                "acceptance_rate": round(entry["paid"] / resolved, 2) if resolved > 0 else None,
            })
            ym = _add_months(ym, 1)
    else:
        monthly_result = []

    # --- Save snapshot ---
    from bounty_intel.db import EngagementSnapshot
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    snapshot_stmt = pg_insert(EngagementSnapshot).values(
        snapshot_date=today,
        confirmed_earnings_eur=Decimal(str(round(confirmed_eur, 2))),
        expected_earnings_eur=Decimal(str(round(confirmed_eur + total_ev, 2))),
        acceptance_rate=Decimal(str(round(historical_rate, 2))) if historical_rate else Decimal("0"),
    )
    snapshot_stmt = snapshot_stmt.on_conflict_do_update(
        index_elements=["snapshot_date"],
        set_={
            "confirmed_earnings_eur": snapshot_stmt.excluded.confirmed_earnings_eur,
            "expected_earnings_eur": snapshot_stmt.excluded.expected_earnings_eur,
            "acceptance_rate": snapshot_stmt.excluded.acceptance_rate,
        },
    )
    session.execute(snapshot_stmt)
    session.commit()
    session.close()

    return {
        "historical_acceptance_rate": round(historical_rate, 2) if historical_rate else None,
        "confirmed_earnings_eur": round(confirmed_eur, 2),
        "payout_conversions": payout_conversions,
        "monthly_breakdown": monthly_result,
        "pending_count": len(scored),
        "scenarios": {
            "pessimistic": {
                "description": "Only triaged submissions pay",
                "additional_eur": round(pessimistic, 2),
                "total_eur": round(confirmed_eur + pessimistic, 2),
            },
            "expected": {
                "description": "Probability-weighted expected value",
                "additional_eur": round(total_ev, 2),
                "total_eur": round(confirmed_eur + total_ev, 2),
            },
            "optimistic": {
                "description": "Submissions outperform by 50%",
                "additional_eur": round(optimistic, 2),
                "total_eur": round(confirmed_eur + optimistic, 2),
            },
            "maximum": {
                "description": "Every pending submission pays",
                "additional_eur": round(total_potential, 2),
                "total_eur": round(confirmed_eur + total_potential, 2),
            },
        },
        "ranked_submissions": scored,
    }


def _has_payouts(session, submission_id: int) -> bool:
    return session.scalar(select(func.count(Payout.id)).where(Payout.submission_id == submission_id)) > 0


def print_forecast(fc: dict) -> None:
    """Print forecast summary to terminal."""
    print(f"\n{'=' * 65}")
    print("BOUNTY FORECAST (EUR)")
    print(f"{'=' * 65}")
    if fc["historical_acceptance_rate"]:
        print(f"Historical acceptance rate: {fc['historical_acceptance_rate']:.0%}")
    print(f"Confirmed earnings: \u20ac{fc['confirmed_earnings_eur']:,.2f}")
    print(f"Pending submissions: {fc['pending_count']}")

    print(f"\n{'─' * 65}")
    print(f"{'SCENARIO':<25} {'ADDITIONAL':>12} {'TOTAL':>12}")
    print(f"{'─' * 65}")
    for name, sc in fc["scenarios"].items():
        print(f"{name.upper():<25} \u20ac{sc['additional_eur']:>10,.0f}  \u20ac{sc['total_eur']:>10,.0f}")

    print(f"\n{'─' * 65}")
    print(f"{'RANK':<4} {'PROB':>5} {'EV(\u20ac)':>8} {'POT(\u20ac)':>8} {'PROGRAM':<15} {'TITLE':<30}")
    print(f"{'─' * 65}")
    for i, s in enumerate(fc["ranked_submissions"][:15], 1):
        print(
            f"{i:<4} {s['acceptance_prob']:>4.0%} {s['expected_value_eur']:>8,.0f} "
            f"{s['expected_bounty_eur']:>8,.0f} "
            f"{s['program'][:15]:<15} "
            f"{s['title'][:30]}"
        )
