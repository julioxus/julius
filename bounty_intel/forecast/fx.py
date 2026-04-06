"""ECB exchange rate fetching via Frankfurter API with in-memory cache."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import date

FALLBACK_EUR_RATES = {"EUR": 1.0, "USD": 0.93, "GBP": 1.18}

_rate_cache: dict[tuple[str, str], float] = {}


def fetch_ecb_rate(currency: str, on_date: str) -> float:
    """Fetch how many EUR 1 unit of `currency` is worth on `on_date` (YYYY-MM-DD)."""
    if currency == "EUR":
        return 1.0

    cache_key = (on_date, currency)
    if cache_key in _rate_cache:
        return _rate_cache[cache_key]

    try:
        url = f"https://api.frankfurter.app/{on_date}?from={currency}&to=EUR&amount=1"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "BountyIntel/1.0")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            rate = data.get("rates", {}).get("EUR", FALLBACK_EUR_RATES.get(currency, 1.0))
            _rate_cache[cache_key] = rate
            return rate
    except (urllib.error.URLError, json.JSONDecodeError, KeyError, TimeoutError, OSError):
        fallback = FALLBACK_EUR_RATES.get(currency, 1.0)
        _rate_cache[cache_key] = fallback
        return fallback


def get_current_rates(currencies: set[str]) -> dict[str, float]:
    """Fetch today's rates for a set of currencies."""
    today = date.today().isoformat()
    rates = {"EUR": 1.0}
    for cur in currencies:
        if cur != "EUR":
            rates[cur] = fetch_ecb_rate(cur, today)
    return rates


def to_eur(amount: float, currency: str, rates: dict[str, float]) -> float:
    return amount * rates.get(currency, 1.0)
