#!/usr/bin/env python3
"""Passive OSINT reconnaissance for prospect skill.

All checks are strictly passive — no port scanning, no fuzzing,
no authenticated access. Only public data sources.
"""

import json
import subprocess
import sys
import re
import os
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

HEADER_IMPACT = {
    "strict-transport-security": "Sin HSTS, un atacante puede interceptar la primera conexión HTTP y redirigir al usuario a una web falsa (ataque de downgrade)",
    "content-security-policy": "Sin CSP, la web es más vulnerable a ataques de inyección de código (XSS) que pueden robar datos de usuarios",
    "x-frame-options": "Sin esta cabecera, su web puede ser embebida en páginas maliciosas para engañar a los usuarios (clickjacking)",
    "x-content-type-options": "Sin esta cabecera, el navegador puede interpretar archivos de forma incorrecta, facilitando ataques",
    "referrer-policy": "Sin esta cabecera, se filtran URLs internas cuando los usuarios navegan a otros sitios",
    "permissions-policy": "Sin esta cabecera, cualquier script embebido puede acceder a la cámara, micrófono o geolocalización del usuario",
}


def run_cmd(cmd, timeout=30):
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except Exception as e:
        return f"[ERROR: {e}]"


def check_headers(domain):
    """Check security headers via HTTP GET."""
    results = {"raw": "", "headers": {}, "missing": [], "present": [], "score": 0}

    for scheme in ["https", "http"]:
        raw = run_cmd(f'curl -sI -L -m 10 {scheme}://{domain}')
        if raw and "[TIMEOUT]" not in raw and "[ERROR" not in raw:
            results["raw"] += f"--- {scheme.upper()} ---\n{raw}\n"
            break
    else:
        results["raw"] = "[Could not connect]"
        return results

    raw_lower = raw.lower()
    for header in SECURITY_HEADERS:
        if header in raw_lower:
            value = ""
            for line in raw.split("\n"):
                if line.lower().startswith(header):
                    value = line.split(":", 1)[1].strip() if ":" in line else ""
                    break
            results["headers"][header] = value
            results["present"].append(header)
        else:
            results["missing"].append(header)

    raw_score = round(len(results["present"]) / len(SECURITY_HEADERS) * 10)
    results["score"] = max(raw_score, 5)
    return results


def check_tls(domain):
    """Check TLS configuration."""
    results = {"raw": "", "version": "", "issuer": "", "expiry": "", "legacy_tls": [], "score": 10}

    raw = run_cmd(
        f'echo | openssl s_client -connect {domain}:443 -servername {domain} 2>/dev/null | openssl x509 -noout -dates -issuer -subject 2>/dev/null'
    )
    results["raw"] = raw

    for line in raw.split("\n"):
        if "notAfter" in line:
            results["expiry"] = line.split("=", 1)[1].strip() if "=" in line else ""
        if "issuer" in line:
            results["issuer"] = line.split("=", 1)[1].strip() if "=" in line else ""

    version_raw = run_cmd(
        f'echo | openssl s_client -connect {domain}:443 -servername {domain} 2>/dev/null | grep "Protocol"'
    )
    results["version"] = version_raw.strip()

    for legacy in ["tls1", "tls1_1"]:
        flag = f"-{legacy}"
        check = run_cmd(
            f'echo | openssl s_client {flag} -connect {domain}:443 -servername {domain} 2>&1 | head -5'
        )
        if "CONNECTED" in check and "error" not in check.lower():
            results["legacy_tls"].append(legacy.replace("tls", "TLS ").replace("_", "."))
            results["score"] -= 3

    if results["expiry"]:
        try:
            exp_date = datetime.strptime(results["expiry"], "%b %d %H:%M:%S %Y %Z")
            days_left = (exp_date - datetime.utcnow()).days
            if days_left < 0:
                results["score"] = max(0, results["score"] - 5)
                results["cert_status"] = f"CADUCADO hace {abs(days_left)} días"
            elif days_left < 30:
                results["score"] = max(0, results["score"] - 2)
                results["cert_status"] = f"Caduca en {days_left} días"
            else:
                results["cert_status"] = f"Válido ({days_left} días restantes)"
        except ValueError:
            results["cert_status"] = "No se pudo determinar"

    return results


def check_dns(domain):
    """Check DNS configuration: SPF, DMARC, MX."""
    results = {"raw": "", "spf": "", "dmarc": "", "mx": [], "dnssec": False, "score": 10}

    spf_raw = run_cmd(f'dig +short {domain} TXT')
    results["raw"] += f"--- TXT ---\n{spf_raw}\n"
    spf_match = [l for l in spf_raw.split("\n") if "v=spf1" in l]
    if spf_match:
        results["spf"] = spf_match[0].strip().strip('"')
    else:
        results["score"] -= 3
        results["spf"] = "NO CONFIGURADO"

    dmarc_raw = run_cmd(f'dig +short _dmarc.{domain} TXT')
    results["raw"] += f"--- DMARC ---\n{dmarc_raw}\n"
    if dmarc_raw.strip():
        results["dmarc"] = dmarc_raw.strip().strip('"')
        if "p=none" in dmarc_raw:
            results["score"] -= 1
    else:
        results["score"] -= 4
        results["dmarc"] = "NO CONFIGURADO"

    mx_raw = run_cmd(f'dig +short {domain} MX')
    results["raw"] += f"--- MX ---\n{mx_raw}\n"
    results["mx"] = [l.strip() for l in mx_raw.strip().split("\n") if l.strip()]

    dnssec_raw = run_cmd(f'dig +dnssec +short {domain} A')
    if "RRSIG" in dnssec_raw:
        results["dnssec"] = True
    else:
        results["score"] -= 1

    return results


def check_subdomains(domain):
    """Enumerate subdomains via Certificate Transparency (crt.sh)."""
    results = {"raw": "", "subdomains": [], "notable": [], "count": 0, "score": 10}

    raw = run_cmd(
        f'curl -s "https://crt.sh/?q=%25.{domain}&output=json" -m 15',
        timeout=20,
    )
    results["raw"] = raw[:5000]

    try:
        entries = json.loads(raw)
        names = set()
        for entry in entries:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower()
                if name and not name.startswith("*"):
                    names.add(name)
        results["subdomains"] = sorted(names)
        results["count"] = len(names)

        notable_keywords = ["admin", "staging", "dev", "test", "api", "vpn", "mail",
                          "ftp", "db", "database", "internal", "intranet", "portal",
                          "jenkins", "gitlab", "jira", "grafana", "kibana"]
        for sub in names:
            prefix = sub.replace(f".{domain}", "")
            if any(kw in prefix for kw in notable_keywords):
                results["notable"].append(sub)

        if len(results["notable"]) > 5:
            results["score"] -= 3
        elif len(results["notable"]) > 2:
            results["score"] -= 1

    except (json.JSONDecodeError, TypeError):
        results["subdomains"] = []
        results["count"] = 0

    return results


def check_shodan(domain):
    """Check Shodan InternetDB for exposed services (public, no API key needed)."""
    results = {"raw": "", "ports": [], "hostnames": [], "vulns": [], "score": 10}

    ip_raw = run_cmd(f'dig +short {domain} A | head -1')
    ip = ip_raw.strip()
    if not ip or not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
        results["raw"] = f"Could not resolve IP for {domain}"
        return results

    raw = run_cmd(f'curl -s "https://internetdb.shodan.io/{ip}" -m 10')
    results["raw"] = raw

    try:
        data = json.loads(raw)
        results["ports"] = data.get("ports", [])
        results["hostnames"] = data.get("hostnames", [])
        results["vulns"] = data.get("vulns", [])

        unusual_ports = [p for p in results["ports"] if p not in [80, 443, 8080, 8443]]
        if len(unusual_ports) > 3:
            results["score"] -= 4
        elif unusual_ports:
            results["score"] -= 2

        if results["vulns"]:
            results["score"] -= min(len(results["vulns"]), 5)

    except (json.JSONDecodeError, TypeError):
        pass

    return results


SPANISH_FIRST_NAMES = {
    'Abel', 'Adrián', 'Adrian', 'Agustín', 'Agustin', 'Alberto', 'Alejandro',
    'Alfonso', 'Alfredo', 'Alicia', 'Almudena', 'Álvaro', 'Alvaro', 'Amalia',
    'Ana', 'Andrés', 'Andres', 'Ángel', 'Angel', 'Ángela', 'Angela', 'Antonio',
    'Araceli', 'Ariadna', 'Arturo', 'Aurora', 'Beatriz', 'Belén', 'Belen',
    'Blanca', 'Boris', 'Carlos', 'Carmen', 'Carolina', 'Catalina', 'Cecilia',
    'Clara', 'Claudia', 'Concepción', 'Concha', 'Cristian', 'Cristina',
    'Daniel', 'Daniela', 'David', 'Diana', 'Diego', 'Dolores', 'Eduardo',
    'Elena', 'Elisa', 'Emilio', 'Enrique', 'Ernesto', 'Esther', 'Eugenia',
    'Eva', 'Federico', 'Felipe', 'Fernando', 'Francisca', 'Francisco',
    'Gabriel', 'Gemma', 'Gloria', 'Gonzalo', 'Guadalupe', 'Guillermo',
    'Gustavo', 'Héctor', 'Hector', 'Hugo', 'Ignacio', 'Inés', 'Ines',
    'Inmaculada', 'Irene', 'Isabel', 'Iván', 'Ivan', 'Jacobo', 'Jaime',
    'Javier', 'Jesús', 'Jesus', 'Joaquín', 'Joaquin', 'Jorge', 'José',
    'Jose', 'Josefa', 'Juan', 'Juana', 'Julia', 'Julián', 'Julian', 'Julio',
    'Laura', 'Leonor', 'Lidia', 'Lorena', 'Lorenzo', 'Lourdes', 'Lucía',
    'Lucia', 'Luis', 'Luisa', 'Manuel', 'Manuela', 'Marcos', 'Margarita',
    'María', 'Maria', 'Mariano', 'Marina', 'Mario', 'Marta', 'Martín',
    'Martin', 'Mateo', 'Mercedes', 'Miguel', 'Miriam', 'Mónica', 'Monica',
    'Montserrat', 'Natalia', 'Nerea', 'Nicolás', 'Nicolas', 'Nuria',
    'Óscar', 'Oscar', 'Pablo', 'Patricia', 'Paula', 'Pedro', 'Pilar',
    'Rafael', 'Ramón', 'Ramon', 'Raquel', 'Raúl', 'Raul', 'Ricardo',
    'Roberto', 'Rocío', 'Rocio', 'Rodrigo', 'Rosa', 'Rosario', 'Rubén',
    'Ruben', 'Salvador', 'Samuel', 'Sandra', 'Santiago', 'Sara', 'Sergio',
    'Silvia', 'Sofía', 'Sofia', 'Soledad', 'Sonia', 'Susana', 'Teresa',
    'Tomás', 'Tomas', 'Valentín', 'Valentin', 'Verónica', 'Veronica',
    'Vicente', 'Víctor', 'Victor', 'Victoria',
}


def _extract_people_names(html):
    """Extract person names from Spanish web pages using a first-name whitelist."""
    import html as html_mod
    text = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<[^>]+>', ' ', text)
    text = html_mod.unescape(text)

    junk_surnames = {
        'Trustindex', 'Google', 'Facebook', 'Instagram', 'Orange', 'Movistar',
        'Vodafone', 'Reviews', 'Rating', 'Stars', 'Cookie', 'Analytics',
        'Services', 'Temporarily', 'Unavailable', 'Loading', 'Error',
    }
    pattern = r'([A-ZÁÉÍÓÚÑ][a-záéíóúñ]{2,})\s+([A-ZÁÉÍÓÚÑ][a-záéíóúñ]{2,})(?:\s+([A-ZÁÉÍÓÚÑ][a-záéíóúñ]{2,}))?'
    names = []
    for m in re.finditer(pattern, text):
        first = m.group(1)
        if first not in SPANISH_FIRST_NAMES:
            continue
        last = m.group(2)
        if len(last) < 3 or last in junk_surnames:
            continue
        name = f"{first} {last}"
        if m.group(3) and len(m.group(3)) >= 3 and m.group(3) not in junk_surnames:
            name += f" {m.group(3)}"
        if name not in names:
            names.append(name)
    return names


def _name_to_email_variants(name, domain):
    """Generate email candidates from a Spanish name: nombre.apellido@, napellido@, etc."""
    import unicodedata
    def strip_accents(s):
        return ''.join(c for c in unicodedata.normalize('NFD', s) if unicodedata.category(c) != 'Mn')

    parts = name.lower().split()
    if len(parts) < 2:
        return []
    first = strip_accents(parts[0])
    last = strip_accents(parts[1])
    variants = [
        f"{first}.{last}@{domain}",
        f"{first[0]}{last}@{domain}",
        f"{first}{last[0]}@{domain}",
        f"{first}@{domain}",
    ]
    if len(parts) >= 3:
        last2 = strip_accents(parts[2])
        variants.append(f"{first}.{last}.{last2}@{domain}")
    return variants


def _search_engine_emails(domain):
    """Harvest emails via Google and Bing search scraping."""
    emails = {}
    ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"

    for engine, url in [
        ("google", f'https://www.google.com/search?q=%22%40{domain}%22&num=50'),
        ("google2", f'https://www.google.com/search?q=site%3A{domain}+email+OR+contacto+OR+contact&num=30'),
        ("bing", f'https://www.bing.com/search?q=%22%40{domain}%22&count=50'),
    ]:
        raw = run_cmd(f'curl -sL -m 10 -H "User-Agent: {ua}" "{url}" 2>/dev/null')
        if raw:
            from urllib.parse import unquote
            raw = unquote(raw)
            found = set(re.findall(r'[a-zA-Z0-9._%+\-]+@' + re.escape(domain), raw))
            for e in found:
                e = e.lower().strip('.')
                if len(e.split('@')[0]) >= 2:
                    emails.setdefault(e, []).append(engine)
    return emails


def _crtsh_emails(domain):
    """Extract emails from Certificate Transparency logs via crt.sh."""
    emails = {}
    raw = run_cmd(f'curl -s -m 15 "https://crt.sh/?q=%25{domain}&output=json"', timeout=20)
    if not raw or "[TIMEOUT]" in raw:
        return emails
    try:
        data = json.loads(raw)
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                if "@" in name and domain in name:
                    emails.setdefault(name.strip().lower(), []).append("crt.sh")
    except (json.JSONDecodeError, TypeError):
        pass
    return emails


def harvest_emails(domain):
    """Harvest emails from multiple OSINT sources: search engines, crt.sh, website, people names."""
    results = {"raw": "", "emails": [], "sources": {}, "people": [], "score": 10}
    found = set()
    all_people = []
    page_cache = {}

    search_emails = _search_engine_emails(domain)
    for e, sources in search_emails.items():
        found.add(e)
        results["sources"].setdefault(e, []).extend(sources)
    results["raw"] += f"--- Search engines: {len(search_emails)} emails ---\n"
    for e, s in search_emails.items():
        results["raw"] += f"  {e} ({', '.join(s)})\n"

    crt_emails = _crtsh_emails(domain)
    for e, sources in crt_emails.items():
        found.add(e)
        results["sources"].setdefault(e, []).extend(sources)
    results["raw"] += f"--- crt.sh: {len(crt_emails)} emails ---\n"

    pages = ["", "/contacto", "/contact", "/about", "/sobre-nosotros",
             "/aviso-legal", "/legal", "/politica-privacidad", "/equipo", "/team",
             "/quienes-somos", "/nuestro-equipo", "/profesionales", "/staff"]
    for path in pages:
        raw = run_cmd(f'curl -sL -m 8 https://www.{domain}{path} 2>/dev/null')
        if not raw or "[TIMEOUT]" in raw or len(raw) < 200:
            raw = run_cmd(f'curl -sL -m 8 https://{domain}{path} 2>/dev/null')
        if not raw or "[TIMEOUT]" in raw:
            continue
        page_cache[path] = raw
        emails_in_page = set(re.findall(
            r'[a-zA-Z0-9._%+\-]+@' + re.escape(domain), raw
        ))
        for e in emails_in_page:
            e = e.lower()
            found.add(e)
            results["sources"].setdefault(e, []).append(f"website:{path or '/'}")
        results["raw"] += f"--- {path or '/'} ---\n{','.join(emails_in_page) or 'none'}\n"

    people_pages = ["/equipo", "/team", "/quienes-somos", "/nuestro-equipo",
                    "/profesionales", "/staff", "/about", "/sobre-nosotros", ""]
    for path in people_pages:
        html = page_cache.get(path, "")
        if html:
            names = _extract_people_names(html)
            for n in names:
                if n not in all_people:
                    all_people.append(n)

    results["raw"] += f"\n--- People found: {len(all_people)} ---\n"
    for person in all_people[:15]:
        results["raw"] += f"  {person}\n"
        variants = _name_to_email_variants(person, domain)
        for v in variants:
            if v not in found:
                found.add(v)
                results["sources"].setdefault(v, []).append(f"person:{person}")

    results["people"] = all_people[:15]

    common_prefixes = ["info", "contacto", "admin", "administracion",
                       "legal", "recepcion", "oficina", "hola", "contact"]
    for prefix in common_prefixes:
        candidate = f"{prefix}@{domain}"
        if candidate not in found:
            results["sources"].setdefault(candidate, []).append("common-pattern")
            found.add(candidate)

    results["emails"] = sorted(found)
    osint_count = len([e for e, s in results["sources"].items()
                       if any(x in str(s) for x in ["google", "bing", "crt.sh"])])
    website_count = len([e for e, s in results["sources"].items() if any("website" in x for x in s)])
    people_count = len([e for e, s in results["sources"].items() if any("person:" in x for x in s)])
    results["raw"] += f"\n--- Total: {len(found)} emails ({osint_count} OSINT, {website_count} website, {people_count} people, {len(common_prefixes)} patterns) ---\n"
    return results


def _check_xposedornot(email):
    """Query XposedOrNot breach-analytics API (free, no auth)."""
    raw = run_cmd(
        f'curl -s -m 15 '
        f'"https://api.xposedornot.com/v1/breach-analytics?email={email}"',
        timeout=20
    )
    if not raw or "[TIMEOUT]" in raw or "[ERROR" in raw:
        return None, raw or ""
    try:
        data = json.loads(raw)
        exposed = data.get("ExposedBreaches") or {}
        breaches_detail = exposed.get("breaches_details") or []
        if not breaches_detail:
            return None, raw
        breach_names = [b.get("breach", "?") for b in breaches_detail]
        return {
            "email": email,
            "breaches": breach_names,
            "count": len(breach_names),
            "risk_score": data.get("BreachMetrics", {}).get("risk_score", 0),
        }, raw
    except (json.JSONDecodeError, TypeError, KeyError):
        return None, raw


def _check_leakcheck(email):
    """Query LeakCheck public API (free, rate-limited)."""
    raw = run_cmd(
        f'curl -s -m 15 '
        f'"https://leakcheck.io/api/public?check={email}"',
        timeout=20
    )
    if not raw or "[TIMEOUT]" in raw or "[ERROR" in raw:
        return None, raw or ""
    try:
        data = json.loads(raw)
        if not data.get("found"):
            return None, raw
        sources = data.get("sources", [])
        breach_names = [s.get("name", "?") for s in sources if s.get("name")]
        return {
            "email": email,
            "breaches": breach_names,
            "count": data.get("found", 0),
            "fields": data.get("fields", []),
        }, raw
    except (json.JSONDecodeError, TypeError, KeyError):
        return None, raw


def check_breaches(domain, emails):
    """Check emails against XposedOrNot (primary) + LeakCheck (secondary).

    Uses HIBP API v3 if HIBP_API_KEY is set (paid, most comprehensive).
    Otherwise uses free APIs: XposedOrNot for detailed analytics,
    LeakCheck for additional coverage.
    """
    import time

    results = {
        "raw": "", "breached_emails": [], "breach_count": 0,
        "breaches": [], "score": 10, "api_used": "none"
    }
    seen_emails = set()

    hibp_key = os.environ.get("HIBP_API_KEY", "")

    if hibp_key:
        results["api_used"] = "hibp-v3"
        for email in emails:
            raw = run_cmd(
                f'curl -s -m 10 -H "hibp-api-key: {hibp_key}" '
                f'-H "user-agent: julius-prospect-recon" '
                f'"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=true"'
            )
            results["raw"] += f"--- hibp:{email} ---\n{raw}\n"
            if raw and "[TIMEOUT]" not in raw and "404" not in raw:
                try:
                    breaches = json.loads(raw)
                    if isinstance(breaches, list) and breaches:
                        breach_names = [b.get("Name", "?") for b in breaches]
                        results["breached_emails"].append({
                            "email": email, "breaches": breach_names,
                            "count": len(breaches)
                        })
                        seen_emails.add(email)
                        results["breach_count"] += len(breaches)
                        for bn in breach_names:
                            if bn not in results["breaches"]:
                                results["breaches"].append(bn)
                except (json.JSONDecodeError, TypeError):
                    pass
            time.sleep(1.6)
    else:
        results["api_used"] = "xposedornot+leakcheck"

        for email in emails:
            hit, raw = _check_xposedornot(email)
            results["raw"] += f"--- xon:{email} ---\n{raw[:500]}\n"
            if hit:
                results["breached_emails"].append(hit)
                seen_emails.add(email)
                results["breach_count"] += hit["count"]
                for bn in hit["breaches"]:
                    if bn not in results["breaches"]:
                        results["breaches"].append(bn)
            time.sleep(0.5)

        for email in emails:
            if email in seen_emails:
                continue
            hit, raw = _check_leakcheck(email)
            results["raw"] += f"--- lc:{email} ---\n{raw[:500]}\n"
            if hit:
                results["breached_emails"].append(hit)
                seen_emails.add(email)
                results["breach_count"] += hit["count"]
                for bn in hit["breaches"]:
                    if bn not in results["breaches"]:
                        results["breaches"].append(bn)
            time.sleep(1.0)

    breached_count = len(results["breached_emails"])
    if breached_count == 0:
        results["score"] = 10
    elif breached_count <= 2:
        results["score"] = 7
    elif breached_count <= 5:
        results["score"] = 5
    elif breached_count <= 10:
        results["score"] = 3
    else:
        results["score"] = 1

    return results


PHP_EOL_VERSIONS = {
    "5.": "2018", "7.0": "2019-01", "7.1": "2019-12", "7.2": "2020-11",
    "7.3": "2021-12", "7.4": "2022-11", "8.0": "2023-11", "8.1": "2025-12",
}


def check_tech(domain):
    """Detect technologies from HTTP response and headers."""
    results = {
        "cms": "", "frameworks": [], "raw": "",
        "server": "", "powered_by": "", "eol_software": [],
        "version_disclosure": [], "score": 10,
    }

    raw = run_cmd(f'curl -sL -m 10 https://{domain} | head -200')
    results["raw"] = raw[:3000]

    hdr_raw = run_cmd(f'curl -sI -L -m 10 https://{domain}')
    results["raw"] += f"\n--- Headers ---\n{hdr_raw}"
    for line in hdr_raw.split("\n"):
        ll = line.lower()
        if ll.startswith("server:"):
            results["server"] = line.split(":", 1)[1].strip()
        if ll.startswith("x-powered-by:"):
            val = line.split(":", 1)[1].strip()
            results["powered_by"] += (", " + val) if results["powered_by"] else val

    if results["server"]:
        results["version_disclosure"].append(f"Server: {results['server']}")
    if results["powered_by"]:
        results["version_disclosure"].append(f"X-Powered-By: {results['powered_by']}")
        results["score"] -= 2

    for pw in results["powered_by"].split(","):
        pw = pw.strip()
        php_match = re.search(r'PHP/(\d+\.\d+)', pw, re.I)
        if php_match:
            php_ver = php_match.group(1)
            for eol_prefix, eol_date in PHP_EOL_VERSIONS.items():
                if php_ver.startswith(eol_prefix):
                    results["eol_software"].append({
                        "name": f"PHP {php_match.group(0).split('/')[1]}",
                        "eol_date": eol_date,
                    })
                    results["score"] -= 5
                    break

    generator_match = re.search(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)', raw, re.I)
    if generator_match:
        results["cms"] = generator_match.group(1)

    if "wp-content" in raw or "wp-includes" in raw:
        results["cms"] = results["cms"] or "WordPress"
    elif "Joomla" in raw:
        results["cms"] = results["cms"] or "Joomla"
    elif "Drupal" in raw:
        results["cms"] = results["cms"] or "Drupal"
    elif "Shopify" in raw:
        results["cms"] = results["cms"] or "Shopify"

    results["score"] = max(0, results["score"])
    return results


def check_compliance(domain):
    """Check GDPR/LSSI-CE compliance signals from public pages."""
    results = {
        "raw": "", "score": 10, "checks": {},
        "cookie_banner": False, "privacy_policy": False,
        "legal_notice": False, "security_txt": False, "robots_txt": False,
    }

    home = run_cmd(f'curl -sL -m 10 https://{domain}')
    results["raw"] += f"--- homepage ({len(home)} bytes) ---\n"

    cookie_keywords = ["cookie", "galleta", "consentimiento", "consent", "cookiebot",
                       "cookie-banner", "cookie-notice", "gdpr", "rgpd", "onetrust",
                       "cookie-law", "tarteaucitron", "klaro", "cc-window"]
    home_lower = home.lower()
    results["cookie_banner"] = any(kw in home_lower for kw in cookie_keywords)
    results["checks"]["cookie_banner"] = "Detectado" if results["cookie_banner"] else "No detectado"
    if not results["cookie_banner"]:
        results["score"] -= 3

    privacy_paths = ["/politica-privacidad", "/privacy-policy", "/privacidad",
                     "/politica-de-privacidad", "/privacy"]
    pp_found = False
    for path in privacy_paths:
        r = run_cmd(f'curl -sI -L -m 5 https://{domain}{path} 2>/dev/null')
        if "200" in r.split("\n")[0] if r else "":
            pp_found = True
            results["raw"] += f"Privacy policy found at {path}\n"
            break
    if not pp_found:
        pp_links = re.findall(r'href="([^"]*(?:privac|privacy)[^"]*)"', home, re.I)
        if pp_links:
            pp_found = True
            results["raw"] += f"Privacy link in page: {pp_links[0]}\n"
    results["privacy_policy"] = pp_found
    results["checks"]["privacy_policy"] = "Presente" if pp_found else "No encontrada"
    if not pp_found:
        results["score"] -= 3

    legal_paths = ["/aviso-legal", "/legal", "/aviso-legal-y-condiciones",
                   "/terminos", "/terms", "/condiciones-de-uso"]
    legal_found = False
    for path in legal_paths:
        r = run_cmd(f'curl -sI -L -m 5 https://{domain}{path} 2>/dev/null')
        if "200" in r.split("\n")[0] if r else "":
            legal_found = True
            results["raw"] += f"Legal notice found at {path}\n"
            break
    if not legal_found:
        legal_links = re.findall(r'href="([^"]*(?:legal|aviso|terms|condiciones)[^"]*)"', home, re.I)
        if legal_links:
            legal_found = True
            results["raw"] += f"Legal link in page: {legal_links[0]}\n"
    results["legal_notice"] = legal_found
    results["checks"]["legal_notice"] = "Presente" if legal_found else "No encontrado"
    if not legal_found:
        results["score"] -= 2

    sec_txt = run_cmd(f'curl -sI -m 5 https://{domain}/.well-known/security.txt 2>/dev/null')
    sec_found = "200" in sec_txt.split("\n")[0] if sec_txt else False
    if not sec_found:
        sec_txt = run_cmd(f'curl -sI -m 5 https://{domain}/security.txt 2>/dev/null')
        sec_found = "200" in sec_txt.split("\n")[0] if sec_txt else False
    results["security_txt"] = sec_found
    results["checks"]["security_txt"] = "Presente" if sec_found else "No encontrado"
    results["raw"] += f"security.txt: {'found' if sec_found else 'not found'}\n"
    if not sec_found:
        results["score"] -= 1

    robots = run_cmd(f'curl -s -m 5 https://{domain}/robots.txt 2>/dev/null')
    robots_found = bool(robots and "user-agent" in robots.lower())
    results["robots_txt"] = robots_found
    results["checks"]["robots_txt"] = "Presente" if robots_found else "No encontrado"
    results["raw"] += f"robots.txt: {'found' if robots_found else 'not found'}\n"

    results["score"] = max(results["score"], 0)
    return results


def run_recon(domain, output_dir, company="", sector=""):
    """Run all passive recon checks in parallel."""
    output_path = Path(output_dir)
    evidence_dir = output_path / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (output_path / "scoring").mkdir(exist_ok=True)

    results = {}
    checks = {
        "headers": lambda: check_headers(domain),
        "tls": lambda: check_tls(domain),
        "dns": lambda: check_dns(domain),
        "subdomains": lambda: check_subdomains(domain),
        "shodan": lambda: check_shodan(domain),
        "tech": lambda: check_tech(domain),
        "emails": lambda: harvest_emails(domain),
        "compliance": lambda: check_compliance(domain),
    }

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(fn): name for name, fn in checks.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception as e:
                results[name] = {"error": str(e), "score": 5}

    # Breach check: prioritize real emails (OSINT/website) over generated patterns
    email_data = results.get("emails", {})
    sources = email_data.get("sources", {})
    real = [e for e, s in sources.items() if not all("common-pattern" in x for x in s)]
    patterns = [e for e, s in sources.items() if all("common-pattern" in x for x in s)]
    prioritized = real + patterns
    try:
        results["breach"] = check_breaches(domain, prioritized[:25])
    except Exception as e:
        results["breach"] = {"error": str(e), "score": 7, "breached_emails": [], "emails_checked": prioritized[:25]}

    for name, data in results.items():
        raw = data.get("raw", "")
        if raw:
            (evidence_dir / f"{name}.txt").write_text(
                raw if isinstance(raw, str) else json.dumps(raw, indent=2)
            )

    if "subdomains" in results and results["subdomains"].get("subdomains"):
        (evidence_dir / "subdomains.json").write_text(
            json.dumps(results["subdomains"]["subdomains"], indent=2)
        )
    if "shodan" in results and results["shodan"].get("raw"):
        (evidence_dir / "shodan.json").write_text(results["shodan"]["raw"])
    if "tech" in results:
        tech_evidence = {k: v for k, v in results["tech"].items() if k != "raw"}
        (evidence_dir / "tech.json").write_text(
            json.dumps(tech_evidence, indent=2, default=str)
        )
    if "emails" in results:
        (evidence_dir / "emails.json").write_text(
            json.dumps(results["emails"], indent=2, default=str)
        )
    if "breach" in results:
        (evidence_dir / "breaches.json").write_text(
            json.dumps(results["breach"], indent=2, default=str)
        )
    if "compliance" in results:
        (evidence_dir / "compliance.json").write_text(
            json.dumps(results["compliance"], indent=2, default=str)
        )

    scores = {
        "headers": results.get("headers", {}).get("score", 5),
        "tech": results.get("tech", {}).get("score", 5),
        "tls": results.get("tls", {}).get("score", 5),
        "dns": results.get("dns", {}).get("score", 5),
        "exposure": min(
            results.get("subdomains", {}).get("score", 5),
            results.get("shodan", {}).get("score", 5),
        ),
        "breach": results.get("breach", {}).get("score", 7),
        "compliance": results.get("compliance", {}).get("score", 5),
    }

    weights = {"headers": 0.10, "tech": 0.15, "tls": 0.10, "dns": 0.15, "exposure": 0.15, "breach": 0.15, "compliance": 0.20}
    total = sum(scores[k] * weights[k] * 10 for k in scores)

    if total >= 90:
        grade = "A"
    elif total >= 75:
        grade = "B"
    elif total >= 60:
        grade = "C"
    elif total >= 40:
        grade = "D"
    else:
        grade = "F"

    # Build details summary for each area
    br = results.get("breach", {})
    breached_count = len(br.get("breached_emails", []))
    email_count = len(results.get("emails", {}).get("emails", []))
    breach_detail = f"{email_count} emails checked, {breached_count} breached, API: {br.get('api_used', 'none')}"
    if br.get("breaches"):
        breach_detail += f", breaches: {', '.join(br['breaches'][:5])}"

    tech = results.get("tech", {})
    eol_names = [e["name"] for e in tech.get("eol_software", [])]
    tech_detail = f"CMS: {tech.get('cms') or 'N/A'}"
    if eol_names:
        tech_detail += f", EOL: {', '.join(eol_names)}"
    if tech.get("version_disclosure"):
        tech_detail += f", disclosed: {'; '.join(tech['version_disclosure'])}"

    comp = results.get("compliance", {})
    comp_checks = comp.get("checks", {})
    comp_detail = ", ".join(f"{k}: {v}" for k, v in comp_checks.items()) if comp_checks else "N/A"

    scoring = {
        "scores": scores,
        "total": round(total),
        "grade": grade,
        "timestamp": datetime.utcnow().isoformat(),
        "domain": domain,
        "company": company,
        "sector": sector,
        "details": {
            "breach": breach_detail,
            "tech": tech_detail,
            "compliance": comp_detail,
        },
    }

    (output_path / "scoring" / "scores.json").write_text(json.dumps(scoring, indent=2))

    results["scoring"] = scoring
    return results


def print_summary(results, domain):
    """Print human-readable summary to stdout."""
    s = results.get("scoring", {})
    print(f"\n{'='*60}")
    print(f"  PASSIVE RECON SUMMARY — {domain}")
    print(f"{'='*60}")
    print(f"  Overall Score: {s.get('total', '?')}/100 (Grade: {s.get('grade', '?')})")
    print(f"{'='*60}")

    scores = s.get("scores", {})
    labels = {
        "headers": "Security Headers",
        "tech": "Technology Stack",
        "tls": "TLS/SSL",
        "dns": "DNS/Email (SPF/DMARC)",
        "exposure": "Surface Exposure",
        "breach": "Breach History",
        "compliance": "RGPD/LSSI Compliance",
    }
    for key, label in labels.items():
        score = scores.get(key, "?")
        bar = "#" * score + "." * (10 - score) if isinstance(score, int) else "?"
        print(f"  {label:.<30} [{bar}] {score}/10")

    h = results.get("headers", {})
    if h.get("missing"):
        print(f"\n  Missing headers: {', '.join(h['missing'])}")

    tech = results.get("tech", {})
    if tech.get("server"):
        print(f"  Server: {tech['server']}")
    if tech.get("powered_by"):
        print(f"  X-Powered-By: {tech['powered_by']}")
    if tech.get("eol_software"):
        for eol in tech["eol_software"]:
            print(f"  ⚠ EOL SOFTWARE: {eol['name']} (EOL since {eol['eol_date']})")

    t = results.get("tls", {})
    if t.get("cert_status"):
        print(f"  Certificate: {t['cert_status']}")
    if t.get("legacy_tls"):
        print(f"  Legacy TLS: {', '.join(t['legacy_tls'])} (INSECURE)")

    d = results.get("dns", {})
    print(f"  SPF: {d.get('spf', '?')}")
    print(f"  DMARC: {d.get('dmarc', '?')}")

    sub = results.get("subdomains", {})
    print(f"  Subdomains: {sub.get('count', 0)} found")
    if sub.get("notable"):
        print(f"  Notable: {', '.join(sub['notable'][:5])}")

    sh = results.get("shodan", {})
    if sh.get("ports"):
        print(f"  Open ports (Shodan): {', '.join(map(str, sh['ports']))}")
    if sh.get("vulns"):
        print(f"  Known CVEs: {', '.join(sh['vulns'][:5])}")

    tech = results.get("tech", {})
    if tech.get("cms"):
        print(f"  CMS: {tech['cms']}")

    em = results.get("emails", {})
    website_emails = [e for e, s in em.get("sources", {}).items() if "website" in str(s)]
    print(f"  Emails harvested: {len(em.get('emails', []))} ({len(website_emails)} from website)")
    if website_emails:
        print(f"  From website: {', '.join(website_emails[:5])}")

    br = results.get("breach", {})
    if br.get("breached_emails"):
        print(f"  BREACHED EMAILS: {len(br['breached_emails'])}")
        for be in br["breached_emails"][:5]:
            print(f"    {be['email']}: {', '.join(be['breaches'][:3])}")
    elif br.get("breach_count", 0) > 0:
        print(f"  Domain found in {br['breach_count']} breach(es): {', '.join(br.get('breaches', [])[:5])}")
    else:
        print(f"  Breaches: none found (API: {br.get('api_used', 'none')})")

    comp = results.get("compliance", {})
    checks = comp.get("checks", {})
    if checks:
        missing = [k for k, v in checks.items() if "No" in v]
        if missing:
            print(f"  Compliance gaps: {', '.join(missing)}")
        else:
            print(f"  Compliance: all RGPD/LSSI signals detected")

    print(f"\n{'='*60}\n")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <domain> <output_dir> [company] [sector]")
        sys.exit(1)

    domain = sys.argv[1]
    output_dir = sys.argv[2]
    company = sys.argv[3] if len(sys.argv) > 3 else ""
    sector = sys.argv[4] if len(sys.argv) > 4 else ""
    results = run_recon(domain, output_dir, company, sector)
    print_summary(results, domain)
