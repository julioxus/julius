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
    """Comprehensive TLS check with Qualys-style scoring.

    Scoring methodology (mirrors SSL Labs):
      Protocol support:   30% weight
      Key exchange:       30% weight
      Cipher strength:    40% weight
    Grade caps applied for critical weaknesses.
    Final 0-100 mapped to 0-10 for the prospect score.
    """
    results = {
        "raw": "", "version": "", "issuer": "", "expiry": "",
        "legacy_tls": [], "score": 10,
        "protocols": {}, "cert": {}, "ciphers": {},
        "vulnerabilities": [], "tls_grade": "?",
    }

    base = f"echo | openssl s_client -connect {domain}:443 -servername {domain}"

    # --- Certificate details ---
    cert_raw = run_cmd(
        f'{base} 2>/dev/null | openssl x509 -noout -dates -issuer -subject'
        f' -serial -ext subjectAltName -fingerprint -text 2>/dev/null'
    )
    results["raw"] += f"--- Certificate ---\n{cert_raw}\n"

    for line in cert_raw.split("\n"):
        if "notAfter" in line and "=" in line:
            results["expiry"] = line.split("=", 1)[1].strip()
        if "notBefore" in line and "=" in line:
            results["cert"]["not_before"] = line.split("=", 1)[1].strip()
        if "issuer" in line.lower() and "=" in line:
            results["issuer"] = line.split("=", 1)[1].strip()

    key_info = run_cmd(
        f'{base} 2>/dev/null | openssl x509 -noout -text 2>/dev/null'
        f' | grep -E "Public-Key:|Signature Algorithm:|Public Key Algorithm"'
    )
    results["raw"] += f"--- Key info ---\n{key_info}\n"

    key_bits = 0
    key_type = "RSA"
    sig_algo = ""
    for line in key_info.split("\n"):
        if "Public-Key" in line:
            m = re.search(r'\((\d+) bit\)', line)
            if m:
                key_bits = int(m.group(1))
        if "Public Key Algorithm" in line:
            algo_lower = line.lower()
            if "ec" in algo_lower or "ecdsa" in algo_lower:
                key_type = "ECC"
            elif "ed25519" in algo_lower or "ed448" in algo_lower:
                key_type = "EdDSA"
        if "Signature Algorithm" in line:
            sig_algo = line.split(":", 1)[1].strip() if ":" in line else ""
    results["cert"]["key_bits"] = key_bits
    results["cert"]["key_type"] = key_type
    results["cert"]["sig_algo"] = sig_algo

    chain_raw = run_cmd(f'{base} 2>/dev/null | grep -c "BEGIN CERTIFICATE"')
    chain_depth = 0
    try:
        chain_depth = int(chain_raw.strip())
    except ValueError:
        pass
    results["cert"]["chain_depth"] = chain_depth

    # --- Certificate expiry ---
    if results["expiry"]:
        try:
            exp_date = datetime.strptime(results["expiry"], "%b %d %H:%M:%S %Y %Z")
            days_left = (exp_date - datetime.utcnow()).days
            if days_left < 0:
                results["cert_status"] = f"CADUCADO hace {abs(days_left)} días"
                results["cert"]["expired"] = True
            elif days_left < 30:
                results["cert_status"] = f"Caduca en {days_left} días"
                results["cert"]["days_left"] = days_left
            else:
                results["cert_status"] = f"Válido ({days_left} días restantes)"
                results["cert"]["days_left"] = days_left
        except ValueError:
            results["cert_status"] = "No se pudo determinar"

    # --- Protocol support ---
    protocol_tests = [
        ("ssl3", "-ssl3", "SSLv3"),
        ("tls1", "-tls1", "TLS 1.0"),
        ("tls1_1", "-tls1_1", "TLS 1.1"),
        ("tls1_2", "-tls1_2", "TLS 1.2"),
        ("tls1_3", "-tls1_3", "TLS 1.3"),
    ]
    for key, flag, label in protocol_tests:
        check = run_cmd(
            f'echo | openssl s_client {flag} -connect {domain}:443'
            f' -servername {domain} 2>&1 | head -10'
        )
        supported = "CONNECTED" in check and "error" not in check.lower() and "wrong version" not in check.lower()
        results["protocols"][label] = supported
        if supported and label in ("TLS 1.0", "TLS 1.1"):
            results["legacy_tls"].append(label)
    results["raw"] += f"--- Protocols ---\n{json.dumps(results['protocols'])}\n"

    version_raw = run_cmd(f'{base} 2>/dev/null | grep "Protocol"')
    results["version"] = version_raw.strip()

    # --- Cipher suite analysis ---
    weak_ciphers = {"RC4": [], "DES": [], "3DES": [], "NULL": [], "EXPORT": [], "MD5": []}
    conn_raw = run_cmd(f'{base} 2>&1')
    current_cipher = ""
    for line in conn_raw.split("\n"):
        if "Cipher    :" in line or "Cipher is" in line:
            current_cipher = line.split(":")[-1].strip() if ":" in line else line.split("is")[-1].strip()
    results["ciphers"]["negotiated"] = current_cipher

    for weak_name, flag in [("RC4", "RC4"), ("DES", "DES"), ("3DES", "3DES"), ("NULL", "NULL"), ("EXPORT", "EXPORT")]:
        check = run_cmd(
            f'echo | openssl s_client -cipher {flag} -connect {domain}:443'
            f' -servername {domain} 2>&1 | head -5',
            timeout=10
        )
        if "CONNECTED" in check and "error" not in check.lower():
            weak_ciphers[weak_name].append(flag)
    results["ciphers"]["weak"] = {k: v for k, v in weak_ciphers.items() if v}
    results["raw"] += f"--- Ciphers ---\nnegotiated: {current_cipher}\nweak: {json.dumps(results['ciphers']['weak'])}\n"

    # --- OCSP stapling ---
    ocsp_raw = run_cmd(
        f'{base} -status 2>/dev/null | grep -A 2 "OCSP Response"',
        timeout=10
    )
    results["cert"]["ocsp_stapling"] = "OCSP Response Status: successful" in ocsp_raw
    results["raw"] += f"--- OCSP ---\n{ocsp_raw}\n"

    # --- Secure renegotiation ---
    reneg_raw = run_cmd(f'{base} 2>/dev/null | grep -i "renegotiation"')
    results["cert"]["secure_reneg"] = "secure" in reneg_raw.lower()
    results["raw"] += f"--- Renegotiation ---\n{reneg_raw}\n"

    # --- TLS_FALLBACK_SCSV ---
    fallback_raw = run_cmd(
        f'echo | openssl s_client -fallback_scsv -tls1_2 -connect {domain}:443'
        f' -servername {domain} 2>&1 | head -10',
        timeout=10
    )
    results["cert"]["fallback_scsv"] = "alert inappropriate fallback" in fallback_raw.lower() or (
        "CONNECTED" in fallback_raw and "error" not in fallback_raw.lower()
    )

    # --- Qualys-style scoring ---
    # Protocol score (0-100)
    proto_score = 0
    protos = results["protocols"]
    if protos.get("SSLv3"):
        proto_score = 20
        results["vulnerabilities"].append("SSLv3 habilitado (POODLE)")
    elif protos.get("TLS 1.0") and not protos.get("TLS 1.2"):
        proto_score = 40
    elif protos.get("TLS 1.0"):
        proto_score = 60
    elif protos.get("TLS 1.1") and not protos.get("TLS 1.2"):
        proto_score = 65
    elif protos.get("TLS 1.1"):
        proto_score = 70
    elif protos.get("TLS 1.2") and protos.get("TLS 1.3"):
        proto_score = 100
    elif protos.get("TLS 1.2"):
        proto_score = 95
    elif protos.get("TLS 1.3"):
        proto_score = 100

    # Key exchange score (0-100) — ECC/EdDSA use smaller key sizes than RSA
    kx_score = 0
    if key_type in ("ECC", "EdDSA"):
        if key_bits >= 384:
            kx_score = 100
        elif key_bits >= 256:
            kx_score = 90
        elif key_bits > 0:
            kx_score = 40
        else:
            kx_score = 70
    else:
        if key_bits >= 4096:
            kx_score = 100
        elif key_bits >= 2048:
            kx_score = 90
        elif key_bits >= 1024:
            kx_score = 40
        elif key_bits > 0:
            kx_score = 10
            results["vulnerabilities"].append(f"Clave RSA débil ({key_bits} bits)")
        else:
            kx_score = 70

    if "sha1" in sig_algo.lower() and "sha256" not in sig_algo.lower():
        kx_score = min(kx_score, 50)
        results["vulnerabilities"].append("Firma SHA-1 (obsoleta)")
    if "md5" in sig_algo.lower():
        kx_score = min(kx_score, 10)
        results["vulnerabilities"].append("Firma MD5 (insegura)")

    # Cipher strength score (0-100)
    cipher_score = 90
    if results["ciphers"]["weak"].get("NULL"):
        cipher_score = 0
        results["vulnerabilities"].append("Cifrado NULL aceptado")
    elif results["ciphers"]["weak"].get("EXPORT"):
        cipher_score = 10
        results["vulnerabilities"].append("Cifrado EXPORT aceptado (FREAK)")
    elif results["ciphers"]["weak"].get("DES"):
        cipher_score = 20
        results["vulnerabilities"].append("Cifrado DES aceptado")
    elif results["ciphers"]["weak"].get("RC4"):
        cipher_score = 30
        results["vulnerabilities"].append("Cifrado RC4 aceptado")
    elif results["ciphers"]["weak"].get("3DES"):
        cipher_score = 50
        results["vulnerabilities"].append("Cifrado 3DES aceptado (SWEET32)")

    if "AES" in current_cipher and ("GCM" in current_cipher or "CHACHA" in current_cipher):
        cipher_score = max(cipher_score, 95)
    elif "AES" in current_cipher:
        cipher_score = max(cipher_score, 80)

    # Weighted total (Qualys formula)
    total = round(proto_score * 0.3 + kx_score * 0.3 + cipher_score * 0.4)

    # Grade caps (Qualys rules)
    grade_cap = "A+"
    if results["cert"].get("expired"):
        grade_cap = "T"
        total = min(total, 20)
    if protos.get("SSLv3"):
        grade_cap = "C"
        total = min(total, 50)
    if protos.get("TLS 1.0") or protos.get("TLS 1.1"):
        if grade_cap not in ("T", "F", "C"):
            grade_cap = "B"
        total = min(total, 80)
    weak_key = (key_type == "RSA" and 0 < key_bits < 1024) or (key_type in ("ECC", "EdDSA") and 0 < key_bits < 160)
    if weak_key:
        grade_cap = "F"
        total = min(total, 20)
    if results["ciphers"]["weak"].get("NULL") or results["ciphers"]["weak"].get("EXPORT"):
        grade_cap = "F"
        total = min(total, 20)
    if results["ciphers"]["weak"].get("RC4"):
        if grade_cap not in ("T", "F"):
            grade_cap = "C"
        total = min(total, 50)

    # Assign grade from score
    if grade_cap in ("T", "F"):
        grade = grade_cap
    elif total >= 90 and grade_cap == "A+":
        grade = "A+" if results["cert"].get("ocsp_stapling") else "A"
    elif total >= 80:
        grade = min_grade("A", grade_cap)
    elif total >= 65:
        grade = min_grade("B", grade_cap)
    elif total >= 50:
        grade = min_grade("C", grade_cap)
    elif total >= 35:
        grade = "D"
    else:
        grade = "F"

    results["tls_grade"] = grade
    results["tls_score"] = total
    results["tls_components"] = {
        "protocol": proto_score,
        "key_exchange": kx_score,
        "cipher_strength": cipher_score,
    }
    results["score"] = max(1, round(total / 10))

    results["raw"] += f"\n--- TLS Grade ---\n"
    results["raw"] += f"Protocol: {proto_score}/100 | Key Exchange: {kx_score}/100 | Cipher: {cipher_score}/100\n"
    results["raw"] += f"Total: {total}/100 | Grade: {grade}\n"
    if results["vulnerabilities"]:
        results["raw"] += f"Vulnerabilities: {', '.join(results['vulnerabilities'])}\n"

    return results


def min_grade(a, b):
    """Return the worse (lower) of two SSL grades."""
    order = ["A+", "A", "B", "C", "D", "F", "T"]
    return a if order.index(a) >= order.index(b) else b


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


def _linkedin_people(company, people, location="Málaga"):
    """Search LinkedIn via Bing to validate people work at the company."""
    from urllib.parse import quote_plus, unquote
    ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
    confirmed = []
    for person in people[:10]:
        query = quote_plus(f'site:linkedin.com/in "{person}" "{company}"')
        raw = run_cmd(
            f'curl -sL -m 8 -H "User-Agent: {ua}" '
            f'"https://www.bing.com/search?q={query}&count=5" 2>/dev/null'
        )
        if raw and "linkedin.com/in/" in raw.lower():
            confirmed.append(person)
    return confirmed


def _name_to_email_candidates(name, domain):
    """Generate plausible email candidates from a name for breach-only checking."""
    import unicodedata
    def strip_accents(s):
        return ''.join(c for c in unicodedata.normalize('NFD', s) if unicodedata.category(c) != 'Mn')

    parts = name.lower().split()
    if len(parts) < 2:
        return []
    first = strip_accents(parts[0])
    last = strip_accents(parts[1])
    candidates = [
        f"{first}.{last}@{domain}",
        f"{first[0]}{last}@{domain}",
        f"{first}{last[0]}@{domain}",
        f"{first}@{domain}",
        f"{first}{last}@{domain}",
    ]
    if len(parts) >= 3:
        last2 = strip_accents(parts[2])
        candidates.append(f"{first}.{last}.{last2}@{domain}")
    return candidates


def _search_engine_emails(domain):
    """Harvest emails via Bing and DuckDuckGo (Google requires JS, unusable with curl)."""
    from urllib.parse import unquote
    emails = {}
    ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"

    searches = [
        ("bing", f'https://www.bing.com/search?q=%22%40{domain}%22&count=50'),
        ("bing2", f'https://www.bing.com/search?q=site%3A{domain}+email+OR+contacto+OR+contact&count=30'),
        ("duckduckgo", f'https://lite.duckduckgo.com/lite/?q=%22%40{domain}%22'),
    ]
    for engine, url in searches:
        if "lite.duckduckgo" in url:
            raw = run_cmd(f'curl -sL -m 10 -H "User-Agent: {ua}" -d "q=%22%40{domain}%22" "https://lite.duckduckgo.com/lite/" 2>/dev/null')
        else:
            raw = run_cmd(f'curl -sL -m 10 -H "User-Agent: {ua}" "{url}" 2>/dev/null')
        if raw:
            raw = unquote(raw)
            found = set(re.findall(r'[a-zA-Z0-9._%+\-]+@' + re.escape(domain), raw))
            for e in found:
                e = e.lower().strip('.')
                if len(e.split('@')[0]) >= 2:
                    emails.setdefault(e, []).append(engine)
    return emails


def _wayback_emails(domain):
    """Harvest emails from Wayback Machine historical snapshots."""
    emails = {}
    cdx_raw = run_cmd(
        f'curl -s -m 15 "http://web.archive.org/cdx/search/cdx?url={domain}/*'
        f'&output=text&fl=original,timestamp&filter=mimetype:text/html'
        f'&collapse=urlkey&limit=20"',
        timeout=20
    )
    if not cdx_raw or "[TIMEOUT]" in cdx_raw:
        return emails

    urls_seen = set()
    for line in cdx_raw.strip().split("\n"):
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        url, ts = parts[0], parts[1]
        norm = re.sub(r'https?://(www\.)?', '', url).rstrip('/')
        if norm in urls_seen:
            continue
        urls_seen.add(norm)
        wb_url = f"https://web.archive.org/web/{ts}/{url}"
        raw = run_cmd(f'curl -sL -m 10 "{wb_url}" 2>/dev/null', timeout=15)
        if raw:
            found = set(re.findall(r'[a-zA-Z0-9._%+\-]+@' + re.escape(domain), raw))
            for e in found:
                e = e.lower().strip('.')
                if len(e.split('@')[0]) >= 2:
                    emails.setdefault(e, []).append("wayback")
    return emails


def _spider_internal_links(domain, page_cache):
    """Follow internal links from cached pages to discover more email-containing pages."""
    discovered = {}
    seen_paths = set(page_cache.keys())
    links = set()
    for html in page_cache.values():
        for href in re.findall(r'href=["\']([^"\'#?]+)', html):
            href = href.strip()
            if href.startswith('/') and len(href) > 1:
                links.add(href)
            elif domain in href:
                path = re.sub(r'https?://[^/]+', '', href)
                if path and path.startswith('/'):
                    links.add(path)

    new_links = [l for l in links if l not in seen_paths and not re.search(
        r'\.(css|js|png|jpg|jpeg|gif|svg|ico|pdf|zip|woff|ttf|xml|json)$', l, re.I
    )][:15]

    for path in new_links:
        raw = run_cmd(f'curl -sL -m 6 https://www.{domain}{path} 2>/dev/null')
        if not raw or "[TIMEOUT]" in raw or len(raw) < 200:
            raw = run_cmd(f'curl -sL -m 6 https://{domain}{path} 2>/dev/null')
        if not raw or "[TIMEOUT]" in raw:
            continue
        found = set(re.findall(r'[a-zA-Z0-9._%+\-]+@' + re.escape(domain), raw))
        for e in found:
            e = e.lower().strip('.')
            if len(e.split('@')[0]) >= 2:
                discovered.setdefault(e, []).append(f"spider:{path}")
        page_cache[path] = raw
    return discovered


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

    def _add_emails(email_dict, label):
        count = 0
        for e, srcs in email_dict.items():
            found.add(e)
            results["sources"].setdefault(e, []).extend(srcs)
            count += 1
        results["raw"] += f"--- {label}: {count} emails ---\n"
        for e, s in email_dict.items():
            results["raw"] += f"  {e} ({', '.join(s)})\n"

    _add_emails(_search_engine_emails(domain), "Search engines (Bing/DDG)")
    _add_emails(_crtsh_emails(domain), "crt.sh")

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

    _add_emails(_spider_internal_links(domain, page_cache), "Spider (internal links)")
    _add_emails(_wayback_emails(domain), "Wayback Machine")

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
    results["people"] = all_people[:15]

    results["emails"] = sorted(found)
    osint_count = len([e for e, s in results["sources"].items()
                       if any(x in str(s) for x in ["bing", "duckduckgo", "crt.sh", "wayback"])])
    website_count = len([e for e, s in results["sources"].items()
                        if any("website" in x or "spider" in x for x in s)])
    results["raw"] += f"\n--- Total: {len(found)} confirmed emails ({osint_count} OSINT, {website_count} website) ---\n"
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

NVD_CPE_MAP = {
    "php": "cpe:2.3:a:php:php:{ver}:*:*:*:*:*:*:*",
    "wordpress": "cpe:2.3:a:wordpress:wordpress:{ver}:*:*:*:*:*:*:*",
    "apache": "cpe:2.3:a:apache:http_server:{ver}:*:*:*:*:*:*:*",
    "nginx": "cpe:2.3:a:f5:nginx:{ver}:*:*:*:*:*:*:*",
    "joomla": "cpe:2.3:a:joomla:joomla\\!:{ver}:*:*:*:*:*:*:*",
    "drupal": "cpe:2.3:a:drupal:drupal:{ver}:*:*:*:*:*:*:*",
}


def _query_nvd(cpe_string, max_results=10):
    """Query NVD API for CVEs matching a CPE via virtualMatchString."""
    from urllib.parse import quote
    url = (
        f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?virtualMatchString={quote(cpe_string)}"
        f"&resultsPerPage={max_results}"
    )
    raw = run_cmd(f'curl -s -m 15 "{url}"', timeout=20)
    if not raw or "[TIMEOUT]" in raw or "[ERROR" in raw:
        return []
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return []

    cves = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        severity = 0.0
        severity_label = ""
        for m in cve.get("metrics", {}).get("cvssMetricV31", []):
            d = m.get("cvssData", {})
            severity = d.get("baseScore", 0.0)
            severity_label = d.get("baseSeverity", "")
        if not severity_label:
            for m in cve.get("metrics", {}).get("cvssMetricV40", []):
                d = m.get("cvssData", {})
                severity = d.get("baseScore", 0.0)
                severity_label = d.get("baseSeverity", "")
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d["value"][:200]
                break
        if cve_id:
            cves.append({
                "id": cve_id,
                "score": severity,
                "severity": severity_label,
                "description": desc,
            })
    total = data.get("totalResults", len(cves))
    return {"total": total, "cves": sorted(cves, key=lambda x: x["score"], reverse=True)}


def _lookup_cves(tech_data):
    """Query NVD API for CVEs affecting detected technologies."""
    import time
    findings = []
    queries = []

    php_ver = ""
    for pw in tech_data.get("powered_by", "").split(","):
        m = re.search(r'PHP/(\d+\.\d+(?:\.\d+)?)', pw.strip(), re.I)
        if m:
            php_ver = m.group(1)
    if php_ver:
        queries.append(("PHP " + php_ver, NVD_CPE_MAP["php"].format(ver=php_ver)))

    cms = tech_data.get("cms", "")
    wp_match = re.search(r'WordPress\s+(\d+\.\d+(?:\.\d+)?)', cms)
    if wp_match:
        queries.append(("WordPress " + wp_match.group(1), NVD_CPE_MAP["wordpress"].format(ver=wp_match.group(1))))

    server = tech_data.get("server", "")
    apache_match = re.search(r'Apache/(\d+\.\d+\.\d+)', server)
    if apache_match:
        queries.append(("Apache " + apache_match.group(1), NVD_CPE_MAP["apache"].format(ver=apache_match.group(1))))
    nginx_match = re.search(r'nginx/(\d+\.\d+\.\d+)', server)
    if nginx_match:
        queries.append(("nginx " + nginx_match.group(1), NVD_CPE_MAP["nginx"].format(ver=nginx_match.group(1))))

    for software, cpe in queries:
        result = _query_nvd(cpe, max_results=10)
        if result and result.get("total", 0) > 0:
            cves = result["cves"]
            critical = sum(1 for c in cves if c["score"] >= 9.0)
            high = sum(1 for c in cves if 7.0 <= c["score"] < 9.0)
            findings.append({
                "software": software,
                "cves_total": result["total"],
                "critical": critical,
                "high": high,
                "sample_cves": [(c["id"], c["score"], c["description"]) for c in cves[:5]],
            })
        time.sleep(0.8)

    return findings


def check_tech(domain):
    """Detect technologies, versions, plugins, and CVE risks."""
    results = {
        "cms": "", "frameworks": [], "raw": "",
        "server": "", "powered_by": "", "eol_software": [],
        "version_disclosure": [], "plugins": [], "cve_findings": [],
        "score": 10,
    }

    raw = run_cmd(f'curl -sL -m 10 https://{domain}')
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

    is_wp = "wp-content" in raw or "wp-includes" in raw
    if is_wp:
        results["cms"] = results["cms"] or "WordPress"
        _detect_wp_plugins(raw, results)
    elif "Joomla" in raw:
        results["cms"] = results["cms"] or "Joomla"
    elif "Drupal" in raw:
        results["cms"] = results["cms"] or "Drupal"
    elif "Shopify" in raw:
        results["cms"] = results["cms"] or "Shopify"

    results["cve_findings"] = _lookup_cves(results)
    if results["cve_findings"]:
        total_cves = sum(f["cves_total"] for f in results["cve_findings"])
        total_critical = sum(f.get("critical", 0) for f in results["cve_findings"])
        if total_critical >= 3:
            results["score"] -= 4
        elif total_critical >= 1:
            results["score"] -= 2
        elif total_cves >= 10:
            results["score"] -= 1

    results["score"] = max(2, results["score"])
    return results


def _detect_wp_plugins(html, results):
    """Extract WordPress plugin names and versions from page source."""
    plugin_pattern = re.compile(
        r'/wp-content/plugins/([a-zA-Z0-9_-]+)(?:/[^"\']*?(?:ver(?:sion)?=|v=)([0-9][0-9.]+))?',
        re.I
    )
    seen = set()
    for m in plugin_pattern.finditer(html):
        slug = m.group(1)
        ver = m.group(2) or ""
        if slug not in seen:
            seen.add(slug)
            label = slug.replace("-", " ").title()
            if ver:
                label += f" {ver}"
            results["plugins"].append(label)
            results["version_disclosure"].append(f"Plugin: {slug}" + (f" v{ver}" if ver else ""))

    theme_pattern = re.compile(r'/wp-content/themes/([a-zA-Z0-9_-]+)', re.I)
    themes_seen = set()
    for m in theme_pattern.finditer(html):
        t = m.group(1)
        if t not in themes_seen:
            themes_seen.add(t)
            results["version_disclosure"].append(f"Theme: {t}")


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

    email_data = results.get("emails", {})
    confirmed_emails = email_data.get("emails", [])
    try:
        results["breach"] = check_breaches(domain, confirmed_emails[:25])
    except Exception as e:
        results["breach"] = {"error": str(e), "score": 7, "breached_emails": [], "emails_checked": confirmed_emails[:25]}

    people = email_data.get("people", [])
    if people:
        linkedin_confirmed = _linkedin_people(company, people)
        candidate_pool = linkedin_confirmed if linkedin_confirmed else people
        already_checked = set(confirmed_emails[:25])
        candidates = []
        for person in candidate_pool[:10]:
            for c in _name_to_email_candidates(person, domain):
                if c not in already_checked and c not in candidates:
                    candidates.append(c)
        if candidates:
            import time
            speculative_hits = []
            results["breach"]["raw"] = results["breach"].get("raw", "")
            results["breach"]["raw"] += f"\n--- Speculative check: {len(candidates[:20])} candidates from {len(candidate_pool)} people ---\n"
            for email in candidates[:20]:
                hit, raw = _check_xposedornot(email)
                if hit:
                    hit["source"] = "speculative-confirmed"
                    speculative_hits.append(hit)
                    results["breach"]["breached_emails"].append(hit)
                    results["breach"]["breach_count"] = results["breach"].get("breach_count", 0) + hit["count"]
                    for bn in hit["breaches"]:
                        if bn not in results["breach"].get("breaches", []):
                            results["breach"].setdefault("breaches", []).append(bn)
                    email_data["emails"].append(email)
                    email_data["sources"][email] = ["breach-confirmed"]
                    results["breach"]["raw"] += f"  ** HIT ** {email}: {hit['breaches']}\n"
                time.sleep(0.5)
            if speculative_hits:
                breached_count = len(results["breach"]["breached_emails"])
                if breached_count <= 2:
                    results["breach"]["score"] = 7
                elif breached_count <= 5:
                    results["breach"]["score"] = 5
                elif breached_count <= 10:
                    results["breach"]["score"] = 3
                else:
                    results["breach"]["score"] = 1
        results["breach"]["linkedin_confirmed"] = linkedin_confirmed
        results["breach"]["people_checked"] = len(candidate_pool)

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
    if "tls" in results:
        tls_evidence = {k: v for k, v in results["tls"].items() if k != "raw"}
        (evidence_dir / "tls.json").write_text(
            json.dumps(tls_evidence, indent=2, default=str)
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
        tech_detail += f", disclosed: {'; '.join(tech['version_disclosure'][:5])}"
    cve_findings = tech.get("cve_findings", [])
    if cve_findings:
        cve_parts = []
        for cf in cve_findings:
            cve_parts.append(f"{cf['software']}: {cf['cves_total']} CVEs ({cf.get('critical',0)} críticos)")
        tech_detail += f", CVEs: {'; '.join(cve_parts)}"

    tls = results.get("tls", {})
    tls_comps = tls.get("tls_components", {})
    tls_detail = f"Grade: {tls.get('tls_grade', '?')}, Score: {tls.get('tls_score', '?')}/100"
    tls_detail += f" (Proto: {tls_comps.get('protocol', '?')}, KX: {tls_comps.get('key_exchange', '?')}, Cipher: {tls_comps.get('cipher_strength', '?')})"
    if tls.get("legacy_tls"):
        tls_detail += f", Legacy: {', '.join(tls['legacy_tls'])}"
    if tls.get("vulnerabilities"):
        tls_detail += f", Vulns: {', '.join(tls['vulnerabilities'])}"

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
            "tls": tls_detail,
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
