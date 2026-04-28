#!/usr/bin/env python3
"""Passive OSINT reconnaissance for prospect skill.

All checks are strictly passive — no port scanning, no fuzzing,
no authenticated access. Only public data sources.
"""

import json
import shutil
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

        expected = {80, 443}
        alt_web = {8080, 8443}
        unusual_ports = [p for p in results["ports"] if p not in expected and p not in alt_web]
        alt_open = [p for p in results["ports"] if p in alt_web]

        if len(unusual_ports) > 3:
            results["score"] -= 4
        elif unusual_ports:
            results["score"] -= 2

        if alt_open:
            results["score"] -= 1

        if results["vulns"]:
            results["score"] -= min(len(results["vulns"]), 5)

        if not unusual_ports and not alt_open and not results["vulns"]:
            results["score"] = 10

    except (json.JSONDecodeError, TypeError):
        pass

    return results


LEAKIX_HIGH_VALUE_PLUGINS = [
    "GitConfigHttpPlugin",
    "DotEnvConfigPlugin",
    "DotDsStoreOpenPlugin",
    "PhpInfoHttpPlugin",
    "DjangoPlugin",
    "FlaskPlugin",
    "RailsPlugin",
    "LaravelTelescopeHttpPlugin",
    "SymfonyProfilerPlugin",
    "SymfonyVerbosePlugin",
    "YiiDebugPlugin",
    "SpringBootActuatorPlugin",
    "GraphQLIntrospectionPlugin",
    "SwaggerUIPlugin",
    "ConfigJsonHttp",
    "PublicEnvPlugin",
    "VsCodeSFTPPlugin",
    "WpUserEnumHttp",
    "ApacheStatusPlugin",
    "JenkinsOpenPlugin",
    "SonarQubePlugin",
    "ElasticSearchOpenPlugin",
    "MongoOpenPlugin",
    "RedisOpenPlugin",
    "MysqlOpenPlugin",
    "PostgreSQLOpenPlugin",
    "CouchDbOpenPlugin",
    "MemcachedOpenPlugin",
    "HttpNTLM",
    "PrometheusPlugin",
    "GrafanaOpenPlugin",
    "DockerAPIPlugin",
    "DockerRegistryHttpPlugin",
    "JupyterPlugin",
    "TraversalHttpPlugin",
    "PhpCgiRcePlugin",
    "Log4JOpportunistic",
    "LDAPPlugin",
    "RsyncOpenPlugin",
    "WebDAVPlugin",
    "DNSPlugin",
    "VNCPlugin",
    "RdpPlugin",
    "NodeREDPlugin",
    "MetabaseHttpPlugin",
    "OllamaPlugin",
]

LEAKIX_PLUGIN_LABELS = {
    "GitConfigHttpPlugin": "Repositorio Git expuesto (.git/config)",
    "DotEnvConfigPlugin": "Archivo .env con credenciales expuesto",
    "DotDsStoreOpenPlugin": "Archivo .DS_Store expuesto (listado de directorios)",
    "PhpInfoHttpPlugin": "Página phpinfo() expuesta (configuración del servidor)",
    "DjangoPlugin": "Django en modo DEBUG (traza de errores pública)",
    "FlaskPlugin": "Flask en modo DEBUG (consola interactiva pública)",
    "RailsPlugin": "Rails en modo DEBUG (traza de errores pública)",
    "LaravelTelescopeHttpPlugin": "Panel Laravel Telescope expuesto",
    "SymfonyProfilerPlugin": "Profiler de Symfony expuesto",
    "SymfonyVerbosePlugin": "Symfony en modo verbose (errores detallados)",
    "YiiDebugPlugin": "Panel de debug Yii expuesto",
    "SpringBootActuatorPlugin": "Spring Boot Actuator expuesto (métricas y configuración)",
    "GraphQLIntrospectionPlugin": "GraphQL con introspección habilitada",
    "SwaggerUIPlugin": "Documentación Swagger/OpenAPI expuesta",
    "ConfigJsonHttp": "Archivo config.json expuesto",
    "PublicEnvPlugin": "Variables de entorno públicas (Next.js/Vite/Nuxt)",
    "VsCodeSFTPPlugin": "Credenciales SFTP de VS Code expuestas",
    "WpUserEnumHttp": "Enumeración de usuarios WordPress vía API REST",
    "ApacheStatusPlugin": "Página server-status de Apache expuesta",
    "JenkinsOpenPlugin": "Jenkins sin autenticación",
    "SonarQubePlugin": "SonarQube público (posible fuga de código fuente)",
    "ElasticSearchOpenPlugin": "Elasticsearch/Kibana sin autenticación",
    "MongoOpenPlugin": "MongoDB sin autenticación",
    "RedisOpenPlugin": "Redis sin autenticación",
    "MysqlOpenPlugin": "MySQL sin autenticación",
    "PostgreSQLOpenPlugin": "PostgreSQL sin autenticación",
    "CouchDbOpenPlugin": "CouchDB sin autenticación",
    "MemcachedOpenPlugin": "Memcached expuesto públicamente",
    "HttpNTLM": "Servidor acepta credenciales NTLM anónimas",
    "PrometheusPlugin": "Prometheus expuesto (métricas de infraestructura)",
    "GrafanaOpenPlugin": "Grafana con versión vulnerable",
    "DockerAPIPlugin": "API de Docker sin autenticación",
    "DockerRegistryHttpPlugin": "Registry de Docker público",
    "JupyterPlugin": "Jupyter Notebook sin autenticación",
    "TraversalHttpPlugin": "Vulnerabilidad de path traversal",
    "PhpCgiRcePlugin": "PHP-CGI vulnerable a ejecución remota de código",
    "Log4JOpportunistic": "Servidor vulnerable a Log4Shell",
    "LDAPPlugin": "LDAP permite binding anónimo",
    "RsyncOpenPlugin": "Rsync expuesto sin autenticación",
    "WebDAVPlugin": "WebDAV sin autenticación",
    "DNSPlugin": "Servidor DNS permite transferencias de zona",
    "VNCPlugin": "VNC sin autenticación",
    "RdpPlugin": "RDP sin Network Level Authentication",
    "NodeREDPlugin": "Node-RED sin autenticación",
    "MetabaseHttpPlugin": "Metabase con versión vulnerable",
    "OllamaPlugin": "Ollama (LLM) expuesto públicamente",
}


def check_leakix(domain):
    """Query LeakIX for confirmed data exposures and misconfigured services.

    Calls /domain/{domain} for full results, then searches for high-value
    plugins specifically. Never stores or displays actual credentials.
    """
    results = {
        "raw": "", "services": [], "leaks": [], "score": 10,
        "leak_count": 0, "service_count": 0,
        "severity_breakdown": {}, "plugins_detected": [],
        "plugin_details": [],
    }

    api_key = os.environ.get("LEAKIX_API_KEY", "")
    if not api_key:
        results["raw"] = "LEAKIX_API_KEY not set — skipping"
        return results

    def _leakix_get(path):
        return run_cmd(
            f'curl -s -m 15 -H "api-key: {api_key}" '
            f'-H "Accept: application/json" '
            f'"{path}"'
        )

    raw = _leakix_get(f"https://leakix.net/domain/{domain}")
    results["raw"] = raw

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return results

    if isinstance(data, dict) and data.get("error"):
        results["raw"] += f"\nAPI error: {data['error']}"
        return results

    raw_services = data.get("Services") or []
    raw_leaks = data.get("Leaks") or []

    for svc in raw_services:
        sw = svc.get("service", {}).get("software", {})
        modules = sw.get("modules") or []
        svc_entry = {
            "ip": svc.get("ip", ""),
            "host": svc.get("host", ""),
            "port": svc.get("port", ""),
            "protocol": svc.get("protocol", ""),
            "transport": svc.get("transport") or [],
            "software": sw.get("name", ""),
            "version": sw.get("version", ""),
            "os": sw.get("os", ""),
            "modules": [{"name": m.get("name", ""), "version": m.get("version", "")}
                        for m in modules if m.get("name")],
            "plugin": svc.get("event_source", ""),
            "time": svc.get("time", ""),
            "tags": svc.get("tags") or [],
        }
        http = svc.get("http") or {}
        if http:
            svc_entry["http"] = {
                "url": http.get("url", ""),
                "status": http.get("status", 0),
                "title": http.get("title", ""),
                "headers": http.get("header") or {},
            }
        ssl = svc.get("ssl") or {}
        if ssl.get("detected"):
            cert = ssl.get("certificate") or {}
            svc_entry["ssl"] = {
                "version": ssl.get("version", ""),
                "cipher": ssl.get("cypher_suite", ""),
                "jarm": ssl.get("jarm", ""),
                "cn": cert.get("cn", ""),
                "san": cert.get("domain") or [],
                "issuer": cert.get("issuer_name", ""),
                "valid": cert.get("valid", False),
                "not_after": cert.get("not_after", ""),
            }
        geo = svc.get("geoip") or {}
        if geo.get("country_name"):
            svc_entry["geoip"] = {
                "country": geo.get("country_name", ""),
                "country_code": geo.get("country_iso_code", ""),
                "city": geo.get("city_name", ""),
                "region": geo.get("region_name", ""),
            }
        net = svc.get("network") or {}
        if net.get("organization_name"):
            svc_entry["network"] = {
                "org": net.get("organization_name", ""),
                "asn": net.get("asn", 0),
                "cidr": net.get("network", ""),
            }
        noauth = svc.get("service", {}).get("credentials", {}).get("noauth", False)
        if noauth:
            svc_entry["noauth"] = True
        results["services"].append(svc_entry)

    severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    seen_plugins = set()
    seen_fingerprints = set()

    def _process_leak(leak):
        fp = leak.get("event_fingerprint", "")
        if fp and fp in seen_fingerprints:
            return
        if fp:
            seen_fingerprints.add(fp)
        leak_meta = leak.get("leak", {})
        sev = (leak_meta.get("severity") or "info").lower()
        severity_count[sev] = severity_count.get(sev, 0) + 1
        plugin = leak.get("event_source", "")
        if plugin and plugin not in seen_plugins:
            seen_plugins.add(plugin)
        dataset = leak_meta.get("dataset") or {}
        entry = {
            "plugin": plugin,
            "severity": sev,
            "stage": leak_meta.get("stage", ""),
            "type": leak_meta.get("type", ""),
            "summary": (leak.get("summary") or "")[:500],
            "ip": leak.get("ip", ""),
            "host": leak.get("host", ""),
            "port": leak.get("port", ""),
            "protocol": leak.get("protocol", ""),
            "transport": leak.get("transport") or [],
            "time": leak.get("time", ""),
            "fingerprint": fp,
            "tags": leak.get("tags") or [],
            "dataset": {
                "rows": dataset.get("rows", 0),
                "files": dataset.get("files", 0),
                "size": dataset.get("size", 0),
                "collections": dataset.get("collections", 0),
                "infected": dataset.get("infected", False),
            },
        }
        http = leak.get("http") or {}
        if http:
            entry["http"] = {
                "url": http.get("url", ""),
                "status": http.get("status", 0),
                "title": http.get("title", ""),
                "headers": http.get("header") or {},
            }
        sw = leak.get("service", {}).get("software", {})
        if sw.get("name"):
            entry["software"] = {
                "name": sw.get("name", ""),
                "version": sw.get("version", ""),
                "os": sw.get("os", ""),
            }
        geo = leak.get("geoip") or {}
        if geo.get("country_name"):
            entry["geoip"] = {
                "country": geo.get("country_name", ""),
                "country_code": geo.get("country_iso_code", ""),
                "city": geo.get("city_name", ""),
            }
        net = leak.get("network") or {}
        if net.get("organization_name"):
            entry["network"] = {
                "org": net.get("organization_name", ""),
                "asn": net.get("asn", 0),
                "cidr": net.get("network", ""),
            }
        noauth = leak.get("service", {}).get("credentials", {}).get("noauth", False)
        if noauth:
            entry["noauth"] = True
        results["leaks"].append(entry)

    for leak in raw_leaks:
        _process_leak(leak)

    import time as _time
    search_raw = _leakix_get(
        f"https://leakix.net/search?q=%2Bhost%3A{domain}&scope=leak&page=0"
    )
    _time.sleep(1.1)
    try:
        search_results = json.loads(search_raw)
        if isinstance(search_results, list):
            for leak in search_results:
                _process_leak(leak)
    except (json.JSONDecodeError, TypeError):
        pass

    results["leak_count"] = len(results["leaks"])
    results["service_count"] = len(raw_services)
    results["severity_breakdown"] = {k: v for k, v in severity_count.items() if v > 0}
    results["plugins_detected"] = sorted(seen_plugins)

    for plugin_name in seen_plugins:
        label = LEAKIX_PLUGIN_LABELS.get(plugin_name, plugin_name)
        is_high_value = plugin_name in LEAKIX_HIGH_VALUE_PLUGINS
        leak_entries = [lk for lk in results["leaks"] if lk["plugin"] == plugin_name]
        worst_sev = "info"
        for lk in leak_entries:
            for s in ("critical", "high", "medium", "low"):
                if lk["severity"] == s:
                    if ("critical", "high", "medium", "low", "info").index(s) < \
                       ("critical", "high", "medium", "low", "info").index(worst_sev):
                        worst_sev = s
        results["plugin_details"].append({
            "plugin": plugin_name,
            "label": label,
            "high_value": is_high_value,
            "severity": worst_sev,
            "count": len(leak_entries),
        })

    results["plugin_details"].sort(
        key=lambda x: (
            not x["high_value"],
            ("critical", "high", "medium", "low", "info").index(x["severity"]),
        )
    )

    crit = severity_count["critical"]
    high = severity_count["high"]
    medium = severity_count["medium"]
    if crit > 0:
        results["score"] -= min(crit * 3, 6)
    if high > 0:
        results["score"] -= min(high * 2, 4)
    if medium > 0:
        results["score"] -= min(medium, 2)
    results["score"] = max(1, results["score"])

    return results


def check_sensitive_paths(domain):
    """Check for exposed sensitive files, admin panels, and misconfigurations."""
    results = {"raw": "", "findings": [], "score": 10}

    base_urls = []
    for scheme in ["https", "http"]:
        test = run_cmd(f'curl -sk -o /dev/null -w "%{{http_code}}" -m 8 {scheme}://{domain}/')
        if test.strip() in ("200", "301", "302", "403"):
            base_urls.append(f"{scheme}://{domain}")
            break
    if not base_urls:
        base_urls = [f"https://{domain}"]

    base = base_urls[0]

    CHECKS = [
        {
            "category": "env_file",
            "paths": ["/.env", "/.env.production", "/.env.local", "/.env.backup"],
            "title": "Archivo .env expuesto",
            "severity": "critica",
            "validate": lambda body, _ct: any(k in body for k in ["DB_PASSWORD", "DB_HOST", "APP_KEY", "SECRET_KEY", "API_KEY", "DATABASE_URL", "MYSQL_", "POSTGRES_"]),
            "extract": lambda body: [line.strip() for line in body.splitlines()[:30] if line.strip() and not line.strip().startswith("#") and "=" in line],
            "risk": "El archivo .env contiene credenciales de base de datos, claves API y secretos de la aplicación en texto plano. Un atacante puede usarlos para acceder directamente a los sistemas internos.",
        },
        {
            "category": "svn",
            "paths": ["/.svn/entries", "/.svn/wc.db"],
            "title": "Repositorio SVN (.svn) expuesto",
            "severity": "critica",
            "validate": lambda body, ct: ("dir" in body.lower() and len(body) < 5000) or "SQLite" in body[:20] or "svn" in body.lower()[:500],
            "extract": lambda body: [line.strip() for line in body.splitlines()[:20] if line.strip()],
            "risk": "El directorio .svn permite reconstruir el código fuente completo, incluyendo historial de cambios y posibles credenciales en versiones anteriores.",
        },
        {
            "category": "debug_log",
            "paths": ["/wp-content/debug.log", "/debug.log"],
            "title": "Log de depuración WordPress expuesto",
            "severity": "alta",
            "validate": lambda body, _ct: any(k in body for k in ["PHP Fatal", "PHP Warning", "PHP Notice", "WordPress database error", "Stack trace", "wp-includes", "wp-content"]),
            "extract": lambda body: body.splitlines()[:15],
            "risk": "El archivo debug.log expone errores internos con rutas del servidor, consultas SQL, y potencialmente credenciales o tokens. Permite a un atacante mapear la infraestructura interna.",
        },
        {
            "category": "backup_files",
            "paths": ["/backup.zip", "/backup.sql", "/db.sql", "/dump.sql", "/backup.tar.gz",
                      "/site.zip", "/www.zip", "/public_html.zip", "/database.sql",
                      "/wp-config.php.bak", "/wp-config.php.old", "/wp-config.php~",
                      "/wp-config.php.save", "/wp-config.bak", "/wp-config.old",
                      "/.wp-config.php.swp", "/config.php.bak"],
            "title": "Archivos de backup expuestos",
            "severity": "critica",
            "validate": lambda body, ct: ct and any(t in ct.lower() for t in ["zip", "sql", "gzip", "tar", "octet-stream"]) or (body[:4] == "PK\x03\x04") or ("CREATE TABLE" in body[:1000]) or ("INSERT INTO" in body[:1000]) or ("mysqldump" in body[:500]) or (body.startswith("<?php") and "DB_PASSWORD" in body[:2000]),
            "risk": "Los archivos de backup contienen la base de datos completa o el código fuente con credenciales. Es equivalente a entregar una copia completa del sistema a un atacante.",
        },
        {
            "category": "phpinfo",
            "paths": ["/phpinfo.php", "/info.php", "/php_info.php", "/test.php", "/i.php"],
            "title": "phpinfo() expuesto públicamente",
            "severity": "alta",
            "validate": lambda body, _ct: "PHP Version" in body and ("phpinfo()" in body or "Configuration" in body),
            "extract": lambda body: _extract_phpinfo(body),
            "risk": "phpinfo() expone la configuración completa del servidor: versión de PHP, extensiones, variables de entorno (que pueden incluir credenciales), rutas internas y configuración del sistema operativo.",
        },
        {
            "category": "db_admin",
            "paths": ["/adminer.php", "/adminer/", "/phpmyadmin/", "/phpMyAdmin/",
                      "/pma/", "/myadmin/", "/dbadmin/", "/sql/"],
            "title": "Panel de administración de base de datos expuesto",
            "severity": "critica",
            "validate": lambda body, _ct: any(k in body for k in ["Adminer", "phpMyAdmin", "Server choice", "Log in", "pma_", "pmahomme"]),
            "extract": lambda body: [],
            "risk": "Un panel de administración de base de datos accesible públicamente permite a un atacante intentar acceder directamente a la base de datos mediante fuerza bruta o credenciales por defecto.",
        },
        {
            "category": "server_status",
            "paths": ["/server-status", "/server-info"],
            "title": "Apache server-status/server-info expuesto",
            "severity": "alta",
            "validate": lambda body, _ct: any(k in body for k in ["Apache Server Status", "Server Version", "Current Time", "Apache Server Information", "Server Built"]),
            "extract": lambda body: [line.strip() for line in body.splitlines() if "Server Version" in line or "Current Time" in line or "Total accesses" in line][:5],
            "risk": "server-status expone información en tiempo real: IPs de clientes, URLs solicitadas, carga del servidor y versión exacta de Apache. Permite a un atacante enumerar endpoints internos y planificar ataques.",
        },
        {
            "category": "wp_user_enum",
            "paths": ["/wp-json/wp/v2/users", "/?rest_route=/wp/v2/users"],
            "title": "Enumeración de usuarios WordPress",
            "severity": "media",
            "validate": lambda body, _ct: body.strip().startswith("[") and '"slug"' in body and '"name"' in body,
            "extract": lambda body: _extract_wp_users(body),
            "risk": "La API REST de WordPress expone los nombres de usuario de los administradores. Un atacante puede usar estos nombres para ataques de fuerza bruta contra el panel de login.",
        },
        {
            "category": "xmlrpc",
            "paths": ["/xmlrpc.php"],
            "title": "WordPress XML-RPC activo",
            "severity": "media",
            "validate": lambda body, _ct: "XML-RPC server accepts POST requests only" in body or "xmlrpc" in body.lower()[:500],
            "extract": lambda body: [],
            "risk": "XML-RPC permite amplificación de fuerza bruta (system.multicall), envío de pingbacks para DDoS, y enumeración de credenciales. Debería estar desactivado si no se utiliza.",
        },
        {
            "category": "ds_store",
            "paths": ["/.DS_Store"],
            "title": "Archivo .DS_Store expuesto",
            "severity": "media",
            "validate": lambda body, _ct: body[:8] == "\x00\x00\x00\x01Bud1" or (len(body) > 10 and body[:4] == "\x00\x00\x00\x01"),
            "extract": lambda body: [],
            "risk": "El archivo .DS_Store de macOS revela la estructura de directorios del proyecto, permitiendo a un atacante descubrir archivos y carpetas ocultas.",
        },
    ]

    def _check_path(path_info):
        category = path_info["category"]
        for path in path_info["paths"]:
            url = f"{base}{path}"
            raw_headers = run_cmd(
                f'curl -sk -D - -o /dev/null -w "\\n%{{http_code}}|%{{size_download}}" '
                f'-H "User-Agent: Mozilla/5.0" "{url}" -m 10'
            )
            lines = raw_headers.strip().split("\n")
            status_line = lines[-1] if lines else ""
            parts = status_line.split("|")
            status = parts[0] if parts else ""
            size = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0

            if status != "200" or size < 10:
                continue

            content_type = ""
            for line in lines[:-1]:
                if line.lower().startswith("content-type:"):
                    content_type = line.split(":", 1)[1].strip()

            body = run_cmd(
                f'curl -sk -H "User-Agent: Mozilla/5.0" "{url}" -m 10'
            )
            if not body:
                continue

            if "<html" in body.lower()[:500] and category not in ("phpinfo", "db_admin", "server_status", "wp_user_enum"):
                if "<!doctype" in body.lower()[:100] or "<head>" in body.lower()[:500]:
                    continue

            try:
                if path_info["validate"](body, content_type):
                    extracted = path_info.get("extract", lambda b: [])(body) if "extract" in path_info else []
                    return {
                        "category": category,
                        "path": path,
                        "url": url,
                        "title": path_info["title"],
                        "severity": path_info["severity"],
                        "risk": path_info["risk"],
                        "size": size,
                        "content_type": content_type,
                        "extracted": extracted[:30] if extracted else [],
                        "body_preview": body[:500],
                    }
            except Exception:
                continue
        return None

    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {executor.submit(_check_path, check): check["category"] for check in CHECKS}
        for future in as_completed(futures):
            cat = futures[future]
            try:
                result = future.result()
                if result:
                    results["findings"].append(result)
                    results["raw"] += f"--- {cat}: {result['url']} ---\nStatus: 200, Size: {result['size']}\n{result['body_preview'][:300]}\n\n"
            except Exception as e:
                results["raw"] += f"--- {cat}: error: {e} ---\n"

    # Git exposure check — runs after path checks using the same base URL
    git_result = _check_git_exposed(base, domain)
    if git_result:
        results["findings"].append(git_result)
        results["raw"] += f"--- git_exposed: {git_result['url']} ---\n"
        results["git_exposed"] = git_result.get("git_data", {})

    crit_count = sum(1 for f in results["findings"] if f["severity"] == "critica")
    high_count = sum(1 for f in results["findings"] if f["severity"] == "alta")
    med_count = sum(1 for f in results["findings"] if f["severity"] == "media")

    if crit_count:
        results["score"] = max(0, 2 - crit_count)
    elif high_count:
        results["score"] = max(2, 5 - high_count)
    elif med_count:
        results["score"] = max(5, 7 - med_count)

    return results


def _parse_git_index(base_url):
    """Parse .git/index binary to extract file paths."""
    import struct
    try:
        with open("/tmp/.prospect_git_index", "rb") as fh:
            data = fh.read()
        if len(data) < 12 or data[:4] != b"DIRC":
            return []
        version = struct.unpack(">I", data[4:8])[0]
        num_entries = struct.unpack(">I", data[8:12])[0]
        if num_entries > 10000 or version not in (2, 3, 4):
            return []
        files = []
        offset = 12
        for _ in range(min(num_entries, 500)):
            if offset + 62 > len(data):
                break
            flags = struct.unpack(">H", data[offset + 60:offset + 62])[0]
            name_len = flags & 0x0FFF
            name_offset = offset + 62
            if version >= 3 and (flags & 0x4000):
                name_offset += 2
            if name_len == 0x0FFF:
                null_pos = data.find(b"\x00", name_offset)
                if null_pos == -1:
                    break
                name = data[name_offset:null_pos].decode("utf-8", errors="replace")
            else:
                name = data[name_offset:name_offset + name_len].decode("utf-8", errors="replace")
            if name and all(c.isprintable() or c == "/" for c in name):
                files.append(name)
            entry_raw_len = (name_offset - offset) + len(name.encode("utf-8"))
            offset += ((entry_raw_len + 8) // 8) * 8
        return files
    except Exception:
        return []


def _check_git_exposed(base_url, domain):
    """Check for exposed .git directory. Returns a finding dict or None."""
    for base in [base_url, base_url.replace("https://", "http://") if "https" in base_url else base_url.replace("http://", "https://")]:
        head_raw = run_cmd(
            f'curl -sk -o /dev/null -w "%{{http_code}}|%{{size_download}}" '
            f'-H "User-Agent: Mozilla/5.0" "{base}/.git/HEAD" -m 10'
        )
        parts = head_raw.strip().split("|")
        if len(parts) != 2 or parts[0] != "200":
            continue

        head_body = run_cmd(
            f'curl -sk -H "User-Agent: Mozilla/5.0" "{base}/.git/HEAD" -m 10'
        )
        if not head_body:
            continue
        head_body = head_body.strip()
        if not (head_body.startswith("ref:") or re.match(r'^[0-9a-f]{40}$', head_body)):
            continue

        git_data = {"exposed": True, "base_url": base, "head_ref": head_body,
                    "files": [], "refs": [], "config": {}, "log_entries": [],
                    "objects_accessible": False}

        config_raw = run_cmd(f'curl -sk -H "User-Agent: Mozilla/5.0" "{base}/.git/config" -m 10')
        if config_raw and "[core]" in config_raw:
            git_data["config"]["raw"] = config_raw[:2000]
            remote_match = re.search(r'url\s*=\s*(.+)', config_raw)
            if remote_match:
                git_data["config"]["remote_url"] = remote_match.group(1).strip()

        packed_raw = run_cmd(f'curl -sk -H "User-Agent: Mozilla/5.0" "{base}/.git/packed-refs" -m 10')
        if packed_raw and not packed_raw.startswith("<!"):
            for line in packed_raw.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    p = line.split()
                    if len(p) == 2:
                        git_data["refs"].append({"hash": p[0], "ref": p[1]})

        logs_raw = run_cmd(f'curl -sk -H "User-Agent: Mozilla/5.0" "{base}/.git/logs/HEAD" -m 10')
        if logs_raw and not logs_raw.startswith("<!"):
            for line in logs_raw.strip().splitlines()[-10:]:
                match = re.search(r'([0-9a-f]{40})\s+([0-9a-f]{40})\s+(.+?)\s+(\d+)\s+[+-]\d+\t(.+)', line)
                if match:
                    git_data["log_entries"].append({
                        "from": match.group(1)[:8], "to": match.group(2)[:8],
                        "author": match.group(3), "message": match.group(5),
                    })

        index_bin = run_cmd(
            f'curl -sk -H "User-Agent: Mozilla/5.0" "{base}/.git/index" -m 10 '
            f'-o /tmp/.prospect_git_index 2>/dev/null && cat /tmp/.prospect_git_index'
        )
        git_data["files"] = _parse_git_index(base)
        if not git_data["files"]:
            index_strings = run_cmd(
                f'strings /tmp/.prospect_git_index 2>/dev/null '
                f'| grep -E "^[a-zA-Z0-9_./-]{{3,}}$" | head -200'
            )
            if index_strings:
                git_data["files"] = [
                    f.strip() for f in index_strings.splitlines()
                    if f.strip() and not f.strip().startswith("DIRC")
                    and ("/" in f.strip() or "." in f.strip())
                ][:200]

        obj_test = run_cmd(
            f'curl -sk -o /dev/null -w "%{{http_code}}" '
            f'-H "User-Agent: Mozilla/5.0" "{base}/.git/objects/" -m 10'
        )
        if obj_test.strip() == "200":
            git_data["objects_accessible"] = True

        desc_raw = run_cmd(f'curl -sk -H "User-Agent: Mozilla/5.0" "{base}/.git/description" -m 5')
        if desc_raw and not desc_raw.startswith("<!") and "Unnamed repository" not in desc_raw:
            git_data["description"] = desc_raw.strip()[:200]

        fetch_raw = run_cmd(f'curl -sk -H "User-Agent: Mozilla/5.0" "{base}/.git/FETCH_HEAD" -m 5')
        if fetch_raw and re.match(r'^[0-9a-f]{40}', fetch_raw.strip()):
            git_data["fetch_head"] = fetch_raw.strip()[:200]

        if git_data["files"]:
            sensitive_patterns = [
                ".env", "config", "password", "secret", "credential", "key",
                "token", "database", "db", "wp-config", "settings.py",
                "application.yml", "application.properties", "appsettings",
                ".pem", ".key", ".p12", "id_rsa", "htpasswd", "shadow",
                "docker-compose", "Dockerfile", "Vagrantfile", ".sql",
            ]
            git_data["sensitive_files"] = [
                f for f in git_data["files"]
                if any(p in f.lower() for p in sensitive_patterns)
            ]
            exts = {}
            dirs = set()
            for f in git_data["files"]:
                parts = f.rsplit(".", 1)
                if len(parts) == 2:
                    ext = parts[1].lower()
                    exts[ext] = exts.get(ext, 0) + 1
                if "/" in f:
                    dirs.add(f.rsplit("/", 1)[0])
            git_data["file_extensions"] = dict(sorted(exts.items(), key=lambda x: -x[1])[:20])
            git_data["directories"] = sorted(dirs)[:50]
            git_data["file_count"] = len(git_data["files"])

        return {
            "category": "git_exposed",
            "path": "/.git/HEAD",
            "url": f"{base}/.git/",
            "title": "Repositorio Git (.git) expuesto públicamente",
            "severity": "alta",
            "justification": "Se ha verificado el acceso directo al archivo .git/HEAD, confirmando que el contenido del repositorio es descargable. Un atacante puede reconstruir el código fuente completo.",
            "risk": "La exposición del directorio .git permite a cualquier atacante descargar el código fuente completo de la aplicación, incluyendo posibles credenciales, claves API, configuraciones internas y lógica de negocio.",
            "size": 0,
            "content_type": "",
            "extracted": git_data.get("files", [])[:30],
            "git_data": git_data,
        }

    return None


def _extract_phpinfo(body):
    """Extract key info from phpinfo output."""
    import re
    info = []
    patterns = [
        (r'PHP Version\s*</td><td[^>]*>([^<]+)', 'PHP Version'),
        (r'System\s*</td><td[^>]*>([^<]+)', 'System'),
        (r'SERVER_SOFTWARE\s*</td><td[^>]*>([^<]+)', 'Server'),
        (r'DOCUMENT_ROOT\s*</td><td[^>]*>([^<]+)', 'Document Root'),
        (r'SERVER_ADMIN\s*</td><td[^>]*>([^<]+)', 'Server Admin'),
    ]
    for pattern, label in patterns:
        m = re.search(pattern, body)
        if m:
            info.append(f"{label}: {m.group(1).strip()}")
    return info


def _extract_wp_users(body):
    """Extract usernames from WP REST API response."""
    try:
        users = json.loads(body)
        return [f"{u.get('slug', '?')} ({u.get('name', '?')})" for u in users[:10]]
    except (json.JSONDecodeError, TypeError):
        return []


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
        raw = run_cmd(f'curl -sL --max-redirs 3 -m 10 "{wb_url}" 2>/dev/null', timeout=15)
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
    "prestashop": "cpe:2.3:a:prestashop:prestashop:{ver}:*:*:*:*:*:*:*",
    "magento": "cpe:2.3:a:magento:magento:{ver}:*:*:*:*:*:*:*",
    "typo3": "cpe:2.3:a:typo3:typo3:{ver}:*:*:*:*:*:*:*",
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
    cms_patterns = [
        (r'WordPress\s+(\d+\.\d+(?:\.\d+)?)', "WordPress", "wordpress"),
        (r'Joomla\s+(\d+\.\d+(?:\.\d+)?)', "Joomla", "joomla"),
        (r'Drupal\s+(\d+\.\d+(?:\.\d+)?)', "Drupal", "drupal"),
        (r'PrestaShop\s+(\d+\.\d+(?:\.\d+)?)', "PrestaShop", "prestashop"),
        (r'Magento\s+(\d+\.\d+(?:\.\d+)?)', "Magento", "magento"),
        (r'TYPO3\s+(\d+\.\d+(?:\.\d+)?)', "TYPO3", "typo3"),
    ]
    for pattern, label, cpe_key in cms_patterns:
        m = re.search(pattern, cms, re.I)
        if m and cpe_key in NVD_CPE_MAP:
            queries.append((f"{label} {m.group(1)}", NVD_CPE_MAP[cpe_key].format(ver=m.group(1))))
            break

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


def run_nuclei_tech(domain):
    """Run nuclei with safe technology-detection templates only.

    Uses http/technologies/ folder with strict safety flags:
    no interactsh, no CVE/exploit tags, rate-limited to 10 req/s.
    Returns list of detected technologies from JSONL output.
    """
    if not shutil.which("nuclei"):
        return {"technologies": [], "raw_matches": 0, "error": "nuclei not installed"}

    cmd = [
        "nuclei",
        "-u", f"https://{domain}",
        "-t", "http/technologies/",
        "-exclude-tags", "intrusive,dos,fuzz,oast",
        "-jsonl",
        "-silent",
        "-rate-limit", "10",
        "-timeout", "10",
        "-no-interactsh",
        "-disable-update-check",
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120
        )
        output = proc.stdout.strip()
    except subprocess.TimeoutExpired:
        return {"technologies": [], "raw_matches": 0, "error": "timeout"}
    except Exception as e:
        return {"technologies": [], "raw_matches": 0, "error": str(e)}

    technologies = []
    seen_ids = set()
    for line in output.split("\n"):
        if not line.strip():
            continue
        try:
            match = json.loads(line)
        except json.JSONDecodeError:
            continue
        tid = match.get("template-id", "")
        if tid in seen_ids:
            continue
        seen_ids.add(tid)
        info = match.get("info", {})
        extracted = match.get("extracted-results") or []
        tech = {
            "id": tid,
            "name": info.get("name", tid),
            "severity": info.get("severity", "info"),
            "tags": info.get("tags", []),
            "matched_at": match.get("matched-at", ""),
            "extracted": extracted,
        }
        technologies.append(tech)

    return {"technologies": technologies, "raw_matches": len(technologies)}


def _merge_nuclei_into_tech(tech_results, nuclei_results):
    """Merge nuclei technology detections into existing tech results."""
    if nuclei_results.get("error") or not nuclei_results.get("technologies"):
        return

    known_cms = tech_results.get("cms", "").lower()
    known_versions = {v.lower() for v in tech_results.get("version_disclosure", [])}

    nuclei_extra = []
    for t in nuclei_results["technologies"]:
        name = t["name"]
        name_lower = name.lower()

        if known_cms and known_cms.split()[0] in name_lower:
            continue
        already_known = any(name_lower in kv for kv in known_versions)
        if already_known:
            continue

        nuclei_extra.append(name)

        if not tech_results["cms"] and any(
            kw in name_lower for kw in ("wordpress", "joomla", "drupal", "prestashop", "magento", "shopify", "wix", "squarespace", "webflow", "typo3")
        ):
            tech_results["cms"] = name

    if nuclei_extra:
        tech_results.setdefault("nuclei_detected", []).extend(nuclei_extra)


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

    _detect_cms(raw, hdr_raw, results)

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


def _detect_cms(html, headers, results):
    """Detect CMS platform and extract plugins/modules/themes."""
    gen_match = re.search(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)', html, re.I)
    generator = gen_match.group(1) if gen_match else ""

    # --- WordPress ---
    if "wp-content" in html or "wp-includes" in html:
        wp_ver = ""
        m = re.search(r'WordPress\s+(\d+\.\d+(?:\.\d+)?)', generator)
        if m:
            wp_ver = m.group(1)
        if not wp_ver:
            m = re.search(r'/wp-(?:includes/js/(?:wp-util|wp-embed|wp-emoji-release)|includes/css/dist/block-library/style)[^"\']*\?ver=(\d+\.\d+(?:\.\d+)?)', html)
            if m:
                wp_ver = m.group(1)
        results["cms"] = f"WordPress {wp_ver}" if wp_ver else "WordPress"
        _extract_wp_components(html, results)
        return

    # --- Joomla ---
    if "/media/com_" in html or "/components/com_" in html or "/media/system/js" in html:
        joomla_ver = ""
        m = re.search(r'Joomla!\s*([\d.]+)', generator)
        if m:
            joomla_ver = m.group(1)
        results["cms"] = f"Joomla {joomla_ver}" if joomla_ver else "Joomla"
        _extract_joomla_components(html, results)
        return

    # --- Drupal ---
    if "/sites/default/files" in html or "Drupal.settings" in html or "/misc/drupal" in html:
        drupal_ver = ""
        m = re.search(r'Drupal\s*([\d.]+)', generator)
        if m:
            drupal_ver = m.group(1)
        results["cms"] = f"Drupal {drupal_ver}" if drupal_ver else "Drupal"
        _extract_drupal_components(html, results)
        return

    # --- PrestaShop ---
    if "/modules/ps_" in html or "prestashop" in html.lower()[:5000] or "var prestashop" in html.lower():
        ps_ver = ""
        m = re.search(r'PrestaShop\s*([\d.]+)', generator)
        if m:
            ps_ver = m.group(1)
        results["cms"] = f"PrestaShop {ps_ver}" if ps_ver else "PrestaShop"
        _extract_prestashop_components(html, results)
        return

    # --- Magento ---
    if "/static/version" in html or "Mage.Cookies" in html or "mage/cookies" in html.lower():
        results["cms"] = "Magento"
        seen = set()
        for m in re.finditer(r'/static/(?:version\d+/)?frontend/([^/]+)/([^/]+)', html):
            theme = f"{m.group(1)}/{m.group(2)}"
            if theme not in seen:
                seen.add(theme)
                results["version_disclosure"].append(f"Theme: {theme}")
        return

    # --- Shopify ---
    if "cdn.shopify.com" in html or "Shopify.theme" in html:
        results["cms"] = "Shopify"
        m = re.search(r'Shopify\.theme\s*=\s*\{[^}]*"name"\s*:\s*"([^"]+)"', html)
        if m:
            results["version_disclosure"].append(f"Theme: {m.group(1)}")
        return

    # --- Wix ---
    if "static.wixstatic.com" in html or "wix-code-sdk" in html:
        results["cms"] = "Wix"
        return

    # --- Squarespace ---
    if "squarespace.com" in html and ("Static.SQUARESPACE" in html or "sqs-" in html):
        results["cms"] = "Squarespace"
        return

    # --- Webflow ---
    if "assets.website-files.com" in html or "webflow" in html.lower()[:3000]:
        wf = re.search(r'data-wf-site="([^"]+)"', html)
        if wf or "Webflow" in generator:
            results["cms"] = "Webflow"
            return

    # --- TYPO3 ---
    if "/typo3conf/" in html or "/typo3temp/" in html:
        results["cms"] = "TYPO3"
        seen = set()
        for m in re.finditer(r'/typo3conf/ext/([a-zA-Z0-9_-]+)', html):
            ext = m.group(1)
            if ext not in seen:
                seen.add(ext)
                results["plugins"].append(ext.replace("_", " ").title())
                results["version_disclosure"].append(f"Extension: {ext}")
        return

    # --- Fallback: use generator tag ---
    if generator:
        clean = generator.split(";")[0].strip()
        results["cms"] = clean


def _extract_wp_components(html, results):
    """Extract WordPress plugins and themes."""
    seen = set()
    for m in re.finditer(
        r'/wp-content/plugins/([a-zA-Z0-9_-]+)(?:/[^"\']*?(?:ver(?:sion)?=|v=)([0-9][0-9.]+))?', html, re.I
    ):
        slug = m.group(1)
        ver = m.group(2) or ""
        if slug not in seen:
            seen.add(slug)
            label = slug.replace("-", " ").title()
            if ver:
                label += f" {ver}"
            results["plugins"].append(label)
            results["version_disclosure"].append(f"Plugin: {slug}" + (f" v{ver}" if ver else ""))
    themes_seen = set()
    for m in re.finditer(r'/wp-content/themes/([a-zA-Z0-9_-]+)', html, re.I):
        t = m.group(1)
        if t not in themes_seen:
            themes_seen.add(t)
            results["version_disclosure"].append(f"Theme: {t}")


def _extract_joomla_components(html, results):
    """Extract Joomla components, modules and templates."""
    seen = set()
    for m in re.finditer(r'/components/(com_[a-zA-Z0-9_]+)', html):
        comp = m.group(1)
        if comp not in seen:
            seen.add(comp)
            results["plugins"].append(comp.replace("com_", "").replace("_", " ").title())
            results["version_disclosure"].append(f"Component: {comp}")
    for m in re.finditer(r'/modules/(mod_[a-zA-Z0-9_]+)', html):
        mod = m.group(1)
        if mod not in seen:
            seen.add(mod)
            results["plugins"].append(mod.replace("mod_", "").replace("_", " ").title())
            results["version_disclosure"].append(f"Module: {mod}")
    for m in re.finditer(r'/templates/([a-zA-Z0-9_-]+)', html):
        t = m.group(1)
        if t not in ("system",) and t not in seen:
            seen.add(t)
            results["version_disclosure"].append(f"Template: {t}")


def _extract_drupal_components(html, results):
    """Extract Drupal modules and themes."""
    seen = set()
    for m in re.finditer(r'/modules/(?:contrib/)?([a-zA-Z0-9_-]+)', html):
        mod = m.group(1)
        if mod not in ("system", "node", "user", "field") and mod not in seen:
            seen.add(mod)
            results["plugins"].append(mod.replace("_", " ").replace("-", " ").title())
            results["version_disclosure"].append(f"Module: {mod}")
    for m in re.finditer(r'/themes/(?:contrib/)?([a-zA-Z0-9_-]+)', html):
        t = m.group(1)
        if t not in seen:
            seen.add(t)
            results["version_disclosure"].append(f"Theme: {t}")


def _extract_prestashop_components(html, results):
    """Extract PrestaShop modules."""
    seen = set()
    for m in re.finditer(r'/modules/([a-zA-Z0-9_-]+)', html):
        mod = m.group(1)
        if mod not in seen:
            seen.add(mod)
            results["plugins"].append(mod.replace("_", " ").replace("-", " ").title())
            results["version_disclosure"].append(f"Module: {mod}")


def _render_page(domain, timeout_ms=12000):
    """Load page with Playwright to get JS-rendered DOM. Returns (html, ok)."""
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                ignore_https_errors=True,
            )
            page = ctx.new_page()
            resp = page.goto(f"https://{domain}", wait_until="networkidle", timeout=timeout_ms)
            status = resp.status if resp else 0
            html = page.content()
            browser.close()
            if status in (403, 401, 503) or len(html) < 2000:
                return html, False
            return html, True
    except Exception:
        return "", False


def check_compliance(domain):
    """Check GDPR/LSSI-CE compliance signals using headless browser + curl, merged."""
    results = {
        "raw": "", "score": 10, "checks": {},
        "cookie_banner": False, "privacy_policy": False,
        "legal_notice": False, "security_txt": False, "robots_txt": False,
    }

    curl_html = run_cmd(f'curl -sL -m 10 https://{domain}')
    rendered, render_ok = _render_page(domain)

    sources = []
    if render_ok and rendered:
        sources.append(("rendered", rendered))
        results["raw"] += f"--- rendered DOM ({len(rendered)} bytes) ---\n"
    if curl_html:
        sources.append(("curl", curl_html))
        results["raw"] += f"--- curl ({len(curl_html)} bytes) ---\n"

    home = "\n".join(html for _, html in sources)
    home_lower = home.lower()

    cookie_keywords = [
        "cookie", "galleta", "consentimiento", "consent", "cookiebot",
        "cookie-banner", "cookie-notice", "gdpr", "rgpd", "onetrust",
        "cookie-law", "tarteaucitron", "klaro", "cc-window", "cc-banner",
        "cookies-eu", "cookie-consent", "cookieconsent", "iubenda",
        "quantcast", "termly", "complianz", "moove_gdpr", "cmplz",
    ]
    results["cookie_banner"] = any(kw in home_lower for kw in cookie_keywords)
    results["checks"]["cookie_banner"] = "Detectado" if results["cookie_banner"] else "No verificado"
    if not results["cookie_banner"]:
        results["score"] -= 3

    all_hrefs = re.findall(r'href="([^"]*)"', home, re.I)
    all_hrefs_lower = [h.lower() for h in all_hrefs]

    privacy_href_kw = ["privac", "proteccion-de-datos", "datos-personales"]
    pp_found = any(any(kw in h for kw in privacy_href_kw) for h in all_hrefs_lower)
    if pp_found:
        match = next(h for h in all_hrefs if any(kw in h.lower() for kw in privacy_href_kw))
        results["raw"] += f"Privacy link found: {match}\n"
    if not pp_found:
        privacy_paths = ["/politica-privacidad", "/privacy-policy", "/privacidad",
                         "/politica-de-privacidad", "/privacy", "/politica-de-cookies",
                         "/cookies", "/proteccion-de-datos"]
        for path in privacy_paths:
            r = run_cmd(f'curl -sI -L -m 5 https://{domain}{path} 2>/dev/null')
            if "200" in r.split("\n")[0] if r else "":
                pp_found = True
                results["raw"] += f"Privacy policy found at {path}\n"
                break
    results["privacy_policy"] = pp_found
    results["checks"]["privacy_policy"] = "Presente" if pp_found else "No verificada"
    if not pp_found:
        results["score"] -= 3

    legal_href_kw = ["aviso-legal", "aviso_legal", "legal-notice", "/legal", "/terminos",
                     "/terms", "/condiciones", "nota-legal", "informacion-legal"]
    legal_found = any(any(kw in h for kw in legal_href_kw) for h in all_hrefs_lower)
    if legal_found:
        match = next(h for h in all_hrefs if any(kw in h.lower() for kw in legal_href_kw))
        results["raw"] += f"Legal link found: {match}\n"
    if not legal_found:
        legal_paths = ["/aviso-legal", "/legal", "/aviso-legal-y-condiciones",
                       "/terminos", "/terms", "/condiciones-de-uso", "/nota-legal",
                       "/informacion-legal", "/terminos-y-condiciones"]
        for path in legal_paths:
            r = run_cmd(f'curl -sI -L -m 5 https://{domain}{path} 2>/dev/null')
            if "200" in r.split("\n")[0] if r else "":
                legal_found = True
                results["raw"] += f"Legal notice found at {path}\n"
                break
    results["legal_notice"] = legal_found
    results["checks"]["legal_notice"] = "Presente" if legal_found else "No verificado"
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
        "leakix": lambda: check_leakix(domain),
        "tech": lambda: check_tech(domain),
        "nuclei": lambda: run_nuclei_tech(domain),
        "emails": lambda: harvest_emails(domain),
        "compliance": lambda: check_compliance(domain),
        "sensitive_paths": lambda: check_sensitive_paths(domain),
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

    # Reconcile LeakIX GitConfigHttpPlugin with sensitive_paths git check
    lix_plugins = set()
    lix_data = results.get("leakix", {})
    for lk in lix_data.get("leaks", []):
        lix_plugins.add(lk.get("plugin", ""))
    sp_data = results.get("sensitive_paths", {})
    sp_cats = {f.get("category") for f in sp_data.get("findings", [])}
    if "GitConfigHttpPlugin" in lix_plugins and "git_exposed" not in sp_cats:
        git_reconciled = False
        for scheme in ["https", "http"]:
            head_raw = run_cmd(
                f'curl -sk -o /dev/null -w "%{{http_code}}" '
                f'-H "User-Agent: Mozilla/5.0" "{scheme}://{domain}/.git/HEAD" -m 10'
            )
            head_body = ""
            if head_raw.strip() == "200":
                head_body = run_cmd(
                    f'curl -sk -H "User-Agent: Mozilla/5.0" "{scheme}://{domain}/.git/HEAD" -m 10'
                ).strip()
            head_ok = head_body.startswith("ref:") or re.match(r'^[0-9a-f]{40}$', head_body or "")
            if head_ok:
                sp_data.setdefault("findings", []).append({
                    "category": "git_exposed",
                    "path": "/.git/HEAD",
                    "url": f"{scheme}://{domain}/.git/",
                    "title": "Repositorio Git (.git) expuesto públicamente",
                    "severity": "alta",
                    "justification": "Se ha verificado el acceso directo al archivo .git/HEAD, confirmando que el contenido del repositorio es descargable. Un atacante puede reconstruir el código fuente completo.",
                    "risk": "La exposición del directorio .git permite a cualquier atacante descargar el código fuente completo de la aplicación.",
                    "size": 0, "content_type": "", "extracted": [],
                    "git_data": {"exposed": True, "head_ref": head_body, "base_url": f"{scheme}://{domain}"},
                })
                git_reconciled = True
                break
            elif head_raw.strip() and head_raw.strip() != "000":
                sp_data.setdefault("findings", []).append({
                    "category": "git_exposed",
                    "path": "/.git/HEAD",
                    "url": f"{scheme}://{domain}/.git/",
                    "title": "Directorio .git detectado (acceso parcial)",
                    "severity": "media",
                    "justification": "Motores de búsqueda de seguridad han indexado el directorio .git, pero no se ha podido verificar el acceso al archivo HEAD. El repositorio podría estar parcialmente protegido o haber sido remediado recientemente.",
                    "risk": "La presencia del directorio .git indica que existe o existió un repositorio de código accesible. Aunque el acceso directo no se ha confirmado, la información indexada puede seguir disponible en cachés de terceros.",
                    "size": 0, "content_type": "", "extracted": [],
                    "git_data": {"exposed": False, "base_url": f"{scheme}://{domain}"},
                })
                git_reconciled = True
                break
        if not git_reconciled:
            sp_data.setdefault("findings", []).append({
                "category": "git_exposed",
                "path": "/.git/",
                "url": f"https://{domain}/.git/",
                "title": "Directorio .git indexado por motores de seguridad",
                "severity": "media",
                "justification": "Motores de búsqueda de seguridad (LeakIX) han confirmado la exposición del directorio .git en este dominio. No se ha podido verificar el acceso directo en este momento (servidor no disponible o conexión rechazada), pero la información indexada puede seguir disponible en cachés de terceros.",
                "risk": "La presencia del directorio .git indica que existe o existió un repositorio de código accesible públicamente, exponiendo potencialmente código fuente, credenciales y lógica de negocio.",
                "size": 0, "content_type": "", "extracted": [],
                "git_data": {"exposed": False, "base_url": f"https://{domain}"},
            })

    nuclei_data = results.pop("nuclei", {})
    if "tech" in results:
        _merge_nuclei_into_tech(results["tech"], nuclei_data)

    for name, data in results.items():
        raw = data.get("raw", "")
        if raw:
            (evidence_dir / f"{name}.txt").write_text(
                raw if isinstance(raw, str) else json.dumps(raw, indent=2)
            )

    if nuclei_data.get("technologies"):
        (evidence_dir / "nuclei.json").write_text(
            json.dumps(nuclei_data, indent=2, default=str)
        )

    if "subdomains" in results and results["subdomains"].get("subdomains"):
        (evidence_dir / "subdomains.json").write_text(
            json.dumps(results["subdomains"]["subdomains"], indent=2)
        )
    if "shodan" in results and results["shodan"].get("raw"):
        (evidence_dir / "shodan.json").write_text(results["shodan"]["raw"])
    if "leakix" in results:
        lix_evidence = {k: v for k, v in results["leakix"].items() if k != "raw"}
        if lix_evidence.get("leak_count", 0) > 0 or lix_evidence.get("service_count", 0) > 0:
            (evidence_dir / "leakix.json").write_text(
                json.dumps(lix_evidence, indent=2, ensure_ascii=False, default=str)
            )
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
    if "sensitive_paths" in results:
        sp_evidence = {k: v for k, v in results["sensitive_paths"].items() if k != "raw"}
        for f in sp_evidence.get("findings", []):
            f.pop("body_preview", None)
        (evidence_dir / "sensitive_paths.json").write_text(
            json.dumps(sp_evidence, indent=2, default=str)
        )

    lix = results.get("leakix", {})
    lix_has_data = lix.get("leak_count", 0) > 0 or lix.get("service_count", 0) > 0

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
        "misconfig": results.get("sensitive_paths", {}).get("score", 10),
    }
    if lix_has_data:
        scores["leakix"] = lix.get("score", 10)

    if lix_has_data:
        weights = {
            "headers": 0.05, "tech": 0.10, "tls": 0.05, "dns": 0.10,
            "exposure": 0.10, "leakix": 0.10, "breach": 0.10,
            "compliance": 0.15, "misconfig": 0.25,
        }
    else:
        weights = {
            "headers": 0.05, "tech": 0.15, "tls": 0.05, "dns": 0.10,
            "exposure": 0.10, "breach": 0.15, "compliance": 0.15, "misconfig": 0.25,
        }
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

    def _build_exposure_detail(res):
        sub = res.get("subdomains", {})
        sh = res.get("shodan", {})
        parts = []
        subs = sub.get("subdomains", [])
        notable = sub.get("notable", [])
        if subs:
            parts.append(f"{len(subs)} subdominios detectados")
            if notable:
                parts.append(f"notables: {', '.join(notable[:8])}")
        ports = sh.get("ports", [])
        if ports:
            parts.append(f"puertos abiertos: {', '.join(str(p) for p in ports)}")
        vulns = sh.get("vulns", [])
        if vulns:
            parts.append(f"{len(vulns)} CVEs conocidos ({', '.join(vulns[:5])})")
        hostnames = sh.get("hostnames", [])
        if hostnames:
            parts.append(f"hostnames: {', '.join(hostnames[:5])}")
        return "; ".join(parts) if parts else ""

    lix_detail = ""
    if lix_has_data:
        lix_parts = []
        if lix.get("leak_count", 0) > 0:
            lix_parts.append(f"{lix['leak_count']} exposiciones confirmadas")
            sev_bd = lix.get("severity_breakdown", {})
            if sev_bd:
                lix_parts.append(", ".join(f"{v} {k}" for k, v in sev_bd.items()))
        if lix.get("plugins_detected"):
            lix_parts.append(f"plugins: {', '.join(lix['plugins_detected'][:5])}")
        lix_detail = "; ".join(lix_parts)

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
            "exposure": _build_exposure_detail(results),
            "leakix": lix_detail,
        },
    }

    (output_path / "scoring" / "scores.json").write_text(json.dumps(scoring, indent=2))

    results["scoring"] = scoring

    _save_recon_completo(results, domain, company, sector, scoring, evidence_dir, nuclei_data)

    return results


def _save_recon_completo(results, domain, company, sector, scoring, evidence_dir, nuclei_data):
    """Build and save a comprehensive, classified recon report to evidence/recon_completo.json."""
    headers = results.get("headers", {})
    tech = results.get("tech", {})
    tls_data = results.get("tls", {})
    dns = results.get("dns", {})
    subs = results.get("subdomains", {})
    shodan = results.get("shodan", {})
    lix = results.get("leakix", {})
    emails = results.get("emails", {})
    breach = results.get("breach", {})
    compliance = results.get("compliance", {})
    sp = results.get("sensitive_paths", {})

    sensitive_patterns = [
        ".env", "config", "password", "secret", "credential", "key",
        "token", "database", "wp-config", "settings.py", "application.yml",
        ".pem", ".p12", "id_rsa", "htpasswd", ".sql", "docker-compose",
    ]

    lix_services = lix.get("services", [])
    lix_leaks = lix.get("leaks", [])
    geos = {}
    networks = {}
    ips_seen = set()
    for item in lix_services + lix_leaks:
        ip = item.get("ip", "")
        if ip and ip not in ips_seen:
            ips_seen.add(ip)
            if item.get("geoip"):
                geos[ip] = item["geoip"]
            if item.get("network"):
                networks[ip] = item["network"]

    ports_lix = sorted(set(item.get("port", "") for item in lix_services if item.get("port")))
    ports_shodan = [str(p) for p in shodan.get("ports", [])]
    all_ports = sorted(set(ports_lix + ports_shodan), key=lambda x: int(x) if x.isdigit() else 0)

    sp_findings = sp.get("findings", [])
    git_data = sp.get("git_exposed", {})

    classified_findings = {"critica": [], "alta": [], "media": []}
    for f in sp_findings:
        entry = {
            "categoria": f.get("category", ""),
            "titulo": f.get("title", ""),
            "url": f.get("url", ""),
            "severidad": f.get("severity", "media"),
            "riesgo": f.get("risk", ""),
            "datos_extraidos": f.get("extracted", []),
        }
        if f.get("category") == "git_exposed" and git_data:
            entry["repositorio"] = {
                "head": git_data.get("head_ref", ""),
                "remote_url": git_data.get("config", {}).get("remote_url", ""),
                "descripcion": git_data.get("description", ""),
                "archivos_total": git_data.get("file_count", len(git_data.get("files", []))),
                "archivos": git_data.get("files", []),
                "archivos_sensibles": git_data.get("sensitive_files", []),
                "extensiones": git_data.get("file_extensions", {}),
                "directorios": git_data.get("directories", []),
                "refs": git_data.get("refs", []),
                "commits": git_data.get("log_entries", []),
                "objects_accesibles": git_data.get("objects_accessible", False),
                "fetch_head": git_data.get("fetch_head", ""),
            }
        sev = f.get("severity", "media")
        classified_findings.get(sev, classified_findings["media"]).append(entry)

    lix_classified = {"critica": [], "alta": [], "media": [], "baja": [], "info": []}
    sev_map_lix = {"critical": "critica", "high": "alta", "medium": "media", "low": "baja", "info": "info"}
    for lk in lix_leaks:
        entry = {
            "plugin": lk.get("plugin", ""),
            "etiqueta": LEAKIX_PLUGIN_LABELS.get(lk.get("plugin", ""), lk.get("plugin", "")),
            "severidad": lk.get("severity", "info"),
            "etapa": lk.get("stage", ""),
            "tipo": lk.get("type", ""),
            "resumen": lk.get("summary", ""),
            "ip": lk.get("ip", ""),
            "host": lk.get("host", ""),
            "puerto": lk.get("port", ""),
            "protocolo": lk.get("protocol", ""),
            "transporte": lk.get("transport", []),
            "fecha": lk.get("time", ""),
            "tags": lk.get("tags", []),
            "sin_autenticacion": lk.get("noauth", False),
            "dataset": lk.get("dataset", {}),
        }
        if lk.get("http"):
            entry["http"] = lk["http"]
        if lk.get("software"):
            entry["software"] = lk["software"]
        if lk.get("geoip"):
            entry["geoip"] = lk["geoip"]
        if lk.get("network"):
            entry["network"] = lk["network"]
        sev_es = sev_map_lix.get(lk.get("severity", "info"), "info")
        lix_classified[sev_es].append(entry)
    lix_classified = {k: v for k, v in lix_classified.items() if v}

    nuclei_techs = nuclei_data.get("technologies", []) if nuclei_data else []
    tech_detected = []
    _seen_tech = set()

    def _add_tech(entry):
        key = entry.get("nombre", "").lower().split("/")[0].strip()
        if key and key in _seen_tech:
            return
        if key:
            _seen_tech.add(key)
        tech_detected.append(entry)

    if tech.get("cms"):
        _add_tech({"tipo": "CMS", "nombre": tech["cms"], "version": tech.get("cms_version", "")})
    if tech.get("server"):
        _add_tech({"tipo": "Servidor Web", "nombre": tech["server"]})
    if tech.get("powered_by"):
        _add_tech({"tipo": "Framework", "nombre": tech["powered_by"]})
    for vd in tech.get("version_disclosure", []):
        name_base = vd.split("/")[0].strip().lower()
        if name_base not in _seen_tech:
            _add_tech({"tipo": "Version Disclosure", "nombre": vd})
    for eol in tech.get("eol_software", []):
        _add_tech({"tipo": "EOL Software", "nombre": eol.get("name", ""), "eol_date": eol.get("eol_date", ""), "riesgo": "alto"})
    for nt in nuclei_techs:
        _add_tech({"tipo": "Nuclei Detection", "nombre": nt.get("name", ""), "matched_at": nt.get("matched_at", "")})
    for sw_item in lix_services:
        if sw_item.get("software"):
            _add_tech({
                "tipo": "LeakIX Service",
                "nombre": sw_item["software"],
                "version": sw_item.get("version", ""),
                "puerto": sw_item.get("port", ""),
                "os": sw_item.get("os", ""),
                "modulos": sw_item.get("modules", []),
            })

    cve_findings = tech.get("cve_findings", [])
    shodan_cves = set(shodan.get("vulns", []))
    cves = []
    seen_cve_ids = set()
    for cf in cve_findings:
        sample = cf.get("cves", [])[:20]
        for c in sample:
            cid = c[0] if isinstance(c, (list, tuple)) else c.get("id", "")
            seen_cve_ids.add(cid)
        cves.append({
            "software": cf.get("software", ""),
            "version": cf.get("version", ""),
            "cves_total": cf.get("cves_total", 0),
            "criticos": cf.get("critical", 0),
            "altos": cf.get("high", 0),
            "cves": sample,
        })
    shodan_only_cves = sorted(shodan_cves - seen_cve_ids)
    if shodan_only_cves:
        cves.append({
            "software": "Shodan (sin atribuir)",
            "version": "",
            "cves_total": len(shodan_only_cves),
            "criticos": 0,
            "altos": 0,
            "cves": shodan_only_cves,
        })

    lix_plugins_set = set(lix.get("plugins_detected", []))
    plugin_to_sp_cat = {
        "GitConfigHttpPlugin": "git_exposed",
        "DotEnvConfigPlugin": "env_file",
        "DotDsStoreOpenPlugin": "ds_store",
        "PhpInfoHttpPlugin": "phpinfo",
        "ApacheStatusPlugin": "server_status",
        "WpUserEnumHttp": "wp_user_enum",
    }
    sp_cats_covered_by_lix = set()
    for plugin, sp_cat in plugin_to_sp_cat.items():
        if plugin in lix_plugins_set:
            sp_cats_covered_by_lix.add(sp_cat)

    for sev_key in classified_findings:
        classified_findings[sev_key] = [
            f for f in classified_findings[sev_key]
            if f.get("categoria") not in sp_cats_covered_by_lix
        ]

    breached_emails = breach.get("breached_emails", [])
    all_emails = emails.get("emails", [])
    email_sources = emails.get("sources", {})

    shodan_hostnames = set(shodan.get("hostnames", []))
    sub_list = subs.get("subdomains", [])
    shodan_only_hostnames = sorted(shodan_hostnames - set(sub_list))

    report = {
        "meta": {
            "dominio": domain,
            "empresa": company,
            "sector": sector,
            "fecha": datetime.utcnow().isoformat(),
            "version": "2.0",
        },
        "puntuacion": {
            "total": scoring.get("total", 0),
            "grado": scoring.get("grade", "?"),
            "categorias": scoring.get("scores", {}),
        },
        "infraestructura": {
            "ips": sorted(ips_seen),
            "puertos_abiertos": all_ports,
            "servicios": [{k: v for k, v in s.items() if k != "tags"} for s in lix_services],
            "geolocalizacion": geos,
            "redes": networks,
            "subdominios": {
                "total": len(sub_list) + len(shodan_only_hostnames),
                "lista": sub_list,
                "solo_shodan": shodan_only_hostnames,
                "notables": subs.get("notable", []),
            },
        },
        "tecnologias": {
            "detecciones": tech_detected,
            "cves_conocidos": cves,
            "js_libraries": tech.get("js_libs", []),
            "meta_generator": tech.get("meta_generator", ""),
        },
        "seguridad_web": {
            "cabeceras": {
                "puntuacion": headers.get("score", 0),
                "presentes": headers.get("present", []),
                "ausentes": headers.get("missing", []),
                "csp": headers.get("csp", ""),
                "hsts": headers.get("hsts", ""),
            },
            "tls": {
                "puntuacion": tls_data.get("score", 0),
                "grado": tls_data.get("tls_grade", ""),
                "score_tls": tls_data.get("tls_score", 0),
                "componentes": tls_data.get("tls_components", {}),
                "certificado": {
                    "estado": tls_data.get("cert_status", ""),
                    "emisor": tls_data.get("issuer", ""),
                    "expira": tls_data.get("expires", ""),
                    "san": tls_data.get("san", []),
                },
                "protocolos_legacy": tls_data.get("legacy_tls", []),
                "vulnerabilidades": tls_data.get("vulnerabilities", []),
            },
            "dns": {
                "puntuacion": dns.get("score", 0),
                "spf": dns.get("spf", ""),
                "dmarc": dns.get("dmarc", ""),
                "mx": dns.get("mx", []),
                "ns": dns.get("ns", []),
                "caa": dns.get("caa", []),
            },
            "compliance": {
                "puntuacion": compliance.get("score", 0),
                "checks": compliance.get("checks", {}),
            },
        },
        "exposiciones": {
            "rutas_sensibles": {
                "puntuacion": sp.get("score", 10),
                "total_hallazgos": len(sp_findings),
                "por_severidad": classified_findings,
            },
            "leakix": {
                "puntuacion": lix.get("score", 10),
                "total_leaks": lix.get("leak_count", 0),
                "total_servicios": lix.get("service_count", 0),
                "severidad": lix.get("severity_breakdown", {}),
                "plugins_detectados": lix.get("plugins_detected", []),
                "plugin_detalle": lix.get("plugin_details", []),
                "hallazgos_por_severidad": lix_classified,
            },
        },
        "emails_y_brechas": {
            "emails_encontrados": {
                "total": len(all_emails),
                "lista": all_emails,
                "fuentes": email_sources,
            },
            "brechas": {
                "puntuacion": breach.get("score", 7),
                "total_brechas": breach.get("breach_count", 0),
                "nombres_brechas": breach.get("breaches", []),
                "emails_afectados": [
                    {
                        "email": be.get("email", ""),
                        "brechas": be.get("breaches", []),
                        "total": be.get("count", 0),
                        "fuente": be.get("source", "confirmed"),
                    }
                    for be in breached_emails
                ],
                "personas_investigadas": breach.get("people_checked", 0),
                "linkedin_confirmados": breach.get("linkedin_confirmed", []),
            },
        },
    }

    if git_data and git_data.get("exposed"):
        report["repositorio_git_expuesto"] = {
            "url": git_data.get("base_url", "") + "/.git/",
            "head": git_data.get("head_ref", ""),
            "remote_url": git_data.get("config", {}).get("remote_url", ""),
            "config_raw": git_data.get("config", {}).get("raw", "")[:1000],
            "descripcion": git_data.get("description", ""),
            "archivos": {
                "total": git_data.get("file_count", len(git_data.get("files", []))),
                "lista_completa": git_data.get("files", []),
                "sensibles": git_data.get("sensitive_files", []),
                "extensiones": git_data.get("file_extensions", {}),
                "directorios": git_data.get("directories", []),
            },
            "refs": git_data.get("refs", []),
            "commits": git_data.get("log_entries", []),
            "objects_accesibles": git_data.get("objects_accessible", False),
            "fetch_head": git_data.get("fetch_head", ""),
        }

    (evidence_dir / "recon_completo.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False, default=str)
    )


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
        "leakix": "Data Exposures (LeakIX)",
        "breach": "Breach History",
        "compliance": "RGPD/LSSI Compliance",
        "misconfig": "Sensitive Files/Misconfig",
    }
    for key, label in labels.items():
        if key not in scores:
            continue
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

    lix = results.get("leakix", {})
    if lix.get("leak_count", 0) > 0:
        sev = lix.get("severity_breakdown", {})
        sev_str = ", ".join(f"{k}: {v}" for k, v in sev.items())
        print(f"  LeakIX: {lix['leak_count']} leaks ({sev_str})")
        if lix.get("plugins_detected"):
            print(f"    Plugins: {', '.join(lix['plugins_detected'][:5])}")
    elif "LEAKIX_API_KEY" not in os.environ:
        print(f"  LeakIX: skipped (no API key)")

    tech = results.get("tech", {})
    if tech.get("cms"):
        print(f"  CMS: {tech['cms']}")
    if tech.get("nuclei_detected"):
        print(f"  Nuclei tech ({len(tech['nuclei_detected'])}): {', '.join(tech['nuclei_detected'][:10])}")

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

    sp = results.get("sensitive_paths", {})
    if sp.get("findings"):
        print(f"\n  ⚠ SENSITIVE PATHS FOUND: {len(sp['findings'])}")
        for f in sp["findings"]:
            print(f"    [{f['severity'].upper()}] {f['title']} — {f['url']}")

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
