# Passive OSINT Recon Checklist

All checks are **strictly passive** — no exploitation, no scanning, no authenticated access.

## Automated (via tools/passive_recon.py)

- [ ] Security headers (curl -sI)
- [ ] TLS/SSL version, certificate expiry, legacy protocol support
- [ ] DNS: SPF, DMARC, MX, DNSSEC
- [ ] Subdomain enumeration (crt.sh Certificate Transparency)
- [ ] Shodan InternetDB (public port/vuln data)
- [ ] Technology detection (response headers + HTML meta)

## Manual enrichment (after automated scan)

- [ ] HaveIBeenPwned domain check (if API key available)
- [ ] LinkedIn: identify IT staff / CISO presence
- [ ] Google dorking: `site:{domain} filetype:pdf|xls|doc`
- [ ] Wayback Machine: check for exposed admin panels, old pages
- [ ] security.txt: `curl -s https://{domain}/.well-known/security.txt`
- [ ] robots.txt: interesting disallowed paths
- [ ] Cookie flags: Secure, HttpOnly, SameSite on session cookies

## Legal boundaries — NEVER do these

- Port scanning (nmap, masscan, naabu)
- Vulnerability scanning (nuclei, nikto, OpenVAS)
- Directory brute-force (ffuf, gobuster, dirbuster)
- Login attempts or credential testing
- Fuzzing of any kind
- Accessing authenticated areas
- Subdomain takeover attempts (even verification)
- Active exploitation of any finding

## Scoring guide

| Area | 10 (perfect) | 7 (good) | 4 (poor) | 1 (critical) |
|------|-------------|----------|----------|--------------|
| Headers | All 6 present + well configured | 4-5 present | 2-3 present | 0-1 present |
| TLS | TLS 1.3, valid cert, no legacy | TLS 1.2, valid cert | Cert issues or TLS 1.1 | Expired cert or TLS 1.0 |
| DNS/Email | SPF+DMARC(reject)+DNSSEC | SPF+DMARC(quarantine) | SPF only or DMARC=none | No SPF, no DMARC |
| Exposure | <10 subs, no unusual ports | <20 subs, standard ports | Notable subs, some ports | Admin panels, DBs exposed |
| Breach | No breaches found | Old breaches (>3yr) | Recent breaches | Active/multiple breaches |
