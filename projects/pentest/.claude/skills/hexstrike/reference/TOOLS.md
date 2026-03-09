# HexStrike AI - Complete Tool Reference

150+ security tools organized by category with MCP function signatures.

## Network & Reconnaissance (25+)

| Tool | MCP Function | Purpose |
|------|-------------|---------|
| Nmap | `nmap_scan(target, options)` | Port scanning, service detection |
| Rustscan | `rustscan_scan(target, options)` | Fast port scanning |
| Masscan | `masscan_scan(target, options)` | Mass IP port scanning |
| AutoRecon | `autorecon_scan(target)` | Automated recon pipeline |
| Amass | `amass_enum(domain, options)` | Subdomain enumeration |
| Subfinder | `subfinder_scan(domain)` | Fast subdomain discovery |
| Fierce | `fierce_scan(domain)` | DNS reconnaissance |
| DNSEnum | `dnsenum_scan(domain)` | DNS enumeration |
| TheHarvester | `theharvester_scan(domain)` | Email/subdomain gathering |
| ARP-Scan | `arp_scan(interface)` | Local network discovery |
| NBTScan | `nbtscan(target)` | NetBIOS scanning |
| RPCClient | `rpcclient(target)` | RPC enumeration |
| Enum4linux | `enum4linux(target)` | SMB/Samba enumeration |
| Enum4linux-ng | `enum4linux_ng(target)` | Modern SMB enumeration |
| SMBMap | `smbmap(target)` | SMB share enumeration |
| Responder | `responder(interface)` | LLMNR/NBT-NS poisoning |
| NetExec | `netexec(target, protocol)` | Network protocol testing |

## Web Application Security (40+)

| Tool | MCP Function | Purpose |
|------|-------------|---------|
| Gobuster | `gobuster_scan(url, wordlist)` | Directory brute-force |
| Feroxbuster | `feroxbuster_scan(url)` | Recursive content discovery |
| Dirsearch | `dirsearch_scan(url)` | Web path discovery |
| FFuf | `ffuf_scan(url, wordlist)` | Fast web fuzzer |
| Dirb | `dirb_scan(url)` | URL brute-force |
| HTTPx | `httpx_scan(targets)` | HTTP probing & tech detect |
| Katana | `katana_crawl(url)` | Web crawler |
| Hakrawler | `hakrawler_crawl(url)` | Web crawler |
| Gau | `gau_fetch(domain)` | Known URLs from archives |
| Waybackurls | `waybackurls_fetch(domain)` | Wayback Machine URLs |
| Nuclei | `nuclei_scan(target, templates)` | Template-based vuln scanner |
| Nikto | `nikto_scan(target)` | Web server scanner |
| SQLMap | `sqlmap_scan(url, params)` | SQL injection testing |
| WPScan | `wpscan(url)` | WordPress vulnerability scanner |
| Arjun | `arjun_scan(url)` | Hidden parameter discovery |
| ParamSpider | `paramspider_scan(domain)` | URL parameter mining |
| X8 | `x8_scan(url)` | Hidden parameter discovery |
| Jaeles | `jaeles_scan(url)` | Security testing framework |
| Dalfox | `dalfox_scan(url, params)` | XSS scanner |
| Wafw00f | `wafw00f_scan(url)` | WAF detection |
| TestSSL | `testssl_scan(host)` | SSL/TLS testing |
| SSLScan | `sslscan(host)` | SSL cipher analysis |
| SSLyze | `sslyze_scan(host)` | SSL configuration audit |
| Whatweb | `whatweb_scan(url)` | Technology fingerprinting |
| JWT-Tool | `jwt_tool(token)` | JWT analysis & attacks |
| Wfuzz | `wfuzz_scan(url, payload)` | Web fuzzer |
| Commix | `commix_scan(url)` | Command injection testing |
| NoSQLMap | `nosqlmap_scan(url)` | NoSQL injection testing |
| Tplmap | `tplmap_scan(url)` | Template injection testing |

## Authentication & Credentials (12+)

| Tool | MCP Function | Purpose |
|------|-------------|---------|
| Hydra | `hydra_attack(target, service)` | Online brute-force |
| John the Ripper | `john_crack(hashfile)` | Password cracking |
| Hashcat | `hashcat_crack(hashfile, mode)` | GPU password cracking |
| Medusa | `medusa_attack(target)` | Parallel login brute-force |
| Patator | `patator_attack(module, target)` | Multi-purpose brute-force |
| Hash-Identifier | `hash_identify(hash)` | Hash type identification |
| HashID | `hashid_identify(hash)` | Hash type detection |
| Evil-WinRM | `evil_winrm(target)` | WinRM shell access |

## Binary Analysis & Reverse Engineering (25+)

| Tool | MCP Function | Purpose |
|------|-------------|---------|
| GDB | `gdb_debug(binary, commands)` | Debugging |
| GDB-PEDA | `gdb_peda(binary)` | Enhanced GDB for exploitation |
| GDB-GEF | `gdb_gef(binary)` | GDB Enhanced Features |
| Radare2 | `radare2_analyze(binary)` | Reverse engineering framework |
| Ghidra | `ghidra_analyze(binary)` | Decompilation & analysis |
| Binwalk | `binwalk_analyze(file)` | Firmware/embedded analysis |
| ROPgadget | `ropgadget_find(binary)` | ROP chain generation |
| Ropper | `ropper_find(binary)` | ROP/JOP/SOP gadget finder |
| One-Gadget | `one_gadget(libc)` | One-shot exploit gadgets |
| Checksec | `checksec_check(binary)` | Binary protections check |
| Pwntools | `pwntools_run(script)` | CTF/exploit development |
| Angr | `angr_analyze(binary)` | Symbolic execution |
| Volatility | `volatility_analyze(dump)` | Memory forensics |
| MSFVenom | `msfvenom_generate(payload)` | Payload generation |

## Cloud & Container Security (20+)

| Tool | MCP Function | Purpose |
|------|-------------|---------|
| Prowler | `prowler_assess(provider)` | Cloud security assessment |
| Scout Suite | `scout_suite_scan(provider)` | Multi-cloud auditing |
| Pacu | `pacu_exploit(module)` | AWS exploitation framework |
| Trivy | `trivy_scan(target, type)` | Container vulnerability scanner |
| Kube-Hunter | `kube_hunter_scan(target)` | Kubernetes penetration testing |
| Kube-Bench | `kube_bench_run()` | CIS Kubernetes benchmark |
| Docker Bench | `docker_bench_run()` | Docker CIS benchmark |
| Checkov | `checkov_scan(directory)` | IaC security scanning |
| Terrascan | `terrascan_scan(directory)` | IaC policy enforcement |

## Bug Bounty & OSINT (20+)

| Tool | MCP Function | Purpose |
|------|-------------|---------|
| Shodan | `shodan_search(query)` | Internet device search |
| Censys | `censys_search(query)` | Internet-wide scanning data |
| Recon-ng | `recon_ng(module, target)` | Recon framework |
| SpiderFoot | `spiderfoot_scan(target)` | OSINT automation |
| Sherlock | `sherlock_search(username)` | Username enumeration |
| TruffleHog | `trufflehog_scan(repo)` | Secret detection in repos |
| Aquatone | `aquatone_scan(targets)` | Visual subdomain recon |
| Subjack | `subjack_check(domains)` | Subdomain takeover check |

## AI Intelligence Tools

| Tool | MCP Function | Purpose |
|------|-------------|---------|
| AI Analyze | `ai_analyze_target(target)` | Intelligent target assessment |
| AI Tool Select | `ai_select_tools(context)` | Context-aware tool selection |
| Bug Bounty Recon | `bugbounty_reconnaissance(target)` | Automated recon workflow |
| CTF Solver | `ctf_solve_challenge(challenge)` | CTF challenge automation |

## Common Tool Chains

### Web Application Pentest
```
subfinder_scan → httpx_scan → nuclei_scan → sqlmap_scan → dalfox_scan
```

### Bug Bounty Recon
```
amass_enum → subfinder_scan → httpx_scan → gobuster_scan → nuclei_scan
```

### Network Assessment
```
nmap_scan → enum4linux_ng → smbmap → netexec → hydra_attack
```

### Cloud Security
```
prowler_assess → trivy_scan → kube_hunter_scan → checkov_scan
```
