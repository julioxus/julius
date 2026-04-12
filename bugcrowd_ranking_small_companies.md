# Bugcrowd Ranking: Small Companies / Low Competition / Best ROI
**Generated: 2026-04-10** | **Source: Bugcrowd API (50+ programs analyzed)**

## Scoring Criteria

| Factor | Weight | Indicator |
|--------|--------|-----------|
| Competition | 30% | Unknown brand, B2B niche, technical barrier |
| Min bounty floor | 25% | Higher min = guaranteed payout even for lows |
| Max bounty | 20% | Upside potential |
| Attack surface | 15% | eComm/auth/payments > static sites |
| Triage speed | 10% | P1 24/7 > Platform |

## TIER 1 - Best Expected ROI

| # | Program | Handle | Bounty | Industry | Why |
|---|---------|--------|--------|----------|-----|
| 1 | **OneTrust** | `onetrust` | $300-$6,500 | Privacy/Compliance | Highest min floor ($300). P1 24/7 = fast triage. Compliance niche, few researchers know it. Complex SaaS with roles/permissions = IDORs |
| 2 | **Gearset** | `gearset-mbb` | $200-$6,000 | Salesforce DevOps | Very niche. Very few researchers understand Salesforce ecosystem. B2B SaaS = CI/CD pipelines, deployment keys, SSRF potential |
| 3 | **Octopus Deploy** | `octopus-deploy` | $200-$6,000 | CI/CD DevOps | Deployment tool. High technical barrier = low competition. Self-hosted option = config bugs. Feature-rich API |
| 4 | **AXIS OS** | `axis-os-public` | $500-$40,000 | IoT/Cameras | Min $500 and max $40K = best ratio on Bugcrowd. Requires embedded/IoT knowledge (very high barrier), but wide open field |
| 5 | **PNI Media** | `pnimedia-bb` | $150-$4,500 | eCommerce/Photo | Nobody knows PNI Media, but they power Walmart/CVS photo services. eComm = payment flows, IDOR on orders, file upload on photos |
| 6 | **Ultra Mobile ECOMM** | `ultramobile-ecomm` | $175-$4,500 | Telecom | New program (2025). Small telecom, eCommerce = cart, payments, account takeover. Low researcher attention |

## TIER 2 - Good ROI with slightly more competition

| # | Program | Handle | Bounty | Industry | Why |
|---|---------|--------|--------|----------|-----|
| 7 | **Bolt Technology** | `bolt-og` | $150-$6,500 | Ride-hailing EU | The "European Uber" but far less researched. Payments + geolocation + driver/rider APIs = huge surface |
| 8 | **Lime** | `lime` | $150-$7,000 | Scooters/Transport | High max ($7K). IoT (scooters) + mobile app + payments. Less sexy than crypto = fewer competitors |
| 9 | **Certinia** (FinancialForce) | `financialforce` | $175-$4,500 | Salesforce ERP | Same niche as Gearset. ERP on Salesforce = IDOR on invoices, permissions, workflows |
| 10 | **Magic Labs** | `magiclabs-mbb-og` | $250-$3,000 | Web3 Auth SDK | Auth SDK = critical surface (bypass, token manipulation). High min ($250). Low max ($3K) limits upside |
| 11 | **MGM Macau** | `mgmmacau-mbb-og` | $250-$7,500 | Casino/Hospitality | Asian casino = geographic niche. $250 floor + $7.5K max. Reservations, loyalty programs, payments |
| 12 | **Moovit** | `moovit-mbb-og` | $100-$7,000 | Transit/Intel | Intel subsidiary. Good surface (location APIs, routes) but low min ($100) |
| 13 | **The Trade Desk** | `thetradedesk-mbb` | $175-$5,000 | AdTech B2B | Programmatic advertising platform. Pure B2B = few researchers. Bidding APIs, data pipelines |

## TIER 3 - Geographic Niches (LATAM)

| # | Program | Handle | Bounty | Industry | Why |
|---|---------|--------|--------|----------|-----|
| 14 | **Rapyd** | `rapyd` | $100-$7,500 | Fintech infra | B2B payment infrastructure. Checkout APIs, disbursement, wallet. Good max but low min |
| 15 | **Bitso** | `bitso-mbb-og` | $50-$7,500 | Crypto LATAM | LATAM exchange, less saturated than Binance. But crypto still competitive |
| 16 | **iFood** | `ifood-og` | $150-$3,750 | Food delivery BR | The "Brazilian Uber Eats". Classic delivery + payments surface. Niche by language/region |
| 17 | **Nubank** | `nubank` | $50-$4,000 | Neobank BR | Huge LATAM digital bank but under-attacked on Bugcrowd. Very low min ($50) |

## AVOID (high competition or low ROI)

| Program | Reason |
|---------|--------|
| OpenAI, Tesla, SpaceX | Hundreds of top researchers already on them |
| Okta, Zendesk, Atlassian | Mature programs, low-hanging fruit exhausted |
| Binance, OpenSea, KuCoin | Crypto = most saturated bounty category |
| HostGator LATAM, Web.com, SnapNames | Min $0 / "Points" = no payment guarantee |
| Bitstamp | $0-$0 = bounties not listed, probably kudos only |
| Under Armour ($125-$2,500) | Max too low for the effort |

## Top 3 Recommendation

1. **OneTrust** - $300 min floor guarantees even a P4 pays well. Privacy SaaS = complex roles, IDOR on consent configs, SSRF on integrations. Fast triage (P1 24/7).
2. **Gearset** - Niche so specific (Salesforce CI/CD) that competition is virtually zero. $200 floor. Look for: deployment pipeline injection, credential exposure, IDOR on orgs/repos.
3. **PNI Media** - Hidden gem. Nobody hunts bugs on a photo printing company, but they process payments and file uploads at scale (Walmart, CVS). $150 floor. Look for: IDOR on orders, file upload bypass, payment tampering.
