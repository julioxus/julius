---
name: web3-audit
description: Smart contract security audit covering 10 vulnerability classes. Uses Foundry for PoCs, Slither for SAST. Integrates with /pentest as an attack category and with Immunefi/bug bounty workflows.
---

# Web3 Smart Contract Audit

Security audit for smart contracts (Solidity, Vyper). Covers the top 10 vulnerability classes by frequency in Immunefi/Code4rena bounty programs.

## Prerequisites

- **Foundry** (forge, cast, anvil): `curl -L https://foundry.paradigm.xyz | bash && foundryup`
- **Slither** (static analysis): `pip3 install slither-analyzer`
- **Source code access**: Contract source or verified Etherscan/Sourcify code

## Vulnerability Classes (by Critical frequency)

| # | Class | % Criticals | Payout Range | Key Pattern |
|---|-------|------------|-------------|-------------|
| 1 | Accounting Desync | 28% | $50K-$2M | Balance/share calculation mismatch across mint/burn/transfer |
| 2 | Reentrancy | 15% | $10K-$500K | External call before state update (CEI violation) |
| 3 | Access Control | 12% | $20K-$1M | Missing modifier, unprotected initializer, wrong role check |
| 4 | Oracle Manipulation | 10% | $50K-$500K | Spot price used without TWAP, single-source oracle |
| 5 | Flash Loan Attack | 8% | $10K-$200K | Price manipulation within single tx via flash loan |
| 6 | Integer Overflow/Underflow | 7% | $5K-$100K | Unchecked math (pre-0.8.0), unsafe casting, precision loss |
| 7 | Unchecked External Call | 6% | $5K-$50K | Return value ignored on transfer/call, silent failure |
| 8 | Front-running / MEV | 5% | $10K-$100K | Sandwich attack on swap, mempool-visible tx ordering |
| 9 | Logic Error (State Machine) | 5% | $10K-$500K | Invalid state transition, missing invariant check |
| 10 | Signature Replay/Malleability | 4% | $5K-$200K | Missing nonce, cross-chain replay, EIP-712 issues |

## Workflow

### Phase 1: Setup & Reconnaissance
```
1. Obtain contract source (repo, Etherscan, Sourcify)
2. Identify: Solidity version, compiler settings, proxy pattern, dependencies
3. Map contract architecture: inheritance, libraries, external calls
4. Identify token standards (ERC-20/721/1155/4626) and DeFi primitives (AMM, lending, vault)
5. Run Slither: slither . --json slither-output.json
6. Parse Slither output for high/medium findings
```

### Phase 2: Static Analysis (SAST)
```
For each vulnerability class:
1. Search for known patterns (see Detection Patterns below)
2. Map external call graph (which contracts are called, in what order)
3. Check: access control on every state-changing function
4. Check: CEI pattern (Checks-Effects-Interactions) compliance
5. Check: math operations for overflow/precision loss
6. Check: oracle usage (spot vs TWAP, single vs multi-source)
```

### Phase 3: Dynamic Testing (Foundry PoCs)
```
For each suspected vulnerability:
1. Write Foundry test: test/PoC_<VulnName>.t.sol
2. Fork mainnet state: forge test --fork-url <RPC> --match-test testPoC
3. Demonstrate: initial state → exploit tx → final state (profit/damage)
4. Quantify: exact USD/ETH impact
```

### Phase 4: Evidence & Reporting
```
For each confirmed finding:
1. finding-NNN/description.md — Writeup with inline code + Foundry output
2. finding-NNN/poc.sol — Foundry test file (executable PoC)
3. finding-NNN/poc_output.txt — forge test output with traces
4. finding-NNN/evidence/ — Relevant source code snippets, call traces
```

## Detection Patterns

**Reentrancy**: External call (`call`, `transfer`, `send`, `.balanceOf()` on untrusted token) before state update. Look for: `nonReentrant` modifier absence, cross-function reentrancy via shared state.

**Accounting Desync**: Compare `totalSupply` / `totalAssets` calculations across all entry points (deposit, withdraw, mint, burn, transfer, fee collection). Look for: rounding direction inconsistency, donation attack vectors (ERC-4626).

**Access Control**: `onlyOwner`, `onlyRole`, `initializer` modifiers. Check: `initialize()` callable by anyone, `selfdestruct` accessible, admin functions without modifier, proxy `delegatecall` to arbitrary implementation.

**Oracle Manipulation**: `getReserves()`, `slot0()`, `latestAnswer()`. Check: single-block price query, no TWAP, manipulable within flash loan.

**Flash Loan**: Any function callable within flash loan callback. Check: price-dependent logic that reads and acts in same tx.

## PoC Template (Foundry)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "forge-std/Test.sol";

contract PoCTest is Test {
    // Target contracts
    address constant TARGET = 0x...;

    function setUp() public {
        vm.createSelectFork("mainnet", BLOCK_NUMBER);
    }

    function testExploit() public {
        uint256 balanceBefore = address(this).balance;
        // ... exploit steps ...
        uint256 profit = address(this).balance - balanceBefore;
        assertGt(profit, 0, "Exploit should be profitable");
        emit log_named_uint("Profit (ETH)", profit);
    }
}
```

Run: `forge test --match-test testExploit -vvvv --fork-url $ETH_RPC_URL`

## Integration

- **Invoked by**: `/pentest` (when scope includes smart contracts), `/intigriti` or `/hackerone` (Immunefi programs)
- **Chain table**: See AGENTS.md — Reentrancy → drain, Oracle manipulation → flash loan, Access control → privilege escalation
- **Output**: Standard finding format (`description.md`, `poc.sol`, `poc_output.txt`, `evidence/`)

## Platform-Specific Notes

**Immunefi**: Impact quantified in USD. Root cause in code (file:line). Foundry PoC mandatory for Critical/High. Payout based on funds at risk.

**Code4rena**: Severity judged by wardens. Submit with full analysis + PoC. Duplicate risk high — speed matters.

## Critical Rules

- **Foundry PoC required** for every finding (no theoretical-only reports)
- **Fork mainnet state** — test against real deployed contracts
- **Quantify impact** in USD/ETH (not "could drain funds")
- **Check all entry points** — deposit, withdraw, mint, burn, swap, liquidate
- **CEI pattern** is the #1 thing to verify on every external call
- Never deploy or execute transactions on mainnet
