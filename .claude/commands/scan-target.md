---
description: Run the full bug bounty pipeline against a target program
arguments:
  - name: program
    description: Program name matching a file in data/programs/
    required: true
---

# Scan Target: $ARGUMENTS.program

You are the COORDINATOR for a bug bounty engagement against `$ARGUMENTS.program`. You orchestrate specialized agents, REASON about their findings between phases, and make strategic decisions about where to focus effort.

## Phase 0: Precheck — Install Tools

Before anything else, ensure all required security tools are installed:

```bash
bash scripts/install-tools.sh
```

Verify critical tools:
```bash
for tool in nuclei ffuf subfinder httpx katana gau dalfox sqlmap dnsx naabu feroxbuster crlfuzz qsreplace ghauri xsstrike; do
  printf "%-15s " "$tool"
  which "$tool" 2>/dev/null || echo "MISSING"
done
```

Also ensure the `bba` CLI works:
```bash
uv run bba --help
```

If any tools are missing after the install script, note which ones and continue — agents will adapt.

**Do NOT proceed to Phase 1 until the precheck is complete.**

## Phase 0.5: Resume Check

Check if a previous scan exists for this program:

```bash
uv run bba db scan-history --program $ARGUMENTS.program
```

If a previous incomplete run exists:
- **Resume**: Skip completed phases, continue from the failed/pending phase
- **Fresh**: Start a new run (but diff results against the previous run at the end)

If no previous run exists, proceed normally.

## Phase 1: Initialize

1. Verify scope file exists: `data/programs/$ARGUMENTS.program.yaml`
2. Read the scope file to understand the target
3. Initialize the database:
```bash
uv run bba db summary --program $ARGUMENTS.program
```

## Phase 2: Reconnaissance

Dispatch the recon agent with the primary domain from the scope file. Pass instructions about which optional phases to run:

> **Agent: recon**
> Run full reconnaissance against [domain] for program $ARGUMENTS.program.
> Use the `uv run bba` CLI for all tool invocations.
> Program name: $ARGUMENTS.program
> Optional phases: Run permutation (Phase 3) and DNS brute-force (Phase 4) only if the target has >5 live subdomains. Skip screenshots (Phase 9) for speed.

## Phase 3: Coordinator Reasoning — Post-Recon

**STOP and THINK.** Analyze the recon results:

```
COORDINATOR REASONING:
- Total subdomains discovered: [count]
- Live HTTP services: [count]
- Non-HTTP ports found: [count and details]
- WAF detected: [yes/no, which WAF]
- Technology stack: [list]
- Architecture pattern: [what the recon suggests]
- High-value targets: [list with reasoning]

STRATEGIC DECISIONS:
- Run infrastructure scanning? [yes/no — yes if non-standard ports found]
- Run OSINT? [yes/no — yes for real targets, skip for local testing]
- Scan strategy: [what to prioritize and why]
- Expected vulnerability classes: [based on tech stack]
- Rate limiting: [adjust if WAF detected]
```

## Phase 4: Infrastructure Scanning (Conditional)

**Only if non-standard ports were found OR coordinator decides full coverage is needed.**

Dispatch the infrastructure agent:

> **Agent: infrastructure**
> Scan infrastructure for program $ARGUMENTS.program.
> Resolved IPs/domains from recon: [list from DB]
> Known infrastructure: [from recon analysis]
> Use the `uv run bba` CLI for all tool invocations.

## Phase 5: OSINT (Conditional)

**Only for real targets (not local-testing). Skip for self-owned/local programs unless specifically requested.**

Dispatch the OSINT agent:

> **Agent: osint**
> Hunt for leaked secrets and cloud misconfigurations for program $ARGUMENTS.program.
> Organization name: [from scope]
> Live URLs: [from recon/DB]
> Use the `uv run bba` CLI for all tool invocations.

## Phase 6: Coordinator Reasoning — Pre-Scan Strategy

**STOP and THINK.** Combine all intelligence gathered:

```
COORDINATOR REASONING:
- Infrastructure findings: [summary from infra agent, if run]
- OSINT findings: [summary from OSINT agent, if run]
- Combined attack surface: [HTTP services + non-HTTP services + OSINT]
- Adjusted scan priorities: [based on all gathered intelligence]
- WAF considerations: [rate limits, evasion strategy]
```

## Phase 7: Vulnerability Scanning

Dispatch the scanner agent with ALL gathered context:

> **Agent: scanner**
> Scan program $ARGUMENTS.program with the following context:
> - Technology profile: [from recon]
> - Priority targets: [from reasoning]
> - WAF status: [from recon — affects rate limiting]
> - OSINT findings: [any exposed endpoints or secrets that inform scanning]
> - Infrastructure findings: [any non-HTTP services to consider]
> - Recommended focus areas: [from your reasoning]
> Use the `uv run bba` CLI for all tool invocations.

## Phase 8: Coordinator Reasoning — Post-Scan

**STOP and THINK.** Analyze scan results and decide on vuln testing:

```
COORDINATOR REASONING:
- Total findings: [count by severity]
- URL classification summary: [from gf_patterns — how many URLs per category]
- Categories warranting deep testing: [based on tech stack + URL classification]
- Categories to skip: [with reasoning]
- WAF considerations for vuln testing: [rate limits, evasion]
```

## Phase 8b: Category-Specific Vulnerability Testing

Dispatch the vuln-tester agent with classified URLs and full context from prior phases:

> **Agent: vuln-tester**
> Run category-specific vulnerability testing for program $ARGUMENTS.program.
> - Classified URLs from gf_patterns: [summary of categories and counts]
> - Technology profile: [from recon]
> - WAF status: [from recon]
> - Scanner findings: [summary — what's already been found]
> - Priority categories: [from your reasoning above]
> Use the `uv run bba` CLI for all tool invocations.

## Phase 8c: Coordinator Reasoning — Post-Vuln-Testing

**STOP and THINK.** Analyze vuln-tester results:

```
COORDINATOR REASONING:
- New findings from vuln testing: [count by severity]
- Attack chains identified: [list any multi-step chains]
- Categories that produced results: [which were productive]
- Deep dive candidates from vuln testing: [findings needing manual investigation]
- Combined finding count: [scanner + vuln-tester totals]
- Deep dive decisions:
  1. [finding] → DEEP DIVE because [reason]
  2. [finding] → SKIP because [reason]
```

## PHASE 9: DEEP DIVES

For each deep-dive candidate identified in Phase 8c:
1. Spawn a deep-dive agent (can be parallel for independent targets)
2. Each deep-dive agent stores findings via `uv run bba db add-finding` with tool="manual-deep-dive"
3. WAIT for ALL deep-dive agents to complete before proceeding
4. Verify results: `uv run bba db findings --program $ARGUMENTS.program --status new`
5. Only then proceed to Phase 10 (Validation)

IMPORTANT: Do NOT proceed to validation until all deep-dive agents have finished.

For EACH finding that warrants investigation, spawn a deep dive agent:

> **Agent: deep-dive**
> Investigate the following for program $ARGUMENTS.program:
> - Target: [specific URL]
> - Hypothesis: [what vulnerability to test]
> - Context: [what recon/scanning revealed]
> Use curl for manual testing. Store confirmed findings via `uv run bba db add-finding` with tool="manual-deep-dive".

## Phase 10: Validation

Dispatch the validator agent to re-test ALL findings:

> **Agent: validator**
> Validate all findings for program $ARGUMENTS.program.
> Re-test each finding independently using curl.
> Apply security reasoning — don't just pattern match.
> Use the `uv run bba` CLI for database queries and updates.

## Phase 11: Coordinator Reasoning — Post-Validation

```
COORDINATOR REASONING:
- Validated findings: [count by severity]
- False positives caught by validator: [count]
- Findings still needing review: [list]
- Overall risk assessment: [critical/high/medium/low]
```

## Phase 12: Reporting

Dispatch the reporter agent:

> **Agent: reporter**
> Generate a professional security report for program $ARGUMENTS.program.
> Include all validated findings with risk analysis and remediation.
> Write the report to data/output/reports/.

## Phase 12.5: Diff & Notify

If this is not the first scan run, diff against the previous run:

```bash
uv run bba db scan-diff <old_run_id> <new_run_id> --category subdomains --program $ARGUMENTS.program
uv run bba db scan-diff <old_run_id> <new_run_id> --category findings --program $ARGUMENTS.program
```

Send notifications for new findings (if notify is configured):
```bash
uv run bba scan notify-findings --program $ARGUMENTS.program --severity medium
```

Include the diff summary in the executive summary below.

## Phase 13: Executive Summary

Present the final summary to the user:

```
## Scan Complete: $ARGUMENTS.program

### Pipeline Summary
- Phases executed: [list which phases ran]
- Agents dispatched: [count]
- Total scan duration: [approximate]

### Results
- Subdomains discovered: X
- Live services: X
- Open ports (non-HTTP): X
- Total findings: X
- Validated vulnerabilities: X
- False positives filtered: X
- Secrets discovered: X

### Critical/High Findings
[List each with one-line description]

### OSINT Findings
[If OSINT ran: secrets, exposed repos, cloud buckets]

### Report
[Path to generated report]

### Recommendation
[One paragraph: overall security posture and immediate actions needed]
```

## Rules

- NEVER scan outside the loaded scope
- NEVER submit reports without human approval — present findings for review
- ALWAYS include explicit COORDINATOR REASONING blocks between phases
- Spawn deep dive agents ONLY for findings that warrant manual investigation
- If recon finds zero live services, skip scanning and report the empty result
- If any phase fails, note the failure and continue with available data
- Infrastructure and OSINT phases are CONDITIONAL — only run when appropriate
- Adjust rate limits if WAF is detected
