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

Before anything else, ensure all required security tools are installed. Run the install script and verify:

```bash
bash scripts/install-tools.sh
```

Then verify critical tools are on PATH:
```bash
for tool in nuclei ffuf subfinder httpx katana gau dalfox sqlmap; do
  printf "%-12s " "$tool"
  which "$tool" 2>/dev/null || echo "MISSING"
done
```

Also ensure the `bba` CLI works:
```bash
uv run bba --help
```

If any tools are missing after the install script, note which ones failed and continue — agents will fall back to curl-based testing for missing tools, but having the full toolkit produces better results.

**Do NOT proceed to Phase 1 until the precheck is complete.**

## Phase 1: Initialize

1. Verify scope file exists: `data/programs/$ARGUMENTS.program.yaml`
2. Read the scope file to understand the target
3. Initialize the database:
```bash
uv run bba db summary --program $ARGUMENTS.program
```

## Phase 2: Reconnaissance

Dispatch the recon agent with the primary domain from the scope file:

> **Agent: recon**
> Run full reconnaissance against [domain] for program $ARGUMENTS.program.
> Use the `uv run bba` CLI for all tool invocations.
> Program name: $ARGUMENTS.program

## Phase 3: Coordinator Reasoning — Post-Recon

**STOP and THINK.** Before dispatching the scanner, analyze the recon results:

```
COORDINATOR REASONING:
- Technology stack detected: [list]
- Architecture pattern: [what the recon suggests]
- High-value targets identified: [list with reasoning]
- Scan strategy decision: [what to prioritize and why]
- Expected vulnerability classes: [based on tech stack]
```

Use this reasoning to craft specific context for the scanner agent.

## Phase 4: Vulnerability Scanning

Dispatch the scanner agent with targeted context from your reasoning:

> **Agent: scanner**
> Scan program $ARGUMENTS.program with the following context:
> - Technology profile: [from recon analysis]
> - Priority targets: [from your reasoning]
> - Recommended focus areas: [from your reasoning]
> Use the `uv run bba` CLI for all tool invocations.

## Phase 5: Coordinator Reasoning — Post-Scan

**STOP and THINK.** Analyze scan results and decide on deep dives:

```
COORDINATOR REASONING:
- Total findings: [count]
- Findings that need deep investigation: [list with reasoning]
- False positive assessment: [which findings look suspicious]
- Deep dive decisions:
  1. [finding] → DEEP DIVE because [reason]
  2. [finding] → SKIP because [reason]
```

## Phase 6: Deep Dives (Dynamic)

For EACH finding that warrants investigation, spawn a deep dive agent:

> **Agent: deep-dive**
> Investigate the following for program $ARGUMENTS.program:
> - Target: [specific URL]
> - Hypothesis: [what vulnerability to test]
> - Context: [what recon/scanning revealed]
> Use curl for manual testing. Store confirmed findings via `uv run bba db add-finding`.

You may spawn multiple deep dive agents in parallel for independent targets.

## Phase 7: Validation

Dispatch the validator agent to re-test ALL findings:

> **Agent: validator**
> Validate all findings for program $ARGUMENTS.program.
> Re-test each finding independently using curl.
> Apply security reasoning — don't just pattern match.
> Use the `uv run bba` CLI for database queries and updates.

## Phase 8: Coordinator Reasoning — Post-Validation

```
COORDINATOR REASONING:
- Validated findings: [count and summary]
- False positives caught: [count]
- Findings still needing review: [list]
- Overall assessment: [risk level for the target]
```

## Phase 9: Reporting

Dispatch the reporter agent:

> **Agent: reporter**
> Generate a professional security report for program $ARGUMENTS.program.
> Include all validated findings with risk analysis and remediation.
> Write the report to data/output/reports/.

## Phase 10: Executive Summary

Present the final summary to the user:

```
## Scan Complete: $ARGUMENTS.program

### Results
- Subdomains discovered: X
- Live services: X
- Total findings: X
- Validated vulnerabilities: X
- False positives filtered: X

### Critical/High Findings
[List each with one-line description]

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
