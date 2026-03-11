---
description: Run the full bug bounty pipeline against a target program
arguments:
  - name: program
    description: Program name matching a file in data/programs/
    required: true
---

# Scan Target: $ARGUMENTS.program

Load scope from `data/programs/$ARGUMENTS.program.yaml` and execute the full pipeline:

1. Verify scope file exists and is valid
2. Initialize the database at `data/db/findings.db`
3. Dispatch the recon agent with the scope file path
4. Review recon results and plan scanning strategy
5. Dispatch the scanner agent with the target list
6. Dispatch the validator agent on all findings
7. Present a final summary with validated findings
