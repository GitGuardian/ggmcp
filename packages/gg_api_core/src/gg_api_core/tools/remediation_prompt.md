**Fallback: Secret remediation guidance**

> If a remediation skill or workflow is available in this session, **follow it instead** —
> it is the authoritative source. The steps below are only a minimal fallback for when no
> such skill is present.

**Context:** You are given the exact locations of hardcoded secrets in a Git repository
(from `list_repo_occurrences` / `list_remediation_targets`). Use each occurrence's `filepath`
and `matches` (`indice_start`, `indice_end`, `pre_line_start`, `pre_line_end`,
`post_line_start`, `post_line_end`) to locate the secret precisely.

**Remediate each secret in this order:**

1. **Rotate first.** A leaked secret must be treated as compromised. Revoke/rotate the
   credential at its provider and issue a replacement *before* touching the code. Removing it
   from the repo does not undo the exposure — anyone who saw it can still use it until it is
   rotated.

2. **Remove the hardcoded value from the code.** Replace it with a reference to an
   environment variable (e.g. `process.env.API_KEY`, `os.getenv("API_KEY")`). Load the real,
   rotated value from a secrets manager or an untracked `.env` file, and make sure `.env` is in
   `.gitignore`. Document the expected variable name in `.env.example` with a placeholder.

3. **Only then consider git history.**
    * If the leaking commit has **not been pushed**, you may amend/rebase locally to drop the
      secret from history before pushing.
    * If it has **already been pushed** (or you are unsure), do **not** rewrite shared history
      as a first move — it breaks collaborators and does not un-leak the secret. Rotation in
      step 1 is what neutralizes the exposure; history rewriting is an optional cleanup to be
      coordinated with the team.
