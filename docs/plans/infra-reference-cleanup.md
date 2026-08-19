# Plan: remove operator-specific infrastructure references

freeq is a public repository. Deployment docs, scripts, and unit files must
describe **how** to run freeq, never **where the maintainer runs it**. Concrete
host names, IP addresses, cloud org/cluster identifiers, and personal home
paths are operator configuration — they belong in the operator's environment,
not in the tree.

## Rules

1. No real host names or IP addresses of running deployments. Use
   `irc.example.com` / `deploy@irc.example.com` placeholders.
2. No cloud organization, project, or cluster identifiers. Take them from an
   environment variable (e.g. `MIREN_CLUSTER`) and default to unset.
3. No personal home paths (`/home/<user>/...`). Use a neutral service path or
   an environment variable with a neutral default.
4. Internal ops runbooks (migration logs, personal task queues) do not belong
   in a public repo at all — delete them.

## Work items

- [x] Inventory every operator-specific reference (host, IP, org, home path).
- [x] Delete internal ops runbooks that are entirely operator-specific.
- [x] Parameterize deploy scripts / systemd / nginx with neutral defaults.
- [x] Redact remaining prose references in docs.
- [x] Re-scan to confirm nothing is left.
- [ ] Note: git history still contains the old values; rewriting history or
      rotating anything host-specific is a separate decision for the operator.

## Deliberately kept

- `freeq-site/templates/base.html` sponsor credit/logo — a public,
  intentional attribution on the project's own marketing site, not infra.
- Generic references to hosting providers and tooling (Miren, Hetzner,
  Terraform) in self-hosting guides — those are instructions, not identity.
