# Security

AGENTS-HQ runs entirely on localhost and requires a login. See `PRIVACY.md` for the
data-handling declaration. This file covers credential hygiene and one historical disclosure.

## Login account

- First login uses the default account documented in the README (`GEPD2` + a default password).
- The panel forces a password change on first sign-in: after logging in you are sent to a setup
  screen and cannot reach any page or API until you set a new password (username optional). The
  new password must be at least 8 characters and cannot be the shipped default.
- Change the account again anytime from Settings > Account.
- The account is stored hashed (pbkdf2) in `runtime/auth.json`, which is gitignored.

## n8n encryption key

- Each install mints its own n8n encryption key into a gitignored root `.env`
  (`N8N_ENCRYPTION_KEY`), written by `python3 setup_stack.py start` and reused across restarts.
  `docker-compose.yml` no longer contains a key.
- `python3 setup_stack.py cleanup` rotates the key out when it wipes the n8n volume.

### Disclosure: a shared n8n key was committed in early history

Earlier commits of `docker-compose.yml` contained a single hard-coded
`N8N_ENCRYPTION_KEY`. It is removed from the working tree, but it may remain reachable in git
history until the history is rewritten. This only matters if real n8n credentials were ever
encrypted under it and the repository is or becomes public. New installs are unaffected: they
generate their own key. The commands below use the placeholder `OLD_N8N_KEY`; substitute your
actual old key value when you run them.

### Purge runbook (operator-run)

Rewriting history is destructive and force-pushes; run it yourself, not from tooling. Back up
the repo first. Old clones and forks keep the key until they re-clone.

Option A - git-filter-repo (recommended):

```bash
pipx install git-filter-repo         # or: pip install git-filter-repo
cd /path/to/agents-hq                 # a fresh clone is safest
printf 'OLD_N8N_KEY==>REDACTED_N8N_KEY\n' > /tmp/ahq-secrets.txt
git filter-repo --replace-text /tmp/ahq-secrets.txt
git remote add origin <your-remote-url>   # filter-repo drops the remote
git push --force --all
git push --force --tags
rm /tmp/ahq-secrets.txt
```

Option B - BFG Repo-Cleaner:

```bash
printf 'OLD_N8N_KEY\n' > /tmp/ahq-secrets.txt
bfg --replace-text /tmp/ahq-secrets.txt
git reflog expire --expire=now --all && git gc --prune=now --aggressive
git push --force
rm /tmp/ahq-secrets.txt
```

After a purge, tell every collaborator to re-clone; existing checkouts still hold the old history.
