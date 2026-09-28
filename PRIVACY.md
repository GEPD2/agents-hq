# Privacy and Data Collection

AGENTS-HQ is a self-hosted security intelligence platform that runs entirely on your
own machine. This document declares what the software stores, where it stores it, and
what leaves the machine. It covers the **Control Panel website** (`website/`); the
intelligence **agents** (`agent_01`-`agent_10`) are described in their own section
because they make deliberate outbound requests as part of their job.

## Summary

- The Control Panel runs on **localhost only** (`127.0.0.1`) over plain HTTP (`:8080`) or
  HTTPS through a local self-signed proxy (`:8443`). It is not exposed to your local network
  or the internet.
- The Control Panel sets **no tracking cookies** and uses **no analytics or telemetry**. The
  only cookie is the login session cookie; it is HttpOnly, SameSite=Lax, lasts 7 days by
  default (`SESSION_TTL`), holds a value derived from a per-install secret (not your password),
  and stays in your browser.
- Nothing you view or enter in the Control Panel is sent to us or to any third party.
- The only browser storage is `localStorage`, used for interface preferences, and it
  never leaves your browser.
- All intelligence data is stored **locally**, on your filesystem and in your local
  MySQL database.

## What the Control Panel stores

### In your browser (`localStorage`)

Used only to remember how you left the interface. Not transmitted anywhere.

| Item | Key | Purpose |
|------|-----|---------|
| Theme choice | `ahq-theme` | Remember dark or light mode across visits |
| Sidebar state | sidebar-collapsed flag | Remember whether the navigation is collapsed |

There are **no tracking cookies**. The panel requires a login, so after you sign in one
HttpOnly SameSite session cookie (`ahq_session`) is set; it holds a value derived from a
per-install secret, never your password, and is used only to keep you signed in. The account
is stored hashed (pbkdf2) in `runtime/auth.json` on your machine; the password itself is
never stored or transmitted.

### On your machine (filesystem and local MySQL)

Data produced by the agents and organised through the Control Panel. It stays on your
machine and is never uploaded by the website.

| Data | Where stored | Purpose |
|------|--------------|---------|
| Agent reports | Filesystem (`reports/`) | The markdown reports agents produce |
| Indicators of compromise | MySQL `iocs` | Extracted IPs, domains, hashes, CVEs, and similar |
| Knowledge base documents | MySQL `documents` | Indexed intelligence for search |
| Threat actor profiles | MySQL `threat_actors` | Persistent actor tracking |
| Case files | MySQL `cases`, `case_items` | Investigations you assemble |
| Geolocation cache | MySQL `ip_geo` | Cached IP geolocation for the map |

Retention is entirely under your control: this data lives until you delete the files or
the database rows. The software applies no automatic expiry.

## What leaves your machine

The Control Panel makes **no external asset requests at all**. Every interface library
(Chart.js, Cytoscape, marked, Prism) is vendored locally under `website/static/vendor/`,
the font (JetBrains Mono) is self-hosted, and the Geo Map is fully offline (a bundled world
map plus a local IP-to-country dataset). No CDN, fonts host, map tile, or geolocation API is
contacted on a page load.

The one outbound path that can occur is under your control:

1. **Optional alert webhook.** If you configure an alert webhook URL in Settings (for
   example a Slack incoming webhook), the platform will POST alert notifications to that
   URL that you chose. This is off unless you set it.

## The intelligence agents

The agents (OSINT, recon, dark web monitor, news and market intel, and others) are
designed to reach out to external sources - DNS, certificate transparency, threat
intelligence feeds, vulnerability databases, breach data, and public APIs. That outbound
activity is the point of those tools and is separate from the Control Panel. API keys the
agents use live in local `.env` files and are never committed to this repository. Review
each agent's own documentation for the sources it contacts.

## Your control

- Runs on hardware you own, on `127.0.0.1` only.
- No account, no cloud sync, no background upload from the Control Panel.
- Delete any report file or database row at any time to remove that data.
- Clear your browser's site data to remove the interface preferences.

## Scope and changes

This declaration describes the software in this repository. It is not legal advice. If
you deploy or modify AGENTS-HQ, you are responsible for the data it then handles. Changes
to what the software collects will be reflected here.

For credential hygiene (the forced first-login password change) and one historical
disclosure about a key that was committed in early git history, see `SECURITY.md`.
