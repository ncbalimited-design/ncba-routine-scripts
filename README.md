# ncba-routine-scripts

Sandbox-safe helper scripts consumed by NCBA Claude Code Routines at boot.

## Contract

Every file in this repo is intended to be:
- **Public-readable** — cloned anonymously by Routine sandboxes, no auth
- **Secret-free** — no tokens, no cookies, no credentials, no URLs that encode secrets
- **Minimally dependent** — Node 18+ built-ins only, or bash, unless noted in a per-script header
- **SHA-pinned at consumption** — every Routine that executes one of these scripts MUST verify its SHA256 against a hardcoded expected value before execution

Updates to any script require pushing the new SHA to the consuming Routine's EXPECTED_SHA same-session as the commit.

## Contents

- scripts/refresh-from-central.js — T6 NLM cookie refresher. Pulls the current NotebookLM cookie wrapper from the ncba-briefings Cloudflare Worker, verifies inner SHA256 integrity, writes the per-profile cookie jar atomically. Consumed by NLM Test 3 Routine and (in future) per-firm Morning Brief Routines.

## Not here

Anything that needs a secret, anything that touches production KV directly, anything that's only relevant inside the private ncba-nlm-pipeline operational repo. Those stay private.
