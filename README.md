# mastodon-xmpp-auth

An [ejabberd](https://www.ejabberd.im/) **external authentication** backend that lets your
Mastodon users log into XMPP with their **Mastodon username and password** — turning your
Mastodon instance into the identity provider for your XMPP server.

It validates credentials directly against Mastodon's PostgreSQL database (bcrypt), with no
account provisioning and no writes: only **local, confirmed, approved, enabled and
non-suspended** Mastodon accounts can authenticate. There is no in-band registration and no
way to create XMPP accounts — the set of valid XMPP users is exactly the set of local
Mastodon users.

Written in Go, it compiles to a single **static binary** with no runtime dependencies, so it
drops straight into the official `ejabberd/ecs` Docker image (or a bare-metal ejabberd) — no
custom image, no interpreter, no shared libraries.

## Testing and security

This program decides who can log into the XMPP server with a Mastodon password, so it is tested against what would hurt: letting in an account that shouldn't (remote, unconfirmed, unapproved, disabled or suspended), writing anything, answering for another domain, and failing open. What is done today (2026-11-08):

**Every pipeline.** GitLab CI ([`.gitlab-ci.yml`](.gitlab-ci.yml), plus the shared security stage from `open/gcn/ci-templates`, file `security.yml`). The test job runs on every pipeline; the security stage runs on every merge request and every push to `main`; the static binary is built, and kept as a job artifact, only from `main`.

- Blocking (the pipeline fails):
  - `go vet`, a `gofmt` check, and the full test suite against a real PostgreSQL 17;
  - `govulncheck`: known vulnerabilities in Go code paths this program actually reaches (in the test job and in the security stage);
  - `gitleaks`: secrets committed to the repository;
  - `trivy`: critical vulnerabilities that have a fix, secrets and misconfigurations in the repository.
- Informative (reported, not blocking): `semgrep`, `gosec`, `yamllint`, and `poutine` (security of the CI pipeline itself). The one `gosec` false positive is annotated in the code with the reason.

**The test suite.** 3 tests (`go test -list`), small because the program is one file:

- the protocol framing: requests are read and answers written in ejabberd's 2-byte length format;
- writes and other domains are denied: `setpass`, `tryregister`, `removeuser`, `removeuser3`, unknown or malformed requests, and any request for a domain other than `XMPP_DOMAIN` answer "no" without touching the database;
- the account filters, on PostgreSQL: one row per case that must be refused (remote, unconfirmed, unapproved, disabled, suspended), case-insensitive usernames, a wrong password, and a password containing `:`. It skips without `XMPP_TEST_DB_HOST`; CI sets it.

**Reviews.** No penetration test or outside review has been run on this program yet.

**Reporting a vulnerability.** Write to contato@gutocarvalho.net. Please don't open a public issue for it.

## Architecture

**Why it exists.** A community that runs Mastodon and an XMPP server would otherwise need a second set of accounts and passwords, and a second sign-up queue to moderate. With this backend the XMPP server has no accounts of its own: the people who can log in are exactly the instance's active local accounts, with the same password, and suspending an account on Mastodon also locks it out of XMPP.

**In plain words.**

1. ejabberd starts this program (`extauth_program`, a pool of processes) and sends it one request per line of its protocol: "is this password right for alice?", "does bob exist?";
2. the program looks up the account in Mastodon's PostgreSQL with one read-only query, keeping only local, confirmed, approved, enabled and non-suspended accounts;
3. it checks the password against the account's bcrypt hash and answers yes or no. Anything else (registration, password changes, errors) is a no.

**Components.**

```
   XMPP client --SASL--> ejabberd --stdin/stdout ({packet, 2})--> mastodon-xmpp-auth
                                                                       |
                                                    one SELECT, 5 s timeout, at most 4 connections
                                                                       v
                                                           Mastodon PostgreSQL
                                                           accounts + users (read-only user)
```

- Nothing is stored: no files, no cache, no HTTP. Each answer comes from the database at that moment, so a suspension or a password change on Mastodon takes effect on the next XMPP login.
- Passwords are never logged; logs go to stderr, since stdout is the protocol.
- XMPP data (rosters, messages, OMEMO keys) stays in ejabberd; this program only replaces the password check.

## How it works

ejabberd talks to an external auth program over stdin/stdout using a simple length-prefixed
protocol (`{packet, 2}` framing). For each request ejabberd sends `operation:arg1:arg2:...`
and expects a 2-byte boolean reply.

This backend answers:

- `auth:User:Server:Password` — verify the password (bcrypt) for a Mastodon account.
- `isuser:User:Server` — does such a local account exist?
- `setpass` / `tryregister` / `removeuser` — always **denied** (read-only backend).

The lookup (case-insensitive on the username) is roughly:

```sql
SELECT u.encrypted_password
FROM accounts a
JOIN users u ON u.account_id = a.id
WHERE a.domain IS NULL            -- local accounts only
  AND lower(a.username) = lower($1)
  AND u.confirmed_at IS NOT NULL
  AND u.approved = true
  AND u.disabled = false
  AND a.suspended_at IS NULL
```

The password is verified with `bcrypt.CompareHashAndPassword` against `users.encrypted_password`.
A timing-normalised dummy compare runs when the account is not found, so response time does not
leak account existence.

## Requirements

- ejabberd (tested with 26.x) configured for external authentication.
- Network access from the ejabberd host to the Mastodon **PostgreSQL** database.
- Go 1.26.5 or newer to build (the version in `go.mod`; only needed at build time).
- Mastodon schema compatible with v4.x (`accounts` + `users` tables, bcrypt `$2a$`/`$2b$`).

## Build

Static, no CGO:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o mastodon-xmpp-auth .
```

That yields a ~5 MB static ELF you can mount or copy anywhere.

## Configuration

All configuration is via environment variables (the process inherits ejabberd's environment):

| Variable        | Default                | Description                                              |
|-----------------|------------------------|----------------------------------------------------------|
| `DB_HOST`       | `127.0.0.1`            | Mastodon PostgreSQL host                                  |
| `DB_PORT`       | `5432`                 | PostgreSQL port                                          |
| `DB_NAME`       | `mastodon_production`  | Database name                                            |
| `DB_USER`       | `mastodon`             | DB user (a **read-only** user is recommended)           |
| `DB_PASS`       | *(empty)*              | DB password                                             |
| `DB_SSLMODE`    | `disable`              | libpq sslmode (`disable`, `require`, `verify-full`, ...) |
| `XMPP_DOMAIN`   | `bolha.im`             | The XMPP vhost this backend serves; requests for other domains are rejected |
| `DEVISE_PEPPER` | *(empty)*              | Devise pepper, if your Mastodon sets one (modern Mastodon does not) |

A read-only DB user is enough and recommended:

```sql
CREATE USER xmpp_auth WITH PASSWORD '...';
GRANT CONNECT ON DATABASE mastodon_production TO xmpp_auth;
GRANT USAGE ON SCHEMA public TO xmpp_auth;
GRANT SELECT ON accounts, users TO xmpp_auth;
```

## Wiring it into ejabberd

In `ejabberd.yml`:

```yaml
hosts:
  - bolha.im                     # must match XMPP_DOMAIN

auth_method: [external]
extauth_program: "/opt/ejabberd/auth/mastodon-xmpp-auth"
extauth_pool_size: 4
```

The DB settings are passed as environment variables to ejabberd (which then passes them to the
extauth subprocess).

### Docker (official image, no rebuild)

Mount the static binary and provide the DB env via `env_file` — nothing else changes about the
official `ejabberd/ecs` image:

```yaml
services:
  ejabberd:
    image: ejabberd/ecs:26.07
    network_mode: host
    env_file:
      - ./auth/db.env            # DB_HOST=... DB_USER=... DB_PASS=... XMPP_DOMAIN=...
    volumes:
      - ./conf/ejabberd.yml:/home/ejabberd/conf/ejabberd.yml:ro
      - ./auth/mastodon-xmpp-auth:/opt/ejabberd/auth/mastodon-xmpp-auth:ro
```

`db.env` (keep it `chmod 600`, never commit it):

```
DB_HOST=10.0.0.5
DB_PORT=5432
DB_NAME=mastodon_production
DB_USER=xmpp_auth
DB_PASS=super-secret
DB_SSLMODE=disable
XMPP_DOMAIN=bolha.im
```

Make sure the binary is executable and readable by the ejabberd user in the container
(`chmod 0755 mastodon-xmpp-auth`).

## Service accounts (bots, bridges)

Because authentication is delegated entirely to Mastodon and there is **no** local account
store, a bot (e.g. a chat bridge) needs a **Mastodon account** to log in — create one and it
authenticates as `bot@your-xmpp-domain`:

```sh
tootctl accounts create mybot --email mybot@example.social --confirmed --approve
```

> **Do not** set `auth_method: [external, internal]` to sneak in local-only accounts. Mixing an
> internal backend with external auth breaks ejabberd's auth chain, and a leftover internal
> account will silently *shadow* external authentication for that username.

## Testing without a client

You can drive the protocol by hand — it's just length-prefixed strings:

```python
import struct, subprocess, os
def call(req):
    p = struct.pack(">H", len(req)) + req.encode()
    out = subprocess.run(["./mastodon-xmpp-auth"], input=p,
                         capture_output=True, env={**os.environ}).stdout
    return struct.unpack(">H", out[2:4])[0]   # 1 = ok, 0 = fail

print(call("isuser:alice:bolha.im"))                 # 1 if alice exists
print(call("auth:alice:bolha.im:hunter2"))           # 1 if password matches
```

(Export the `DB_*` and `XMPP_DOMAIN` variables first.)

The automated tests are `go test ./...` (add a throwaway PostgreSQL for the account filters). Changing the code, by hand or with a coding agent: read [AGENTS.md](AGENTS.md) first. It has the commands and the rules a change must keep (read-only, which accounts may log in, one domain, fail closed).

## Notes

- **OMEMO / PEP / MUC** and everything else are unaffected — this only replaces the password
  check. Message archive, carbons, pubsub, etc. work as usual.
- Usernames are matched case-insensitively; ejabberd lowercases the SASL localpart, and so does
  the query.
- Remote (federated) accounts have no row in `users` and therefore cannot authenticate — only
  your instance's local users can.

## License

MIT — see [LICENSE](LICENSE).
