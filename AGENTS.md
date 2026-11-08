# AGENTS.md

Notes for coding agents (and people) changing mastodon-xmpp-auth. The README explains the protocol,
configuration and ejabberd wiring; this file says how to change the code without breaking it.

## What it is

One file, `main.go`: an ejabberd extauth program. It reads 2-byte length-framed requests on stdin
(`readPacket`), answers `1`/`0` on stdout (`writeResult`), and checks passwords against a Mastodon
PostgreSQL database with bcrypt. No writes, no state, no HTTP.

## Commands

```sh
gofmt -l .            # must print nothing
go vet ./...
go test ./...         # without XMPP_TEST_DB_HOST the database test skips itself
```

With a database (`TestAccountFilters` **drops and recreates** the `accounts` and `users` tables, and
refuses a database whose name does not end in `_test`):

```sh
P=55667   # any free port
docker run -d --name xmpp-auth-pg-$P -p $P:5432 -e POSTGRES_PASSWORD=pg -e POSTGRES_DB=xmpp_test postgres:17 &&
  until docker exec xmpp-auth-pg-$P pg_isready -U postgres -q; do sleep 1; done &&
  XMPP_TEST_DB_HOST=127.0.0.1 XMPP_TEST_DB_PORT=$P go test -count=1 ./...
docker rm -f xmpp-auth-pg-$P
```

Test variables: `XMPP_TEST_DB_HOST`, `_PORT` (5432), `_NAME` (xmpp_test), `_USER` (postgres),
`_PASSWORD` (pg). Build the static binary with the command in the README.

## Rules that must hold

1. **Read-only.** `setpass`, `tryregister`, `removeuser`, `removeuser3` and unknown operations
   answer `0`; the only SQL is the `SELECT` in `lookupHash`. (`TestWritesAndOtherDomainsAreDenied`)
2. **Only local, confirmed, approved, enabled, non-suspended accounts.** Every filter in
   `lookupHash` stays (`a.domain IS NULL`, `confirmed_at`, `approved`, `disabled`, `suspended_at`);
   the username match is case-insensitive and the password may contain `:` (`SplitN` with 3).
   (`TestAccountFilters`, one row per excluded case)
3. **One domain.** Requests for a server other than `XMPP_DOMAIN` fail before touching the database.
4. **No existence leak through `auth`.** An unknown user still runs a bcrypt compare on `dummyHash`.
   Never log passwords; logs go to stderr only (stdout is the protocol).
5. **Fail closed and bounded.** Any error or panic answers `0` (`handle` recovers); each query has a
   5s timeout, the pool is capped at 4 connections.

## Changing it

0. Check the README and `handle` first: the protocol is fixed by ejabberd, so most changes are to
   `lookupHash`.
1. A new account condition: add it to the query, mirror it in the README's SQL, add a row for the
   excluded case to `TestAccountFilters` (and the column to its `CREATE TABLE`).
2. `gofmt -l .`, `go vet ./...`, the tests with a database. There is no CI and no `VERSION` file;
   code, comments, commits and the README in English, and keep the README's SQL and settings table
   true. Review any change for what it lets authenticate: scanners do not see that.
