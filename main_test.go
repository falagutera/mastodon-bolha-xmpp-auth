package main

import (
	"bytes"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// Framing: 2-byte big-endian length, then the payload; the answer is length 2 + value 1 or 0.
func TestFraming(t *testing.T) {
	p, err := readPacket(bytes.NewReader(append([]byte{0, 9}, "isuser:a:"...)))
	if err != nil || p != "isuser:a:" {
		t.Fatalf("readPacket: %q %v", p, err)
	}
	var b bytes.Buffer
	writeResult(&b, true)
	writeResult(&b, false)
	if !bytes.Equal(b.Bytes(), []byte{0, 2, 0, 1, 0, 2, 0, 0}) {
		t.Fatalf("writeResult: %v", b.Bytes())
	}
}

// Read-only, and nothing outside XMPP_DOMAIN: these never reach the database (db is nil here).
func TestWritesAndOtherDomainsAreDenied(t *testing.T) {
	db, xmppDomain = nil, "example.im"
	for _, p := range []string{"setpass:a:example.im:x", "tryregister:a:example.im:x", "removeuser:a:example.im",
		"removeuser3:a:example.im:x", "auth:a:other.im:x", "isuser:a:other.im", "auth:a", "nonsense", ""} {
		if handle(p) {
			t.Errorf("%q must be denied", p)
		}
	}
}

// The account filters, against a real PostgreSQL. Skipped without XMPP_TEST_DB_HOST.
// It drops and recreates the accounts and users tables, so it refuses a database whose name does not end in _test.
func TestAccountFilters(t *testing.T) {
	host := os.Getenv("XMPP_TEST_DB_HOST")
	if host == "" {
		t.Skip("XMPP_TEST_DB_HOST not set")
	}
	name := env("XMPP_TEST_DB_NAME", "xmpp_test")
	if !strings.HasSuffix(name, "_test") {
		t.Fatalf("refusing database %q: the test drops tables, use a name ending in _test", name)
	}
	var err error
	db, err = sql.Open("postgres", fmt.Sprintf("host=%s port=%s dbname=%s user=%s password=%s sslmode=disable",
		host, env("XMPP_TEST_DB_PORT", "5432"), name, env("XMPP_TEST_DB_USER", "postgres"), env("XMPP_TEST_DB_PASSWORD", "pg")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	xmppDomain, pepper = "example.im", ""
	hash, _ := bcrypt.GenerateFromPassword([]byte("secret:with:colons"), bcrypt.MinCost)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`DROP TABLE IF EXISTS users, accounts`)
	exec(`CREATE TABLE accounts (id bigint PRIMARY KEY, username text NOT NULL, domain text, suspended_at timestamp)`)
	exec(`CREATE TABLE users (id bigserial PRIMARY KEY, account_id bigint REFERENCES accounts, encrypted_password text NOT NULL DEFAULT '',
		confirmed_at timestamp, approved boolean NOT NULL DEFAULT true, disabled boolean NOT NULL DEFAULT false)`)
	rows := []struct {
		id                            int
		user                          string
		domain                        any
		suspended, confirmed, approve bool
		disabled                      bool
	}{
		{1, "Ana", nil, false, true, true, false}, // the only one allowed
		{2, "remote", "other.social", false, true, true, false},
		{3, "unconfirmed", nil, false, false, true, false},
		{4, "pending", nil, false, true, false, false},
		{5, "disabled", nil, false, true, true, true},
		{6, "suspended", nil, true, true, true, false},
	}
	for _, r := range rows {
		exec(`INSERT INTO accounts VALUES ($1, $2, $3, CASE WHEN $4 THEN now() END)`, r.id, r.user, r.domain, r.suspended)
		exec(`INSERT INTO users (account_id, encrypted_password, confirmed_at, approved, disabled)
			VALUES ($1, $2, CASE WHEN $3 THEN now() END, $4, $5)`, r.id, string(hash), r.confirmed, r.approve, r.disabled)
	}
	if !handle("auth:ana:EXAMPLE.IM:secret:with:colons") || !handle("isuser:ANA:example.im") {
		t.Fatal("local, confirmed, approved, enabled account must authenticate (case-insensitive, ':' in password)")
	}
	if handle("auth:ana:example.im:wrong") {
		t.Fatal("wrong password accepted")
	}
	for _, r := range rows[1:] {
		if handle("auth:"+r.user+":example.im:secret:with:colons") || handle("isuser:"+r.user+":example.im") {
			t.Errorf("%s must not authenticate", r.user)
		}
	}
}
