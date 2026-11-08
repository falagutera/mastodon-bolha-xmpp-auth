// mastodon-xmpp-auth: ejabberd external-auth (extauth) backend that validates
// XMPP logins against the Mastodon Postgres database.
//
// Only LOCAL, confirmed, approved, enabled, non-suspended Mastodon accounts can
// authenticate (i.e. only @bolha.us users). The XMPP localpart is matched
// case-insensitively against accounts.username; the password is verified against
// users.encrypted_password (bcrypt, Devise). Optionally supports a Devise pepper.
//
// Protocol: ejabberd speaks the "extauth" protocol over stdin/stdout with 2-byte
// big-endian length framing. Request payload is "op:arg1:arg2:...". Response is a
// 2-byte length (=2) followed by a 2-byte value (1=ok, 0=fail).
package main

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

func ctxTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}

// A fixed bcrypt hash used to normalise timing when a user is not found, so the
// response time does not leak account existence. (hash of a random string)
// nosemgrep: generic.secrets.security.detected-bcrypt-hash.detected-bcrypt-hash -- not a credential, only burns bcrypt time
const dummyHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

var (
	db         *sql.DB
	xmppDomain string
	pepper     string
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	log.SetOutput(os.Stderr)
	log.SetPrefix("mastodon-xmpp-auth: ")
	log.SetFlags(0)

	xmppDomain = env("XMPP_DOMAIN", "bolha.im")
	pepper = os.Getenv("DEVISE_PEPPER") // empty = no pepper (Mastodon default)

	dsn := fmt.Sprintf(
		"host=%s port=%s dbname=%s user=%s password=%s sslmode=%s connect_timeout=5",
		env("DB_HOST", "127.0.0.1"),
		env("DB_PORT", "5432"),
		env("DB_NAME", "mastodon_production"),
		env("DB_USER", "mastodon"),
		os.Getenv("DB_PASS"),
		env("DB_SSLMODE", "disable"),
	)

	var err error
	db, err = sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("sql.Open: %v", err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxIdleTime(5 * time.Minute)
	if err := db.Ping(); err != nil {
		log.Printf("warning: initial db ping failed: %v", err)
	}

	in := os.Stdin
	out := os.Stdout
	for {
		payload, err := readPacket(in)
		if err == io.EOF {
			return
		}
		if err != nil {
			log.Printf("read error: %v", err)
			return
		}
		ok := handle(payload)
		if err := writeResult(out, ok); err != nil {
			log.Printf("write error: %v", err)
			return
		}
	}
}

// readPacket reads one 2-byte-length-framed request.
func readPacket(r io.Reader) (string, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return "", err
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// writeResult writes the 2-byte-length-framed boolean response.
func writeResult(w io.Writer, ok bool) error {
	var v uint16
	if ok {
		v = 1
	}
	var out [4]byte
	binary.BigEndian.PutUint16(out[0:2], 2) // length
	binary.BigEndian.PutUint16(out[2:4], v) // value
	_, err := w.Write(out[:])
	return err
}

func handle(payload string) (result bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic handling request: %v", r)
			result = false
		}
	}()

	sep := strings.IndexByte(payload, ':')
	if sep < 0 {
		return false
	}
	op := payload[:sep]
	rest := payload[sep+1:]

	switch op {
	case "auth":
		// rest = user:server:password  (password may contain ':')
		parts := strings.SplitN(rest, ":", 3)
		if len(parts) != 3 {
			return false
		}
		return auth(parts[0], parts[1], parts[2])
	case "isuser":
		parts := strings.SplitN(rest, ":", 2)
		if len(parts) != 2 {
			return false
		}
		return isUser(parts[0], parts[1])
	case "setpass", "tryregister", "removeuser", "removeuser3":
		// read-only backend: registration / password changes not allowed here.
		return false
	default:
		log.Printf("unknown op: %q", op)
		return false
	}
}

// lookupHash returns the bcrypt hash for a local, confirmed, approved, enabled,
// non-suspended account whose username matches (case-insensitive). ok=false if no
// such account.
func lookupHash(user, server string) (hash string, ok bool) {
	if !strings.EqualFold(server, xmppDomain) {
		return "", false
	}
	const q = `
		SELECT u.encrypted_password
		FROM accounts a
		JOIN users u ON u.account_id = a.id
		WHERE a.domain IS NULL
		  AND lower(a.username) = lower($1)
		  AND u.confirmed_at IS NOT NULL
		  AND u.approved = true
		  AND u.disabled = false
		  AND a.suspended_at IS NULL
		LIMIT 1`
	ctx, cancel := ctxTimeout()
	defer cancel()
	err := db.QueryRowContext(ctx, q, user).Scan(&hash)
	if err == sql.ErrNoRows {
		return "", false
	}
	if err != nil {
		log.Printf("db query error for user %q: %v", user, err)
		return "", false
	}
	return hash, true
}

func isUser(user, server string) bool {
	_, ok := lookupHash(user, server)
	return ok
}

func auth(user, server, password string) bool {
	hash, ok := lookupHash(user, server)
	if !ok {
		// Normalise timing to avoid leaking account existence.
		_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password+pepper))
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password+pepper))
	if err != nil {
		return false
	}
	// constant-time no-op to keep the success path symmetric
	_ = subtle.ConstantTimeCompare([]byte(user), []byte(user))
	return true
}
