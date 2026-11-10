package main

import (
	"database/sql"
	"errors"
	"sort"
	"strings"

	_ "modernc.org/sqlite"
)

// Device is a registered phone or browser extension (PROTOCOL.md §3).
type Device struct {
	ID        string
	Kind      string // "phone" or "ext"
	PublicKey string // b64
	PushToken *string
}

// Queued is a message waiting for an offline recipient.
type Queued struct {
	Sender   string
	SenderPk string
	Body     string
	At       int64
}

// DB is the relay's SQLite store. The schema is the one the TypeScript relay used, so an
// existing database keeps its devices.
type DB struct{ sql *sql.DB }

func OpenDB(path string) (*DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// One connection: SQLite serializes writes anyway, and ":memory:" is per connection.
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`
		PRAGMA journal_mode = WAL;
		CREATE TABLE IF NOT EXISTS devices (
			id TEXT PRIMARY KEY,
			kind TEXT NOT NULL,
			public_key TEXT NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			push_token TEXT,
			created_at INTEGER NOT NULL,
			last_seen INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS queue (
			seq INTEGER PRIMARY KEY AUTOINCREMENT,
			recipient TEXT NOT NULL,
			sender TEXT NOT NULL,
			sender_pk TEXT NOT NULL,
			body TEXT NOT NULL,
			at INTEGER NOT NULL,
			expires INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS queue_recipient ON queue (recipient, seq);`)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &DB{db}, nil
}

func (d *DB) Close() error { return d.sql.Close() }

// InsertDevice returns false on an id or token collision; the caller retries with a new id.
func (d *DB) InsertDevice(dev Device, tokenHash string, now int64) (bool, error) {
	_, err := d.sql.Exec(
		"INSERT INTO devices (id, kind, public_key, token_hash, push_token, created_at, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)",
		dev.ID, dev.Kind, dev.PublicKey, tokenHash, dev.PushToken, now, now)
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return false, nil
	}
	return err == nil, err
}

func (d *DB) device(where string, arg string) (*Device, error) {
	var dev Device
	var push sql.NullString
	err := d.sql.QueryRow("SELECT id, kind, public_key, push_token FROM devices WHERE "+where+" = ?", arg).
		Scan(&dev.ID, &dev.Kind, &dev.PublicKey, &push)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if push.Valid {
		dev.PushToken = &push.String
	}
	return &dev, nil
}

func (d *DB) DeviceByID(id string) (*Device, error)       { return d.device("id", id) }
func (d *DB) DeviceByTokenHash(h string) (*Device, error) { return d.device("token_hash", h) }

func (d *DB) Touch(id string, now int64) error {
	_, err := d.sql.Exec("UPDATE devices SET last_seen = ? WHERE id = ?", now, id)
	return err
}

func (d *DB) SetPushToken(id string, token *string) error {
	_, err := d.sql.Exec("UPDATE devices SET push_token = ? WHERE id = ?", token, id)
	return err
}

func (d *DB) DeleteDevice(id string) error {
	if _, err := d.sql.Exec("DELETE FROM devices WHERE id = ?", id); err != nil {
		return err
	}
	_, err := d.sql.Exec("DELETE FROM queue WHERE recipient = ?", id)
	return err
}

// Enqueue stores m for recipient and keeps only its newest maxPerRecipient messages.
func (d *DB) Enqueue(recipient string, m Queued, expires int64, maxPerRecipient int) error {
	if _, err := d.sql.Exec(
		"INSERT INTO queue (recipient, sender, sender_pk, body, at, expires) VALUES (?, ?, ?, ?, ?, ?)",
		recipient, m.Sender, m.SenderPk, m.Body, m.At, expires); err != nil {
		return err
	}
	_, err := d.sql.Exec(
		"DELETE FROM queue WHERE recipient = ? AND seq NOT IN (SELECT seq FROM queue WHERE recipient = ? ORDER BY seq DESC LIMIT ?)",
		recipient, recipient, maxPerRecipient)
	return err
}

// Take removes and returns the recipient's unexpired messages, oldest first.
func (d *DB) Take(recipient string, now int64) ([]Queued, error) {
	rows, err := d.sql.Query(
		"DELETE FROM queue WHERE recipient = ? AND expires > ? RETURNING seq, sender, sender_pk, body, at",
		recipient, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type row struct {
		seq int64
		m   Queued
	}
	var got []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.seq, &r.m.Sender, &r.m.SenderPk, &r.m.Body, &r.m.At); err != nil {
			return nil, err
		}
		got = append(got, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(got, func(i, j int) bool { return got[i].seq < got[j].seq })
	out := make([]Queued, len(got))
	for i, r := range got {
		out[i] = r.m
	}
	return out, nil
}

// Purge drops expired queued messages.
func (d *DB) Purge(now int64) error {
	_, err := d.sql.Exec("DELETE FROM queue WHERE expires <= ?", now)
	return err
}
