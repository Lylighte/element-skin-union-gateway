package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Lylighte/element-skin-union-gateway/internal/model"
	_ "modernc.org/sqlite"
)

type Store struct {
	db      *sql.DB
	secrets string
}

const schema = `
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS signing_generations(version INTEGER PRIMARY KEY CHECK(version>0),fingerprint TEXT NOT NULL,ref TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS gateway_state(id INTEGER PRIMARY KEY CHECK(id=1),active_version INTEGER REFERENCES signing_generations(version),member_ref TEXT NOT NULL DEFAULT '',directory_version INTEGER NOT NULL DEFAULT 0,synced_at INTEGER NOT NULL DEFAULT 0,requested INTEGER NOT NULL DEFAULT 1,completed INTEGER NOT NULL DEFAULT 0,last_error TEXT NOT NULL DEFAULT '');
INSERT OR IGNORE INTO gateway_state(id) VALUES(1);
CREATE TABLE IF NOT EXISTS union_members(code TEXT NOT NULL,root_url TEXT NOT NULL,PRIMARY KEY(code,root_url));
CREATE TABLE IF NOT EXISTS local_profiles(id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE COLLATE NOCASE);
CREATE TABLE IF NOT EXISTS blocked_profiles(id TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS callback_nonces(nonce TEXT PRIMARY KEY,expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS webhook_receipts(id TEXT PRIMARY KEY,received_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS join_receipts(server_hash TEXT PRIMARY KEY,profile_id TEXT NOT NULL,expires_at INTEGER NOT NULL);
`

func Open(path, secrets string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(secrets, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	f.Close()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, secrets: secrets}, nil
}

func (s *Store) Close() error { return s.db.Close() }
func (s *Store) State(ctx context.Context) (model.State, error) {
	var v model.State
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(g.version,0),COALESCE(g.fingerprint,''),COALESCE(g.ref,''),member_ref,directory_version,synced_at,requested,completed,last_error FROM gateway_state s LEFT JOIN signing_generations g ON g.version=s.active_version WHERE s.id=1`).Scan(&v.Generation.Version, &v.Generation.Fingerprint, &v.Generation.Ref, &v.MemberRef, &v.DirectoryVersion, &v.SyncedAt, &v.Requested, &v.Completed, &v.LastError)
	return v, err
}

func (s *Store) WriteSecret(data []byte) (string, error) {
	random := make([]byte, 24)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	ref := hex.EncodeToString(random) + ".secret"
	path := filepath.Join(s.secrets, ref)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return "", err
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	if runtime.GOOS != "windows" {
		d, e := os.Open(s.secrets)
		if e != nil {
			return "", e
		}
		e = d.Sync()
		d.Close()
		if e != nil {
			return "", e
		}
	}
	ok = true
	return ref, nil
}

func (s *Store) ReadSecret(ref string) ([]byte, error) {
	if len(ref) != 55 || filepath.Base(ref) != ref || filepath.Ext(ref) != ".secret" {
		return nil, model.ErrInvalid
	}
	if _, err := hex.DecodeString(ref[:48]); err != nil {
		return nil, model.ErrInvalid
	}
	return os.ReadFile(filepath.Join(s.secrets, ref))
}

func (s *Store) Activate(ctx context.Context, g model.Generation) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current int64
	if err = tx.QueryRowContext(ctx, "SELECT COALESCE(active_version,0) FROM gateway_state WHERE id=1").Scan(&current); err != nil {
		return err
	}
	if g.Version <= current {
		return errors.New("key_version_conflict")
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO signing_generations(version,fingerprint,ref) VALUES(?,?,?)", g.Version, g.Fingerprint, g.Ref); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE gateway_state SET active_version=? WHERE id=1", g.Version); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) SetMember(ctx context.Context, ref string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE gateway_state SET member_ref=? WHERE id=1", ref)
	return err
}

func (s *Store) SetDirectory(ctx context.Context, version int64, members []model.Member) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current int64
	if err = tx.QueryRowContext(ctx, "SELECT directory_version FROM gateway_state WHERE id=1").Scan(&current); err != nil {
		return err
	}
	if version < current {
		return errors.New("directory_version_conflict")
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM union_members"); err != nil {
		return err
	}
	for _, m := range members {
		if _, err = tx.ExecContext(ctx, "INSERT INTO union_members(code,root_url) VALUES(?,?)", m.Code, m.Root); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, "UPDATE gateway_state SET directory_version=? WHERE id=1", version); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Members(ctx context.Context) ([]model.Member, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT code,root_url FROM union_members ORDER BY code,root_url")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []model.Member{}
	for rows.Next() {
		var m model.Member
		if err = rows.Scan(&m.Code, &m.Root); err != nil {
			return nil, err
		}
		result = append(result, m)
	}
	return result, rows.Err()
}

func (s *Store) CommitProfiles(ctx context.Context, profiles []model.Profile, revision int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "DELETE FROM local_profiles"); err != nil {
		return err
	}
	for _, p := range profiles {
		if _, err = tx.ExecContext(ctx, "INSERT INTO local_profiles(id,name) VALUES(?,?)", p.ID, p.Name); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, "UPDATE gateway_state SET synced_at=?,completed=?,last_error='' WHERE id=1", time.Now().UnixMilli(), revision); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Local(ctx context.Context, id string) (model.Profile, error) {
	var p model.Profile
	err := s.db.QueryRowContext(ctx, `SELECT id,name FROM local_profiles WHERE id=? AND NOT EXISTS(SELECT 1 FROM blocked_profiles WHERE id=?)`, id, id).Scan(&p.ID, &p.Name)
	if errors.Is(err, sql.ErrNoRows) {
		return p, model.ErrIdentity
	}
	return p, err
}

func (s *Store) Block(ctx context.Context, ids []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range ids {
		if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO blocked_profiles(id) VALUES(?)", id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) RequestSync(ctx context.Context, eventID string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if eventID != "" {
		if _, err = tx.ExecContext(ctx, "DELETE FROM webhook_receipts WHERE received_at<?", time.Now().Add(-7*24*time.Hour).UnixMilli()); err != nil {
			return false, err
		}
		res, e := tx.ExecContext(ctx, "INSERT OR IGNORE INTO webhook_receipts(id,received_at) VALUES(?,?)", eventID, time.Now().UnixMilli())
		if e != nil {
			return false, e
		}
		n, e := res.RowsAffected()
		if e != nil {
			return false, e
		}
		if n == 0 {
			return false, nil
		}
	}
	if _, err = tx.ExecContext(ctx, "UPDATE gateway_state SET requested=requested+1 WHERE id=1"); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

func (s *Store) Failure(ctx context.Context, code string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE gateway_state SET last_error=? WHERE id=1", code)
	return err
}

func (s *Store) Nonce(ctx context.Context, nonce string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "DELETE FROM callback_nonces WHERE expires_at<?", now.UnixMilli()); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO callback_nonces(nonce,expires_at) VALUES(?,?)", nonce, now.Add(time.Minute).UnixMilli())
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return model.ErrReplay
	}
	return tx.Commit()
}

func hash(value string) string { b := sha256.Sum256([]byte(value)); return hex.EncodeToString(b[:]) }
func (s *Store) RecordJoin(ctx context.Context, server, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "DELETE FROM join_receipts WHERE expires_at<?", time.Now().UnixMilli()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO join_receipts(server_hash,profile_id,expires_at) VALUES(?,?,?) ON CONFLICT(server_hash) DO UPDATE SET profile_id=excluded.profile_id,expires_at=excluded.expires_at", hash(server), id, time.Now().Add(30*time.Second).UnixMilli()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Joined(ctx context.Context, server string) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx, "SELECT profile_id FROM join_receipts WHERE server_hash=? AND expires_at>?", hash(server), time.Now().UnixMilli()).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", model.ErrIdentity
	}
	return id, err
}
