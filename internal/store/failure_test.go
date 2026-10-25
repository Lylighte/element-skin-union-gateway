package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lylighte/element-skin-union-gateway/internal/model"
)

func TestDatabaseFailuresRollbackRelatedState(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "state.db"), filepath.Join(dir, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	exec := func(q string) {
		t.Helper()
		if _, e := s.db.Exec(q); e != nil {
			t.Fatal(e)
		}
	}
	count := func(table string, want int) {
		t.Helper()
		var n int
		if e := s.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); e != nil || n != want {
			t.Fatal(table, n, e)
		}
	}
	exec("CREATE TRIGGER fail_state BEFORE UPDATE ON gateway_state BEGIN SELECT RAISE(ABORT,'state write denied'); END")
	if e := s.Activate(ctx, model.Generation{Version: 1, Fingerprint: "fp", Ref: "ref"}); e == nil || !strings.Contains(e.Error(), "state write denied") {
		t.Fatal(e)
	}
	count("signing_generations", 0)
	if _, e := s.RequestSync(ctx, "event-rollback"); e == nil || !strings.Contains(e.Error(), "state write denied") {
		t.Fatal(e)
	}
	count("webhook_receipts", 0)
	if e := s.SetDirectory(ctx, 2, []model.Member{{Code: "T", Root: "https://test.example"}}); e == nil {
		t.Fatal("directory state committed")
	}
	count("union_members", 0)
	if e := s.CommitProfiles(ctx, []model.Profile{{ID: "id", Name: "Test"}}, 1); e == nil {
		t.Fatal("profile state committed")
	}
	count("local_profiles", 0)
	if e := s.SetMember(ctx, "ref"); e == nil {
		t.Fatal("member credential committed")
	}
	if e := s.Failure(ctx, "failure"); e == nil {
		t.Fatal("error state committed")
	}
	exec("DROP TRIGGER fail_state")
	exec("CREATE TRIGGER fail_block BEFORE INSERT ON blocked_profiles WHEN NEW.id='second' BEGIN SELECT RAISE(ABORT,'block denied'); END")
	if e := s.Block(ctx, []string{"first", "second"}); e == nil || !strings.Contains(e.Error(), "block denied") {
		t.Fatal(e)
	}
	count("blocked_profiles", 0)
	exec("CREATE TRIGGER fail_nonce BEFORE INSERT ON callback_nonces BEGIN SELECT RAISE(ABORT,'nonce denied'); END")
	if e := s.Nonce(ctx, "nonce", time.Now()); e == nil || !strings.Contains(e.Error(), "nonce denied") {
		t.Fatal(e)
	}
	count("callback_nonces", 0)
	exec("INSERT INTO join_receipts(server_hash,profile_id,expires_at) VALUES('expired','old',0)")
	exec("CREATE TRIGGER fail_join BEFORE INSERT ON join_receipts BEGIN SELECT RAISE(ABORT,'join receipt denied'); END")
	if e := s.RecordJoin(ctx, "server", "profile"); e == nil || !strings.Contains(e.Error(), "join receipt denied") {
		t.Fatal(e)
	}
	count("join_receipts", 1)
	exec("CREATE TRIGGER fail_receipt BEFORE INSERT ON webhook_receipts BEGIN SELECT RAISE(ABORT,'receipt denied'); END")
	if _, e := s.RequestSync(ctx, "event"); e == nil || !strings.Contains(e.Error(), "receipt denied") {
		t.Fatal(e)
	}
	count("webhook_receipts", 0)
}

func TestClosedDatabaseAndSecretDirectoryFailures(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "db")
	secretDir := filepath.Join(dir, "secrets")
	s, err := Open(path, secretDir)
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(secretDir)
	if _, e := s.WriteSecret([]byte("not-persisted")); !os.IsNotExist(e) {
		t.Fatal(e)
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	for _, op := range []func() error{
		func() error { _, e := s.State(ctx); return e },
		func() error { return s.Activate(ctx, model.Generation{Version: 1}) },
		func() error { return s.SetMember(ctx, "ref") },
		func() error { return s.SetDirectory(ctx, 1, nil) },
		func() error { _, e := s.Members(ctx); return e },
		func() error { return s.CommitProfiles(ctx, nil, 0) },
		func() error { _, e := s.Local(ctx, "id"); return e },
		func() error { return s.Block(ctx, []string{"id"}) },
		func() error { _, e := s.RequestSync(ctx, "event"); return e },
		func() error { return s.Nonce(ctx, "nonce", time.Now()) },
		func() error { return s.RecordJoin(ctx, "server", "id") },
		func() error { _, e := s.Joined(ctx, "server"); return e },
	} {
		e := op()
		if e == nil || e.Error() != "sql: database is closed" {
			t.Fatal(e)
		}
	}
	if e := os.WriteFile(path, []byte("not a database"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := Open(path, secretDir); e == nil {
		t.Fatal("corrupt database")
	}
}
