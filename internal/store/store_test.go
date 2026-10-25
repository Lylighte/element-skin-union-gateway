package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lylighte/element-skin-union-gateway/internal/model"
)

func TestDurableStateTransactionsAndReplay(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "state.db"), filepath.Join(dir, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	ref, err := s.WriteSecret([]byte("synthetic-secret"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.ReadSecret(ref)
	if err != nil || string(got) != "synthetic-secret" {
		t.Fatal(string(got), err)
	}
	if _, err = s.ReadSecret("../escape"); !errors.Is(err, model.ErrInvalid) {
		t.Fatal(err)
	}
	if _, err = s.ReadSecret("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz.secret"); !errors.Is(err, model.ErrInvalid) {
		t.Fatal(err)
	}
	if err = s.SetMember(ctx, ref); err != nil {
		t.Fatal(err)
	}
	g := model.Generation{Version: 1, Fingerprint: "fingerprint", Ref: ref}
	if err = s.Activate(ctx, g); err != nil {
		t.Fatal(err)
	}
	if err = s.Activate(ctx, g); err == nil {
		t.Fatal("same version")
	}
	members := []model.Member{{Code: "TEST", Root: "https://test.example"}, {Code: "TEST", Root: "https://other.example"}}
	if err = s.SetDirectory(ctx, 2, members); err != nil {
		t.Fatal(err)
	}
	if err = s.SetDirectory(ctx, 1, members); err == nil {
		t.Fatal("rollback")
	}
	if err = s.SetDirectory(ctx, 3, append(members, members[0])); err == nil {
		t.Fatal("duplicate")
	}
	ms, err := s.Members(ctx)
	if err != nil || len(ms) != 2 || ms[0].Root != "https://other.example" {
		t.Fatal(ms, err)
	}
	profiles := []model.Profile{{ID: "11111111111141118111111111111111", Name: "UnionTest"}}
	if err = s.CommitProfiles(ctx, profiles, 1); err != nil {
		t.Fatal(err)
	}
	if err = s.CommitProfiles(ctx, append(profiles, profiles[0]), 2); err == nil {
		t.Fatal("duplicate profile committed")
	}
	p, err := s.Local(ctx, profiles[0].ID)
	if err != nil || p.Name != "UnionTest" {
		t.Fatal(p, err)
	}
	if err = s.RecordJoin(ctx, "server-id", p.ID); err != nil {
		t.Fatal(err)
	}
	if id, e := s.Joined(ctx, "server-id"); e != nil || id != p.ID {
		t.Fatal(id, e)
	}
	if _, e := s.Joined(ctx, "missing"); !errors.Is(e, model.ErrIdentity) {
		t.Fatal(e)
	}
	if err = s.Block(ctx, []string{p.ID}); err != nil {
		t.Fatal(err)
	}
	if _, e := s.Local(ctx, p.ID); !errors.Is(e, model.ErrIdentity) {
		t.Fatal(e)
	}
	for _, event := range []string{"event", "event", ""} {
		fresh, e := s.RequestSync(ctx, event)
		if e != nil {
			t.Fatal(e)
		}
		if event == "" && !fresh {
			t.Fatal("manual request deduplicated")
		}
	}
	var count atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			if e := s.Nonce(ctx, "same-nonce", time.Now()); e == nil {
				count.Add(1)
			} else if !errors.Is(e, model.ErrReplay) {
				t.Error(e)
			}
		})
	}
	wg.Wait()
	if count.Load() != 1 {
		t.Fatal(count.Load())
	}
	if err = s.Failure(ctx, "test_failure"); err != nil {
		t.Fatal(err)
	}
	state, err := s.State(ctx)
	if err != nil || state.Generation != g || state.MemberRef != ref || state.DirectoryVersion != 2 || state.Requested != 3 || state.Completed != 1 || state.LastError != "test_failure" || state.SyncedAt <= 0 {
		t.Fatalf("%+v %v", state, err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(filepath.Join(dir, "state.db"), filepath.Join(dir, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	state, err = s.State(ctx)
	if err != nil || state.Generation.Version != 1 || state.Requested != 3 {
		t.Fatal(state, err)
	}
	if _, err = s.db.Exec("UPDATE join_receipts SET expires_at=0"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Joined(ctx, "server-id"); !errors.Is(err, model.ErrIdentity) {
		t.Fatal(err)
	}
}

func TestOpenAndSecretErrors(t *testing.T) {
	dir := t.TempDir()
	block := filepath.Join(dir, "file")
	if err := os.WriteFile(block, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(block, "db"), dir); err == nil {
		t.Fatal("bad state path")
	}
	if _, err := Open(filepath.Join(dir, "db"), block); err == nil {
		t.Fatal("bad secret dir")
	}
	s, err := Open(filepath.Join(dir, "db"), filepath.Join(dir, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReadSecret("000000000000000000000000000000000000000000000000.secret"); err == nil {
		t.Fatal("missing file")
	}
	s.Close()
	if err = s.Activate(context.Background(), model.Generation{Version: 1}); err == nil {
		t.Fatal("closed db")
	}
}
