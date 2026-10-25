package service_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Lylighte/element-skin-union-gateway/internal/model"
	"github.com/Lylighte/element-skin-union-gateway/internal/service"
	"github.com/Lylighte/element-skin-union-gateway/internal/signing"
	"github.com/Lylighte/element-skin-union-gateway/internal/store"
	"github.com/Lylighte/element-skin-union-gateway/internal/testutil"
)

func TestKeyActivationRollbackAndRestart(t *testing.T) {
	f := testutil.New(t)
	f.Ready()
	ctx := context.Background()
	state, err := f.Store.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	before := state.Generation
	for _, tc := range []struct {
		name   string
		change func(*testutil.Fixture)
	}{
		{"invalid PEM", func(f *testutil.Fixture) { f.Private = "not-a-key"; f.KeyVersion = 2 }},
		{"rollback", func(f *testutil.Fixture) { f.KeyVersion = 0 }},
		{"upstream rejection", func(f *testutil.Fixture) { f.FailPath = "/privatekey"; f.FailStatus = 403 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.Update(func(f *testutil.Fixture) {
				f.Private = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(f.Key.Private)}))
				f.KeyVersion = 1
				f.FailPath = ""
				tc.change(f)
			})
			if err = f.Service.RefreshKey(ctx); err == nil {
				t.Fatal("bad activation accepted")
			}
			got, e := f.Store.State(ctx)
			if e != nil || got.Generation != before {
				t.Fatal(got, e)
			}
		})
	}
	candidate, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	raw := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(candidate)})
	newKey, e := signing.ParsePrivate(raw)
	if e != nil {
		t.Fatal(e)
	}
	f.Update(func(f *testutil.Fixture) { f.FailPath = ""; f.Private = string(raw); f.KeyVersion = 2 })
	if err = f.Service.RefreshKey(ctx); err == nil {
		t.Fatal("public mismatch accepted")
	}
	f.Update(func(f *testutil.Fixture) { f.Key = newKey; f.KeyVersion = 1 })
	if err = f.Service.RefreshKey(ctx); err == nil {
		t.Fatal("same version different key")
	}
	f.Update(func(f *testutil.Fixture) { f.KeyVersion = 2 })
	if err = f.Service.RefreshKey(ctx); err != nil {
		t.Fatal(err)
	}
	if err = f.Service.RefreshKey(ctx); err != nil {
		t.Fatal("idempotency", err)
	}
	if err = f.Service.SetMember(ctx, "updated-member"); err != nil {
		t.Fatal(err)
	}
	if err = f.Service.SetMember(ctx, "updated-member"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "bad\nkey"} {
		if !errors.Is(f.Service.SetMember(ctx, bad), model.ErrInvalid) {
			t.Fatal(bad)
		}
	}
	restarted, e := service.New(ctx, f.Cfg, f.Store, f.Service.Skin, f.Service.Hub, f.Service.Log)
	if e != nil {
		t.Fatal(e)
	}
	status, e := restarted.Status(ctx)
	if e != nil || status["active_key_version"] != int64(2) || status["public_key_fingerprint"] != newKey.Fingerprint || status["ready"] != true {
		t.Fatal(status, e)
	}
	if e = restarted.RefreshDirectory(ctx); e != nil {
		t.Fatal(e)
	}
	calls := f.Recorded()
	if calls[len(calls)-1].Member != "updated-member" {
		t.Fatal("restart lost member credential")
	}
	state, e = f.Store.State(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if err = os.Remove(filepath.Join(f.Cfg.SecretDir, state.Generation.Ref)); err != nil {
		t.Fatal(err)
	}
	if _, e = service.New(ctx, f.Cfg, f.Store, f.Service.Skin, f.Service.Hub, f.Service.Log); e == nil {
		t.Fatal("missing active key replaced")
	}
}

func TestReconciliationFailureKeepsPriorSnapshot(t *testing.T) {
	f := testutil.New(t)
	f.Ready()
	ctx := context.Background()
	state, _ := f.Store.State(ctx)
	f.Update(func(f *testutil.Fixture) {
		f.Profiles = []model.Profile{{ID: testutil.OtherID, Name: "NewPlayer"}}
		f.FailPath = "/sync"
		f.FailStatus = 500
	})
	if err := f.Service.Sync(ctx); err == nil {
		t.Fatal("failed Hub sync")
	}
	p, err := f.Store.Local(ctx, testutil.ID)
	if err != nil || p.Name != "UnionTest" {
		t.Fatal(p, err)
	}
	after, _ := f.Store.State(ctx)
	if after.Completed != state.Completed || after.SyncedAt != state.SyncedAt {
		t.Fatal(after)
	}
	f.Update(func(f *testutil.Fixture) { f.FailPath = "/v2/admin/profiles"; f.FailStatus = 503 })
	n := len(f.Recorded())
	if err = f.Service.Sync(ctx); err == nil {
		t.Fatal("partial upstream failure")
	}
	for _, call := range f.Recorded()[n:] {
		if call.Path == "/sync" {
			t.Fatal("submitted partial snapshot")
		}
	}
	f.Update(func(f *testutil.Fixture) { f.FailPath = "" })
	if err = f.Service.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = f.Store.Local(ctx, testutil.ID); !errors.Is(err, model.ErrIdentity) {
		t.Fatal(err)
	}
	if _, err = f.Store.Local(ctx, testutil.OtherID); err != nil {
		t.Fatal(err)
	}
}

func TestBackgroundBootstrapAndUnregisteredState(t *testing.T) {
	f := testutil.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	f.Service.Run(ctx)
	if !f.Service.Ready(context.Background()) {
		t.Fatal("bootstrap not ready")
	}
	for _, call := range f.Recorded() {
		if call.Path == "/sync" && call.Body != `{"profileList":{"11111111111141118111111111111111":"UnionTest"}}` {
			t.Fatal(call.Body)
		}
	}
	// A separately initialized member can receive signed bootstrap calls before it has a key.
	f2 := testutil.New(t)
	f2.Cfg.MemberKey = ""
	dir := t.TempDir()
	f2.Cfg.StatePath = filepath.Join(dir, "db")
	f2.Cfg.SecretDir = filepath.Join(dir, "secrets")
	if err := f2.Service.VerifyCallback(context.Background(), nil, "bad", "nonce", "signature"); !errors.Is(err, model.ErrInvalid) {
		t.Fatal(err)
	}
	st, err := store.Open(f2.Cfg.StatePath, f2.Cfg.SecretDir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	unregistered, err := service.New(context.Background(), f2.Cfg, st, f2.Service.Skin, f2.Service.Hub, f2.Service.Log)
	if err != nil {
		t.Fatal(err)
	}
	if unregistered.Ready(context.Background()) {
		t.Fatal("unregistered member ready")
	}
	for _, op := range []func(context.Context) error{unregistered.RefreshDirectory, unregistered.RefreshKey, unregistered.Sync} {
		if err = op(context.Background()); !errors.Is(err, model.ErrNotReady) {
			t.Fatal(err)
		}
	}
	if _, err = unregistered.Diagnose(context.Background()); !errors.Is(err, model.ErrNotReady) {
		t.Fatal(err)
	}
	if _, err = unregistered.QueryEmail(context.Background(), "UnionTest"); err == nil || err.Error() != "query_email_disabled" {
		t.Fatal(err)
	}
}
