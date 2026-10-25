package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func cliConfig(t *testing.T, listen string) string {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "client"), []byte("synthetic-client"), 0600)
	os.WriteFile(filepath.Join(dir, "admin"), []byte(strings.Repeat("a", 64)), 0600)
	text := fmt.Sprintf("listen: %q\npublic_root: https://union.example.org/sub\nelementskin_api_url: http://127.0.0.1:1\nelementskin_site_url: https://skin.example.org\nservice_client_id: application\nservice_client_secret_file: client\nadmin_token_file: admin\nstate_path: data/state.db\nsecret_dir: data/secrets\n", listen)
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCommandsAndGracefulServer(t *testing.T) {
	var out, errOut bytes.Buffer
	ctx := context.Background()
	for _, tc := range []struct {
		args   []string
		output string
	}{{[]string{"version"}, "0.1.0\n"}, {[]string{"check-config", "-config", cliConfig(t, "127.0.0.1:0")}, "configuration valid\n"}} {
		out.Reset()
		if err := run(ctx, tc.args, &out, &errOut); err != nil || out.String() != tc.output {
			t.Fatal(out.String(), err)
		}
	}
	out.Reset()
	if err := run(ctx, []string{"generate-secret"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	b, err := hex.DecodeString(strings.TrimSpace(out.String()))
	if err != nil || len(b) != 32 {
		t.Fatal(out.String(), err)
	}
	for _, args := range [][]string{{"unknown"}, {"serve", "-unknown"}, {"serve", "extra"}, {"check-config", "-config", "missing"}} {
		if err = run(ctx, args, &out, &errOut); err == nil {
			t.Fatal(args)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/live" || r.URL.Path == "/sub/health/live" {
			w.Write([]byte("{}"))
			return
		}
		if r.URL.Path == "/health/bad" {
			w.WriteHeader(503)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/sub/admin/") || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 64) {
			t.Error("admin request", r.URL.Path)
		}
		if strings.HasSuffix(r.URL.Path, "/diagnose") {
			w.WriteHeader(502)
		}
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")
	path := cliConfig(t, host)
	if err = run(ctx, []string{"healthcheck", "-url", server.URL + "/health/live"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if err = run(ctx, []string{"healthcheck", "-url", server.URL + "/health/bad"}, &out, &errOut); err == nil {
		t.Fatal("unhealthy")
	}
	if err = run(ctx, []string{"healthcheck", "-config", path}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if err = run(ctx, []string{"serve", "-config", path}, &out, &errOut); err == nil || err.Error() != "listen_failed" {
		t.Fatal("occupied listener", err)
	}
	for _, action := range []string{"status", "sync", "refresh-key", "refresh-directory"} {
		out.Reset()
		if err = run(ctx, []string{"admin", "-config", path, "-action", action}, &out, &errOut); err != nil || out.String() != `{"status":"ok"}` {
			t.Fatal(action, out.String(), err)
		}
	}
	for _, action := range []string{"diagnose", "unknown"} {
		if err = run(ctx, []string{"admin", "-config", path, "-action", action}, &out, &errOut); err == nil {
			t.Fatal(action)
		}
	}
	serveCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	errOut.Reset()
	if err = run(serveCtx, []string{"serve", "-config", cliConfig(t, "127.0.0.1:0")}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errOut.String(), "gateway_started") || strings.Contains(errOut.String(), "synthetic-client") {
		t.Fatal(errOut.String())
	}
}

func TestMainEntryPoint(t *testing.T) {
	args := os.Args
	defer func() { os.Args = args }()
	os.Args = []string{"union-gateway", "version"}
	main()
}
