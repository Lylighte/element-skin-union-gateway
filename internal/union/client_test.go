package union

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Lylighte/element-skin-union-gateway/internal/model"
)

func TestRejectsMalformedHubResponsesAndStatuses(t *testing.T) {
	for _, tc := range []struct {
		name, path, body string
		status           int
	}{
		{"empty directory", "/serverlist", `{"servers":[],"version":1}`, 200},
		{"wrong directory type", "/serverlist", `{"servers":"bad","version":1}`, 200},
		{"invalid member", "/serverlist", `{"servers":[{"code":"TEST","bs_root":"http://bad.example"}],"version":1}`, 200},
		{"duplicate member", "/serverlist", `{"servers":[{"code":"TEST","bs_root":"https://test.example"},{"code":"TEST","bs_root":"https://test.example"}],"version":1}`, 200},
		{"key empty", "/privatekey", `{"privateKey":"","privateKeyVersion":1}`, 200},
		{"key malformed", "/privatekey", "bad", 200},
		{"public missing", "/yggdrasil", "{}", 200},
		{"host invalid", "", "{}", 200},
		{"mapped invalid", "/profile/mapped/byuuid/11111111111141118111111111111111", "bad", 200},
		{"mapped mismatch", "/profile/mapped/byuuid/11111111111141118111111111111111", `{"uuid":"22222222222242228222222222222222","name":"UnionTest"}`, 200},
		{"hub rejects", "/sync", "", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				actual := r.URL.Path
				if actual == "/" {
					actual = ""
				}
				if actual != tc.path {
					t.Error(r.URL.Path)
				}
				if tc.path != "" && tc.path != "/yggdrasil" && len(tc.path) < 20 && r.Header.Get("X-Union-Member-Key") != "member" {
					t.Error("member header")
				}
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			c := New(srv.URL, srv.Client())
			ctx := context.Background()
			var err error
			switch tc.path {
			case "/serverlist":
				_, _, err = c.Directory(ctx, "member")
			case "/privatekey":
				_, _, err = c.PrivateKey(ctx, "member")
			case "/yggdrasil":
				_, err = c.MaterialPublic(ctx)
			case "":
				_, err = c.HostPublic(ctx)
			case "/sync":
				err = c.Sync(ctx, "member", nil)
			default:
				err = c.CheckIdentity(ctx, model.Profile{ID: "11111111111141118111111111111111", Name: "UnionTest"})
			}
			if err == nil {
				t.Fatal("invalid response accepted")
			}
			if tc.status == 403 {
				var hub *Error
				if !errors.As(err, &hub) || hub.Status != 403 || hub.Error() != "union_rejected" {
					t.Fatal(err)
				}
			}
		})
	}
}
