package elementskin

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestExactServiceTokenAndCursorPagination(t *testing.T) {
	p1, _ := os.ReadFile("testdata/page1.json")
	p2, _ := os.ReadFile("testdata/page2.json")
	tokens, pages := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			tokens++
			b, _ := io.ReadAll(r.Body)
			q, _ := url.ParseQuery(string(b))
			if r.Method != "POST" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || q.Get("client_id") != "id" || q.Get("client_secret") != "secret" || q.Get("grant_type") != "client_credentials" || q.Get("scope") != "profile.read.any" || len(q) != 4 {
				t.Error("token request", q)
			}
			w.Write([]byte(`{"access_token":"service","token_type":"Bearer","expires_in":300}`))
		case "/v2/admin/profiles":
			pages++
			if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer service" || r.URL.Query().Get("limit") != "100" || r.URL.Query().Has("next_cursor") {
				t.Error(r.URL, r.Header)
			}
			if r.URL.Query().Get("cursor") == "" {
				w.Write(p1)
			} else if r.URL.Query().Get("cursor") == "opaque+/=" {
				w.Write(p2)
			} else {
				t.Error("wrong cursor")
			}
		case "/authserver/validate":
			if r.Method != "POST" || r.URL.RawQuery != "a=b" {
				t.Error(r.Method, r.URL)
			}
			w.WriteHeader(204)
		default:
			t.Error(r.URL)
		}
	}))
	defer srv.Close()
	c := New(srv.URL, "id", "secret", &http.Client{Timeout: time.Second})
	profiles, err := c.Profiles(context.Background(), "")
	if err != nil || len(profiles) != 2 || profiles[0].Name != "UnionTest" || profiles[1].ID != "22222222222242228222222222222222" {
		t.Fatal(profiles, err)
	}
	p, err := c.Find(context.Background(), profiles[0].ID, "UnionTest")
	if err != nil || p.Email != "test@example.org" {
		t.Fatal(p, err)
	}
	p, err = c.Lookup(context.Background(), "uniontest")
	if err != nil || p.ID != profiles[0].ID {
		t.Fatal(p, err)
	}
	if _, err = c.Find(context.Background(), "missing", "UnionTest"); err == nil {
		t.Fatal("missing profile found")
	}
	if _, err = c.Lookup(context.Background(), "Missing"); err == nil {
		t.Fatal("missing name found")
	}
	r, err := c.Proxy(context.Background(), "POST", "/authserver/validate", "a=b", []byte("{}"))
	if err != nil || r.Status != 204 {
		t.Fatal(r, err)
	}
	if tokens != 1 || pages != 10 {
		t.Fatal("token/page count", tokens, pages)
	}
}

func TestRejectsUntrustedTokenAndPageResponses(t *testing.T) {
	for _, tc := range []struct {
		name, token, page       string
		tokenStatus, pageStatus int
	}{
		{"token rejection", "", "", 403, 200},
		{"malformed token", "bad", "", 200, 200},
		{"empty token", `{"access_token":"","token_type":"Bearer","expires_in":300}`, "", 200, 200},
		{"page rejection", "", "", 200, 401},
		{"missing items", "", `{"page_size":0}`, 200, 200},
		{"malformed page", "", "bad", 200, 200},
		{"wrong size", "", `{"items":[],"has_next":false,"page_size":1}`, 200, 200},
		{"invalid identity", "", `{"items":[{"id":"bad","name":"Test"}],"page_size":1}`, 200, 200},
		{"cursor missing", "", `{"items":[],"has_next":true,"page_size":0}`, 200, 200},
		{"duplicate page", "", `{"items":[{"id":"11111111111141118111111111111111","name":"Test"}],"page_size":1,"has_next":true,"next_cursor":"repeat"}`, 200, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/oauth/token" {
					w.WriteHeader(tc.tokenStatus)
					token := tc.token
					if token == "" {
						token = `{"access_token":"service","token_type":"Bearer","expires_in":300}`
					}
					w.Write([]byte(token))
				} else {
					w.WriteHeader(tc.pageStatus)
					w.Write([]byte(tc.page))
				}
			}))
			defer srv.Close()
			c := New(srv.URL, "id", "secret", &http.Client{Timeout: time.Second})
			if _, err := c.Profiles(context.Background(), ""); err == nil {
				t.Fatal("invalid response accepted")
			}
			if tc.pageStatus == 401 && c.token != "" {
				t.Fatal("rejected service token cached")
			}
		})
	}
	c := New("http://127.0.0.1:1", "id", "secret", &http.Client{Timeout: time.Second})
	if _, err := c.Profiles(context.Background(), ""); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal(err)
	}
}
