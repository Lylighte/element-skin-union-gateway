package netutil

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBoundedRequestsAndDecoding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			if r.Method != "POST" || r.Header.Get("X-Test") != "present" || r.Header.Get("Accept") != "application/json" {
				t.Error("request headers")
			}
			w.WriteHeader(201)
			w.Write([]byte(`{"id":1}`))
		case "/redirect":
			w.Header().Set("Location", "/ok")
			w.WriteHeader(302)
		case "/large":
			w.Write([]byte(strings.Repeat("x", MaxBody+1)))
		}
	}))
	defer srv.Close()
	c := Client(time.Second)
	r, err := Do(context.Background(), c, "POST", srv.URL+"/ok", []byte("{}"), http.Header{"X-Test": {"present"}})
	if err != nil || r.Status != 201 || string(r.Body) != `{"id":1}` {
		t.Fatalf("%+v %v", r, err)
	}
	for _, target := range []string{srv.URL + "/redirect", srv.URL + "/large", "://bad"} {
		if _, err = Do(context.Background(), c, "GET", target, nil, http.Header{}); err == nil {
			t.Fatal(target)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = Do(ctx, c, "GET", srv.URL, nil, http.Header{}); err == nil {
		t.Fatal("cancelled request accepted")
	}
	var value map[string]int
	if Decode([]byte(`{"id":1}`), &value) != nil || value["id"] != 1 {
		t.Fatal(value)
	}
	for _, body := range []string{"bad", `{} {}`} {
		if Decode([]byte(body), &value) == nil {
			t.Fatal(body)
		}
	}
}
