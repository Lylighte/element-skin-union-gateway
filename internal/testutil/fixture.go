package testutil

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lylighte/element-skin-union-gateway/internal/adapter/elementskin"
	"github.com/Lylighte/element-skin-union-gateway/internal/config"
	"github.com/Lylighte/element-skin-union-gateway/internal/model"
	"github.com/Lylighte/element-skin-union-gateway/internal/netutil"
	"github.com/Lylighte/element-skin-union-gateway/internal/service"
	"github.com/Lylighte/element-skin-union-gateway/internal/signing"
	"github.com/Lylighte/element-skin-union-gateway/internal/store"
	"github.com/Lylighte/element-skin-union-gateway/internal/union"
)

const ID = "11111111111141118111111111111111"
const OtherID = "22222222222242228222222222222222"

type Call struct{ Method, Path, Query, Member, Body string }
type Fixture struct {
	T          testing.TB
	Service    *service.Service
	Store      *store.Store
	Cfg        config.Config
	Skin, Hub  *httptest.Server
	Key        *signing.Key
	Host       *rsa.PrivateKey
	Private    string
	mu         sync.Mutex
	Calls      []Call
	Profiles   []model.Profile
	KeyVersion int64
	MappedName string
	FailPath   string
	FailStatus int
	Joined     bool
	Revoked    bool
	ProfileID  string
	BadTexture bool
	Responses  map[string]model.Response
}

func New(t testing.TB) *Fixture {
	t.Helper()
	private, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(private)})
	key, e := signing.ParsePrivate(data)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	f := &Fixture{T: t, Key: key, Host: private, Private: string(data), KeyVersion: 1, MappedName: "UnionTest", ProfileID: ID, Profiles: []model.Profile{{ID: ID, Name: "UnionTest", UserID: "owner", Email: "test@example.org"}}}
	f.Skin = httptest.NewServer(http.HandlerFunc(f.skin))
	f.Hub = httptest.NewServer(http.HandlerFunc(f.hub))
	t.Cleanup(f.Skin.Close)
	t.Cleanup(f.Hub.Close)
	c := config.Config{Listen: "127.0.0.1:8267", PublicRoot: "https://union.example.org", SiteName: "Test Union", ElementSkinURL: f.Skin.URL, ElementSkinSite: "https://skin.example.org", ClientID: "test-client", ClientSecret: "synthetic-client-secret", AdminToken: strings.Repeat("a", 64), MemberKey: "synthetic-member", WebhookSecret: "synthetic-webhook", StatePath: filepath.Join(dir, "state.db"), SecretDir: filepath.Join(dir, "secrets"), Scope: "profile.read.any", TimeoutSeconds: 2, SyncSeconds: 10}
	f.Cfg = c
	f.Store, e = store.Open(c.StatePath, c.SecretDir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.Store.Close() })
	client := netutil.Client(2 * time.Second)
	f.Service, e = service.New(context.Background(), c, f.Store, elementskin.New(f.Skin.URL, c.ClientID, c.ClientSecret, client), union.New(f.Hub.URL, client), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if e != nil {
		t.Fatal(e)
	}
	return f
}

func (f *Fixture) Ready() {
	f.T.Helper()
	ctx := context.Background()
	for _, op := range []func(context.Context) error{f.Service.RefreshDirectory, f.Service.RefreshKey, f.Service.Sync} {
		if err := op(ctx); err != nil {
			f.T.Fatal(err)
		}
	}
}

func (f *Fixture) Update(fn func(*Fixture)) { f.mu.Lock(); defer f.mu.Unlock(); fn(f) }
func (f *Fixture) Recorded() []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Call(nil), f.Calls...)
}
func (f *Fixture) record(r *http.Request) bool {
	b, _ := io.ReadAll(r.Body)
	f.Calls = append(f.Calls, Call{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("X-Union-Member-Key"), string(b)})
	return r.URL.Path == f.FailPath
}
func output(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(value)
}

func (f *Fixture) skin(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.record(r) {
		w.WriteHeader(f.FailStatus)
		w.Write([]byte(`{"error":"ForbiddenOperationException","errorMessage":"Rejected."}`))
		return
	}
	if response, ok := f.Responses[r.URL.Path]; ok {
		w.WriteHeader(response.Status)
		w.Write(response.Body)
		return
	}
	switch {
	case r.URL.Path == "/oauth/token":
		output(w, map[string]any{"access_token": "service-token", "token_type": "Bearer", "expires_in": 300})
	case r.URL.Path == "/v2/admin/profiles":
		if r.Header.Get("Authorization") != "Bearer service-token" {
			f.T.Error("service token")
		}
		ps := []model.Profile{}
		for _, p := range f.Profiles {
			if q := r.URL.Query().Get("q"); q == "" || strings.Contains(strings.ToLower(p.Name), strings.ToLower(q)) {
				ps = append(ps, p)
			}
		}
		output(w, map[string]any{"items": ps, "has_next": false, "next_cursor": "", "page_size": len(ps)})
	case r.URL.Path == "/authserver/authenticate" || r.URL.Path == "/authserver/refresh":
		output(w, map[string]any{"accessToken": "synthetic-user-token", "clientToken": "client-token", "selectedProfile": map[string]string{"id": ID, "name": "UnionTest"}, "availableProfiles": []map[string]string{{"id": ID, "name": "UnionTest"}}})
	case r.URL.Path == "/authserver/validate" || r.URL.Path == "/authserver/invalidate" || r.URL.Path == "/authserver/signout":
		w.WriteHeader(204)
	case r.URL.Path == "/sessionserver/session/minecraft/join":
		f.Joined = true
		w.WriteHeader(204)
	case r.URL.Path == "/sessionserver/session/minecraft/hasJoined" || strings.HasPrefix(r.URL.Path, "/sessionserver/session/minecraft/profile/"):
		if f.Revoked {
			w.WriteHeader(403)
			w.Write([]byte(`{"error":"ForbiddenOperationException","errorMessage":"Permission denied."}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "hasJoined") && !f.Joined {
			w.WriteHeader(204)
			return
		}
		id := f.ProfileID
		if f.BadTexture {
			id = OtherID
		}
		texture, _ := json.Marshal(map[string]any{"timestamp": 1786118400123, "profileId": id, "profileName": "UnionTest", "textures": map[string]any{"SKIN": map[string]any{"url": "https://skin.example.org/static/textures/skin.png", "metadata": map[string]string{"model": "slim"}}, "CAPE": map[string]string{"url": "https://skin.example.org/static/textures/cape.png"}}})
		output(w, model.YggProfile{ID: f.ProfileID, Name: "UnionTest", Properties: []model.Property{{Name: "textures", Value: base64.StdEncoding.EncodeToString(texture), Signature: "upstream-signature"}, {Name: "uploadableTextures", Value: "skin,cape"}}})
	default:
		f.T.Errorf("unexpected skin request: %s", r.URL.Path)
		w.WriteHeader(404)
	}
}

func (f *Fixture) hub(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.record(r) {
		w.WriteHeader(f.FailStatus)
		return
	}
	switch {
	case r.URL.Path == "" || r.URL.Path == "/":
		der, _ := x509.MarshalPKIXPublicKey(&f.Host.PublicKey)
		output(w, map[string]string{"union_host_signature_public_key": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))})
	case r.URL.Path == "/serverlist":
		output(w, map[string]any{"servers": []model.Member{{Code: "TEST", Root: "https://union.example.org/subpath"}, {Code: "OTHER", Root: "https://other.example.org"}}, "version": 2})
	case r.URL.Path == "/privatekey":
		output(w, map[string]any{"privateKey": f.Private, "privateKeyVersion": f.KeyVersion})
	case r.URL.Path == "/yggdrasil":
		output(w, map[string]string{"signaturePublicKey": f.Key.PublicPEM})
	case r.URL.Path == "/sync":
		w.WriteHeader(200)
	case strings.HasPrefix(r.URL.Path, "/profile/mapped/byuuid/"):
		output(w, map[string]string{"uuid": strings.TrimPrefix(r.URL.Path, "/profile/mapped/byuuid/"), "name": f.MappedName})
	case r.URL.Path == "/diagnose":
		output(w, map[string]string{"status": "ok"})
	default:
		f.T.Errorf("unexpected Hub request: %s", r.URL.Path)
		w.WriteHeader(404)
	}
}
