package httpapi_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lylighte/element-skin-union-gateway/internal/httpapi"
	"github.com/Lylighte/element-skin-union-gateway/internal/model"
	"github.com/Lylighte/element-skin-union-gateway/internal/netutil"
	"github.com/Lylighte/element-skin-union-gateway/internal/testutil"
)

func request(h http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func check(t *testing.T, w *httptest.ResponseRecorder, status int, body string) {
	t.Helper()
	if w.Code != status || (body != "" && strings.TrimSpace(w.Body.String()) != body) {
		t.Fatalf("status=%d body=%s; want %d %s", w.Code, w.Body, status, body)
	}
}

var counter atomic.Int64

func signed(f *testutil.Fixture, body string) map[string]string {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := fmt.Sprint("nonce-", counter.Add(1))
	d := sha256.Sum256([]byte(body + ts + nonce))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, f.Host, crypto.SHA256, d[:])
	return map[string]string{"X-Message-Timestamp": ts, "X-Message-Nonce": nonce, "X-Message-Signature": base64.StdEncoding.EncodeToString(sig)}
}

func TestAuthenticationJoinAndMaterialFlow(t *testing.T) {
	f := testutil.New(t)
	f.Ready()
	h := httpapi.New(f.Service)
	check(t, request(h, "GET", "/health/live", "", nil), 200, `{"live":true,"version":"0.1.0"}`)
	check(t, request(h, "GET", "/health/ready", "", nil), 200, `{"ready":true}`)
	meta := request(h, "GET", "/api/yggdrasil", "", nil)
	check(t, meta, 200, "")
	var m map[string]any
	if netutil.Decode(meta.Body.Bytes(), &m) != nil || m["signaturePublickey"] != f.Key.PublicPEM {
		t.Fatal(m)
	}
	if meta.Header().Get("X-Authlib-Injector-API-Location") != "https://union.example.org/api/yggdrasil" {
		t.Fatal(meta.Header())
	}
	for _, path := range []string{"/api/yggdrasil/", "/", "/api/publickeys", "/minecraftservices/publickeys/", "/api/yggdrasil/api/publickeys/", "/api/yggdrasil/minecraftservices/publickeys"} {
		check(t, request(h, "GET", path, "", nil), 200, "")
	}
	login := request(h, "POST", "/api/yggdrasil/authserver/authenticate", `{"username":"UnionTest","password":"synthetic-password","clientToken":"client-token"}`, nil)
	check(t, login, 200, "")
	var authenticated map[string]any
	json.Unmarshal(login.Body.Bytes(), &authenticated)
	if authenticated["accessToken"] != "synthetic-user-token" {
		t.Fatal(authenticated)
	}
	check(t, request(h, "POST", "/api/yggdrasil/authserver/refresh", `{"accessToken":"synthetic-user-token"}`, nil), 200, "")
	for _, name := range []string{"validate", "invalidate", "signout"} {
		check(t, request(h, "POST", "/api/yggdrasil/authserver/"+name, "{}", nil), 204, "")
	}
	path := "/api/yggdrasil/sessionserver/session/minecraft"
	check(t, request(h, "GET", path+"/hasJoined?username=UnionTest&serverId=absent", "", nil), 204, "")
	join := `{"accessToken":"synthetic-user-token","selectedProfile":"11111111111141118111111111111111","serverId":"test-server"}`
	check(t, request(h, "POST", path+"/join", join, nil), 204, "")
	check(t, request(h, "GET", path+"/hasJoined?username=Wrong&serverId=test-server", "", nil), 204, "")
	w := request(h, "GET", path+"/hasJoined?username=UnionTest&serverId=test-server", "", nil)
	check(t, w, 200, "")
	var p model.YggProfile
	if netutil.Decode(w.Body.Bytes(), &p) != nil || p.ID != testutil.ID || p.Name != "UnionTest" || len(p.Properties) != 2 {
		t.Fatal(p)
	}
	for _, prop := range p.Properties {
		raw, err := base64.StdEncoding.DecodeString(prop.Signature)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) != 256 {
			t.Fatal("signature length")
		}
		digest := sha1.Sum([]byte(prop.Value))
		if rsa.VerifyPKCS1v15(&f.Key.Private.PublicKey, crypto.SHA1, digest[:], raw) != nil {
			t.Fatal("invalid Union property signature")
		}
		// Signatures must match the exact original property, including slim metadata.
		value, _ := base64.StdEncoding.DecodeString(p.Properties[0].Value)
		if !bytes.Contains(value, []byte(`"model":"slim"`)) {
			t.Fatal(string(value))
		}
	}
	profilePath := path + "/profile/" + testutil.ID
	unsigned := request(h, "GET", profilePath, "", nil)
	check(t, unsigned, 200, "")
	if strings.Contains(unsigned.Body.String(), "signature") {
		t.Fatal(unsigned.Body.String())
	}
	check(t, request(h, "GET", profilePath+"?unsigned=false", "", nil), 200, "")
	for _, lookup := range []string{"/api/users/profiles/minecraft/uniontest", "/minecraftservices/minecraft/profile/lookup/name/UnionTest"} {
		check(t, request(h, "GET", "/api/yggdrasil"+lookup, "", nil), 200, `{"id":"11111111111141118111111111111111","name":"UnionTest"}`)
	}
	check(t, request(h, "GET", "/api/yggdrasil/api/users/profiles/minecraft/Missing", "", nil), 204, "")
	check(t, request(h, "GET", "/api/yggdrasil/minecraftservices/minecraft/profile/lookup/name/Missing", "", nil), 404, `{"error":"NOT_FOUND","errorMessage":"Profile not found."}`)
	for _, bulk := range []string{"/api/profiles/minecraft", "/minecraftservices/minecraft/profile/lookup/bulk/byname"} {
		check(t, request(h, "POST", "/api/yggdrasil"+bulk, `["UnionTest","Missing","uniontest"]`, nil), 200, `[{"id":"11111111111141118111111111111111","name":"UnionTest"}]`)
	}
	f.Update(func(f *testutil.Fixture) { f.Revoked = true })
	check(t, request(h, "GET", path+"/hasJoined?username=UnionTest&serverId=test-server", "", nil), 403, `{"error":"ForbiddenOperationException","errorMessage":"Permission denied."}`)
}

func TestRejectsInvalidAndForeignIdentityWithoutSigning(t *testing.T) {
	f := testutil.New(t)
	h := httpapi.New(f.Service)
	check(t, request(h, "GET", "/health/ready", "", nil), 503, `{"ready":false}`)
	check(t, request(h, "GET", "/api/yggdrasil", "", nil), 503, "")
	check(t, request(h, "GET", "/api/publickeys", "", nil), 503, "")
	check(t, request(h, "POST", "/api/yggdrasil/authserver/authenticate", "{}", nil), 503, "")
	f.Ready()
	for _, tc := range []struct{ method, path, body string }{
		{"POST", "/api/yggdrasil/sessionserver/session/minecraft/join", "{}"},
		{"GET", "/api/yggdrasil/sessionserver/session/minecraft/hasJoined?username=x", ""},
		{"GET", "/api/yggdrasil/sessionserver/session/minecraft/profile/bad", ""},
		{"POST", "/api/yggdrasil/api/profiles/minecraft", "null"},
		{"POST", "/api/yggdrasil/api/profiles/minecraft", `["bad/name"]`},
		{"GET", "/api/yggdrasil/api/users/profiles/minecraft/Bad%2FName", ""},
		{"POST", "/api/yggdrasil/authserver/validate", strings.Repeat("x", (1<<20)+1)},
	} {
		check(t, request(h, tc.method, tc.path, tc.body, nil), 400, "")
	}
	check(t, request(h, "GET", "/api/yggdrasil/sessionserver/session/minecraft/profile/"+testutil.OtherID, "", nil), 403, "")
	f.Update(func(f *testutil.Fixture) { f.MappedName = "BoundOther" })
	check(t, request(h, "POST", "/api/yggdrasil/authserver/authenticate", "{}", nil), 403, "")
	calls := f.Recorded()
	found := false
	for _, call := range calls {
		if call.Path == "/authserver/invalidate" {
			found = true
		}
	}
	if !found {
		t.Fatal("rejected authentication token not revoked")
	}
	f.Update(func(f *testutil.Fixture) { f.MappedName = "UnionTest"; f.BadTexture = true })
	check(t, request(h, "GET", "/api/yggdrasil/sessionserver/session/minecraft/profile/"+testutil.ID+"?unsigned=false", "", nil), 403, "")
	f.Update(func(f *testutil.Fixture) { f.BadTexture = false; f.ProfileID = testutil.OtherID })
	check(t, request(h, "GET", "/api/yggdrasil/sessionserver/session/minecraft/profile/"+testutil.ID+"?unsigned=false", "", nil), 403, "")
	f.Update(func(f *testutil.Fixture) { f.FailPath = "/authserver/authenticate"; f.FailStatus = 403 })
	check(t, request(h, "POST", "/api/yggdrasil/authserver/authenticate", "{}", nil), 403, `{"error":"ForbiddenOperationException","errorMessage":"Rejected."}`)
}

func TestSignedMemberOperationsAndDurableReplay(t *testing.T) {
	f := testutil.New(t)
	f.Ready()
	h := httpapi.New(f.Service)
	check(t, request(h, "GET", "/api/union/member", "", nil), 200, `{"enabledFeatures":[],"privateKeyVersion":1,"serverListVersion":2,"yggdrasilApiVersion":"element-skin-union-gateway/0.1.0"}`)
	check(t, request(h, "POST", "/api/union/member/diagnose", `{"nonce":"echo"}`, nil), 403, `{"error":"ForbiddenOperationException","errorMessage":"Union host verification failure."}`)
	body := `{"nonce":"echo"}`
	headers := signed(f, body)
	w := request(h, "POST", "/api/union/member/diagnose", body, headers)
	check(t, w, 200, "")
	var diagnosed struct {
		Nonce     string  `json:"nonce"`
		Timestamp float64 `json:"timestamp"`
	}
	json.Unmarshal(w.Body.Bytes(), &diagnosed)
	if diagnosed.Nonce != "echo" || diagnosed.Timestamp < float64(time.Now().Unix()-2) {
		t.Fatal(diagnosed)
	}
	check(t, request(h, "POST", "/api/union/member/diagnose", body, headers), 403, "")
	for _, action := range []string{"updatelist", "updateprivatekey", "sync"} {
		check(t, request(h, "POST", "/api/union/member/"+action, "", signed(f, "")), 200, "")
	}
	for _, action := range []string{"updatebackendkey", "diagnose", "remapuuid"} {
		check(t, request(h, "POST", "/api/union/member/"+action, "{}", signed(f, "{}")), 400, "")
	}
	key := `{"key":"rotated-member"}`
	check(t, request(h, "POST", "/api/union/member/updatebackendkey", key, signed(f, key)), 200, "")
	check(t, request(h, "POST", "/api/union/member/updatelist", "", signed(f, "")), 200, "")
	calls := f.Recorded()
	if calls[len(calls)-1].Member != "rotated-member" {
		t.Fatal("credential rotation not used")
	}
	check(t, request(h, "GET", "/api/union/member/queryemail?username=UnionTest", "", signed(f, "")), 501, "")
	f.Service.Cfg.QueryEmail = true
	check(t, request(h, "GET", "/api/union/member/queryemail?username=UnionTest", "", signed(f, "")), 200, `{"email":"test@example.org"}`)
	check(t, request(h, "GET", "/api/union/member/queryemail?username=Missing", "", signed(f, "")), 204, "")
	check(t, request(h, "GET", "/api/union/member/queryemail?username=bad%2Fname", "", signed(f, "")), 400, "")
	check(t, request(h, "POST", "/api/union/member/updateplugin", "{}", signed(f, "{}")), 501, `{"error":"remote_update_unsupported"}`)
	remap := `{"remapped_uuid":{"11111111111141118111111111111111":"22222222222242228222222222222222"}}`
	check(t, request(h, "POST", "/api/union/member/remapuuid", remap, signed(f, remap)), 501, `{"error":"identity_mapping_unsupported"}`)
	if _, err := f.Store.Local(context.Background(), testutil.ID); err != model.ErrIdentity {
		t.Fatal(err)
	}
}

func TestAdministrationWebhookAndSubpath(t *testing.T) {
	f := testutil.New(t)
	f.Ready()
	f.Service.Cfg.PublicRoot = "https://union.example.org/member"
	h := httpapi.New(f.Service)
	check(t, request(h, "GET", "/health/live", "", nil), 404, "")
	check(t, request(h, "GET", "/member/health/live", "", nil), 200, "")
	for i := 0; i < 31; i++ {
		status := 401
		if i == 30 {
			status = 429
		}
		check(t, request(h, "GET", "/member/admin/status", "", nil), status, "")
	}
	admin := map[string]string{"Authorization": "Bearer " + f.Cfg.AdminToken}
	check(t, request(h, "GET", "/member/admin/status", "", admin), 200, "")
	for _, action := range []string{"refresh-directory", "refresh-key", "sync", "diagnose"} {
		check(t, request(h, "POST", "/member/admin/"+action, "", admin), 200, "")
	}
	body := `{"id":"evt-test","type":"profile.updated","created_at":1786118400000,"data":{"profile_id":"11111111111141118111111111111111","user_id":"owner"}}`
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	mac := hmac.New(sha256.New, []byte(f.Cfg.WebhookSecret))
	mac.Write([]byte(ts + "." + body))
	headers := map[string]string{"Webhook-Timestamp": ts, "Webhook-Id": "evt-test", "Webhook-Signature": "v1=" + hex.EncodeToString(mac.Sum(nil))}
	check(t, request(h, "POST", "/member/webhooks/elementskin", body, nil), 401, `{"error":"webhook_signature_invalid"}`)
	check(t, request(h, "POST", "/member/webhooks/elementskin", body, headers), 202, `{"accepted":true,"duplicate":false}`)
	check(t, request(h, "POST", "/member/webhooks/elementskin", body, headers), 202, `{"accepted":true,"duplicate":true}`)
	headers["Webhook-Id"] = "mismatch"
	check(t, request(h, "POST", "/member/webhooks/elementskin", body, headers), 400, "")
	f.Service.Cfg.WebhookSecret = ""
	check(t, request(h, "POST", "/member/webhooks/elementskin", body, headers), 503, `{"error":"webhook_disabled"}`)
	f.Update(func(f *testutil.Fixture) { f.FailPath = "/serverlist"; f.FailStatus = 500 })
	check(t, request(h, "POST", "/member/admin/refresh-directory", "", admin), 502, "")
}
