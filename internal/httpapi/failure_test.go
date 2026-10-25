package httpapi_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/Lylighte/element-skin-union-gateway/internal/httpapi"
	"github.com/Lylighte/element-skin-union-gateway/internal/model"
	"github.com/Lylighte/element-skin-union-gateway/internal/service"
	"github.com/Lylighte/element-skin-union-gateway/internal/testutil"
)

func TestMalformedSuccessesNeverBecomeSignedProfiles(t *testing.T) {
	f := testutil.New(t)
	f.Ready()
	h := httpapi.New(f.Service)
	base := "/sessionserver/session/minecraft"
	join := `{"accessToken":"synthetic-user-token","selectedProfile":"11111111111141118111111111111111","serverId":"failure-server"}`
	check(t, request(h, "POST", "/api/yggdrasil"+base+"/join", join, nil), 204, "")
	validValue := base64.StdEncoding.EncodeToString([]byte(`{"profileId":"11111111111141118111111111111111","profileName":"UnionTest","textures":{}}`))
	profile := func(properties []model.Property) string {
		b, _ := json.Marshal(model.YggProfile{ID: testutil.ID, Name: "UnionTest", Properties: properties})
		return string(b)
	}
	badDomain := base64.StdEncoding.EncodeToString([]byte(`{"profileId":"11111111111141118111111111111111","profileName":"UnionTest","textures":{"SKIN":{"url":"https://untrusted.example/skin.png"}}}`))
	for _, tc := range []struct {
		name, method, path, body, response string
		upstream, status                   int
	}{
		{"invalid login", "POST", "/authserver/authenticate", "{}", "{}", 200, 502},
		{"invalid refresh", "POST", "/authserver/refresh", "{}", "bad", 200, 502},
		{"invalid validation status", "POST", "/authserver/validate", "{}", "{}", 200, 502},
		{"non JSON rejection", "POST", "/authserver/validate", "{}", "private database details", 500, 502},
		{"wrong join status", "POST", base + "/join", join, "{}", 200, 502},
		{"rejected join", "POST", base + "/join", join, `{"error":"ForbiddenOperationException","errorMessage":"Rejected."}`, 403, 403},
		{"wrong hasJoined status", "GET", base + "/hasJoined?username=UnionTest&serverId=failure-server", "", "{}", 202, 502},
		{"absent upstream session", "GET", base + "/hasJoined?username=UnionTest&serverId=failure-server", "", "", 204, 204},
		{"upstream session error", "GET", base + "/hasJoined?username=UnionTest&serverId=failure-server", "", `{"error":"ForbiddenOperationException","errorMessage":"Rejected."}`, 403, 403},
		{"malformed profile", "GET", base + "/profile/" + testutil.ID + "?unsigned=false", "", "bad", 200, 502},
		{"absent profile", "GET", base + "/profile/" + testutil.ID, "", "", 204, 204},
		{"wrong profile status", "GET", base + "/profile/" + testutil.ID, "", "{}", 202, 502},
		{"rejected profile", "GET", base + "/profile/" + testutil.ID, "", `{"error":"ForbiddenOperationException","errorMessage":"Rejected."}`, 403, 403},
		{"missing textures", "GET", base + "/profile/" + testutil.ID, "", profile(nil), 200, 502},
		{"duplicate properties", "GET", base + "/profile/" + testutil.ID, "", profile([]model.Property{{Name: "textures", Value: validValue}, {Name: "textures", Value: validValue}}), 200, 502},
		{"bad base64", "GET", base + "/profile/" + testutil.ID, "", profile([]model.Property{{Name: "textures", Value: "!"}}), 200, 502},
		{"bad JSON", "GET", base + "/profile/" + testutil.ID, "", profile([]model.Property{{Name: "textures", Value: base64.StdEncoding.EncodeToString([]byte("bad"))}}), 200, 502},
		{"untrusted texture domain", "GET", base + "/profile/" + testutil.ID, "", profile([]model.Property{{Name: "textures", Value: badDomain}}), 200, 502},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.path
			for i, ch := range path {
				if ch == '?' {
					path = path[:i]
					break
				}
			}
			f.Update(func(f *testutil.Fixture) {
				f.Responses = map[string]model.Response{path: {Status: tc.upstream, Body: []byte(tc.response)}}
			})
			w := request(h, tc.method, "/api/yggdrasil"+tc.path, tc.body, nil)
			check(t, w, tc.status, "")
			if tc.status >= 400 && json.Valid(w.Body.Bytes()) && w.Body.String() == tc.response && tc.upstream == 200 {
				t.Fatal("invalid success was forwarded")
			}
		})
	}
	f.Update(func(f *testutil.Fixture) { f.Responses = nil; f.FailPath = "/v2/admin/profiles"; f.FailStatus = 403 })
	check(t, request(h, "GET", "/api/yggdrasil"+base+"/profile/"+testutil.ID, "", nil), 502, "")
}

func TestRevokedTokenAndRestartCannotSignFallback(t *testing.T) {
	f := testutil.New(t)
	f.Ready()
	h := httpapi.New(f.Service)
	path := "/api/yggdrasil/sessionserver/session/minecraft"
	join := `{"accessToken":"synthetic-user-token","selectedProfile":"11111111111141118111111111111111","serverId":"revoked-server"}`
	check(t, request(h, "POST", path+"/join", join, nil), 204, "")
	f.Update(func(f *testutil.Fixture) {
		f.Responses = map[string]model.Response{"/authserver/validate": {Status: 403, Body: []byte(`{"error":"ForbiddenOperationException","errorMessage":"Invalid token."}`)}}
	})
	before := len(f.Recorded())
	check(t, request(h, "GET", path+"/hasJoined?username=UnionTest&serverId=revoked-server", "", nil), 403, `{"error":"ForbiddenOperationException","errorMessage":"Invalid token."}`)
	for _, call := range f.Recorded()[before:] {
		if call.Path == "/sessionserver/session/minecraft/hasJoined" {
			t.Fatal("revoked session reached fallback-capable endpoint")
		}
	}
	check(t, request(h, "GET", path+"/hasJoined?username=UnionTest&serverId=revoked-server", "", nil), 204, "")
	f.Update(func(f *testutil.Fixture) { f.Responses = nil })
	check(t, request(h, "POST", path+"/join", join, nil), 204, "")
	restarted, err := service.New(context.Background(), f.Cfg, f.Store, f.Service.Skin, f.Service.Hub, f.Service.Log)
	if err != nil {
		t.Fatal(err)
	}
	check(t, request(httpapi.New(restarted), "GET", path+"/hasJoined?username=UnionTest&serverId=revoked-server", "", nil), 204, "")
}
