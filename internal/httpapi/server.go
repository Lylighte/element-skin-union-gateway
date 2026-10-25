package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Lylighte/element-skin-union-gateway/internal/model"
	"github.com/Lylighte/element-skin-union-gateway/internal/netutil"
	"github.com/Lylighte/element-skin-union-gateway/internal/service"
)

const maxRequest = 1 << 20

type Server struct {
	s        *service.Service
	mux      *http.ServeMux
	adminMu  sync.Mutex
	window   time.Time
	attempts int
}

func New(s *service.Service) http.Handler {
	h := &Server{s: s, mux: http.NewServeMux()}
	h.routes()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 110*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
		start := time.Now()
		var id [12]byte
		_, _ = rand.Read(id[:])
		requestID := hex.EncodeToString(id[:])
		w.Header().Set("X-Request-ID", requestID)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		recorder := &responseStatus{ResponseWriter: w, status: 200}
		h.mux.ServeHTTP(recorder, r)
		h.s.Log.Info("http_request", "request_id", requestID, "method", r.Method, "route", r.Pattern, "status", recorder.status, "duration_ms", time.Since(start).Milliseconds())
	})
}

type responseStatus struct {
	http.ResponseWriter
	status int
}

func (w *responseStatus) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (h *Server) routes() {
	p := h.s.Cfg.RootPath()
	on := func(method, path string, fn http.HandlerFunc) { h.mux.HandleFunc(method+" "+p+path, fn) }
	on("GET", "/health/live", func(w http.ResponseWriter, r *http.Request) {
		write(w, 200, map[string]any{"live": true, "version": service.Version})
	})
	on("GET", "/health/ready", func(w http.ResponseWriter, r *http.Request) {
		ready := h.s.Ready(r.Context())
		status := 200
		if !ready {
			status = 503
		}
		write(w, status, map[string]bool{"ready": ready})
	})
	metadata := func(w http.ResponseWriter, r *http.Request) {
		h.yggHeaders(w)
		value, err := h.s.Metadata(r.Context())
		if err != nil {
			fail(w, err)
			return
		}
		write(w, 200, value)
	}
	on("GET", "/api/yggdrasil", metadata)
	on("GET", "/api/yggdrasil/{$}", metadata)
	keys := func(w http.ResponseWriter, r *http.Request) {
		h.yggHeaders(w)
		value, err := h.s.PublicKeys()
		if err != nil {
			fail(w, err)
			return
		}
		write(w, 200, value)
	}
	for _, path := range []string{"/minecraftservices/publickeys", "/api/publickeys", "/api/yggdrasil/minecraftservices/publickeys", "/api/yggdrasil/api/publickeys"} {
		on("GET", path, keys)
		on("GET", path+"/{$}", keys)
	}
	for _, name := range []string{"authenticate", "refresh", "validate", "invalidate", "signout"} {
		path := "/authserver/" + name
		on("POST", "/api/yggdrasil"+path, h.proxy(path))
	}
	for _, route := range []struct{ method, path string }{
		{"POST", "/sessionserver/session/minecraft/join"}, {"GET", "/sessionserver/session/minecraft/hasJoined"},
		{"GET", "/sessionserver/session/minecraft/profile/{uuid}"},
		{"GET", "/api/users/profiles/minecraft/{name}"}, {"POST", "/api/profiles/minecraft"},
		{"GET", "/minecraftservices/minecraft/profile/lookup/name/{name}"}, {"POST", "/minecraftservices/minecraft/profile/lookup/bulk/byname"},
	} {
		on(route.method, "/api/yggdrasil"+route.path, h.proxy(route.path))
	}
	on("GET", "/api/union/member", h.hello)
	on("GET", "/api/union/member/{$}", h.hello)
	for _, action := range []string{"updatelist", "updateprivatekey", "updatebackendkey", "sync", "diagnose", "remapuuid", "updateplugin"} {
		on("POST", "/api/union/member/"+action, h.callback(action))
	}
	on("GET", "/api/union/member/queryemail", h.callback("queryemail"))
	on("POST", "/webhooks/elementskin", h.webhook)
	for _, action := range []string{"refresh-directory", "refresh-key", "sync", "diagnose"} {
		on("POST", "/admin/"+action, h.admin(h.action(action)))
	}
	on("GET", "/admin/status", h.admin(func(w http.ResponseWriter, r *http.Request) {
		v, err := h.s.Status(r.Context())
		if err != nil {
			fail(w, err)
			return
		}
		write(w, 200, v)
	}))
	on("GET", "/{$}", func(w http.ResponseWriter, r *http.Request) {
		write(w, 200, map[string]any{"application": "element-skin-union-gateway", "version": service.Version, "authentication_url": strings.TrimRight(h.s.Cfg.PublicRoot, "/") + "/api/yggdrasil", "ready": h.s.Ready(r.Context())})
	})
}

func (h *Server) yggHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("X-Authlib-Injector-API-Location", strings.TrimRight(h.s.Cfg.PublicRoot, "/")+"/api/yggdrasil")
}

func (h *Server) proxy(template string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.yggHeaders(w)
		body, err := read(w, r)
		if err != nil {
			fail(w, model.ErrInvalid)
			return
		}
		path := template
		for _, key := range []string{"uuid", "name"} {
			v := r.PathValue(key)
			if strings.ContainsAny(v, "/\\?#\x00") {
				fail(w, model.ErrInvalid)
				return
			}
			path = strings.ReplaceAll(path, "{"+key+"}", v)
		}
		res, err := h.s.Proxy(r.Context(), r.Method, path, r.URL.RawQuery, body)
		if err != nil {
			fail(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(res.Status)
		if res.Status != 204 {
			_, _ = w.Write(res.Body)
		}
	}
}

func (h *Server) hello(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	value, err := h.s.Hello(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	write(w, 200, value)
}

func (h *Server) callback(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := read(w, r)
		if err != nil {
			fail(w, model.ErrInvalid)
			return
		}
		if err = h.s.VerifyCallback(r.Context(), body, r.Header.Get("X-Message-Timestamp"), r.Header.Get("X-Message-Nonce"), r.Header.Get("X-Message-Signature")); err != nil {
			write(w, 403, map[string]string{"error": "ForbiddenOperationException", "errorMessage": "Union host verification failure."})
			return
		}
		switch action {
		case "updatebackendkey":
			var in struct {
				Key string `json:"key"`
			}
			if netutil.Decode(body, &in) != nil {
				fail(w, model.ErrInvalid)
				return
			}
			err = h.s.SetMember(r.Context(), in.Key)
		case "updatelist":
			err = h.s.RefreshDirectory(r.Context())
		case "updateprivatekey":
			err = h.s.RefreshKey(r.Context())
		case "sync":
			err = h.s.Sync(r.Context())
		case "diagnose":
			var in struct {
				Nonce string `json:"nonce"`
			}
			if netutil.Decode(body, &in) != nil || in.Nonce == "" {
				fail(w, model.ErrInvalid)
				return
			}
			write(w, 200, map[string]any{"nonce": in.Nonce, "timestamp": float64(time.Now().UnixMilli()) / 1000})
			return
		case "queryemail":
			if !h.s.Cfg.QueryEmail {
				write(w, 501, map[string]string{"error": "query_email_disabled"})
				return
			}
			var email string
			email, err = h.s.QueryEmail(r.Context(), r.URL.Query().Get("username"))
			if err == nil {
				if email == "" {
					w.WriteHeader(204)
				} else {
					write(w, 200, map[string]string{"email": email})
				}
				return
			}
		case "remapuuid":
			var in struct {
				Remapped map[string]string `json:"remapped_uuid"`
			}
			if netutil.Decode(body, &in) != nil || len(in.Remapped) == 0 || len(in.Remapped) > 1000 {
				fail(w, model.ErrInvalid)
				return
			}
			ids := []string{}
			for from, to := range in.Remapped {
				id, e := model.UUID(from)
				_, e2 := model.UUID(to)
				if e != nil || e2 != nil {
					fail(w, model.ErrInvalid)
					return
				}
				ids = append(ids, id)
			}
			if err = h.s.Store.Block(r.Context(), ids); err != nil {
				fail(w, err)
				return
			}
			write(w, 501, map[string]string{"error": "identity_mapping_unsupported"})
			return
		case "updateplugin":
			write(w, 501, map[string]string{"error": "remote_update_unsupported"})
			return
		}
		if err != nil {
			fail(w, err)
			return
		}
		w.WriteHeader(200)
	}
}

func (h *Server) admin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || len(token) != len(h.s.Cfg.AdminToken) || subtle.ConstantTimeCompare([]byte(token), []byte(h.s.Cfg.AdminToken)) != 1 {
			h.adminMu.Lock()
			if time.Since(h.window) > time.Minute {
				h.window = time.Now()
				h.attempts = 0
			}
			h.attempts++
			limited := h.attempts > 30
			h.adminMu.Unlock()
			if limited {
				w.Header().Set("Retry-After", "60")
				write(w, 429, map[string]string{"error": "rate_limited"})
				return
			}
			w.Header().Set("WWW-Authenticate", "Bearer")
			write(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func (h *Server) action(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var err error
		switch action {
		case "refresh-directory":
			err = h.s.RefreshDirectory(r.Context())
		case "refresh-key":
			err = h.s.RefreshKey(r.Context())
		case "sync":
			err = h.s.Sync(r.Context())
		case "diagnose":
			status, e := h.s.Diagnose(r.Context())
			if e != nil {
				fail(w, e)
				return
			}
			write(w, 200, map[string]int{"hub_status": status})
			return
		}
		if err != nil {
			fail(w, err)
			return
		}
		write(w, 200, map[string]string{"status": "ok"})
	}
}

func (h *Server) webhook(w http.ResponseWriter, r *http.Request) {
	if h.s.Cfg.WebhookSecret == "" {
		write(w, 503, map[string]string{"error": "webhook_disabled"})
		return
	}
	body, err := read(w, r)
	if err != nil {
		fail(w, model.ErrInvalid)
		return
	}
	ts := r.Header.Get("Webhook-Timestamp")
	stamp, e := strconv.ParseInt(ts, 10, 64)
	delta := time.Now().UnixMilli() - stamp
	signature := strings.TrimPrefix(r.Header.Get("Webhook-Signature"), "v1=")
	decoded, e2 := hex.DecodeString(signature)
	mac := hmac.New(sha256.New, []byte(h.s.Cfg.WebhookSecret))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	if e != nil || e2 != nil || !strings.HasPrefix(r.Header.Get("Webhook-Signature"), "v1=") || delta > 300000 || delta < -300000 || !hmac.Equal(decoded, mac.Sum(nil)) {
		write(w, 401, map[string]string{"error": "webhook_signature_invalid"})
		return
	}
	var in struct {
		ID      string `json:"id"`
		Type    string `json:"type"`
		Created int64  `json:"created_at"`
		Data    struct {
			ID string `json:"profile_id"`
		} `json:"data"`
	}
	if netutil.Decode(body, &in) != nil || in.ID == "" || len(in.ID) > 200 || in.ID != r.Header.Get("Webhook-Id") || in.Created < 1 {
		fail(w, model.ErrInvalid)
		return
	}
	if _, err = model.UUID(in.Data.ID); err != nil {
		fail(w, model.ErrInvalid)
		return
	}
	if in.Type != "profile.created" && in.Type != "profile.updated" && in.Type != "profile.deleted" {
		fail(w, model.ErrInvalid)
		return
	}
	fresh, err := h.s.Store.RequestSync(r.Context(), in.ID)
	if err != nil {
		fail(w, err)
		return
	}
	write(w, 202, map[string]bool{"accepted": true, "duplicate": !fresh})
}

func read(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequest)
	defer r.Body.Close()
	return io.ReadAll(r.Body)
}
func write(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func fail(w http.ResponseWriter, err error) {
	status, code, message := 502, "ServiceUnavailableException", "Gateway upstream unavailable."
	switch {
	case errors.Is(err, model.ErrInvalid):
		status, code, message = 400, "IllegalArgumentException", "Invalid request."
	case errors.Is(err, model.ErrIdentity):
		status, code, message = 403, "ForbiddenOperationException", "Union identity is unavailable or requires mapping."
	case errors.Is(err, model.ErrNotReady):
		status, code, message = 503, "ServiceUnavailableException", "Gateway initialization is incomplete."
	}
	write(w, status, map[string]string{"error": code, "errorMessage": message})
}
