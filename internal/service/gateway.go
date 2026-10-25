package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Lylighte/element-skin-union-gateway/internal/model"
	"github.com/Lylighte/element-skin-union-gateway/internal/netutil"
)

func encoded(value any) model.Response {
	b, _ := json.Marshal(value)
	return model.Response{Status: 200, Body: b}
}

func (s *Service) local(ctx context.Context, id string) (model.Profile, error) {
	id, err := model.UUID(id)
	if err != nil {
		return model.Profile{}, model.ErrInvalid
	}
	p, err := s.Store.Local(ctx, id)
	if err != nil {
		return p, err
	}
	p, err = s.Skin.Find(ctx, p.ID, p.Name)
	if err != nil {
		return p, err
	}
	if err = s.Hub.CheckIdentity(ctx, p); err != nil {
		return p, err
	}
	return p, nil
}

func (s *Service) lookup(ctx context.Context, name string) (model.Profile, error) {
	if !model.ValidName(name) {
		return model.Profile{}, model.ErrInvalid
	}
	p, err := s.Skin.Lookup(ctx, name)
	if err != nil {
		return p, err
	}
	return s.local(ctx, p.ID)
}

func (s *Service) Proxy(ctx context.Context, method, path, query string, body []byte) (model.Response, error) {
	if strings.HasPrefix(path, "/authserver/") {
		if path != "/authserver/invalidate" && path != "/authserver/signout" && !s.Ready(ctx) {
			return model.Response{}, model.ErrNotReady
		}
		res, err := s.Skin.Proxy(ctx, method, path, query, body)
		if err != nil {
			return res, err
		}
		if res.Status >= 400 {
			return checkedError(res)
		}
		if path == "/authserver/authenticate" || path == "/authserver/refresh" {
			if res.Status != 200 {
				return res, errors.New("authentication_response_invalid")
			}
			if err = s.validateAuthentication(ctx, res.Body); err != nil {
				return model.Response{}, err
			}
		} else if res.Status != 204 {
			return res, errors.New("authentication_response_invalid")
		}
		return res, nil
	}
	if !s.Ready(ctx) {
		return model.Response{}, model.ErrNotReady
	}
	switch {
	case path == "/sessionserver/session/minecraft/join":
		var in struct {
			Access string `json:"accessToken"`
			ID     string `json:"selectedProfile"`
			Server string `json:"serverId"`
		}
		if netutil.Decode(body, &in) != nil || in.Access == "" || len(in.Access) > 4096 || in.Server == "" || len(in.Server) > 1024 {
			return model.Response{}, model.ErrInvalid
		}
		p, err := s.local(ctx, in.ID)
		if err != nil {
			return model.Response{}, err
		}
		started := time.Now()
		res, err := s.Skin.Proxy(ctx, method, path, query, body)
		if err != nil {
			return res, err
		}
		if res.Status >= 400 {
			return checkedError(res)
		}
		if res.Status != 204 {
			return res, errors.New("join_response_invalid")
		}
		if err = s.Store.RecordJoin(ctx, in.Server, p.ID); err != nil {
			return model.Response{}, err
		}
		if err = s.rememberJoin(in.Server, p.ID, in.Access, started); err != nil {
			return model.Response{}, err
		}
		return res, nil
	case path == "/sessionserver/session/minecraft/hasJoined":
		q, err := url.ParseQuery(query)
		if err != nil {
			return model.Response{}, model.ErrInvalid
		}
		if !model.ValidName(q.Get("username")) || q.Get("serverId") == "" || len(q.Get("serverId")) > 1024 {
			return model.Response{}, model.ErrInvalid
		}
		proof, ok := s.originJoin(q.Get("serverId"))
		if !ok {
			return model.Response{Status: 204}, nil
		}
		id, err := s.Store.Joined(ctx, q.Get("serverId"))
		if errors.Is(err, model.ErrIdentity) {
			return model.Response{Status: 204}, nil
		}
		if err != nil {
			return model.Response{}, err
		}
		if id != proof.ID {
			return model.Response{Status: 204}, nil
		}
		validation, _ := json.Marshal(map[string]string{"accessToken": proof.Token})
		validated, err := s.Skin.Proxy(ctx, "POST", "/authserver/validate", "", validation)
		if err != nil {
			return model.Response{}, err
		}
		if validated.Status >= 400 {
			s.forgetJoin(q.Get("serverId"), proof.Token)
			return checkedError(validated)
		}
		if validated.Status != 204 {
			return model.Response{}, errors.New("token_validation_response_invalid")
		}
		p, err := s.local(ctx, id)
		if err != nil {
			return model.Response{}, err
		}
		if p.Name != q.Get("username") {
			return model.Response{Status: 204}, nil
		}
		res, err := s.Skin.Proxy(ctx, method, path, query, nil)
		if err != nil {
			return res, err
		}
		if res.Status >= 400 {
			return checkedError(res)
		}
		if res.Status == 204 {
			return res, nil
		}
		if res.Status != 200 {
			return res, errors.New("profile_response_invalid")
		}
		current, ok := s.originJoin(q.Get("serverId"))
		if !ok || current.ID != proof.ID || current.Token != proof.Token {
			return model.Response{Status: 204}, nil
		}
		return s.resign(ctx, res, p, true)
	case strings.HasPrefix(path, "/sessionserver/session/minecraft/profile/"):
		id := strings.TrimPrefix(path, "/sessionserver/session/minecraft/profile/")
		p, err := s.local(ctx, id)
		if err != nil {
			return model.Response{}, err
		}
		q, err := url.ParseQuery(query)
		if err != nil {
			return model.Response{}, model.ErrInvalid
		}
		res, err := s.Skin.Proxy(ctx, method, path, query, nil)
		if err != nil {
			return res, err
		}
		if res.Status >= 400 {
			return checkedError(res)
		}
		if res.Status == 204 {
			return res, nil
		}
		if res.Status != 200 {
			return res, errors.New("profile_response_invalid")
		}
		return s.resign(ctx, res, p, q.Get("unsigned") == "false")
	case strings.HasPrefix(path, "/api/users/profiles/minecraft/") || strings.HasPrefix(path, "/minecraftservices/minecraft/profile/lookup/name/"):
		name := path[strings.LastIndex(path, "/")+1:]
		p, err := s.lookup(ctx, name)
		if errors.Is(err, model.ErrIdentity) {
			if strings.HasPrefix(path, "/minecraftservices/") {
				return model.Response{Status: 404, Body: []byte(`{"error":"NOT_FOUND","errorMessage":"Profile not found."}`)}, nil
			}
			return model.Response{Status: 204}, nil
		}
		if err != nil {
			return model.Response{}, err
		}
		return encoded(map[string]string{"id": p.ID, "name": p.Name}), nil
	case path == "/api/profiles/minecraft" || path == "/minecraftservices/minecraft/profile/lookup/bulk/byname":
		var names []string
		if netutil.Decode(body, &names) != nil || names == nil || len(names) > 100 {
			return model.Response{}, model.ErrInvalid
		}
		results := []map[string]string{}
		seen := map[string]bool{}
		for _, name := range names {
			p, err := s.lookup(ctx, name)
			if errors.Is(err, model.ErrIdentity) {
				continue
			}
			if err != nil {
				return model.Response{}, err
			}
			if !seen[p.ID] {
				results = append(results, map[string]string{"id": p.ID, "name": p.Name})
				seen[p.ID] = true
			}
		}
		return encoded(results), nil
	}
	return model.Response{}, model.ErrInvalid
}

func checkedError(r model.Response) (model.Response, error) {
	if !json.Valid(r.Body) {
		return model.Response{}, errors.New("upstream_error_invalid")
	}
	return r, nil
}

func (s *Service) validateAuthentication(ctx context.Context, body []byte) error {
	var out struct {
		Access    string          `json:"accessToken"`
		Available []model.Profile `json:"availableProfiles"`
		Selected  *model.Profile  `json:"selectedProfile"`
	}
	if netutil.Decode(body, &out) != nil || out.Access == "" || len(out.Available) > 100 {
		return errors.New("authentication_response_invalid")
	}
	validate := func(p model.Profile) error {
		local, err := s.local(ctx, p.ID)
		if err != nil {
			return err
		}
		if local.Name != p.Name {
			return model.ErrIdentity
		}
		return nil
	}
	var failure error
	if out.Selected != nil {
		failure = validate(*out.Selected)
	}
	if failure == nil {
		for _, p := range out.Available {
			if failure = validate(p); failure != nil {
				break
			}
		}
	}
	if failure != nil {
		b, _ := json.Marshal(map[string]string{"accessToken": out.Access})
		_, _ = s.Skin.Proxy(ctx, http.MethodPost, "/authserver/invalidate", "", b)
	}
	return failure
}

func (s *Service) resign(ctx context.Context, res model.Response, expected model.Profile, sign bool) (model.Response, error) {
	var p model.YggProfile
	if netutil.Decode(res.Body, &p) != nil {
		return model.Response{}, errors.New("profile_response_invalid")
	}
	id, err := model.UUID(p.ID)
	if err != nil || id != expected.ID || p.Name != expected.Name || len(p.Properties) > 16 {
		return model.Response{}, model.ErrIdentity
	}
	seen := map[string]bool{}
	for _, prop := range p.Properties {
		if prop.Name == "" || seen[prop.Name] || len(prop.Value) > 1<<20 {
			return model.Response{}, errors.New("property_invalid")
		}
		seen[prop.Name] = true
		if prop.Name == "textures" {
			raw, e := base64.StdEncoding.Strict().DecodeString(prop.Value)
			if e != nil {
				return model.Response{}, errors.New("textures_invalid")
			}
			var texture struct {
				ID       string `json:"profileId"`
				Name     string `json:"profileName"`
				Textures map[string]struct {
					URL string `json:"url"`
				} `json:"textures"`
			}
			if netutil.Decode(raw, &texture) != nil {
				return model.Response{}, errors.New("textures_invalid")
			}
			tid, e := model.UUID(texture.ID)
			if e != nil || tid != expected.ID || texture.Name != expected.Name {
				return model.Response{}, model.ErrIdentity
			}
			metadata, e := s.Metadata(ctx)
			if e != nil {
				return model.Response{}, e
			}
			domains := metadata["skinDomains"].([]string)
			for _, t := range texture.Textures {
				u, e := url.Parse(t.URL)
				allowed := false
				if e == nil && u.User == nil && u.Scheme == "https" {
					for _, d := range domains {
						if strings.EqualFold(u.Hostname(), d) {
							allowed = true
							break
						}
					}
				}
				if !allowed {
					return model.Response{}, errors.New("texture_domain_rejected")
				}
			}
		}
	}
	if !seen["textures"] {
		return model.Response{}, errors.New("textures_missing")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.key == nil {
		return model.Response{}, model.ErrNotReady
	}
	for i := range p.Properties {
		p.Properties[i].Signature = ""
		if sign {
			signature, e := s.key.Sign(p.Properties[i].Value)
			if e != nil {
				return model.Response{}, e
			}
			p.Properties[i].Signature = signature
		}
	}
	return encoded(p), nil
}
