package elementskin

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Lylighte/element-skin-union-gateway/internal/model"
	"github.com/Lylighte/element-skin-union-gateway/internal/netutil"
)

type Client struct {
	base, id, secret string
	http             *http.Client
	mu               sync.Mutex
	token            string
	expires          time.Time
}

func New(base, id, secret string, httpClient *http.Client) *Client {
	return &Client{base: strings.TrimRight(base, "/"), id: id, secret: secret, http: httpClient}
}

func (c *Client) Proxy(ctx context.Context, method, path, query string, body []byte) (model.Response, error) {
	target := c.base + path
	if query != "" {
		target += "?" + query
	}
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	return netutil.Do(ctx, c.http, method, target, body, h)
}

func (c *Client) access(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.expires) {
		return c.token, nil
	}
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"profile.read.any"}, "client_id": {c.id}, "client_secret": {c.secret}}
	h := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	r, err := netutil.Do(ctx, c.http, http.MethodPost, c.base+"/oauth/token", []byte(form.Encode()), h)
	if err != nil {
		return "", err
	}
	if r.Status != 200 {
		return "", errors.New("service_token_rejected")
	}
	var token struct {
		Access  string `json:"access_token"`
		Type    string `json:"token_type"`
		Expires int    `json:"expires_in"`
	}
	if netutil.Decode(r.Body, &token) != nil || token.Access == "" || !strings.EqualFold(token.Type, "bearer") || token.Expires < 1 {
		return "", errors.New("service_token_invalid")
	}
	c.token = token.Access
	ttl := time.Duration(token.Expires) * time.Second
	if ttl > 30*time.Second {
		ttl -= 30 * time.Second
	}
	c.expires = time.Now().Add(ttl)
	return c.token, nil
}

func (c *Client) Profiles(ctx context.Context, query string) ([]model.Profile, error) {
	token, err := c.access(ctx)
	if err != nil {
		return nil, err
	}
	profiles := []model.Profile{}
	seenIDs := map[string]bool{}
	seenNames := map[string]bool{}
	seenCursors := map[string]bool{}
	cursor := ""
	for page := 0; page < 1000; page++ {
		q := url.Values{"limit": {"100"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		if query != "" {
			q.Set("q", query)
		}
		h := http.Header{"Authorization": {"Bearer " + token}}
		r, e := netutil.Do(ctx, c.http, "GET", c.base+"/v2/admin/profiles?"+q.Encode(), nil, h)
		if e != nil {
			return nil, e
		}
		if r.Status != 200 {
			if r.Status == 401 {
				c.mu.Lock()
				if c.token == token {
					c.token = ""
				}
				c.mu.Unlock()
			}
			return nil, errors.New("profiles_rejected")
		}
		var p struct {
			Items   []model.Profile `json:"items"`
			HasNext bool            `json:"has_next"`
			Next    string          `json:"next_cursor"`
			Size    int             `json:"page_size"`
		}
		if netutil.Decode(r.Body, &p) != nil || p.Items == nil || p.Size != len(p.Items) || len(p.Items) > 100 {
			return nil, errors.New("profiles_invalid")
		}
		for _, item := range p.Items {
			id, e := model.UUID(item.ID)
			if e != nil || !model.ValidName(item.Name) || seenIDs[id] || seenNames[strings.ToLower(item.Name)] {
				return nil, errors.New("profiles_invalid")
			}
			item.ID = id
			seenIDs[id] = true
			seenNames[strings.ToLower(item.Name)] = true
			profiles = append(profiles, item)
		}
		if !p.HasNext {
			return profiles, nil
		}
		if p.Next == "" || p.Next == cursor || seenCursors[p.Next] || len(p.Items) == 0 {
			return nil, errors.New("pagination_invalid")
		}
		seenCursors[p.Next] = true
		cursor = p.Next
	}
	return nil, errors.New("pagination_limit")
}

func (c *Client) Find(ctx context.Context, id, name string) (model.Profile, error) {
	ps, err := c.Profiles(ctx, name)
	if err != nil {
		return model.Profile{}, err
	}
	for _, p := range ps {
		if p.ID == id && p.Name == name {
			return p, nil
		}
	}
	return model.Profile{}, model.ErrIdentity
}

func (c *Client) Lookup(ctx context.Context, name string) (model.Profile, error) {
	ps, err := c.Profiles(ctx, name)
	if err != nil {
		return model.Profile{}, err
	}
	for _, p := range ps {
		if strings.EqualFold(p.Name, name) {
			return p, nil
		}
	}
	return model.Profile{}, model.ErrIdentity
}
