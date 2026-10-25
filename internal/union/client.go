package union

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Lylighte/element-skin-union-gateway/internal/model"
	"github.com/Lylighte/element-skin-union-gateway/internal/netutil"
	"github.com/Lylighte/element-skin-union-gateway/internal/signing"
)

const Root = "https://skin.mualliance.ltd/api/union"

type Client struct {
	root   string
	http   *http.Client
	mu     sync.Mutex
	public *rsa.PublicKey
	until  time.Time
}
type Error struct{ Status int }

func (e *Error) Error() string { return "union_rejected" }

// The executable always supplies Root. An injected root is for isolated protocol tests.
func New(root string, c *http.Client) *Client {
	return &Client{root: strings.TrimRight(root, "/"), http: c}
}

func (c *Client) request(ctx context.Context, method, path, key string, body any) (model.Response, error) {
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			return model.Response{}, err
		}
	}
	h := http.Header{"Content-Type": {"application/json"}}
	if key != "" {
		h.Set("X-Union-Member-Key", key)
	}
	r, err := netutil.Do(ctx, c.http, method, c.root+path, data, h)
	if err != nil {
		return r, err
	}
	if r.Status < 200 || r.Status >= 300 {
		return r, &Error{Status: r.Status}
	}
	return r, nil
}

func (c *Client) Directory(ctx context.Context, key string) ([]model.Member, int64, error) {
	r, err := c.request(ctx, "GET", "/serverlist", key, nil)
	if err != nil {
		return nil, 0, err
	}
	var out struct {
		Members []model.Member `json:"servers"`
		Version int64          `json:"version"`
	}
	if netutil.Decode(r.Body, &out) != nil || out.Version < 1 || len(out.Members) == 0 {
		return nil, 0, errors.New("directory_invalid")
	}
	seen := map[string]bool{}
	for _, m := range out.Members {
		u, e := url.Parse(m.Root)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || m.Code == "" || len(m.Code) > 32 || strings.ContainsAny(m.Code, "/ \r\n\t") || seen[m.Code+"\n"+m.Root] {
			return nil, 0, errors.New("directory_invalid")
		}
		seen[m.Code+"\n"+m.Root] = true
	}
	return out.Members, out.Version, nil
}

func (c *Client) PrivateKey(ctx context.Context, key string) (string, int64, error) {
	r, err := c.request(ctx, "GET", "/privatekey", key, nil)
	if err != nil {
		return "", 0, err
	}
	var out struct {
		Private string `json:"privateKey"`
		Version int64  `json:"privateKeyVersion"`
	}
	if netutil.Decode(r.Body, &out) != nil || out.Private == "" || out.Version < 1 {
		return "", 0, errors.New("key_response_invalid")
	}
	return out.Private, out.Version, nil
}

func (c *Client) MaterialPublic(ctx context.Context) (string, error) {
	r, err := c.request(ctx, "GET", "/yggdrasil", "", nil)
	if err != nil {
		return "", err
	}
	var out struct {
		Public string `json:"signaturePublicKey"`
	}
	if netutil.Decode(r.Body, &out) != nil || out.Public == "" {
		return "", errors.New("public_key_missing")
	}
	return out.Public, nil
}

func (c *Client) HostPublic(ctx context.Context) (*rsa.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.public != nil && time.Now().Before(c.until) {
		return c.public, nil
	}
	r, err := c.request(ctx, "GET", "", "", nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		Public string `json:"union_host_signature_public_key"`
	}
	if netutil.Decode(r.Body, &out) != nil {
		return nil, errors.New("host_key_invalid")
	}
	k, _, err := signing.Public([]byte(out.Public))
	if err != nil {
		return nil, err
	}
	c.public = k
	c.until = time.Now().Add(time.Minute)
	return k, nil
}

func (c *Client) Sync(ctx context.Context, key string, profiles []model.Profile) error {
	all := make(map[string]string, len(profiles))
	for _, p := range profiles {
		all[p.ID] = p.Name
	}
	_, err := c.request(ctx, "POST", "/sync", key, struct {
		Profiles map[string]string `json:"profileList"`
	}{all})
	return err
}

func (c *Client) CheckIdentity(ctx context.Context, p model.Profile) error {
	r, err := c.request(ctx, "GET", "/profile/mapped/byuuid/"+url.PathEscape(p.ID), "", nil)
	if err != nil {
		return err
	}
	var out struct {
		ID   string `json:"uuid"`
		Name string `json:"name"`
	}
	if netutil.Decode(r.Body, &out) != nil {
		return errors.New("mapped_profile_invalid")
	}
	id, err := model.UUID(out.ID)
	if err != nil || id != p.ID || out.Name != p.Name {
		return model.ErrIdentity
	}
	return nil
}

func (c *Client) Diagnose(ctx context.Context, key string) (int, error) {
	r, err := c.request(ctx, "POST", "/diagnose", key, nil)
	return r.Status, err
}
