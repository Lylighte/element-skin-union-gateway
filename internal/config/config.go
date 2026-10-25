package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen            string   `yaml:"listen"`
	PublicRoot        string   `yaml:"public_root"`
	SiteName          string   `yaml:"site_name"`
	ElementSkinURL    string   `yaml:"elementskin_api_url"`
	ElementSkinSite   string   `yaml:"elementskin_site_url"`
	ClientID          string   `yaml:"service_client_id"`
	ClientSecretFile  string   `yaml:"service_client_secret_file"`
	AdminTokenFile    string   `yaml:"admin_token_file"`
	MemberKeyFile     string   `yaml:"member_key_file"`
	WebhookSecretFile string   `yaml:"webhook_secret_file"`
	StatePath         string   `yaml:"state_path"`
	SecretDir         string   `yaml:"secret_dir"`
	SkinDomains       []string `yaml:"skin_domains"`
	TimeoutSeconds    int      `yaml:"timeout_seconds"`
	SyncSeconds       int      `yaml:"sync_interval_seconds"`
	QueryEmail        bool     `yaml:"enable_query_email"`
	Scope             string   `yaml:"service_scope"`
	ClientSecret      string   `yaml:"-"`
	AdminToken        string   `yaml:"-"`
	MemberKey         string   `yaml:"-"`
	WebhookSecret     string   `yaml:"-"`
}

func Load(path string) (Config, error) {
	c := Config{Listen: "0.0.0.0:8267", SiteName: "Element Skin Union", TimeoutSeconds: 8, SyncSeconds: 300, Scope: "profile.read.any"}
	f, err := os.Open(path)
	if err != nil {
		return c, errors.New("config_unreadable")
	}
	defer f.Close()
	d := yaml.NewDecoder(f)
	d.KnownFields(true)
	if err = d.Decode(&c); err != nil {
		return c, errors.New("config_invalid")
	}
	if d.Decode(new(any)) != io.EOF {
		return c, errors.New("config_invalid")
	}
	base, _ := filepath.Abs(filepath.Dir(path))
	fields := []struct {
		env   string
		value *string
	}{
		{"LISTEN", &c.Listen}, {"PUBLIC_ROOT", &c.PublicRoot}, {"ELEMENTSKIN_API_URL", &c.ElementSkinURL},
		{"SERVICE_CLIENT_ID", &c.ClientID}, {"STATE_PATH", &c.StatePath}, {"SECRET_DIR", &c.SecretDir},
	}
	for _, field := range fields {
		if v, ok := os.LookupEnv("UNION_GATEWAY_" + field.env); ok {
			*field.value = v
		}
	}
	secrets := []struct {
		env      string
		path     *string
		value    *string
		required bool
	}{
		{"CLIENT_SECRET", &c.ClientSecretFile, &c.ClientSecret, true},
		{"ADMIN_TOKEN", &c.AdminTokenFile, &c.AdminToken, true},
		{"MEMBER_KEY", &c.MemberKeyFile, &c.MemberKey, false},
		{"WEBHOOK_SECRET", &c.WebhookSecretFile, &c.WebhookSecret, false},
	}
	for _, s := range secrets {
		if v, ok := os.LookupEnv("UNION_GATEWAY_" + s.env); ok {
			*s.value = strings.TrimSpace(v)
		} else if *s.path != "" {
			*s.path = resolve(base, *s.path)
			b, e := os.ReadFile(*s.path)
			if e != nil {
				return c, fmt.Errorf("secret_unreadable: %s", s.env)
			}
			*s.value = strings.TrimSpace(string(b))
		}
		if (s.required && *s.value == "") || strings.ContainsAny(*s.value, "\r\n") {
			return c, fmt.Errorf("secret_invalid: %s", s.env)
		}
	}
	c.StatePath = resolve(base, c.StatePath)
	c.SecretDir = resolve(base, c.SecretDir)
	if err = c.Validate(); err != nil {
		return c, err
	}
	return c, nil
}

func resolve(base, value string) string {
	if value == "" || filepath.IsAbs(value) {
		return value
	}
	return filepath.Join(base, value)
}

func (c Config) Validate() error {
	for _, v := range []struct {
		name, value string
		https       bool
	}{
		{"public_root", c.PublicRoot, true}, {"elementskin_api_url", c.ElementSkinURL, false}, {"elementskin_site_url", c.ElementSkinSite, true},
	} {
		u, err := url.Parse(v.value)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || (u.Scheme != "https" && (v.https || u.Scheme != "http")) || strings.Contains(u.Path, "..") {
			return fmt.Errorf("url_invalid: %s", v.name)
		}
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return errors.New("listen_invalid")
	}
	if c.ClientID == "" || c.StatePath == "" || c.SecretDir == "" || len(c.AdminToken) < 32 || len(c.ClientSecret) == 0 {
		return errors.New("config_required")
	}
	if c.TimeoutSeconds < 1 || c.TimeoutSeconds > 30 || c.SyncSeconds < 10 || c.SyncSeconds > 86400 {
		return errors.New("interval_invalid")
	}
	if c.Scope != "profile.read.any" {
		return errors.New("service_scope_invalid")
	}
	for _, d := range c.SkinDomains {
		if d == "" || strings.ContainsAny(d, "/:@ \t\r\n") {
			return errors.New("skin_domain_invalid")
		}
	}
	return nil
}

func (c Config) Timeout() time.Duration { return time.Duration(c.TimeoutSeconds) * time.Second }
func (c Config) RootPath() string {
	u, _ := url.Parse(c.PublicRoot)
	return strings.TrimRight(u.Path, "/")
}
