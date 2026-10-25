package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const example = `listen: "127.0.0.1:8267"
public_root: "https://union.example.org/member"
elementskin_api_url: "http://skin:8080"
elementskin_site_url: "https://skin.example.org"
service_client_id: "application"
service_client_secret_file: "client"
admin_token_file: "admin"
member_key_file: "member"
state_path: "data/state.db"
secret_dir: "data/secrets"
`

func setup(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{"client": "synthetic-client", "admin": strings.Repeat("a", 64), "member": "synthetic-member", "config.yaml": example} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "config.yaml")
}

func TestConfigFilesEnvironmentAndRequiredFields(t *testing.T) {
	path := setup(t)
	c, err := Load(path)
	if err != nil || c.MemberKey != "synthetic-member" || c.ClientSecret != "synthetic-client" || c.RootPath() != "/member" || c.Timeout().Seconds() != 8 || c.StatePath != filepath.Join(filepath.Dir(path), "data/state.db") {
		t.Fatal(c, err)
	}
	t.Setenv("UNION_GATEWAY_LISTEN", "127.0.0.1:9000")
	t.Setenv("UNION_GATEWAY_CLIENT_SECRET", "environment-secret")
	t.Setenv("UNION_GATEWAY_ADMIN_TOKEN", strings.Repeat("b", 64))
	t.Setenv("UNION_GATEWAY_MEMBER_KEY", "")
	c, err = Load(path)
	if err != nil || c.Listen != "127.0.0.1:9000" || c.ClientSecret != "environment-secret" || c.AdminToken != strings.Repeat("b", 64) || c.MemberKey != "" {
		t.Fatal(c, err)
	}
	if err = os.WriteFile(path, []byte(example+"unknown_field: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Load(path); err == nil {
		t.Fatal("unknown field")
	}
}

func TestConfigRejectsInvalidURLsSecretsAndIntervals(t *testing.T) {
	base, err := Load(setup(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Config){
		func(c *Config) { c.PublicRoot = "http://public.example" },
		func(c *Config) { c.PublicRoot = "https://user:password@public.example" },
		func(c *Config) { c.PublicRoot = "https://public.example/?q=1" },
		func(c *Config) { c.ElementSkinURL = "file:///secret" },
		func(c *Config) { c.PublicRoot = "https://public.example/a/../b" },
		func(c *Config) { c.Listen = "invalid" }, func(c *Config) { c.AdminToken = "short" }, func(c *Config) { c.ClientID = "" },
		func(c *Config) { c.StatePath = "" }, func(c *Config) { c.SecretDir = "" },
		func(c *Config) { c.TimeoutSeconds = 0 }, func(c *Config) { c.SyncSeconds = 9 },
		func(c *Config) { c.Scope = "admin" }, func(c *Config) { c.SkinDomains = []string{"https://bad.example"} },
	} {
		c := base
		change(&c)
		if c.Validate() == nil {
			t.Fatal("invalid config accepted")
		}
	}
	for _, content := range []string{"bad: [", "service_client_id: x\n", strings.ReplaceAll(example, "client-secret", "missing")} {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		os.WriteFile(path, []byte(content), 0600)
		if _, err = Load(path); err == nil {
			t.Fatal(content)
		}
	}
	if _, err = Load(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing config")
	}
}
