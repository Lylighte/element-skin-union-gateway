package service

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Lylighte/element-skin-union-gateway/internal/adapter/elementskin"
	"github.com/Lylighte/element-skin-union-gateway/internal/config"
	"github.com/Lylighte/element-skin-union-gateway/internal/model"
	"github.com/Lylighte/element-skin-union-gateway/internal/signing"
	"github.com/Lylighte/element-skin-union-gateway/internal/store"
	"github.com/Lylighte/element-skin-union-gateway/internal/union"
)

var Version = "0.1.0"

type Service struct {
	Cfg     config.Config
	Store   *store.Store
	Skin    *elementskin.Client
	Hub     *union.Client
	Log     *slog.Logger
	mu      sync.RWMutex
	key     *signing.Key
	version int64
	member  string
	control sync.Mutex
	syncMu  sync.Mutex
	joinsMu sync.Mutex
	joins   map[string]joinProof
}

type joinProof struct {
	ID, Token string
	Expires   time.Time
}

func New(ctx context.Context, c config.Config, st *store.Store, skin *elementskin.Client, hub *union.Client, logger *slog.Logger) (*Service, error) {
	s := &Service{Cfg: c, Store: st, Skin: skin, Hub: hub, Log: logger, joins: make(map[string]joinProof)}
	state, err := st.State(ctx)
	if err != nil {
		return nil, err
	}
	if state.Generation.Version > 0 {
		raw, e := st.ReadSecret(state.Generation.Ref)
		if e != nil {
			return nil, errors.New("active_key_unreadable")
		}
		key, e := signing.ParsePrivate(raw)
		if e != nil || key.Fingerprint != state.Generation.Fingerprint {
			return nil, errors.New("active_key_invalid")
		}
		s.key = key
		s.version = state.Generation.Version
	}
	if state.MemberRef != "" {
		b, e := st.ReadSecret(state.MemberRef)
		if e != nil {
			return nil, errors.New("member_key_unreadable")
		}
		s.member = string(b)
	} else if c.MemberKey != "" {
		if err = s.SetMember(ctx, c.MemberKey); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Service) memberKey() string { s.mu.RLock(); defer s.mu.RUnlock(); return s.member }
func (s *Service) SetMember(ctx context.Context, key string) error {
	if key == "" || len(key) > 4096 || strings.ContainsAny(key, "\r\n") {
		return model.ErrInvalid
	}
	s.control.Lock()
	defer s.control.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if key == s.member {
		return nil
	}
	ref, err := s.Store.WriteSecret([]byte(key))
	if err != nil {
		return err
	}
	if err = s.Store.SetMember(ctx, ref); err != nil {
		return err
	}
	s.member = key
	return nil
}

func (s *Service) RefreshKey(ctx context.Context) error {
	s.control.Lock()
	defer s.control.Unlock()
	member := s.memberKey()
	if member == "" {
		return model.ErrNotReady
	}
	private, version, err := s.Hub.PrivateKey(ctx, member)
	if err != nil {
		return err
	}
	key, err := signing.ParsePrivate([]byte(private))
	if err != nil {
		return err
	}
	public, err := s.Hub.MaterialPublic(ctx)
	if err != nil {
		return err
	}
	_, fp, err := signing.Public([]byte(public))
	if err != nil || fp != key.Fingerprint {
		return errors.New("union_key_mismatch")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if version < s.version {
		return errors.New("key_version_rollback")
	}
	if version == s.version {
		if s.key != nil && s.key.Fingerprint == fp {
			return nil
		}
		return errors.New("key_version_conflict")
	}
	ref, err := s.Store.WriteSecret([]byte(private))
	if err != nil {
		return err
	}
	if err = s.Store.Activate(ctx, model.Generation{Version: version, Fingerprint: fp, Ref: ref}); err != nil {
		return err
	}
	s.key = key
	s.version = version
	return nil
}

func (s *Service) RefreshDirectory(ctx context.Context) error {
	s.control.Lock()
	defer s.control.Unlock()
	key := s.memberKey()
	if key == "" {
		return model.ErrNotReady
	}
	members, version, err := s.Hub.Directory(ctx, key)
	if err != nil {
		return err
	}
	return s.Store.SetDirectory(ctx, version, members)
}

func (s *Service) Sync(ctx context.Context) error {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	member := s.memberKey()
	if member == "" {
		return model.ErrNotReady
	}
	state, err := s.Store.State(ctx)
	if err != nil {
		return err
	}
	profiles, err := s.Skin.Profiles(ctx, "")
	if err != nil {
		return err
	}
	if err = s.Hub.Sync(ctx, member, profiles); err != nil {
		return err
	}
	return s.Store.CommitProfiles(ctx, profiles, state.Requested)
}

func (s *Service) Ready(ctx context.Context) bool {
	s.mu.RLock()
	ok := s.key != nil && s.member != ""
	s.mu.RUnlock()
	if !ok {
		return false
	}
	state, err := s.Store.State(ctx)
	return err == nil && state.DirectoryVersion > 0 && state.SyncedAt > 0
}

func (s *Service) Status(ctx context.Context) (map[string]any, error) {
	state, err := s.Store.State(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	fp := ""
	if s.key != nil {
		fp = s.key.Fingerprint
	}
	return map[string]any{"version": Version, "ready": s.key != nil && s.member != "" && state.DirectoryVersion > 0 && state.SyncedAt > 0, "member_key_configured": s.member != "", "active_key_version": s.version, "public_key_fingerprint": fp, "directory_version": state.DirectoryVersion, "last_synced_at": state.SyncedAt, "pending_sync": state.Requested > state.Completed, "last_error": state.LastError}, nil
}

func (s *Service) Hello(ctx context.Context) (map[string]any, error) {
	state, err := s.Store.State(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]any{"yggdrasilApiVersion": "element-skin-union-gateway/" + Version, "serverListVersion": state.DirectoryVersion, "privateKeyVersion": s.version, "enabledFeatures": []string{}}, nil
}

func (s *Service) PublicKeys() (map[string]any, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.key == nil {
		return nil, model.ErrNotReady
	}
	key := map[string]string{"publicKey": base64.StdEncoding.EncodeToString(s.key.DER)}
	return map[string]any{"profilePropertyKeys": []any{key}, "playerCertificateKeys": []any{}}, nil
}

func (s *Service) Metadata(ctx context.Context) (map[string]any, error) {
	if !s.Ready(ctx) {
		return nil, model.ErrNotReady
	}
	members, err := s.Store.Members(ctx)
	if err != nil {
		return nil, err
	}
	domains := map[string]bool{}
	for _, m := range members {
		u, _ := url.Parse(m.Root)
		domains[u.Hostname()] = true
	}
	for _, d := range s.Cfg.SkinDomains {
		domains[d] = true
	}
	u, _ := url.Parse(s.Cfg.ElementSkinSite)
	domains[u.Hostname()] = true
	list := []string{}
	for d := range domains {
		list = append(list, d)
	}
	sort.Strings(list)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.key == nil {
		return nil, model.ErrNotReady
	}
	return map[string]any{
		"meta":        map[string]any{"serverName": s.Cfg.SiteName, "implementationName": "element-skin-union-gateway", "implementationVersion": Version, "feature.non_email_login": true, "links": map[string]string{"homepage": s.Cfg.ElementSkinSite, "register": strings.TrimRight(s.Cfg.ElementSkinSite, "/") + "/register/"}},
		"skinDomains": list, "signaturePublickey": s.key.PublicPEM,
	}, nil
}

func (s *Service) VerifyCallback(ctx context.Context, body []byte, timestamp, nonce, signature string) error {
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	now := time.Now()
	if err != nil || ts < now.Unix()-10 || ts > now.Unix()+30 || len(nonce) < 1 || len(nonce) > 200 || len(signature) > 4096 {
		return model.ErrInvalid
	}
	key, err := s.Hub.HostPublic(ctx)
	if err != nil {
		return err
	}
	if err = signing.Verify(key, body, timestamp, nonce, signature); err != nil {
		return err
	}
	return s.Store.Nonce(ctx, nonce, now)
}

func (s *Service) QueryEmail(ctx context.Context, name string) (string, error) {
	if !s.Cfg.QueryEmail {
		return "", errors.New("query_email_disabled")
	}
	if !model.ValidName(name) {
		return "", model.ErrInvalid
	}
	p, err := s.Skin.Lookup(ctx, name)
	if errors.Is(err, model.ErrIdentity) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return p.Email, nil
}

func (s *Service) Diagnose(ctx context.Context) (int, error) {
	key := s.memberKey()
	if key == "" {
		return 0, model.ErrNotReady
	}
	return s.Hub.Diagnose(ctx, key)
}

// Run serializes outbound reconciliation. Webhook receipts persist a revision, not an assumed event order.
func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var nextRefresh, nextSync, nextAttempt time.Time
	backoff := 5 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		now := time.Now()
		if now.After(nextRefresh) {
			if err := s.RefreshDirectory(ctx); err != nil {
				s.report(ctx, "directory_refresh_failed")
			}
			if err := s.RefreshKey(ctx); err != nil {
				s.report(ctx, "key_refresh_failed")
			}
			nextRefresh = now.Add(time.Minute)
		}
		state, err := s.Store.State(ctx)
		if err == nil && !now.Before(nextAttempt) && (now.After(nextSync) || state.Requested > state.Completed) {
			if err = s.Sync(ctx); err != nil {
				s.report(ctx, "profile_sync_failed")
				nextAttempt = now.Add(backoff)
				backoff = min(backoff*2, 5*time.Minute)
			} else {
				nextAttempt = time.Time{}
				backoff = 5 * time.Second
				nextSync = now.Add(time.Duration(s.Cfg.SyncSeconds) * time.Second)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Service) report(ctx context.Context, code string) {
	_ = s.Store.Failure(ctx, code)
	s.Log.Warn("background_operation_failed", "code", code)
}
