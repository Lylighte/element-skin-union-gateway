package service

import (
	"time"

	"github.com/Lylighte/element-skin-union-gateway/internal/model"
)

// This is only an origin/expiry gate. The upstream must still validate token and session.
// Tokens never enter SQLite and do not survive a gateway restart.
func (s *Service) rememberJoin(server, id, token string, started time.Time) error {
	s.joinsMu.Lock()
	defer s.joinsMu.Unlock()
	now := time.Now()
	for key, proof := range s.joins {
		if !now.Before(proof.Expires) {
			delete(s.joins, key)
		}
	}
	expires := started.Add(25 * time.Second)
	if !now.Before(expires) {
		delete(s.joins, server)
		return model.ErrNotReady
	}
	if _, exists := s.joins[server]; !exists && len(s.joins) >= 4096 {
		return model.ErrNotReady
	}
	s.joins[server] = joinProof{ID: id, Token: token, Expires: expires}
	return nil
}

func (s *Service) originJoin(server string) (joinProof, bool) {
	s.joinsMu.Lock()
	defer s.joinsMu.Unlock()
	proof, ok := s.joins[server]
	if ok && !time.Now().Before(proof.Expires) {
		delete(s.joins, server)
		return joinProof{}, false
	}
	return proof, ok
}

func (s *Service) forgetJoin(server, token string) {
	s.joinsMu.Lock()
	defer s.joinsMu.Unlock()
	if s.joins[server].Token == token {
		delete(s.joins, server)
	}
}
