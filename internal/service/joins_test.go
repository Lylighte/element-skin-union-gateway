package service

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Lylighte/element-skin-union-gateway/internal/model"
)

func TestVolatileJoinProofExpiryCapacityAndConcurrentAccess(t *testing.T) {
	s := &Service{joins: make(map[string]joinProof)}
	start := time.Now()
	if err := s.rememberJoin("server", "profile", "token", start); err != nil {
		t.Fatal(err)
	}
	proof, ok := s.originJoin("server")
	if !ok || proof.ID != "profile" || proof.Token != "token" || !proof.Expires.Equal(start.Add(25*time.Second)) {
		t.Fatal(proof, ok)
	}
	s.forgetJoin("server", "previous-token")
	if _, ok = s.originJoin("server"); !ok {
		t.Fatal("late rejection removed a new join")
	}
	s.forgetJoin("server", "token")
	if _, ok = s.originJoin("server"); ok {
		t.Fatal("revoked token retained")
	}
	s.joins["expired"] = joinProof{Expires: start.Add(-time.Second)}
	if _, ok = s.originJoin("expired"); ok {
		t.Fatal("expired proof")
	}
	if err := s.rememberJoin("expired", "profile", "token", start.Add(-time.Minute)); !errors.Is(err, model.ErrNotReady) {
		t.Fatal(err)
	}
	for i := range 4096 {
		s.joins[fmt.Sprint(i)] = joinProof{ID: "profile", Token: "token", Expires: start.Add(time.Minute)}
	}
	if err := s.rememberJoin("overflow", "profile", "token", time.Now()); !errors.Is(err, model.ErrNotReady) {
		t.Fatal(err)
	}
	if err := s.rememberJoin("0", "profile", "new", time.Now()); err != nil {
		t.Fatal(err)
	}
	s.joins["1"] = joinProof{Expires: start.Add(-time.Minute)}
	if err := s.rememberJoin("new", "profile", "token", time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(s.joins) != 4096 {
		t.Fatal(len(s.joins))
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 10 {
				s.originJoin("new")
				s.forgetJoin("missing", "old")
				s.rememberJoin("0", "profile", "new", time.Now())
			}
		})
	}
	wg.Wait()
	if proof, ok = s.originJoin("0"); !ok || proof.Token != "new" {
		t.Fatal(proof, ok)
	}
}
