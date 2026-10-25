package model

import (
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
)

var (
	ErrNotReady = errors.New("not_ready")
	ErrIdentity = errors.New("identity_unavailable")
	ErrReplay   = errors.New("replayed_request")
	ErrInvalid  = errors.New("invalid_input")
	namePattern = regexp.MustCompile(`^[A-Za-z0-9_]{1,16}$`)
)

type Profile struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	UserID string `json:"user_id,omitempty"`
	Email  string `json:"owner_email,omitempty"`
}

type Property struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Signature string `json:"signature,omitempty"`
}

type YggProfile struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Properties []Property `json:"properties"`
}

type Member struct {
	Code string `json:"code"`
	Root string `json:"bs_root"`
}

type Generation struct {
	Version     int64
	Fingerprint string
	Ref         string
}

type State struct {
	Generation       Generation
	MemberRef        string
	DirectoryVersion int64
	SyncedAt         int64
	Requested        int64
	Completed        int64
	LastError        string
}

type Response struct {
	Status int
	Body   []byte
}

func UUID(value string) (string, error) {
	value = strings.ToLower(strings.ReplaceAll(value, "-", ""))
	if len(value) != 32 {
		return "", ErrInvalid
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", ErrInvalid
	}
	return value, nil
}

func ValidName(value string) bool { return namePattern.MatchString(value) }
