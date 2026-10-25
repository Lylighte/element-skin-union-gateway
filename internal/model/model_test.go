package model

import (
	"errors"
	"testing"
)

func TestUUIDAndNameValidation(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		valid    bool
	}{
		{"11111111-1111-4111-8111-111111111111", "11111111111141118111111111111111", true},
		{"AAAAAAAAAAAA4AAA8AAAAAAAAAAAAAAA", "aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa", true},
		{"short", "", false}, {"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "", false},
	} {
		got, err := UUID(tc.in)
		if got != tc.want || (err == nil) != tc.valid {
			t.Fatalf("UUID(%q)=%q,%v", tc.in, got, err)
		}
		if !tc.valid && !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		in    string
		valid bool
	}{{"UnionTest_1", true}, {"", false}, {"abcdefghijklmnopq", false}, {"test/name", false}, {"用户", false}} {
		if ValidName(tc.in) != tc.valid {
			t.Fatal(tc)
		}
	}
}
