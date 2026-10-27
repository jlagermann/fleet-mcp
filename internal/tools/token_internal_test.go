package tools

import (
	"testing"
	"time"
)

func TestRedeemToken(t *testing.T) {
	t0 := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	clock := t0
	now = func() time.Time { return clock }
	defer func() { now = time.Now }()

	if err := redeemToken("never-issued"); err == nil {
		t.Error("redeemed a token no preview issued")
	}

	tok := issueToken(ConfirmToken("h", "fm_test", 1))
	if err := redeemToken(tok); err != nil {
		t.Fatalf("fresh token refused: %v", err)
	}
	if err := redeemToken(tok); err == nil {
		t.Error("token redeemed twice")
	}

	// A new preview of the same request issues the same token again.
	issueToken(tok)
	clock = t0.Add(tokenTTL - time.Second)
	if err := redeemToken(tok); err != nil {
		t.Errorf("token refused within the TTL: %v", err)
	}

	issueToken(tok)
	clock = clock.Add(tokenTTL + time.Second)
	if err := redeemToken(tok); err == nil {
		t.Error("expired token redeemed")
	}

	// Issuing prunes expired tokens.
	issueToken("old")
	clock = clock.Add(2 * tokenTTL)
	issueToken("new")
	issued.Lock()
	_, stale := issued.at["old"]
	issued.Unlock()
	if stale {
		t.Error("expired token not pruned")
	}
	_ = redeemToken("new")
}
