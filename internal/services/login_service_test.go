package services

import (
	"testing"
	"time"
)

func TestLoginFailureBlocksIPOnThirdAttempt(t *testing.T) {
	svc := NewLoginService()
	svc.notify = nil
	now := time.Now()
	for i := 0; i < loginIPMaxFailures; i++ {
		svc.recordLoginFailure("admin", "192.0.2.10", now, "test")
	}

	state := svc.byIP["192.0.2.10"]
	if state.Failures != loginIPMaxFailures || !state.BlockedUntil.Equal(now.Add(loginBlockDuration)) {
		t.Fatalf("unexpected IP state: %#v", state)
	}
}

func TestLoginFailureAlwaysAddsMinuteCooldown(t *testing.T) {
	svc := NewLoginService()
	svc.notify = nil
	now := time.Now()
	svc.recordLoginFailure("admin", "192.0.2.11", now, "test")
	if wait := svc.loginWait("admin", "192.0.2.11", now); wait != loginCooldown {
		t.Fatalf("cooldown = %s, want %s", wait, loginCooldown)
	}
}
