package embedded

import (
	"context"
	"testing"
	"time"
)

func TestKiroWaitForRequestSlotPacesBursts(t *testing.T) {
	now := time.Now().UTC()
	executor := &kiroHTTPExecutor{
		options:       KiroOptions{Now: func() time.Time { return now }},
		minInterval:   map[string]time.Time{},
		endpointUntil: map[string]map[string]time.Time{},
	}
	// First call should not block and return a slot equal to the (fake) clock.
	slot, err := executor.waitForRequestSlot(context.Background(), "cred-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slot.Equal(now) {
		t.Fatalf("first slot %v should equal clock %v", slot, now)
	}
}

func TestKiroWaitForRequestSlotSpacing(t *testing.T) {
	now := time.Now().UTC()
	executor := &kiroHTTPExecutor{
		options:       KiroOptions{Now: func() time.Time { return now }},
		minInterval:   map[string]time.Time{},
		endpointUntil: map[string]map[string]time.Time{},
	}
	ctx := context.Background()
	if _, err := executor.waitForRequestSlot(ctx, "cred-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Reserve again without advancing the clock: the slot must be exactly
	// kiroMinRequestInterval ahead, proving spacing is enforced.
	slot2, err := executor.waitForRequestSlot(ctx, "cred-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := slot2.Sub(now); got != kiroMinRequestInterval {
		t.Fatalf("second slot delta = %v, want %v", got, kiroMinRequestInterval)
	}
	// A third call with no clock advance still yields a slot spaced by one
	// interval from the previous, i.e. two intervals from the start.
	slot3, err := executor.waitForRequestSlot(ctx, "cred-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := slot3.Sub(now); got != 2*kiroMinRequestInterval {
		t.Fatalf("third slot delta = %v, want %v", got, 2*kiroMinRequestInterval)
	}
}

func TestKiroEndpointBucketBlockAndRotate(t *testing.T) {
	var now time.Time
	now = time.Now().UTC()
	executor := &kiroHTTPExecutor{
		options:       KiroOptions{Now: func() time.Time { return now }},
		minInterval:   map[string]time.Time{},
		endpointUntil: map[string]map[string]time.Time{},
	}
	// Initially all endpoints available.
	if !executor.endpointAvailable("cred-1", "runtime.us-east-1.kiro.dev") {
		t.Fatal("runtime should be available initially")
	}
	// Block one endpoint.
	executor.blockEndpoint("cred-1", "runtime.us-east-1.kiro.dev")
	if executor.endpointAvailable("cred-1", "runtime.us-east-1.kiro.dev") {
		t.Fatal("runtime should be blocked after 429")
	}
	// Different credential not affected.
	if !executor.endpointAvailable("cred-2", "runtime.us-east-1.kiro.dev") {
		t.Fatal("cred-2 should not be blocked by cred-1 429")
	}
	// Advance clock past cooldown -> becomes available again.
	now = now.Add(kiroEndpointBucketCooldown + time.Second)
	if !executor.endpointAvailable("cred-1", "runtime.us-east-1.kiro.dev") {
		t.Fatal("runtime should become available after cooldown")
	}
}

func TestKiroChooseVariantsPrefersOpenEndpoints(t *testing.T) {
	var now time.Time
	now = time.Now().UTC()
	executor := &kiroHTTPExecutor{
		options:       KiroOptions{Now: func() time.Time { return now }},
		minInterval:   map[string]time.Time{},
		endpointUntil: map[string]map[string]time.Time{},
	}
	// Without AWS rotation, only runtime exists.
	variants := executor.chooseVariants("cred-1", "us-east-1")
	if len(variants) != 1 {
		t.Fatalf("variants = %d, want 1 (AWS rotation off)", len(variants))
	}
	if variants[0].host != "runtime.us-east-1.kiro.dev" {
		t.Fatalf("first variant = %q, want runtime", variants[0].host)
	}
}
