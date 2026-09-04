package embedded

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// kiroObserveTestRoundTripper intercepts both the OIDC token refresh endpoint
// and the GetUsageLimits plane, capturing the bearer token presented to the
// usage endpoint so a test can assert a stale credential was refreshed before
// the remote quote was observed.
type kiroObserveTestRoundTripper struct {
	usageBearer string
	refreshHits int
}

func (rt *kiroObserveTestRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasSuffix(req.URL.Path, "/token") {
		rt.refreshHits++
		if req.URL.Host != "oidc.us-east-1.amazonaws.com" {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"error":"unexpected_host"}`)),
				Request:    req,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"accessToken":"fresh-token","expiresIn":3600}`)),
			Request:    req,
		}, nil
	}
	if req.URL.Host == "codewhisperer.us-east-1.amazonaws.com" {
		rt.usageBearer = req.Header.Get("Authorization")
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/x-amz-json-1.0"}},
			Body: io.NopCloser(strings.NewReader(
				`{"nextDateReset":1790812800,"usageBreakdownList":[{"currentUsage":23,"currentUsageWithPrecision":23.08,"displayName":"Credit","resourceType":"CREDIT","unit":"INVOCATIONS","usageLimit":50,"usageLimitWithPrecision":50,"percentageUsed":0.4616,"nextDateReset":1790812800}]}`)),
			Request: req,
		}, nil
	}
	return &http.Response{
		StatusCode: http.StatusInternalServerError,
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
		Body:       io.NopCloser(strings.NewReader("unexpected host")),
		Request:    req,
	}, nil
}

// TestObserveKiroAccountRefreshesStaleTokenBeforeRemote verifies that a stored
// credential whose bearer token has already expired is refreshed (using its own
// persisted OIDC client) before the remote GetUsageLimits plane is queried, so
// the observed usage reflects real live usage rather than silently falling back
// to the local mirror.
func TestObserveKiroAccountRefreshesStaleTokenBeforeRemote(t *testing.T) {
	rt := &kiroObserveTestRoundTripper{}
	options := KiroOptions{
		CodewhispererHost: "https://codewhisperer.us-east-1.amazonaws.com/",
		HTTPClient:        &http.Client{Transport: rt},
	}
	// Expire is in the past, so the stored token is already expired.
	credential := KiroCredential{
		Type: ProviderKiro, AuthKind: string(KiroAuthOIDC),
		AccessToken: "stale-token", RefreshToken: "refresh-token",
		ClientID: "cid", ClientSecret: "csecret",
		ProfileARN: "arn:aws:codewhisperer:us-east-1:638616132270:profile/XTEST",
		Region:     "us-east-1", TokenType: "Bearer",
		Expire: "2020-01-01T00:00:00Z",
	}

	observation, err := ObserveKiroAccount(context.Background(), credential, options)
	if err != nil {
		t.Fatalf("ObserveKiroAccount error: %v", err)
	}
	if rt.refreshHits != 1 {
		t.Fatalf("OIDC refresh hits = %d, want 1", rt.refreshHits)
	}
	if rt.usageBearer != "Bearer fresh-token" {
		t.Fatalf("GetUsageLimits Authorization = %q, want Bearer fresh-token", rt.usageBearer)
	}
	if len(observation.IncompleteSources) != 0 {
		t.Fatalf("IncompleteSources = %v, want empty (remote should be authoritative)", observation.IncompleteSources)
	}
	if observation.AccountQuotaObserved != true || observation.CreditQuotaObserved != true {
		t.Fatalf("expected remote credit quota observed, got AccountQuotaObserved=%v CreditQuotaObserved=%v",
			observation.AccountQuotaObserved, observation.CreditQuotaObserved)
	}
	if len(observation.Usage.Meters) == 0 {
		t.Fatal("expected at least one usage meter")
	}
	if got := observation.Usage.Meters[0].CurrentUsage; got != 23.08 {
		t.Fatalf("credit CurrentUsage = %v, want 23.08", got)
	}
}

// TestObserveKiroAccountUsesFreshTokenWithoutRefresh verifies that a credential
// whose token is still valid is NOT refreshed, so no unnecessary OIDC round-trip
// happens on every observation.
func TestObserveKiroAccountUsesFreshTokenWithoutRefresh(t *testing.T) {
	rt := &kiroObserveTestRoundTripper{}
	options := KiroOptions{
		CodewhispererHost: "https://codewhisperer.us-east-1.amazonaws.com/",
		HTTPClient:        &http.Client{Transport: rt},
	}
	credential := KiroCredential{
		Type: ProviderKiro, AuthKind: string(KiroAuthOIDC),
		AccessToken: "valid-token", RefreshToken: "refresh-token",
		ClientID: "cid", ClientSecret: "csecret",
		ProfileARN: "arn:aws:codewhisperer:us-east-1:638616132270:profile/XTEST",
		Region:     "us-east-1", TokenType: "Bearer",
		// Valid for 7 days from now.
		Expire: kiroNow(options).Add(7 * 24 * time.Hour).Format(time.RFC3339),
	}

	if _, err := ObserveKiroAccount(context.Background(), credential, options); err != nil {
		t.Fatalf("ObserveKiroAccount error: %v", err)
	}
	if rt.refreshHits != 0 {
		t.Fatalf("OIDC refresh hits = %d, want 0 for a still-valid token", rt.refreshHits)
	}
	if rt.usageBearer != "Bearer valid-token" {
		t.Fatalf("GetUsageLimits Authorization = %q, want Bearer valid-token", rt.usageBearer)
	}
}
