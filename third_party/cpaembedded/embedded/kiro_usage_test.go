package embedded

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// kiroUsageTestRoundTripper intercepts GetUsageLimits on the codewhisperer
// runtime host, captures the request, and returns a realistic usage response.
type kiroUsageTestRoundTripper struct {
	gotTarget   string
	gotBearer   string
	gotPath     string
	statusCode  int
	responseBody string
}

func (rt *kiroUsageTestRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.gotTarget = req.Header.Get("X-Amz-Target")
	rt.gotBearer = req.Header.Get("Authorization")
	rt.gotPath = req.URL.Host + req.URL.Path
	body := rt.responseBody
	if body == "" {
		body = `{"nextDateReset":1790812800,"overageConfiguration":{"overageStatus":"DISABLED"},"subscriptionInfo":{"subscriptionTitle":"KIRO FREE","type":"Q_DEVELOPER_STANDALONE_FREE"},"usageBreakdownList":[{"currency":"USD","currentUsage":13,"currentUsageWithPrecision":13.35,"displayName":"Credit","displayNamePlural":"Credits","resourceType":"CREDIT","unit":"INVOCATIONS","usageLimit":50,"usageLimitWithPrecision":50,"nextDateReset":1790812800}]}`
	}
	code := rt.statusCode
	if code == 0 {
		code = http.StatusOK
	}
	return &http.Response{
		StatusCode: code,
		Header:     http.Header{"Content-Type": []string{"application/x-amz-json-1.0"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}

func TestDiscoverKiroUsageLimitsRemote(t *testing.T) {
	rt := &kiroUsageTestRoundTripper{}
	options := KiroOptions{
		CodewhispererHost: "https://codewhisperer.us-east-1.amazonaws.com/",
		HTTPClient:        &http.Client{Transport: rt},
	}
	credential := KiroCredential{
		Type: ProviderKiro, AuthKind: string(KiroAuthOIDC),
		AccessToken: "bearer-token", RefreshToken: "refresh-token",
		ClientID: "cid", ClientSecret: "csecret",
		ProfileARN: "arn:aws:codewhisperer:us-east-1:638616132270:profile/XTEST",
		Region:     "us-east-1", TokenType: "Bearer",
	}
	disc, err := DiscoverKiroUsageLimits(context.Background(), credential, options)
	if err != nil {
		t.Fatalf("DiscoverKiroUsageLimits error: %v", err)
	}
	if rt.gotTarget != kiroGetUsageLimitsTarget {
		t.Fatalf("X-Amz-Target = %q, want %q", rt.gotTarget, kiroGetUsageLimitsTarget)
	}
	if !strings.HasPrefix(rt.gotBearer, "Bearer bearer-token") {
		t.Fatalf("Authorization = %q, want Bearer bearer-token", rt.gotBearer)
	}
	if rt.gotPath != "codewhisperer.us-east-1.amazonaws.com/" {
		t.Fatalf("called host/path = %q, want codewhisperer host", rt.gotPath)
	}
	if disc == nil || len(disc.Breaks) == 0 {
		t.Fatal("expected at least one usage meter")
	}
	credit := disc.Breaks[0]
	if credit.Unit != "INVOCATIONS" {
		t.Fatalf("meter unit = %q, want INVOCATIONS", credit.Unit)
	}
	if credit.CurrentUsage != 13.35 {
		t.Fatalf("meter CurrentUsage = %v, want 13.35", credit.CurrentUsage)
	}
	if credit.UsageLimit != 50 {
		t.Fatalf("meter UsageLimit = %v, want 50", credit.UsageLimit)
	}
	if !credit.UsageLimitExplicit {
		t.Fatal("UsageLimitExplicit should be true for a remote limit")
	}
	if credit.ResetDate == "" {
		t.Fatal("expected a ResetDate derived from nextDateReset")
	}
	if !strings.EqualFold(credit.Type, "CREDIT") {
		t.Fatalf("meter Type = %q, want CREDIT", credit.Type)
	}
}

func TestDiscoverKiroUsageLimitsFallbackOnHTTPError(t *testing.T) {
	rt := &kiroUsageTestRoundTripper{statusCode: http.StatusUnauthorized}
	options := KiroOptions{
		CodewhispererHost: "https://codewhisperer.us-east-1.amazonaws.com/",
		HTTPClient:        &http.Client{Transport: rt},
	}
	credential := KiroCredential{
		Type: ProviderKiro, AuthKind: string(KiroAuthSocial),
		AccessToken: "bearer-token", RefreshToken: "refresh-token",
		Region: "us-east-1", TokenType: "Bearer",
	}
	if _, err := DiscoverKiroUsageLimits(context.Background(), credential, options); err == nil {
		t.Fatal("expected an error on non-2xx usage response")
	}
}
