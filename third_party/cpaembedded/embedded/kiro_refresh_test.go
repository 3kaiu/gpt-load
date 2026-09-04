package embedded

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// kiroRefreshTestRoundTripper intercepts the Kiro refreshToken endpoint over
// the real (region-based) host and returns a fixed fresh access token.
type kiroRefreshTestRoundTripper struct{}

func (kiroRefreshTestRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasSuffix(req.URL.Path, "/refreshToken") && req.Method == http.MethodPost {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"accessToken":"fresh-access","refreshToken":"fresh-refresh","expiresIn":3600,"profileArn":"arn:test"}`)),
			Request:    req,
		}, nil
	}
	return nil, http.ErrHandlerTimeout
}

// mockRefreshClient returns an HTTP client whose transport intercepts the Kiro
// refresh endpoint and returns a fixed fresh token payload.
func mockRefreshClient() *http.Client {
	return &http.Client{Transport: kiroRefreshTestRoundTripper{}}
}

func TestKiroRefreshCredentialIfExpired(t *testing.T) {
	now := time.Now().UTC()
	fresh := KiroCredential{
		Type: ProviderKiro, AuthKind: string(KiroAuthSocial),
		AccessToken: "valid-now", RefreshToken: "refresh-token",
		Expire: now.Add(2 * time.Hour).Format(time.RFC3339), TokenType: "Bearer",
	}
	expired := KiroCredential{
		Type: ProviderKiro, AuthKind: string(KiroAuthSocial),
		AccessToken: "stale-access", RefreshToken: "refresh-token",
		Expire: now.Add(-time.Minute).Format(time.RFC3339), TokenType: "Bearer",
	}
	aboutToExpire := KiroCredential{
		Type: ProviderKiro, AuthKind: string(KiroAuthSocial),
		AccessToken: "stale-access-2", RefreshToken: "refresh-token",
		Expire: now.Add(2 * time.Minute).Format(time.RFC3339), TokenType: "Bearer",
	}
	apiKeyCredential := KiroCredential{
		Type: ProviderKiro, AuthKind: string(KiroAuthAPIKey),
		AccessToken: "api-key", RefreshToken: "",
		Expire: now.Add(-time.Minute).Format(time.RFC3339), TokenType: "Bearer",
	}

	options := KiroOptions{
		Region:     "us-east-1",
		HTTPClient: mockRefreshClient(),
		Now:        func() time.Time { return now },
	}
	executor := &kiroHTTPExecutor{baseURL: "", client: &http.Client{}, options: options}

	t.Run("fresh token unchanged", func(t *testing.T) {
		got := executor.refreshCredentialIfExpired(context.Background(), fresh)
		if got.AccessToken != "valid-now" {
			t.Fatalf("AccessToken = %q, want valid-now (should not refresh)", got.AccessToken)
		}
	})

	t.Run("expired token refreshed", func(t *testing.T) {
		got := executor.refreshCredentialIfExpired(context.Background(), expired)
		if got.AccessToken != "fresh-access" {
			t.Fatalf("AccessToken = %q, want fresh-access (should refresh expired token)", got.AccessToken)
		}
	})

	t.Run("about-to-expire token refreshed", func(t *testing.T) {
		got := executor.refreshCredentialIfExpired(context.Background(), aboutToExpire)
		if got.AccessToken != "fresh-access" {
			t.Fatalf("AccessToken = %q, want fresh-access (should refresh near-expiry token)", got.AccessToken)
		}
	})

	t.Run("api key never refreshed", func(t *testing.T) {
		got := executor.refreshCredentialIfExpired(context.Background(), apiKeyCredential)
		if got.AccessToken != "api-key" {
			t.Fatalf("AccessToken = %q, want api-key (API-key credentials have no refresh)", got.AccessToken)
		}
	})

	t.Run("no refresh token returns unchanged", func(t *testing.T) {
		noRefresh := expired
		noRefresh.RefreshToken = ""
		got := executor.refreshCredentialIfExpired(context.Background(), noRefresh)
		if got.AccessToken != "stale-access" {
			t.Fatalf("AccessToken = %q, want stale-access (no refresh token -> unchanged)", got.AccessToken)
		}
	})
}

func TestKiroRefreshCredentialIfExpiredIgnoresRefreshError(t *testing.T) {
	now := time.Now().UTC()
	failing := &http.Client{Transport: mockFailRT{}}

	expired := KiroCredential{
		Type: ProviderKiro, AuthKind: string(KiroAuthSocial),
		AccessToken: "stale", RefreshToken: "refresh-token",
		Expire: now.Add(-time.Minute).Format(time.RFC3339), TokenType: "Bearer",
	}
	options := KiroOptions{Region: "us-east-1", HTTPClient: failing, Now: func() time.Time { return now }}
	executor := &kiroHTTPExecutor{baseURL: "", client: &http.Client{}, options: options}

	got := executor.refreshCredentialIfExpired(context.Background(), expired)
	if got.AccessToken != "stale" {
		t.Fatalf("AccessToken = %q, want stale (refresh error must be swallowed)", got.AccessToken)
	}
}

// oidcRoundTripper intercepts the AWS SSO OIDC token endpoint and asserts the
// refresh body carries the registered client credentials.
type oidcRoundTripper struct {
	capturedBody string
	host         string
}

func (o *oidcRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodPost && strings.HasSuffix(req.URL.Host, ".amazonaws.com") &&
		strings.HasSuffix(req.URL.Path, "/token") {
		o.host = req.URL.Host
		b, _ := io.ReadAll(req.Body)
		o.capturedBody = string(b)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"accessToken":"fresh-oidc-access","refreshToken":"fresh-oidc-refresh","expiresIn":3600}`)),
			Request:    req,
		}, nil
	}
	return nil, http.ErrHandlerTimeout
}

func TestKiroRefreshCredentialOIDC(t *testing.T) {
	now := time.Now().UTC()
	expired := KiroCredential{
		Type: ProviderKiro, AuthKind: string(KiroAuthOIDC),
		AccessToken: "stale-oidc", RefreshToken: "aor-refresh",
		ClientID: "client-id", ClientSecret: "client-secret",
		Expire: now.Add(-time.Minute).Format(time.RFC3339), TokenType: "Bearer",
	}
	rt := &oidcRoundTripper{}
	options := KiroOptions{Region: "us-east-1", HTTPClient: &http.Client{Transport: rt}, Now: func() time.Time { return now }}

	t.Run("expired OIDC refreshed via oidc endpoint", func(t *testing.T) {
		executor := &kiroHTTPExecutor{baseURL: "", client: &http.Client{}, options: options}
		got := executor.refreshCredentialIfExpired(context.Background(), expired)
		if got.AccessToken != "fresh-oidc-access" {
			t.Fatalf("AccessToken = %q, want fresh-oidc-access", got.AccessToken)
		}
		if rt.host != "oidc.us-east-1.amazonaws.com" {
			t.Fatalf("host = %q, want oidc.us-east-1.amazonaws.com", rt.host)
		}
		var body map[string]string
		if err := json.Unmarshal([]byte(rt.capturedBody), &body); err != nil {
			t.Fatalf("decode captured body: %v", err)
		}
		if body["grantType"] != "refresh_token" {
			t.Errorf("grantType = %q, want refresh_token", body["grantType"])
		}
		if body["clientId"] != "client-id" || body["clientSecret"] != "client-secret" {
			t.Errorf("client credentials not present in refresh body: %q", rt.capturedBody)
		}
		if body["refreshToken"] != "aor-refresh" {
			t.Errorf("refreshToken not present in refresh body")
		}
	})

	t.Run("OIDC without client secret not refreshed", func(t *testing.T) {
		missing := expired
		missing.ClientSecret = ""
		executor := &kiroHTTPExecutor{baseURL: "", client: &http.Client{}, options: options}
		got := executor.refreshCredentialIfExpired(context.Background(), missing)
		if got.AccessToken != "stale-oidc" {
			t.Fatalf("AccessToken = %q, want stale-oidc (no client secret -> unchanged)", got.AccessToken)
		}
	})
}

// mockFailRT always fails the request.
type mockFailRT struct{}

func (mockFailRT) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, &timeoutError{}
}

type timeoutError struct{}

func (*timeoutError) Error() string   { return "timeout" }
func (*timeoutError) Timeout() bool   { return true }
func (*timeoutError) Temporary() bool { return true }

func TestKiroRetryAfterFromHeader(t *testing.T) {
	cases := []struct {
		name   string
		header map[string][]string
		want   time.Duration
	}{
		{"nil header", nil, 0},
		{"no retry-after", map[string][]string{"Content-Type": {`"application/json"`}}, 0},
		{"numeric seconds", map[string][]string{"Retry-After": {"540"}}, 540 * time.Second},
		{"malformed", map[string][]string{"Retry-After": {"abc"}}, 0},
		{"zero ignored", map[string][]string{"Retry-After": {"0"}}, 0},
		{"negative ignored", map[string][]string{"Retry-After": {"-5"}}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := kiroRetryAfterFromHeader(http.Header(c.header))
			if got != c.want {
				t.Fatalf("kiroRetryAfterFromHeader() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestKiroRetryAfterFromBody(t *testing.T) {
	cases := []struct {
		name string
		body string
		want time.Duration
	}{
		{"empty", "", 0},
		{"credit throttle", `{"__type":"com.amazon.kiro.runtimeservice#ThrottlingException","reason":"CREDIT_CONSUMPTION_RATE_EXCEEDED","retryAfterMilliseconds":300000}`, 5 * time.Minute},
		{"zero ignored", `{"retryAfterMilliseconds":0}`, 0},
		{"no field", `{"message":"x"}`, 0},
		{"not json", `not json`, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := kiroRetryAfterFromBody(c.body)
			if got != c.want {
				t.Fatalf("kiroRetryAfterFromBody() = %v, want %v", got, c.want)
			}
		})
	}
}

// TestKiroHTTP429BodyRetryAfterEndToEnd verifies the full chain:
// httptest 429 with retryAfterMilliseconds body → kiroHTTPErrorFromResponse
// → KiroExecutionError.RetryAfter == 5 minutes.
func TestKiroHTTP429BodyRetryAfterEndToEnd(t *testing.T) {
	body := `{"__type":"com.amazon.kiro.runtimeservice#ThrottlingException","message":"Too many requests, please wait before trying again.","reason":"CREDIT_CONSUMPTION_RATE_EXCEEDED","retryAfterMilliseconds":300000}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	err2 := kiroHTTPErrorFromResponse(resp)
	if err2 == nil {
		t.Fatal("expected error")
	}
	var execErr *KiroExecutionError
	if !errors.As(err2, &execErr) {
		t.Fatalf("not *KiroExecutionError: %v", err2)
	}
	if execErr.StatusCode() != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", execErr.StatusCode())
	}
	ra := execErr.RetryAfter()
	if ra == nil {
		t.Fatal("RetryAfter() is nil")
	}
	want := 5 * time.Minute
	if *ra != want {
		t.Fatalf("RetryAfter() = %v, want %v", *ra, want)
	}
}

func TestKiroHTTP400BodyReasonEndToEnd(t *testing.T) {
	body := `{"__type":"com.amazon.coral.service#ValidationException","reason":"CONTENT_LENGTH_EXCEEDS_THRESHOLD","message":"Input content length exceeds the maximum limit"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	err2 := kiroHTTPErrorFromResponse(resp)
	if err2 == nil {
		t.Fatal("expected error")
	}
	var execErr *KiroExecutionError
	if !errors.As(err2, &execErr) {
		t.Fatalf("not *KiroExecutionError: %v", err2)
	}
	if execErr.StatusCode() != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", execErr.StatusCode())
	}
	if execErr.ErrorCode() != "ValidationException" {
		t.Fatalf("code = %q, want %q", execErr.ErrorCode(), "ValidationException")
	}
	if !strings.Contains(execErr.Error(), "CONTENT_LENGTH_EXCEEDS_THRESHOLD") {
		t.Fatalf("error message should contain reason: %v", execErr.Error())
	}
}
