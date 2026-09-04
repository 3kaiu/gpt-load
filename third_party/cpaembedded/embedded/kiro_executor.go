package embedded

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/sjson"
)

const (
	kiroAMZTarget       = "AmazonCodeWhispererStreamingService.GenerateAssistantResponse"
	kiroAMZTargetMCP    = "AmazonQDeveloperStreamingService.SendMessage"
	kiroUserAgent       = "aws-sdk-rust/1.3.15 ua/2.1 api/codewhispererstreaming/0.1.17593 os/macos lang/rust/1.92.0 md/appVersion-2.10.0 app/AmazonQ-For-CLI"
	kiroAMZUserAgent    = "aws-sdk-rust/1.3.15 ua/2.1 api/codewhispererstreaming/0.1.17593 os/macos lang/rust/1.92.0 m/F app/AmazonQ-For-CLI"
	kiroCPAProvider     = "kiro"
	kiroMaxAttempts     = 3
	kiroBodyReadIdle    = 180 * time.Second
	kiroUpstreamBodyMax = 4 * 1024 * 1024
	// kiroEndpointRetries is the number of additional endpoint rotation attempts
	// after the first 429.  Each attempt uses a different upstream endpoint with
	// an independent rate-limit bucket, so the effective wait is 2-5s per
	// attempt instead of the full 5-minute credit-consumption cooldown.
	kiroEndpointRetries = 2
	// kiroEndpointRetryBase is the base delay between endpoint rotation retries.
	kiroEndpointRetryBase = 2 * time.Second
	// kiroEndpointBucketCooldown is how long one endpoint stays on the block
	// list after a 429 before it is retried.  Only that endpoint is blocked; the
	// others in the account remain available, matching the kiro2cc-proxy /
	// AIClient2API bucket model.  The effect is rotation in 2-30s instead of the
	// full 5-minute credit-consumption cooldown.
	kiroEndpointBucketCooldown = 30 * time.Second
	// kiroMinRequestInterval is the minimum spacing enforced per credential
	// between consecutive upstream calls.  Kiro throttles on fast bursts
	// (CREDIT_CONSUMPTION_RATE_EXCEEDED), so systematically spacing requests
	// prevents triggering that bucket in the first place.
	kiroMinRequestInterval = 800 * time.Millisecond
	// kiroMaxUpstreamBodyBytes is a hard pre-dispatch guard.  Kiro rejects
	// oversized payloads with HTTP 400 CONTENT_LENGTH_EXCEEDS_THRESHOLD (~400KB
	// budget); checking before sending avoids a useless round-trip and a wasted
	// rate-limit slot.
	kiroMaxUpstreamBodyBytes = 350 * 1024
)

type KiroExecutionError struct {
	status     int
	code       string
	summary    string
	retryAfter time.Duration
}

// (KiroExecutionError).Error returns the error message.
func (err *KiroExecutionError) Error() string {
	if err == nil || strings.TrimSpace(err.summary) == "" {
		return "Kiro upstream request failed"
	}
	return err.summary
}

// (KiroExecutionError).StatusCode returns the HTTP status code.
func (err *KiroExecutionError) StatusCode() int {
	if err == nil {
		return 0
	}
	return err.status
}

// (KiroExecutionError).ErrorCode returns the upstream error code.
func (err *KiroExecutionError) ErrorCode() string {
	if err == nil {
		return ""
	}
	return err.code
}

// (KiroExecutionError).RetryAfter returns the retry-after duration.
func (err *KiroExecutionError) RetryAfter() *time.Duration {
	if err == nil || err.retryAfter <= 0 {
		return nil
	}
	value := err.retryAfter
	return &value
}

// KiroHTTPExecutor executes Anthropic-format requests against the Kiro runtime.
type KiroHTTPExecutor interface {
	ExecuteCanonical(context.Context, string, KiroCredential, ExecuteRequest) (ExecuteResponse, error)
	CountTokensCanonical(context.Context, string, KiroCredential, ExecuteRequest) (ExecuteResponse, error)
	ExecuteStreamCanonical(context.Context, string, KiroCredential, ExecuteRequest) (*ExecuteStreamResponse, error)
}

type kiroHTTPExecutor struct {
	baseURL string
	client  *http.Client
	options KiroOptions

	// mu guards the pacing and endpoint-bucket state below.  The executor is a
	// process singleton shared by all Kiro requests, so concurrent access is
	// possible and must be serialized.
	mu sync.Mutex
	// minInterval tracks the next allowed dispatch time per credential for
	// request pacing (anti fast-rate-limiting).
	minInterval map[string]time.Time
	// endpointUntil tracks, per credential, the earliest time each endpoint
	// bucket becomes available again after a 429.
	endpointUntil map[string]map[string]time.Time
}

// NewKiroHTTPExecutor returns a Kiro executor using the production HTTP client.
func NewKiroHTTPExecutor() KiroHTTPExecutor {
	return &kiroHTTPExecutor{
		baseURL: "", client: &http.Client{},
		minInterval: map[string]time.Time{}, endpointUntil: map[string]map[string]time.Time{},
	}
}

// NewKiroHTTPExecutorWithOptions returns a Kiro executor with explicit options
// (e.g. a custom clock for testing or a token refresh lead time override).
func NewKiroHTTPExecutorWithOptions(options KiroOptions) KiroHTTPExecutor {
	return &kiroHTTPExecutor{
		baseURL: "", client: &http.Client{}, options: options,
		minInterval: map[string]time.Time{}, endpointUntil: map[string]map[string]time.Time{},
	}
}

// kiroTokenRefreshLeadTime is the duration before token expiry at which the
// executor proactively refreshes the access token.  This prevents using a
// token that is valid at Prepare() time but expires before the upstream call
// completes (a common race with short-lived SSO access tokens).
const kiroTokenRefreshLeadTime = 5 * time.Minute

// refreshCredentialIfExpired checks the Kiro credential's expiry and, when
// the access token is about to expire or already expired, uses the refresh
// token to obtain a fresh pair.  The credential is returned (possibly
// refreshed).  Errors are silently ignored — the caller will see the
// upstream 401/403 and retry via the gateway's normal decision path.
func (executor *kiroHTTPExecutor) refreshCredentialIfExpired(
	ctx context.Context,
	credential KiroCredential,
) KiroCredential {
	if KiroAuthKind(credential.AuthKind) != KiroAuthSocial {
		return credential
	}
	refreshToken := strings.TrimSpace(credential.RefreshToken)
	if refreshToken == "" {
		return credential
	}
	if expiration, ok := KiroCredentialExpiresAt(credential); ok {
		leadTime := kiroTokenRefreshLeadTime
		if executor.options.TokenRefreshLeadTime > 0 {
			leadTime = executor.options.TokenRefreshLeadTime
		}
		if expiration.After(kiroNow(executor.options).Add(leadTime)) {
			return credential
		}
	}
	refreshed, err := RefreshKiroCredentialOnce(ctx, credential, executor.options)
	if err != nil {
		return credential
	}
	return refreshed
}

// kiroEndpointVariant describes one upstream endpoint for request routing.
// Different endpoints use independent rate-limit buckets; rotating between
// them on 429 lets us retry in 2-5s instead of waiting the full 5-minute
// credit-consumption cooldown.
type kiroEndpointVariant struct {
	host      string
	amzTarget string // empty = no x-amz-target header
}

// kiroEndpointVariants returns the available API endpoint variants for the
// given region.  The first entry is the default (runtime); the rest are
// kiroEnableAwsRotate reports whether rotation to the AWS (AmazonQ / CodeWhisperer)
// endpoints is enabled.  The Kiro runtime endpoint is always valid for Kiro
// local/web bearer tokens.  The AWS endpoints are additionally used by the
// kiro2cc-proxy ecosystem — they carry the same bearer token but a distinct
// X-Amz-Target header and an independent rate-limit bucket, so rotating to them
// after a runtime 429 keeps the request flowing instead of cooldowning.  Because
// those endpoints route through the AWS ecosystem and are not verifiable without
// a live Kiro token, they are gated behind KIRO_AWS_ROTATE=1 so the safe runtime
// endpoint stays the default.
func kiroEnableAwsRotate() bool {
	return os.Getenv("KIRO_AWS_ROTATE") != ""
}

// kiroEndpointVariants returns the upstream endpoints to try.  The first entry
// is the default (runtime).  When AWS rotation is enabled the AmazonQ and
// CodeWhisperer endpoints follow; each is a distinct bucket whose 429 is tracked
// independently by the endpoint bucket registry.  runtime.* always authenticates
// a Kiro local/web bearer token; the AWS endpoints use the same token but a
// separate X-Amz-Target and are best-effort rotation targets.
func kiroEndpointVariants(region string) []kiroEndpointVariant {
	region = strings.ToLower(strings.TrimSpace(region))
	if region == "" {
		region = DefaultKiroRegion
	}
	variants := []kiroEndpointVariant{
		{host: "runtime." + region + ".kiro.dev"},
	}
	if kiroEnableAwsRotate() {
		variants = append(variants,
			kiroEndpointVariant{host: "q." + region + ".amazonaws.com", amzTarget: kiroAMZTargetMCP},
			kiroEndpointVariant{host: "codewhisperer.us-east-1.amazonaws.com", amzTarget: kiroAMZTarget},
			kiroEndpointVariant{host: "q." + region + ".amazonaws.com", amzTarget: ""},
		)
	}
	return variants
}

// (kiroHTTPExecutor).endpoint returns the Kiro API endpoint URL.
func (executor *kiroHTTPExecutor) endpoint(credential KiroCredential) (string, error) {
	if strings.TrimSpace(executor.baseURL) != "" {
		return strings.TrimRight(executor.baseURL, "/"), nil
	}
	region := strings.TrimSpace(credential.Region)
	if region == "" {
		region = DefaultKiroRegion
	}
	return KiroRuntimeURL(region)
}

// (kiroHTTPExecutor).requestBody builds the request body for Kiro API calls.
func (executor *kiroHTTPExecutor) requestBody(credential KiroCredential, request kiroRequest) ([]byte, error) {
	payload, err := buildKiroPayload(request, credential.ProfileARN)
	if err != nil {
		return nil, err
	}
	// When this is an API-key credential the runtime requires the TokenType
	// header instead of a profileArn in the body.
	if KiroAuthKind(credential.AuthKind) == KiroAuthAPIKey {
		payload, err = sjson.DeleteBytes(payload, "profileArn")
		if err != nil {
			return nil, err
		}
	}
	return payload, nil
}

// (kiroHTTPExecutor).newRequest creates an HTTP request with the default
// CodeWhisperer x-amz-target header.
func (executor *kiroHTTPExecutor) newRequest(ctx context.Context, method, url string, body []byte) (*http.Request, error) {
	return executor.newRequestWithTarget(ctx, method, url, body, kiroAMZTarget)
}

// (kiroHTTPExecutor).newRequestWithTarget creates an HTTP request with a
// caller-specified x-amz-target header.  When amzTarget is empty the header
// is omitted (used by the Ide and Runtime endpoints).
func (executor *kiroHTTPExecutor) newRequestWithTarget(ctx context.Context, method, url string, body []byte, amzTarget string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.0")
	req.Header.Set("Accept", "*/*")
	if amzTarget != "" {
		req.Header.Set("X-Amz-Target", amzTarget)
	}
	req.Header.Set("User-Agent", kiroUserAgent)
	req.Header.Set("x-amz-user-agent", kiroAMZUserAgent)
	req.Header.Set("x-amzn-codewhisperer-optout", "false")
	req.Header.Set("amz-sdk-invocation-id", randomKiroHex(16))
	return req, nil
}

// waitForRequestSlot paces per-credential request dispatch so a fast burst of
// requests does not trip Kiro's CREDIT_CONSUMPTION_RATE_EXCEEDED throttle.  It
// blocks until the credential's minimum interval has elapsed or the context is
// done, returning the release time so the caller can also release the slot.
func (executor *kiroHTTPExecutor) waitForRequestSlot(ctx context.Context, credentialID string) (time.Time, error) {
	if credentialID == "" {
		return time.Time{}, nil
	}
	now := kiroNow(executor.options)
	executor.mu.Lock()
	if executor.minInterval == nil {
		executor.minInterval = map[string]time.Time{}
	}
	next := executor.minInterval[credentialID]
	if next.Before(now) {
		next = now
	}
	executor.minInterval[credentialID] = next.Add(kiroMinRequestInterval)
	executor.mu.Unlock()
	wait := next.Sub(now)
	if wait <= 0 {
		return next, nil
	}
	select {
	case <-time.After(wait):
		return next, nil
	case <-ctx.Done():
		return time.Time{}, ctx.Err()
	}
}

// blockEndpoint records that a particular endpoint returned 429 for a given
// credential, keeping that bucket out of rotation for kiroEndpointBucketCooldown.
func (executor *kiroHTTPExecutor) blockEndpoint(credentialID, host string) {
	if credentialID == "" || host == "" {
		return
	}
	executor.mu.Lock()
	if executor.endpointUntil == nil {
		executor.endpointUntil = map[string]map[string]time.Time{}
	}
	buckets := executor.endpointUntil[credentialID]
	if buckets == nil {
		buckets = map[string]time.Time{}
		executor.endpointUntil[credentialID] = buckets
	}
	buckets[host] = kiroNow(executor.options).Add(kiroEndpointBucketCooldown)
	executor.mu.Unlock()
}

// endpointAvailable reports whether a given endpoint bucket is currently open
// for the credential (i.e. not in 429 cooldown).
func (executor *kiroHTTPExecutor) endpointAvailable(credentialID, host string) bool {
	if credentialID == "" {
		return true
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	buckets := executor.endpointUntil[credentialID]
	if buckets == nil {
		return true
	}
	until := buckets[host]
	return until.Before(kiroNow(executor.options))
}

// chooseVariants returns the endpoint variants ordered for this attempt: the
// non-blocked buckets first (default endpoint first when it is open), then the
// blocked ones (as a last resort).  This keeps rotation on open buckets while
// still falling back to a cooldowning bucket rather than failing outright.
func (executor *kiroHTTPExecutor) chooseVariants(credentialID string, region string) []kiroEndpointVariant {
	variants := kiroEndpointVariants(region)
	if len(variants) == 0 {
		variants = kiroEndpointVariants("")
	}
	if credentialID == "" {
		return variants
	}
	open := make([]kiroEndpointVariant, 0, len(variants))
	blocked := make([]kiroEndpointVariant, 0, len(variants))
	first := variants[0]
	var firstBlocked bool
	for _, v := range variants {
		available := executor.endpointAvailable(credentialID, v.host)
		if v.host == first.host {
			firstBlocked = !available
		}
		if available {
			open = append(open, v)
		} else {
			blocked = append(blocked, v)
		}
	}
	// Prefer the runtime default among the open buckets so we do not jump to an
	// AWS endpoint while the runtime bucket is already open.  Only when it is
	// itself blocked do we promote a different open bucket to the front.
	if firstBlocked && len(open) > 1 {
		if open[0].host == first.host {
			open = append(open[1:], open[0])
		}
	}
	return append(open, blocked...)
}

// preflightPayload rejects oversized Kiro payloads before dispatch to avoid a
// wasted round-trip and a rate-limit slot on a request Kiro would reject with
// HTTP 400 CONTENT_LENGTH_EXCEEDS_THRESHOLD.
func preflightPayload(body []byte) error {
	if len(body) > kiroMaxUpstreamBodyBytes {
		return &KiroExecutionError{
			status:  http.StatusBadRequest,
			code:    "CONTENT_LENGTH_EXCEEDS_THRESHOLD",
			summary: fmt.Sprintf("Kiro payload size %d exceeds the %d-byte pre-dispatch limit", len(body), kiroMaxUpstreamBodyBytes),
		}
	}
	return nil
}

// (kiroHTTPExecutor).ExecuteCanonical executes a Kiro request and returns an Anthropic-formatted response.
func (executor *kiroHTTPExecutor) ExecuteCanonical(
	ctx context.Context,
	credentialID string,
	credential KiroCredential,
	request ExecuteRequest,
) (ExecuteResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	normalizeKiroCredential(&credential)
	if err := validateKiroCredential(credential); err != nil {
		return ExecuteResponse{}, err
	}
	if !isKiroClaudeFormat(request.Format) {
		return ExecuteResponse{}, fmt.Errorf("Kiro executor requires Anthropic format")
	}
	credential = executor.refreshCredentialIfExpired(ctx, credential)
	parsed, err := parseKiroRequest(request.Payload)
	if err != nil {
		return ExecuteResponse{}, err
	}
	body, err := executor.requestBody(credential, parsed)
	if err != nil {
		return ExecuteResponse{}, err
	}
	if os.Getenv("KIRO_DEBUG_HTTP") != "" {
		fmt.Fprintf(os.Stderr, "[kiro-debug] request payload bytes=%d input_chars=%d\n", len(body), len(request.Payload))
	}
	// Pre-dispatch size guard: Kiro rejects oversized payloads with HTTP 400,
	// so reject locally before spending a rate-limit slot on the trip.
	if err := preflightPayload(body); err != nil {
		return ExecuteResponse{}, err
	}
	// Request pacing: never fire two upstream calls for the same account within
	// kiroMinRequestInterval.  This is the primary defense against fast 429s.
	nextSlot, err := executor.waitForRequestSlot(ctx, credentialID)
	if err != nil {
		return ExecuteResponse{}, err
	}
	_ = nextSlot
	// Endpoint rotation on 429: each endpoint is an independent rate-limit
	// bucket.  The loop re-chooses the order each attempt so a 429-cooldowning
	// bucket drops to the back, letting us rotate to an open one in ~2s instead
	// of the full 5-minute credit-consumption cooldown.
	variants := kiroEndpointVariants(credential.Region)
	if len(variants) == 0 {
		variants = kiroEndpointVariants("")
	}
	lastErr := error(nil)
	for attempt := 0; attempt <= kiroEndpointRetries; attempt++ {
		ordered := executor.chooseVariants(credentialID, credential.Region)
		variant := ordered[attempt%len(ordered)]
		endpointURL := "https://" + variant.host + "/generateAssistantResponse"
		req, err := executor.newRequestWithTarget(ctx, http.MethodPost, endpointURL, body, variant.amzTarget)
		if err != nil {
			return ExecuteResponse{}, err
		}
		executor.setAuth(req, credential)
		response, err := executor.client.Do(req)
		if err != nil {
			if os.Getenv("KIRO_DEBUG_HTTP") != "" {
				fmt.Fprintf(os.Stderr, "[kiro-debug] network error on endpoint %s: %v\n", variant.host, err)
			}
			lastErr = convertKiroDoError(err)
			if attempt < kiroEndpointRetries {
				delay := kiroEndpointRetryBase + time.Duration(attempt)*time.Second
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return ExecuteResponse{}, ctx.Err()
				}
				continue
			}
			return ExecuteResponse{}, lastErr
		}
		if response.StatusCode == http.StatusTooManyRequests {
			executor.blockEndpoint(credentialID, variant.host)
			err := kiroHTTPErrorFromResponse(response)
			if os.Getenv("KIRO_DEBUG_HTTP") != "" {
				fmt.Fprintf(os.Stderr, "[kiro-debug] 429 on endpoint %s, cooldowning bucket; retrying another endpoint if retries remain\n", variant.host)
			}
			if attempt < kiroEndpointRetries && len(variants) > 1 {
				delay := kiroEndpointRetryBase + time.Duration(attempt)*time.Second
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return ExecuteResponse{}, ctx.Err()
				}
				lastErr = err
				continue
			}
			return ExecuteResponse{}, err
		}
		if response.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(io.LimitReader(response.Body, 8*1024))
			response.Body.Close()
			if os.Getenv("KIRO_DEBUG_HTTP") != "" {
				fmt.Fprintf(os.Stderr, "[kiro-debug] HTTP %d on endpoint %s body: %s\n",
					response.StatusCode, variant.host, string(raw))
			}
			lastErr = &KiroExecutionError{status: response.StatusCode, summary: fmt.Sprintf("Kiro upstream returned HTTP %d: %s", response.StatusCode, string(raw))}
			if attempt < kiroEndpointRetries {
				delay := kiroEndpointRetryBase + time.Duration(attempt)*time.Second
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return ExecuteResponse{}, ctx.Err()
				}
				continue
			}
			return ExecuteResponse{}, lastErr
		}
		if contentType := response.Header.Get("Content-Type"); !strings.Contains(contentType, "amazon.eventstream") {
			raw, _ := io.ReadAll(io.LimitReader(response.Body, 8*1024))
			response.Body.Close()
			if os.Getenv("KIRO_DEBUG_HTTP") != "" {
				fmt.Fprintf(os.Stderr, "[kiro-debug] non-eventstream Content-Type on endpoint %s: %s body: %s\n",
					variant.host, contentType, string(raw))
			}
			lastErr = &KiroExecutionError{status: http.StatusBadGateway, summary: "Kiro upstream returned non-eventstream response"}
			if attempt < kiroEndpointRetries {
				delay := kiroEndpointRetryBase + time.Duration(attempt)*time.Second
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return ExecuteResponse{}, ctx.Err()
				}
				continue
			}
			return ExecuteResponse{}, lastErr
		}
		var (
			blocks      []map[string]any
			usage       map[string]any
			stopReason  = "stop_sequence"
			thinking    []string
			sig         string
			upstreamErr error
		)
		streamErr := parseKiroStream(response.Body, func(event kiroEvent) bool {
			switch event.Type {
			case kiroEventAssistantResponse:
				if strings.TrimSpace(event.Content) != "" {
					blocks = append(blocks, map[string]any{"type": "text", "text": event.Content})
				}
			case kiroEventReasoningContent:
				if strings.TrimSpace(event.ThinkingText) != "" {
					thinking = append(thinking, event.ThinkingText)
				}
				if strings.TrimSpace(event.Signature) != "" {
					sig = event.Signature
				}
			case kiroEventToolUse:
				var input any = map[string]any{}
				if strings.TrimSpace(event.ToolInput) != "" {
					_ = json.Unmarshal([]byte(event.ToolInput), &input)
				}
				blocks = append(blocks, map[string]any{
					"type": "tool_use", "id": event.ToolUseID, "name": event.ToolName, "input": input,
				})
			case kiroEventMetadata:
				usage = kiroAnthropicUsage(event)
				stopReason = "end_turn"
			case kiroEventInvalidState, kiroEventException:
				// Surface the upstream error instead of silently succeeding on the
				// partial output accumulated so far.
				if msg := event.ErrorText(); msg != "" && upstreamErr == nil {
					upstreamErr = &KiroExecutionError{status: http.StatusBadGateway, code: "upstream", summary: msg}
				}
			}
			return false
		})
		if upstreamErr != nil {
			return ExecuteResponse{}, upstreamErr
		}
		if streamErr != nil {
			return ExecuteResponse{}, &KiroExecutionError{status: http.StatusBadGateway, code: "eventstream", summary: streamErr.Error()}
		}
		// Prepend thinking block when present.
		if len(thinking) > 0 {
			content := make([]map[string]any, 0, len(blocks)+1)
			block := map[string]any{"type": "thinking", "thinking": strings.Join(thinking, "")}
			if sig != "" {
				block["signature"] = sig
			}
			content = append(content, block)
			content = append(content, blocks...)
			blocks = content
		}
		if usage == nil {
			usage = map[string]any{"input_tokens": 0, "output_tokens": 0}
		}
		final := map[string]any{
			"id": "msg_" + randomKiroHex(8), "type": "message", "role": "assistant",
			"content": blocks, "model": parsed.Model, "stop_reason": stopReason, "stop_sequence": nil,
			"usage": usage,
		}
		raw, err := json.Marshal(final)
		if err != nil {
			return ExecuteResponse{}, err
		}
		return ExecuteResponse{Payload: raw, Headers: response.Header.Clone()}, nil
	}
	return ExecuteResponse{}, lastErr
}

// (kiroHTTPExecutor).CountTokensCanonical returns a local token count estimate.
func (executor *kiroHTTPExecutor) CountTokensCanonical(
	ctx context.Context,
	credentialID string,
	credential KiroCredential,
	request ExecuteRequest,
) (ExecuteResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	normalizeKiroCredential(&credential)
	if err := validateKiroCredential(credential); err != nil {
		return ExecuteResponse{}, err
	}
	if !isKiroClaudeFormat(request.Format) {
		return ExecuteResponse{}, fmt.Errorf("Kiro executor requires Anthropic format")
	}
	inputTokens := estimateKiroTokens(request.Payload)
	status := map[string]any{
		"input_tokens": inputTokens, "output_tokens": 0,
		"server_tokens": 0,
	}
	raw, err := json.Marshal(status)
	if err != nil {
		return ExecuteResponse{}, err
	}
	return ExecuteResponse{Payload: raw}, nil
}

// CountKiroTokensLocal is a credential-less local token estimate for the
// Anthropic count-tokens path. Kiro exposes no token-counting endpoint, so the
// value is a whitespace/byte heuristic returned in the standard Anthropic
// count_tokens response shape.
func CountKiroTokensLocal(payload []byte) []byte {
	inputTokens := estimateKiroTokens(payload)
	status := map[string]any{
		"input_tokens": inputTokens, "output_tokens": 0, "server_tokens": 0,
	}
	raw, err := json.Marshal(status)
	if err != nil {
		return []byte(`{"input_tokens":0,"output_tokens":0,"server_tokens":0}`)
	}
	return raw
}

// (kiroHTTPExecutor).ExecuteStreamCanonical executes a Kiro request and streams Anthropic-formatted events.
func (executor *kiroHTTPExecutor) ExecuteStreamCanonical(
	ctx context.Context,
	credentialID string,
	credential KiroCredential,
	request ExecuteRequest,
) (*ExecuteStreamResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	normalizeKiroCredential(&credential)
	if err := validateKiroCredential(credential); err != nil {
		return nil, err
	}
	if !isKiroClaudeFormat(request.Format) {
		return nil, fmt.Errorf("Kiro executor requires Anthropic format")
	}
	credential = executor.refreshCredentialIfExpired(ctx, credential)
	parsed, err := parseKiroRequest(request.Payload)
	if err != nil {
		return nil, err
	}
	body, err := executor.requestBody(credential, parsed)
	if err != nil {
		return nil, err
	}
	// Pre-dispatch size guard, same as ExecuteCanonical.
	if err := preflightPayload(body); err != nil {
		return nil, err
	}
	// Request pacing (same anti-fast-429 defense as ExecuteCanonical).
	if _, err := executor.waitForRequestSlot(ctx, credentialID); err != nil {
		return nil, err
	}
	// Endpoint rotation on 429 (same per-bucket logic as ExecuteCanonical).
	variants := kiroEndpointVariants(credential.Region)
	if len(variants) == 0 {
		variants = kiroEndpointVariants("")
	}
	lastErr := error(nil)
	for attempt := 0; attempt <= kiroEndpointRetries; attempt++ {
		ordered := executor.chooseVariants(credentialID, credential.Region)
		variant := ordered[attempt%len(ordered)]
		endpointURL := "https://" + variant.host + "/generateAssistantResponse"
		req, err := executor.newRequestWithTarget(ctx, http.MethodPost, endpointURL, body, variant.amzTarget)
		if err != nil {
			return nil, err
		}
		executor.setAuth(req, credential)
		response, err := executor.client.Do(req)
		if err != nil {
			if os.Getenv("KIRO_DEBUG_HTTP") != "" {
				fmt.Fprintf(os.Stderr, "[kiro-debug] network error on endpoint %s: %v\n", variant.host, err)
			}
			lastErr = convertKiroDoError(err)
			if attempt < kiroEndpointRetries {
				delay := kiroEndpointRetryBase + time.Duration(attempt)*time.Second
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				continue
			}
			return nil, lastErr
		}
		if response.StatusCode == http.StatusTooManyRequests {
			executor.blockEndpoint(credentialID, variant.host)
			err := kiroHTTPErrorFromResponse(response)
			if os.Getenv("KIRO_DEBUG_HTTP") != "" {
				fmt.Fprintf(os.Stderr, "[kiro-debug] 429 on endpoint %s, cooldowning bucket; retrying another endpoint if retries remain\n", variant.host)
			}
			if attempt < kiroEndpointRetries && len(ordered) > 1 {
				delay := kiroEndpointRetryBase + time.Duration(attempt)*time.Second
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				lastErr = err
				continue
			}
			return nil, err
		}
		if response.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(io.LimitReader(response.Body, 8*1024))
			response.Body.Close()
			if os.Getenv("KIRO_DEBUG_HTTP") != "" {
				fmt.Fprintf(os.Stderr, "[kiro-debug] HTTP %d on endpoint %s body: %s\n",
					response.StatusCode, variant.host, string(raw))
			}
			lastErr = &KiroExecutionError{status: response.StatusCode, summary: fmt.Sprintf("Kiro upstream returned HTTP %d: %s", response.StatusCode, string(raw))}
			if attempt < kiroEndpointRetries {
				delay := kiroEndpointRetryBase + time.Duration(attempt)*time.Second
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				continue
			}
			return nil, lastErr
		}
		if contentType := response.Header.Get("Content-Type"); !strings.Contains(contentType, "amazon.eventstream") {
			raw, _ := io.ReadAll(io.LimitReader(response.Body, 8*1024))
			response.Body.Close()
			if os.Getenv("KIRO_DEBUG_HTTP") != "" {
				fmt.Fprintf(os.Stderr, "[kiro-debug] non-eventstream Content-Type on endpoint %s: %s body: %s\n",
					variant.host, contentType, string(raw))
			}
			lastErr = &KiroExecutionError{status: http.StatusBadGateway, summary: "Kiro upstream returned non-eventstream response"}
			if attempt < kiroEndpointRetries {
				delay := kiroEndpointRetryBase + time.Duration(attempt)*time.Second
				if os.Getenv("KIRO_DEBUG_HTTP") != "" {
					fmt.Fprintf(os.Stderr, "[kiro-debug] non-eventstream on endpoint %s, rotating (attempt %d/%d, delay %v)\n",
						variant.host, attempt+1, kiroEndpointRetries, delay)
				}
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				continue
			}
			return nil, lastErr
		}
		chunks := make(chan ExecuteStreamChunk)
		go func() {
			defer close(chunks)
			_ = executor.emitKiroSSE(ctx, chunks, parsed.Model, response.Body)
			_ = response.Body.Close()
		}()
		return &ExecuteStreamResponse{Headers: response.Header.Clone(), Chunks: chunks}, nil
	}
	return nil, lastErr
}

// emitKiroSSE consumes the Kiro event stream and writes Anthropic SSE chunks.
func (executor *kiroHTTPExecutor) emitKiroSSE(ctx context.Context, chunks chan<- ExecuteStreamChunk, model string, reader io.Reader) error {
	emit := func(payload []byte) bool {
		chunk := ExecuteStreamChunk{Payload: payload}
		select {
		case chunks <- chunk:
			return true
		case <-ctx.Done():
			return false
		}
	}
	if !emit(ktoSSE("message_start", map[string]any{
		"type": "message_start", "message": map[string]any{
			"id": "msg_" + randomKiroHex(8), "type": "message", "role": "assistant",
			"model": model, "content": []any{}, "stop_reason": nil, "stop_sequence": nil,
			"usage": map[string]any{"input_tokens": 0, "output_tokens": 0},
		},
	})) {
		return ctx.Err()
	}
	index := 0
	thinkingIndex := -1
	// parseKiroStream returns immediately when the callback reports true (stop).
	err := parseKiroStream(reader, func(event kiroEvent) bool {
		return emitKiroEventSSE(emit, &index, &thinkingIndex, event)
	})
	_ = err
	emit(message_deltaSSE(map[string]any{
		"type": "message_delta", "delta": map[string]any{"stop_reason": "end_turn", "stop_sequence": nil},
		"usage": map[string]any{"output_tokens": 0},
	}))
	emit(ktoSSE("message_stop", map[string]any{"type": "message_stop"}))
	return err
}

// emitKiroEventSSE maps one kiroEvent onto Anthropic SSE output. Returns false
// when the consumer wants to continue, true to stop.
func emitKiroEventSSE(emit func([]byte) bool, index *int, thinkingIndex *int, event kiroEvent) bool {
	switch event.Type {
	case kiroEventReasoningContent:
		if *thinkingIndex < 0 {
			*thinkingIndex = *index
			*index++
			if !emit(ktoSSE("content_block_start", map[string]any{
				"type": "content_block_start", "index": *thinkingIndex, "content_block": map[string]any{"type": "thinking", "thinking": "", "signature": ""},
			})) {
				return true
			}
		}
		if strings.TrimSpace(event.ThinkingText) != "" {
			if !emit(ktoSSE("content_block_delta", map[string]any{
				"type": "content_block_delta", "index": *thinkingIndex, "delta": map[string]any{"type": "thinking_delta", "thinking": event.ThinkingText},
			})) {
				return true
			}
		}
		if strings.TrimSpace(event.Signature) != "" {
			if !emit(ktoSSE("content_block_delta", map[string]any{
				"type": "content_block_delta", "index": *thinkingIndex, "delta": map[string]any{"type": "signature_delta", "signature": event.Signature},
			})) {
				return true
			}
		}
	case kiroEventAssistantResponse:
		if strings.TrimSpace(event.Content) != "" {
			blockIndex := *index
			*index++
			if !emit(ktoSSE("content_block_start", map[string]any{
				"type": "content_block_start", "index": blockIndex, "content_block": map[string]any{"type": "text", "text": ""},
			})) {
				return true
			}
			if !emit(ktoSSE("content_block_delta", map[string]any{
				"type": "content_block_delta", "index": blockIndex, "delta": map[string]any{"type": "text_delta", "text": event.Content},
			})) {
				return true
			}
			if !emit(ktoSSE("content_block_stop", map[string]any{"type": "content_block_stop", "index": blockIndex})) {
				return true
			}
		}
	case kiroEventToolUse:
		blockIndex := *index
		*index++
		var input any = map[string]any{}
		if strings.TrimSpace(event.ToolInput) != "" {
			_ = json.Unmarshal([]byte(event.ToolInput), &input)
		}
		if !emit(ktoSSE("content_block_start", map[string]any{
			"type": "content_block_start", "index": blockIndex, "content_block": map[string]any{
				"type": "tool_use", "id": event.ToolUseID, "name": event.ToolName, "input": map[string]any{},
			},
		})) {
			return true
		}
		// Emit the tool input as an input_json_delta for a complete tool call.
		if rawInput, err := json.Marshal(input); err == nil && len(rawInput) > 0 {
			if !emit(ktoSSE("content_block_delta", map[string]any{
				"type": "content_block_delta", "index": blockIndex, "delta": map[string]any{"type": "input_json_delta", "partial_json": string(rawInput)},
			})) {
				return true
			}
		}
		if !emit(ktoSSE("content_block_stop", map[string]any{"type": "content_block_stop", "index": blockIndex})) {
			return true
		}
	case kiroEventMetadata, kiroEventMetering:
		// Usage arrives at the end; folded into message_delta by the caller.
	}
	return false
}

// ktoSSE converts a Kiro event type string to SSE event type.
func ktoSSE(eventType string, payload map[string]any) []byte {
	raw, err := json.Marshal(payload)
	if err != nil {
		return []byte{}
	}
	return []byte(fmt.Sprintf("event: %s\ndata: %s\n\n", eventType, raw))
}

// message_deltaSSE formats message_delta SSE data.
func message_deltaSSE(payload map[string]any) []byte {
	return ktoSSE("message_delta", payload)
}

// kiroAnthropicUsage converts Kiro usage metadata to Anthropic format.
func kiroAnthropicUsage(event kiroEvent) map[string]any {
	usage := map[string]any{
		"input_tokens": event.InputTokens, "output_tokens": event.OutputTokens,
		"cache_creation_input_tokens": event.CacheWriteInputTokens,
		"cache_read_input_tokens":     event.CacheReadInputTokens,
	}
	return usage
}

// setAuth attaches the bearer token, adding the TokenType header for API keys.
func (executor *kiroHTTPExecutor) setAuth(request *http.Request, credential KiroCredential) {
	request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(credential.AccessToken))
	if KiroAuthKind(credential.AuthKind) == KiroAuthAPIKey {
		request.Header.Set("TokenType", "API_KEY")
	}
}

// isKiroClaudeFormat checks if a Kiro error response is Claude-compatible format.
func isKiroClaudeFormat(format string) bool {
	format = strings.ToLower(strings.TrimSpace(format))
	return format == "" || format == "claude" || format == "anthropic"
}

// kiroHTTPErrorFromResponse creates an HTTP error from a Kiro response.
func kiroHTTPErrorFromResponse(response *http.Response) error {
	summary := fmt.Sprintf("Kiro upstream returned HTTP %d", response.StatusCode)
	retryAfter := kiroRetryAfterFromHeader(response.Header)
	body := ""
	if response != nil && response.Body != nil {
		raw, _ := io.ReadAll(io.LimitReader(response.Body, 8*1024))
		body = string(raw)
		// Kiro reports throttling retry windows in the JSON body
		// (retryAfterMilliseconds), not always in the Retry-After header.
		if fromBody := kiroRetryAfterFromBody(body); fromBody > retryAfter {
			retryAfter = fromBody
		}
	}
	// Parse the structured JSON body to extract a human-readable reason
	// (e.g. CONTENT_LENGTH_EXCEEDS_THRESHOLD, CREDIT_CONSUMPTION_RATE_EXCEEDED).
	// This gives the caller a meaningful error instead of a generic HTTP status.
	code := ""
	if body != "" {
		var envelope struct {
			Type    string `json:"__type"`
			Reason  string `json:"reason"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal([]byte(body), &envelope); err == nil {
			code = strings.TrimPrefix(envelope.Type, "com.amazon.coral.service#")
			if strings.TrimSpace(envelope.Reason) != "" {
				summary = fmt.Sprintf("Kiro upstream rejected request: %s (HTTP %d)", envelope.Reason, response.StatusCode)
			} else if strings.TrimSpace(envelope.Message) != "" {
				summary = envelope.Message
			}
		}
	}
	// Diagnostic aid: dump the upstream body for 4xx/5xx so a Kiro rejection
	// can be understood. Gated behind KIRO_DEBUG_HTTP to stay silent by default.
	if response != nil && os.Getenv("KIRO_DEBUG_HTTP") != "" &&
		response.StatusCode >= http.StatusBadRequest && body != "" {
		fmt.Fprintf(os.Stderr, "[kiro-debug] HTTP %d body: %s\n", response.StatusCode, body)
	}
	return &KiroExecutionError{
		status: response.StatusCode, code: code, summary: summary, retryAfter: retryAfter,
	}
}

// kiroRetryAfterFromBody reads Kiro's JSON body field "retryAfterMilliseconds"
// (used for CREDIT_CONSUMPTION_RATE_EXCEEDED throttling) as a duration.
func kiroRetryAfterFromBody(body string) time.Duration {
	if body == "" {
		return 0
	}
	var envelope struct {
		RetryAfterMS int64 `json:"retryAfterMilliseconds"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil || envelope.RetryAfterMS <= 0 {
		return 0
	}
	return time.Duration(envelope.RetryAfterMS) * time.Millisecond
}

// kiroRetryAfterFromHeader reads the upstream Retry-After header as a whole
// number of seconds.  Kiro throttling (HTTP 429) commonly reports the exact
// window to wait; propagating it lets the gateway cooldown the credential for
// precisely the upstream-suggested delay instead of a fixed 10-minute default.
func kiroRetryAfterFromHeader(header http.Header) time.Duration {
	if header == nil {
		return 0
	}
	value := strings.TrimSpace(header.Get("Retry-After"))
	if value == "" {
		return 0
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil || seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

// kiroJSONEnvelopeError creates an error from a Kiro JSON envelope.
func kiroJSONEnvelopeError(response *http.Response, body io.Reader) error {
	raw, _ := io.ReadAll(io.LimitReader(body, kiroUpstreamBodyMax))
	var envelope struct {
		Type    string `json:"__type"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(raw, &envelope)
	code := strings.TrimPrefix(envelope.Type, "com.amazon.coral.service#")
	message := envelope.Message
	if strings.TrimSpace(message) == "" {
		message = fmt.Sprintf("Kiro upstream returned non-eventstream response (HTTP %d)", response.StatusCode)
	}
	retryAfter := kiroRetryAfterFromHeader(response.Header)
	if fromBody := kiroRetryAfterFromBody(string(raw)); fromBody > retryAfter {
		retryAfter = fromBody
	}
	return &KiroExecutionError{status: response.StatusCode, code: code, summary: message, retryAfter: retryAfter}
}

// convertKiroDoError wraps a Go error as a Kiro execution error.
func convertKiroDoError(err error) error {
	if os.Getenv("KIRO_DEBUG_HTTP") != "" {
		fmt.Fprintf(os.Stderr, "[kiro-debug] network error: %v\n", err)
	}
	var netErr interface{ Timeout() }
	if errors.As(err, &netErr) {
		return &KiroExecutionError{status: 0, code: "network", summary: "Kiro network request failed"}
	}
	return &KiroExecutionError{status: 0, code: "network", summary: err.Error()}
}

// estimateKiroTokens is a crude token estimate for the count-tokens path.
func estimateKiroTokens(raw []byte) int {
	if len(raw) == 0 {
		return 0
	}
	return (len(raw) + 3) / 4
}

// randomKiroHex generates a random hex string for Kiro IDs.
func randomKiroHex(n int) string {
	return randomHex(n)
}
