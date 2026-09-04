package embedded

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	kiroGetUsageLimitsTarget = "AmazonCodeWhispererService.GetUsageLimits"
	kiroGetUsageLimitsOrigin = "AI_EDITOR"
	maxKiroUsageBytes        = 512 * 1024
)

// KiroCodewhispererURL builds the AWS CodeWhisperer Runtime host that serves
// the GetUsageLimits operation for a given region. This is the remote quota
// plane (codewhisperer.{region}.amazonaws.com), distinct from the kiro.dev
// runtime/management planes. It is intentionally best-effort: the operation is
// not part of AWS's public, documented API surface and may change.
func KiroCodewhispererURL(region string) (string, error) {
	region, err := validateKiroRegion(region)
	if err != nil {
		return "", err
	}
	return "https://codewhisperer." + region + ".amazonaws.com/", nil
}

// kiroUsageLimitsResponse is the parsed shape of the GetUsageLimits response.
type kiroUsageLimitsResponse struct {
	NextDateReset    *float64             `json:"nextDateReset"`
	UsageBreakdownList []kiroUsageBreakJSONRemote `json:"usageBreakdownList"`
}

// kiroUsageBreakJSONRemote is one quota breakdown entry in the remote response.
type kiroUsageBreakJSONRemote struct {
	Currency                   string  `json:"currency"`
	CurrentUsage               float64 `json:"currentUsage"`
	CurrentUsageWithPrecision  float64 `json:"currentUsageWithPrecision"`
	DisplayName                string  `json:"displayName"`
	DisplayNamePlural          string  `json:"displayNamePlural"`
	PercentageUsed             float64 `json:"percentageUsed"`
	ResourceType               string  `json:"resourceType"`
	Unit                       string  `json:"unit"`
	UsageLimit                 float64 `json:"usageLimit"`
	UsageLimitWithPrecision    float64 `json:"usageLimitWithPrecision"`
	NextDateReset              *float64 `json:"nextDateReset"`
}

// DiscoverKiroUsageLimits queries the AWS CodeWhisperer Runtime GetUsageLimits
// operation for the account's live credit/quota state. It reports meters in
// the same KiroUsageDiscovery shape that the local desktop mirror uses, so
// observers can consume remote and local data identically. OAuth (social /
// OIDC) credentials carry the bearer access token the operation requires;
// API-key credentials cannot authenticate against this plane and report
// observation unavailable.
func DiscoverKiroUsageLimits(ctx context.Context, credential KiroCredential, options KiroOptions) (*KiroUsageDiscovery, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	normalizeKiroCredential(&credential)
	if err := validateKiroCredentialWithOptions(credential, options); err != nil {
		return nil, err
	}
	if strings.TrimSpace(credential.AccessToken) == "" {
		return nil, ErrKiroAccountObservationUnavailable
	}
	host := strings.TrimSpace(options.CodewhispererHost)
	if host == "" {
		var err error
		host, err = KiroCodewhispererURL(credential.Region)
		if err != nil {
			return nil, err
		}
	}
	payload, err := json.Marshal(map[string]any{
		"profileArn": strings.TrimSpace(credential.ProfileARN),
		"origin":     kiroGetUsageLimitsOrigin,
	})
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, host, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-amz-json-1.0")
	request.Header.Set("Accept", "*/*")
	request.Header.Set("X-Amz-Target", kiroGetUsageLimitsTarget)
	request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(credential.AccessToken))
	request.Header.Set("User-Agent", kiroUserAgent)
	request.Header.Set("x-amz-user-agent", kiroAMZUserAgent)
	request.Header.Set("amz-sdk-invocation-id", randomKiroHex(16))
	response, err := kiroHTTPClient(options).Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxKiroUsageBytes+1))
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	if len(raw) > maxKiroUsageBytes {
		return nil, fmt.Errorf("Kiro usage response is too large")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, kiroHTTPErrorFromResponse(response)
	}
	var result kiroUsageLimitsResponse
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("decode Kiro usage: %w", err)
	}
	discovery := &KiroUsageDiscovery{}
	for _, entry := range result.UsageBreakdownList {
		limit := firstPositiveKiro(entry.UsageLimitWithPrecision, entry.UsageLimit)
		used := firstPositiveKiro(entry.CurrentUsageWithPrecision, entry.CurrentUsage)
		discovery.Breaks = append(discovery.Breaks, KiroUsageBreak{
			DisplayName:        firstNonEmpty(entry.DisplayName, entry.DisplayNamePlural),
			Type:               strings.TrimSpace(entry.ResourceType),
			Unit:               strings.TrimSpace(entry.Unit),
			CurrentUsage:       used,
			UsageLimit:         limit,
			UsageLimitExplicit: limit > 0,
			PercentageUsed:     entry.PercentageUsed,
			ResetDate:          kiroRemoteResetDate(entry.NextDateReset),
			CurrencyCode:       strings.TrimSpace(entry.Currency),
		})
	}
	return discovery, nil
}

// kiroRemoteResetDate formats a reset date epoch (seconds) as an RFC3339
// string. It returns "" when the value is absent or invalid.
func kiroRemoteResetDate(epoch *float64) string {
	if epoch == nil || *epoch <= 0 {
		return ""
	}
	return time.Unix(int64(*epoch), 0).UTC().Format(time.RFC3339)
}

// firstPositiveKiro returns the first positive value among the candidates.
func firstPositiveKiro(values ...float64) float64 {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}
