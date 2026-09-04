package kiro

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	cpaembedded "github.com/router-for-me/CLIProxyAPI/v7/gptload-embedded/embedded"

	"gpt-load/internal/channel/modules"
	"gpt-load/internal/channel/spec"
	subscriptionruntime "gpt-load/internal/subscription/runtime"
)

type kiroDriver struct{}

// newKiroDriver creates a new Kiro driver.
func newKiroDriver() *kiroDriver { return &kiroDriver{} }

// Implementations returns all Kiro subscription driver implementations.
func Implementations() subscriptionruntime.Implementations {
	driver := newKiroDriver()
	return subscriptionruntime.Implementations{
		Drivers:           []subscriptionruntime.Driver{driver},
		ModelDiscoveries:  []subscriptionruntime.ModelDiscovery{kiroModelDiscovery{driver}},
		QuotaObservations: []subscriptionruntime.QuotaObservation{kiroQuotaObservation{driver}},
	}
}

// ID returns the Kiro driver identifier.
func (*kiroDriver) ID() spec.SubscriptionDriverID { return modules.KiroSubscriptionDriver }

// Parse parses a Kiro credential from raw JSON.
func (*kiroDriver) Parse(raw []byte) (subscriptionruntime.Credential, error) {
	value, err := ParseCredentialJSON(raw)
	if err != nil {
		return subscriptionruntime.Credential{}, err
	}
	canonical, err := MarshalCredential(value)
	if err != nil {
		return subscriptionruntime.Credential{}, err
	}
	return kiroRuntimeCredential(value, canonical), nil
}

// Refresh refreshes a Kiro credential.
func (d *kiroDriver) Refresh(ctx context.Context, current subscriptionruntime.Credential) (subscriptionruntime.Credential, error) {
	// A self-discovered Kiro account is an AWS SSO / IdC bearer whose token the
	// Kiro desktop app owns and keeps fresh in its token cache. Kiro's social
	// refreshToken endpoint does not apply to it, so prefer re-reading the live
	// on-disk token cache when the account identity matches. Only fall back to
	// the provider refresh when no matching local token is present.
	value, err := ParseCredentialJSON(current.Canonical())
	if err != nil {
		return subscriptionruntime.Credential{}, err
	}
	if local, found, localErr := DiscoverLocalCredential(ctx); localErr == nil && found {
		if strings.TrimSpace(local.AccountID) != "" && local.AccountID == value.AccountID {
			canonical, marshalErr := MarshalCredential(local)
			if marshalErr != nil {
				return subscriptionruntime.Credential{}, marshalErr
			}
			return kiroRuntimeCredential(local, canonical), nil
		}
	}
	refreshed, err := RefreshCredentialOnce(ctx, value)
	if err != nil {
		return subscriptionruntime.Credential{}, err
	}
	canonical, err := MarshalCredential(refreshed)
	if err != nil {
		return subscriptionruntime.Credential{}, err
	}
	return kiroRuntimeCredential(refreshed, canonical), nil
}

// ClassifyRefreshFailure classifies a Kiro refresh failure.
func (*kiroDriver) ClassifyRefreshFailure(err error) subscriptionruntime.RefreshFailureDecision {
	if errors.Is(err, ErrCredentialIdentityChanged) {
		return subscriptionruntime.RefreshFailureDecision{Kind: subscriptionruntime.RefreshFailureIdentityChanged}
	}
	var tokenErr *TokenEndpointError
	if errors.As(err, &tokenErr) {
		return kiroTokenEndpointDecision(tokenErr.StatusCode, tokenErr.Code, tokenErr.RetryAfter)
	}
	return subscriptionruntime.RefreshFailureDecision{Kind: subscriptionruntime.RefreshFailureOutcomeUnknown}
}

// kiroTokenEndpointDecision classifies a Kiro OAuth token-endpoint failure.
//
// Retryable statuses stay retryable; explicit rejection OAuth codes (and any
// client-error auth status) demand re-authorization; only genuinely ambiguous
// errors are reported as outcome_unknown. In particular a 400/401/403 with an
// empty or unrecognized code is a rejection of the stored refresh token /
// client registration, not an unknowable failure — leaving it permanent
// outcome_unknown would brick a credential that could instead recover via
// self-healing on its next refresh.
func kiroTokenEndpointDecision(statusCode int, oauthCode string, retryAfter time.Duration) subscriptionruntime.RefreshFailureDecision {
	decision := subscriptionruntime.RefreshFailureDecision{
		Kind: subscriptionruntime.RefreshFailureOutcomeUnknown, StatusCode: statusCode,
		OAuthCode: strings.TrimSpace(oauthCode), RetryAfter: retryAfter,
	}
	if subscriptionruntime.TokenEndpointFailureRetryable(statusCode, oauthCode) {
		decision.Kind = subscriptionruntime.RefreshFailureRetryable
		return decision
	}
	if IsDefinitiveRefreshRejection(oauthCode) || kiroRefreshClientError(statusCode) {
		decision.Kind = subscriptionruntime.RefreshFailureReauthorizationRequired
	}
	return decision
}

// kiroRefreshClientError reports whether the HTTP status reflects a definitive
// rejection of the presented refresh token / client credentials — always a
// re-authorization condition, never a transient or unknowable failure.
func kiroRefreshClientError(statusCode int) bool {
	switch statusCode {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
		return true
	default:
		return false
	}
}

// BeginDeviceAuthorization starts Kiro device authorization flow.
func (*kiroDriver) BeginDeviceAuthorization(ctx context.Context) (subscriptionruntime.DeviceAuthorization, error) {
	value, err := BeginDeviceAuthorization(ctx)
	if err != nil {
		return subscriptionruntime.DeviceAuthorization{}, err
	}
	state, err := marshalDeviceState(value.State)
	if err != nil {
		return subscriptionruntime.DeviceAuthorization{}, err
	}
	return subscriptionruntime.DeviceAuthorization{
		VerificationURL: value.VerificationURL, UserCode: value.UserCode, DriverState: state,
		ExpiresAt: value.ExpiresAt, PollInterval: value.PollInterval,
	}, nil
}

// PollDeviceAuthorization polls for Kiro device authorization completion.
func (*kiroDriver) PollDeviceAuthorization(ctx context.Context, raw []byte) (subscriptionruntime.DeviceAuthorizationPoll, error) {
	state, err := unmarshalDeviceState(raw)
	if err != nil {
		return subscriptionruntime.DeviceAuthorizationPoll{}, err
	}
	value, err := PollDeviceAuthorizationOnce(ctx, state)
	if err != nil {
		return subscriptionruntime.DeviceAuthorizationPoll{}, err
	}
	result := subscriptionruntime.DeviceAuthorizationPoll{PollInterval: value.PollInterval}
	switch value.Status {
	case DeviceAuthorizationPending:
		result.Status = subscriptionruntime.DeviceAuthorizationPending
		result.DriverState, err = marshalDeviceState(value.State)
	case DeviceAuthorizationAuthorized:
		result.Status = subscriptionruntime.DeviceAuthorizationAuthorized
		canonical, marshalErr := MarshalCredential(value.Credential)
		if marshalErr != nil {
			return subscriptionruntime.DeviceAuthorizationPoll{}, marshalErr
		}
		result.Credential = kiroRuntimeCredential(value.Credential, canonical)
	case DeviceAuthorizationDenied:
		result.Status = subscriptionruntime.DeviceAuthorizationDenied
	case DeviceAuthorizationExpired:
		result.Status = subscriptionruntime.DeviceAuthorizationExpired
	default:
		return subscriptionruntime.DeviceAuthorizationPoll{}, errors.New("unknown Kiro device authorization status")
	}
	return result, err
}

// ImportCredential imports a Kiro credential from external source.
func (*kiroDriver) ImportCredential(ctx context.Context, raw []byte) (subscriptionruntime.Credential, error) {
	value, err := ImportCredential(ctx, raw)
	if err != nil {
		return subscriptionruntime.Credential{}, err
	}
	canonical, err := MarshalCredential(value)
	if err != nil {
		return subscriptionruntime.Credential{}, err
	}
	return kiroRuntimeCredential(value, canonical), nil
}

// DiscoverLocalCredential discovers a locally logged-in Kiro account.
func (*kiroDriver) DiscoverLocalCredential(ctx context.Context) (subscriptionruntime.Credential, bool, error) {
	value, found, err := DiscoverLocalCredential(ctx)
	if err != nil || !found {
		return subscriptionruntime.Credential{}, false, err
	}
	canonical, err := MarshalCredential(value)
	if err != nil {
		return subscriptionruntime.Credential{}, false, err
	}
	return kiroRuntimeCredential(value, canonical), true, nil
}

type kiroModelDiscovery struct{ *kiroDriver }

// ID returns the Kiro model discovery identifier.
func (kiroModelDiscovery) ID() spec.UtilityID { return modules.KiroModelDiscovery }

// DiscoverModels discovers available Kiro models.
func (*kiroDriver) DiscoverModels(ctx context.Context, credential subscriptionruntime.Credential) ([]string, error) {
	value, err := ParseCredentialJSON(credential.Canonical())
	if err != nil {
		return nil, err
	}
	models, err := ListModels(ctx, value)
	if err != nil {
		if errors.Is(err, ErrModelDiscoveryUnavailable) {
			// Self-discovered (no profileArn) and API-key accounts cannot resolve
			// Kiro's management plane, so live discovery is locally unavailable.
			// This is not a failure: fall back to the static Kiro model catalog so
			// the channel still exposes its known models instead of a 502.
			return cpaembedded.MergeModelCatalog(cpaembedded.ProviderKiro, nil), nil
		}
		var upstream *UpstreamHTTPError
		if errors.As(err, &upstream) {
			return nil, &subscriptionruntime.UpstreamHTTPError{StatusCode: upstream.StatusCode}
		}
		return nil, err
	}
	return cpaembedded.MergeModelCatalog(cpaembedded.ProviderKiro, models), nil
}

// Observe observes Kiro account quota and usage.
func (*kiroDriver) Observe(ctx context.Context, credential subscriptionruntime.Credential) (subscriptionruntime.Observation, error) {
	value, err := ParseCredentialJSON(credential.Canonical())
	if err != nil {
		return subscriptionruntime.Observation{}, err
	}
	observed, err := ObserveAccount(ctx, value)
	if err != nil {
		var upstream *UpstreamHTTPError
		if errors.As(err, &upstream) {
			return subscriptionruntime.Observation{}, &subscriptionruntime.UpstreamHTTPError{StatusCode: upstream.StatusCode}
		}
		if errors.Is(err, ErrAccountObservationPayloadInvalid) {
			return subscriptionruntime.Observation{}, subscriptionruntime.ErrObservationPayloadInvalid
		}
		if errors.Is(err, ErrAccountObservationUnavailable) {
			return subscriptionruntime.Observation{}, subscriptionruntime.ErrObservationUnavailable
		}
		return subscriptionruntime.Observation{}, err
	}
	normalized, err := NormalizeObservation(value.Email, observed)
	if err != nil {
		return subscriptionruntime.Observation{}, fmt.Errorf("%w: %v", subscriptionruntime.ErrObservationPayloadInvalid, err)
	}
	observedScopes := kiroObservedQuotaScopes(observed)
	quotaObserved := len(observedScopes) > 0
	return subscriptionruntime.Observation{
		Payload: normalized, Header: observed.Header.Clone(), Partial: len(observed.IncompleteSources) > 0,
		AccountObserved: observed.AccountObserved, QuotaObserved: quotaObserved,
		ObservedQuotaScopes: observedScopes,
	}, nil
}

// kiroObservedQuotaScopes returns the quota scopes to observe for Kiro.
func kiroObservedQuotaScopes(observed AccountObservation) []string {
	scopes := make([]string, 0, 2)
	if observed.AccountQuotaObserved {
		scopes = append(scopes, quotaScopeAccount)
	}
	if observed.CreditQuotaObserved {
		scopes = append(scopes, quotaScopeCredits)
	}
	return scopes
}

type kiroQuotaObservation struct{ *kiroDriver }

// ID returns the Kiro quota observation identifier.
func (kiroQuotaObservation) ID() spec.UtilityID { return modules.KiroQuotaObservation }

// kiroRuntimeCredential converts a Kiro credential to runtime format.
func kiroRuntimeCredential(value Credential, canonical []byte) subscriptionruntime.Credential {
	expiresAt, expires := CredentialExpiresAt(value)
	account := subscriptionruntime.Account{
		Email: strings.TrimSpace(value.Email), ExpiresAt: expiresAt, ExpiresAtKnown: expires,
	}
	return subscriptionruntime.NewCredential(
		canonical, strings.TrimSpace(value.AccountID), account, expiresAt, expires, value.SecretValues(),
	)
}

// StoredAccountID parses the Kiro credential canonical blob via the CPA bridge
// and returns the AccountID. The control layer calls this through the
// subscriptionruntime.AccountIdentifier interface so it never needs to import
// the CPA bridge directly.
func (*kiroDriver) StoredAccountID(canonical []byte) string {
	value, err := ParseCredentialJSON(canonical)
	if err != nil || value.AccountID == "" {
		return ""
	}
	return value.AccountID
}

var _ subscriptionruntime.AccountIdentifier = (*kiroDriver)(nil)
var _ subscriptionruntime.DeviceAuthorizationDriver = (*kiroDriver)(nil)
var _ subscriptionruntime.CredentialFileImporter = (*kiroDriver)(nil)
var _ subscriptionruntime.SelfDiscoveryDriver = (*kiroDriver)(nil)
