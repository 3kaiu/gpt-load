package embedded

import (
	"context"
	"net/http"
	"strings"
)

// KiroUsageMeter is one credit/resource meter observed on the account.
type KiroUsageMeter struct {
	DisplayName        string
	Unit               string
	CurrentUsage       float64
	UsageLimit         float64
	UsageLimitExplicit bool
	PercentageUsed     float64
	ResetDate          string
}

// KiroUsageObservation aggregates the credit/resource meters for one account.
type KiroUsageObservation struct {
	Meters []KiroUsageMeter
}

// KiroAccountObservation is GPT-Load's normalized, projection-safe account
// observation for a Kiro subscription. It is deliberately sparse and free of
// arbitrary billing assumptions: Kiro exposes quota only through the local
// desktop mirror, so that is what this observes.
type KiroAccountObservation struct {
	Usage KiroUsageObservation
	// ModelID is the account's last selected model, when readable locally.
	ModelID string
	// Header is preserved for parity with other providers; it is unused by Kiro.
	Header http.Header
	// AccountObserved reports whether the local account mirror was reachable.
	AccountObserved bool
	// AccountQuotaObserved reports whether at least one quota meter was found.
	AccountQuotaObserved bool
	// CreditQuotaObserved reports whether the primary credit meter was found.
	CreditQuotaObserved bool
	// LoadedViaFreecode reports whether the observation came from the local
	// desktop mirror that freecode manages (self-exploration).
	LoadedViaFreecode bool
	IncompleteSources []string
}

// ObserveKiroAccount observes the Kiro account managed by the credential. It
// prefers the live remote quota plane (GetUsageLimits on the AWS CodeWhisperer
// Runtime), which reflects current usage without depending on a fresh local
// desktop mirror, and falls back to the local desktop mirror when the remote
// plane is unavailable. Identity is bound to the credential being monitored so
// one account's exhaustion never triggers another's rotation.
func ObserveKiroAccount(ctx context.Context, credential KiroCredential, options KiroOptions) (KiroAccountObservation, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	normalizeKiroCredential(&credential)
	observation := KiroAccountObservation{
		Header:            http.Header{},
		AccountObserved:   true,
		IncompleteSources: []string{},
	}
	// Remote usage is the preferred, primary source: it reflects live usage
	// even when the local desktop app has not refreshed its mirror. A stored
	// bearer token can expire on disk (short-lived IdC/SSO access tokens), which
	// would otherwise make the remote call fail with 401/403 and silently fall
	// back to the local mirror (often reporting stale/zero usage). Refresh the
	// account's own token first so the remote plane is reached with a fresh
	// access token — this keeps every stored account self-contained by using its
	// own persisted OIDC/social client rather than the currently active desktop
	// login.
	credential = refreshKiroCredentialIfExpired(ctx, credential, options)
	remote, remoteErr := DiscoverKiroUsageLimits(ctx, credential, options)
	if remoteErr == nil && remote != nil && len(remote.Breaks) > 0 {
		observation.ModelID = strings.TrimSpace(remote.ModelID)
		meters := make([]KiroUsageMeter, 0, len(remote.Breaks))
		for _, brk := range remote.Breaks {
			meters = append(meters, kiroMeterFromBreak(brk))
		}
		observation.Usage.Meters = meters
		observation.AccountObserved = true
		observation.AccountQuotaObserved = len(meters) > 0
		observation.CreditQuotaObserved = hasKiroCreditMeter(meters)
		return observation, nil
	}
	if remoteErr != nil {
		observation.IncompleteSources = append(observation.IncompleteSources, "remote_usage")
	}
	// Fall back to the local desktop mirror for quota self-exploration.
	discovery, err := DiscoverKiroLocal()
	if err != nil {
		observation.IncompleteSources = append(observation.IncompleteSources, "local_mirror")
		return observation, ErrKiroAccountObservationUnavailable
	}
	observation.AccountObserved = discovery.TokenFound || discovery.Usage != nil
	observation.LoadedViaFreecode = true
	identityMismatch := strings.TrimSpace(credential.AccountID) != "" &&
		discovery.AccountID != "" &&
		!strings.EqualFold(strings.TrimSpace(discovery.AccountID), strings.TrimSpace(credential.AccountID))
	if identityMismatch {
		observation.IncompleteSources = append(observation.IncompleteSources, "identity_mismatch")
	} else if discovery.Usage != nil {
		observation.ModelID = strings.TrimSpace(discovery.Usage.ModelID)
		meters := make([]KiroUsageMeter, 0, len(discovery.Usage.Breaks))
		for _, brk := range discovery.Usage.Breaks {
			meters = append(meters, kiroMeterFromBreak(brk))
		}
		observation.Usage.Meters = meters
		observation.AccountQuotaObserved = len(meters) > 0
		observation.CreditQuotaObserved = hasKiroCreditMeter(meters)
	}
	return observation, nil
}

// kiroMeterFromBreak converts a KiroUsageBreak into a normalized usage meter.
func kiroMeterFromBreak(brk KiroUsageBreak) KiroUsageMeter {
	return KiroUsageMeter{
		DisplayName: brk.DisplayName, Unit: brk.Unit,
		CurrentUsage: brk.CurrentUsage, UsageLimit: brk.UsageLimit,
		UsageLimitExplicit: brk.UsageLimitExplicit, PercentageUsed: brk.PercentageUsed,
		ResetDate: brk.ResetDate,
	}
}

// refreshKiroCredentialIfExpired refreshes an OAuth Kiro credential when its
// access token is missing, already expired, or within the refresh lead time of
// expiring. It uses the account's own persisted client (standalone OIDC/social
// refresh) so the refreshed token is bound to this stored account, independent
// of whichever login is currently active on the desktop. Refresh failures are
// intentionally non-fatal: the caller falls back to the existing token (and the
// observe path's local-mirror fallback still applies).
func refreshKiroCredentialIfExpired(ctx context.Context, credential KiroCredential, options KiroOptions) KiroCredential {
	kind := KiroAuthKind(credential.AuthKind)
	if kind != KiroAuthSocial && kind != KiroAuthOIDC {
		return credential
	}
	if strings.TrimSpace(credential.RefreshToken) == "" {
		return credential
	}
	if kind == KiroAuthOIDC &&
		(strings.TrimSpace(credential.ClientID) == "" || strings.TrimSpace(credential.ClientSecret) == "") {
		// An OIDC credential without its own client registration cannot refresh
		// standalone; leave the stored (possibly stale) token as-is.
		return credential
	}
	if expiration, ok := KiroCredentialExpiresAt(credential); ok {
		if expiration.After(kiroNow(options).Add(kiroTokenRefreshLeadTime)) {
			return credential
		}
	}
	refreshed, err := RefreshKiroCredentialOnce(ctx, credential, options)
	if err != nil {
		return credential
	}
	return refreshed
}

// hasKiroCreditMeter checks if the Kiro usage state has a credit meter entry.
func hasKiroCreditMeter(meters []KiroUsageMeter) bool {
	for _, meter := range meters {
		kind := strings.ToLower(strings.TrimSpace(meter.Unit))
		if kind == "invocations" || kind == "credits" {
			return true
		}
	}
	return false
}
