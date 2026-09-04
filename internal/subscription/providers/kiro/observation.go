package kiro

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	providerobservation "gpt-load/internal/subscription/providers/observation"
)

const (
	quotaScopeAccount = "account"
	quotaScopeCredits = "credits"
)

type UsageMeter struct {
	DisplayName        string
	Unit               string
	CurrentUsage       float64
	UsageLimit         float64
	UsageLimitExplicit bool
	PercentageUsed     float64
	ResetDate          string
}

type UsageObservation struct {
	Meters []UsageMeter
}

type AccountObservation struct {
	Usage                UsageObservation
	ModelID              string
	Header               http.Header
	AccountObserved      bool
	AccountQuotaObserved bool
	CreditQuotaObserved  bool
	LoadedViaFreecode    bool
	IncompleteSources    []string
}

// NormalizeObservation normalizes raw Kiro observation data into structured format.
func NormalizeObservation(email string, observation AccountObservation) ([]byte, error) {
	result := providerobservation.Snapshot{
		Plan:         kiroPlan(observation),
		Account:      &providerobservation.AccountSummary{Email: strings.TrimSpace(email)},
		QuotaWindows: make([]providerobservation.QuotaWindow, 0, len(observation.Usage.Meters)),
	}
	primarySet := false
	for index, meter := range observation.Usage.Meters {
		window, err := kiroMeterWindow(index, meter)
		if err != nil {
			return nil, err
		}
		if window.Scope == quotaScopeAccount && !primarySet {
			window.IsPrimary = true
			primarySet = true
		}
		result.QuotaWindows = append(result.QuotaWindows, window)
	}
	return json.Marshal(result)
}

// kiroPlan maps Kiro plan name to normalized plan identifier.
func kiroPlan(observation AccountObservation) providerobservation.PlanSummary {
	if len(observation.Usage.Meters) == 0 {
		return providerobservation.PlanSummary{}
	}
	first := observation.Usage.Meters[0]
	if first.UsageLimit > 0 {
		return providerobservation.PlanSummary{Name: "Kiro Pro", Level: providerobservation.PlanLevelStandard}
	}
	return providerobservation.PlanSummary{Name: "Free", Level: providerobservation.PlanLevelFree}
}

// kiroMeterWindow determines the quota scope for a given meter and window type.
func kiroMeterWindow(index int, meter UsageMeter) (providerobservation.QuotaWindow, error) {
	id := providerobservation.SafeID(meter.DisplayName)
	if id == "" {
		id = fmt.Sprintf("meter-%d", index+1)
	}
	unit := strings.ToLower(strings.TrimSpace(meter.Unit))
	scope := quotaScopeAccount
	if unit == "invocations" || unit == "credits" {
		scope = quotaScopeCredits
	}
	window := providerobservation.QuotaWindow{
		ID: id, Label: providerobservation.DisplayName(meter.DisplayName), Scope: scope,
		Unit: unit, State: "unknown",
	}
	resetAt := kiroResetAt(meter.ResetDate)
	switch unit {
	case "invocations", "credits":
		// Surface the real per-account credit figures (e.g. "9.97 used / 50")
		// instead of folding them into a percentage against an implicit 100
		// limit. Keeping the raw Used/Limit lets the UI show the exact numbers
		// the Kiro desktop app shows. Utilization is intentionally omitted for
		// this meter so the account-card prefers the raw used/remaining labels;
		// rotation still works because kiroPrimaryQuotaUsage falls back to
		// Used/Limit when Utilization is absent.
		window.LabelKey = providerobservation.QuotaLabelIncludedUsage
		window.Unit = "credits"
		used := meter.CurrentUsage
		window.Used = &used
		limit := meter.UsageLimit
		if limit <= 0 {
			limit = 100.0
			window.Used = &used
		}
		window.Limit = &limit
		remaining := limit - used
		window.Remaining = &remaining
		window.State = "available"
		if remaining <= 0 {
			window.State = "exhausted"
		}
	default:
		if meter.UsageLimitExplicit {
			used := meter.CurrentUsage
			limit := meter.UsageLimit
			window.Used = &used
			window.Limit = &limit
			remaining := math.Max(0, limit-used)
			window.Remaining = &remaining
			if limit > 0 {
				utilization := math.Min(1, used/limit)
				window.Utilization = &utilization
			}
			window.State = "available"
			if remaining <= 0 {
				window.State = "exhausted"
			}
		}
	}
	if resetAt != nil {
		window.ResetAtMS = resetAt
	}
	return window, nil
}

// kiroResetAt computes the reset time for a Kiro quota window.
func kiroResetAt(raw string) *int64 {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil
	}
	ms := parsed.UnixMilli()
	return &ms
}
