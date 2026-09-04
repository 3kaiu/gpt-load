package control

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"gpt-load/internal/channel"
	app_errors "gpt-load/internal/platform/errors"
	stateloader "gpt-load/internal/state/loader"
	"gpt-load/internal/storage/models"
)

// KiroAppendResult reports the outcome of an explicit "discover the currently
// signed-in Kiro account and append it to this group unless it already exists"
// user action. Unlike rotation/rediscover (which swap the account in place on a
// single credential row), append never overwrites an existing account row — new
// accounts are accumulated side by side so multiple Kiro accounts can coexist.
type KiroAppendResult struct {
	// Appended is true when a previously-unseen local Kiro account was written
	// into a brand-new credential row for the group.
	Appended bool `json:"appended"`
	// Reason classifies when no append happened:
	//   "no_local_account"     — the local Kiro token cache held no usable account.
	//   "already_present"      — the discovered account already exists in the group.
	//   ""                     — the append completed.
	Reason string `json:"reason,omitempty"`
	// Account is the account identity that was discovered or already present.
	Account string `json:"account,omitempty"`
	// CredentialID is the new credential row id when an append happened.
	CredentialID uint `json:"credential_id,omitempty"`
}

// AppendKiroDiscoveredCredential reacts to the user manually switching the Kiro
// desktop app to a different account and clicking "append": it re-reads the
// local token cache and, when the discovered account is not already present in
// the group, persists it as an additional credential row (accumulating multiple
// accounts) rather than replacing any existing row. It never runs interactive
// authorization.
func (s *Service) AppendKiroDiscoveredCredential(
	ctx context.Context,
	groupID uint,
) (KiroAppendResult, error) {
	if groupID == 0 {
		return KiroAppendResult{}, app_errors.ErrBadRequest
	}
	var result KiroAppendResult

	var group models.Group
	if err := s.withReadSnapshot(ctx, func(tx *gorm.DB) error {
		return tx.Take(&group, groupID).Error
	}); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return KiroAppendResult{}, app_errors.ErrResourceNotFound
		}
		return KiroAppendResult{}, app_errors.ParseDBError(err)
	}
	if normalizeGroupConnectionType(group.ConnectionType) != models.ConnectionTypeSubscription ||
		channel.ID(group.ChannelID) != channelIDKiro {
		return KiroAppendResult{}, app_errors.ErrValidation
	}

	discoverer, err := s.subscriptionDriver(channel.ID(group.ChannelID))
	if err != nil {
		return KiroAppendResult{}, app_errors.ErrInternalServer
	}
	fresh, found, err := s.discoverLocalKiroAccount(ctx, group, models.Credential{}, discoverer)
	if err != nil {
		return KiroAppendResult{}, err
	}
	if !found {
		result.Reason = "no_local_account"
		return result, nil
	}
	freshIdentity := fresh.Identity()
	if freshIdentity == "" {
		result.Reason = "no_local_account"
		return result, nil
	}
	result.Account = freshIdentity

	identityFingerprint := s.subscriptionIdentityFingerprint(channel.ID(group.ChannelID), freshIdentity)
	if identityFingerprint == "" {
		return KiroAppendResult{}, app_errors.ErrInternalServer
	}

	canonical := fresh.Canonical()
	if len(canonical) == 0 {
		return KiroAppendResult{}, app_errors.ErrInternalServer
	}
	ciphertext, err := s.encryption.Encrypt(string(canonical))
	fingerprint := s.encryption.Hash(string(canonical))
	clear(canonical)
	if err != nil {
		return KiroAppendResult{}, app_errors.ErrInternalServer
	}

	var newID uint
	err = s.writeCredentialConfig(ctx, group.ID, 0, func(tx *gorm.DB) error {
		// Check by identity fingerprint (primary dedup — same account).
		var existing int64
		if err := tx.Model(&models.Credential{}).
			Where("group_id = ? AND identity_fingerprint = ?", group.ID, identityFingerprint).
			Count(&existing).Error; err != nil {
			return app_errors.ParseDBError(err)
		}
		if existing > 0 {
			result.Reason = "already_present"
			return nil
		}
		// Also check by credential fingerprint (canonical data hash) so that
		// the same token under a legacy identity format is still recognized.
		var byData int64
		if err := tx.Model(&models.Credential{}).
			Where("group_id = ? AND fingerprint = ?", group.ID, fingerprint).
			Count(&byData).Error; err != nil {
			return app_errors.ParseDBError(err)
		}
		if byData > 0 {
			result.Reason = "already_present"
			return nil
		}
		row := models.Credential{
			GroupID: group.ID, Data: ciphertext, Fingerprint: fingerprint,
			IdentityFingerprint: identityFingerprint, SecretVersion: 1,
			AuthState: models.CredentialAuthStateReady, Status: models.CredentialStatusActive,
			CreatedAtMS: s.now().UnixMilli(), UpdatedAtMS: s.now().UnixMilli(),
		}
		if err := tx.Create(&row).Error; err != nil {
			if app_errors.ParseDBError(err) == app_errors.ErrDuplicateResource {
				result.Reason = "already_present"
				return nil
			}
			return app_errors.ParseDBError(err)
		}
		newID = row.ID
		result.Appended = true
		result.CredentialID = newID
		return nil
	}, func() error {
		if newID == 0 {
			return nil
		}
		entries, err := stateloader.BuildGroupCredentialEntriesWithProxy(ctx, s.db, group.ID, s.encryption)
		if err != nil {
			return err
		}
		if _, err := s.reconcileRegistryGroup(group.ID, entries); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return KiroAppendResult{}, err
	}

	if result.Appended {
		s.rotationMonitor.logger.WithField("event", "kiro.append.added").
			WithField("group_id", group.ID).
			WithField("credential_id", newID).
			WithField("account", result.Account).
			Info("Kiro account appended as a new credential")
	} else {
		s.rotationMonitor.logger.WithField("event", "kiro.append."+result.Reason).
			WithField("group_id", group.ID).
			WithField("account", result.Account).
			WithField("credential_id", newID).
			Info("Kiro append did not add a credential")
	}
	return result, nil
}
