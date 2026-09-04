package embedded

import "testing"

// TestKiroOIDCFromMatchedLocalCredential verifies the identity-guarded upgrade
// of a stored social credential to OIDC using the local IdC client registration.
// The pairing must only happen when the local active account identity matches
// the stored account, so a foreign token is never paired with a mismatched
// client.
func TestKiroOIDCFromMatchedLocalCredential(t *testing.T) {
	stored := KiroCredential{
		Type: ProviderKiro, AuthKind: string(KiroAuthSocial),
		AccountID: "rt:aaa", RefreshToken: "rt-stored",
	}
	matchingLocal := KiroCredential{
		Type: ProviderKiro, AuthKind: string(KiroAuthOIDC),
		AccountID: "rt:aaa", ClientID: "cid", ClientSecret: "csecret",
	}
	otherLocal := KiroCredential{
		Type: ProviderKiro, AuthKind: string(KiroAuthOIDC),
		AccountID: "rt:bbb", ClientID: "cid2", ClientSecret: "csecret2",
	}
	socialLocal := KiroCredential{
		Type: ProviderKiro, AuthKind: string(KiroAuthSocial),
		AccountID: "rt:aaa", ClientID: "cid", ClientSecret: "csecret",
	}

	t.Run("matching local IdC login upgrades to OIDC", func(t *testing.T) {
		got, ok := kiroOIDCFromMatchedLocalCredential(stored, matchingLocal)
		if !ok {
			t.Fatal("expected matched local login to upgrade")
		}
		if got.AuthKind != string(KiroAuthOIDC) {
			t.Fatalf("auth kind = %q, want %q", got.AuthKind, KiroAuthOIDC)
		}
		if got.ClientID != "cid" || got.ClientSecret != "csecret" {
			t.Fatalf("client creds = %q/%q, want cid/csecret", got.ClientID, got.ClientSecret)
		}
		if got.RefreshToken != "rt-stored" {
			t.Fatalf("refresh token was replaced: %q", got.RefreshToken)
		}
	})

	t.Run("mismatched local account is rejected", func(t *testing.T) {
		if _, ok := kiroOIDCFromMatchedLocalCredential(stored, otherLocal); ok {
			t.Fatal("foreign local account must not pair with the stored token")
		}
	})

	t.Run("social local login is rejected", func(t *testing.T) {
		if _, ok := kiroOIDCFromMatchedLocalCredential(stored, socialLocal); ok {
			t.Fatal("a social local login cannot back an OIDC upgrade")
		}
	})

	t.Run("empty stored account id is rejected", func(t *testing.T) {
		empty := stored
		empty.AccountID = ""
		if _, ok := kiroOIDCFromMatchedLocalCredential(empty, matchingLocal); ok {
			t.Fatal("empty stored account id must not upgrade")
		}
	})

	t.Run("matching local without client creds is rejected", func(t *testing.T) {
		noCreds := matchingLocal
		noCreds.ClientID = ""
		if _, ok := kiroOIDCFromMatchedLocalCredential(stored, noCreds); ok {
			t.Fatal("local login without a client registration must not upgrade")
		}
	})
}

// TestKiroOIDCPersisted verifies a stored social credential WITH its own
// persisted client registration upgrades to OIDC standalone — no dependency on
// which login is currently active on the desktop. This is what lets a stored
// account refresh as an independent, long-lived credential.
func TestKiroOIDCPersisted(t *testing.T) {
	stored := KiroCredential{
		Type: ProviderKiro, AuthKind: string(KiroAuthSocial),
		AccountID: "rt:aaa", RefreshToken: "rt-stored",
		ClientID: "cid", ClientSecret: "csecret",
	}

	t.Run("stored credential with its own client upgrades standalone", func(t *testing.T) {
		got, ok := kiroOIDCPersisted(stored)
		if !ok {
			t.Fatal("expected stored credential with client to upgrade")
		}
		if got.AuthKind != string(KiroAuthOIDC) {
			t.Fatalf("auth kind = %q, want %q", got.AuthKind, KiroAuthOIDC)
		}
		if got.ClientID != "cid" || got.ClientSecret != "csecret" {
			t.Fatalf("client creds = %q/%q, want cid/csecret", got.ClientID, got.ClientSecret)
		}
		if got.RefreshToken != "rt-stored" {
			t.Fatalf("refresh token was replaced: %q", got.RefreshToken)
		}
	})

	t.Run("stored credential without client is rejected", func(t *testing.T) {
		noClient := stored
		noClient.ClientID = ""
		if _, ok := kiroOIDCPersisted(noClient); ok {
			t.Fatal("stored credential without a client must not upgrade standalone")
		}
	})

	t.Run("stored credential without refresh token is rejected", func(t *testing.T) {
		noRefresh := stored
		noRefresh.RefreshToken = ""
		if _, ok := kiroOIDCPersisted(noRefresh); ok {
			t.Fatal("stored credential without a refresh token must not upgrade")
		}
	})
}

// TestKiroOIDCUpgrade verifies the fallback priority: the stored credential's
// OWN persisted client is preferred over identity-matched local discovery, so
// an inactive stored account that already carries its client can still refresh.
func TestKiroOIDCUpgrade(t *testing.T) {
	withClient := KiroCredential{
		Type: ProviderKiro, AuthKind: string(KiroAuthSocial),
		AccountID: "rt:aaa", RefreshToken: "rt-stored",
		ClientID: "cid", ClientSecret: "csecret",
	}
	withoutClient := KiroCredential{
		Type: ProviderKiro, AuthKind: string(KiroAuthSocial),
		AccountID: "rt:bbb", RefreshToken: "rt-b",
	}

	t.Run("prefers stored credential's own client", func(t *testing.T) {
		got, ok := kiroOIDCUpgrade(withClient)
		if !ok {
			t.Fatal("expected upgrade for stored credential with client")
		}
		if got.AuthKind != string(KiroAuthOIDC) {
			t.Fatalf("auth kind = %q, want %q", got.AuthKind, KiroAuthOIDC)
		}
		// Should use the stored client, not depend on local discovery result.
		if got.ClientID != "cid" {
			t.Fatalf("client id = %q, want stored cid", got.ClientID)
		}
	})

	t.Run("without own client delegates to identity-matched local", func(t *testing.T) {
		_ = withoutClient
		// kiroOIDCFromMatchedLocal reads the real local cache; we can only assert
		// it does not panic and returns a defined result. The pure identity gate
		// is covered by TestKiroOIDCFromMatchedLocalCredential.
		_, _ = kiroOIDCUpgrade(withoutClient)
	})
}
