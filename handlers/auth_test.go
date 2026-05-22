package handlers

import (
	"dwCloud/types"
	"testing"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func TestSafeRedirectPath(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: "/"},
		{name: "local path with query", in: "/login/v2/grant?stateToken=abc&direct=0", want: "/login/v2/grant?stateToken=abc&direct=0"},
		{name: "absolute URL", in: "https://evil.example/path", want: "/"},
		{name: "scheme relative URL", in: "//evil.example/path", want: "/"},
		{name: "relative path", in: "dashboard", want: "/"},
		{name: "fragment stripped", in: "/dashboard#section", want: "/dashboard"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := safeRedirectPath(tt.in); got != tt.want {
				t.Fatalf("safeRedirectPath(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestOIDCProfileFromClaims(t *testing.T) {
	email := "ada@example.com"
	avatar := "https://idp.example/avatar.png"
	profile, err := oidcProfileFromClaims(&oidc.IDToken{
		Issuer:  "https://idp.example",
		Subject: "subject-1",
	}, map[string]interface{}{
		"email":              email,
		"email_verified":     "true",
		"preferred_username": "Ada",
		"avatar_url":         avatar,
	})
	if err != nil {
		t.Fatalf("oidcProfileFromClaims returned error: %v", err)
	}
	if profile.Provider != "https://idp.example" || profile.Subject != "subject-1" {
		t.Fatalf("unexpected provider/subject: %#v", profile)
	}
	if profile.Email == nil || *profile.Email != email {
		t.Fatalf("email = %#v, want %q", profile.Email, email)
	}
	if !profile.EmailVerified {
		t.Fatalf("email should be verified")
	}
	if profile.DisplayName != "Ada" {
		t.Fatalf("display name = %q, want Ada", profile.DisplayName)
	}
	if profile.AvatarURL == nil || *profile.AvatarURL != avatar {
		t.Fatalf("avatar = %#v, want %q", profile.AvatarURL, avatar)
	}
}

func TestOIDCProfileFallsBackToSubject(t *testing.T) {
	profile, err := oidcProfileFromClaims(&oidc.IDToken{
		Issuer:  "https://idp.example",
		Subject: "subject-1",
	}, map[string]interface{}{})
	if err != nil {
		t.Fatalf("oidcProfileFromClaims returned error: %v", err)
	}
	if profile.DisplayName != "subject-1" {
		t.Fatalf("display name = %q, want subject fallback", profile.DisplayName)
	}
}

func TestOIDCProfileRequiresIssuerAndSubject(t *testing.T) {
	_, err := oidcProfileFromClaims(&oidc.IDToken{Issuer: "https://idp.example"}, map[string]interface{}{})
	if err == nil {
		t.Fatalf("expected missing subject to fail")
	}
}

func TestUsernameBase(t *testing.T) {
	if got := usernameBase("Jack Smith", nil, "subject"); got != "jsmith" {
		t.Fatalf("usernameBase() = %q, want jsmith", got)
	}

	email := "ada@example.com"
	if got := usernameBase("", &email, "subject"); got != "aada" {
		t.Fatalf("usernameBase() = %q, want aada", got)
	}
}

func TestRemoteWipeCheckMatchesTokenBeforeWipeState(t *testing.T) {
	oldToken := "old-token"
	currentToken := "current-token"
	now := time.Now()
	oldID := uuid.New()
	currentID := uuid.New()

	passwords := []types.DbAppPassword{
		{
			ID:           oldID,
			SecretHash:   mustBcryptHash(t, oldToken),
			RemoteWipeAt: &now,
		},
		{
			ID:         currentID,
			SecretHash: mustBcryptHash(t, currentToken),
		},
	}

	current := matchAppPasswordByToken(passwords, currentToken)
	if current == nil || current.ID != currentID {
		t.Fatalf("current token matched %#v, want app password %s", current, currentID)
	}
	if appPasswordNeedsRemoteWipe(current) {
		t.Fatalf("current token should not inherit the old app password's wipe state")
	}

	old := matchAppPasswordByToken(passwords, oldToken)
	if old == nil || old.ID != oldID {
		t.Fatalf("old token matched %#v, want app password %s", old, oldID)
	}
	if !appPasswordNeedsRemoteWipe(old) {
		t.Fatalf("old token should still require remote wipe")
	}
}

func TestRemoteWipeCheckIgnoresCompletedWipe(t *testing.T) {
	now := time.Now()
	password := types.DbAppPassword{
		SecretHash:            mustBcryptHash(t, "token"),
		RemoteWipeAt:          &now,
		RemoteWipeCompletedAt: &now,
	}

	matched := matchAppPasswordByToken([]types.DbAppPassword{password}, "token")
	if matched == nil {
		t.Fatalf("expected token to match")
	}
	if appPasswordNeedsRemoteWipe(matched) {
		t.Fatalf("completed remote wipe should not keep returning wipe=true")
	}
}

func mustBcryptHash(t *testing.T, plain string) string {
	t.Helper()

	hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("failed to hash token: %v", err)
	}
	return string(hash)
}
