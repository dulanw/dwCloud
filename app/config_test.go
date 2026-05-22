package app

import (
	"reflect"
	"testing"
	"time"
)

func TestNormalizeOIDCScopesAddsOpenIDAndTrims(t *testing.T) {
	got := normalizeOIDCScopes(" profile, email ,profile ")
	want := []string{"openid", "profile", "email"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeOIDCScopes() = %#v, want %#v", got, want)
	}
}

func TestNormalizeOIDCScopesKeepsExistingOpenID(t *testing.T) {
	got := normalizeOIDCScopes("email,openid,profile")
	want := []string{"email", "openid", "profile"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeOIDCScopes() = %#v, want %#v", got, want)
	}
}

func TestOptionalDurationUsesDefault(t *testing.T) {
	got, err := optionalDuration("", 4*time.Hour)
	if err != nil {
		t.Fatalf("optionalDuration returned error: %v", err)
	}
	if got != 4*time.Hour {
		t.Fatalf("optionalDuration() = %s, want 4h", got)
	}
}

func TestOptionalDurationParsesDuration(t *testing.T) {
	got, err := optionalDuration("2h30m", 4*time.Hour)
	if err != nil {
		t.Fatalf("optionalDuration returned error: %v", err)
	}
	if got != 150*time.Minute {
		t.Fatalf("optionalDuration() = %s, want 2h30m", got)
	}
}

func TestOptionalDurationRejectsNonPositiveDuration(t *testing.T) {
	if _, err := optionalDuration("0s", 4*time.Hour); err == nil {
		t.Fatalf("expected zero duration to fail")
	}
}
