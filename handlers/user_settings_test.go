package handlers

import "testing"

func TestValidateOptionalEmail(t *testing.T) {
	email, err := validateOptionalEmail("ada@example.com")
	if err != nil {
		t.Fatalf("validateOptionalEmail returned error: %v", err)
	}
	if email == nil || *email != "ada@example.com" {
		t.Fatalf("email = %#v, want ada@example.com", email)
	}

	if _, err := validateOptionalEmail("not an email"); err == nil {
		t.Fatalf("expected invalid email to fail")
	}
}

func TestValidateOptionalURL(t *testing.T) {
	avatarURL, err := validateOptionalURL("https://example.com/avatar.png")
	if err != nil {
		t.Fatalf("validateOptionalURL returned error: %v", err)
	}
	if avatarURL == nil || *avatarURL != "https://example.com/avatar.png" {
		t.Fatalf("url = %#v, want https URL", avatarURL)
	}

	for _, value := range []string{"javascript:alert(1)", "/avatar.png"} {
		if _, err := validateOptionalURL(value); err == nil {
			t.Fatalf("expected %q to fail", value)
		}
	}
}

func TestCleanProfileField(t *testing.T) {
	got, err := cleanProfileField(" en_GB ", "Language", 35)
	if err != nil {
		t.Fatalf("cleanProfileField returned error: %v", err)
	}
	if got != "en_GB" {
		t.Fatalf("got %q, want en_GB", got)
	}

	if _, err := cleanProfileField("en\nGB", "Language", 35); err == nil {
		t.Fatalf("expected control character to fail")
	}
}
