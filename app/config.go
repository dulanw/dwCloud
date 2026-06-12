package app

import (
	"context"
	"dwCloud/component"
	"fmt"
	"html/template"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

type IdProvider struct {
	DisplayName string
	Logo        templ.Component

	Provider *oidc.Provider
	Config   *oauth2.Config
}

type Config struct {
	Domain    string
	Protocol  string
	ServerURL string

	ListenAddr      string
	SessionKey      string
	SessionDuration time.Duration
	StorageDir      string
	UploadDir       string

	PostgresAddress  string
	PostgresUser     string
	PostgresPassword string
	PostgresDB       string

	IDPs map[string]IdProvider
}

func normalizeOIDCScopes(scope string) []string {
	seen := map[string]bool{}
	scopes := []string{}
	for _, raw := range strings.Split(scope, ",") {
		s := strings.TrimSpace(raw)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		scopes = append(scopes, s)
	}
	if !seen["openid"] {
		scopes = append([]string{"openid"}, scopes...)
	}
	return scopes
}

func optionalDuration(value string, defaultValue time.Duration) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultValue, nil
	}

	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, err
	}
	if duration <= 0 {
		return 0, fmt.Errorf("must be positive")
	}
	return duration, nil
}

func (cfg *Config) Load(ctx context.Context) error {
	cfg.Protocol = os.Getenv("PROTOCOL")
	if cfg.Protocol == "" {
		return fmt.Errorf("missing PROTOCOL")
	}

	cfg.Domain = strings.TrimRight(os.Getenv("DOMAIN"), "/")
	if cfg.Domain == "" {
		return fmt.Errorf("missing DOMAIN")
	}

	cfg.ServerURL = cfg.Protocol + "://" + cfg.Domain

	cfg.ListenAddr = os.Getenv("LISTEN_ADDRESS")
	if cfg.ListenAddr == "" {
		return fmt.Errorf("missing LISTEN_ADDRESS")
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// OIDC provider configs
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	cfg.IDPs = make(map[string]IdProvider)
	sawIDPConfig := false
	for i := 1; ; i++ {
		clientId := os.Getenv(fmt.Sprintf("IDP_CLIENT_ID_%d", i))
		if clientId == "" {
			break
		}
		sawIDPConfig = true

		secret := os.Getenv(fmt.Sprintf("IDP_SECRET_%d", i))
		if secret == "" {
			slog.Error(fmt.Sprintf("Missing IDP_SECRET_%d", i))
			continue
		}

		endpoint := os.Getenv(fmt.Sprintf("IDP_ENDPOINT_%d", i))
		if endpoint == "" {
			slog.Error(fmt.Sprintf("Missing IDP_ENDPOINT_%d", i))
			continue
		}

		scope := os.Getenv(fmt.Sprintf("IDP_SCOPES_%d", i))
		if scope == "" {
			slog.Error(fmt.Sprintf("Missing IDP_SCOPES_%d", i))
			continue
		}
		scopes := normalizeOIDCScopes(scope)

		id := os.Getenv(fmt.Sprintf("IDP_ID_%d", i))
		if id == "" {
			slog.Error(fmt.Sprintf("Missing IDP_ID_%d", i))
			continue
		}

		name := os.Getenv(fmt.Sprintf("IDP_NAME_%d", i))
		if name == "" {
			slog.Error(fmt.Sprintf("Missing IDP_NAME_%d", i))
			continue
		}

		path := os.Getenv(fmt.Sprintf("IDP_LOGO_%d", i))
		if path == "" {
			slog.Error(fmt.Sprintf("Missing IDP_LOGO_%d", i))
			continue
		}

		b, err := os.ReadFile(path)
		if err != nil {
			slog.Error(fmt.Sprintf("failed to readfile %s", path), "error", err)
			continue
		}

		provider, err := oidc.NewProvider(ctx, endpoint)
		if err != nil {
			return fmt.Errorf("failed to initialise provider %s: %w", id, err)
		}

		config := &oauth2.Config{
			ClientID:     clientId,
			ClientSecret: secret,
			Endpoint:     provider.Endpoint(),
			Scopes:       scopes,
			RedirectURL:  cfg.ServerURL + "/auth/callback/" + id,
		}

		cfg.IDPs[id] = IdProvider{
			DisplayName: name,
			Logo:        component.SSOIcon(template.HTML(b)),
			Provider:    provider,
			Config:      config,
		}
	}
	if len(cfg.IDPs) == 0 {
		if sawIDPConfig {
			return fmt.Errorf("no valid IDP configured")
		}
		return fmt.Errorf("missing IDP_CLIENT_ID_1")
	}

	cfg.PostgresAddress = os.Getenv("POSTGRES_ADDRESS")
	if cfg.PostgresAddress == "" {
		return fmt.Errorf("missing POSTGRES_ADDRESS")
	}

	cfg.PostgresUser = os.Getenv("POSTGRES_USER")
	if cfg.PostgresUser == "" {
		return fmt.Errorf("missing POSTGRES_USER")
	}

	cfg.PostgresPassword = os.Getenv("POSTGRES_PASSWORD")
	if cfg.PostgresPassword == "" {
		return fmt.Errorf("missing POSTGRES_PASSWORD")
	}

	cfg.PostgresDB = os.Getenv("POSTGRES_DB")
	if cfg.PostgresDB == "" {
		return fmt.Errorf("missing POSTGRES_DB")
	}

	cfg.SessionKey = os.Getenv("SESSION_KEY")
	if cfg.SessionKey == "" {
		return fmt.Errorf("missing SESSION_KEY")
	}

	sessionDuration, err := optionalDuration(os.Getenv("SESSION_DURATION"), 4*time.Hour)
	if err != nil {
		return fmt.Errorf("invalid SESSION_DURATION: %w", err)
	}
	cfg.SessionDuration = sessionDuration

	cfg.StorageDir = os.Getenv("STORAGE_DIR")
	if cfg.StorageDir == "" {
		return fmt.Errorf("missing STORAGE_DIR")
	}

	cfg.UploadDir = os.Getenv("UPLOAD_DIR")
	if cfg.UploadDir == "" {
		return fmt.Errorf("missing UPLOAD_DIR")
	}

	return nil
}

func (cfg *Config) GetDSN() string {
	return fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", cfg.PostgresUser, cfg.PostgresPassword, cfg.PostgresAddress, cfg.PostgresDB)
}
