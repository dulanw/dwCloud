package handlers

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"dwCloud/component"
	mytemplate "dwCloud/template"
	"dwCloud/types"
	"dwCloud/utils"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/gosimple/slug"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v5"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

const csrfSessionKey = "csrf_token"

func hashAppPassword(plain string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

func safeRedirectPath(next string) string {
	next = strings.TrimSpace(next)
	if next == "" {
		return "/"
	}

	u, err := url.Parse(next)
	if err != nil || u.IsAbs() || u.Host != "" {
		return "/"
	}
	if !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") {
		return "/"
	}

	if u.Path == "" {
		u.Path = "/"
	}
	u.Scheme = ""
	u.Host = ""
	return u.RequestURI()
}

func addNextParam(rawURL string, next string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set("next", safeRedirectPath(next))
	u.RawQuery = q.Encode()
	return u.String()
}

func optionalStringClaim(claims map[string]interface{}, names ...string) *string {
	for _, name := range names {
		v, ok := claims[name]
		if !ok || v == nil {
			continue
		}
		var s string
		switch t := v.(type) {
		case string:
			s = t
		case fmt.Stringer:
			s = t.String()
		default:
			continue
		}
		if s = strings.TrimSpace(s); s != "" {
			return &s
		}
	}
	return nil
}

func optionalBoolClaim(claims map[string]interface{}, names ...string) bool {
	for _, name := range names {
		v, ok := claims[name]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case bool:
			return t
		case string:
			return strings.EqualFold(strings.TrimSpace(t), "true")
		}
	}
	return false
}

type oidcUserProfile struct {
	Provider      string
	Subject       string
	Email         *string
	EmailVerified bool
	DisplayName   string
	AvatarURL     *string
}

func oidcProfileFromClaims(idToken *oidc.IDToken, claims map[string]interface{}) (oidcUserProfile, error) {
	profile := oidcUserProfile{
		Provider: strings.TrimSpace(idToken.Issuer),
		Subject:  strings.TrimSpace(idToken.Subject),
	}
	if profile.Provider == "" || profile.Subject == "" {
		return oidcUserProfile{}, fmt.Errorf("ID token is missing issuer or subject")
	}

	profile.Email = optionalStringClaim(claims, "email", "preferred_email")
	profile.EmailVerified = optionalBoolClaim(claims, "email_verified")

	display := optionalStringClaim(claims, "name", "preferred_username", "nickname")
	if display == nil && profile.Email != nil {
		local, _, _ := strings.Cut(*profile.Email, "@")
		local = strings.TrimSpace(local)
		if local != "" {
			display = &local
		}
	}
	if display == nil {
		display = &profile.Subject
	}
	profile.DisplayName = *display

	profile.AvatarURL = optionalStringClaim(claims, "picture", "avatar_url")
	return profile, nil
}

func storageDirFromDisplayName(displayName string) string {
	base := strings.ReplaceAll(slug.Make(displayName), "-", "_")
	base = strings.Trim(base, "_")
	if base == "" {
		base = "user"
	}
	return base + "_" + utils.GenerateRandHex(8)
}

func usernameBase(displayName string, email *string, subject string) string {
	source := strings.TrimSpace(displayName)
	if source == "" && email != nil {
		source, _, _ = strings.Cut(strings.TrimSpace(*email), "@")
	}
	if source == "" {
		source = subject
	}

	slugged := strings.Trim(slug.Make(source), "-")
	parts := strings.FieldsFunc(slugged, func(r rune) bool {
		return r == '-'
	})
	if len(parts) == 0 {
		return "user"
	}

	first := parts[0]
	last := parts[len(parts)-1]
	if first == "" || last == "" {
		return "user"
	}
	base := first[:1] + last
	base = strings.Trim(slug.Make(base), "-")
	if base == "" {
		return "user"
	}
	return strings.ReplaceAll(base, "-", "")
}

func randomFourDigits() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(10000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%04d", n.Int64()), nil
}

func (h *Handler) generateUniqueUsername(ctx context.Context, displayName string, email *string, subject string) (string, error) {
	base := usernameBase(displayName, email, subject)
	for i := 0; i < 100; i++ {
		suffix, err := randomFourDigits()
		if err != nil {
			return "", err
		}
		candidate := base + suffix

		var count int
		if err := h.app.State.Db.GetContext(ctx, &count, `
			SELECT count(*) FROM users WHERE username = $1
		`, candidate); err != nil {
			return "", err
		}
		if count == 0 {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("failed to generate a unique username")
}

func (h *Handler) sessionOptions(maxAge time.Duration) *sessions.Options {
	return &sessions.Options{
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		HttpOnly: true,
		Secure:   strings.EqualFold(strings.TrimSpace(h.app.Cfg.Protocol), "https"),
		SameSite: http.SameSiteLaxMode,
	}
}

func sessionExpiresAt(sess *sessions.Session) (time.Time, bool) {
	switch value := sess.Values["expires_at"].(type) {
	case int64:
		return time.Unix(value, 0), true
	case int:
		return time.Unix(int64(value), 0), true
	case string:
		expiresAt, err := time.Parse(time.RFC3339, value)
		return expiresAt, err == nil
	case time.Time:
		return value, true
	default:
		return time.Time{}, false
	}
}

func (h *Handler) expireSessionCookie(c *echo.Context) {
	c.SetCookie(&http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0).UTC(),
		HttpOnly: true,
		Secure:   strings.EqualFold(strings.TrimSpace(h.app.Cfg.Protocol), "https"),
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *Handler) csrfToken(c *echo.Context) (string, error) {
	sess, err := session.Get("session", c)
	if err != nil {
		h.expireSessionCookie(c)
		return "", echo.NewHTTPError(http.StatusUnauthorized, "Invalid session")
	}

	token, _ := sess.Values[csrfSessionKey].(string)
	token = strings.TrimSpace(token)
	if token != "" {
		return token, nil
	}

	token = utils.GenerateRandHex(64)
	sess.Values[csrfSessionKey] = token
	sess.Options = h.sessionOptions(h.app.Cfg.SessionDuration)
	if err := sess.Save(c.Request(), c.Response()); err != nil {
		return "", echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	return token, nil
}

func (h *Handler) requireCSRF(c *echo.Context) error {
	sess, err := session.Get("session", c)
	if err != nil {
		h.expireSessionCookie(c)
		return echo.NewHTTPError(http.StatusForbidden, "Invalid CSRF token")
	}

	expected, _ := sess.Values[csrfSessionKey].(string)
	submitted := strings.TrimSpace(c.FormValue("csrf_token"))
	if submitted == "" {
		submitted = strings.TrimSpace(c.Request().Header.Get("X-CSRF-Token"))
	}
	if expected == "" || submitted == "" || subtle.ConstantTimeCompare([]byte(submitted), []byte(expected)) != 1 {
		return echo.NewHTTPError(http.StatusForbidden, "Invalid CSRF token")
	}
	return nil
}

func (h *Handler) AuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		user, err := h.getUserFromSession(c)
		if err != nil {
			// Preserve the local target so browser login can resume the client flow.
			loginURL := addNextParam("/login", c.Request().RequestURI)
			return c.Redirect(http.StatusFound, loginURL)
		}
		c.Set("session_user", *user)
		return next(c)
	}
}

func (h *Handler) BasicAuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		username, ap, err := h.getAppPasswordFromBasicAuth(c)
		if err != nil {
			c.Response().Header().Set("WWW-Authenticate", `Basic realm="dwCloud"`)
			return c.NoContent(http.StatusUnauthorized)
		}

		var user types.DbUser
		if err := h.app.State.Db.GetContext(c.Request().Context(), &user, `
			SELECT * FROM users WHERE id = $1 LIMIT 1
		`, ap.UserID); err != nil {
			c.Response().Header().Set("WWW-Authenticate", `Basic realm="dwCloud"`)
			return c.NoContent(http.StatusUnauthorized)
		}

		c.Set("basic_auth_username", *username)
		c.Set("basic_auth_app_password", *ap)
		c.Set("basic_auth_user", user)

		return next(c)
	}
}

func (h *Handler) AdminAuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		user, err := h.getUserFromSession(c)
		if err != nil {
			return err
		}

		if !h.isAdmin(*user) {
			return echo.NewHTTPError(http.StatusForbidden, "Admin access required")
		}

		return next(c)
	}
}

func (h *Handler) LoginV2Handler(c *echo.Context) error {
	pollId := utils.GenerateRandHex(128)
	flowId := utils.GenerateRandHex(128)

	userAgent := c.Request().Header.Get("User-Agent")
	if userAgent == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Missing User-Agent header")
	}

	if _, err := h.app.State.Db.ExecContext(c.Request().Context(), `
		INSERT INTO login_v2_sessions (poll_token, flow_token, user_agent, expires_at)
		VALUES ($1, $2, $3, $4)
	`, pollId, flowId, userAgent, time.Now().Add(20*time.Minute)); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"poll": map[string]interface{}{
			"token":    pollId,
			"endpoint": h.app.Cfg.ServerURL + "/index.php/login/v2/poll",
		},
		"login": h.app.Cfg.ServerURL + "/login/v2/flow/" + flowId,
	})
}

func (h *Handler) LoginV2FlowHandler(c *echo.Context) error {
	flowToken := strings.TrimSpace(c.Param("flowToken"))
	if flowToken == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Missing flow token")
	}

	ctx := c.Request().Context()

	// Note required as long as we don't need a different error for expired token
	// Ensure flow exists and not expired
	/*var s LoginV2Session
	if err := DB.NewSelect().
		Model(&s).
		Where("flow_token = ?", flowToken).
		Limit(1).
		Scan(ctx); err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "Invalid flow token")
	}

	if time.Now().After(s.ExpiresAt) {
		return echo.NewHTTPError(http.StatusGone, "Flow token expired")
	}*/

	// Generate a fresh state token and store it
	stateToken := utils.GenerateRandHex(128)

	res, err := h.app.State.Db.ExecContext(ctx, `
		UPDATE login_v2_sessions
		SET state_token = $1
		WHERE flow_token = $2
		  AND expires_at > now()
		  AND approved_at IS NULL
	`, stateToken, flowToken)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	if affected == 0 {
		return echo.NewHTTPError(http.StatusNotFound, "Flow token invalid/missing/expired")
	}

	// After login finishes, we want to land on /login/v2/grant?direct=0&stateToken=...
	// Reuse your existing login page: it already supports next=...
	return c.Redirect(http.StatusFound, "/login/v2/grant?stateToken="+url.QueryEscape(stateToken))
}

func (h *Handler) LoginV2PollHandler(c *echo.Context) error {

	pollToken := c.FormValue("token")
	if pollToken == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Missing token")
	}

	ctx := c.Request().Context()

	// Use a transaction
	tx, err := h.app.State.Db.BeginTxx(ctx, nil)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() { _ = tx.Rollback() }()

	var loginSession types.DbLoginV2Session
	if err = tx.GetContext(ctx, &loginSession, `
		SELECT * FROM login_v2_sessions
		WHERE poll_token = $1
		LIMIT 1
		FOR UPDATE
	`, pollToken); err != nil {
		return c.NoContent(http.StatusForbidden)
	}

	// Expired => delete and 403
	if time.Now().After(loginSession.ExpiresAt) {
		if _, err = tx.ExecContext(ctx, `
			DELETE FROM login_v2_sessions WHERE poll_token = $1
		`, pollToken); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
		if err := tx.Commit(); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
		return c.NoContent(http.StatusForbidden)
	}

	// Not approved yet => 404 until done
	if loginSession.ApprovedAt == nil || loginSession.UserID == nil {
		if err := tx.Commit(); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
		return c.NoContent(http.StatusNotFound)
	}

	// Approved: delete the flow row so it can only be consumed once
	if _, err = tx.ExecContext(ctx, `
		DELETE FROM login_v2_sessions WHERE poll_token = $1
	`, pollToken); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	var user types.DbUser
	if err := tx.GetContext(ctx, &user, `
		SELECT * FROM users WHERE id = $1 LIMIT 1
	`, *loginSession.UserID); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	plain := utils.GenerateRandHex(72)
	secretHash, err := hashAppPassword(plain)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO app_passwords (user_id, label, secret_hash)
		VALUES ($1, $2, $3)
	`, user.ID, loginSession.UserAgent, secretHash); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO files (user_id, path, is_dir, ocid, version, size_bytes, mtime, created_at, updated_at)
		VALUES ($1, '', true, '', 1, 0, NOW(), NOW(), NOW())
		ON CONFLICT (user_id, path) DO NOTHING
	`, user.ID); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	if err := tx.Commit(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"server":      h.app.Cfg.ServerURL,
		"loginName":   user.Username,
		"appPassword": plain,
	})
}

func (h *Handler) RemoteWipeCheckHandler(c *echo.Context) error {
	token := strings.TrimSpace(c.FormValue("token"))
	if token == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Missing token")
	}

	ap, err := h.findAppPasswordByToken(c.Request().Context(), token)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	if appPasswordNeedsRemoteWipe(ap) {
		return c.JSON(http.StatusOK, map[string]bool{
			"wipe": true,
		})
	}

	return c.JSON(http.StatusNotFound, map[string]bool{
		"wipe": false,
	})
}

func (h *Handler) RemoteWipeSuccessHandler(c *echo.Context) error {
	token := strings.TrimSpace(c.FormValue("token"))
	if token == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Missing token")
	}

	ap, err := h.findAppPasswordByToken(c.Request().Context(), token)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	if ap == nil || ap.RemoteWipeAt == nil {
		return c.JSON(http.StatusNotFound, map[string]bool{
			"success": false,
		})
	}

	if _, err := h.app.State.Db.ExecContext(c.Request().Context(), `
		UPDATE app_passwords
		SET remote_wipe_completed_at = COALESCE(remote_wipe_completed_at, NOW())
		WHERE id = $1
	`, ap.ID); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return c.JSON(http.StatusOK, map[string]bool{
		"success": true,
	})
}

func (h *Handler) findAppPasswordByToken(ctx context.Context, token string) (*types.DbAppPassword, error) {
	var appPasswords []types.DbAppPassword
	if err := h.app.State.Db.SelectContext(ctx, &appPasswords, `
		SELECT id, user_id, label, secret_hash, created_at, last_used_at, revoked_at, remote_wipe_at, remote_wipe_completed_at
		FROM app_passwords
		ORDER BY created_at DESC
	`); err != nil {
		return nil, err
	}

	return matchAppPasswordByToken(appPasswords, token), nil
}

func matchAppPasswordByToken(appPasswords []types.DbAppPassword, token string) *types.DbAppPassword {
	for i := range appPasswords {
		ap := &appPasswords[i]
		if err := bcrypt.CompareHashAndPassword([]byte(ap.SecretHash), []byte(token)); err == nil {
			return ap
		}
	}

	return nil
}

func appPasswordNeedsRemoteWipe(ap *types.DbAppPassword) bool {
	return ap != nil && ap.RemoteWipeAt != nil && ap.RemoteWipeCompletedAt == nil
}

func (h *Handler) LoginHandler(c *echo.Context) error {
	next := safeRedirectPath(c.QueryParam("next"))

	sess, err := session.Get("session", c)
	if err != nil {
		h.expireSessionCookie(c)
	} else if auth, ok := sess.Values["authenticated"].(bool); ok && auth {
		if user, err := h.getUserFromSession(c); err == nil {
			c.Set("session_user", *user)
			// Already logged in, redirect to default or requested page.
			return c.Redirect(http.StatusFound, next)
		}
	}

	var buttons []templ.Component
	for id, idp := range h.app.Cfg.IDPs {
		href := fmt.Sprintf("%s/auth/%s", h.app.Cfg.ServerURL, id)
		if next != "/" {
			href = addNextParam(href, next)
		}
		buttons = append(buttons, component.SSOButton(idp.DisplayName, href, idp.Logo))
	}

	html := mytemplate.HTML("Login", mytemplate.Box(mytemplate.Login(buttons)))
	return Render(c, http.StatusOK, html)
}

func (h *Handler) GrantHandler(c *echo.Context) error {
	// Read stateToken from query (GET) or form (POST)
	stateToken := strings.TrimSpace(c.QueryParam("stateToken"))
	if stateToken == "" {
		stateToken = strings.TrimSpace(c.FormValue("stateToken"))
	}
	if stateToken == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Missing state token")
	}
	if c.Request().Method == http.MethodPost {
		if err := h.requireCSRF(c); err != nil {
			return err
		}
	}

	ctx := c.Request().Context()

	tx, err := h.app.State.Db.BeginTxx(ctx, nil)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() { _ = tx.Rollback() }()

	// we need to load it for both GET/PUT to check the expiry
	var flow types.DbLoginV2Session
	if err := tx.GetContext(ctx, &flow, `
		SELECT * FROM login_v2_sessions
		WHERE state_token = $1
		  AND approved_at IS NULL
		LIMIT 1
		FOR UPDATE
	`, stateToken); err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "Invalid state token")
	}
	if time.Now().After(flow.ExpiresAt) {
		return echo.NewHTTPError(http.StatusGone, "Flow expired")
	}

	currentUser, err := h.getUserFromSession(c)
	if err != nil {
		return err
	}
	uid := currentUser.ID.String()

	if c.Request().Method == http.MethodGet {
		if flow.UserID != nil {
			return echo.NewHTTPError(http.StatusForbidden, "Invalid state token")
		}

		if _, err = tx.ExecContext(ctx, `
			UPDATE login_v2_sessions SET user_id = $1 WHERE id = $2
		`, uid, flow.ID); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		if err := tx.Commit(); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		// bind the user_id
		displayName := "Unknown"
		if currentUser.DisplayName != nil && strings.TrimSpace(*currentUser.DisplayName) != "" {
			displayName = strings.TrimSpace(*currentUser.DisplayName)
		}

		csrfToken, err := h.csrfToken(c)
		if err != nil {
			return err
		}
		action := "/login/v2/grant"
		html := mytemplate.HTML("Grant", mytemplate.Box(mytemplate.Grant(displayName, flow.UserAgent, action, stateToken, csrfToken)))
		return Render(c, http.StatusOK, html)

	}

	if flow.UserID == nil {
		return echo.NewHTTPError(http.StatusForbidden, "Invalid state token")
	}
	if flow.UserID.String() != uid {
		return echo.NewHTTPError(http.StatusForbidden, "Invalid state token")
	}

	if _, err = tx.ExecContext(ctx, `
		UPDATE login_v2_sessions
		SET approved_at = $1,
			state_token = NULL
		WHERE id = $2
	`, time.Now(), flow.ID); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	if err := tx.Commit(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	html := mytemplate.HTML("Grant", mytemplate.Box(mytemplate.Info("Account connected", "Your client should now be connected!<br>You can close this window.")))
	return Render(c, http.StatusOK, html)
}

func (h *Handler) AuthHandler(c *echo.Context) error {

	id := c.Param("provider")
	idp, ok := h.app.Cfg.IDPs[id]
	if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid provider: %s", id))
	}

	csrf := utils.GenerateRandHex(128)
	nonce := utils.GenerateRandHex(64)
	payload := map[string]string{
		"csrf": csrf,
		"next": safeRedirectPath(c.QueryParam("next")),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	authUrl := idp.Config.AuthCodeURL(
		base64.RawURLEncoding.EncodeToString(data),
		oauth2.SetAuthURLParam("nonce", nonce),
	)

	sess, err := session.Get("auth", c)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	sess.Values["csrf"] = csrf
	sess.Values["nonce"] = nonce
	sess.Options = h.sessionOptions(10 * time.Minute)

	if err := sess.Save(c.Request(), c.Response()); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return c.Redirect(http.StatusFound, authUrl)
}

func (h *Handler) AuthCallbackHandler(c *echo.Context) error {
	sess, err := session.Get("auth", c)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	stateParam := c.QueryParam("state")
	data, err := base64.RawURLEncoding.DecodeString(stateParam)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid state: %s", err))
	}

	var payload map[string]string
	if err := json.Unmarshal(data, &payload); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid state payload: %s", err))
	}

	csrf := payload["csrf"]
	sessionCSRF, _ := sess.Values["csrf"].(string)
	if csrf == "" || csrf != sessionCSRF {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid state")
	}
	nonce, _ := sess.Values["nonce"].(string)

	// clear auth sess
	sess.Values = make(map[interface{}]interface{})
	sess.Options = h.sessionOptions(-1 * time.Second)
	_ = sess.Save(c.Request(), c.Response())

	if oauthError := strings.TrimSpace(c.QueryParam("error")); oauthError != "" {
		description := strings.TrimSpace(c.QueryParam("error_description"))
		if description == "" {
			description = oauthError
		}
		return echo.NewHTTPError(http.StatusBadRequest, description)
	}

	id := c.Param("provider")
	idp, ok := h.app.Cfg.IDPs[id]
	if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid provider: %s", id))
	}

	code := strings.TrimSpace(c.QueryParam("code"))
	if code == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Missing authorization code")
	}
	token, err := idp.Config.Exchange(c.Request().Context(), code)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, fmt.Sprintf("Token exchange failed: %s", err))
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return echo.NewHTTPError(http.StatusBadGateway, "ID token missing")
	}

	// Verify ID token
	verifier := idp.Provider.Verifier(&oidc.Config{ClientID: idp.Config.ClientID})
	idToken, err := verifier.Verify(c.Request().Context(), rawIDToken)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, fmt.Sprintf("Token verify failed: %s", err))
	}
	if nonce == "" || idToken.Nonce != nonce {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid nonce")
	}

	// Parse claims
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to parse claims")
	}
	if userInfo, err := idp.Provider.UserInfo(c.Request().Context(), oauth2.StaticTokenSource(token)); err == nil {
		var userInfoClaims map[string]interface{}
		if err := userInfo.Claims(&userInfoClaims); err == nil {
			for k, v := range userInfoClaims {
				claims[k] = v
			}
		}
	}

	profile, err := oidcProfileFromClaims(idToken, claims)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, err.Error())
	}

	var count int
	if err = h.app.State.Db.GetContext(c.Request().Context(), &count, `
		SELECT count(*) FROM users
	`); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	// only the first user will be an admin, cannot add more admins after that
	role := "user"
	if count == 0 {
		role = "admin"
	}

	now := time.Now()
	directory := storageDirFromDisplayName(profile.DisplayName)
	username, err := h.generateUniqueUsername(c.Request().Context(), profile.DisplayName, profile.Email, profile.Subject)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	var user types.DbUser
	if err = h.app.State.Db.QueryRowxContext(c.Request().Context(), `
		INSERT INTO users (username, provider, subject, email, email_verified, display_name, role, avatar_url, last_login_at, storage_dir)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (provider, subject) DO UPDATE
		SET email = EXCLUDED.email,
			email_verified = EXCLUDED.email_verified,
			display_name = EXCLUDED.display_name,
			avatar_url = EXCLUDED.avatar_url,
			last_login_at = EXCLUDED.last_login_at
		RETURNING *
	`, username, profile.Provider, profile.Subject, profile.Email, profile.EmailVerified, profile.DisplayName, role, profile.AvatarURL, now, directory).StructScan(&user); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	// Create a user root directory on filesystem
	userRoot := filepath.Join(h.app.Cfg.StorageDir, user.StorageDir)
	createdUserRoot := false
	if _, err := os.Stat(userRoot); err != nil {
		if os.IsNotExist(err) {
			if err = os.MkdirAll(userRoot, 0o750); err == nil {
				createdUserRoot = true
			}
		}

		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
	}

	if _, err := h.app.State.Db.ExecContext(c.Request().Context(), `
		INSERT INTO files (user_id, path, is_dir, ocid, version, size_bytes, mtime, created_at, updated_at)
		VALUES ($1, '', true, '', 1, 0, $2, $2, $2)
		ON CONFLICT (user_id, path) DO NOTHING
	`, user.ID, now); err != nil {
		if createdUserRoot {
			_ = os.Remove(userRoot)
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	// set session for both nextcloud login v2 and normal login
	sess, err = session.Get("session", c)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	sess.Values["user"] = user.ID.String()
	sess.Values["authenticated"] = true
	sess.Values["expires_at"] = time.Now().Add(h.app.Cfg.SessionDuration).Unix()
	sess.Options = h.sessionOptions(h.app.Cfg.SessionDuration)
	err = sess.Save(c.Request(), c.Response())
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("Failed to save session: %s", err))
	}

	next := safeRedirectPath(payload["next"])
	return c.Redirect(http.StatusFound, next)
}

func (h *Handler) getUsernameFromBasicAuth(c *echo.Context) (*string, error) {
	_, user, err := h.getUserFromBasicAuth(c)
	if err != nil {
		return nil, err
	}
	username := user.Username
	return &username, nil
}

func (h *Handler) getUserFromBasicAuth(c *echo.Context) (*string, *types.DbUser, error) {
	if username, ok := c.Get("basic_auth_username").(string); ok {
		if user, ok := c.Get("basic_auth_user").(types.DbUser); ok {
			return &username, &user, nil
		}
	}

	username, ap, err := h.getAppPasswordFromBasicAuth(c)
	if err != nil {
		return nil, nil, err
	}

	ctx := c.Request().Context()

	var user types.DbUser
	if err := h.app.State.Db.GetContext(ctx, &user, `
    	SELECT * FROM users WHERE id = $1 LIMIT 1
	`, ap.UserID); err != nil {
		return nil, nil, echo.NewHTTPError(http.StatusUnauthorized, "Invalid credentials")
	}

	c.Set("basic_auth_username", *username)
	c.Set("basic_auth_app_password", *ap)
	c.Set("basic_auth_user", user)

	return username, &user, nil
}

func (h *Handler) getUserFromSession(c *echo.Context) (*types.DbUser, error) {
	if user, ok := c.Get("session_user").(types.DbUser); ok {
		return &user, nil
	}

	sess, err := session.Get("session", c)
	if err != nil {
		h.expireSessionCookie(c)
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "Invalid session")
	}

	auth, ok := sess.Values["authenticated"].(bool)
	if !ok || !auth {
		h.expireSessionCookie(c)
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "Not authenticated")
	}

	expiresAt, ok := sessionExpiresAt(sess)
	if !ok || time.Now().After(expiresAt) {
		h.expireSessionCookie(c)
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "Session expired")
	}

	userID, ok := sess.Values["user"].(string)
	if !ok || strings.TrimSpace(userID) == "" {
		h.expireSessionCookie(c)
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "Not authenticated")
	}

	id, err := uuid.Parse(userID)
	if err != nil {
		h.expireSessionCookie(c)
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "Invalid session")
	}

	ctx := c.Request().Context()

	var user types.DbUser
	if err := h.app.State.Db.GetContext(ctx, &user, `
    	SELECT * FROM users WHERE id = $1 LIMIT 1
	`, id); err != nil {
		h.expireSessionCookie(c)
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "Invalid credentials")
	}

	c.Set("session_user", user)
	return &user, nil
}

func (h *Handler) isAdmin(user types.DbUser) bool {
	return strings.EqualFold(strings.TrimSpace(user.Role), "admin")
}

func basicAuthCredentials(c *echo.Context) (string, string, error) {
	username, password, ok := c.Request().BasicAuth()
	username = strings.TrimSpace(username)
	if !ok || username == "" || password == "" {
		return "", "", echo.NewHTTPError(http.StatusUnauthorized, "Missing Basic authentication")
	}
	return username, password, nil
}

func (h *Handler) getAppPasswordFromBasicAuth(c *echo.Context) (*string, *types.DbAppPassword, error) {
	if username, ok := c.Get("basic_auth_username").(string); ok {
		if ap, ok := c.Get("basic_auth_app_password").(types.DbAppPassword); ok {
			return &username, &ap, nil
		}
	}

	username, password, err := basicAuthCredentials(c)
	if err != nil {
		return nil, nil, err
	}

	var user types.DbUser
	if err := h.app.State.Db.GetContext(c.Request().Context(), &user, `
		SELECT * FROM users WHERE username = $1 LIMIT 1
	`, username); err != nil {
		return nil, nil, echo.NewHTTPError(http.StatusUnauthorized, "Invalid credentials")
	}

	var appPasswords []types.DbAppPassword
	if err := h.app.State.Db.SelectContext(c.Request().Context(), &appPasswords, `
		SELECT *
		FROM app_passwords
		WHERE user_id = $1 AND revoked_at IS NULL
		ORDER BY created_at DESC
	`, user.ID); err != nil {
		return nil, nil, echo.NewHTTPError(http.StatusUnauthorized, "Invalid credentials")
	}

	for _, ap := range appPasswords {
		if err := bcrypt.CompareHashAndPassword([]byte(ap.SecretHash), []byte(password)); err == nil {
			_, _ = h.app.State.Db.ExecContext(c.Request().Context(), `
				UPDATE app_passwords SET last_used_at = NOW() WHERE id = $1
			`, ap.ID)
			return &username, &ap, nil
		}
	}

	return nil, nil, echo.NewHTTPError(http.StatusUnauthorized, "Invalid credentials")
}
