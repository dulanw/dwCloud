package handlers

import (
	mytemplate "dwCloud/template"
	"dwCloud/types"
	"dwCloud/utils"
	"errors"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
)

func (h *Handler) UserSettingsHandler(c *echo.Context) error {
	user, err := h.getUserFromSession(c)
	if err != nil {
		return err
	}

	if c.Request().Method == http.MethodGet {
		csrfToken, err := h.csrfToken(c)
		if err != nil {
			return err
		}
		content := mytemplate.UserSettingsPage(*user, "", false, csrfToken)
		return h.renderAppPage(c, "Personal Info", *user, content)
	}

	if err := h.requireCSRF(c); err != nil {
		return err
	}
	csrfToken, err := h.csrfToken(c)
	if err != nil {
		return err
	}
	updated, message, isErr := h.updateCurrentUserSettings(c, *user)
	if updated.ID == uuid.Nil {
		updated = *user
	}

	panel := mytemplate.UserProfilePanel(updated, message, isErr, csrfToken)
	if isPartialRequest(c) {
		return Render(c, http.StatusOK, panel)
	}

	content := mytemplate.UserSettingsPage(updated, message, isErr, csrfToken)
	return h.renderAppPage(c, "Personal Info", updated, content)
}

func (h *Handler) updateCurrentUserSettings(c *echo.Context, user types.DbUser) (types.DbUser, string, bool) {
	displayName := nullableFormValue(c.FormValue("display_name"))
	email, err := validateOptionalEmail(c.FormValue("email"))
	if err != nil {
		return user, err.Error(), true
	}

	timezone := strings.TrimSpace(c.FormValue("timezone"))
	if timezone == "" {
		timezone = "Europe/London"
	}
	if _, err := time.LoadLocation(timezone); err != nil {
		return user, "Timezone is not valid.", true
	}

	language, err := cleanProfileField(c.FormValue("language"), "Language", 35)
	if err != nil {
		return user, err.Error(), true
	}
	if language == "" {
		language = "en_GB"
	}

	localeValue, err := cleanProfileField(c.FormValue("locale"), "Locale", 35)
	if err != nil {
		return user, err.Error(), true
	}
	var locale *string
	if localeValue != "" {
		locale = &localeValue
	}

	avatarURL, err := validateOptionalURL(c.FormValue("avatar_url"))
	if err != nil {
		return user, err.Error(), true
	}

	emailVerified := user.EmailVerified
	if !stringPointersEqual(user.Email, email) {
		emailVerified = false
	}

	if _, err := h.app.State.Db.ExecContext(c.Request().Context(), `
		UPDATE users
		SET display_name = $1,
			email = $2,
			email_verified = $3,
			timezone = $4,
			language = $5,
			locale = $6,
			avatar_url = $7
		WHERE id = $8
	`, displayName, email, emailVerified, timezone, language, locale, avatarURL, user.ID); err != nil {
		return user, err.Error(), true
	}

	updated, err := h.getUser(c, user.ID)
	if err != nil {
		return user, err.Error(), true
	}
	return updated, "Saved", false
}

func validateOptionalEmail(value string) (*string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	address, err := mail.ParseAddress(value)
	if err != nil || address.Address != value {
		return nil, errors.New("Email is not valid.")
	}
	return &value, nil
}

func validateOptionalURL(value string) (*string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	u, err := url.Parse(value)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return nil, errors.New("Avatar URL must be an absolute URL.")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, errors.New("Avatar URL must use http or https.")
	}
	return &value, nil
}

func cleanProfileField(value string, label string, max int) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) > max {
		return "", errors.New(label + " is too long.")
	}
	if strings.ContainsAny(value, "\r\n\t") {
		return "", errors.New(label + " cannot contain control characters.")
	}
	return value, nil
}

func stringPointersEqual(a *string, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func (h *Handler) UserSecurityHandler(c *echo.Context) error {
	user, err := h.getUserFromSession(c)
	if err != nil {
		return err
	}

	passwords, err := h.listAppPasswords(c, user.ID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	csrfToken, err := h.csrfToken(c)
	if err != nil {
		return err
	}

	content := mytemplate.UserSecurityPage(*user, passwords, "", "", "", false, csrfToken)
	return h.renderAppPage(c, "Security", *user, content)
}

func (h *Handler) AppPasswordCreateHandler(c *echo.Context) error {
	user, err := h.getUserFromSession(c)
	if err != nil {
		return err
	}
	if err := h.requireCSRF(c); err != nil {
		return err
	}

	label := strings.TrimSpace(c.FormValue("label"))
	if label == "" {
		label = "App password"
	}
	if len(label) > 120 {
		return h.renderSecurityContent(c, *user, "", "", "Label is too long.", true)
	}

	plain := utils.GenerateRandHex(72)
	secretHash, err := hashAppPassword(plain)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	if _, err := h.app.State.Db.ExecContext(c.Request().Context(), `
		INSERT INTO app_passwords (user_id, label, secret_hash)
		VALUES ($1, $2, $3)
	`, user.ID, label, secretHash); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return h.renderSecurityContent(c, *user, user.Username, plain, "App password created.", false)
}

func (h *Handler) AppPasswordRevokeHandler(c *echo.Context) error {
	user, err := h.getUserFromSession(c)
	if err != nil {
		return err
	}
	if err := h.requireCSRF(c); err != nil {
		return err
	}

	passwordID, err := uuid.Parse(strings.TrimSpace(c.Param("id")))
	if err != nil {
		return h.renderSecurityContent(c, *user, "", "", "App password not found.", true)
	}

	result, err := h.app.State.Db.ExecContext(c.Request().Context(), `
		UPDATE app_passwords
		SET revoked_at = NOW()
		WHERE id = $1
		  AND user_id = $2
		  AND revoked_at IS NULL
	`, passwordID, user.ID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return h.renderSecurityContent(c, *user, "", "", "App password was already revoked or not found.", true)
	}

	return h.renderSecurityContent(c, *user, "", "", "App password revoked. It will be deleted after 7 days.", false)
}

func (h *Handler) AppPasswordRemoteWipeHandler(c *echo.Context) error {
	user, err := h.getUserFromSession(c)
	if err != nil {
		return err
	}
	if err := h.requireCSRF(c); err != nil {
		return err
	}

	passwordID, err := uuid.Parse(strings.TrimSpace(c.Param("id")))
	if err != nil {
		return h.renderSecurityContent(c, *user, "", "", "App password not found.", true)
	}

	result, err := h.app.State.Db.ExecContext(c.Request().Context(), `
		UPDATE app_passwords
		SET revoked_at = NOW(),
			remote_wipe_at = NOW()
		WHERE id = $1
		  AND user_id = $2
		  AND remote_wipe_at IS NULL
	`, passwordID, user.ID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return h.renderSecurityContent(c, *user, "", "", "Remote wipe was already requested or the app password was not found.", true)
	}

	return h.renderSecurityContent(c, *user, "", "", "Remote wipe requested. The app password has been revoked.", false)
}

func (h *Handler) renderSecurityContent(c *echo.Context, user types.DbUser, generatedUsername string, generatedPassword string, message string, isError bool) error {
	passwords, err := h.listAppPasswords(c, user.ID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	csrfToken, err := h.csrfToken(c)
	if err != nil {
		return err
	}
	return Render(c, http.StatusOK, mytemplate.UserSecurityContent(user.Username, passwords, generatedUsername, generatedPassword, message, isError, csrfToken))
}

func (h *Handler) listAppPasswords(c *echo.Context, userID uuid.UUID) ([]types.DbAppPassword, error) {
	var passwords []types.DbAppPassword
	err := h.app.State.Db.SelectContext(c.Request().Context(), &passwords, `
		SELECT *
		FROM app_passwords
		WHERE user_id = $1
		ORDER BY revoked_at IS NULL DESC, created_at DESC
	`, userID)
	return passwords, err
}
