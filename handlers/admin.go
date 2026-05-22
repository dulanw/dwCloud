package handlers

import (
	"database/sql"
	mytemplate "dwCloud/template"
	"dwCloud/types"
	"errors"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
)

func (h *Handler) AdminUsersHandler(c *echo.Context) error {
	currentUser, err := h.getUserFromSession(c)
	if err != nil {
		return err
	}

	users, err := h.listAdminUsers(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	csrfToken, err := h.csrfToken(c)
	if err != nil {
		return err
	}

	content := mytemplate.AdminUsersPage(users, csrfToken)
	return h.renderAppPage(c, "Admin Users", *currentUser, content)
}

func (h *Handler) AdminOperationsHandler(c *echo.Context) error {
	currentUser, err := h.getUserFromSession(c)
	if err != nil {
		return err
	}

	content := mytemplate.AdminOperationsPage(h.app.State.Previews.Status())
	return h.renderAppPage(c, "Admin Operations", *currentUser, content)
}

func (h *Handler) AdminOperationsStatusHandler(c *echo.Context) error {
	return Render(c, http.StatusOK, mytemplate.AdminOperationsStatus(h.app.State.Previews.Status()))
}

func (h *Handler) AdminUserUpdateHandler(c *echo.Context) error {
	userID, err := uuid.Parse(strings.TrimSpace(c.Param("id")))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid user id")
	}

	user, err := h.getUser(c, userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusNotFound, "user not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	if err := h.requireCSRF(c); err != nil {
		return err
	}

	displayName := nullableFormValue(c.FormValue("display_name"))
	email := nullableFormValue(c.FormValue("email"))
	storageDir := strings.TrimSpace(c.FormValue("storage_dir"))
	view, err := h.adminUserView(c, user)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	quotaBytes, err := parseQuotaBytes(c.FormValue("quota_value"), c.FormValue("quota_unit"))
	if err != nil {
		return h.renderAdminUserUpdate(c, view, "Quota must be a non-negative number.", c.FormValue("view"))
	}

	storageDir, err = validateStorageDir(storageDir)
	if err != nil {
		return h.renderAdminUserUpdate(c, view, err.Error(), c.FormValue("view"))
	}

	if err = os.MkdirAll(filepath.Join(h.app.Cfg.StorageDir, storageDir), 0o750); err != nil {
		return h.renderAdminUserUpdate(c, view, "Storage directory could not be created.", c.FormValue("view"))
	}

	if _, err = h.app.State.Db.ExecContext(c.Request().Context(), `
		UPDATE users
		SET display_name = $1,
			email = $2,
			storage_dir = $3,
			quota_bytes = $4
		WHERE id = $5
	`, displayName, email, storageDir, quotaBytes, userID); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	user, err = h.getUser(c, userID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	view, err = h.adminUserView(c, user)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return h.renderAdminUserUpdate(c, view, "Saved", c.FormValue("view"))
}

func (h *Handler) listAdminUsers(c *echo.Context) ([]types.AdminUserView, error) {
	var users []types.DbUser
	if err := h.app.State.Db.SelectContext(c.Request().Context(), &users, `
		SELECT *
		FROM users
		ORDER BY created_at DESC, id DESC
	`); err != nil {
		return nil, err
	}

	views := make([]types.AdminUserView, 0, len(users))
	for _, user := range users {
		view, err := h.adminUserView(c, user)
		if err != nil {
			return nil, err
		}
		views = append(views, view)
	}

	return views, nil
}

func (h *Handler) getUser(c *echo.Context, id uuid.UUID) (types.DbUser, error) {
	var user types.DbUser
	err := h.app.State.Db.GetContext(c.Request().Context(), &user, `
		SELECT *
		FROM users
		WHERE id = $1
		LIMIT 1
	`, id)
	return user, err
}

func (h *Handler) adminUserView(c *echo.Context, user types.DbUser) (types.AdminUserView, error) {
	usageBytes, err := h.userUsageBytes(c, user.ID)
	if err != nil {
		return types.AdminUserView{}, err
	}
	return types.AdminUserView{User: user, UsageBytes: usageBytes}, nil
}

func (h *Handler) userUsageBytes(c *echo.Context, id uuid.UUID) (int64, error) {
	var usageBytes int64
	if err := h.app.State.Db.GetContext(c.Request().Context(), &usageBytes, `
		SELECT COALESCE(size_bytes, 0)
		FROM files
		WHERE user_id = $1 AND path = ''
		LIMIT 1
	`, id); err == nil {
		return usageBytes, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}

	err := h.app.State.Db.GetContext(c.Request().Context(), &usageBytes, `
		SELECT COALESCE(SUM(size_bytes), 0)
		FROM files
		WHERE user_id = $1 AND is_dir = false
	`, id)
	return usageBytes, err
}

func (h *Handler) renderAdminUserUpdate(c *echo.Context, view types.AdminUserView, message string, variant string) error {
	csrfToken, err := h.csrfToken(c)
	if err != nil {
		return err
	}
	return Render(c, http.StatusOK, mytemplate.AdminUserDisclosure(view, message, true, csrfToken))
}

func isPartialRequest(c *echo.Context) bool {
	return strings.EqualFold(c.QueryParam("partial"), "true") || strings.EqualFold(c.Request().Header.Get("HX-Request"), "true")
}

func nullableFormValue(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return &value
}

func nullableValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func displayName(user types.DbUser) string {
	if user.DisplayName != nil && strings.TrimSpace(*user.DisplayName) != "" {
		return strings.TrimSpace(*user.DisplayName)
	}
	if user.Email != nil && strings.TrimSpace(*user.Email) != "" {
		return strings.TrimSpace(*user.Email)
	}
	return user.ID.String()
}

func validateStorageDir(value string) (string, error) {
	value = filepath.Clean(strings.TrimSpace(value))
	if value == "." || value == "" {
		return "", errors.New("storage directory is required")
	}
	if filepath.IsAbs(value) || filepath.VolumeName(value) != "" {
		return "", errors.New("storage directory must be relative")
	}
	if strings.ContainsAny(value, `/\`) {
		return "", errors.New("storage directory cannot be nested")
	}
	if value == ".." || strings.HasPrefix(value, ".."+string(filepath.Separator)) {
		return "", errors.New("storage directory cannot escape the storage root")
	}
	return value, nil
}

func parseQuotaBytes(value string, unit string) (int64, error) {
	quotaValue, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil || quotaValue < 0 {
		return 0, errors.New("invalid quota")
	}

	multiplier, ok := byteUnitMultiplier(unit)
	if !ok {
		return 0, errors.New("invalid quota unit")
	}

	bytes := quotaValue * float64(multiplier)
	if bytes > float64(math.MaxInt64) {
		return 0, errors.New("quota is too large")
	}

	return int64(math.Round(bytes)), nil
}

func byteUnitMultiplier(unit string) (int64, bool) {
	switch strings.ToUpper(strings.TrimSpace(unit)) {
	case "B":
		return 1, true
	case "KB":
		return 1024, true
	case "MB":
		return 1024 * 1024, true
	case "GB":
		return 1024 * 1024 * 1024, true
	case "TB":
		return 1024 * 1024 * 1024 * 1024, true
	default:
		return 0, false
	}
}
