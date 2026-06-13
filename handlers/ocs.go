package handlers

import (
	"dwCloud/types"
	"dwCloud/utils"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/labstack/echo/v5"
)

func (h *Handler) StatusHandler(c *echo.Context) error {
	//{"installed":true,"maintenance":false,"needsDbUpgrade":false,"version":"32.0.5.0","versionstring":"32.0.5","edition":"","productname":"Nextcloud","extendedSupport":false}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"installed":       true,
		"maintenance":     false,
		"needsDbUpgrade":  false,
		"version":         "32.0.5.0",
		"versionstring":   "32.0.5",
		"edition":         "",
		"productname":     "Nextcloud",
		"extendedSupport": false,
	})
}

func (h *Handler) OCSCapabilitiesHandler(c *echo.Context) error {
	//curl -H "OCS-APIRequest: true" PROTOCOL://DOMAIN/ocs/v2.php/cloud/capabilities?format=json

	ocsHeader := c.Request().Header.Get("OCS-APIRequest")
	if ocsHeader == "" {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"message": "OCS-APIRequest header is required",
		})
	}

	// Example OCS response
	data := types.OCSCapabilitiesData{
		Version: types.Version{
			Major:           32,
			Minor:           0,
			Micro:           5,
			String:          "32.0.5",
			Edition:         "",
			ExtendedSupport: "",
		},
		Capabilities: types.Capabilities{
			Bruteforce: types.Bruteforce{
				Delay:       0,
				AllowListed: "",
			},
			DAV: types.DAV{
				AbsenceReplacement:    true,
				AbsenceSupported:      true,
				BulkUpload:            "1.0",
				Chunking:              "1.0",
				PublicSharingChunking: true,
			},
			Files: types.Files{
				BlacklistedFiles:            []string{".htaccess"},
				ForbiddenFilenames:          []string{".htaccess"},
				ForbiddenFilenameBasenames:  []string{},
				ForbiddenFilenameCharacters: []string{"\\", "/"},
				ForbiddenFilenameExtensions: []string{".filepart", ".part"},
				BigFileChunking:             true,
				ChunkedUpload: types.ChunkedUpload{
					MaxSize:          104857600, // 100MB per chunk
					MaxParallelCount: 5,
				},
				FileConversions:            []interface{}{},
				WindowsCompatibleFilenames: false,
				DirectEditing: types.DirectEditing{
					URL:            h.app.Cfg.ServerURL + "/ocs/v2.php/apps/files/api/v1/directEditing",
					ETag:           "",
					SupportsFileID: true,
				},
				Comments:        true,
				Undelete:        false,
				DeleteFromTrash: false,
				Versioning:      false,
				VersionLabeling: false,
				VersionDeletion: false,
			},
			Registration: types.Registration{
				Enabled:  1,
				ApiRoot:  "/ocs/v2.php/apps/registration/api/v1/",
				ApiLevel: "v1",
			},
			Theming: types.Theming{
				Name:              "Nextcloud",
				ProductName:       "Nextcloud",
				URL:               h.app.Cfg.ServerURL,
				Slogan:            "a safe home for all your data",
				Color:             "#00679e",
				ColorText:         "#ffffff",
				ColorElement:      "#00679e",
				ColorBright:       "#00679e",
				ColorDark:         "#00679e",
				Logo:              fmt.Sprintf("%s/core/img/logo/logo.svg?v=0", h.app.Cfg.ServerURL),
				Background:        fmt.Sprintf("%s/apps/theming/img/background/jo-myoung-hee-fluid.webp", h.app.Cfg.ServerURL),
				BackgroundText:    "#ffffff",
				BackgroundPlain:   "",
				BackgroundDefault: "1",
				LogoHeader:        fmt.Sprintf("%s/core/img/logo/logo.svg?v=0", h.app.Cfg.ServerURL),
				Favicon:           fmt.Sprintf("%s/core/img/logo/logo.svg?v=0", h.app.Cfg.ServerURL),
			},
		},
	}

	format := c.QueryParam("format")
	if format != "json" {
		xmlResp := types.OCSXML[types.OCSCapabilitiesData]{
			Meta: types.OKMeta(100),
			Data: data,
		}
		return utils.PrettyXML(c, http.StatusOK, xmlResp)
	}

	return utils.PrettyJSON(c, http.StatusOK, types.NewOCSJSON(types.OKMeta(100), data))
}

func (h *Handler) OCSUserHandler(c *echo.Context) error {
	//curl -H "OCS-APIRequest: true" PROTOCOL://DOMAIN//ocs/v1.php/cloud/user?format=json

	ocsHeader := c.Request().Header.Get("OCS-APIRequest")
	if strings.TrimSpace(ocsHeader) == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "OCS-APIRequest header is required")
	}

	_, user, err := h.getUserFromBasicAuth(c)
	if err != nil {
		return err
	}
	username := user.Username

	display := "Unknown"
	if user.DisplayName != nil && strings.TrimSpace(*user.DisplayName) != "" {
		display = strings.TrimSpace(*user.DisplayName)
	}
	displayDash := strings.ReplaceAll(display, " ", "-")

	email := ""
	if user.Email != nil {
		email = *user.Email
	}
	locale := ""
	if user.Locale != nil {
		locale = *user.Locale
	}

	// storage location
	storagePath := filepath.ToSlash(filepath.Join(h.app.Cfg.StorageDir, user.StorageDir))
	quotaTotal := user.QuotaBytes
	// Use the DB-maintained root size instead of walking the whole storage tree on
	// every request: clients poll this endpoint frequently.
	used, sizeErr := h.userUsageBytes(c, user.ID)
	if sizeErr != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, sizeErr.Error())
	}
	free := quotaTotal - used
	if free < 0 {
		free = 0
	}
	relative := 0.0
	if quotaTotal > 0 {
		relative = float64(used) / float64(quotaTotal)
	}

	groups := []string{}
	if strings.EqualFold(strings.TrimSpace(user.Role), "admin") {
		groups = []string{"admin"}
	}

	data := types.OCSUserData{
		Enabled:         true,
		StorageLocation: storagePath,

		ID: username,

		FirstLoginTimestamp: user.CreatedAt.Unix(),
		LastLoginTimestamp:  user.LastLoginAt.Unix(),
		LastLogin:           user.LastLoginAt.UnixMilli(),

		Backend:  "Database",
		Subadmin: []string{},

		Quota: types.OCSUserQuota{
			Free:     free,
			Used:     used,
			Total:    quotaTotal,
			Relative: relative,
			Quota:    quotaTotal,
		},

		Manager:     "",
		AvatarScope: "v2-federated",

		Email:               email,
		EmailScope:          "v2-federated",
		AdditionalMail:      []string{},
		AdditionalMailScope: []any{},

		DisplayName:      display,
		DisplayNameDash:  displayDash,
		DisplayNameScope: "v2-federated",

		Role:      "",
		RoleScope: "v2-local",

		Pronouns:      "",
		PronounsScope: "v2-federated",

		Groups:   groups,
		Language: user.Language,
		Locale:   locale,
		Timezone: user.Timezone,

		NotifyEmail: nil,

		BackendCapabilities: types.OCSUserBackendCapabilities{
			SetDisplayName: true,
			SetPassword:    true,
		},
	}

	format := c.QueryParam("format")
	if format != "json" {
		xmlResp := types.OCSXML[types.OCSUserData]{
			Meta: types.OKMeta(100),
			Data: data,
		}
		return utils.PrettyXML(c, http.StatusOK, xmlResp)
	}

	return utils.PrettyJSON(c, http.StatusOK, types.NewOCSJSON(types.OKMeta(100), data))
}

func (h *Handler) OCSUserStatusHandler(c *echo.Context) error {
	ocsHeader := c.Request().Header.Get("OCS-APIRequest")
	if strings.TrimSpace(ocsHeader) == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "OCS-APIRequest header is required")
	}

	username, err := h.getUsernameFromBasicAuth(c)
	if err != nil {
		return err
	}

	data := types.OCSUserStatusData{
		UserID:              *username,
		Message:             nil,
		MessageID:           nil,
		MessageIsPredefined: false,
		Icon:                nil,
		ClearAt:             nil,
		Status:              "offline",
		StatusIsUserDefined: false,
	}

	// This endpoint is effectively JSON-only in clients; still honor format param.
	if strings.EqualFold(strings.TrimSpace(c.QueryParam("format")), "json") || c.QueryParam("format") == "" {
		return utils.PrettyJSON(c, http.StatusOK, types.NewOCSJSON(types.OKMeta(200), data))
	}

	// XML fallback
	xmlResp := types.OCSXML[types.OCSUserStatusData]{
		Meta: types.OKMeta(100),
		Data: data,
	}
	return utils.PrettyXML(c, http.StatusOK, xmlResp)
}

// Terms of Service (desktop client may request this during setup)
func (h *Handler) OCSTermsOfServiceHandler(c *echo.Context) error {
	// Do not hard-fail on missing OCS-APIRequest; clients can be inconsistent.
	// If you want to enforce it later, do it only after everything else works.

	if strings.EqualFold(strings.TrimSpace(c.QueryParam("format")), "json") || c.QueryParam("format") == "" {
		data := map[string]any{
			"terms":     []any{},
			"languages": map[string]string{},
			"hasSigned": true,
		}
		return utils.PrettyJSON(c, http.StatusOK, types.NewOCSJSON(types.OKMeta(100), data))
	}

	type termsXMLData struct {
		Terms     []string `xml:"terms>element"`
		Languages []string `xml:"languages>element"`
		HasSigned bool     `xml:"hasSigned"`
	}
	xmlResp := types.OCSXML[termsXMLData]{
		Meta: types.OKMeta(100),
		Data: termsXMLData{Terms: []string{}, Languages: []string{}, HasSigned: true},
	}
	return utils.PrettyXML(c, http.StatusOK, xmlResp)

}

func (h *Handler) DAVAvatarHandler(c *echo.Context) error {
	_, user, err := h.getUserFromBasicAuth(c)
	if err != nil {
		return err
	}

	if strings.TrimSpace(c.Param("username")) != user.Username {
		return c.NoContent(http.StatusNotFound)
	}

	if user.AvatarURL == nil || strings.TrimSpace(*user.AvatarURL) == "" {
		c.Response().Header().Set("Cache-Control", "private, max-age=300")
		return c.NoContent(http.StatusNotFound)
	}

	return c.Redirect(http.StatusFound, strings.TrimSpace(*user.AvatarURL))
}

func (h *Handler) OCSNotificationsHandler(c *echo.Context) error {
	// Return an empty list of notifications, but as OCS "ok".
	data := []any{}
	return utils.PrettyJSON(c, http.StatusOK, types.NewOCSJSON(types.OKMeta(200), data))
}

func (h *Handler) OCSNavigationAppsHandler(c *echo.Context) error {
	// Return an empty list of navigation apps.
	data := []any{}
	return utils.PrettyJSON(c, http.StatusOK, types.NewOCSJSON(types.OKMeta(200), data))
}
