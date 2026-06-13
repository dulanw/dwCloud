package handlers

import (
	"dwCloud/app"
	"dwCloud/component"
	mytemplate "dwCloud/template"
	"dwCloud/types"
	"dwCloud/utils"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/a-h/templ"
	"github.com/labstack/echo/v5"
)

type Handler struct {
	app       *app.App
	credCache *credentialCache
}

func NewHandler(a *app.App) *Handler {
	return &Handler{
		app:       a,
		credCache: newCredentialCache(credentialCacheTTL, credentialCacheMaxEntries),
	}
}

// This custom Render replaces Echo's echo.Context.Render() with templ's templ.Component.Render().
func Render(ctx *echo.Context, statusCode int, t templ.Component) error {
	buf := templ.GetBuffer()
	defer templ.ReleaseBuffer(buf)

	if err := t.Render(ctx.Request().Context(), buf); err != nil {
		return err
	}

	return ctx.HTML(statusCode, buf.String())
}

func (h *Handler) ErrorHandler(c *echo.Context, err error) {
	if resp, uErr := echo.UnwrapResponse(c.Response()); uErr == nil {
		if resp.Committed {
			return // response has been already sent to the client by handler or some middleware
		}
	}

	req := c.Request()
	path := req.URL.Path

	code := http.StatusInternalServerError
	msg := http.StatusText(http.StatusInternalServerError)

	var he *echo.HTTPError
	if errors.As(err, &he) {
		code = he.Code
		if strings.TrimSpace(he.Message) != "" {
			msg = he.Message
		}
	}

	// Never expose internal error details (database errors, filesystem paths,
	// upstream OIDC errors, ...) to clients. Log them server-side and return a
	// generic status text for 5xx responses.
	if code >= http.StatusInternalServerError {
		slog.Error("request failed", "method", req.Method, "path", path, "status", code, "error", err)
		msg = http.StatusText(code)
	}

	// /ocs/v2.php/cloud/... and /ocs/v2.php/cloud/capabilities
	isOCS := strings.HasPrefix(path, "/ocs/") || strings.TrimSpace(req.Header.Get("OCS-APIRequest")) != ""
	if isOCS {
		ocsMsg := msg
		if code == http.StatusUnauthorized || code == http.StatusForbidden {
			ocsMsg = "Current user is not logged in"
		}

		meta := types.Meta{
			Status:       "failure",
			StatusCode:   997,
			Message:      ocsMsg,
			TotalItems:   "",
			ItemsPerPage: "",
		}

		// JSON when explicitly asked, otherwise XML (matches common Nextcloud behavior)
		if strings.EqualFold(c.QueryParam("format"), "json") {
			data := []any{}
			cErr := utils.PrettyJSON(c, http.StatusOK, types.NewOCSJSON(meta, data))
			if cErr != nil {
				slog.Error("echo default error handler failed to send error to client", "error", cErr)
			}
			return
		}

		type emptyData struct{} // forces <data/> in XML
		xmlResp := types.OCSXML[emptyData]{Meta: meta, Data: emptyData{}}
		cErr := utils.PrettyXML(c, http.StatusOK, xmlResp)
		if cErr != nil {
			slog.Error("echo default error handler failed to send error to client", "error", cErr)
		}
		return
	}

	// HTML error page
	var cErr error
	if req.Method == http.MethodHead {
		cErr = c.NoContent(code)
	} else {
		html := mytemplate.HTML("Error", mytemplate.Box(mytemplate.Error(code, http.StatusText(code), msg)))
		cErr = Render(c, code, html)
	}
	if cErr != nil {
		c.Logger().Error("failed to send error page to client", "error", errors.Join(err, cErr))
	}
}

func (h *Handler) DashboardHandler(c *echo.Context) error {
	user, err := h.getUserFromSession(c)
	if err != nil {
		return err
	}
	content := mytemplate.DashboardPage(*user, h.isAdmin(*user))
	return h.renderAppPage(c, "Dashboard", *user, content)
}

func (h *Handler) renderAppPage(c *echo.Context, title string, user types.DbUser, content templ.Component) error {
	if isPartialRequest(c) {
		return Render(c, http.StatusOK, content)
	}

	navbar := component.Navbar(displayName(user), nullableValue(user.Email))
	sidebar := component.Sidebar(h.isAdmin(user))
	html := mytemplate.LayoutSidebar(title, navbar, sidebar, content)
	return Render(c, http.StatusOK, html)
}
