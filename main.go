package main

import (
	"context"
	"dwCloud/app"
	"dwCloud/handlers"
	"embed"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/a-h/templ"
	"github.com/gorilla/sessions"
	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

//go:embed static/*
var staticFS embed.FS

// This custom Render replaces Echo's echo.Context.Render() with templ's templ.Component.Render().
func Render(ctx *echo.Context, statusCode int, t templ.Component) error {
	buf := templ.GetBuffer()
	defer templ.ReleaseBuffer(buf)

	if err := t.Render(ctx.Request().Context(), buf); err != nil {
		return err
	}

	return ctx.HTML(statusCode, buf.String())
}

func main() {
	a := new(app.App)
	err := a.Init()

	if err != nil {
		slog.Error("Failed to init app", "error", err)
		os.Exit(1)
	}

	h := handlers.NewHandler(a)

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// sessions
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	e := echo.New()
	sessionStore := sessions.NewCookieStore([]byte(a.Cfg.SessionKey))
	sessionStore.MaxAge(int(a.Cfg.SessionDuration.Seconds()))
	e.Use(session.Middleware(sessionStore))
	e.Use(middleware.RequestLogger())
	e.Use(middleware.Recover())

	//e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
	//	return func(c *echo.Context) error {
	//
	//		req := c.Request()
	//
	//		fmt.Println("---- REQUEST DEBUG ----")
	//		fmt.Println("Method:", req.Method)
	//		fmt.Println("URI:", req.RequestURI)
	//
	//		for name, values := range req.Header {
	//			for _, value := range values {
	//				fmt.Printf("Header: %s = %s\n", name, value)
	//			}
	//		}
	//
	//		fmt.Println("-----------------------")
	//
	//		return next(c)
	//	}
	//})

	// serve static
	e.Static("/static", "static")
	e.File("/favicon.ico", "static/images/favicon.ico")

	// error handling
	e.HTTPErrorHandler = h.ErrorHandler

	//redirect to dashboard
	e.GET("/", func(c *echo.Context) error {
		return c.Redirect(http.StatusFound, "/dashboard")
	})

	// nextcloud
	e.GET("/status.php", h.StatusHandler)
	e.GET("/ocs/v1.php/cloud/capabilities", h.OCSCapabilitiesHandler)
	e.GET("/ocs/v2.php/cloud/capabilities", h.OCSCapabilitiesHandler)
	e.GET("/ocs/v2.php/apps/terms_of_service/terms", h.OCSTermsOfServiceHandler)
	e.GET("/index.php/204", func(c *echo.Context) error {
		return c.NoContent(http.StatusNoContent)
	})

	// Login Flow v2
	e.POST("/index.php/login/v2", h.LoginV2Handler)
	e.POST("/index.php/login/v2/poll", h.LoginV2PollHandler)
	e.GET("/login/v2/flow/:flowToken", h.LoginV2FlowHandler)
	e.POST("/index.php/core/wipe/check", h.RemoteWipeCheckHandler)
	e.POST("/index.php/core/wipe/success", h.RemoteWipeSuccessHandler)

	// Login FLow
	e.GET("/login", h.LoginHandler)
	e.GET("/auth/:provider", h.AuthHandler)
	e.GET("/auth/callback/:provider", h.AuthCallbackHandler)

	// Grant/AppPassword
	protected := e.Group("")
	protected.Use(h.AuthMiddleware)
	protected.GET("/login/v2/grant", h.GrantHandler)
	protected.POST("/login/v2/grant", h.GrantHandler)

	// Normal User
	protected.GET("/dashboard", h.DashboardHandler)
	protected.GET("/settings/user", h.UserSettingsHandler)
	protected.POST("/settings/user", h.UserSettingsHandler)
	protected.GET("/settings/user/security", h.UserSecurityHandler)
	protected.POST("/settings/user/security/app-passwords", h.AppPasswordCreateHandler)
	protected.POST("/settings/user/security/app-passwords/:id/revoke", h.AppPasswordRevokeHandler)
	protected.POST("/settings/user/security/app-passwords/:id/wipe", h.AppPasswordRemoteWipeHandler)

	// Admin
	admin := protected.Group("")
	admin.Use(h.AdminAuthMiddleware)
	admin.GET("/settings/admin", h.AdminOperationsHandler)
	admin.GET("/settings/admin/general", h.AdminOperationsHandler)
	admin.GET("/settings/admin/general/status", h.AdminOperationsStatusHandler)
	admin.GET("/settings/admin/users", h.AdminUsersHandler)
	admin.POST("/settings/admin/users/:id", h.AdminUserUpdateHandler)

	// WebDAV
	basicAuth := e.Group("")
	basicAuth.Use(h.BasicAuthMiddleware)
	basicAuth.GET("/ocs/v1.php/cloud/user", h.OCSUserHandler)
	basicAuth.GET("/ocs/v2.php/apps/user_status/api/v1/user_status", h.OCSUserStatusHandler)
	basicAuth.GET("/ocs/v2.php/apps/notifications/api/v2/notifications", h.OCSNotificationsHandler)
	basicAuth.GET("/ocs/v2.php/core/navigation/apps", h.OCSNavigationAppsHandler)
	basicAuth.GET("/index.php/core/preview", h.PreviewHandler)
	basicAuth.GET("/remote.php/dav/avatars/:username/:size", h.DAVAvatarHandler)

	davMethods := []string{
		"GET",
		"HEAD",
		"PUT",
		"POST",
		"DELETE",
		"OPTIONS",
		"PROPFIND",
		"PROPPATCH",
		"MKCOL",
		"COPY",
		"MOVE",
		"REPORT",
		"LOCK",
		"UNLOCK",
	}

	for _, m := range davMethods {
		basicAuth.Add(m, "/remote.php/dav/files/:username", h.WebDAVHandler)
		basicAuth.Add(m, "/remote.php/dav/files/:username/", h.WebDAVHandler)

		basicAuth.Add(m, "/remote.php/dav/files/:username/*", h.WebDAVHandler)
		basicAuth.Add(m, "/remote.php/dav/files/:username/*/", h.WebDAVHandler)
	}

	// chunk upload
	basicAuth.Add("MKCOL", "/remote.php/dav/uploads/:username/:transferID", h.WebDAVUploadHandler)
	basicAuth.Add("PUT", "/remote.php/dav/uploads/:username/:transferID/:chunkName", h.WebDAVUploadHandler)
	basicAuth.Add("MOVE", "/remote.php/dav/uploads/:username/:transferID/.file", h.WebDAVUploadHandler)
	basicAuth.Add("PROPFIND", "/remote.php/dav/uploads/:username/:transferID", h.WebDAVUploadHandler)

	//basicAuth.Add("PROPFIND", "/remote.php/dav/files/:username", h.WebDAVFilesRootPropfindHandler)

	// Start background cleanup of expired flows
	go runLoginFlowJanitor(context.Background(), a.State.Db, 1*time.Second)

	if err := e.Start(a.Cfg.ListenAddr); err != nil {
		e.Logger.Error("failed to start server", "error", err)
	}
}

func runLoginFlowJanitor(ctx context.Context, db *sqlx.DB, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = db.ExecContext(ctx, `
                DELETE FROM login_v2_sessions WHERE expires_at <= now()
            `)
			_, _ = db.ExecContext(ctx, `
                DELETE FROM locks WHERE timeout_at < NOW()
            `)
			_, _ = db.ExecContext(ctx, `
				DELETE FROM app_passwords WHERE revoked_at <= NOW() - INTERVAL '7 days'
			`)
		}
	}
}
