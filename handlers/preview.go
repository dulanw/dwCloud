package handlers

import (
	"dwCloud/app"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v5"
)

func (h *Handler) PreviewHandler(c *echo.Context) error {
	_, user, err := h.getUserFromBasicAuth(c)
	if err != nil {
		return err
	}

	fileID := strings.TrimSpace(c.QueryParam("fileId"))
	if fileID == "" {
		return c.NoContent(http.StatusNotFound)
	}

	x, _ := strconv.Atoi(strings.TrimSpace(c.QueryParam("x")))
	y, _ := strconv.Atoi(strings.TrimSpace(c.QueryParam("y")))
	preserveAspect := strings.EqualFold(strings.TrimSpace(c.QueryParam("a")), "true") || strings.TrimSpace(c.QueryParam("a")) == "1"

	data, etag, err := h.app.State.Previews.Get(c.Request().Context(), user.ID, fileID, x, y, preserveAspect)
	if err != nil {
		if errors.Is(err, app.ErrPreviewNotFound) {
			return c.NoContent(http.StatusNotFound)
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	c.Response().Header().Set("ETag", `"`+etag+`"`)
	c.Response().Header().Set("Cache-Control", "private, max-age=3600")
	return c.Blob(http.StatusOK, "image/jpeg", data)
}
