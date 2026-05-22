package utils

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"log/slog"
	"net/http"

	"github.com/labstack/echo/v5"
)

func PrettyJSON(c *echo.Context, status int, v any) error {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		slog.Error("PrettyJSON json.MarshalIndent failed", "error", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	b = append(b, '\n')

	c.Response().Header().Set("Content-Type", "application/json; charset=utf-8")
	return c.Blob(status, "application/json; charset=utf-8", b)
}

func PrettyXML(c *echo.Context, status int, v any) error {
	var buf bytes.Buffer
	buf.WriteString(xml.Header) // <?xml version="1.0" encoding="UTF-8"?>\n

	enc := xml.NewEncoder(&buf)
	enc.Indent("", " ")
	if err := enc.Encode(v); err != nil {
		_ = enc.Close()
		slog.Error("PrettyXML xml.Encode failed", "error", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	if err := enc.Close(); err != nil {
		slog.Error("PrettyXML xml.Close failed", "error", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	buf.WriteByte('\n')

	c.Response().Header().Set("Content-Type", "application/xml; charset=utf-8")
	return c.Blob(status, "application/xml; charset=utf-8", buf.Bytes())
}

func GenerateRandHex(length int) string {
	b := make([]byte, length/2) // 64 bytes × 2 hex chars = 128 characters
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
