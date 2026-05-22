package handlers

import (
	"errors"
	"net/http"
	"testing"

	"github.com/labstack/echo/v5"
)

func TestCleanUploadSegment(t *testing.T) {
	got, err := cleanUploadSegment(" chunk-001 ", "chunk name")
	if err != nil {
		t.Fatalf("cleanUploadSegment returned error: %v", err)
	}
	if got != "chunk-001" {
		t.Fatalf("cleanUploadSegment returned %q, want chunk-001", got)
	}
}

func TestCleanUploadSegmentRejectsPathSyntax(t *testing.T) {
	for _, value := range []string{"", ".", "..", "../x", `..\x`, "/abs", `C:\x`, "C:"} {
		t.Run(value, func(t *testing.T) {
			_, err := cleanUploadSegment(value, "transfer ID")
			if err == nil {
				t.Fatalf("expected %q to be rejected", value)
			}
			var httpErr *echo.HTTPError
			if !errors.As(err, &httpErr) || httpErr.Code != http.StatusBadRequest {
				t.Fatalf("error = %#v, want HTTP 400", err)
			}
		})
	}
}
