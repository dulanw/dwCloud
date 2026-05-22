package utils

import (
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strings"

	"github.com/labstack/echo/v5"
)

const davFilesPrefix = "/remote.php/dav/files/"

// DavExtractRelFromReqPath extracts the DAV-relative path (slash-separated, no leading slash)
// and *verifies the URL username segment matches the authenticated username*.
//
// Example reqPath:
//
//	/remote.php/dav/files/admin/New%20folder/test.txt
//
// Returns:
//
//	rel: "" for the user root collection, otherwise "New folder/test.txt"
//	isCollectionPath: whether the REQUEST URL ended in "/" (client hint only)
func davExtractRelFromReqPath(reqPath string, expectedUsername string) (rel string, isCollectionPath bool, err error) {
	expectedUsername = strings.TrimSpace(expectedUsername)
	if expectedUsername == "" {
		return "", false, echo.NewHTTPError(http.StatusInternalServerError, "Missing expected username")
	}

	after, ok := strings.CutPrefix(reqPath, davFilesPrefix)
	if !ok {
		return "", false, echo.NewHTTPError(http.StatusBadRequest, "bad DAV path")
	}

	// Split "<username>" from the rest of the path.
	urlUser, rest, _ := strings.Cut(after, "/")

	// Username may be percent-encoded; decode best-effort before comparing.
	urlUserDecoded, _ := url.PathUnescape(urlUser)
	if strings.TrimSpace(urlUserDecoded) != expectedUsername {
		// 404 avoids leaking whether the user exists, matching typical DAV behavior.
		return "", false, echo.NewHTTPError(http.StatusNotFound, "not found")
	}

	isCollectionPath = strings.HasSuffix(reqPath, "/")

	if rest == "" {
		return "", isCollectionPath, nil
	}

	rest, _ = url.PathUnescape(rest)
	rest = strings.TrimLeft(rest, "/")
	return rest, isCollectionPath, nil
}

func davAbsClean(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

func davAssertUnderRoot(rootAbs, targetAbs string) error {
	rel, err := filepath.Rel(rootAbs, targetAbs)
	if err != nil {
		return err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return echo.NewHTTPError(http.StatusForbidden, "path escapes user root")
	}
	return nil
}

// DavResolveRelToFS resolves a DAV-relative path to an absolute filesystem path,
// rejecting any path that escapes userRoot.
func davResolveRelToFS(userRoot string, relDAV string) (fsAbs string, err error) {
	rootAbs, err := davAbsClean(userRoot)
	if err != nil {
		return "", err
	}

	target := filepath.Clean(filepath.Join(rootAbs, filepath.FromSlash(relDAV)))

	if err := davAssertUnderRoot(rootAbs, target); err != nil {
		return "", err
	}
	return target, nil
}

// DavRelCanonicalFromFS returns the canonical slash-separated DAV path for an
// absolute filesystem path relative to userRoot. Returns "" for the root itself.
func davRelCanonicalFromFS(userRoot, fsAbs string) (string, error) {
	rootAbs, err := davAbsClean(userRoot)
	if err != nil {
		return "", err
	}

	target, err := davAbsClean(fsAbs)
	if err != nil {
		return "", err
	}

	rel, err := filepath.Rel(rootAbs, target)
	if err != nil {
		return "", err
	}
	if rel == "." {
		return "", nil
	}
	if err := davAssertUnderRoot(rootAbs, target); err != nil {
		return "", err
	}
	return filepath.ToSlash(rel), nil
}

// MapDAVRequestToFS maps the request URL to an absolute filesystem path inside
// userRoot, returning the canonical DAV-relative path and a collection hint.
// relCanon is "" when the request targets the root.
func MapDAVRequestToFS(urlPath string, userRoot string, username string) (fsAbs string, relCanon string, isCollectionPath bool, err error) {
	relRaw, isCollectionPath, err := davExtractRelFromReqPath(urlPath, username)
	if err != nil {
		return "", "", false, err
	}

	fsAbs, err = davResolveRelToFS(userRoot, relRaw)
	if err != nil {
		return "", "", isCollectionPath, err
	}

	relCanon, err = davRelCanonicalFromFS(userRoot, fsAbs)
	if err != nil {
		return "", "", isCollectionPath, err
	}

	return fsAbs, relCanon, isCollectionPath, nil
}

func ParentPaths(relCanon string) []string {
	relCanon = strings.Trim(relCanon, "/")
	if relCanon == "" {
		return nil
	}

	paths := []string{""}
	var parents []string
	for p := path.Dir(relCanon); p != "." && p != "/"; p = path.Dir(p) {
		parents = append(parents, p)
	}
	for i := len(parents) - 1; i >= 0; i-- {
		paths = append(paths, parents[i])
	}
	return paths
}
