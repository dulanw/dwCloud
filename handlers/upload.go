package handlers

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
)

// chunk uploads
type WebDAVUpload struct {
	WebDAV

	userUpload string
}

type uploadSessionMeta struct {
	Destination string `json:"destination"`
	TotalLength int64  `json:"total_length"`
}

func uploadSessionMetaPath(sessionDir string) string {
	return filepath.Join(sessionDir, ".meta")
}

func writeUploadSessionMeta(sessionDir string, meta uploadSessionMeta) error {
	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return os.WriteFile(uploadSessionMetaPath(sessionDir), append(data, '\n'), 0o640)
}

func readUploadSessionMeta(sessionDir string) (uploadSessionMeta, error) {
	data, err := os.ReadFile(uploadSessionMetaPath(sessionDir))
	if err != nil {
		return uploadSessionMeta{}, err
	}
	var meta uploadSessionMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return uploadSessionMeta{}, err
	}
	return meta, nil
}

func cleanUploadSegment(value, label string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", echo.NewHTTPError(http.StatusBadRequest, "missing "+label)
	}
	if value == "." || value == ".." ||
		strings.Contains(value, ":") ||
		strings.ContainsAny(value, `/\`) ||
		filepath.IsAbs(value) ||
		filepath.VolumeName(value) != "" {
		return "", echo.NewHTTPError(http.StatusBadRequest, "invalid "+label)
	}
	return value, nil
}

func (h *Handler) WebDAVUploadHandler(c *echo.Context) error {
	username, user, err := h.getUserFromBasicAuth(c)
	if err != nil {
		return err
	}

	userRoot, err := ensureUserDir(h.app.Cfg.StorageDir, user.StorageDir)
	if err != nil {
		return err
	}

	userUpload, err := ensureUserDir(h.app.Cfg.UploadDir, user.StorageDir)
	if err != nil {
		return err
	}

	w := &WebDAVUpload{
		WebDAV: WebDAV{
			h:        h,
			db:       h.app.State.Db,
			username: username,
			user:     user,
			userRoot: userRoot,
		},
		userUpload: userUpload,
	}

	return w.serveNativeWebDAVUpload(c)
}

func (w *WebDAVUpload) serveNativeWebDAVUpload(c *echo.Context) error {
	switch c.Request().Method {
	case "PROPFIND":
		return w.handleDAVUploadPropfind(c)
	case "PUT":
		return w.handleDAVUploadPut(c)
	case "MKCOL":
		return w.handleDAVUploadMkcol(c)
	case "MOVE":
		return w.handleDAVUploadMove(c)
	default:
		return c.NoContent(http.StatusMethodNotAllowed)
	}
}

func (w *WebDAVUpload) handleDAVUploadMkcol(c *echo.Context) error {
	transferID, err := cleanUploadSegment(c.Param("transferID"), "transfer ID")
	if err != nil {
		return err
	}

	destination := strings.TrimSpace(c.Request().Header.Get("Destination"))
	if destination == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing Destination header")
	}
	totalLength := strings.TrimSpace(c.Request().Header.Get("OC-Total-Length"))
	if totalLength == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing OC-Total-Length header")
	}
	totalBytes, err := strconv.ParseInt(totalLength, 10, 64)
	if err != nil || totalBytes < 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid OC-Total-Length header")
	}

	destURL, err := url.Parse(destination)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid Destination header")
	}
	_, destRelCanon, _, err := w.mapDAVRequestToFS(destURL.Path)
	if err != nil {
		return err
	}
	if destRelCanon == "" {
		return echo.NewHTTPError(http.StatusForbidden, "cannot assemble to root")
	}

	sessionDir := filepath.Join(w.userUpload, transferID)
	if err := os.MkdirAll(sessionDir, 0o750); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	if err := writeUploadSessionMeta(sessionDir, uploadSessionMeta{
		Destination: destination,
		TotalLength: totalBytes,
	}); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return c.NoContent(http.StatusCreated)
}

func (w *WebDAVUpload) handleDAVUploadPut(c *echo.Context) error {
	transferID, err := cleanUploadSegment(c.Param("transferID"), "transfer ID")
	if err != nil {
		return err
	}
	chunkName, err := cleanUploadSegment(c.Param("chunkName"), "chunk name")
	if err != nil {
		return err
	}

	sessionDir := filepath.Join(w.userUpload, transferID)
	if _, err := os.Stat(sessionDir); err != nil {
		if os.IsNotExist(err) {
			return echo.NewHTTPError(http.StatusNotFound, "upload session not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	chunkPath := filepath.Join(sessionDir, chunkName)
	f, err := os.OpenFile(chunkPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	_, copyErr := io.Copy(f, c.Request().Body)
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(chunkPath)
		return echo.NewHTTPError(http.StatusInternalServerError, copyErr.Error())
	}
	if closeErr != nil {
		_ = os.Remove(chunkPath)
		return echo.NewHTTPError(http.StatusInternalServerError, closeErr.Error())
	}

	return c.NoContent(http.StatusCreated)
}

func (w *WebDAVUpload) handleDAVUploadMove(c *echo.Context) error {
	transferID, err := cleanUploadSegment(c.Param("transferID"), "transfer ID")
	if err != nil {
		return err
	}

	destHeader := strings.TrimSpace(c.Request().Header.Get("Destination"))
	if destHeader == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing Destination header")
	}

	destURL, err := url.Parse(destHeader)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid Destination header")
	}

	destFsAbs, destRelCanon, _, err := w.mapDAVRequestToFS(destURL.Path)
	if err != nil {
		return err
	}
	if destRelCanon == "" {
		return echo.NewHTTPError(http.StatusForbidden, "cannot assemble to root")
	}

	ocChecksum := strings.TrimSpace(c.Request().Header.Get("OC-Checksum"))
	xOCMtime := strings.TrimSpace(c.Request().Header.Get("X-OC-Mtime"))

	// Collect and sort chunks.
	sessionDir := filepath.Join(w.userUpload, transferID)
	meta, err := readUploadSessionMeta(sessionDir)
	if err != nil {
		if os.IsNotExist(err) {
			return echo.NewHTTPError(http.StatusBadRequest, "upload session metadata missing")
		}
		return echo.NewHTTPError(http.StatusBadRequest, "upload session metadata invalid")
	}
	if strings.TrimSpace(meta.Destination) != "" {
		metaDestURL, err := url.Parse(meta.Destination)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "upload session destination invalid")
		}
		_, metaDestRelCanon, _, err := w.mapDAVRequestToFS(metaDestURL.Path)
		if err != nil {
			return err
		}
		if metaDestRelCanon != destRelCanon {
			return echo.NewHTTPError(http.StatusConflict, "upload destination does not match session")
		}
	}

	entries, err := os.ReadDir(sessionDir)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	var chunks []string
	for _, e := range entries {
		if name := e.Name(); name != ".meta" && name != ".file" {
			chunks = append(chunks, name)
		}
	}
	sort.Strings(chunks)
	if len(chunks) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "no chunks found")
	}

	// Assemble chunks into a temp file.
	tmpName := destFsAbs + ".tmp." + strconv.FormatInt(time.Now().UnixNano(), 36)
	tmp, err := os.OpenFile(tmpName, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	hasher := sha1.New()
	var assembledBytes int64
	for _, chunkName := range chunks {
		cf, err := os.Open(filepath.Join(sessionDir, chunkName))
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
		n, copyErr := io.Copy(io.MultiWriter(tmp, hasher), cf)
		assembledBytes += n
		_ = cf.Close()
		if copyErr != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
			return echo.NewHTTPError(http.StatusInternalServerError, copyErr.Error())
		}
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	if assembledBytes != meta.TotalLength {
		_ = os.Remove(tmpName)
		return echo.NewHTTPError(http.StatusBadRequest, "assembled upload size does not match OC-Total-Length")
	}

	gotSHA1 := hex.EncodeToString(hasher.Sum(nil))

	if ocChecksum != "" {
		parts := strings.SplitN(ocChecksum, ":", 2)
		if len(parts) != 2 || !strings.EqualFold(strings.TrimSpace(parts[0]), "SHA1") {
			_ = os.Remove(tmpName)
			return c.NoContent(http.StatusBadRequest)
		}
		if strings.ToLower(strings.TrimSpace(parts[1])) != gotSHA1 {
			_ = os.Remove(tmpName)
			return c.NoContent(http.StatusPreconditionFailed)
		}
	}

	ctx := c.Request().Context()
	conn, err := w.db.Connx(ctx)
	if err != nil {
		_ = os.Remove(tmpName)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() { _ = conn.Close() }()

	var sessionLocks davSessionLocks
	defer w.unlockDAVSessionLocks(conn, &sessionLocks)

	if err := w.acquireFileLocks(conn, ctx, destRelCanon, filepath.Dir(destFsAbs), &sessionLocks); err != nil {
		_ = os.Remove(tmpName)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	tx, err := conn.BeginTxx(ctx, nil)
	if err != nil {
		_ = os.Remove(tmpName)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() { _ = tx.Rollback() }()

	result, err := w.publishFile(ctx, tx, destFsAbs, tmpName, destRelCanon, gotSHA1, xOCMtime)
	if err != nil {
		_ = os.Remove(tmpName)
		var httpErr *echo.HTTPError
		if errors.As(err, &httpErr) {
			return err
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	if err := w.h.app.State.Previews.Enqueue(result.OCID); err != nil {
		slog.Warn("failed to queue preview after chunked DAV upload", "path", destRelCanon, "ocid", result.OCID, "error", err)
	}

	_ = os.RemoveAll(sessionDir)

	etag := etagFromOCIDVersion(result.OCID, result.Version)
	c.Response().Header().Set("ETag", etag)
	c.Response().Header().Set("OC-ETag", etag)
	c.Response().Header().Set("OC-Fileid", result.OCID)
	c.Response().Header().Set("X-OC-Mtime", "accepted")

	if result.Existed {
		return c.NoContent(http.StatusNoContent)
	}
	return c.NoContent(http.StatusCreated)
}

func (w *WebDAVUpload) handleDAVUploadPropfind(c *echo.Context) error {
	transferID, err := cleanUploadSegment(c.Param("transferID"), "transfer ID")
	if err != nil {
		return err
	}

	sessionDir := filepath.Join(w.userUpload, transferID)
	if _, err := os.Stat(sessionDir); err != nil {
		if os.IsNotExist(err) {
			return echo.NewHTTPError(http.StatusNotFound, "upload session not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	entries, err := os.ReadDir(sessionDir)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	type xmlResourceType struct {
		Collection *struct{} `xml:"DAV: collection,omitempty"`
	}
	type xmlProp struct {
		ResourceType  *xmlResourceType `xml:"DAV: resourcetype,omitempty"`
		ContentLength *string          `xml:"DAV: getcontentlength,omitempty"`
	}
	type xmlPropstat struct {
		Prop   xmlProp `xml:"DAV: prop"`
		Status string  `xml:"DAV: status"`
	}
	type xmlResponse struct {
		Href     string        `xml:"DAV: href"`
		Propstat []xmlPropstat `xml:"DAV: propstat"`
	}
	type xmlMultistatus struct {
		XMLName   xml.Name      `xml:"DAV: multistatus"`
		XmlnsD    string        `xml:"xmlns:d,attr"`
		XmlnsS    string        `xml:"xmlns:s,attr"`
		XmlnsOC   string        `xml:"xmlns:oc,attr"`
		XmlnsNC   string        `xml:"xmlns:nc,attr"`
		Responses []xmlResponse `xml:"DAV: response"`
	}

	basePath := c.Request().URL.Path
	if !strings.HasSuffix(basePath, "/") {
		basePath += "/"
	}

	strPtr := func(s string) *string { return &s }

	responses := []xmlResponse{
		// The session directory itself — resourcetype=collection, no contentlength
		{
			Href: basePath,
			Propstat: []xmlPropstat{
				// Directory - 200 propstat: resourcetype=collection, no contentlength
				{
					Prop:   xmlProp{ResourceType: &xmlResourceType{Collection: &struct{}{}}},
					Status: "HTTP/1.1 200 OK",
				},
				// Directory - 404 propstat: only contentlength missing
				{
					Prop:   xmlProp{ContentLength: nil}, // ResourceType omitted
					Status: "HTTP/1.1 404 Not Found",
				},
			},
		},
	}

	for _, e := range entries {
		name := e.Name()
		if name == ".meta" {
			continue // internal only, don't expose
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		size := strPtr(strconv.FormatInt(info.Size(), 10))
		responses = append(responses, xmlResponse{
			Href: basePath + name,
			Propstat: []xmlPropstat{
				{
					Prop: xmlProp{
						ResourceType:  &xmlResourceType{}, // emits <d:resourcetype/> but no collection
						ContentLength: size,
					},
					Status: "HTTP/1.1 200 OK",
				},
			},
		})
	}

	ms := xmlMultistatus{
		XmlnsD:    "DAV:",
		XmlnsS:    "http://sabredav.org/ns",
		XmlnsOC:   "http://owncloud.org/ns",
		XmlnsNC:   "http://nextcloud.org/ns",
		Responses: responses,
	}

	out, err := xml.Marshal(ms)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	c.Response().Header().Set("DAV", strings.Join([]string{
		"1", "3", "extended-mkcol", "access-control",
		"calendarserver-principal-property-search",
		"nc-paginate", "nextcloud-checksum-update",
		"nc-calendar-search", "nc-enable-birthday-calendar",
	}, ", "))

	payload := append([]byte(xml.Header), out...)
	return c.Blob(http.StatusMultiStatus, "application/xml; charset=utf-8", payload)

}
