package handlers

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"database/sql"
	"dwCloud/types"
	"dwCloud/utils"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo/v5"
)

type WebDAV struct {
	h        *Handler
	db       *sqlx.DB
	username *string
	user     *types.DbUser
	userRoot string
}

func (w *WebDAV) mapDAVRequestToFS(urlPath string) (fsAbs string, relCanon string, isCollectionPath bool, err error) {
	return utils.MapDAVRequestToFS(urlPath, w.userRoot, w.user.Username)
}

func ensureUserDir(baseDir, userSubDir string) (string, error) {
	base := filepath.Clean(baseDir)
	userDir := filepath.Clean(filepath.Join(base, userSubDir))

	rel, err := filepath.Rel(base, userDir)
	if err != nil {
		return "", echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	if rel == "." || strings.HasPrefix(rel, "..") {
		return "", echo.NewHTTPError(http.StatusForbidden, "invalid user directory")
	}

	if err := os.MkdirAll(userDir, 0o750); err != nil {
		return "", echo.NewHTTPError(http.StatusInternalServerError, "failed to create user directory")
	}

	return userDir, nil
}

func (h *Handler) WebDAVHandler(c *echo.Context) error {
	username, user, err := h.getUserFromBasicAuth(c)
	if err != nil {
		return err
	}

	// Resolve user root on disk and harden against traversal.
	userRoot, err := ensureUserDir(h.app.Cfg.StorageDir, user.StorageDir)
	if err != nil {
		return err
	}

	w := &WebDAV{
		h:        h,
		db:       h.app.State.Db,
		username: username,
		user:     user,
		userRoot: userRoot,
	}
	return w.serveNativeWebDAV(c)
}

func (w *WebDAV) serveNativeWebDAV(c *echo.Context) error {
	switch c.Request().Method {
	case "PROPFIND":
		return w.handleDAVPropfind(c)
	case "HEAD":
		return w.handleDAVHead(c)
	case http.MethodGet:
		return w.handleDAVGet(c)
	case "PUT":
		return w.handleDAVPut(c)
	case "MKCOL":
		return w.handleDAVMkcol(c)
	case "DELETE":
		return w.handleDAVDelete(c)
	case "MOVE":
		return w.handleDAVMove(c)
	case "COPY":
		return w.handleDAVCopy(c)
	case "PROPPATCH":
		return w.handleDAVProppatch(c)
	case "LOCK":
		return w.handleDAVLock(c)
	case "UNLOCK":
		return w.handleDAVUnlock(c)
	case "OPTIONS":
		return w.handleDAVOptions(c)

	case "REPORT":
		// Nextcloud may probe these; returning 501 is generally safer than 405.
		return c.NoContent(http.StatusNotImplemented)
	default:
		return c.NoContent(http.StatusMethodNotAllowed)
	}
}

func davLockKey(userID uuid.UUID, relCanon string) int64 {
	h := fnv.New64a()
	_, _ = h.Write(userID[:])
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(relCanon))
	return int64(h.Sum64())
}

type davSessionLocks struct {
	exclusive []int64
	shared    []int64
}

func (w *WebDAV) acquireFileLocks(conn *sqlx.Conn, ctx context.Context, relCanon string, parentAbs string, locks *davSessionLocks) error {
	if _, err := os.Stat(parentAbs); err != nil {
		if os.IsNotExist(err) {
			return echo.NewHTTPError(http.StatusConflict, "parent directory does not exist")
		}
		return err
	}

	ancestors := utils.ParentPaths(relCanon)
	exclusive := []string{relCanon}
	return w.lockDAVSessionLocks(conn, ctx, exclusive, ancestors, locks)
}

func (w *WebDAV) lockDAVSessionLocks(conn *sqlx.Conn, ctx context.Context, exclusive []string, shared []string, locks *davSessionLocks) error {

	// Exclusive session locks.
	for _, p := range exclusive {
		key := davLockKey(w.user.ID, p)
		if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, key); err != nil {
			return err
		}
		locks.exclusive = append(locks.exclusive, key)
	}

	// Shared session locks.
	for _, p := range shared {
		key := davLockKey(w.user.ID, p)
		if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock_shared($1)`, key); err != nil {
			return err
		}
		locks.shared = append(locks.shared, key)
	}

	return nil
}

func (w *WebDAV) unlockDAVSessionLocks(conn *sqlx.Conn, locks *davSessionLocks) {
	if len(locks.exclusive) == 0 && len(locks.shared) == 0 {
		return
	}

	unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for i := len(locks.exclusive) - 1; i >= 0; i-- {
		if _, err := conn.ExecContext(unlockCtx, `SELECT pg_advisory_unlock($1)`, locks.exclusive[i]); err != nil {
			slog.Warn("failed to release DAV exclusive session advisory lock", "error", err)
		}
	}

	for i := len(locks.shared) - 1; i >= 0; i-- {
		if _, err := conn.ExecContext(unlockCtx, `SELECT pg_advisory_unlock_shared($1)`, locks.shared[i]); err != nil {
			slog.Warn("failed to release DAV shared session advisory lock", "error", err)
		}
	}
}

// etagFromOCIDVersion returns a Nextcloud-looking strong ETag.
// It is stable across rename as long as ocid stays stable and a version doesn't change.
func etagFromOCIDVersion(ocid string, version int64) string {
	seed := fmt.Sprintf("%s:%d", ocid, version)
	sum := md5.Sum([]byte(seed))
	hex32 := hex.EncodeToString(sum[:])

	return `"` + hex32 + `"`
}

func davContentType(entry *types.DbFile) string {
	if entry.IsDir {
		return "httpd/unix-directory"
	}

	if contentType := mime.TypeByExtension(path.Ext(entry.Path)); contentType != "" {
		return contentType
	}
	return "application/octet-stream"
}

func normalizeETag(etag string) string {
	etag = strings.TrimSpace(etag)
	etag = strings.TrimPrefix(etag, "W/")
	return strings.Trim(etag, `"`)
}

func etagHeaderMatches(header, current string) bool {
	current = normalizeETag(current)
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || normalizeETag(candidate) == current {
			return true
		}
	}
	return false
}

func davModTime(entry *types.DbFile) time.Time {
	if entry == nil || entry.Mtime.IsZero() {
		return time.Unix(0, 0).UTC()
	}
	return entry.Mtime.UTC()
}

func davPathIsDescendant(parent, child string) bool {
	parent = strings.Trim(parent, "/")
	child = strings.Trim(child, "/")
	return parent != "" && strings.HasPrefix(child, parent+"/")
}

func normalizeDAVDepth(raw, defaultDepth string, allowed ...string) (string, error) {
	depth := strings.ToLower(strings.TrimSpace(raw))
	if depth == "" {
		depth = defaultDepth
	}
	for _, value := range allowed {
		if depth == value {
			return depth, nil
		}
	}
	return "", echo.NewHTTPError(http.StatusBadRequest, "invalid Depth header")
}

func getFileRow(ctx context.Context, db *sqlx.DB, userID uuid.UUID, relCanon string) (*types.DbFile, error) {
	var row types.DbFile
	if err := db.GetContext(ctx, &row, `
		SELECT *
		FROM files
		WHERE user_id = $1 AND path = $2
		LIMIT 1
	`, userID, relCanon); err != nil {
		return nil, err
	}
	return &row, nil
}

func getFileChildren(ctx context.Context, db *sqlx.DB, userID uuid.UUID, relCanon string) ([]types.DbFile, error) {
	// Match direct children only: path starts with "<relCanon>/" but has no further slash.
	// Root case: relCanon == "" means children are top-level paths with no slash.
	var rows []types.DbFile

	var err error
	if relCanon == "" {
		err = db.SelectContext(ctx, &rows, `
			SELECT *
			FROM files
			WHERE user_id = $1
			  AND path != ''
			  AND path NOT LIKE '%/%'
    	`, userID)
	} else {
		err = db.SelectContext(ctx, &rows, `
			SELECT *
			FROM files
			WHERE user_id = $1
			  AND LEFT(path, length($2) + 1) = $2 || '/'
			  AND POSITION('/' IN SUBSTRING(path FROM length($2) + 2)) = 0
    	`, userID, relCanon)
	}

	if err != nil {
		return nil, err
	}
	return rows, nil
}

func getFileChildCounts(ctx context.Context, db *sqlx.DB, userID uuid.UUID, relCanon string) (int, int, error) {
	type childCounts struct {
		Folders int `db:"folders"`
		Files   int `db:"files"`
	}

	var counts childCounts
	var err error
	if relCanon == "" {
		err = db.GetContext(ctx, &counts, `
			SELECT
				COUNT(*) FILTER (WHERE is_dir) AS folders,
				COUNT(*) FILTER (WHERE NOT is_dir) AS files
			FROM files
			WHERE user_id = $1
			  AND path != ''
			  AND path NOT LIKE '%/%'
		`, userID)
	} else {
		err = db.GetContext(ctx, &counts, `
			SELECT
				COUNT(*) FILTER (WHERE is_dir) AS folders,
				COUNT(*) FILTER (WHERE NOT is_dir) AS files
			FROM files
			WHERE user_id = $1
			  AND LEFT(path, length($2) + 1) = $2 || '/'
			  AND POSITION('/' IN SUBSTRING(path FROM length($2) + 2)) = 0
		`, userID, relCanon)
	}
	if err != nil {
		return 0, 0, err
	}
	return counts.Folders, counts.Files, nil
}

// updateAncestorSizes adds delta (can be negative) to all ancestor directories.
// Call this inside a transaction after inserting/updating/deleting a file.
// relCanon is the file's path, delta is new_size - old_size.
func updateAncestorSizes(ctx context.Context, tx *sqlx.Tx, userID uuid.UUID, relCanon string, delta int64) ([]types.DbFile, error) {
	if delta == 0 {
		return nil, nil
	}
	var rows []types.DbFile
	err := tx.SelectContext(ctx, &rows, `
		UPDATE files
		SET size_bytes = size_bytes + $3,
			updated_at = NOW()
		WHERE user_id = $1
		  AND is_dir = true
		  AND (path = '' OR (path <> '' AND LEFT($2, length(path) + 1) = path || '/'))
		RETURNING *
	`, userID, relCanon, delta)
	return rows, err
}

func fileTreeSizeTx(ctx context.Context, tx *sqlx.Tx, userID uuid.UUID, relCanon string) (int64, error) {
	var size int64
	err := tx.QueryRowxContext(ctx, `
		SELECT COALESCE(size_bytes, 0)
		FROM files
		WHERE user_id = $1 AND path = $2
	`, userID, relCanon).Scan(&size)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return size, err
}

func quotaExceeded(delta, used, quota int64) *echo.HTTPError {
	return echo.NewHTTPError(http.StatusInsufficientStorage, fmt.Sprintf("quota exceeded: need %d more bytes, used %d of %d", delta, used, quota))
}

func (w *WebDAV) userRootSizeLockedTx(ctx context.Context, tx *sqlx.Tx) (int64, error) {
	var used int64
	err := tx.QueryRowxContext(ctx, `
		SELECT COALESCE(size_bytes, 0)
		FROM files
		WHERE user_id = $1 AND path = ''
		FOR UPDATE
	`, w.user.ID).Scan(&used)
	if err == nil {
		return used, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}

	err = tx.QueryRowxContext(ctx, `
		WITH usage AS (
			SELECT COALESCE(SUM(size_bytes), 0)::bigint AS used
			FROM files
			WHERE user_id = $1 AND is_dir = false
		)
		INSERT INTO files (user_id, path, is_dir, ocid, version, size_bytes, mtime, created_at, updated_at)
		SELECT $1, '', true, '', 1, used, NOW(), NOW(), NOW()
		FROM usage
		ON CONFLICT (user_id, path) DO UPDATE
		SET size_bytes = EXCLUDED.size_bytes,
			updated_at = NOW()
		RETURNING size_bytes
	`, w.user.ID).Scan(&used)
	return used, err
}

func (w *WebDAV) enforceQuotaDeltaTx(ctx context.Context, tx *sqlx.Tx, delta int64) error {
	if delta <= 0 {
		return nil
	}

	used, err := w.userRootSizeLockedTx(ctx, tx)
	if err != nil {
		return err
	}
	if delta > w.user.QuotaBytes-used {
		return quotaExceeded(delta, used, w.user.QuotaBytes)
	}
	return nil
}

func backupExistingPath(fsPath string) (string, error) {
	backup := fsPath + ".bak." + strconv.FormatInt(time.Now().UnixNano(), 36)
	if err := os.Rename(fsPath, backup); err != nil {
		return "", err
	}
	return backup, nil
}

func restoreBackedUpPath(target, backup string) {
	_ = os.RemoveAll(target)
	if backup != "" {
		_ = os.Rename(backup, target)
	}
}

type davIfHeader struct {
	lists []davIfList
}

type davIfList struct {
	resourceTag string
	conditions  []davIfCondition
}

type davIfCondition struct {
	not   bool
	token string
	etag  string
}

type davLockRow struct {
	Token string `db:"token"`
	Depth string `db:"depth"`
	Path  string `db:"path"`
}

const (
	davIfErrToken    rune = -1
	davIfEOFToken    rune = -2
	davIfStringToken rune = -3
	davIfNotToken    rune = -4
	davIfAngleToken  rune = -5
	davIfSquareToken rune = -6
)

func parseDAVIfHeader(httpHeader string) (davIfHeader, bool) {
	s := strings.TrimSpace(httpHeader)
	switch tokenType, _, _ := lexDAVIf(s); tokenType {
	case '(':
		return parseDAVIfNoTagLists(s)
	case davIfAngleToken:
		return parseDAVIfTaggedLists(s)
	default:
		return davIfHeader{}, false
	}
}

func parseDAVIfNoTagLists(s string) (davIfHeader, bool) {
	var h davIfHeader
	for {
		l, remaining, ok := parseDAVIfList(s)
		if !ok {
			return davIfHeader{}, false
		}
		h.lists = append(h.lists, l)
		if remaining == "" {
			return h, true
		}
		s = remaining
	}
}

func parseDAVIfTaggedLists(s string) (davIfHeader, bool) {
	var h davIfHeader
	resourceTag := ""
	listsAfterTag := 0
	for first := true; ; first = false {
		tokenType, tokenStr, remaining := lexDAVIf(s)
		switch tokenType {
		case davIfAngleToken:
			if !first && listsAfterTag == 0 {
				return davIfHeader{}, false
			}
			resourceTag = tokenStr
			listsAfterTag = 0
			s = remaining
		case '(':
			listsAfterTag++
			l, remaining, ok := parseDAVIfList(s)
			if !ok {
				return davIfHeader{}, false
			}
			l.resourceTag = resourceTag
			h.lists = append(h.lists, l)
			if remaining == "" {
				return h, true
			}
			s = remaining
		default:
			return davIfHeader{}, false
		}
	}
}

func parseDAVIfList(s string) (davIfList, string, bool) {
	tokenType, _, s := lexDAVIf(s)
	if tokenType != '(' {
		return davIfList{}, "", false
	}

	var l davIfList
	for {
		tokenType, _, remaining := lexDAVIf(s)
		if tokenType == ')' {
			if len(l.conditions) == 0 {
				return davIfList{}, "", false
			}
			return l, remaining, true
		}

		c, remaining, ok := parseDAVIfCondition(s)
		if !ok {
			return davIfList{}, "", false
		}
		l.conditions = append(l.conditions, c)
		s = remaining
	}
}

func parseDAVIfCondition(s string) (davIfCondition, string, bool) {
	tokenType, tokenStr, remaining := lexDAVIf(s)
	c := davIfCondition{}
	if tokenType == davIfNotToken {
		c.not = true
		tokenType, tokenStr, remaining = lexDAVIf(remaining)
	}

	switch tokenType {
	case davIfStringToken, davIfAngleToken:
		c.token = tokenStr
	case davIfSquareToken:
		c.etag = tokenStr
	default:
		return davIfCondition{}, "", false
	}
	return c, remaining, true
}

func lexDAVIf(s string) (tokenType rune, tokenStr string, remaining string) {
	for len(s) > 0 && (s[0] == '\t' || s[0] == ' ') {
		s = s[1:]
	}
	if len(s) == 0 {
		return davIfEOFToken, "", ""
	}

	i := 0
	for ; i < len(s); i++ {
		switch s[i] {
		case '\t', ' ', '(', ')', '<', '>', '[', ']':
			goto done
		}
	}

done:
	if i != 0 {
		tokenStr, remaining = s[:i], s[i:]
		if tokenStr == "Not" {
			return davIfNotToken, "", remaining
		}
		return davIfStringToken, tokenStr, remaining
	}

	switch s[0] {
	case '<':
		j := strings.IndexByte(s, '>')
		if j < 0 {
			return davIfErrToken, "", ""
		}
		return davIfAngleToken, s[1:j], s[j+1:]
	case '[':
		j := strings.IndexByte(s, ']')
		if j < 0 {
			return davIfErrToken, "", ""
		}
		return davIfSquareToken, s[1:j], s[j+1:]
	default:
		return rune(s[0]), "", s[1:]
	}
}

func currentDAVETagTx(ctx context.Context, tx *sqlx.Tx, userID uuid.UUID, relCanon string) (string, error) {
	var row struct {
		OCID    string `db:"ocid"`
		Version int64  `db:"version"`
	}
	err := tx.QueryRowxContext(ctx, `
		SELECT ocid, version
		FROM files
		WHERE user_id = $1 AND path = $2
	`, userID, relCanon).StructScan(&row)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return etagFromOCIDVersion(row.OCID, row.Version), nil
}

func evaluateDAVIfHeader(lists []davIfList, currentETag string, activeTokens map[string]struct{}) (bool, int) {
	activeLockCount := len(activeTokens)
	failureStatus := 0
	recordFailure := func(status int) {
		if status == 0 {
			return
		}
		if status == http.StatusPreconditionFailed || failureStatus == 0 {
			failureStatus = status
		}
	}

	for _, list := range lists {
		listOK := true
		listHasActivePositiveToken := false
		listFailureStatus := 0

		for _, condition := range list.conditions {
			conditionOK := false
			conditionFailureStatus := http.StatusPreconditionFailed

			switch {
			case condition.token != "":
				_, tokenActive := activeTokens[condition.token]
				conditionOK = tokenActive
				if !condition.not && tokenActive {
					listHasActivePositiveToken = true
				}
				if condition.not {
					conditionOK = !conditionOK
				}
				if !conditionOK && activeLockCount > 0 && !condition.not && condition.token != "DAV:no-lock" {
					conditionFailureStatus = http.StatusLocked
				}
			case condition.etag != "":
				conditionOK = currentETag != "" && etagHeaderMatches(condition.etag, currentETag)
				if condition.not {
					conditionOK = !conditionOK
				}
			}

			if !conditionOK {
				listOK = false
				if conditionFailureStatus == http.StatusPreconditionFailed || listFailureStatus == 0 {
					listFailureStatus = conditionFailureStatus
				}
			}
		}

		if listOK {
			if activeLockCount == 0 || listHasActivePositiveToken {
				return true, 0
			}
			recordFailure(http.StatusLocked)
			continue
		}

		recordFailure(listFailureStatus)
	}

	if failureStatus == 0 {
		failureStatus = http.StatusPreconditionFailed
	}
	return false, failureStatus
}

func activeDAVLockTokenSet(tokens []string) map[string]struct{} {
	set := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		set[token] = struct{}{}
	}
	return set
}

func davLockCoversRel(lockPath, depth, relCanon string) bool {
	return lockPath == relCanon || (depth == "infinity" && (lockPath == "" || davPathIsDescendant(lockPath, relCanon)))
}

func davTaggedListRelApplies(tagRelCanon, relCanon string, locks []davLockRow) bool {
	if tagRelCanon == relCanon {
		return true
	}
	for _, lock := range locks {
		if lock.Path == tagRelCanon && davLockCoversRel(lock.Path, lock.Depth, relCanon) {
			return true
		}
	}
	return false
}

func (w *WebDAV) davIfListAppliesToRel(list davIfList, relCanon string, locks []davLockRow) bool {
	if list.resourceTag == "" {
		return true
	}

	resourceURL, err := url.Parse(list.resourceTag)
	if err != nil || resourceURL.Path == "" {
		return false
	}
	_, tagRelCanon, _, err := w.mapDAVRequestToFS(resourceURL.Path)
	if err != nil {
		return false
	}
	return davTaggedListRelApplies(tagRelCanon, relCanon, locks)
}

func extractLockToken(ifHeader string) string {
	// Find any urn:uuid: or opaquelocktoken: URI inside angle brackets
	for _, prefix := range []string{"urn:uuid:", "opaquelocktoken:"} {
		idx := strings.Index(ifHeader, prefix)
		if idx == -1 {
			continue
		}
		// Find the opening < before the prefix
		start := strings.LastIndex(ifHeader[:idx], "<")
		if start == -1 {
			continue
		}
		end := strings.Index(ifHeader[start:], ">")
		if end == -1 {
			continue
		}
		return ifHeader[start+1 : start+end]
	}
	return ""
}

func (w *WebDAV) checkLockTx(ctx context.Context, tx *sqlx.Tx, relCanon string, ifHeader string) error {
	var locks []davLockRow
	err := tx.SelectContext(ctx, &locks, `
        SELECT token, depth, path FROM locks
        WHERE user_id = $1
          AND timeout_at > NOW()
          AND (
            path = $2
            OR (depth = 'infinity' AND (path = '' OR LEFT($2, length(path) + 1) = path || '/'))
          )
        FOR UPDATE
    `, w.user.ID, relCanon)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	locked := len(locks) > 0

	if strings.TrimSpace(ifHeader) != "" {
		parsedIf, ok := parseDAVIfHeader(ifHeader)
		if !ok {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid If header")
		}

		applicableLists := make([]davIfList, 0, len(parsedIf.lists))
		for _, list := range parsedIf.lists {
			if w.davIfListAppliesToRel(list, relCanon, locks) {
				applicableLists = append(applicableLists, list)
			}
		}

		currentETag, err := currentDAVETagTx(ctx, tx, w.user.ID, relCanon)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		activeTokens := make([]string, 0, len(locks))
		for _, lk := range locks {
			activeTokens = append(activeTokens, lk.Token)
		}
		if ok, status := evaluateDAVIfHeader(applicableLists, currentETag, activeDAVLockTokenSet(activeTokens)); !ok {
			return echo.NewHTTPError(status, "If header condition failed")
		}
		return nil
	}

	if !locked {
		return nil
	}

	return echo.NewHTTPError(http.StatusLocked, "resource is locked")
}

func (w *WebDAV) checkLockSubtreeTx(ctx context.Context, tx *sqlx.Tx, relCanon string, ifHeader string) error {
	presentedToken := extractLockToken(ifHeader)

	type lockRow struct {
		Token string `db:"token"`
	}

	var locks []lockRow
	err := tx.SelectContext(ctx, &locks, `
        SELECT token FROM locks
        WHERE user_id = $1
          AND timeout_at > NOW()
          AND (
            path = $2
            OR ($2 = '' OR LEFT(path, length($2) + 1) = $2 || '/')
            OR (depth = 'infinity' AND (path = '' OR LEFT($2, length(path) + 1) = path || '/'))
          )
        FOR UPDATE
    `, w.user.ID, relCanon)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	if len(locks) == 0 {
		if presentedToken != "" {
			// Token asserted but no lock exists
			return echo.NewHTTPError(http.StatusPreconditionFailed,
				"lock token does not match any active lock")
		}
		return nil
	}

	// There are locks in subtree
	if presentedToken == "" {
		return echo.NewHTTPError(http.StatusLocked,
			"resource or descendant is locked")
	}

	for _, lk := range locks {
		if lk.Token != presentedToken {
			return echo.NewHTTPError(http.StatusPreconditionFailed,
				"lock token does not match active subtree lock")
		}
	}

	return nil
}

func setDAVHeader(c *echo.Context) {
	c.Response().Header().Set("DAV", strings.Join([]string{
		"1", "2", "3", "extended-mkcol", "access-control",
		"calendarserver-principal-property-search",
		"nc-paginate", "nextcloud-checksum-update",
		"nc-calendar-search", "nc-enable-birthday-calendar",
	}, ", "))
}

func (w *WebDAV) handleDAVOptions(c *echo.Context) error {
	setDAVHeader(c)
	c.Response().Header().Set("Allow", "OPTIONS, GET, HEAD, DELETE, PROPFIND, PUT, PROPPATCH, COPY, MOVE, MKCOL, LOCK, UNLOCK")
	c.Response().Header().Set("MS-Author-Via", "DAV")
	return c.NoContent(http.StatusOK)
}

func (w *WebDAV) handleDAVPropfind(c *echo.Context) error {
	_, relCanon, _, err := w.mapDAVRequestToFS(c.Request().URL.Path)
	if err != nil {
		return err
	}

	ctx := c.Request().Context()
	selfEntry, err := getFileRow(ctx, w.db, w.user.ID, relCanon)
	if err != nil {
		return c.NoContent(http.StatusNotFound)
	}

	depth := strings.TrimSpace(c.Request().Header.Get("Depth"))
	if depth == "" {
		depth = "0"
	}
	listChildren := strings.EqualFold(depth, "1") || strings.EqualFold(depth, "infinity")

	type propfindProp struct {
		Any []xml.Name `xml:",any"`
	}
	type propfindReq struct {
		XMLName xml.Name      `xml:"propfind"`
		Prop    *propfindProp `xml:"prop"`
		Allprop *struct{}     `xml:"allprop"`
	}

	// limit body to avoid abuse; PROPFIND bodies are tiny
	var bodyBuf []byte
	if c.Request().Body != nil {
		bodyBuf, _ = io.ReadAll(io.LimitReader(c.Request().Body, 1<<20)) // 1 MiB
		_ = c.Request().Body.Close()

		// Replace with a no-op body so later code doesn't accidentally reread.
		c.Request().Body = io.NopCloser(bytes.NewReader(nil))
	}

	var pf propfindReq
	parsed := false
	if len(bytes.TrimSpace(bodyBuf)) > 0 {
		dec := xml.NewDecoder(bytes.NewReader(bodyBuf))
		for {
			tok, err := dec.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				return echo.NewHTTPError(http.StatusBadRequest, "invalid XML request body")
			}
			if se, ok := tok.(xml.StartElement); ok {
				for _, attr := range se.Attr {
					// Reject empty namespace prefix declarations e.g. xmlns:ns1=""
					if attr.Name.Space == "xmlns" && attr.Value == "" {
						return echo.NewHTTPError(http.StatusBadRequest, "invalid namespace declaration: empty namespace URI")
					}
				}
			}
		}

		if err := xml.Unmarshal(bodyBuf, &pf); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid XML request body")
		}
		parsed = true
	}

	type qname struct {
		Space string
		Local string
	}
	reqSet := map[qname]bool{}

	// If client sent no body, treat it as "request common props".
	// If client sent <allprop/>, treat it as "request common props".
	requestCommon := !parsed || pf.Allprop != nil || pf.Prop == nil || len(pf.Prop.Any) == 0
	if !requestCommon {
		for _, n := range pf.Prop.Any {
			reqSet[qname{Space: n.Space, Local: n.Local}] = true
		}
	}

	asked := func(space, local string) bool {
		if requestCommon {
			return true
		}
		return reqSet[qname{Space: space, Local: local}]
	}

	handledLiveProps := map[qname]bool{
		{Space: "DAV:", Local: "resourcetype"}:          true,
		{Space: "DAV:", Local: "getlastmodified"}:       true,
		{Space: "DAV:", Local: "getetag"}:               true,
		{Space: "DAV:", Local: "getcontentlength"}:      true,
		{Space: "DAV:", Local: "getcontenttype"}:        true,
		{Space: "DAV:", Local: "quota-available-bytes"}: true,
		{Space: "DAV:", Local: "quota-used-bytes"}:      true,

		{Space: "http://owncloud.org/ns", Local: "size"}:               true,
		{Space: "http://owncloud.org/ns", Local: "id"}:                 true,
		{Space: "http://owncloud.org/ns", Local: "fileid"}:             true,
		{Space: "http://owncloud.org/ns", Local: "permissions"}:        true,
		{Space: "http://owncloud.org/ns", Local: "downloadURL"}:        true,
		{Space: "http://owncloud.org/ns", Local: "dDC"}:                true,
		{Space: "http://owncloud.org/ns", Local: "checksums"}:          true,
		{Space: "http://owncloud.org/ns", Local: "data-fingerprint"}:   true,
		{Space: "http://owncloud.org/ns", Local: "share-types"}:        true,
		{Space: "http://owncloud.org/ns", Local: "favorite"}:           true,
		{Space: "http://owncloud.org/ns", Local: "comments-unread"}:    true,
		{Space: "http://owncloud.org/ns", Local: "owner-id"}:           true,
		{Space: "http://owncloud.org/ns", Local: "owner-display-name"}: true,

		{Space: "http://nextcloud.org/ns", Local: "share-attributes"}:          true,
		{Space: "http://nextcloud.org/ns", Local: "is-mount-root"}:             true,
		{Space: "http://nextcloud.org/ns", Local: "is-encrypted"}:              true,
		{Space: "http://nextcloud.org/ns", Local: "metadata-files-live-photo"}: true,
		{Space: "http://nextcloud.org/ns", Local: "has-preview"}:               true,
		{Space: "http://nextcloud.org/ns", Local: "contained-folder-count"}:    true,
		{Space: "http://nextcloud.org/ns", Local: "contained-file-count"}:      true,
	}

	// Special-case: the “Depth: 0 + only <oc:size/>” probe that Nextcloud does.
	// Official server responds with a single 200 propstat containing only oc:size.
	sizeOnlyProbe := false
	if !requestCommon && len(reqSet) == 1 && asked("http://owncloud.org/ns", "size") {
		sizeOnlyProbe = true
	}

	// href for the resource is based on request path, and directories must end with "/"
	selfHref := c.Request().URL.Path
	if selfEntry.IsDir && !strings.HasSuffix(selfHref, "/") {
		selfHref += "/"
	}

	// empty and set string literal ptr
	emptyStruct := struct{}{}
	setStrlPtr := func(dst **string, v string) {
		*dst = &v
	}

	// true when a "missing propstat" has at least one element to emit
	hasMissing := func(m types.WebDAVPropNotFound) bool {
		return m.ContentLength != nil ||
			m.QuotaAvailableBytes != nil ||
			m.QuotaUsedBytes != nil ||
			m.OCDownloadURL != nil ||
			m.OCDDC != nil ||
			m.OCChecksums != nil ||
			m.NCIsEncrypted != nil ||
			m.NCMetadataFilesLivePhoto != nil ||
			len(m.DeadProperties) > 0
	}

	addResponseFor := func(href string, entry *types.DbFile) types.WebDAVResponse {

		// Build 200 OK bag
		ok := types.WebDAVPropOK{}

		// If this was the special size-only probe, return exactly one propstat (200) with only oc:size.
		if sizeOnlyProbe {
			ok = types.WebDAVPropOK{
				OCSize: strconv.FormatInt(entry.SizeBytes, 10),
			}
			return types.WebDAVResponse{
				Href: href,
				Propstat: []types.WebDAVPropstat{
					{Prop: ok, Status: "HTTP/1.1 200 OK"},
				},
			}
		}

		// Build 404 Not Found bag (requested-but-not-supported-by-us / not-applicable)
		miss := types.WebDAVPropNotFound{}

		isDir := entry.IsDir

		// Shared computed values
		lastMod := davModTime(entry).Format(http.TimeFormat)
		etag := etagFromOCIDVersion(entry.OCID, entry.Version)

		// Permissions (simple model, but shaped like Nextcloud)
		perms := "RGDNVW"
		if isDir {
			perms = "RGDNVCK"
		}

		// --- DAV props
		if asked("DAV:", "resourcetype") {
			if isDir {
				ok.ResourceType = &types.WebDAVResourceType{Collection: &struct{}{}}
			} else {
				// For files, Nextcloud emits <d:resourcetype/> (empty). Omitting vs empty is usually fine;
				// but since the property was requested, we want an empty resourcetype element in 200.
				ok.ResourceType = &types.WebDAVResourceType{}
			}
		}

		if asked("DAV:", "getlastmodified") {
			ok.LastModified = lastMod
		}

		if asked("DAV:", "getetag") {
			ok.ETag = etag
		}

		if asked("DAV:", "getcontentlength") {
			if isDir {
				// Nextcloud commonly reports this as missing for collections.
				miss.ContentLength = &emptyStruct
			} else {
				setStrlPtr(&ok.ContentLength, strconv.FormatInt(entry.SizeBytes, 10))
			}
		}

		if asked("DAV:", "getcontenttype") {
			ok.ContentType = davContentType(entry)
		}

		if asked("DAV:", "quota-available-bytes") || asked("DAV:", "quota-used-bytes") {
			if isDir {

				// quota-available-bytes is the total available - current dir size, nextcloud seems to do it this way
				usedBytes := entry.SizeBytes
				availableBytes := w.user.QuotaBytes - usedBytes
				if availableBytes < 0 {
					availableBytes = 0
				}
				if asked("DAV:", "quota-available-bytes") {
					setStrlPtr(&ok.QuotaAvailableBytes, strconv.FormatInt(availableBytes, 10))
				}
				if asked("DAV:", "quota-used-bytes") {
					setStrlPtr(&ok.QuotaUsedBytes, strconv.FormatInt(usedBytes, 10))
				}
			} else {
				if asked("DAV:", "quota-available-bytes") {
					miss.QuotaAvailableBytes = &emptyStruct
				}
				if asked("DAV:", "quota-used-bytes") {
					miss.QuotaUsedBytes = &emptyStruct
				}
			}
		}

		// --- ownCloud / Nextcloud extension props
		if asked("http://owncloud.org/ns", "size") {
			// Nextcloud uses oc:size for both files and dirs; dir value is often 0/aggregate.
			ok.OCSize = strconv.FormatInt(entry.SizeBytes, 10)
		}

		if asked("http://owncloud.org/ns", "id") {
			ok.OCID = entry.OCID
		}

		if asked("http://owncloud.org/ns", "fileid") {
			ok.OCFileID = strconv.FormatInt(entry.ID, 10)
		}

		if asked("http://owncloud.org/ns", "permissions") {
			ok.OCPermissions = perms
		}

		if asked("http://owncloud.org/ns", "favorite") {
			favorite := 0
			ok.OCFavorite = &favorite
		}

		if asked("http://owncloud.org/ns", "comments-unread") {
			commentsUnread := 0
			ok.OCCommentsUnread = &commentsUnread
		}

		if asked("http://owncloud.org/ns", "owner-id") {
			ok.OCOwnerID = w.user.Username
		}

		if asked("http://owncloud.org/ns", "owner-display-name") {
			ok.OCOwnerDisplayName = displayName(*w.user)
		}

		if asked("http://owncloud.org/ns", "downloadURL") {
			if isDir {
				miss.OCDownloadURL = &emptyStruct
			} else {
				setStrlPtr(&ok.OCDownloadURL, "")
			}
		}

		if asked("http://owncloud.org/ns", "dDC") {
			// Not implemented: return requested-but-missing
			miss.OCDDC = &emptyStruct
		}

		if asked("http://owncloud.org/ns", "checksums") {
			if !isDir && entry.ContentSHA1 != nil && strings.TrimSpace(*entry.ContentSHA1) != "" {
				ok.OCChecksums = &types.WebDAVChecksums{
					Checksums: []string{"SHA1:" + strings.ToLower(strings.TrimSpace(*entry.ContentSHA1))},
				}
			} else {
				ok.OCChecksums = &types.WebDAVChecksums{}
			}
		}

		if asked("http://owncloud.org/ns", "data-fingerprint") {
			// Official server sends empty string sometimes; keep it present.
			ok.OCDataFingerprint = ""
		}

		if asked("http://owncloud.org/ns", "share-types") {
			// Present as empty element in official responses.
			ok.OCShareTypes = &struct{}{}
		}

		if asked("http://nextcloud.org/ns", "share-attributes") {
			ok.NCShareAttributes = "[]"
		}

		if asked("http://nextcloud.org/ns", "is-mount-root") {
			// Your types want this always-present when included in the OK bag.
			mountRoot := false
			ok.NCIsMountRoot = &mountRoot
		}

		if asked("http://nextcloud.org/ns", "is-encrypted") {
			ok.NCIsEncrypted = "0"
		}

		if asked("http://nextcloud.org/ns", "metadata-files-live-photo") {
			livePhoto := false
			ok.NCMetadataFilesLivePhoto = &livePhoto
		}

		if asked("http://nextcloud.org/ns", "has-preview") {
			hasPreview := false
			ok.NCHasPreview = &hasPreview
		}

		if isDir && (asked("http://nextcloud.org/ns", "contained-folder-count") || asked("http://nextcloud.org/ns", "contained-file-count")) {
			folderCount, fileCount, err := getFileChildCounts(ctx, w.db, w.user.ID, entry.Path)
			if err == nil {
				if asked("http://nextcloud.org/ns", "contained-folder-count") {
					ok.NCContainedFolderCount = &folderCount
				}
				if asked("http://nextcloud.org/ns", "contained-file-count") {
					ok.NCContainedFileCount = &fileCount
				}
			}
		} else if !isDir {
			if asked("http://nextcloud.org/ns", "contained-folder-count") {
				miss.DeadProperties = append(miss.DeadProperties, types.WebDAVDeadProperty{
					XMLName: xml.Name{Space: "http://nextcloud.org/ns", Local: "contained-folder-count"},
				})
			}
			if asked("http://nextcloud.org/ns", "contained-file-count") {
				miss.DeadProperties = append(miss.DeadProperties, types.WebDAVDeadProperty{
					XMLName: xml.Name{Space: "http://nextcloud.org/ns", Local: "contained-file-count"},
				})
			}
		}

		// Fetch dead properties.
		type deadProp struct {
			Namespace string `db:"namespace"`
			LocalName string `db:"local_name"`
			Value     string `db:"value"`
		}
		var deadProps []deadProp
		_ = w.db.SelectContext(ctx, &deadProps, `
			SELECT namespace, local_name, value
			FROM file_properties
			WHERE user_id = $1 AND path = $2
		`, w.user.ID, entry.Path)

		for _, dp := range deadProps {
			if requestCommon || reqSet[qname{Space: dp.Namespace, Local: dp.LocalName}] {
				ok.DeadProperties = append(ok.DeadProperties, types.WebDAVDeadProperty{
					XMLName:  xml.Name{Space: dp.Namespace, Local: dp.LocalName},
					InnerXML: dp.Value,
				})
			}
		}

		// For explicitly requested dead properties that don't exist, return 404.
		if !requestCommon {
			foundProps := map[qname]bool{}
			for _, dp := range deadProps {
				foundProps[qname{Space: dp.Namespace, Local: dp.LocalName}] = true
			}
			for q := range reqSet {
				isLiveProp := q.Space == "DAV:" || q.Space == "http://owncloud.org/ns" || q.Space == "http://nextcloud.org/ns"
				if isLiveProp && !handledLiveProps[q] {
					miss.DeadProperties = append(miss.DeadProperties, types.WebDAVDeadProperty{
						XMLName: xml.Name{Space: q.Space, Local: q.Local},
					})
				}
				if !isLiveProp && !foundProps[q] {
					miss.DeadProperties = append(miss.DeadProperties, types.WebDAVDeadProperty{
						XMLName: xml.Name{Space: q.Space, Local: q.Local},
					})
				}
			}
		}

		propstats := []types.WebDAVPropstat{
			{Prop: ok, Status: "HTTP/1.1 200 OK"},
		}
		if hasMissing(miss) {
			propstats = append(propstats, types.WebDAVPropstat{
				Prop:   miss,
				Status: "HTTP/1.1 404 Not Found",
			})
		}

		return types.WebDAVResponse{
			Href:     href,
			Propstat: propstats,
		}
	}

	// --- Build multistatus responses (self + optional children)
	responses := make([]types.WebDAVResponse, 0, 32)
	responses = append(responses, addResponseFor(selfHref, selfEntry))

	if selfEntry.IsDir && listChildren {
		children, err := getFileChildren(ctx, w.db, w.user.ID, relCanon)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		for i := range children {
			child := &children[i]
			name := path.Base(child.Path)
			childHref := selfHref + url.PathEscape(name)
			if child.IsDir {
				childHref += "/"
			}
			responses = append(responses, addResponseFor(childHref, child))
		}
	}

	// --- Marshal XML
	ms := types.WebDAVMultiStatus{
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

	payload := append([]byte(xml.Header), out...)

	setDAVHeader(c)
	return c.Blob(http.StatusMultiStatus, "application/xml; charset=utf-8", payload)
}

func (w *WebDAV) handleDAVHead(c *echo.Context) error {
	fsAbs, relCanon, _, err := w.mapDAVRequestToFS(c.Request().URL.Path)
	if err != nil {
		return err
	}

	fi, err := os.Stat(fsAbs)
	if err != nil {
		if os.IsNotExist(err) {
			return echo.NewHTTPError(http.StatusNotFound, "not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	setDAVHeader(c)
	if fi.IsDir() {
		return c.NoContent(http.StatusOK)
	}

	row, err := getFileRow(c.Request().Context(), w.db, w.user.ID, relCanon)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "not found")
	}

	etag := etagFromOCIDVersion(row.OCID, row.Version)
	c.Response().Header().Set("ETag", etag)
	c.Response().Header().Set("OC-ETag", etag)
	c.Response().Header().Set("OC-Fileid", row.OCID)
	c.Response().Header().Set("Last-Modified", davModTime(row).Format(http.TimeFormat))
	c.Response().Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
	return c.NoContent(http.StatusOK)
}

func (w *WebDAV) handleDAVMkcol(c *echo.Context) error {
	fsAbs, relCanon, _, err := w.mapDAVRequestToFS(c.Request().URL.Path)
	if err != nil {
		return err
	}
	if relCanon == "" {
		return echo.NewHTTPError(http.StatusForbidden, "Cannot MKCOL root")
	}

	// MKCOL must have empty body
	if c.Request().ContentLength > 0 {
		return echo.NewHTTPError(http.StatusUnsupportedMediaType, "MKCOL request body must be empty")
	}

	ctx := c.Request().Context()
	conn, err := w.db.Connx(ctx)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() { _ = conn.Close() }()

	var sessionLocks davSessionLocks
	defer w.unlockDAVSessionLocks(conn, &sessionLocks)

	ancestors := utils.ParentPaths(relCanon)
	exclusive := []string{relCanon}

	if err := w.lockDAVSessionLocks(conn, ctx, exclusive, ancestors, &sessionLocks); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	tx, err := conn.BeginTxx(ctx, nil)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() { _ = tx.Rollback() }()

	// Check the immediate parent exists on disk (under lock).
	parentAbs := filepath.Dir(fsAbs)
	if _, err := os.Stat(parentAbs); err != nil {
		if os.IsNotExist(err) {
			return echo.NewHTTPError(http.StatusConflict, "parent directory does not exist")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	// Check if target already exists.
	if _, err := os.Stat(fsAbs); err == nil {
		return echo.NewHTTPError(http.StatusMethodNotAllowed, "collection already exists")
	}

	if err := os.Mkdir(fsAbs, 0o750); err != nil {
		if os.IsExist(err) {
			return echo.NewHTTPError(http.StatusMethodNotAllowed, "collection already exists")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	now := time.Now().UTC()

	// Upsert ancestor dirs (they must exist but may not be in DB yet).
	for _, p := range ancestors {
		if _, err := tx.ExecContext(ctx, `
        INSERT INTO files (user_id, path, is_dir, ocid, version, size_bytes, mtime, created_at, updated_at)
        VALUES ($1, $2, true, '', 1, 0, $3, $3, $3)
        ON CONFLICT (user_id, path) DO NOTHING
    `, w.user.ID, p, now); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
	}

	row := &types.DbFile{
		UserID:    w.user.ID,
		Path:      relCanon,
		IsDir:     true,
		OCID:      "",
		Version:   1,
		SizeBytes: 0,
		Mtime:     now,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err = tx.QueryRowxContext(ctx, `
		INSERT INTO files (user_id, path, is_dir, ocid, version, size_bytes, mtime, content_sha1, created_at, updated_at)
		VALUES ($1, $2, true, '', 1, 0, $3, '', $3, $3)
		ON CONFLICT (user_id, path) DO UPDATE
		SET updated_at = EXCLUDED.updated_at
		RETURNING *
	`, w.user.ID, relCanon, now).StructScan(row); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	if err := tx.Commit(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	etag := etagFromOCIDVersion(row.OCID, row.Version)
	c.Response().Header().Set("ETag", etag)
	c.Response().Header().Set("OC-ETag", etag)
	c.Response().Header().Set("OC-Fileid", row.OCID)

	setDAVHeader(c)
	return c.NoContent(http.StatusCreated)
}

type publishResult struct {
	OCID    string
	Version int64
	Existed bool
}

// publishFile atomically publishes tmpName to fsAbs, updates the DB, and returns the file's OCID/version.
// Must be called with the advisory lock on relCanon already held.
func (w *WebDAV) publishFile(
	ctx context.Context,
	tx *sqlx.Tx,
	fsAbs, tmpName, relCanon, gotSHA1, xOCMtime string,
) (*publishResult, error) {
	// Back up existing file so we can restore on failure.
	fiExisting, statErr := os.Stat(fsAbs)
	existed := statErr == nil
	if statErr != nil && !os.IsNotExist(statErr) {
		return nil, statErr
	}
	if existed && fiExisting.IsDir() {
		return nil, echo.NewHTTPError(http.StatusMethodNotAllowed, "cannot replace a collection with a file")
	}

	var oldRow struct {
		SizeBytes int64 `db:"size_bytes"`
		IsDir     bool  `db:"is_dir"`
	}
	oldSize := int64(0)
	if err := tx.QueryRowxContext(ctx, `
		SELECT size_bytes, is_dir FROM files WHERE user_id = $1 AND path = $2
	`, w.user.ID, relCanon).StructScan(&oldRow); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	} else if err == nil {
		if oldRow.IsDir {
			return nil, echo.NewHTTPError(http.StatusMethodNotAllowed, "cannot replace a collection with a file")
		}
		oldSize = oldRow.SizeBytes
	}

	tmpInfo, err := os.Stat(tmpName)
	if err != nil {
		return nil, err
	}
	newSize := tmpInfo.Size()
	delta := newSize - oldSize
	if err := w.enforceQuotaDeltaTx(ctx, tx, delta); err != nil {
		return nil, err
	}

	backupName := ""
	if existed {
		backupName, err = backupExistingPath(fsAbs)
		if err != nil {
			return nil, err
		}
	}

	restore := func() {
		_ = os.Remove(fsAbs)
		if backupName != "" {
			_ = os.Rename(backupName, fsAbs)
		}
	}

	if err := os.Rename(tmpName, fsAbs); err != nil {
		if backupName != "" {
			_ = os.Rename(backupName, fsAbs)
		}
		return nil, err
	}

	if xOCMtime != "" {
		if sec, err := strconv.ParseInt(xOCMtime, 10, 64); err == nil && sec > 0 {
			t := time.Unix(sec, 0).UTC()
			_ = os.Chtimes(fsAbs, t, t)
		}
	}

	// we already renamed tmpName to fsAbs
	fi, err := os.Stat(fsAbs)
	if err != nil {
		restore()
		return nil, err
	}

	var row types.DbFile

	now := time.Now().UTC()
	if err = tx.QueryRowxContext(ctx, `
        INSERT INTO files (user_id, path, is_dir, ocid, version, size_bytes, mtime, content_sha1, created_at, updated_at)
        VALUES ($1, $2, false, '', 1, $3, $4, $5, $6, $6)
        ON CONFLICT (user_id, path) DO UPDATE SET
            is_dir       = false,
            version      = files.version + 1,
            size_bytes   = EXCLUDED.size_bytes,
            mtime        = EXCLUDED.mtime,
            content_sha1 = EXCLUDED.content_sha1,
            updated_at   = EXCLUDED.updated_at
        RETURNING *
    `, w.user.ID, relCanon, newSize, fi.ModTime().UTC(), gotSHA1, now).StructScan(&row); err != nil {
		restore()
		return nil, err
	}

	_, err = updateAncestorSizes(ctx, tx, w.user.ID, relCanon, delta)
	if err != nil {
		restore()
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		restore()
		return nil, err
	}

	if backupName != "" {
		_ = os.Remove(backupName)
	}

	return &publishResult{
		OCID:    row.OCID,
		Version: row.Version,
		Existed: existed,
	}, nil
}

func (w *WebDAV) handleDAVPut(c *echo.Context) error {
	fsAbs, relCanon, _, err := w.mapDAVRequestToFS(c.Request().URL.Path)
	if err != nil {
		return err
	}
	if relCanon == "" {
		return echo.NewHTTPError(http.StatusForbidden, "cannot PUT to root")
	}

	parentAbs := filepath.Dir(fsAbs)
	if _, err := os.Stat(parentAbs); err != nil {
		if os.IsNotExist(err) {
			return echo.NewHTTPError(http.StatusConflict, "parent directory does not exist")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	// --- Non-chunked upload: atomic replace, with optional checksum + mtime ---
	// Write body to a temp file FIRST (no lock held) so we don't block other uploads.
	// We'll take the advisory lock only for "publish (rename) + DB update".
	tmpName := fsAbs + ".tmp." + strconv.FormatInt(time.Now().UnixNano(), 36)
	tmp, err := os.OpenFile(tmpName, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	hasher := sha1.New()
	_, copyErr := io.Copy(io.MultiWriter(tmp, hasher), c.Request().Body)
	closeErr := tmp.Close()
	if copyErr != nil {
		_ = os.Remove(tmpName)
		return echo.NewHTTPError(http.StatusInternalServerError, copyErr.Error())
	}
	if closeErr != nil {
		_ = os.Remove(tmpName)
		return echo.NewHTTPError(http.StatusInternalServerError, closeErr.Error())
	}
	gotSHA1 := hex.EncodeToString(hasher.Sum(nil))

	// Nextcloud-ish extra headers (optional, but good to accept)
	ocChecksum := strings.TrimSpace(c.Request().Header.Get("OC-Checksum")) // e.g. "SHA1:..."
	_ = strings.TrimSpace(c.Request().Header.Get("OC-Chunk-Size"))         // informational for this endpoint
	_ = strings.TrimSpace(c.Request().Header.Get("OC-Total-Length"))       // informational for this endpoint
	xOCMtime := strings.TrimSpace(c.Request().Header.Get("X-OC-Mtime"))    // unix timestamp (seconds)

	// Verify OC-Checksum if present and supported
	// Verify OC-Checksum if provided
	if ocChecksum != "" {
		parts := strings.SplitN(ocChecksum, ":", 2)
		if len(parts) != 2 || !strings.EqualFold(strings.TrimSpace(parts[0]), "SHA1") {
			_ = os.Remove(tmpName)
			return c.NoContent(http.StatusBadRequest)
		}
		want := strings.ToLower(strings.TrimSpace(parts[1]))
		if want != gotSHA1 {
			_ = os.Remove(tmpName)
			return c.NoContent(http.StatusPreconditionFailed)
		}
	}

	ctx := c.Request().Context()
	conn, err := w.db.Connx(ctx)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() { _ = conn.Close() }()

	var sessionLocks davSessionLocks
	defer w.unlockDAVSessionLocks(conn, &sessionLocks)

	if err := w.acquireFileLocks(conn, ctx, relCanon, parentAbs, &sessionLocks); err != nil {
		_ = os.Remove(tmpName)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	// Transaction for advisory lock + DB update.
	tx, err := conn.BeginTxx(ctx, nil)
	if err != nil {
		_ = os.Remove(tmpName)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() { _ = tx.Rollback() }()

	if err := w.checkLockTx(ctx, tx, relCanon, c.Request().Header.Get("If")); err != nil {
		_ = os.Remove(tmpName)
		return err
	}

	// check if-match header
	ifMatch := strings.TrimSpace(c.Request().Header.Get("If-Match"))
	if ifMatch != "" {
		var currentOCID string
		var currentVersion int64
		err := tx.QueryRowxContext(ctx, `
        	SELECT ocid, version FROM files WHERE user_id = $1 AND path = $2
    	`, w.user.ID, relCanon).Scan(&currentOCID, &currentVersion)

		if errors.Is(err, sql.ErrNoRows) {
			_ = os.Remove(tmpName)
			return c.NoContent(http.StatusPreconditionFailed)
		} else if err != nil {
			_ = os.Remove(tmpName)
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
		currentETag := etagFromOCIDVersion(currentOCID, currentVersion)
		if !etagHeaderMatches(ifMatch, currentETag) {
			_ = os.Remove(tmpName)
			return c.NoContent(http.StatusPreconditionFailed)
		}
	}

	result, err := w.publishFile(ctx, tx, fsAbs, tmpName, relCanon, gotSHA1, xOCMtime)
	if err != nil {
		_ = os.Remove(tmpName)
		var httpErr *echo.HTTPError
		if errors.As(err, &httpErr) {
			return err
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	if err := w.h.app.State.Previews.Enqueue(result.OCID); err != nil {
		slog.Warn("failed to queue preview after DAV PUT", "path", relCanon, "ocid", result.OCID, "error", err)
	}

	etag := etagFromOCIDVersion(result.OCID, result.Version)
	c.Response().Header().Set("ETag", etag)
	c.Response().Header().Set("OC-ETag", etag)
	c.Response().Header().Set("OC-Fileid", result.OCID)
	c.Response().Header().Set("X-Oc-Mtime", "accepted")

	// Mimic the "Created" response (201) when a new file; otherwise 204 for overwriting
	if result.Existed {
		return c.NoContent(http.StatusNoContent)
	}
	return c.NoContent(http.StatusCreated)
}

func (w *WebDAV) handleDAVMove(c *echo.Context) error {
	fsAbs, relCanon, _, err := w.mapDAVRequestToFS(c.Request().URL.Path)
	if err != nil {
		return err
	}
	if relCanon == "" {
		return echo.NewHTTPError(http.StatusForbidden, "cannot MOVE root")
	}

	// Parse Destination header.
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
		return echo.NewHTTPError(http.StatusForbidden, "cannot MOVE to root")
	}
	if relCanon == destRelCanon {
		return echo.NewHTTPError(http.StatusForbidden, "source and destination are the same")
	}
	if davPathIsDescendant(relCanon, destRelCanon) {
		return echo.NewHTTPError(http.StatusForbidden, "cannot MOVE a collection into itself")
	}

	// Acquire locks in consistent order (sort paths to avoid deadlocks).
	// Shared lock on all ancestors of both src and dest, exclusive on src and dest themselves.
	srcAncestors := utils.ParentPaths(relCanon)
	dstAncestors := utils.ParentPaths(destRelCanon)

	// Deduplicate and sort ancestor locks.
	ancestorSet := map[string]struct{}{}
	for _, p := range append(srcAncestors, dstAncestors...) {
		ancestorSet[p] = struct{}{}
	}
	ancestors := make([]string, 0, len(ancestorSet))
	for p := range ancestorSet {
		ancestors = append(ancestors, p)
	}
	sort.Strings(ancestors)

	// Exclusive locks on src and dest in consistent order.
	first, second := relCanon, destRelCanon
	if relCanon > destRelCanon {
		first, second = destRelCanon, relCanon
	}
	exclusive := []string{first, second}

	ctx := c.Request().Context()
	conn, err := w.db.Connx(ctx)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() { _ = conn.Close() }()

	var sessionLocks davSessionLocks
	defer w.unlockDAVSessionLocks(conn, &sessionLocks)

	if err := w.lockDAVSessionLocks(conn, ctx, exclusive, ancestors, &sessionLocks); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	tx, err := conn.BeginTxx(ctx, nil)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() { _ = tx.Rollback() }()

	ifHeader := c.Request().Header.Get("If")
	if err := w.checkLockSubtreeTx(ctx, tx, relCanon, ifHeader); err != nil {
		return err
	}
	if err := w.checkLockTx(ctx, tx, destRelCanon, ifHeader); err != nil {
		return err
	}

	// Check source exists.
	srcFi, err := os.Stat(fsAbs)
	if err != nil {
		if os.IsNotExist(err) {
			return echo.NewHTTPError(http.StatusNotFound, "source not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	// Check dest parent exists.
	destParentAbs := filepath.Dir(destFsAbs)
	if _, err := os.Stat(destParentAbs); err != nil {
		if os.IsNotExist(err) {
			return echo.NewHTTPError(http.StatusConflict, "destination parent does not exist")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	// Check overwrite.
	_, destStatErr := os.Stat(destFsAbs)
	destExisted := destStatErr == nil

	overwrite := strings.ToUpper(strings.TrimSpace(c.Request().Header.Get("Overwrite"))) != "F"
	if destExisted && !overwrite {
		return echo.NewHTTPError(http.StatusPreconditionFailed, "destination exists and overwrite is disabled")
	}
	if destExisted && davPathIsDescendant(destRelCanon, relCanon) {
		return echo.NewHTTPError(http.StatusForbidden, "cannot overwrite an ancestor of the source")
	}
	overwrittenSize := int64(0)
	if destExisted {
		overwrittenSize, err = fileTreeSizeTx(ctx, tx, w.user.ID, destRelCanon)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
	}

	isDir := srcFi.IsDir()

	// Compute size being moved (files only, not dirs, since dir size_bytes tracks subtree).
	var movedSize int64
	if isDir {
		if err := tx.QueryRowxContext(ctx, `
			SELECT COALESCE(SUM(size_bytes), 0)
			FROM files
			WHERE user_id = $1
			  AND is_dir = false
			  AND (path = $2 OR LEFT(path, length($2) + 1) = $2 || '/')
		`, w.user.ID, relCanon).Scan(&movedSize); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
	} else {
		if err := tx.QueryRowxContext(ctx, `
			SELECT COALESCE(size_bytes, 0) FROM files WHERE user_id = $1 AND path = $2
		`, w.user.ID, relCanon).Scan(&movedSize); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
	}

	destBackup := ""
	movedSource := false
	committed := false
	defer func() {
		if committed {
			return
		}
		if movedSource {
			_ = os.Rename(destFsAbs, fsAbs)
		}
		if destBackup != "" {
			restoreBackedUpPath(destFsAbs, destBackup)
		}
	}()

	// If dest existed and is a dir, delete its subtree from DB first.
	if destExisted {
		destBackup, err = backupExistingPath(destFsAbs)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM files
			WHERE user_id = $1
			  AND (path = $2 OR LEFT(path, length($2) + 1) = $2 || '/')
		`, w.user.ID, destRelCanon); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		_, err := updateAncestorSizes(ctx, tx, w.user.ID, destRelCanon, -overwrittenSize)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
	}

	// Rename on filesystem.
	if err := os.Rename(fsAbs, destFsAbs); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	movedSource = true

	// Update DB paths: rewrite src prefix to dest prefix.
	var row types.DbFile

	// Update DB paths: rewrite src prefix to dest prefix.
	if isDir {
		if _, err := tx.ExecContext(ctx, `
			UPDATE files
			SET path = $3 || substring(path from length($2) + 1),
			    updated_at = NOW()
			WHERE user_id = $1
			  AND (path = $2 OR LEFT(path, length($2) + 1) = $2 || '/')
		`, w.user.ID, relCanon, destRelCanon); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		if _, err := tx.ExecContext(ctx, `
			UPDATE file_properties
			SET path = $3 || substring(path from length($2) + 1)
			WHERE user_id = $1
			  AND (path = $2 OR LEFT(path, length($2) + 1) = $2 || '/')
		`, w.user.ID, relCanon, destRelCanon); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		if err := tx.QueryRowxContext(ctx, `
			SELECT * FROM files WHERE user_id = $1 AND path = $2
		`, w.user.ID, destRelCanon).StructScan(&row); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
	} else {
		now := time.Now().UTC()
		if err := tx.QueryRowxContext(ctx, `
			UPDATE files
			SET path = $3, updated_at = $4
			WHERE user_id = $1 AND path = $2
			RETURNING *
    	`, w.user.ID, relCanon, destRelCanon, now).StructScan(&row); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		if _, err := tx.ExecContext(ctx, `
			UPDATE file_properties
			SET path = $3
			WHERE user_id = $1 AND path = $2
		`, w.user.ID, relCanon, destRelCanon); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
	}

	// Update ancestor sizes: subtract from src ancestors, add to dest ancestors.
	srcParentCanon := path.Dir(relCanon)
	if srcParentCanon == "." {
		srcParentCanon = ""
	}
	dstParentCanon := path.Dir(destRelCanon)
	if dstParentCanon == "." {
		dstParentCanon = ""
	}

	if srcParentCanon != dstParentCanon {
		_, err := updateAncestorSizes(ctx, tx, w.user.ID, relCanon, -movedSize)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		_, err = updateAncestorSizes(ctx, tx, w.user.ID, destRelCanon, movedSize)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
	}

	if err := tx.Commit(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	committed = true
	if destBackup != "" {
		_ = os.RemoveAll(destBackup)
	}

	etag := etagFromOCIDVersion(row.OCID, row.Version)
	c.Response().Header().Set("ETag", etag)
	c.Response().Header().Set("OC-ETag", etag)
	c.Response().Header().Set("OC-Fileid", row.OCID)

	if destExisted {
		return c.NoContent(http.StatusNoContent)
	}
	return c.NoContent(http.StatusCreated)
}

func (w *WebDAV) handleDAVDelete(c *echo.Context) error {
	fsAbs, relCanon, _, err := w.mapDAVRequestToFS(c.Request().URL.Path)
	if err != nil {
		return err
	}
	if relCanon == "" {
		return echo.NewHTTPError(http.StatusForbidden, "cannot DELETE root")
	}

	// Shared lock on ancestors, exclusive lock on the target.
	ancestors := utils.ParentPaths(relCanon)
	exclusive := []string{relCanon}

	ctx := c.Request().Context()
	conn, err := w.db.Connx(ctx)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() { _ = conn.Close() }()

	var sessionLocks davSessionLocks
	defer w.unlockDAVSessionLocks(conn, &sessionLocks)

	if err := w.lockDAVSessionLocks(conn, ctx, exclusive, ancestors, &sessionLocks); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	tx, err := conn.BeginTxx(ctx, nil)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() { _ = tx.Rollback() }()

	if err := w.checkLockSubtreeTx(ctx, tx, relCanon, c.Request().Header.Get("If")); err != nil {
		return err
	}

	// Check target exists.
	fi, err := os.Stat(fsAbs)
	if err != nil {
		if os.IsNotExist(err) {
			return echo.NewHTTPError(http.StatusNotFound, "not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	isDir := fi.IsDir()
	deleteBackup, err := backupExistingPath(fsAbs)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	committed := false
	defer func() {
		if !committed {
			restoreBackedUpPath(fsAbs, deleteBackup)
		}
	}()

	// Compute size delta before deleting from DB.
	var totalSize int64
	if isDir {
		// Use the dir row's size_bytes, which already tracks the full subtree
		if err := tx.QueryRowxContext(ctx, `
        	SELECT COALESCE(size_bytes, 0) FROM files WHERE user_id = $1 AND path = $2
    	`, w.user.ID, relCanon).Scan(&totalSize); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		if _, err := tx.ExecContext(ctx, `
			DELETE FROM files
			WHERE user_id = $1
			  AND (path = $2 OR LEFT(path, length($2) + 1) = $2 || '/')
		`, w.user.ID, relCanon); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
	} else {
		if err := tx.QueryRowxContext(ctx, `
			DELETE FROM files
			WHERE user_id = $1 AND path = $2
			RETURNING size_bytes
		`, w.user.ID, relCanon).Scan(&totalSize); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
	}

	// Update ancestor directory sizes.
	_, err = updateAncestorSizes(ctx, tx, w.user.ID, relCanon, -totalSize)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	if err := tx.Commit(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	committed = true
	_ = os.RemoveAll(deleteBackup)

	return c.NoContent(http.StatusNoContent)
}

func (w *WebDAV) handleDAVGet(c *echo.Context) error {
	fsAbs, relCanon, _, err := w.mapDAVRequestToFS(c.Request().URL.Path)
	if err != nil {
		return err
	}

	// Directories are not directly downloadable via GET.
	fi, err := os.Stat(fsAbs)
	if err != nil {
		if os.IsNotExist(err) {
			return echo.NewHTTPError(http.StatusNotFound, "not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	if fi.IsDir() {
		return echo.NewHTTPError(http.StatusMethodNotAllowed, "cannot GET a collection")
	}

	// Fetch DB row for ETag.
	ctx := c.Request().Context()
	row, err := getFileRow(ctx, w.db, w.user.ID, relCanon)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "not found")
	}

	etag := etagFromOCIDVersion(row.OCID, row.Version)

	// If-None-Match caching.
	if inm := strings.TrimSpace(c.Request().Header.Get("If-None-Match")); inm != "" {
		if etagHeaderMatches(inm, etag) {
			return c.NoContent(http.StatusNotModified)
		}
	}

	// Detect content type.
	contentType := mime.TypeByExtension(filepath.Ext(fsAbs))
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	c.Response().Header().Set("ETag", etag)
	c.Response().Header().Set("OC-ETag", etag)
	c.Response().Header().Set("OC-Fileid", row.OCID)
	c.Response().Header().Set("Last-Modified", davModTime(row).Format(http.TimeFormat))
	c.Response().Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(fsAbs)+"\"")

	// http.ServeContent handles Range requests, If-Range, and Content-Length automatically.
	f, err := os.Open(fsAbs)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() { _ = f.Close() }()

	http.ServeContent(c.Response(), c.Request(), filepath.Base(fsAbs), davModTime(row), f)
	return nil
}

// copyFileFS copies a single file from src to dst atomically.
func copyFileFS(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	tmp := dst + ".tmp." + strconv.FormatInt(time.Now().UnixNano(), 36)
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

func (w *WebDAV) handleDAVCopy(c *echo.Context) error {
	fsAbs, relCanon, _, err := w.mapDAVRequestToFS(c.Request().URL.Path)
	if err != nil {
		return err
	}
	if relCanon == "" {
		return echo.NewHTTPError(http.StatusForbidden, "cannot COPY root")
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
		return echo.NewHTTPError(http.StatusForbidden, "cannot COPY to root")
	}
	if relCanon == destRelCanon {
		return echo.NewHTTPError(http.StatusForbidden, "source and destination are the same")
	}
	if davPathIsDescendant(relCanon, destRelCanon) {
		return echo.NewHTTPError(http.StatusForbidden, "cannot COPY a collection into itself")
	}

	depth, err := normalizeDAVDepth(c.Request().Header.Get("Depth"), "infinity", "0", "infinity")
	if err != nil {
		return err
	}
	overwrite := strings.ToUpper(strings.TrimSpace(c.Request().Header.Get("Overwrite"))) != "F"

	ctx := c.Request().Context()

	// Shared locks on all ancestors of both src and dest.
	srcAncestors := utils.ParentPaths(relCanon)
	dstAncestors := utils.ParentPaths(destRelCanon)

	ancestorSet := map[string]struct{}{}
	for _, p := range append(srcAncestors, dstAncestors...) {
		ancestorSet[p] = struct{}{}
	}
	ancestors := make([]string, 0, len(ancestorSet))
	for p := range ancestorSet {
		ancestors = append(ancestors, p)
	}
	sort.Strings(ancestors)

	// Exclusive lock on dest.
	// Exclusive locks on src and dest in consistent order.
	first, second := relCanon, destRelCanon
	if relCanon > destRelCanon {
		first, second = destRelCanon, relCanon
	}
	exclusive := []string{first, second}

	conn, err := w.db.Connx(ctx)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() { _ = conn.Close() }()

	var sessionLocks davSessionLocks
	defer w.unlockDAVSessionLocks(conn, &sessionLocks)

	if err := w.lockDAVSessionLocks(conn, ctx, exclusive, ancestors, &sessionLocks); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	tx, err := conn.BeginTxx(ctx, nil)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() { _ = tx.Rollback() }()

	if err := w.checkLockTx(ctx, tx, destRelCanon, c.Request().Header.Get("If")); err != nil {
		return err
	}

	// Check source exists.
	srcFi, err := os.Stat(fsAbs)
	if err != nil {
		if os.IsNotExist(err) {
			return echo.NewHTTPError(http.StatusNotFound, "source not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	// Check dest parent exists.
	if _, err := os.Stat(filepath.Dir(destFsAbs)); err != nil {
		if os.IsNotExist(err) {
			return echo.NewHTTPError(http.StatusConflict, "destination parent does not exist")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	// Check overwrite.
	_, destStatErr := os.Stat(destFsAbs)
	destExisted := destStatErr == nil
	if destExisted && !overwrite {
		return echo.NewHTTPError(http.StatusPreconditionFailed, "destination exists and overwrite is disabled")
	}
	if destExisted && davPathIsDescendant(destRelCanon, relCanon) {
		return echo.NewHTTPError(http.StatusForbidden, "cannot overwrite an ancestor of the source")
	}
	overwrittenSize := int64(0)
	if destExisted {
		overwrittenSize, err = fileTreeSizeTx(ctx, tx, w.user.ID, destRelCanon)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
	}

	isDir := srcFi.IsDir()
	copiedSize := int64(0)
	if !(isDir && depth == "0") {
		copiedSize, err = fileTreeSizeTx(ctx, tx, w.user.ID, relCanon)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
	}
	if err := w.enforceQuotaDeltaTx(ctx, tx, copiedSize-overwrittenSize); err != nil {
		return err
	}

	destBackup := ""
	copiedDest := false
	committed := false
	defer func() {
		if committed {
			return
		}
		if destBackup != "" {
			restoreBackedUpPath(destFsAbs, destBackup)
		} else if copiedDest {
			_ = os.RemoveAll(destFsAbs)
		}
	}()

	// If dest exists, remove it first.
	if destExisted {
		destBackup, err = backupExistingPath(destFsAbs)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
		if _, err := tx.ExecContext(ctx, `
            DELETE FROM files
            WHERE user_id = $1
              AND (path = $2 OR LEFT(path, length($2) + 1) = $2 || '/')
        `, w.user.ID, destRelCanon); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
		_, err := updateAncestorSizes(ctx, tx, w.user.ID, destRelCanon, -overwrittenSize)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
	}

	now := time.Now().UTC()

	if isDir && depth == "infinity" {
		copiedDest = true
		// Use DB rows as source of truth for which files to copy,
		// since the filesystem walk could race with concurrent PUTs.
		type srcRow struct {
			Path        string    `db:"path"`
			IsDir       bool      `db:"is_dir"`
			SizeBytes   int64     `db:"size_bytes"`
			Mtime       time.Time `db:"mtime"`
			ContentSHA1 *string   `db:"content_sha1"`
		}
		var srcRows []srcRow
		if err := tx.SelectContext(ctx, &srcRows, `
			SELECT path, is_dir, size_bytes, mtime, content_sha1
			FROM files
			WHERE user_id = $1
			  AND (path = $2 OR LEFT(path, length($2) + 1) = $2 || '/')
			ORDER BY path
		`, w.user.ID, relCanon); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		// Copy filesystem entries only for what's in the DB snapshot.
		for _, row := range srcRows {
			suffix := strings.TrimPrefix(row.Path[len(relCanon):], "/")
			srcPath := filepath.Join(fsAbs, suffix)
			dstPath := filepath.Join(destFsAbs, suffix)
			if row.IsDir {
				if err := os.MkdirAll(dstPath, 0o750); err != nil {
					_ = os.RemoveAll(destFsAbs)
					return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
				}
			} else {
				if err := os.MkdirAll(filepath.Dir(dstPath), 0o750); err != nil {
					_ = os.RemoveAll(destFsAbs)
					return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
				}
				if err := copyFileFS(srcPath, dstPath); err != nil {
					_ = os.RemoveAll(destFsAbs)
					return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
				}
			}
		}

		// Insert DB rows for dest using the snapshot.
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO files (user_id, path, is_dir, ocid, version, size_bytes, mtime, content_sha1, created_at, updated_at)
			SELECT $1,
				   $3 || substring(path from length($2) + 1),
				   is_dir, '', 1, size_bytes, mtime, content_sha1, $4, $4
			FROM files
			WHERE user_id = $1
			  AND (path = $2 OR LEFT(path, length($2) + 1) = $2 || '/')
			ON CONFLICT (user_id, path) DO NOTHING
		`, w.user.ID, relCanon, destRelCanon, now); err != nil {
			_ = os.RemoveAll(destFsAbs)
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		// Copy dead properties for all items in the subtree.
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO file_properties (user_id, path, namespace, local_name, value)
			SELECT $1,
				   $3 || substring(path from length($2) + 1),
				   namespace, local_name, value
			FROM file_properties
			WHERE user_id = $1
			  AND (path = $2 OR LEFT(path, length($2) + 1) = $2 || '/')
			ON CONFLICT (user_id, path, namespace, local_name) DO NOTHING
		`, w.user.ID, relCanon, destRelCanon); err != nil {
			_ = os.RemoveAll(destFsAbs)
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		// Update ancestor sizes for dest.
		_, err := updateAncestorSizes(ctx, tx, w.user.ID, destRelCanon, copiedSize)
		if err != nil {
			_ = os.RemoveAll(destFsAbs)
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

	} else if isDir && depth == "0" {
		// Depth 0 on a dir: copy only the directory itself, no children.
		copiedDest = true
		if err := os.Mkdir(destFsAbs, 0o750); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
		if _, err := tx.ExecContext(ctx, `
            INSERT INTO files (user_id, path, is_dir, ocid, version, size_bytes, mtime, content_sha1, created_at, updated_at)
            VALUES ($1, $2, true, '', 1, 0, $3, '', $3, $3)
            ON CONFLICT (user_id, path) DO NOTHING
        `, w.user.ID, destRelCanon, now); err != nil {
			_ = os.Remove(destFsAbs)
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO file_properties (user_id, path, namespace, local_name, value)
			SELECT $1, $3, namespace, local_name, value
			FROM file_properties
			WHERE user_id = $1 AND path = $2
			ON CONFLICT (user_id, path, namespace, local_name) DO NOTHING
		`, w.user.ID, relCanon, destRelCanon); err != nil {
			_ = os.Remove(destFsAbs)
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

	} else {
		// Copy single file.
		copiedDest = true
		if err := copyFileFS(fsAbs, destFsAbs); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		var out types.DbFile
		if err := tx.QueryRowxContext(ctx, `
            INSERT INTO files (user_id, path, is_dir, ocid, version, size_bytes, mtime, content_sha1, created_at, updated_at)
            SELECT $1, $3, false, '', 1, size_bytes, mtime, content_sha1, $4, $4
            FROM files WHERE user_id = $1 AND path = $2
            ON CONFLICT (user_id, path) DO UPDATE SET
                version      = files.version + 1,
                size_bytes   = EXCLUDED.size_bytes,
                mtime        = EXCLUDED.mtime,
                content_sha1 = EXCLUDED.content_sha1,
                updated_at   = EXCLUDED.updated_at
            RETURNING *
        `, w.user.ID, relCanon, destRelCanon, now).StructScan(&out); err != nil {
			_ = os.Remove(destFsAbs)
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		// Copy dead properties for the file.
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO file_properties (user_id, path, namespace, local_name, value)
			SELECT $1, $3, namespace, local_name, value
			FROM file_properties
			WHERE user_id = $1 AND path = $2
			ON CONFLICT (user_id, path, namespace, local_name) DO NOTHING
		`, w.user.ID, relCanon, destRelCanon); err != nil {
			_ = os.Remove(destFsAbs)
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		_, err := updateAncestorSizes(ctx, tx, w.user.ID, destRelCanon, out.SizeBytes)
		if err != nil {
			_ = os.Remove(destFsAbs)
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		etag := etagFromOCIDVersion(out.OCID, out.Version)
		c.Response().Header().Set("ETag", etag)
		c.Response().Header().Set("OC-ETag", etag)
		c.Response().Header().Set("OC-Fileid", out.OCID)
	}

	if err := tx.Commit(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	committed = true
	if destBackup != "" {
		_ = os.RemoveAll(destBackup)
	}
	if err := w.queuePreviewsForPath(ctx, destRelCanon); err != nil {
		slog.Warn("failed to queue previews after DAV COPY", "path", destRelCanon, "error", err)
	}

	if destExisted {
		return c.NoContent(http.StatusNoContent)
	}
	return c.NoContent(http.StatusCreated)
}

func (w *WebDAV) queuePreviewsForPath(ctx context.Context, relCanon string) error {
	var fileIDs []string
	if err := w.db.SelectContext(ctx, &fileIDs, `
		SELECT ocid
		FROM files
		WHERE user_id = $1
		  AND is_dir = false
		  AND (path = $2 OR LEFT(path, length($2) + 1) = $2 || '/')
	`, w.user.ID, relCanon); err != nil {
		return err
	}
	for _, fileID := range fileIDs {
		if err := w.h.app.State.Previews.Enqueue(fileID); err != nil {
			return err
		}
	}
	return nil
}

func (w *WebDAV) handleDAVProppatch(c *echo.Context) error {
	fsAbs, relCanon, _, err := w.mapDAVRequestToFS(c.Request().URL.Path)
	if err != nil {
		return err
	}

	fi, err := os.Stat(fsAbs)
	if err != nil {
		if os.IsNotExist(err) {
			return echo.NewHTTPError(http.StatusNotFound, "not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	var body []byte
	if c.Request().Body != nil {
		body, _ = io.ReadAll(io.LimitReader(c.Request().Body, 1<<20))
		_ = c.Request().Body.Close()
	}

	type xmlPropOp struct {
		IsSet bool
		Props []types.WebDAVDeadProperty
	}

	// Parse in document order to preserve set/remove sequencing.
	var ops []xmlPropOp
	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.DefaultSpace = "DAV:"
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid XML request body")
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		local := strings.ToLower(se.Name.Local)
		if (local == "set" || local == "remove") && (se.Name.Space == "DAV:" || se.Name.Space == "") {
			isSet := local == "set"
			var propEl struct {
				Any []types.WebDAVDeadProperty `xml:",any"`
			}
			// Find and decode the nested <prop> element.
			for {
				inner, err := dec.Token()
				if err != nil {
					break
				}
				innerSE, ok := inner.(xml.StartElement)
				if !ok {
					if _, ok := inner.(xml.EndElement); ok {
						break
					}
					continue
				}
				if strings.ToLower(innerSE.Name.Local) == "prop" {
					_ = dec.DecodeElement(&propEl, &innerSE)
					break
				}
			}
			if len(propEl.Any) > 0 {
				ops = append(ops, xmlPropOp{IsSet: isSet, Props: propEl.Any})
			}
		}
	}

	type propResult struct {
		XMLName xml.Name
		Status  string
	}
	var results []propResult

	ctx := c.Request().Context()

	ancestors := utils.ParentPaths(relCanon)
	exclusive := []string{relCanon}

	conn, err := w.db.Connx(ctx)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() { _ = conn.Close() }()

	var sessionLocks davSessionLocks
	defer w.unlockDAVSessionLocks(conn, &sessionLocks)

	if err := w.lockDAVSessionLocks(conn, ctx, exclusive, ancestors, &sessionLocks); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	tx, err := conn.BeginTxx(ctx, nil)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() { _ = tx.Rollback() }()

	if err := w.checkLockTx(ctx, tx, relCanon, c.Request().Header.Get("If")); err != nil {
		return err
	}

	// Process in document order.
	for _, op := range ops {
		for _, prop := range op.Props {
			if op.IsSet {
				localLower := strings.ToLower(prop.XMLName.Local)
				handled := false

				if localLower == "lastmodified" || localLower == "x-oc-mtime" || localLower == "win32lastmodifiedtime" {
					val := strings.TrimSpace(prop.InnerXML)
					var t time.Time
					if sec, err := strconv.ParseInt(val, 10, 64); err == nil && sec > 0 {
						t = time.Unix(sec, 0).UTC()
					} else if parsed, err := http.ParseTime(val); err == nil {
						t = parsed.UTC()
					}
					if !t.IsZero() {
						_ = os.Chtimes(fsAbs, t, t)
						if _, err := tx.ExecContext(ctx, `
							UPDATE files SET mtime = $3, updated_at = NOW()
							WHERE user_id = $1 AND path = $2
						`, w.user.ID, relCanon, t); err != nil {
							return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
						}
						handled = true
					}
				}

				if !handled {
					if _, err := tx.ExecContext(ctx, `
						INSERT INTO file_properties (user_id, path, namespace, local_name, value)
						VALUES ($1, $2, $3, $4, $5)
						ON CONFLICT (user_id, path, namespace, local_name) DO UPDATE SET value = EXCLUDED.value
					`, w.user.ID, relCanon, prop.XMLName.Space, prop.XMLName.Local, prop.InnerXML); err != nil {
						return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
					}
				}
			} else {
				if _, err := tx.ExecContext(ctx, `
					DELETE FROM file_properties
					WHERE user_id = $1 AND path = $2 AND namespace = $3 AND local_name = $4
				`, w.user.ID, relCanon, prop.XMLName.Space, prop.XMLName.Local); err != nil {
					return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
				}
			}
			results = append(results, propResult{XMLName: prop.XMLName, Status: "HTTP/1.1 200 OK"})
		}
	}

	if err := tx.Commit(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	type proppatchProp struct {
		XMLName xml.Name
	}
	type proppatchPropBag struct {
		Props []proppatchProp `xml:",any"`
	}

	statusMap := map[string][]proppatchProp{}
	for _, r := range results {
		statusMap[r.Status] = append(statusMap[r.Status], proppatchProp{XMLName: r.XMLName})
	}

	var propStats []types.WebDAVPropstat
	for status, props := range statusMap {
		propStats = append(propStats, types.WebDAVPropstat{
			Prop:   proppatchPropBag{Props: props},
			Status: status,
		})
	}

	href := c.Request().URL.Path
	if fi.IsDir() && !strings.HasSuffix(href, "/") {
		href += "/"
	}

	ms := types.WebDAVMultiStatus{
		XmlnsD:  "DAV:",
		XmlnsS:  "http://sabredav.org/ns",
		XmlnsOC: "http://owncloud.org/ns",
		XmlnsNC: "http://nextcloud.org/ns",
		Responses: []types.WebDAVResponse{
			{Href: href, Propstat: propStats},
		},
	}

	out, err := xml.Marshal(ms)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	payload := append([]byte(xml.Header), out...)
	return c.Blob(http.StatusMultiStatus, "application/xml; charset=utf-8", payload)
}

func newLockToken() string {
	return "urn:uuid:" + uuid.New().String()
}

func (w *WebDAV) writeLockResponse(c *echo.Context, token, relCanon, depth, ownerXML, scope string, timeoutSecs, status int) error {
	href := c.Request().URL.Path

	ownerEl := ""
	if ownerXML != "" {
		ownerEl = "<d:owner>" + ownerXML + "</d:owner>"
	}

	scopeEl := "<d:lockscope><d:exclusive/></d:lockscope>"
	if scope == "shared" {
		scopeEl = "<d:lockscope><d:shared/></d:lockscope>"
	}

	body := `<?xml version="1.0" encoding="utf-8"?>` +
		`<d:prop xmlns:d="DAV:">` +
		`<d:lockdiscovery>` +
		`<d:activelock>` +
		`<d:locktype><d:write/></d:locktype>` +
		scopeEl +
		`<d:depth>` + depth + `</d:depth>` +
		ownerEl +
		`<d:timeout>Second-` + strconv.Itoa(timeoutSecs) + `</d:timeout>` +
		`<d:locktoken><d:href>` + token + `</d:href></d:locktoken>` +
		`<d:lockroot><d:href>` + href + `</d:href></d:lockroot>` +
		`</d:activelock>` +
		`</d:lockdiscovery>` +
		`</d:prop>`

	c.Response().Header().Set("Lock-Token", "<"+token+">")
	return c.Blob(status, "application/xml; charset=utf-8", []byte(body))
}

func (w *WebDAV) handleDAVLock(c *echo.Context) error {
	ctx := c.Request().Context()

	_, relCanon, _, err := w.mapDAVRequestToFS(c.Request().URL.Path)
	if err != nil {
		return err
	}

	// Parse Timeout header.
	timeoutSecs := 3600
	if th := c.Request().Header.Get("Timeout"); th != "" {
		for _, part := range strings.Split(th, ",") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "Second-") {
				if n, err := strconv.Atoi(strings.TrimPrefix(part, "Second-")); err == nil && n > 0 {
					timeoutSecs = n
				}
				break
			}
		}
	}
	timeoutAt := time.Now().Add(time.Duration(timeoutSecs) * time.Second)

	depth, err := normalizeDAVDepth(c.Request().Header.Get("Depth"), "infinity", "0", "infinity")
	if err != nil {
		return err
	}

	var body []byte
	if c.Request().Body != nil {
		body, _ = io.ReadAll(io.LimitReader(c.Request().Body, 1<<20))
		_ = c.Request().Body.Close()
	}

	// Parse lockinfo.
	type xmlLockInfo struct {
		Scope struct {
			Exclusive *struct{} `xml:"exclusive"`
			Shared    *struct{} `xml:"shared"`
		} `xml:"lockscope"`
		Owner struct {
			InnerXML string `xml:",innerxml"`
		} `xml:"owner"`
	}
	var li xmlLockInfo
	scope := "exclusive"
	ownerXML := ""
	if len(body) > 0 {
		_ = xml.Unmarshal(body, &li)
		if li.Scope.Shared != nil {
			scope = "shared"
		}
		ownerXML = li.Owner.InnerXML
	}

	tx, err := w.db.BeginTxx(ctx, nil)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `LOCK TABLE locks IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	// Refresh existing lock if If header contains a valid token.
	ifHeader := c.Request().Header.Get("If")
	if ifHeader != "" {
		token := extractLockToken(ifHeader)
		if token != "" {
			var existingOwner, existingScope, existingDepth string
			err := tx.QueryRowxContext(ctx, `
				UPDATE locks SET timeout_at = $3
				WHERE token = $1 AND user_id = $2 AND timeout_at > NOW()
				RETURNING owner_xml, scope, depth
			`, token, w.user.ID, timeoutAt).Scan(&existingOwner, &existingScope, &existingDepth)
			if err == nil {
				if err := tx.Commit(); err != nil {
					return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
				}
				return w.writeLockResponse(c, token, relCanon, existingDepth, existingOwner, existingScope, timeoutSecs, http.StatusOK)
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
			}
		}
	}

	// Only exclusive locks conflict with everything.
	// Shared locks conflict only with exclusive locks.
	var conflictCount int
	if err := tx.QueryRowxContext(ctx, `
		SELECT COUNT(*) FROM locks
		WHERE user_id = $1
		  AND timeout_at > NOW()
		  AND (scope = 'exclusive' OR $3 = 'exclusive')
		  AND (
			path = $2
			OR (depth = 'infinity' AND (path = '' OR LEFT($2, length(path) + 1) = path || '/'))
			OR ($4 = 'infinity' AND ($2 = '' OR LEFT(path, length($2) + 1) = $2 || '/'))
		  )
	`, w.user.ID, relCanon, scope, depth).Scan(&conflictCount); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	if conflictCount > 0 {
		return echo.NewHTTPError(http.StatusLocked, "resource is already locked")
	}

	// Create new lock.
	token := newLockToken()
	if _, err := tx.ExecContext(ctx, `
        INSERT INTO locks (token, user_id, path, depth, scope, owner_xml, timeout_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
    `, token, w.user.ID, relCanon, depth, scope, ownerXML, timeoutAt); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	// 201 if resource doesn't exist yet (lock-null), 200 otherwise.
	statusCode := http.StatusOK
	var fileCount int
	_ = tx.QueryRowxContext(ctx, `
        SELECT COUNT(*) FROM files WHERE user_id = $1 AND path = $2
    `, w.user.ID, relCanon).Scan(&fileCount)
	if fileCount == 0 {
		statusCode = http.StatusCreated
	}

	if err := tx.Commit(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return w.writeLockResponse(c, token, relCanon, depth, ownerXML, scope, timeoutSecs, statusCode)
}

func (w *WebDAV) handleDAVUnlock(c *echo.Context) error {
	ctx := c.Request().Context()

	lockTokenHeader := c.Request().Header.Get("Lock-Token")
	token := strings.Trim(lockTokenHeader, "<>")
	if token == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing Lock-Token header")
	}

	result, err := w.db.ExecContext(ctx, `
        DELETE FROM locks
        WHERE token = $1 AND user_id = $2
    `, token, w.user.ID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return echo.NewHTTPError(http.StatusConflict, "lock not found")
	}

	return c.NoContent(http.StatusNoContent)
}
