package app

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

var ErrPreviewNotFound = errors.New("preview not found")

type PreviewService struct {
	db         *sqlx.DB
	storageDir string
	dir        string
	queuePath  string
	vipsPath   string
	ffmpegPath string

	mu     sync.Mutex
	queued map[string]struct{}
	status PreviewStatus
	wake   chan struct{}
}

type PreviewStatus struct {
	Running   bool
	StartedAt time.Time
	UpdatedAt time.Time
	Current   string
	Queued    int
	Processed int
	Generated int
	Skipped   int
	Failed    int
	LastError string
}

type previewSize struct {
	Width  int
	Height int
}

var previewSizes = []previewSize{
	{Width: 32, Height: 32},
	{Width: 256, Height: 256},
	{Width: 1024, Height: 1024},
	{Width: 2030, Height: 1920},
}

type previewQueueFile struct {
	FileIDs []string `json:"file_ids"`
}

type previewFile struct {
	ID         int64     `db:"id"`
	UserID     uuid.UUID `db:"user_id"`
	StorageDir string    `db:"storage_dir"`
	Path       string    `db:"path"`
	IsDir      bool      `db:"is_dir"`
	OCID       string    `db:"ocid"`
	Version    int64     `db:"version"`
}

func NewPreviewService(cfg *Config, db *sqlx.DB) (*PreviewService, error) {
	dir := filepath.Join(cfg.StorageDir, ".thumbnails")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}

	s := &PreviewService{
		db:         db,
		storageDir: cfg.StorageDir,
		dir:        dir,
		queuePath:  filepath.Join(dir, "queue.json"),
		queued:     make(map[string]struct{}),
		wake:       make(chan struct{}, 1),
	}
	if err := s.loadQueue(); err != nil {
		return nil, err
	}
	s.detectPreviewTools()
	return s, nil
}

func (s *PreviewService) detectPreviewTools() {
	if path, err := exec.LookPath("vips"); err == nil {
		s.vipsPath = path
	} else {
		slog.Warn("vips was not found; image previews will not be generated", "error", err)
	}

	if path, err := exec.LookPath("ffmpeg"); err == nil {
		s.ffmpegPath = path
	} else {
		slog.Warn("ffmpeg was not found; video previews will not be generated", "error", err)
	}
}

func (s *PreviewService) Start(ctx context.Context) {
	go s.run(ctx)
}

func (s *PreviewService) Status() PreviewStatus {
	s.mu.Lock()
	defer s.mu.Unlock()

	status := s.status
	status.Queued = len(s.queued)
	return status
}

func (s *PreviewService) Enqueue(fileID string) error {
	_, err := s.enqueueMany([]string{fileID})
	return err
}

func (s *PreviewService) EnqueueAll(ctx context.Context) (int, error) {
	var fileIDs []string
	if err := s.db.SelectContext(ctx, &fileIDs, `
		SELECT ocid
		FROM files
		WHERE is_dir = false
		ORDER BY id
	`); err != nil {
		return 0, err
	}
	return s.enqueueMany(fileIDs)
}

func (s *PreviewService) enqueueMany(fileIDs []string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	added := 0
	for _, fileID := range fileIDs {
		fileID = strings.TrimSpace(fileID)
		if fileID == "" {
			continue
		}
		if _, ok := s.queued[fileID]; ok {
			continue
		}
		s.queued[fileID] = struct{}{}
		added++
	}
	if added == 0 {
		return 0, nil
	}
	s.status.Queued = len(s.queued)
	s.status.UpdatedAt = time.Now().UTC()
	if err := s.saveQueueLocked(); err != nil {
		return 0, err
	}

	select {
	case s.wake <- struct{}{}:
	default:
	}
	return added, nil
}

func (s *PreviewService) Remove(fileID string) {
	fileID = strings.TrimSpace(fileID)
	if fileID == "" {
		return
	}
	s.mu.Lock()
	delete(s.queued, fileID)
	s.status.Queued = len(s.queued)
	s.status.UpdatedAt = time.Now().UTC()
	_ = s.saveQueueLocked()
	s.mu.Unlock()

	_ = os.RemoveAll(filepath.Join(s.dir, safePreviewID(fileID)))
}

func (s *PreviewService) Get(ctx context.Context, userID uuid.UUID, fileID string, x, y int, preserveAspect bool) ([]byte, string, error) {
	if x <= 0 {
		x = 256
	}
	if y <= 0 {
		y = 256
	}
	if x > 2048 {
		x = 2048
	}
	if y > 2048 {
		y = 2048
	}
	size := nearestPreviewSize(x, y)
	crop := !preserveAspect

	row, err := s.getFile(ctx, userID, fileID)
	if err != nil {
		return nil, "", ErrPreviewNotFound
	}

	etag := previewETag(row.OCID, row.Version, size.Width, size.Height, crop)
	thumbPath := s.thumbnailPath(row.OCID, row.Version, size.Width, size.Height, crop)
	if data, err := os.ReadFile(thumbPath); err == nil {
		return data, etag, nil
	} else if !os.IsNotExist(err) {
		return nil, "", err
	}

	if err := s.Enqueue(row.OCID); err != nil {
		return nil, "", err
	}
	return nil, etag, ErrPreviewNotFound
}

func (s *PreviewService) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		case <-time.After(30 * time.Second):
		}

		for {
			fileID := s.peek()
			if fileID == "" {
				break
			}
			err := s.generateQueued(ctx, fileID)
			if err == nil {
				s.complete(fileID, false)
				continue
			}
			if errors.Is(err, ErrPreviewNotFound) {
				s.complete(fileID, true)
				continue
			}
			if err != nil {
				s.fail(fileID, err)
				slog.Warn("failed to generate queued preview", "fileID", fileID, "error", err)
				break
			}
		}
	}
}

func (s *PreviewService) generateQueued(ctx context.Context, fileID string) error {
	row, err := s.getFile(ctx, uuid.Nil, fileID)
	if err != nil {
		return ErrPreviewNotFound
	}
	for _, size := range previewSizes {
		if _, err := s.generate(ctx, row, size.Width, size.Height, false); err != nil {
			return err
		}
	}
	return nil
}

func (s *PreviewService) peek() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	for fileID := range s.queued {
		now := time.Now().UTC()
		if !s.status.Running {
			s.status = PreviewStatus{
				Running:   true,
				StartedAt: now,
			}
		}
		s.status.Current = fileID
		s.status.Queued = len(s.queued)
		s.status.UpdatedAt = now
		return fileID
	}
	if s.status.Running {
		s.status.Running = false
		s.status.Current = ""
		s.status.Queued = 0
		s.status.UpdatedAt = time.Now().UTC()
	}
	return ""
}

func (s *PreviewService) complete(fileID string, skipped bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.queued, fileID)
	s.status.Processed++
	if skipped {
		s.status.Skipped++
	} else {
		s.status.Generated++
	}
	s.status.Current = ""
	s.status.Queued = len(s.queued)
	s.status.UpdatedAt = time.Now().UTC()
	if len(s.queued) == 0 {
		s.status.Running = false
	}
	_ = s.saveQueueLocked()
}

func (s *PreviewService) fail(fileID string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.status.Failed++
	s.status.Current = fileID
	s.status.Queued = len(s.queued)
	s.status.LastError = err.Error()
	s.status.Running = false
	s.status.UpdatedAt = time.Now().UTC()
}

func (s *PreviewService) loadQueue() error {
	data, err := os.ReadFile(s.queuePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var q previewQueueFile
	if err := json.Unmarshal(data, &q); err != nil {
		return err
	}
	for _, fileID := range q.FileIDs {
		if fileID = strings.TrimSpace(fileID); fileID != "" {
			s.queued[fileID] = struct{}{}
		}
	}
	return nil
}

func (s *PreviewService) saveQueueLocked() error {
	q := previewQueueFile{FileIDs: make([]string, 0, len(s.queued))}
	for fileID := range s.queued {
		q.FileIDs = append(q.FileIDs, fileID)
	}
	data, err := json.MarshalIndent(q, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.queuePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	return replaceGeneratedFile(tmp, s.queuePath)
}

func (s *PreviewService) getFile(ctx context.Context, userID uuid.UUID, fileID string) (*previewFile, error) {
	fileID = strings.TrimSpace(fileID)
	if fileID == "" {
		return nil, ErrPreviewNotFound
	}

	var row previewFile
	query := `
		SELECT f.id, f.user_id, u.storage_dir, f.path, f.is_dir, f.ocid, f.version
		FROM files f
		JOIN users u ON u.id = f.user_id
		WHERE (f.ocid = $1 OR f.id::text = $1)
		  AND f.is_dir = false
	`
	args := []any{fileID}
	if userID != uuid.Nil {
		query += ` AND f.user_id = $2`
		args = append(args, userID)
	}
	query += ` LIMIT 1`

	if err := s.db.GetContext(ctx, &row, query, args...); err != nil {
		return nil, err
	}
	return &row, nil
}

func (s *PreviewService) generate(ctx context.Context, row *previewFile, x, y int, crop bool) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	srcPath, err := s.sourcePath(row)
	if err != nil {
		return nil, err
	}
	thumbPath := s.thumbnailPath(row.OCID, row.Version, x, y, crop)
	if err := os.MkdirAll(filepath.Dir(thumbPath), 0o750); err != nil {
		return nil, err
	}

	f, err := os.Open(srcPath)
	if err != nil {
		return nil, ErrPreviewNotFound
	}

	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	contentType := http.DetectContentType(head[:n])
	_ = f.Close()

	if strings.HasPrefix(contentType, "image/") {
		if s.vipsPath == "" {
			return nil, ErrPreviewNotFound
		}
		if err := s.generateImageWithVips(ctx, srcPath, thumbPath, x, y, crop); err != nil {
			return nil, err
		}
		return os.ReadFile(thumbPath)
	}

	if strings.HasPrefix(contentType, "video/") || isVideoExtension(srcPath) {
		if s.ffmpegPath == "" {
			return nil, ErrPreviewNotFound
		}
		if err := s.generateVideoWithFFmpeg(ctx, srcPath, thumbPath, x, y, crop); err != nil {
			return nil, err
		}
		return os.ReadFile(thumbPath)
	}

	return nil, ErrPreviewNotFound
}

func (s *PreviewService) sourcePath(row *previewFile) (string, error) {
	srcPath := filepath.Clean(filepath.Join(s.storageDir, row.StorageDir, filepath.FromSlash(row.Path)))
	userRoot := filepath.Clean(filepath.Join(s.storageDir, row.StorageDir))
	rel, err := filepath.Rel(userRoot, srcPath)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", ErrPreviewNotFound
	}
	return srcPath, nil
}

func (s *PreviewService) generateImageWithVips(ctx context.Context, srcPath, thumbPath string, x, y int, crop bool) error {
	tmp := thumbPath + ".tmp." + strconv.FormatInt(time.Now().UnixNano(), 36) + ".jpg"
	// Use `vips thumbnail` rather than `vipsthumbnail`: it writes the output to
	// exactly the filename given. vipsthumbnail's `-o` is a name pattern whose
	// directory handling is version-dependent, and some builds drop the directory
	// and write the thumbnail next to the source or in the working directory,
	// which then makes the publish rename fail with "no such file or directory".
	args := []string{"thumbnail", srcPath, tmp + "[Q=85]", strconv.Itoa(x), "--height", strconv.Itoa(y)}
	if crop {
		args = append(args, "--crop", "centre")
	} else {
		args = append(args, "--size", "down")
	}

	cmd := exec.CommandContext(ctx, s.vipsPath, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		_ = os.Remove(tmp)
		if stderr.Len() > 0 {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
		}
		return err
	}
	return replaceGeneratedFile(tmp, thumbPath)
}

func (s *PreviewService) generateVideoWithFFmpeg(ctx context.Context, srcPath, thumbPath string, x, y int, crop bool) error {
	tmp := thumbPath + ".tmp." + strconv.FormatInt(time.Now().UnixNano(), 36) + ".jpg"
	filter := fmt.Sprintf("thumbnail,scale=%d:%d:force_original_aspect_ratio=decrease,pad=%d:%d:(ow-iw)/2:(oh-ih)/2", x, y, x, y)
	if crop {
		filter = fmt.Sprintf("thumbnail,scale=%d:%d:force_original_aspect_ratio=increase,crop=%d:%d", x, y, x, y)
	}

	args := []string{
		"-hide_banner",
		"-loglevel", "error",
		"-y",
		"-ss", "10",
		"-i", srcPath,
		"-vf", filter,
		"-frames:v", "1",
		"-q:v", "3",
		tmp,
	}

	if err := s.runFFmpeg(ctx, args, tmp); err == nil {
		return replaceGeneratedFile(tmp, thumbPath)
	}

	args = []string{
		"-hide_banner",
		"-loglevel", "error",
		"-y",
		"-i", srcPath,
		"-vf", filter,
		"-frames:v", "1",
		"-q:v", "3",
		tmp,
	}
	if err := s.runFFmpeg(ctx, args, tmp); err != nil {
		return err
	}
	return replaceGeneratedFile(tmp, thumbPath)
}

func replaceGeneratedFile(tmp string, dst string) error {
	if err := os.Rename(tmp, dst); err == nil {
		return nil
	} else if runtime.GOOS != "windows" {
		_ = os.Remove(tmp)
		return err
	} else {
		if _, statErr := os.Stat(dst); statErr != nil {
			_ = os.Remove(tmp)
			if os.IsNotExist(statErr) {
				return err
			}
			return statErr
		}
	}

	backup := dst + ".bak." + strconv.FormatInt(time.Now().UnixNano(), 36)
	if err := os.Rename(dst, backup); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Rename(backup, dst)
		_ = os.Remove(tmp)
		return err
	}
	_ = os.Remove(backup)
	return nil
}

func (s *PreviewService) runFFmpeg(ctx context.Context, args []string, tmp string) error {
	cmd := exec.CommandContext(ctx, s.ffmpegPath, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		_ = os.Remove(tmp)
		if stderr.Len() > 0 {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
		}
		return err
	}
	return nil
}

func isVideoExtension(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".3g2", ".3gp", ".avi", ".m4v", ".mkv", ".mov", ".mp4", ".mpeg", ".mpg", ".ogv", ".webm", ".wmv":
		return true
	default:
		return false
	}
}

func (s *PreviewService) thumbnailPath(ocid string, version int64, x, y int, crop bool) string {
	name := fmt.Sprintf("v%d_%dx%d", version, x, y)
	if crop {
		name += "_crop"
	}
	return filepath.Join(s.dir, safePreviewID(ocid), name+".jpg")
}

func safePreviewID(fileID string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "..", "_")
	return replacer.Replace(fileID)
}

func previewETag(ocid string, version int64, x, y int, crop bool) string {
	sum := md5.Sum([]byte(fmt.Sprintf("%s:%d:%d:%d:%t", ocid, version, x, y, crop)))
	return hex.EncodeToString(sum[:])
}

func nearestPreviewSize(width, height int) previewSize {
	best := previewSizes[len(previewSizes)-1]
	for _, size := range previewSizes {
		if size.Width >= width && size.Height >= height {
			best = size
			break
		}
	}
	return best
}
