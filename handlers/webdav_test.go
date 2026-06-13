package handlers

import (
	"dwCloud/types"
	"net/http"
	"testing"
	"time"
)

func TestETagHelpers(t *testing.T) {
	etag := etagFromOCIDVersion("00000001ocabcdef", 7)
	if len(etag) != 34 || etag[0] != '"' || etag[len(etag)-1] != '"' {
		t.Fatalf("etagFromOCIDVersion() = %q, want quoted 32-char digest", etag)
	}

	current := `"abc123"`
	for _, header := range []string{`"abc123"`, `W/"abc123"`, `"other", "abc123"`, `*`} {
		if !etagHeaderMatches(header, current) {
			t.Fatalf("etagHeaderMatches(%q, %q) = false, want true", header, current)
		}
	}
	if etagHeaderMatches(`"other"`, current) {
		t.Fatalf("unexpected ETag match")
	}
}

func TestDAVModTimeUsesDatabaseRow(t *testing.T) {
	want := time.Date(2024, time.March, 14, 15, 9, 26, 0, time.UTC)
	row := &types.DbFile{Mtime: want}

	if got := davModTime(row); !got.Equal(want) {
		t.Fatalf("davModTime() = %s, want %s", got, want)
	}
}

func TestDAVPathIsDescendant(t *testing.T) {
	tests := []struct {
		parent string
		child  string
		want   bool
	}{
		{parent: "Photos", child: "Photos/2026", want: true},
		{parent: "Photos", child: "Photos", want: false},
		{parent: "Photos", child: "Photoshop/file.txt", want: false},
		{parent: "", child: "Photos", want: false},
	}

	for _, tt := range tests {
		if got := davPathIsDescendant(tt.parent, tt.child); got != tt.want {
			t.Fatalf("davPathIsDescendant(%q, %q) = %t, want %t", tt.parent, tt.child, got, tt.want)
		}
	}
}

func TestNormalizeDAVDepth(t *testing.T) {
	tests := []struct {
		raw     string
		want    string
		wantErr bool
	}{
		{raw: "", want: "infinity"},
		{raw: "0", want: "0"},
		{raw: "Infinity", want: "infinity"},
		{raw: "  infinity  ", want: "infinity"},
		{raw: "1", wantErr: true},
	}

	for _, tt := range tests {
		got, err := normalizeDAVDepth(tt.raw, "infinity", "0", "infinity")
		if tt.wantErr {
			if err == nil {
				t.Fatalf("normalizeDAVDepth(%q) returned nil error", tt.raw)
			}
			continue
		}
		if err != nil {
			t.Fatalf("normalizeDAVDepth(%q) returned error: %v", tt.raw, err)
		}
		if got != tt.want {
			t.Fatalf("normalizeDAVDepth(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

func TestDAVIfHeaderEvaluatesLockAndETag(t *testing.T) {
	parsed, ok := parseDAVIfHeader(`(<urn:uuid:token> ["etag"]) (Not <DAV:no-lock> ["etag"])`)
	if !ok {
		t.Fatalf("parseDAVIfHeader returned false")
	}

	active := activeDAVLockTokenSet([]string{"urn:uuid:token"})

	if allowed, status := evaluateDAVIfHeader(parsed.lists, `"etag"`, active); !allowed || status != 0 {
		t.Fatalf("valid lock token and ETag allowed=%t status=%d, want allowed", allowed, status)
	}

	if allowed, status := evaluateDAVIfHeader(parsed.lists, `"other"`, active); allowed || status != http.StatusPreconditionFailed {
		t.Fatalf("bogus ETag allowed=%t status=%d, want 412", allowed, status)
	}
}

func TestDAVIfHeaderRequiresMatchingTokenForLockedResource(t *testing.T) {
	parsed, ok := parseDAVIfHeader(`(<urn:uuid:token-x>) (Not <DAV:no-lock>)`)
	if !ok {
		t.Fatalf("parseDAVIfHeader returned false")
	}

	active := activeDAVLockTokenSet([]string{"urn:uuid:token"})
	if allowed, status := evaluateDAVIfHeader(parsed.lists, `"etag"`, active); allowed || status != http.StatusLocked {
		t.Fatalf("corrupt token allowed=%t status=%d, want 423", allowed, status)
	}
}

func TestDAVIfHeaderNoLockSentinelFails(t *testing.T) {
	parsed, ok := parseDAVIfHeader(`(<DAV:no-lock>)`)
	if !ok {
		t.Fatalf("parseDAVIfHeader returned false")
	}

	if allowed, status := evaluateDAVIfHeader(parsed.lists, `"etag"`, nil); allowed || status != http.StatusPreconditionFailed {
		t.Fatalf("DAV:no-lock allowed=%t status=%d, want 412", allowed, status)
	}
}

func TestDAVTaggedListAppliesToDepthInfinityParentLock(t *testing.T) {
	locks := []davLockRow{{
		Token: "urn:uuid:token",
		Depth: "infinity",
		Path:  "lockcoll",
	}}

	if !davTaggedListRelApplies("lockcoll", "lockcoll/lockme.txt", locks) {
		t.Fatalf("tagged list for depth-infinity lock root should apply to locked child")
	}

	if davTaggedListRelApplies("other", "lockcoll/lockme.txt", locks) {
		t.Fatalf("tagged list for unrelated resource should not apply")
	}
}

func TestDAVChildHref(t *testing.T) {
	tests := []struct {
		name      string
		selfHref  string
		relCanon  string
		childPath string
		isDir     bool
		want      string
	}{
		{
			name:      "root direct child file",
			selfHref:  "/remote.php/dav/files/admin/",
			relCanon:  "",
			childPath: "report final.txt",
			isDir:     false,
			want:      "/remote.php/dav/files/admin/report%20final.txt",
		},
		{
			name:      "root direct child dir",
			selfHref:  "/remote.php/dav/files/admin/",
			relCanon:  "",
			childPath: "Photos",
			isDir:     true,
			want:      "/remote.php/dav/files/admin/Photos/",
		},
		{
			name:      "nested descendant for depth infinity",
			selfHref:  "/remote.php/dav/files/admin/Photos/",
			relCanon:  "Photos",
			childPath: "Photos/2026/trip pics/img 1.jpg",
			isDir:     false,
			want:      "/remote.php/dav/files/admin/Photos/2026/trip%20pics/img%201.jpg",
		},
	}

	for _, tt := range tests {
		if got := davChildHref(tt.selfHref, tt.relCanon, tt.childPath, tt.isDir); got != tt.want {
			t.Fatalf("%s: davChildHref() = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestDAVContentType(t *testing.T) {
	if got := davContentType(&types.DbFile{Path: "Pictures", IsDir: true}); got != "httpd/unix-directory" {
		t.Fatalf("directory content type = %q, want httpd/unix-directory", got)
	}

	if got := davContentType(&types.DbFile{Path: "Pictures/photo.jpg"}); got != "image/jpeg" {
		t.Fatalf("jpg content type = %q, want image/jpeg", got)
	}

	if got := davContentType(&types.DbFile{Path: "unknown.blobthing"}); got != "application/octet-stream" {
		t.Fatalf("unknown content type = %q, want application/octet-stream", got)
	}
}
