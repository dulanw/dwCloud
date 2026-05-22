package utils

import "testing"

func TestMapDAVRequestToFSAcceptsExpectedUsername(t *testing.T) {
	root := t.TempDir()
	_, rel, _, err := MapDAVRequestToFS("/remote.php/dav/files/bbrown1592/Documents", root, "bbrown1592")
	if err != nil {
		t.Fatalf("MapDAVRequestToFS returned error: %v", err)
	}
	if rel != "Documents" {
		t.Fatalf("rel = %q, want Documents", rel)
	}
}

func TestMapDAVRequestToFSRejectsOtherUsers(t *testing.T) {
	root := t.TempDir()
	_, _, _, err := MapDAVRequestToFS("/remote.php/dav/files/other-user/Documents", root, "bbrown1592")
	if err == nil {
		t.Fatalf("expected other-user to be rejected")
	}
}

func TestParentPathsIncludesRoot(t *testing.T) {
	tests := []struct {
		name string
		path string
		want []string
	}{
		{name: "root", path: "", want: nil},
		{name: "top level", path: "Documents", want: []string{""}},
		{name: "nested", path: "Documents/Reports/May.txt", want: []string{"", "Documents", "Documents/Reports"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParentPaths(tt.path)
			if len(got) != len(tt.want) {
				t.Fatalf("ParentPaths(%q) = %#v, want %#v", tt.path, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("ParentPaths(%q) = %#v, want %#v", tt.path, got, tt.want)
				}
			}
		})
	}
}
