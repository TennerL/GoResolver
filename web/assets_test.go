package web

import "testing"

func TestBuiltFrontendAssetsAreEmbedded(t *testing.T) {
	for _, path := range []string{"static/dist/app.js", "static/dist/app.css"} {
		if _, err := StaticFS.ReadFile(path); err != nil {
			t.Fatalf("expected embedded asset %s: %v", path, err)
		}
	}
}
