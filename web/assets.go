package web

import "embed"

// Embed both the built static assets and the HTML shell used to mount the SPA.
//
//go:embed static templates
var StaticFS embed.FS
