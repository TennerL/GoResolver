package web

import "embed"

// Embed the full static tree so nested build output like static/dist/app.js is available.
//go:embed static
var StaticFS embed.FS
