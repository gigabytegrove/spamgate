package server

import (
	"embed"
	"net/http"
	"strings"
)

//go:embed assets/index.html assets/app.css assets/app.js assets/spamgate-logo.png assets/spamgate-icon.png assets/favicon.png
var assetFS embed.FS
var indexHTML string

func init() {
	b, e := assetFS.ReadFile("assets/index.html")
	if e != nil {
		panic(e)
	}
	indexHTML = string(b)
}
func assetImage(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/assets/")
	switch name {
	case "spamgate-logo.png", "spamgate-icon.png", "favicon.png":
		serveAsset(w, r, "assets/"+name, "image/png")
	default:
		http.NotFound(w, r)
	}
}
func assetCSS(w http.ResponseWriter, r *http.Request) {
	serveAsset(w, r, "assets/app.css", "text/css; charset=utf-8")
}
func assetJS(w http.ResponseWriter, r *http.Request) {
	serveAsset(w, r, "assets/app.js", "text/javascript; charset=utf-8")
}
func serveAsset(w http.ResponseWriter, r *http.Request, path, typ string) {
	b, e := assetFS.ReadFile(path)
	if e != nil {
		http.Error(w, "Asset not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", typ)
	// Development builds update embedded HTML, JS and CSS together. Never cache
	// stale assets across binary upgrades or users can see the previous UI.
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
}
