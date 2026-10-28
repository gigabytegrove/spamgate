package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRedesignAssetsEmbedded(t *testing.T) {
	for _, name := range []string{"tailwind.css", "redesign.css"} {
		req := httptest.NewRequest(http.MethodGet, "/assets/"+name, nil)
		w := httptest.NewRecorder()
		assetCSS(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s status %d", name, w.Code)
		}
		if !strings.HasPrefix(w.Header().Get("Content-Type"), "text/css") {
			t.Fatalf("%s incorrect content type", name)
		}
		if w.Body.Len() < 100 {
			t.Fatalf("%s empty asset", name)
		}
	}
	if !strings.Contains(indexHTML, "/assets/redesign.css") {
		t.Fatal("redesign not linked")
	}
	if !strings.Contains(indexHTML, "/assets/tailwind.css") {
		t.Fatal("tailwind not linked")
	}
}
