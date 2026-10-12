package attack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbeDebugPathsPprof(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/debug/pprof/" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><body>Types of profiles available:<a href=\"/debug/pprof/goroutine\">goroutine</a></body></html>"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	fs := probeDebugPaths(context.Background(), httpClient(), srv.URL)
	if len(fs) != 1 || fs[0].RuleID != "ATK-DEBUG" {
		t.Fatalf("expected one ATK-DEBUG for pprof, got %+v", fs)
	}
}

func TestProbeDebugPathsMarkerRequired(t *testing.T) {
	// A catch-all handler that returns 200 with unrelated content must not trip
	// any debug finding, since no marker matches.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("welcome home"))
	}))
	defer srv.Close()

	if fs := probeDebugPaths(context.Background(), httpClient(), srv.URL); len(fs) != 0 {
		t.Fatalf("expected no findings without a content marker, got %+v", fs)
	}
}

func TestAnalyzeHTTPDebugBody(t *testing.T) {
	body := "Traceback (most recent call last): File app.py, DJANGO_SETTINGS_MODULE=..."
	fs := analyzeHTTP("http://127.0.0.1:8000/", http.StatusInternalServerError, http.Header{}, body)
	found := false
	for _, f := range fs {
		if f.RuleID == "ATK-DEBUG" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected ATK-DEBUG from debug body markers, got %+v", fs)
	}
}
