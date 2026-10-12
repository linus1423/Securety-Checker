package attack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/linus1423/Securety-Checker/internal/sandbox"
)

// httpContainer builds a container whose published port points at srv, so the
// native HTTP probes have a real endpoint to hit.
func httpContainer(t *testing.T, name string, srv *httptest.Server) sandbox.Container {
	t.Helper()
	host, port := hostPort(t, srv)
	var c sandbox.Container
	c.Name = "/" + name
	c.NetworkSettings.Ports = map[string][]struct {
		HostIP   string `json:"HostIp"`
		HostPort string `json:"HostPort"`
	}{"80/tcp": {{HostIP: host, HostPort: port}}}
	return c
}

func TestRunParallelCollectsFindings(t *testing.T) {
	// A server that omits every security header, so ProbeHTTP reports ATK-HEADER.
	newSrv := func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("hello"))
		}))
	}
	s1, s2, s3 := newSrv(), newSrv(), newSrv()
	defer s1.Close()
	defer s2.Close()
	defer s3.Close()

	containers := []sandbox.Container{
		httpContainer(t, "a", s1),
		httpContainer(t, "b", s2),
		httpContainer(t, "c", s3),
	}

	var (
		mu    sync.Mutex
		steps []string
	)
	fs := Run(context.Background(), containers, Options{
		Concurrency: 3,
		Progress: func(s string) {
			mu.Lock()
			steps = append(steps, s)
			mu.Unlock()
		},
	})

	// Each of the three targets should contribute at least one ATK-HEADER finding.
	header := 0
	for _, f := range fs {
		if f.RuleID == "ATK-HEADER" {
			header++
		}
	}
	if header != 3 {
		t.Fatalf("expected 3 ATK-HEADER findings (one per target), got %d in %+v", header, fs)
	}
	if len(steps) < 3 {
		t.Errorf("expected a progress line per target, got %v", steps)
	}
	for _, s := range steps {
		if !strings.HasPrefix(s, "Probe ") {
			t.Errorf("unexpected progress line %q", s)
		}
	}
}
