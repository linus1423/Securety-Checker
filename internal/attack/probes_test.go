package attack

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRedisUnauthenticated(t *testing.T) {
	cases := []struct {
		resp string
		want bool
	}{
		{"+PONG\r\n", true},
		{"-NOAUTH Authentication required.\r\n", false},
		{"-ERR authentication required\r\n", false},
		{"", false},
		{"$garbage", false},
	}
	for _, tc := range cases {
		if got := redisUnauthenticated(tc.resp); got != tc.want {
			t.Errorf("redisUnauthenticated(%q) = %v, want %v", tc.resp, got, tc.want)
		}
	}
}

// tcpOnce starts a listener that answers the first connection with reply, then
// returns its host and port. It closes itself when the test ends.
func tcpOnce(t *testing.T, reply string) (host, port string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 256)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte(reply))
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	return h, p
}

func TestProbeServicesRedis(t *testing.T) {
	h, p := tcpOnce(t, "+PONG\r\n")
	tgt := Target{Host: h, Port: p, ContainerPort: "6379"}
	fs := ProbeServices(context.Background(), tgt)
	if len(fs) != 1 || fs[0].RuleID != "ATK-NOAUTH" {
		t.Fatalf("expected one ATK-NOAUTH finding for open Redis, got %+v", fs)
	}

	h2, p2 := tcpOnce(t, "-NOAUTH Authentication required.\r\n")
	if fs := ProbeServices(context.Background(), Target{Host: h2, Port: p2, ContainerPort: "6379"}); len(fs) != 0 {
		t.Errorf("expected no finding for password-protected Redis, got %+v", fs)
	}
}

func hostPort(t *testing.T, srv *httptest.Server) (host, port string) {
	t.Helper()
	u := strings.TrimPrefix(srv.URL, "http://")
	h, p, err := net.SplitHostPort(u)
	if err != nil {
		t.Fatal(err)
	}
	return h, p
}

func TestProbeServicesElasticsearch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"cluster_name":"docker-cluster","lucene_version":"9.7.0"}`))
	}))
	defer srv.Close()
	h, p := hostPort(t, srv)
	fs := ProbeServices(context.Background(), Target{Host: h, Port: p, ContainerPort: "9200"})
	if len(fs) != 1 || fs[0].RuleID != "ATK-NOAUTH" {
		t.Fatalf("expected ATK-NOAUTH for open Elasticsearch, got %+v", fs)
	}
}

func TestProbeServicesRabbitDefaultCreds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if ok && u == "guest" && p == "guest" {
			w.Write([]byte(`{"rabbitmq_version":"3.12.0"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	h, p := hostPort(t, srv)
	fs := ProbeServices(context.Background(), Target{Host: h, Port: p, ContainerPort: "15672"})
	if len(fs) != 1 || fs[0].RuleID != "ATK-DEFAULTCRED" {
		t.Fatalf("expected ATK-DEFAULTCRED for guest:guest, got %+v", fs)
	}
}

func TestProbeAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/openapi.json":
			w.Write([]byte(`{"openapi":"3.0.0","paths":{}}`))
		case r.URL.Path == "/graphql" && r.Method == http.MethodPost:
			w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"}}}}`))
		case strings.Contains(r.URL.Path, "etc/passwd"):
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))
		case r.URL.RawQuery != "" && strings.Contains(r.URL.RawQuery, "%27") || strings.Contains(r.URL.RawQuery, "'"):
			w.Write([]byte("You have an error in your SQL syntax near '''"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	fs := ProbeAPI(context.Background(), srv.URL)
	ids := ruleIDs(fs)
	for _, want := range []string{"ATK-APIDOC", "ATK-GRAPHQL", "ATK-TRAVERSAL", "ATK-SQLI"} {
		if !ids[want] {
			t.Errorf("expected %s finding, got %+v", want, fs)
		}
	}
}

func TestProbeAPIClean(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	if fs := ProbeAPI(context.Background(), srv.URL); len(fs) != 0 {
		t.Errorf("expected no API findings on a clean server, got %+v", fs)
	}
}
