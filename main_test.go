package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// hostChecking mimics Ollama on loopback: foreign Host is rejected.
func hostChecking(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Host, "127.0.0.1") && !strings.HasPrefix(r.Host, "localhost") {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.Write([]byte(`{"models":[]}`))
}

func portOf(ts *httptest.Server) int {
	_, p, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	n, _ := strconv.Atoi(p)
	return n
}

func TestJudge(t *testing.T) {
	cases := []struct {
		plain, spoofed int
		rebind, auth   string
	}{
		{200, 403, "blocked", "none"},
		{200, 200, "open", "none"},
		{200, 302, "open", "none"},
		{401, 401, "n/a", "required"},
		{500, 500, "?", "?"},
	}
	for _, c := range cases {
		rb, au := judge(c.plain, c.spoofed)
		if rb != c.rebind || au != c.auth {
			t.Errorf("judge(%d,%d) = %s,%s want %s,%s", c.plain, c.spoofed, rb, au, c.rebind, c.auth)
		}
	}
}

func TestAuditLoopbackWithHostCheck(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(hostChecking)) // binds 127.0.0.1
	defer ts.Close()
	res := audit([]int{portOf(ts)}, localAddrs())
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d", len(res))
	}
	r := res[0]
	if r.AllIfaces || r.Rebind != "blocked" || r.Auth != "none" || r.Red {
		t.Errorf("unexpected: %+v", r)
	}
}

func TestAuditAllIfacesOpen(t *testing.T) {
	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Skip(err)
	}
	ts := &httptest.Server{Listener: l, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})}}
	ts.Start()
	defer ts.Close()
	addrs := localAddrs()
	if len(addrs) <= 2 {
		t.Skip("no non-loopback address on this host")
	}
	res := audit([]int{portOf(ts)}, addrs)
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d", len(res))
	}
	r := res[0]
	if !r.AllIfaces || r.Rebind != "open" || !r.Red {
		t.Errorf("unexpected: %+v", r)
	}
}

// bindDependent mimics Ollama on 0.0.0.0: Host is checked only for
// requests that arrive on a loopback address.
func bindDependent(w http.ResponseWriter, r *http.Request) {
	local := r.Context().Value(http.LocalAddrContextKey).(net.Addr).(*net.TCPAddr)
	if local.IP.IsLoopback() && !strings.HasPrefix(r.Host, "127.0.0.1") && !strings.HasPrefix(r.Host, "[::1]") {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.Write([]byte("ok"))
}

func TestAuditProbesNonLoopbackToo(t *testing.T) {
	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Skip(err)
	}
	ts := &httptest.Server{Listener: l, Config: &http.Server{Handler: http.HandlerFunc(bindDependent)}}
	ts.Start()
	defer ts.Close()
	addrs := localAddrs()
	if len(addrs) <= 2 {
		t.Skip("no non-loopback address on this host")
	}
	res := audit([]int{portOf(ts)}, addrs)
	if len(res) != 1 || res[0].Rebind != "open" {
		t.Errorf("want rebind=open via non-loopback probe, got %+v", res)
	}
}

func TestAuditNothingOpen(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	if res := audit([]int{port}, localAddrs()); len(res) != 0 {
		t.Errorf("want no result, got %+v", res)
	}
}
