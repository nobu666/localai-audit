package main

import (
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// Signature is an endpoint whose 200 response body identifies a service.
// Only services whose response shape was confirmed from source or docs
// carry one (2026-09-12); the rest stay listed as candidates. The
// signature path must answer without credentials: a service that puts
// auth in front of it stays unconfirmed ("?") even though it is running.
type Signature struct {
	Path   string
	Marker string // substring of the body; "" means a 200 on the path is enough
}

const bodyLimit = 64 << 10

// identify returns the names of candidates whose signature matched on
// the open port. Services without a signature never match.
func identify(addr string, port int, cands []Service) []string {
	var hits []string
	for _, c := range cands {
		if c.Sig.Path == "" {
			continue
		}
		body, status, err := fetch("http://" + net.JoinHostPort(addr, strconv.Itoa(port)) + c.Sig.Path)
		if err != nil || status != http.StatusOK {
			continue
		}
		if c.Sig.Marker == "" || strings.Contains(body, c.Sig.Marker) {
			hits = append(hits, c.Name)
		}
	}
	return hits
}

func fetch(url string) (string, int, error) {
	resp, err := client.Get(url)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, bodyLimit))
	return string(b), resp.StatusCode, nil
}
