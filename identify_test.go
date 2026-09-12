package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIdentify(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tags":
			w.Write([]byte(`{"models":[]}`))
		case "/api/v0/models":
			w.Write([]byte(`{"data":[{"type":"llm"}]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer ts.Close()
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	port := atoi(portStr)
	cands := []Service{
		{"Ollama", nil, "/api/tags", Signature{"/api/tags", `"models"`}},
		{"LM Studio", nil, "/v1/models", Signature{"/api/v0/models", `"type"`}},
		{"llama.cpp", nil, "/v1/models", Signature{"/props", "default_generation_settings"}},
		{"LocalAI", nil, "/v1/models", Signature{}},
	}
	hits := identify(host, port, cands)
	if strings.Join(hits, ",") != "Ollama,LM Studio" {
		t.Errorf("want Ollama and LM Studio confirmed, got %v", hits)
	}
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}
