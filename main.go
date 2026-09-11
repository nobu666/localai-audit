// localai-audit checks local AI services (Ollama, LM Studio, ...) for the
// two exposures that let a web page or a LAN neighbour reach them:
// listening on all interfaces, and accepting requests with a foreign
// Host header (DNS rebinding).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	connectTimeout = 400 * time.Millisecond
	httpTimeout    = 3 * time.Second
	spoofHost      = "evil.example"
)

type Result struct {
	Port      int      `json:"port"`
	Service   string   `json:"service"`
	Listen    []string `json:"listen"`     // addresses that accepted a connection
	AllIfaces bool     `json:"all_ifaces"` // reachable on a non-loopback address
	Plain     int      `json:"plain_status"`
	Spoofed   int      `json:"spoofed_status"`
	Rebind    string   `json:"rebind"` // open | blocked | n/a | ?
	Auth      string   `json:"auth"`   // none | required | ?
	Red       bool     `json:"red"`
}

func main() {
	extra := flag.String("ports", "", "extra ports to check, comma separated")
	asJSON := flag.Bool("json", false, "output JSON")
	flag.Parse()

	ports := knownPorts()
	seen := map[int]bool{}
	for _, p := range ports {
		seen[p] = true
	}
	for _, p := range strings.Split(*extra, ",") {
		if p = strings.TrimSpace(p); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "bad port %q\n", p)
				os.Exit(2)
			}
			if !seen[n] {
				seen[n] = true
				ports = append(ports, n)
			}
		}
	}

	results := audit(ports, localAddrs())

	if *asJSON {
		json.NewEncoder(os.Stdout).Encode(results)
	} else {
		printTable(results)
	}
	for _, r := range results {
		if r.Red {
			os.Exit(1)
		}
	}
}

// localAddrs returns loopback first, then every unicast address on the host.
func localAddrs() []string {
	addrs := []string{"127.0.0.1", "::1"}
	ifAddrs, _ := net.InterfaceAddrs()
	for _, a := range ifAddrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() {
			continue
		}
		addrs = append(addrs, ipn.IP.String())
	}
	return addrs
}

func audit(ports []int, addrs []string) []Result {
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)
	open := map[int][]string{}

	for _, port := range ports {
		for _, addr := range addrs {
			wg.Add(1)
			sem <- struct{}{}
			go func(port int, addr string) {
				defer wg.Done()
				defer func() { <-sem }()
				c, err := net.DialTimeout("tcp", net.JoinHostPort(addr, strconv.Itoa(port)), connectTimeout)
				if err != nil {
					return
				}
				c.Close()
				mu.Lock()
				open[port] = append(open[port], addr)
				mu.Unlock()
			}(port, addr)
		}
	}
	wg.Wait()

	var results []Result
	for port, listen := range open {
		sort.Slice(listen, func(i, j int) bool { return isLoopback(listen[i]) && !isLoopback(listen[j]) })
		r := Result{Port: port, Listen: listen}
		for _, a := range listen {
			if !isLoopback(a) {
				r.AllIfaces = true
			}
		}
		cands := candidates(port)
		var names []string
		for _, c := range cands {
			names = append(names, c.Name)
		}
		r.Service = strings.Join(names, " / ")
		if r.Service == "" {
			r.Service = "(unknown)"
		}
		// Probe loopback and, when bound to all interfaces, the first
		// non-loopback address too: a service may check Host on one
		// path and not the other. Keep the worse result.
		probe(&r, listen[0], cands)
		if r.AllIfaces {
			ext := r
			probe(&ext, listen[len(listen)-1], cands)
			if ext.Rebind == "open" && r.Rebind != "open" {
				r = ext
			}
		}
		r.Red = r.AllIfaces || r.Rebind == "open"
		results = append(results, r)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })
	return results
}

func isLoopback(a string) bool { return net.ParseIP(a).IsLoopback() }

// probe fills Plain/Spoofed/Rebind/Auth. It tries each candidate's path
// until one is not 404, then sends the same request with a foreign Host.
func probe(r *Result, addr string, cands []Service) {
	var paths []string
	for _, c := range cands {
		paths = append(paths, c.Path)
	}
	paths = append(paths, "/")
	base := "http://" + net.JoinHostPort(addr, strconv.Itoa(r.Port))
	r.Rebind, r.Auth = "?", "?"

	for _, path := range paths {
		plain, err := get(base+path, "")
		if err != nil {
			return // not HTTP (or TLS); nothing more to say
		}
		if plain == http.StatusNotFound && path != "/" {
			continue
		}
		spoofed, _ := get(base+path, spoofHost)
		r.Plain, r.Spoofed = plain, spoofed
		r.Rebind, r.Auth = judge(plain, spoofed)
		return
	}
}

// judge derives the two verdicts from the plain and spoofed status codes.
func judge(plain, spoofed int) (rebind, auth string) {
	switch {
	case plain/100 == 2:
		auth = "none"
	case plain == http.StatusUnauthorized || plain == http.StatusForbidden:
		auth = "required"
	default:
		return "?", "?"
	}
	if auth == "required" {
		return "n/a", auth // cannot tell Host check from auth check
	}
	switch {
	case spoofed/100 == 2 || spoofed/100 == 3:
		rebind = "open"
	case spoofed/100 == 4:
		rebind = "blocked"
	default:
		rebind = "?"
	}
	return rebind, auth
}

var client = &http.Client{
	Timeout:       httpTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func get(url, host string) (int, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, err
	}
	if host != "" {
		req.Host = host
		req.Header.Set("Origin", "http://"+host)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

func printTable(results []Result) {
	if len(results) == 0 {
		fmt.Println("no local AI services found on known ports")
		return
	}
	fmt.Printf("%-6s %-28s %-10s %-8s %-9s %s\n", "PORT", "SERVICE", "LISTEN", "REBIND", "AUTH", "VERDICT")
	for _, r := range results {
		listen := "loopback"
		if r.AllIfaces {
			listen = "ALL"
		}
		verdict := "ok"
		if r.Red {
			verdict = "RED"
		}
		fmt.Printf("%-6d %-28s %-10s %-8s %-9s %s\n", r.Port, r.Service, listen, r.Rebind, r.Auth, verdict)
	}
}
