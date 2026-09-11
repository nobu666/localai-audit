package main

// Service is a local AI service we know how to probe.
// Path must be an endpoint that answers 2xx without auth when the
// service has no auth, and 401/403 when it requires auth.
type Service struct {
	Name  string
	Ports []int
	Path  string
}

// ponytail: identification is by port only; same-port services are
// listed as candidates. Body-based fingerprinting when real responses
// are collected.
var services = []Service{
	{"Ollama", []int{11434}, "/api/tags"},
	{"LM Studio", []int{1234}, "/v1/models"},
	{"llama.cpp", []int{8080}, "/v1/models"},
	{"LocalAI", []int{8080}, "/v1/models"},
	{"vLLM", []int{8000}, "/v1/models"},
	{"Jan", []int{1337}, "/v1/models"},
	{"text-generation-webui", []int{5000}, "/v1/models"},
	{"KoboldCpp", []int{5001}, "/api/v1/model"},
	{"Open WebUI", []int{8080, 3000}, "/api/v1/auths/"},
	{"ComfyUI", []int{8188}, "/system_stats"},
	{"SD WebUI (A1111)", []int{7860}, "/sdapi/v1/options"},
	{"Jupyter", []int{8888}, "/api/status"},
	{"Chroma", []int{8000}, "/api/v2/heartbeat"},
	{"Qdrant", []int{6333}, "/collections"},
	{"Weaviate", []int{8080}, "/v1/.well-known/ready"},
}

// candidates returns the services registered for a port.
func candidates(port int) []Service {
	var out []Service
	for _, s := range services {
		for _, p := range s.Ports {
			if p == port {
				out = append(out, s)
			}
		}
	}
	return out
}

func knownPorts() []int {
	seen := map[int]bool{}
	var out []int
	for _, s := range services {
		for _, p := range s.Ports {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}
