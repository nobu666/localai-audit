package main

// Service is a local AI service we know how to probe.
// Path must be an endpoint that answers 2xx without auth when the
// service has no auth, and 401/403 when it requires auth.
type Service struct {
	Name  string
	Ports []int
	Path  string
	Sig   Signature // optional: how to confirm this is really that service
}

// Identification is by port, then confirmed by Signature where one is
// known. Same-port services without a match stay listed as candidates.
var services = []Service{
	{"Ollama", []int{11434}, "/api/tags", Signature{"/api/tags", `"models"`}},
	{"LM Studio", []int{1234}, "/v1/models", Signature{"/api/v0/models", "compatibility_type"}}, // shape confirmed on LM Studio 0.4.24
	{"llama.cpp", []int{8080}, "/v1/models", Signature{"/props", "default_generation_settings"}},
	{"LocalAI", []int{8080}, "/v1/models", Signature{"/", "LocalAI"}}, // index page title; confirmed on v3.0.0
	{"vLLM", []int{8000}, "/v1/models", Signature{}},
	{"Jan", []int{1337}, "/v1/models", Signature{}},
	{"text-generation-webui", []int{5000}, "/v1/models", Signature{}},
	{"KoboldCpp", []int{5001}, "/api/v1/model", Signature{"/api/extra/version", "KoboldCpp"}},
	{"Open WebUI", []int{8080, 3000}, "/api/v1/auths/", Signature{"/api/config", `"Open WebUI"`}}, // confirmed on 0.11.3
	{"ComfyUI", []int{8188}, "/system_stats", Signature{"/system_stats", "comfyui_version"}},
	{"SD WebUI (A1111)", []int{7860}, "/sdapi/v1/options", Signature{"/sdapi/v1/options", "sd_model_checkpoint"}},
	{"Jupyter", []int{8888}, "/api/status", Signature{"/login", "Jupyter"}}, // login page title; confirmed on jupyter_server 2.21
	{"Chroma", []int{8000}, "/api/v2/heartbeat", Signature{"/api/v2/heartbeat", "nanosecond heartbeat"}},
	{"Qdrant", []int{6333}, "/collections", Signature{"/", "qdrant"}},
	{"Weaviate", []int{8080}, "/v1/.well-known/ready", Signature{"/v1/meta", "grpcMaxMessageSize"}},
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
