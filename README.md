# localai-audit

Checks the local AI services on your machine (Ollama, LM Studio, llama.cpp, ...) for the two exposures that let a web page or a LAN neighbour talk to them without you noticing:

- **Listening on all interfaces** (`0.0.0.0` / `[::]`) instead of loopback.
- **Accepting a foreign `Host` header**, which is what a DNS-rebinding page sends. Ollama, for example, skips its `Host` check entirely once it is bound to a non-loopback address ([`allowedHostsMiddleware`](https://github.com/ollama/ollama/blob/main/server/routes.go)). That combination is how [CVE-2026-65105](https://nvidia.custhelp.com/app/answers/detail/a_id/5872) hijacked NemoClaw's Ollama from a single browser visit.

No root, no `lsof`, no dependencies. One static binary.

```
$ localai-audit
PORT   SERVICE  LISTEN    REBIND   AUTH  VERDICT
11434  Ollama   loopback  blocked  none  ok
```

Exit code is `1` when any row is `RED`, so it works in a cron job or CI. Columns are sized to their content; on a terminal too narrow for the table it prints one record per port instead.

## Install

```
go install github.com/nobu666/localai-audit@latest
```

## What it does

For every known port (plus any you pass with `--ports`), it tries to connect on `127.0.0.1`, `::1`, and every non-loopback address of the host. A port that answers on a non-loopback address is bound to all interfaces.

For each open port it then sends two GETs to the service's API path: one plain, one with `Host: evil.example` and `Origin: http://evil.example`. Redirects are not followed.

| Column | Meaning |
|---|---|
| `LISTEN` | `loopback` or `ALL` (reachable on a non-loopback address) |
| `REBIND` | `blocked`: plain 2xx, spoofed 4xx. `open`: spoofed 2xx/3xx, a rebinding page gets through. `n/a`: the service requires auth, so the Host check cannot be told apart. `?`: not HTTP, or unexpected status |
| `AUTH` | `none`: the API answered 2xx with no credentials. `required`: 401/403 |
| `VERDICT` | `RED` when `LISTEN` is `ALL` or `REBIND` is `open`. Either one is a separate attack path |

`--json` prints the same data, including every address that accepted a connection and the raw status codes.

## What it does not do

- It does not look at the host firewall. Connecting to your own LAN address goes through the loopback route, so `ufw` or the macOS application firewall never sees it. `LISTEN ALL` means the socket is bound to all interfaces, not that a neighbour can definitely reach it.
- It does not identify services by response body. Ports shared by several tools (8080: llama.cpp / LocalAI / Open WebUI / Weaviate) list all candidates. The verdict does not depend on which one it is.
- It does not send any request that changes state. Two GETs per port, nothing else.

## Known false positives

- **macOS port 5000 and 7000**: AirPlay Receiver (`ControlCenter`) listens on `*:5000`. It shows up as `ALL / n/a / required / RED`. Turn it off in System Settings > General > AirDrop & Handoff, or ignore the row.

## Fixing a RED

- **Ollama**: unset `OLLAMA_HOST`, or set it to `127.0.0.1:11434`. If you need LAN access, put a reverse proxy with auth in front; Ollama has no auth of its own.
- **LM Studio**: turn off "Serve on Local Network" unless you need it, and enable authentication if you do.
- **Anything else**: find the `--host` / `ADDRESS` / `bind` option and set it to `127.0.0.1`.

## Known ports

| Service | Port(s) | Probe path |
|---|---|---|
| Ollama | 11434 | `/api/tags` |
| LM Studio | 1234 | `/v1/models` |
| llama.cpp (llama-server) | 8080 | `/v1/models` |
| LocalAI | 8080 | `/v1/models` |
| vLLM | 8000 | `/v1/models` |
| Jan | 1337 | `/v1/models` |
| text-generation-webui | 5000 | `/v1/models` |
| KoboldCpp | 5001 | `/api/v1/model` |
| Open WebUI | 8080, 3000 | `/api/v1/auths/` |
| ComfyUI | 8188 | `/system_stats` |
| Stable Diffusion WebUI | 7860 | `/sdapi/v1/options` |
| Jupyter | 8888 | `/api/status` |
| Chroma | 8000 | `/api/v2/heartbeat` |
| Qdrant | 6333 | `/collections` |
| Weaviate | 8080 | `/v1/.well-known/ready` |

Missing one? Add a line to `services.go` and send a PR.

## License

MIT
