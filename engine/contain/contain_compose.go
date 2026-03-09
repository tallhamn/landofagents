package contain

import (
	"os"
	"text/template"
)

type composeData struct {
	AgentName      string
	RunID          string
	Volumes        []string
	ManagedEnv     []string // fixed KEY=VALUE env entries owned by runtime hook
	ManagedVolumes []string // fixed host:container volume mounts owned by runtime hook
	KitDir         string
	AgentPort      int
	ProxyPort      int
	Mode           string
	UseBuild       bool     // runtime has Dockerfile
	AgentImage     string   // runtime has pre-built image
	EnvVars        []string // passthrough variable names from runtime.yml
}

var composeTmpl = template.Must(template.New("compose").Parse(`services:
  loa-authz:
    build:
      context: .
      dockerfile: Dockerfile.authz
    command: ["authz", "--agent", "{{.AgentName}}", "--port", "{{.AgentPort}}", "--mode", "{{.Mode}}"]
    environment:
      - LOA_KIT=/etc/loa
      - LOA_RUN_ID={{.RunID}}
    volumes:
      - {{.KitDir}}/config:/etc/loa/config:ro
      - {{.KitDir}}/policies:/etc/loa/policies:ro
      - {{.KitDir}}/audit:/etc/loa/audit
    networks:
      - agent-net

  envoy:
    image: envoyproxy/envoy:v1.31-latest
    volumes:
      - ./envoy.yaml:/etc/envoy/envoy.yaml:ro
    depends_on:
      - loa-authz
    networks:
      - agent-net
      - external-net

  {{.AgentName}}:
{{- if .UseBuild}}
    build:
      context: .
      dockerfile: Dockerfile.agent
{{- else}}
    image: {{.AgentImage}}
{{- end}}
    stdin_open: true
    tty: true
    environment:
      - HTTP_PROXY=http://envoy:10000
      - HTTPS_PROXY=http://envoy:10000
      - NO_PROXY=localhost,127.0.0.1,loa-authz
      - LOA_KIT=/etc/loa
      - LOA_AGENT_NAME={{.AgentName}}
      - LOA_RUN_ID={{.RunID}}
{{- range .ManagedEnv}}
      - {{.}}
{{- end}}
{{- range .EnvVars}}
      - {{.}}=$` + `{{"{"}}{{.}}{{"}"}}` + `
{{- end}}
    depends_on:
      - envoy
    volumes:
      - {{.KitDir}}/workspaces/{{.AgentName}}:/workspace
      - {{.KitDir}}/config:/etc/loa/config:ro
      - {{.KitDir}}/policies:/etc/loa/policies:ro
      - {{.KitDir}}/audit:/etc/loa/audit
{{- range .ManagedVolumes}}
      - {{.}}
{{- end}}
{{- range .Volumes}}
      - {{.}}
{{- end}}
    networks:
      - agent-net

networks:
  agent-net:
    driver: bridge
    internal: true
  external-net:
    driver: bridge
`))

func generateCompose(path string, data composeData) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return composeTmpl.Execute(f, data)
}
