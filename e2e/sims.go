package main

import (
	"fmt"
	"time"
)

// deploySims creates the Discord and Google simulator Deployments + NodePort
// Services using the application image with simulator arguments.
func (e *env) deploySims() error {
	simDeploy := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: %NAME%
  namespace: ` + ns + `
spec:
  replicas: 1
  selector:
    matchLabels: {app: %NAME%}
  template:
    metadata:
      labels: {app: %NAME%}
    spec:
      containers:
      - name: sim
        image: ` + appImage + `
        imagePullPolicy: Never
        args: [%ARGS%]
        ports:
        - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: %NAME%
  namespace: ` + ns + `
spec:
  type: NodePort
  selector: {app: %NAME%}
  ports:
  - port: 80
    targetPort: 8080
    nodePort: %NODEPORT%
`
	discordArgs := `"sim-discord", "--addr", ":8080",
		"--client-id", "e2e-app-id", "--client-secret", "e2e-discord-secret",
		"--redirect-uri", "` + e.appURL + `/callback/discord",
		"--bot-token", "e2e-bot-token"`
	googleArgs := `"sim-google", "--addr", ":8080",
		"--issuer", "` + e.googURL + `",
		"--client-id", "e2e-google-id", "--client-secret", "e2e-google-secret",
		"--redirect-uri", "` + e.appURL + `/callback/google"`

	for _, s := range []struct{ name, args, port string }{
		{"discord-sim", discordArgs, fmt.Sprint(nodePortDisc)},
		{"google-sim", googleArgs, fmt.Sprint(nodePortGoog)},
	} {
		manifest := simDeploy
		manifest = replaceAll(manifest, "%NAME%", s.name)
		manifest = replaceAll(manifest, "%ARGS%", s.args)
		manifest = replaceAll(manifest, "%NODEPORT%", s.port)
		e.applyManifest(manifest)
	}
	// Wait for both sims to answer.
	if err := e.waitURL(e.discURL + "/_admin/dump"); err != nil {
		return fmt.Errorf("discord sim not ready: %w", err)
	}
	if err := e.waitURL(e.googURL + "/_admin/dump"); err != nil {
		return fmt.Errorf("google sim not ready: %w", err)
	}
	return nil
}

func (e *env) applyManifest(manifest string) {
	p := writeFile("manifest.yaml", manifest)
	e.kubectlNoNS("apply", "-f", p)
}

func (e *env) waitURL(url string) error {
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := httpGetNoFollow(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timeout waiting for %s", url)
}

func replaceAll(s, old, new string) string {
	for {
		t := replaceOne(s, old, new)
		if t == s {
			return s
		}
		s = t
	}
}

func replaceOne(s, old, new string) string {
	i := indexOf(s, old)
	if i < 0 {
		return s
	}
	return s[:i] + new + s[i+len(old):]
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
