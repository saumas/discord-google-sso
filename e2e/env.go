package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/saumas/discord-google-sso/internal/state"
)

// Test-world identifiers (Discord-style snowflakes).
const (
	guildID    = "900001"
	userMain   = "100000000000000001" // Alice, the primary member
	userSecond = "100000000000000002" // Bob, second member
	userAdmin  = "100000000000000003" // the admin
	userFresh  = "100000000000000004" // never-linked member used in races
	userOut    = "100000000000000005" // outsider (not in the guild)

	roleVerified1 = "111111111111111111"
	roleVerified2 = "222222222222222222"
	roleRemoved   = "999999999999999999"
	roleUnverif1  = "888888888888888888"
	roleUnverif2  = "889999999999999999"
	roleAdmin     = "555555555555555555"
	roleUnrelated = "777777777777777777"

	ns            = "dgs-e2e"
	release       = "dgs"
	stateSecret   = "dgs-e2e-state"
	credSecret    = "dgs-e2e-credentials"
	appImage      = "localhost/discord-google-sso:e2e"
	nodePortApp   = 30000
	nodePortDisc  = 30001
	nodePortGoog  = 30002
	reconInterval = "3s"
)

type googleID struct {
	Sub           string
	Email         string
	Name          string
	Hd            string
	EmailVerified bool
}

var (
	gIDWorkspace  = googleID{Sub: "g-sub-1", Email: "alice@example.com", Name: "Alice", Hd: "example.com", EmailVerified: true}
	gIDOther      = googleID{Sub: "g-sub-2", Email: "bob@example.com", Name: "Bob", Hd: "example.com", EmailVerified: true}
	gIDEvilDomain = googleID{Sub: "g-sub-3", Email: "eve@evil.io", Name: "Eve", Hd: "evil.io", EmailVerified: true}
	gIDConsumer   = googleID{Sub: "g-sub-4", Email: "casual@gmail.com", Name: "Casual", EmailVerified: true}
	gIDUnverified = googleID{Sub: "g-sub-5", Email: "nev@example.com", Name: "Nev", Hd: "example.com", EmailVerified: false}
)

// env is the shared E2E environment.
type env struct {
	cluster     string
	kubeconfig  string
	nodeIP      string
	appURL      string
	discURL     string
	googURL     string
	priv        ed25519.PrivateKey
	pubHex      string
	client      kubernetes.Interface
	browser     *browser
	adminToken  string
	workDir     string
	releaseDir  string
	issuedSoFar []string // provider-issued secrets seen (for redaction check)
}

func (e *env) teardown() {
	fmt.Println("deleting cluster...")
	runCmd("", "kind", "delete", "cluster", "--name", e.cluster)
}

func runCmd(dir, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, out.String())
	}
	return out.String(), nil
}

func mustRun(dir, name string, args ...string) string {
	out, err := runCmd(dir, name, args...)
	if err != nil {
		panic(err)
	}
	return out
}

func (e *env) kubectl(args ...string) string {
	return mustRun(e.releaseDir, "kubectl", append([]string{"--kubeconfig", e.kubeconfig, "-n", ns}, args...)...)
}

func (e *env) kubectlNoNS(args ...string) string {
	return mustRun(e.releaseDir, "kubectl", append([]string{"--kubeconfig", e.kubeconfig}, args...)...)
}

func (e *env) helm(args ...string) string {
	return mustRun(e.releaseDir, "helm", append([]string{"--kubeconfig", e.kubeconfig}, args...)...)
}

func setup(ctx context.Context, cluster string) (*env, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	repo := filepath.Dir(wd)

	fmt.Println("[setup] building container image")
	if out, err := runCmd(repo, "docker", "build", "-t", appImage, "."); err != nil {
		return nil, fmt.Errorf("docker build: %v\n%s", err, out)
	}

	fmt.Println("[setup] creating kind cluster", cluster)
	runCmd(repo, "kind", "delete", "cluster", "--name", cluster) // idempotent rerun
	kubeconfig := filepath.Join(os.TempDir(), cluster+".kubeconfig")
	kcfgYAML := `kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
`
	if out, err := runCmd(repo, "kind", "create", "cluster", "--name", cluster, "--kubeconfig", kubeconfig, "--config", writeFile("kind.yaml", kcfgYAML)); err != nil {
		return nil, fmt.Errorf("kind create: %v\n%s", err, out)
	}

	if out, err := runCmd(repo, "kind", "load", "docker-image", appImage, "--name", cluster); err != nil {
		return nil, fmt.Errorf("kind load: %v\n%s", err, out)
	}

	// Discover the node IP (OrbStack/Docker routes host traffic to it).
	nodeIP := strings.TrimSpace(mustRun(repo, "docker", "inspect", fmt.Sprintf("%s-control-plane", cluster), "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"))
	if nodeIP == "" {
		return nil, fmt.Errorf("could not discover kind node IP")
	}

	e := &env{
		cluster:    cluster,
		kubeconfig: kubeconfig,
		nodeIP:     nodeIP,
		appURL:     fmt.Sprintf("http://%s:%d", nodeIP, nodePortApp),
		discURL:    fmt.Sprintf("http://%s:%d", nodeIP, nodePortDisc),
		googURL:    fmt.Sprintf("http://%s:%d", nodeIP, nodePortGoog),
		releaseDir: repo,
	}

	// Ed25519 keypair for interaction request signing.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	e.priv, e.pubHex = priv, hex.EncodeToString(pub)

	// Kubernetes client from the generated kubeconfig.
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}
	e.client, err = kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	fmt.Println("[setup] helm lint")
	if out, err := runCmd(repo, "helm", "lint", "charts/discord-google-sso"); err != nil {
		return nil, fmt.Errorf("helm lint: %v\n%s", err, out)
	}

	fmt.Println("[setup] chart render assertions")
	if err := e.assertChartRenders(repo); err != nil {
		return nil, err
	}

	fmt.Println("[setup] creating namespace and credentials secret")
	e.kubectlNoNS("create", "namespace", ns)
	e.kubectlNoNS("-n", ns, "create", "secret", "generic", credSecret,
		"--from-literal=discord-client-secret=e2e-discord-secret",
		"--from-literal=discord-bot-token=e2e-bot-token",
		"--from-literal=google-client-secret=e2e-google-secret")

	fmt.Println("[setup] deploying provider simulators")
	if err := e.deploySims(); err != nil {
		return nil, err
	}

	fmt.Println("[setup] installing chart")
	if err := e.helmInstall(repo, "example.com"); err != nil {
		return nil, err
	}

	fmt.Println("[setup] waiting for readiness")
	if err := e.waitReady(); err != nil {
		return nil, err
	}

	fmt.Println("[setup] booting browser")
	e.browser, err = newBrowser(ctx)
	if err != nil {
		return nil, err
	}

	fmt.Println("[setup] guild members")
	e.discAdmin("POST", "/_admin/member", map[string]any{"user_id": userMain, "guild_id": guildID, "roles": []string{roleUnverif1, roleUnverif2, roleUnrelated}})
	e.discAdmin("POST", "/_admin/member", map[string]any{"user_id": userSecond, "guild_id": guildID, "roles": []string{roleUnverif1, roleUnverif2, roleUnrelated}})
	e.discAdmin("POST", "/_admin/member", map[string]any{"user_id": userAdmin, "guild_id": guildID, "roles": []string{roleAdmin, roleUnrelated}})
	e.discAdmin("POST", "/_admin/member", map[string]any{"user_id": userFresh, "guild_id": guildID, "roles": []string{roleUnverif1, roleUnverif2}})

	// The slash command should be registered at startup.
	if err := e.waitCommandRegistered(); err != nil {
		return nil, err
	}
	return e, nil
}

func writeFile(name, content string) string {
	p := filepath.Join(os.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		panic(err)
	}
	return p
}

func (e *env) helmInstall(repo, domains string) error {
	values := template.Must(template.New("v").Parse(`image:
  repository: {{.Image}}
  tag: e2e
  pullPolicy: Never
guildID: "{{.Guild}}"
publicBaseURL: "{{.AppURL}}"
discord:
  clientID: "e2e-app-id"
  publicKey: "{{.PubKey}}"
  baseURL: "{{.DiscURL}}"
google:
  clientID: "e2e-google-id"
  baseURL: "{{.GoogURL}}"
allowedDomains: [{{.Domains}}]
addRoles: ["{{.R1}}", "{{.R2}}"]
removeRoles: ["{{.RR}}"]
unverifiedRoles: ["{{.U1}}", "{{.U2}}"]
adminRoleIDs: ["{{.RA}}"]
adminUserIDs: ["{{.AdminUser}}"]
credentialsSecret: {{.CredSecret}}
stateSecretName: {{.StateSecret}}
reconcileInterval: "{{.Interval}}"
service:
  type: NodePort
  nodePort: {{.NodePort}}
`))
	data := map[string]any{
		"Image": appImage, "Guild": guildID, "AppURL": e.appURL, "PubKey": e.pubHex,
		"DiscURL": e.discURL, "GoogURL": e.googURL, "Domains": domains,
		"R1": roleVerified1, "R2": roleVerified2, "RR": roleRemoved,
		"U1": roleUnverif1, "U2": roleUnverif2, "RA": roleAdmin, "AdminUser": userAdmin,
		"CredSecret": credSecret, "StateSecret": stateSecret,
		"Interval": reconInterval, "NodePort": nodePortApp,
	}
	var buf bytes.Buffer
	if err := values.Execute(&buf, data); err != nil {
		return err
	}
	valsFile := writeFile("e2e-values.yaml", buf.String())
	out, err := runCmd(repo, "helm", "upgrade", "--install", release, "charts/discord-google-sso",
		"--namespace", ns, "--kubeconfig", e.kubeconfig, "-f", valsFile, "--wait", "--timeout", "180s")
	if err != nil {
		return fmt.Errorf("helm install: %v\n%s", err, out)
	}
	return nil
}

// assertChartRenders verifies the chart templates no state Secret.
func (e *env) assertChartRenders(repo string) error {
	out := mustRun(repo, "helm", "template", release, "charts/discord-google-sso", "--set", "guildID=1")
	for _, doc := range strings.Split(out, "---") {
		if strings.Contains(doc, "kind: Secret") {
			return fmt.Errorf("chart templates a Secret; the app-owned state Secret must never be templated:\n%s", doc)
		}
	}
	return nil
}

func (e *env) waitReady() error {
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(e.appURL + "/readyz")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("app never became ready")
}

func (e *env) waitCommandRegistered() error {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		dump := e.discDump()
		if cmds, ok := dump["commands"].(map[string]any); ok {
			if _, ok := cmds["e2e-app-id"].(map[string]any); ok {
				if g, ok := cmds["e2e-app-id"].(map[string]any)[guildID]; ok && g != nil {
					return nil
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("slash command never registered")
}

// --- state ---

func (e *env) readState() (*state.Doc, error) {
	sec, err := e.client.CoreV1().Secrets(ns).Get(context.Background(), stateSecret, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	data := sec.Data[state.DataKey]
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(gz)
	if err != nil {
		return nil, err
	}
	var doc state.Doc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func (e *env) stateMember(id string) *state.Member {
	doc, err := e.readState()
	if err != nil {
		return nil
	}
	return doc.Members[id]
}

// --- sim admin ---

func (e *env) discAdmin(method, path string, body any) map[string]any {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.discURL+path, rd)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

func (e *env) googAdmin(method, path string, body any) map[string]any {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.googURL+path, rd)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

func (e *env) discDump() map[string]any { return e.discAdmin("GET", "/_admin/dump", nil) }

// memberRoles returns the roles the Discord simulator currently holds for a user.
func (e *env) memberRoles(user string) []string {
	dump := e.discDump()
	if members, ok := dump["members"].(map[string]any); ok {
		if g, ok := members[guildID].(map[string]any); ok {
			if m, ok := g[user].(map[string]any); ok {
				if roles, ok := m["roles"].([]any); ok {
					var out []string
					for _, r := range roles {
						out = append(out, fmt.Sprint(r))
					}
					return out
				}
			}
		}
	}
	return nil
}

func (e *env) hasRole(user, role string) bool {
	for _, r := range e.memberRoles(user) {
		if r == role {
			return true
		}
	}
	return false
}

func (e *env) loginDiscord(user string) {
	e.discAdmin("POST", "/_admin/login-as", map[string]string{"user_id": user})
}

func (e *env) loginGoogle(id googleID) {
	e.googAdmin("POST", "/_admin/login-as", map[string]any{
		"sub": id.Sub, "email": id.Email, "name": id.Name, "hd": id.Hd, "email_verified": id.EmailVerified,
	})
}

func (e *env) collectIssuedSecrets() []string {
	var out []string
	for _, s := range e.discAdmin("GET", "/_admin/dump", nil)["issued_secrets"].([]any) {
		out = append(out, fmt.Sprint(s))
	}
	for _, s := range e.googAdmin("GET", "/_admin/dump", nil)["issued_secrets"].([]any) {
		out = append(out, fmt.Sprint(s))
	}
	return out
}

// appLogs returns the application pod logs (all containers of the Deployment).
func (e *env) appLogs() string {
	return e.kubectl("logs", "deploy/"+release+"-discord-google-sso", "--tail=100000")
}

// restartApp deletes the Deployment pod and waits for readiness.
func (e *env) restartApp() error {
	e.kubectl("delete", "pod", "-l", "app.kubernetes.io/instance="+release+",app.kubernetes.io/name=discord-google-sso", "--wait=false")
	return e.waitReady()
}

// scaleApp scales the application Deployment.
func (e *env) scaleApp(replicas int) {
	e.kubectl("scale", "deploy/"+release+"-discord-google-sso", fmt.Sprintf("--replicas=%d", replicas))
}
