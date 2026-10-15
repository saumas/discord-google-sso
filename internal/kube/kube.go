// Package kube provides Kubernetes client construction: in-cluster when
// running as a pod (server and operator CLI), kubeconfig otherwise (tests
// and local runs).
package kube

import (
	"fmt"
	"os"
	"strings"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// CurrentNamespace returns the namespace the process runs in: the service
// account namespace in-cluster, or "default".
func CurrentNamespace() string {
	if ns := os.Getenv("DGS_NAMESPACE"); ns != "" {
		return ns
	}
	if b, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		if ns := strings.TrimSpace(string(b)); ns != "" {
			return ns
		}
	}
	return "default"
}

// Client returns a Kubernetes clientset and the effective namespace. It uses
// the in-cluster configuration when available and falls back to the
// kubeconfig chain otherwise.
func Client() (kubernetes.Interface, string, error) {
	if cfg, err := rest.InClusterConfig(); err == nil {
		cs, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			return nil, "", fmt.Errorf("in-cluster client: %w", err)
		}
		return cs, CurrentNamespace(), nil
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	overrides := &clientcmd.ConfigOverrides{CurrentContext: os.Getenv("DGS_KUBECONTEXT")}
	kubeconfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)
	cfg, err := kubeconfig.ClientConfig()
	if err != nil {
		return nil, "", fmt.Errorf("kubeconfig: %w", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, "", err
	}
	ns, _, err := kubeconfig.Namespace()
	if err != nil || ns == "" {
		ns = "default"
	}
	return cs, ns, nil
}
