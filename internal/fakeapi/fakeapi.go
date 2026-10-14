// Package fakeapi provides an in-process fake Kubernetes API server for
// tests: it implements the Secret endpoints with real resourceVersion
// compare-and-swap conflict semantics, backed by an httptest server, so the
// production client-go code path is exercised without a cluster.
package fakeapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Server is a fake Secrets-only Kubernetes API server.
type Server struct {
	mu      sync.Mutex
	secrets map[string]*corev1.Secret // key: namespace/name
	rv      int
	srv     *httptest.Server
	// Writes counts mutating requests served.
	Writes int
}

// New starts a fake API server.
func New() *Server {
	s := &Server{secrets: map[string]*corev1.Secret{}, rv: 100}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/namespaces/{ns}/secrets/{name}", s.get)
	mux.HandleFunc("POST /api/v1/namespaces/{ns}/secrets", s.post)
	mux.HandleFunc("PUT /api/v1/namespaces/{ns}/secrets/{name}", s.put)
	s.srv = httptest.NewServer(mux)
	return s
}

// Client returns a clientset speaking JSON against the fake server.
func (s *Server) Client() kubernetes.Interface {
	cfg := &rest.Config{Host: s.srv.URL}
	// The generated clientset defaults to protobuf; force JSON so the
	// hand-rolled fake server can decode it. Also lift the default QPS
	// limiter so hammering tests are not throttled.
	cfg.ContentType = "application/json"
	cfg.AcceptContentTypes = "application/json"
	cfg.QPS = 500
	cfg.Burst = 1000
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		panic(err)
	}
	return cs
}

// URL returns the underlying server URL.
func (s *Server) URL() string { return s.srv.URL }

// Close shuts the server down.
func (s *Server) Close() { s.srv.Close() }

func statusErr(w http.ResponseWriter, code int, reason metav1.StatusReason, message string) {
	se := &apierrors.StatusError{ErrStatus: metav1.Status{
		Status:  metav1.StatusFailure,
		Code:    int32(code),
		Reason:  reason,
		Message: message,
	}}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(se.ErrStatus)
}

func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := r.PathValue("ns") + "/" + r.PathValue("name")
	sec, ok := s.secrets[key]
	if !ok {
		statusErr(w, http.StatusNotFound, metav1.StatusReasonNotFound, "secrets \""+r.PathValue("name")+"\" not found")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(sec)
}

func (s *Server) post(w http.ResponseWriter, r *http.Request) {
	var sec corev1.Secret
	if err := json.NewDecoder(r.Body).Decode(&sec); err != nil {
		statusErr(w, http.StatusBadRequest, metav1.StatusReasonBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := r.PathValue("ns") + "/" + sec.Name
	if _, exists := s.secrets[key]; exists {
		statusErr(w, http.StatusConflict, metav1.StatusReasonAlreadyExists, "already exists")
		return
	}
	s.rv++
	sec.ResourceVersion = strconv.Itoa(s.rv)
	sec.Namespace = r.PathValue("ns")
	s.secrets[key] = &sec
	s.Writes++
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(&sec)
}

func (s *Server) put(w http.ResponseWriter, r *http.Request) {
	var in corev1.Secret
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		statusErr(w, http.StatusBadRequest, metav1.StatusReasonBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := r.PathValue("ns") + "/" + r.PathValue("name")
	cur, ok := s.secrets[key]
	if !ok {
		statusErr(w, http.StatusNotFound, metav1.StatusReasonNotFound, "not found")
		return
	}
	if in.ResourceVersion == "" || in.ResourceVersion != cur.ResourceVersion {
		statusErr(w, http.StatusConflict, metav1.StatusReasonConflict, "the object has been modified; please apply your changes to the latest version")
		return
	}
	s.rv++
	in.ResourceVersion = strconv.Itoa(s.rv)
	in.Namespace = r.PathValue("ns")
	s.secrets[key] = &in
	s.Writes++
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(&in)
}
