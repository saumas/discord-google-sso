package state

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// MaxSecretBytes bounds the marshaled Secret object size. etcd rejects
// objects approaching ~1 MiB; the state Secret is written as base64-encoded
// gzipped JSON, so the usable payload bound is correspondingly lower.
const MaxSecretBytes = 900 * 1024

// ErrTooLarge is returned when the updated state document would exceed the
// Secret size budget. The existing state is left untouched.
var ErrTooLarge = errors.New("state document too large for Secret budget")

// casRetries bounds read-modify-write retries on resourceVersion conflicts.
const casRetries = 32

// casBackoff spaces conflict retries so contending writers converge instead
// of starving each other in hot loops.
func casBackoff(attempt int) time.Duration {
	d := time.Duration(attempt) * 5 * time.Millisecond
	if d > 250*time.Millisecond {
		d = 250 * time.Millisecond
	}
	return d
}

// Store owns the application state Secret. It is the only component that
// reads and writes it.
type Store struct {
	client    kubernetes.Interface
	namespace string
	name      string
	log       *slog.Logger
}

// NewStore returns a Store for the named Secret in the given namespace.
func NewStore(client kubernetes.Interface, namespace, name string, log *slog.Logger) *Store {
	// A nil logger is a supported entry point: the operator CLI passes nil
	// and uses slog.Default() output.
	if log == nil {
		log = slog.Default()
	}
	return &Store{client: client, namespace: namespace, name: name, log: log}
}

// Namespace returns the store namespace.
func (s *Store) Namespace() string { return s.namespace }

// Name returns the Secret name.
func (s *Store) Name() string { return s.name }

// Load reads the state Secret, creating it if missing. It refuses corrupt
// data, unknown schema versions, and foreign guild IDs instead of resetting.
// After creating, it re-reads the Secret: another writer may have created it
// first in the race window, and the returned document must reflect persisted
// state rather than a locally built one.
func (s *Store) Load(ctx context.Context, guildID string) (*Doc, error) {
	decode := func(sec *corev1.Secret) (*Doc, error) {
		doc, err := decodeDoc(sec)
		if err != nil {
			return nil, err
		}
		if err := doc.Validate(guildID); err != nil {
			return nil, fmt.Errorf("state secret %s/%s: %w", s.namespace, s.name, err)
		}
		return doc, nil
	}
	sec, err := s.client.CoreV1().Secrets(s.namespace).Get(ctx, s.name, metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("get state secret: %w", err)
		}
		if err := s.create(ctx, NewDoc(guildID)); err != nil {
			return nil, err
		}
		// Re-read: our Create may have lost the race to another writer, in
		// which case the persisted document is authoritative.
		sec, err = s.client.CoreV1().Secrets(s.namespace).Get(ctx, s.name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("get state secret after create: %w", err)
		}
		return decode(sec)
	}
	return decode(sec)
}

func decodeDoc(sec *corev1.Secret) (*Doc, error) {
	data, ok := sec.Data[DataKey]
	if !ok {
		return nil, fmt.Errorf("state secret %s/%s has no %q field", sec.Namespace, sec.Name, DataKey)
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("state secret is corrupt (not gzip): %w", err)
	}
	raw, err := io.ReadAll(gz)
	if err != nil {
		return nil, fmt.Errorf("state secret is corrupt (gzip data): %w", err)
	}
	var doc Doc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("state secret is corrupt (invalid JSON): %w", err)
	}
	return &doc, nil
}

func (s *Store) create(ctx context.Context, doc *Doc) error {
	sec, err := s.secretFromDoc(doc, "")
	if err != nil {
		return err
	}
	_, err = s.client.CoreV1().Secrets(s.namespace).Create(ctx, sec, metav1.CreateOptions{})
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			// Another writer created it first; caller retries via Update.
			return nil
		}
		return fmt.Errorf("create state secret: %w", err)
	}
	return nil
}

func (s *Store) secretFromDoc(doc *Doc, resourceVersion string) (*corev1.Secret, error) {
	if err := doc.Validate(doc.GuildID); err != nil {
		return nil, fmt.Errorf("refusing to write invalid state: %w", err)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(raw); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	sec := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{
			Name:            s.name,
			Namespace:       s.namespace,
			ResourceVersion: resourceVersion,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{DataKey: buf.Bytes()},
	}
	// Size check against the actually stored object: the API server stores
	// Secret data base64-encoded, so the budget applies to the full marshaled
	// object.
	enc, err := json.Marshal(sec)
	if err != nil {
		return nil, err
	}
	if len(enc) > MaxSecretBytes {
		return nil, fmt.Errorf("%w: marshaled secret is %d bytes (budget %d)", ErrTooLarge, len(enc), MaxSecretBytes)
	}
	return sec, nil
}

// Update performs a read-modify-write of the state document with
// resourceVersion conflict detection and retry. The mutate function is
// re-invoked on each retry against a fresh copy of the current document, so
// concurrent updates preserve both changes and the compare-and-swap enforces
// identity-link uniqueness atomically.
func (s *Store) Update(ctx context.Context, guildID string, mutate func(*Doc) error) error {
	var lastErr error
	for i := range casRetries {
		sec, err := s.client.CoreV1().Secrets(s.namespace).Get(ctx, s.name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) && i == 0 {
				if err := s.create(ctx, NewDoc(guildID)); err != nil {
					return err
				}
				continue
			}
			return fmt.Errorf("get state secret for update: %w", err)
		}
		doc, err := decodeDoc(sec)
		if err != nil {
			// Corrupt or foreign state must never be reset by an update.
			return err
		}
		if err := doc.Validate(guildID); err != nil {
			return fmt.Errorf("refusing update: %w", err)
		}
		if err := mutate(doc); err != nil {
			return err
		}
		out, err := s.secretFromDoc(doc, sec.ResourceVersion)
		if err != nil {
			return err
		}
		_, err = s.client.CoreV1().Secrets(s.namespace).Update(ctx, out, metav1.UpdateOptions{})
		if err == nil {
			return nil
		}
		if apierrors.IsConflict(err) {
			lastErr = err
			select { // back off, re-read, re-mutate, retry
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(casBackoff(i)):
			}
			continue
		}
		if apierrors.IsNotFound(err) {
			// Secret vanished (should not happen: app-owned); recreate.
			if err := s.create(ctx, NewDoc(guildID)); err != nil {
				return err
			}
			continue
		}
		return fmt.Errorf("update state secret: %w", err)
	}
	if lastErr == nil {
		lastErr = errors.New("too many conflicts")
	}
	return fmt.Errorf("state update lost all CAS retries: %w", lastErr)
}
