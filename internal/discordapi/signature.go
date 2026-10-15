package discordapi

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"time"
)

// InteractionSignatureWindow bounds how old an interaction timestamp may be
// before the request is rejected as stale.
const InteractionSignatureWindow = 10 * time.Minute

// ErrInvalidSignature is returned when an interaction request fails
// signature verification.
var ErrInvalidSignature = errors.New("invalid interaction signature")

// VerifyInteractionRequest verifies a Discord interaction request signature
// per Discord's documented scheme: Ed25519 (RFC 8037) over the concatenated
// timestamp and raw body, with the hex-encoded application public key.
func VerifyInteractionRequest(publicKeyHex, timestamp, signatureHex string, body []byte) error {
	pub, err := hex.DecodeString(publicKeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return ErrInvalidSignature
	}
	sig, err := hex.DecodeString(signatureHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}
	ts, err := parseUnixSeconds(timestamp)
	if err != nil {
		return ErrInvalidSignature
	}
	t := time.Unix(ts, 0)
	if time.Since(t) > InteractionSignatureWindow || t.After(time.Now().Add(InteractionSignatureWindow)) {
		return ErrInvalidSignature
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), append([]byte(timestamp), body...), sig) {
		return ErrInvalidSignature
	}
	return nil
}

func parseUnixSeconds(s string) (int64, error) {
	var n int64
	if s == "" {
		return 0, errors.New("empty timestamp")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, errors.New("non-numeric timestamp")
		}
		n = n*10 + int64(r-'0')
	}
	return n, nil
}
