package scanner

import (
	"context"
	"fmt"

	"github.com/heimdallr-dev/gjallar/internal/domain"
)

// Cosign implements app.Attestor with `cosign attest`: the predicate is
// signed with a private key and stored in the image's registry, where
// `cosign verify-attestation` or Kyverno can check it without Gjallar.
type Cosign struct {
	Bin string // default "cosign"
	// Key is a cosign key reference: "env://COSIGN_PRIVATE_KEY" (with
	// COSIGN_PASSWORD set), "k8s://ns/secret", or a KMS URI.
	Key string
	// Insecure allows plain-HTTP / self-signed registries (labs only).
	Insecure bool
	Run      Runner
}

// Attest signs predicate about ref (by digest) and pushes the attestation.
func (c Cosign) Attest(ctx context.Context, ref domain.ImageRef, predicateType string, predicate []byte) error {
	if !ref.Digest.Valid() {
		return fmt.Errorf("cosign: %s has no digest", ref.String())
	}
	run := c.Run
	if run == nil {
		run = ExecRunner
	}
	path, cleanup, err := writeTemp("gjallar-predicate-*.json", predicate)
	if err != nil {
		return err
	}
	defer cleanup()
	// No transparency log: private registries, no public Rekor entry.
	args := []string{"attest", "--yes", "--key", c.Key, "--type", predicateType, "--predicate", path, "--tlog-upload=false"}
	if c.Insecure {
		args = append(args, "--allow-insecure-registry", "--allow-http-registry")
	}
	args = append(args, ref.Repository+"@"+string(ref.Digest))
	_, err = run(ctx, nil, or(c.Bin, "cosign"), args...)
	return err
}
