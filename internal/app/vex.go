package app

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/heimdallr-dev/gjallar/internal/domain"
)

// OpenVEX renders the accepted findings of one image as an OpenVEX document,
// so other tools (Grype --vex, Trivy --vex, Kyverno) honour the same decisions.
func OpenVEX(repository string, d domain.Digest, accepted []FindingView, now time.Time) map[string]any {
	product := "pkg:oci/" + repository + "@" + string(d)
	stmts := []map[string]any{}
	for _, f := range accepted {
		stmts = append(stmts, map[string]any{
			"vulnerability": map[string]string{"name": f.VulnID},
			"products":      []map[string]string{{"@id": product}},
			"status":        "not_affected", "justification": "vulnerable_code_not_in_execute_path",
			"impact_statement": "Accepted in Gjallar",
		})
	}
	return map[string]any{
		"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://gjallar/vex/" + string(d),
		"author": "gjallar", "timestamp": now.UTC().Format(time.RFC3339), "version": 1, "statements": stmts,
	}
}

// publishVEX queues signing of the image's current VEX document.
func (h *Hub) publishVEX(ctx context.Context, d domain.Digest) error {
	img, err := h.Repo.Image(ctx, d)
	if err != nil {
		return err
	}
	fs, err := h.Repo.ListFindings(ctx, FindingFilter{Digest: d, State: string(domain.StateAccepted), Limit: 5000})
	if err != nil {
		return err
	}
	doc, err := json.Marshal(OpenVEX(img.Repository, d, fs, h.Now()))
	if err != nil {
		return err
	}
	return h.Bus.Publish(ctx, domain.SubjJobVEX, domain.VEXJob{Image: domain.ImageRef{Repository: img.Repository, Tag: img.Tag, Digest: d}, Document: doc})
}

// VEXWorker signs VEX documents as cosign attestations for images in your
// own registries (the same AttestRepos as SBOM attestations).
type VEXWorker struct {
	Attest      Attestor
	AttestRepos []string
}

// Handle signs one VEX document; images elsewhere are skipped.
func (w VEXWorker) Handle(ctx context.Context, job domain.VEXJob) error {
	if !hasPrefix(job.Image.Repository, w.AttestRepos) {
		return nil
	}
	if err := w.Attest.Attest(ctx, job.Image, "openvex", job.Document); err != nil {
		return fmt.Errorf("attest vex %s: %w", job.Image.String(), err)
	}
	return nil
}
