package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/heimdallr-dev/gjallar/internal/domain"
)

// Syft implements app.SBOMGenerator.
type Syft struct {
	Bin string // default "syft"
	// Source forces the image source: registry (default in-cluster),
	// docker, podman, containerd, oci-archive... Empty lets Syft auto-detect.
	Source string
	// Scope is "squashed" (default) or "all-layers".
	Scope string
	Run   Runner
}

// Generate runs `syft <source>:<ref> -o syft-json`.
func (s Syft) Generate(ctx context.Context, ref domain.ImageRef) (domain.SBOM, error) {
	bin, run := or(s.Bin, "syft"), s.Run
	if run == nil {
		run = ExecRunner
	}
	target := ref.String()
	if s.Source != "" {
		target = s.Source + ":" + target
	}
	args := []string{"scan", target, "-o", "syft-json", "-q"}
	if s.Scope != "" {
		args = append(args, "--scope", s.Scope)
	}
	out, err := run(ctx, nil, bin, args...)
	if err != nil {
		return domain.SBOM{}, err
	}
	sbom, err := ParseSyftJSON(out)
	if err != nil {
		return domain.SBOM{}, err
	}
	if !sbom.Digest.Valid() {
		sbom.Digest = ref.Digest
	}
	return sbom, nil
}

type syftDoc struct {
	Artifacts []struct {
		Name     string          `json:"name"`
		Version  string          `json:"version"`
		Type     string          `json:"type"`
		PURL     string          `json:"purl"`
		Licenses json.RawMessage `json:"licenses"`
	} `json:"artifacts"`
	Distro struct {
		ID        string `json:"id"`
		VersionID string `json:"versionID"`
	} `json:"distro"`
	Source struct {
		Metadata struct {
			ManifestDigest string   `json:"manifestDigest"`
			RepoDigests    []string `json:"repoDigests"`
			UserInput      string   `json:"userInput"`
		} `json:"metadata"`
	} `json:"source"`
}

// ParseSyftJSON extracts what Gjallar needs from a Syft JSON document and
// keeps the original bytes in SBOM.Raw for Grype re-matching.
func ParseSyftJSON(raw []byte) (domain.SBOM, error) {
	var doc syftDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return domain.SBOM{}, fmt.Errorf("parse syft json: %w", err)
	}
	s := domain.SBOM{Raw: raw}
	if doc.Distro.ID != "" {
		s.Distro = strings.TrimSpace(doc.Distro.ID + " " + doc.Distro.VersionID)
	}
	// Prefer the registry (repo) digest: that is what Kubernetes reports.
	for _, rd := range doc.Source.Metadata.RepoDigests {
		if _, d, ok := strings.Cut(rd, "@"); ok {
			s.Digest = domain.Digest(d)
			break
		}
	}
	if !s.Digest.Valid() {
		s.Digest = domain.Digest(doc.Source.Metadata.ManifestDigest)
	}
	for _, a := range doc.Artifacts {
		s.Packages = append(s.Packages, domain.Package{
			Name: a.Name, Version: a.Version, Type: a.Type, PURL: a.PURL, Licenses: parseLicenses(a.Licenses),
		})
	}
	return s, nil
}

// Syft has emitted licenses both as strings and as objects over time.
func parseLicenses(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var strs []string
	if json.Unmarshal(raw, &strs) == nil {
		return strs
	}
	var objs []struct {
		Value          string `json:"value"`
		SPDXExpression string `json:"spdxExpression"`
	}
	if json.Unmarshal(raw, &objs) != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, o := range objs {
		v := o.SPDXExpression
		if v == "" {
			v = o.Value
		}
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func or(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// Convert implements app.SBOMConverter with `syft convert`.
func (s Syft) Convert(ctx context.Context, raw []byte, format string) ([]byte, error) {
	run := s.Run
	if run == nil {
		run = ExecRunner
	}
	path, cleanup, err := writeTemp("gjallar-sbom-*.json", raw)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	if format == "cyclonedx-json" {
		format = "cyclonedx-json@1.6" // widest reader support (Trivy, Dependency-Track); Syft's default 1.7 is rejected by Trivy 0.69
	}
	return run(ctx, nil, or(s.Bin, "syft"), "convert", path, "-o", format, "-q")
}
