package scanner

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path"
	"strings"

	"github.com/heimdallr-dev/gjallar/internal/domain"
)

// BuiltinLicenses implements app.LicenseChecker with Gjallar's own policy
// engine over the licenses Syft already extracted. No extra binary needed.
type BuiltinLicenses struct{}

// Evaluate applies the policy.
func (BuiltinLicenses) Evaluate(_ context.Context, s domain.SBOM, p domain.LicensePolicy) ([]domain.LicenseResult, error) {
	return p.Evaluate(s), nil
}

// Grant implements app.LicenseChecker by running Anchore Grant as a second
// opinion. Per-package verdicts come from the built-in engine (same Syft
// license data); Grant's own policy decides pass/fail for the image.
type Grant struct {
	Bin        string // default "grant"
	ConfigPath string // .grant.yaml
	Run        Runner
}

// Evaluate runs `grant check <sbom>`; a non-zero exit marks the image.
func (g Grant) Evaluate(ctx context.Context, s domain.SBOM, p domain.LicensePolicy) ([]domain.LicenseResult, error) {
	results := p.Evaluate(s)
	bin, run := or(g.Bin, "grant"), g.Run
	if run == nil {
		run = ExecRunner
	}
	path, cleanup, err := writeTemp("gjallar-sbom-*.json", s.Raw)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	args := []string{"check", path}
	if g.ConfigPath != "" {
		args = append(args, "--config", g.ConfigPath)
	}
	_, err = run(ctx, nil, bin, args...)
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return results, nil
	case errors.As(err, &exitErr):
		// Grant found a policy violation. Record it as an image-level result
		// so it shows up even if the built-in policy is more permissive.
		results = append(results, domain.LicenseResult{Digest: s.Digest, Package: "(image)", License: "grant-policy", Verdict: domain.LicenseDenied})
		return results, nil
	default:
		return nil, err
	}
}

// Copa implements app.Patcher with Copacetic. Copa needs a BuildKit daemon
// and a vulnerability report. Copa reads Trivy reports natively, so Trivy is
// the default report generator here (pin a known-good release: 0.69.4–0.69.6
// were compromised, CVE-2026-33634). Set Scanner to "grype" only if you have
// a copa-grype scanner plugin on PATH.
type Copa struct {
	Bin          string // default "copa"
	GrypeBin     string // default "grype"
	BuildkitAddr string // e.g. tcp://gjallar-buildkitd:1234
	Scanner      string // "trivy" (default) or "grype" (needs a copa-grype plugin)
	TagSuffix    string // default "-patched"
	TargetRepo   string // e.g. harbor.example.com/gjallar; empty = push next to the source
	Timeout      string // copa --timeout; default 20m (copa's own 5m is too short for ~40 OS updates)
	Push         bool
	Run          Runner
}

// Patch scans the image, then runs `copa patch` and returns the new reference.
func (c Copa) Patch(ctx context.Context, ref domain.ImageRef, _ []domain.Finding) (string, error) {
	if c.BuildkitAddr == "" {
		return "", fmt.Errorf("copa: no BuildKit address configured (GJALLAR_BUILDKIT_ADDR)")
	}
	run := c.Run
	if run == nil {
		run = ExecRunner
	}
	scanner := or(c.Scanner, "trivy")
	var report []byte
	var err error
	switch scanner {
	case "grype":
		report, err = run(ctx, nil, or(c.GrypeBin, "grype"), ref.String(), "-o", "json", "-q", "--only-fixed")
	default:
		report, err = run(ctx, nil, "trivy", "image", "--pkg-types", "os", "--ignore-unfixed", "-f", "json", "-q", ref.String())
	}
	if err != nil {
		return "", fmt.Errorf("copa report: %w", err)
	}
	reportPath, cleanup, err := writeTemp("gjallar-report-*.json", report)
	if err != nil {
		return "", err
	}
	defer cleanup()

	tag := ref.Tag
	if tag == "" {
		tag = "latest"
	}
	newTag := tag + or(c.TagSuffix, "-patched")
	// Copa patches a tag, not a digest.
	src := domain.ImageRef{Repository: ref.Repository, Tag: tag}
	out := strings.TrimSuffix(ref.Repository, "/") + ":" + newTag
	target := newTag
	if c.TargetRepo != "" {
		// Public images (docker.io/library/nginx) can't be pushed back; write to our registry.
		out = strings.TrimSuffix(c.TargetRepo, "/") + "/" + path.Base(ref.Repository) + ":" + newTag
		target = out
	}
	args := []string{"patch", "-i", src.String(), "-r", reportPath, "-t", target, "-a", c.BuildkitAddr, "--scanner", scanner, "--timeout", or(c.Timeout, "20m")}
	if c.Push {
		args = append(args, "--push")
	}
	if _, err := run(ctx, nil, or(c.Bin, "copa"), args...); err != nil {
		return "", err
	}
	return out, nil
}
