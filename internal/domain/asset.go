// Package domain holds Gjallar's core model. It has no dependencies on
// infrastructure: no NATS, no SQL, no HTTP. Everything else depends on it.
package domain

import (
	"fmt"
	"strings"
	"time"
)

// Digest is an OCI content digest such as "sha256:abc...". Images are
// identified by digest, never by tag, so each image is scanned once.
type Digest string

// Valid reports whether d looks like an OCI digest.
func (d Digest) Valid() bool {
	algo, hex, ok := strings.Cut(string(d), ":")
	return ok && algo != "" && len(hex) >= 32
}

// Short returns the first 12 hex characters, for display.
func (d Digest) Short() string {
	_, hex, ok := strings.Cut(string(d), ":")
	if !ok || len(hex) < 12 {
		return string(d)
	}
	return hex[:12]
}

// ImageRef points at an image in a registry.
type ImageRef struct {
	Repository string `json:"repository"`
	Tag        string `json:"tag,omitempty"`
	Digest     Digest `json:"digest,omitempty"`
}

// String renders the most precise reference available.
func (r ImageRef) String() string {
	switch {
	case r.Digest != "":
		return r.Repository + "@" + string(r.Digest)
	case r.Tag != "":
		return r.Repository + ":" + r.Tag
	default:
		return r.Repository
	}
}

// ParseImageRef parses "repo[:tag][@digest]".
func ParseImageRef(s string) (ImageRef, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return ImageRef{}, fmt.Errorf("empty image reference")
	}
	var ref ImageRef
	if repo, dg, ok := strings.Cut(s, "@"); ok {
		ref.Digest = Digest(dg)
		s = repo
	}
	// A colon after the last slash is a tag; before it, a registry port.
	if i := strings.LastIndex(s, ":"); i > strings.LastIndex(s, "/") {
		ref.Repository, ref.Tag = s[:i], s[i+1:]
	} else {
		ref.Repository = s
	}
	if ref.Repository == "" {
		return ImageRef{}, fmt.Errorf("invalid image reference %q", s)
	}
	return ref, nil
}

// UsesMutableTag reports whether the reference relies on a tag that can move.
func (r ImageRef) UsesMutableTag() bool {
	return r.Digest == "" && (r.Tag == "" || r.Tag == "latest")
}

// Image is a scanned (or to-be-scanned) image, keyed by digest.
type Image struct {
	Digest      Digest    `json:"digest"`
	Repository  string    `json:"repository"`
	Tag         string    `json:"tag,omitempty"`
	Distro      string    `json:"distro,omitempty"`
	Packages    int       `json:"packages"`
	SBOMReady   bool      `json:"sbom_ready"`
	DBVersion   string    `json:"db_version,omitempty"`
	FirstSeen   time.Time `json:"first_seen"`
	LastScanned time.Time `json:"last_scanned,omitempty"`
}

// Container is one container inside a workload.
type Container struct {
	Name  string   `json:"name"`
	Image ImageRef `json:"image"`
	// Security context facts the posture checks need.
	Privileged               bool     `json:"privileged,omitempty"`
	RunAsNonRoot             bool     `json:"run_as_non_root,omitempty"`
	AllowPrivilegeEscalation bool     `json:"allow_privilege_escalation,omitempty"`
	ReadOnlyRootFS           bool     `json:"read_only_root_fs,omitempty"`
	HasLimits                bool     `json:"has_limits,omitempty"`
	AddedCapabilities        []string `json:"added_capabilities,omitempty"`
}

// Workload is anything that runs containers: Deployment, StatefulSet, Job...
type Workload struct {
	Cluster     string      `json:"cluster"`
	Namespace   string      `json:"namespace"`
	Kind        string      `json:"kind"`
	Name        string      `json:"name"`
	Containers  []Container `json:"containers"`
	HostNetwork bool        `json:"host_network,omitempty"`
	HostPID     bool        `json:"host_pid,omitempty"`
	HostPath    bool        `json:"host_path,omitempty"`
	// Exposed is true when a LoadBalancer/NodePort Service or an Ingress
	// routes traffic to this workload.
	Exposed  bool      `json:"exposed"`
	LastSeen time.Time `json:"last_seen"`
	// ExternalPosture: violations found by the agent's policy engine
	// (Kubescape regolibrary via OPA), stored next to the built-in GJ checks.
	ExternalPosture []PostureViolation `json:"external_posture,omitempty"`
}

// ID is the stable identity of a workload across scans.
func (w Workload) ID() string {
	return strings.Join([]string{w.Cluster, w.Namespace, w.Kind, w.Name}, "/")
}
