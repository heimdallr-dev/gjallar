// Package gadget streams Inspektor Gadget trace_open events by running
// `kubectl-gadget run trace_open -A -o json` as a subprocess, like the
// scanner adapters do with their CLIs. Field names verified against
// Inspektor Gadget v0.58.0 on containerd (runtime.containerImageDigest is
// empty there, so callers resolve digests from the pod status).
package gadget

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// Open is one successful file open inside a Kubernetes container.
type Open struct {
	Namespace, Pod, Container, Path string
}

type event struct {
	Fname    string `json:"fname"`
	ErrorRaw int    `json:"error_raw"`
	K8s      struct {
		Namespace     string `json:"namespace"`
		PodName       string `json:"podName"`
		ContainerName string `json:"containerName"`
	} `json:"k8s"`
}

// Parse reads JSON lines and calls fn for each successful open in a pod.
// Malformed lines and failed opens (ENOENT probing etc.) are skipped.
func Parse(r io.Reader, fn func(Open)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		var e event
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.ErrorRaw != 0 || e.K8s.PodName == "" || !strings.HasPrefix(e.Fname, "/") {
			continue
		}
		fn(Open{Namespace: e.K8s.Namespace, Pod: e.K8s.PodName, Container: e.K8s.ContainerName, Path: e.Fname})
	}
	return sc.Err()
}

// Stream runs the gadget until ctx ends or the process exits.
// image is the gadget reference, e.g. "trace_open:v0.58.0".
func Stream(ctx context.Context, bin, image string, fn func(Open)) error {
	cmd := exec.CommandContext(ctx, bin, "run", image, "--all-namespaces", "--output", "json")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr strings.Builder
	cmd.Stderr = &limited{w: &stderr, n: 4096}
	if err := cmd.Start(); err != nil {
		return err
	}
	perr := Parse(out, fn)
	if err := cmd.Wait(); err != nil && ctx.Err() == nil {
		return fmt.Errorf("%s run %s: %w: %s", bin, image, err, strings.TrimSpace(stderr.String()))
	}
	return perr
}

// limited keeps the first n bytes of stderr for error messages.
type limited struct {
	w io.Writer
	n int
}

func (l *limited) Write(p []byte) (int, error) {
	if l.n > 0 {
		k := min(len(p), l.n)
		l.n -= k
		_, _ = l.w.Write(p[:k])
	}
	return len(p), nil
}
