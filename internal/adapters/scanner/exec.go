// Package scanner adapts the Anchore and Copacetic CLIs to Gjallar's ports.
// Engines run as subprocesses: no heavy library dependencies, any version
// can be swapped by changing the image, and a crash cannot take down Gjallar.
package scanner

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/heimdallr-dev/gjallar/internal/platform/telemetry"
)

// Runner executes a binary. Swappable in tests.
type Runner func(ctx context.Context, env []string, name string, args ...string) (stdout []byte, err error)

// ExecRunner runs a real subprocess and folds stderr into errors.
func ExecRunner(ctx context.Context, env []string, name string, args ...string) (_ []byte, err error) {
	engine, start := filepath.Base(name), time.Now()
	defer func() {
		telemetry.EngineSeconds.Add(time.Since(start).Seconds(), engine)
		telemetry.EngineRuns.Inc(engine, map[bool]string{true: "ok", false: "error"}[err == nil])
	}()
	cmd := exec.CommandContext(ctx, name, args...)
	// No hidden phone-home: engines never check the internet for their own updates.
	cmd.Env = append(append(os.Environ(), noUpdateChecks...), env...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if len(msg) > 2000 {
			msg = msg[len(msg)-2000:]
		}
		return out.Bytes(), fmt.Errorf("%s %s: %w: %s", name, strings.Join(redact(args), " "), err, msg)
	}
	return out.Bytes(), nil
}

func redact(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		if strings.Contains(strings.ToLower(a), "password") || strings.Contains(strings.ToLower(a), "token") {
			out[i] = "***"
		} else {
			out[i] = a
		}
	}
	return out
}

func writeTemp(pattern string, data []byte) (string, func(), error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", nil, err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", nil, err
	}
	f.Close()
	return f.Name(), func() { os.Remove(f.Name()) }, nil
}

var noUpdateChecks = []string{"SYFT_CHECK_FOR_APP_UPDATE=false", "GRYPE_CHECK_FOR_APP_UPDATE=false", "GRANT_CHECK_FOR_APP_UPDATE=false"}
