package rego

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
)

// Runs against a real regolibrary release (GJALLAR_REGOLIB_DIR with files
// rules, controls, default_config_inputs) and a real opa on PATH.
func TestRegolibraryControls(t *testing.T) {
	dir := os.Getenv("GJALLAR_REGOLIB_DIR")
	if _, err := exec.LookPath("opa"); err != nil || dir == "" {
		t.Skip("needs opa on PATH and GJALLAR_REGOLIB_DIR")
	}
	ctx := context.Background()
	e, err := Load(ctx, "", dir)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(e.Dir)
	t.Logf("loaded %d rules, dropped %d", e.Rules, len(e.Dropped))
	if e.Rules < 50 {
		t.Fatalf("too few rules compiled: %d (dropped %v)", e.Rules, e.Dropped)
	}
	pod := func(name string, privileged bool, image string) json.RawMessage {
		b, _ := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "Pod",
			"metadata": map[string]any{"name": name, "namespace": "demo"},
			"spec": map[string]any{"containers": []map[string]any{{"name": "c", "image": image,
				"securityContext": map[string]any{"privileged": privileged, "allowPrivilegeEscalation": privileged, "runAsNonRoot": !privileged, "readOnlyRootFilesystem": !privileged,
					"capabilities": map[string]any{"drop": []string{"ALL"}}},
				"resources": map[string]any{"limits": map[string]any{"cpu": "1", "memory": "1Gi"}, "requests": map[string]any{"cpu": "100m", "memory": "100Mi"}}}}}})
		return b
	}
	rs, err := e.Evaluate(ctx, []json.RawMessage{pod("bad", true, "nginx:latest"), pod("good", false, "nginx@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")})
	if err != nil {
		t.Fatal(err)
	}
	per := map[string]map[string]bool{}
	for _, r := range rs {
		if per[r.Name] == nil {
			per[r.Name] = map[string]bool{}
		}
		per[r.Name][r.ControlID] = true
	}
	t.Logf("bad pod fails %d controls, good pod %d", len(per["bad"]), len(per["good"]))
	if !per["bad"]["C-0057"] { // Privileged container
		t.Errorf("privileged pod must fail C-0057, got %v", per["bad"])
	}
	if per["good"]["C-0057"] || len(per["good"]) >= len(per["bad"]) {
		t.Errorf("hardened pod should fail fewer controls: good=%v", per["good"])
	}
}
