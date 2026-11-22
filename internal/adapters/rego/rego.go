// Package rego evaluates Kubescape's open regolibrary controls (C-xxxx) with
// the OPA CLI, next to Gjallar's built-in GJ posture checks. All usable rules
// are loaded into one OPA bundle (each rule's package renamed) so a whole
// cluster is evaluated with a single `opa eval` per inventory pass.
package rego

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/heimdallr-dev/gjallar/internal/domain"
)

// workloadKinds are the objects Gjallar sends; rules matching none are skipped.
var workloadKinds = map[string]bool{"Pod": true, "Deployment": true, "StatefulSet": true, "DaemonSet": true, "Job": true, "CronJob": true, "ReplicaSet": true}

// Engine holds a compiled bundle in Dir.
type Engine struct {
	Bin      string // opa binary
	Dir      string
	Rules    int               // rules loaded
	Dropped  []string          // rules that did not compile standalone
	controls map[string][]ctrl // rule name → controls using it
}

type ctrl struct {
	ID       string
	Severity domain.Severity
}

// Result is one control failing on one Kubernetes object.
type Result struct {
	Kind, Namespace, Name string
	ControlID             string
	Severity              domain.Severity
	Message               string
}

var pkgLine = regexp.MustCompile(`(?m)^package armo_builtins\s*$`)
var badFile = regexp.MustCompile(`(r_\d+)\.rego:\d+`)

// Load builds the bundle from a regolibrary release folder (files "rules",
// "controls", "default_config_inputs") into a temporary directory.
func Load(ctx context.Context, bin, libDir string) (*Engine, error) {
	var rules []struct {
		Name             string `json:"name"`
		Rule             string `json:"rule"`
		RuleLanguage     string `json:"ruleLanguage"`
		RuleDependencies []any  `json:"ruleDependencies"`
		Match            []struct {
			Resources []string `json:"resources"`
		} `json:"match"`
	}
	var controls []struct {
		ID        string   `json:"controlID"`
		RuleNames []string `json:"rulesNames"`
		BaseScore float64  `json:"baseScore"`
	}
	var cfg struct {
		Settings struct {
			PostureControlInputs json.RawMessage `json:"postureControlInputs"`
		} `json:"settings"`
	}
	for f, v := range map[string]any{"rules": &rules, "controls": &controls, "default_config_inputs": &cfg} {
		b, err := os.ReadFile(filepath.Join(libDir, f))
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, v); err != nil {
			return nil, fmt.Errorf("regolibrary %s: %w", f, err)
		}
	}
	e := &Engine{Bin: or(bin, "opa"), controls: map[string][]ctrl{}}
	for _, c := range controls {
		for _, r := range c.RuleNames {
			e.controls[r] = append(e.controls[r], ctrl{ID: c.ID, Severity: severity(c.BaseScore)})
		}
	}
	dir, err := os.MkdirTemp("", "gjallar-rego-")
	if err != nil {
		return nil, err
	}
	e.Dir = dir
	names := map[string]string{} // module → rule name
	for i, r := range rules {
		usable := strings.EqualFold(r.RuleLanguage, "rego") && len(r.RuleDependencies) == 0 && len(e.controls[r.Name]) > 0
		match := false
		for _, m := range r.Match {
			for _, k := range m.Resources {
				match = match || workloadKinds[k]
			}
		}
		if !usable || !match {
			continue
		}
		mod := fmt.Sprintf("r_%d", i)
		names[mod] = r.Name
		if err := os.WriteFile(filepath.Join(dir, mod+".rego"), []byte(pkgLine.ReplaceAllString(r.Rule, "package "+mod)), 0o600); err != nil {
			return nil, err
		}
	}
	data, _ := json.Marshal(map[string]json.RawMessage{"postureControlInputs": cfg.Settings.PostureControlInputs})
	if err := os.WriteFile(filepath.Join(dir, "data.json"), data, 0o600); err != nil {
		return nil, err
	}
	// Drop modules that don't compile on their own (they need Kubescape-only
	// helper libraries); one bad rule must not disable the rest.
	for range len(names) + 1 {
		out, err := exec.CommandContext(ctx, e.Bin, "check", "--v0-compatible", dir).CombinedOutput()
		if err == nil {
			break
		}
		bad := badFile.FindAllStringSubmatch(string(out), -1)
		if len(bad) == 0 {
			return nil, fmt.Errorf("opa check: %s", strings.TrimSpace(string(out)))
		}
		for _, m := range bad {
			if n, ok := names[m[1]]; ok {
				e.Dropped = append(e.Dropped, n)
				delete(names, m[1])
				_ = os.Remove(filepath.Join(dir, m[1]+".rego"))
			}
		}
	}
	var all strings.Builder
	all.WriteString("package gjallar_all\n\n")
	for mod, name := range names {
		fmt.Fprintf(&all, "results[%q] := data.%s.deny\n", name, mod)
	}
	e.Rules = len(names)
	return e, os.WriteFile(filepath.Join(dir, "all.rego"), []byte(all.String()), 0o600)
}

// Evaluate runs every loaded control over the objects (Kubernetes JSON).
func (e *Engine) Evaluate(ctx context.Context, objects []json.RawMessage) ([]Result, error) {
	in, err := json.Marshal(objects)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, e.Bin, "eval", "--v0-compatible", "-d", e.Dir, "--stdin-input", "-f", "json", "data.gjallar_all.results")
	cmd.Stdin = bytes.NewReader(in)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("opa eval: %w: %s", err, strings.TrimSpace(errb.String()))
	}
	return e.parse(out.Bytes())
}

func (e *Engine) parse(b []byte) ([]Result, error) {
	var doc struct {
		Result []struct {
			Expressions []struct {
				Value map[string][]struct {
					AlertMessage string `json:"alertMessage"`
					AlertObject  struct {
						K8sAPIObjects []struct {
							Kind     string `json:"kind"`
							Metadata struct {
								Name      string `json:"name"`
								Namespace string `json:"namespace"`
							} `json:"metadata"`
						} `json:"k8sApiObjects"`
					} `json:"alertObject"`
				} `json:"value"`
			} `json:"expressions"`
		} `json:"result"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("opa output: %w", err)
	}
	var out []Result
	for _, r := range doc.Result {
		for _, ex := range r.Expressions {
			for rule, msgs := range ex.Value {
				for _, m := range msgs {
					for _, o := range m.AlertObject.K8sAPIObjects {
						for _, c := range e.controls[rule] {
							out = append(out, Result{Kind: o.Kind, Namespace: o.Metadata.Namespace, Name: o.Metadata.Name,
								ControlID: c.ID, Severity: c.Severity, Message: m.AlertMessage})
						}
					}
				}
			}
		}
	}
	return out, nil
}

func severity(score float64) domain.Severity {
	switch {
	case score >= 7:
		return domain.SeverityHigh
	case score >= 4:
		return domain.SeverityMedium
	default:
		return domain.SeverityLow
	}
}

func or(v, d string) string {
	if v == "" {
		return d
	}
	return v
}
