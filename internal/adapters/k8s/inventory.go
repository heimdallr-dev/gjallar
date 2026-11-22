// Package k8s reads cluster inventory straight from the Kubernetes API with
// the standard library (no client-go), keeping the agent tiny.
package k8s

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/heimdallr-dev/gjallar/internal/domain"
)

const saDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// Client talks to the API server.
type Client struct {
	Base  string
	Token string
	HTTP  *http.Client
}

// InCluster builds a client from the pod's service account.
func InCluster() (*Client, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" {
		return nil, fmt.Errorf("not running in a cluster (KUBERNETES_SERVICE_HOST unset)")
	}
	tok, err := os.ReadFile(saDir + "/token")
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(saDir + "/ca.crt")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	return &Client{
		Base:  "https://" + strings.Trim(host, "[]") + ":" + port,
		Token: strings.TrimSpace(string(tok)),
		HTTP:  &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}},
	}, nil
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+path, nil)
	if err != nil {
		return err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("GET %s: %w", path, errNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", path, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

var errNotFound = errors.New("not found")

// ---- minimal API types ------------------------------------------------

type meta struct {
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace"`
	Labels          map[string]string `json:"labels"`
	OwnerReferences []struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"ownerReferences"`
}

type secCtx struct {
	Privileged               *bool  `json:"privileged"`
	RunAsNonRoot             *bool  `json:"runAsNonRoot"`
	RunAsUser                *int64 `json:"runAsUser"`
	AllowPrivilegeEscalation *bool  `json:"allowPrivilegeEscalation"`
	ReadOnlyRootFilesystem   *bool  `json:"readOnlyRootFilesystem"`
	Capabilities             *struct {
		Add []string `json:"add"`
	} `json:"capabilities"`
}

type pod struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		HostNetwork     bool    `json:"hostNetwork"`
		HostPID         bool    `json:"hostPID"`
		SecurityContext *secCtx `json:"securityContext"`
		Volumes         []struct {
			HostPath *struct{} `json:"hostPath"`
		} `json:"volumes"`
		Containers []struct {
			Name            string  `json:"name"`
			Image           string  `json:"image"`
			SecurityContext *secCtx `json:"securityContext"`
			Resources       struct {
				Limits map[string]string `json:"limits"`
			} `json:"resources"`
		} `json:"containers"`
	} `json:"spec"`
	Status struct {
		Phase             string `json:"phase"`
		ContainerStatuses []struct {
			Name    string `json:"name"`
			ImageID string `json:"imageID"`
		} `json:"containerStatuses"`
	} `json:"status"`
}

type service struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		Type     string            `json:"type"`
		Selector map[string]string `json:"selector"`
	} `json:"spec"`
}

type ingress struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		DefaultBackend *ingBackend `json:"defaultBackend"`
		Rules          []struct {
			HTTP *struct {
				Paths []struct {
					Backend ingBackend `json:"backend"`
				} `json:"paths"`
			} `json:"http"`
		} `json:"rules"`
	} `json:"spec"`
}

type ingBackend struct {
	Service *struct {
		Name string `json:"name"`
	} `json:"service"`
}

type list[T any] struct {
	Items []T `json:"items"`
}

// ContainerDigest returns the image digest a running container uses, from
// the pod's container status (runtime events don't carry it on containerd).
// It returns "" with no error when the pod or container is gone or not
// started yet.
func (c *Client) ContainerDigest(ctx context.Context, ns, podName, container string) (domain.Digest, error) {
	var p pod
	if err := c.get(ctx, "/api/v1/namespaces/"+url.PathEscape(ns)+"/pods/"+url.PathEscape(podName), &p); err != nil {
		if errors.Is(err, errNotFound) {
			return "", nil
		}
		return "", err
	}
	for _, cs := range p.Status.ContainerStatuses {
		if cs.Name == container {
			return domain.Digest(digestFromImageID(cs.ImageID)), nil
		}
	}
	return "", nil
}

// ---- inventory ------------------------------------------------------------

var rsHash = regexp.MustCompile(`-[a-z0-9]{6,10}$`)

// Collect lists running pods, groups them into workloads, resolves image
// digests from container status and marks workloads reachable from outside
// (LoadBalancer/NodePort Services or Ingress backends).
func (c *Client) Collect(ctx context.Context, cluster string, skipNamespaces map[string]bool) ([]domain.Workload, error) {
	var pods list[pod]
	if err := c.get(ctx, "/api/v1/pods?fieldSelector=status.phase%3DRunning", &pods); err != nil {
		return nil, err
	}
	var svcs list[service]
	if err := c.get(ctx, "/api/v1/services", &svcs); err != nil {
		return nil, err
	}
	var ings list[ingress]
	if err := c.get(ctx, "/apis/networking.k8s.io/v1/ingresses", &ings); err != nil {
		ings.Items = nil // Ingress API may be absent or forbidden; exposure falls back to Services
	}
	return BuildWorkloads(cluster, pods.Items, svcs.Items, ings.Items, skipNamespaces, time.Now()), nil
}

// BuildWorkloads is the pure part of Collect, separated for testing.
func BuildWorkloads(cluster string, pods []pod, svcs []service, ings []ingress, skip map[string]bool, now time.Time) []domain.Workload {
	ingressed := map[string]bool{} // ns/service
	for _, ig := range ings {
		mark := func(b *ingBackend) {
			if b != nil && b.Service != nil {
				ingressed[ig.Metadata.Namespace+"/"+b.Service.Name] = true
			}
		}
		mark(ig.Spec.DefaultBackend)
		for _, r := range ig.Spec.Rules {
			if r.HTTP != nil {
				for _, p := range r.HTTP.Paths {
					mark(&p.Backend)
				}
			}
		}
	}
	exposedBy := func(p pod) bool {
		for _, s := range svcs {
			if s.Metadata.Namespace != p.Metadata.Namespace || len(s.Spec.Selector) == 0 {
				continue
			}
			if !selects(s.Spec.Selector, p.Metadata.Labels) {
				continue
			}
			if s.Spec.Type == "LoadBalancer" || s.Spec.Type == "NodePort" || ingressed[s.Metadata.Namespace+"/"+s.Metadata.Name] {
				return true
			}
		}
		return false
	}

	byID := map[string]*domain.Workload{}
	var order []string
	for _, p := range pods {
		if skip[p.Metadata.Namespace] {
			continue
		}
		kind, name := owner(p)
		w := domain.Workload{Cluster: cluster, Namespace: p.Metadata.Namespace, Kind: kind, Name: name, LastSeen: now,
			HostNetwork: p.Spec.HostNetwork, HostPID: p.Spec.HostPID, Exposed: exposedBy(p)}
		for _, v := range p.Spec.Volumes {
			if v.HostPath != nil {
				w.HostPath = true
			}
		}
		digests := map[string]string{}
		for _, cs := range p.Status.ContainerStatuses {
			digests[cs.Name] = digestFromImageID(cs.ImageID)
		}
		for _, ct := range p.Spec.Containers {
			ref, err := domain.ParseImageRef(ct.Image)
			if err != nil {
				continue
			}
			if d := digests[ct.Name]; d != "" {
				ref.Digest = domain.Digest(d)
			}
			sc := merge(p.Spec.SecurityContext, ct.SecurityContext)
			c := domain.Container{Name: ct.Name, Image: ref, HasLimits: ct.Resources.Limits["memory"] != "" && ct.Resources.Limits["cpu"] != ""}
			c.Privileged = sc.Privileged != nil && *sc.Privileged
			c.RunAsNonRoot = (sc.RunAsNonRoot != nil && *sc.RunAsNonRoot) || (sc.RunAsUser != nil && *sc.RunAsUser != 0)
			c.AllowPrivilegeEscalation = sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation
			c.ReadOnlyRootFS = sc.ReadOnlyRootFilesystem != nil && *sc.ReadOnlyRootFilesystem
			if sc.Capabilities != nil {
				c.AddedCapabilities = sc.Capabilities.Add
			}
			w.Containers = append(w.Containers, c)
		}
		id := w.ID()
		if existing, ok := byID[id]; ok {
			existing.Exposed = existing.Exposed || w.Exposed // replicas of the same workload
			continue
		}
		byID[id] = &w
		order = append(order, id)
	}
	out := make([]domain.Workload, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out
}

func owner(p pod) (kind, name string) {
	if len(p.Metadata.OwnerReferences) == 0 {
		return "Pod", p.Metadata.Name
	}
	o := p.Metadata.OwnerReferences[0]
	switch o.Kind {
	case "ReplicaSet":
		return "Deployment", rsHash.ReplaceAllString(o.Name, "")
	case "Job":
		// CronJob-created jobs end in a timestamp suffix.
		if i := strings.LastIndex(o.Name, "-"); i > 0 && len(o.Name)-i-1 >= 8 {
			return "CronJob", o.Name[:i]
		}
	}
	return o.Kind, o.Name
}

func selects(sel, labels map[string]string) bool {
	for k, v := range sel {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// digestFromImageID handles "docker-pullable://repo@sha256:..", "repo@sha256:.."
// and bare "sha256:..". A bare config digest is not a registry digest, so
// it is ignored rather than mis-scanned.
func digestFromImageID(id string) string {
	id = strings.TrimPrefix(id, "docker-pullable://")
	if _, d, ok := strings.Cut(id, "@"); ok {
		return d
	}
	return ""
}

func merge(pod, ctr *secCtx) secCtx {
	var out secCtx
	if pod != nil {
		out = *pod
	}
	if ctr == nil {
		return out
	}
	if ctr.Privileged != nil {
		out.Privileged = ctr.Privileged
	}
	if ctr.RunAsNonRoot != nil {
		out.RunAsNonRoot = ctr.RunAsNonRoot
	}
	if ctr.RunAsUser != nil {
		out.RunAsUser = ctr.RunAsUser
	}
	if ctr.AllowPrivilegeEscalation != nil {
		out.AllowPrivilegeEscalation = ctr.AllowPrivilegeEscalation
	}
	if ctr.ReadOnlyRootFilesystem != nil {
		out.ReadOnlyRootFilesystem = ctr.ReadOnlyRootFilesystem
	}
	if ctr.Capabilities != nil {
		out.Capabilities = ctr.Capabilities
	}
	return out
}

// RestartDeployment triggers a rolling restart, like `kubectl rollout restart`.
func (c *Client) RestartDeployment(ctx context.Context, ns, name string) error {
	body := fmt.Sprintf(`{"spec":{"template":{"metadata":{"annotations":{"gjallar.io/restartedAt":%q}}}}}`, time.Now().UTC().Format(time.RFC3339))
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, fmt.Sprintf("%s/apis/apps/v1/namespaces/%s/deployments/%s", c.Base, ns, name), strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/strategic-merge-patch+json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("patch deployment %s/%s: %s", ns, name, resp.Status)
	}
	return nil
}

// DeploymentRolledOut reports whether the latest rollout finished.
func (c *Client) DeploymentRolledOut(ctx context.Context, ns, name string) (bool, error) {
	var d struct {
		Metadata struct {
			Generation int64 `json:"generation"`
		} `json:"metadata"`
		Spec struct {
			Replicas *int32 `json:"replicas"`
		} `json:"spec"`
		Status struct {
			ObservedGeneration int64 `json:"observedGeneration"`
			UpdatedReplicas    int32 `json:"updatedReplicas"`
			AvailableReplicas  int32 `json:"availableReplicas"`
			Replicas           int32 `json:"replicas"`
		} `json:"status"`
	}
	if err := c.get(ctx, fmt.Sprintf("/apis/apps/v1/namespaces/%s/deployments/%s", ns, name), &d); err != nil {
		return false, err
	}
	want := int32(1)
	if d.Spec.Replicas != nil {
		want = *d.Spec.Replicas
	}
	s := d.Status
	return s.ObservedGeneration >= d.Metadata.Generation && s.UpdatedReplicas == want && s.AvailableReplicas == want && s.Replicas == want, nil
}

// RawObjects returns running pods and their controllers as full Kubernetes
// JSON (for OPA/regolibrary), and for each "Kind/namespace/name" the
// workload it belongs to as "Kind/name" (matching Workload.ID()).
func (c *Client) RawObjects(ctx context.Context, skipNamespaces map[string]bool) ([]json.RawMessage, map[string]string, error) {
	var objs []json.RawMessage
	owners := map[string]string{}
	for _, src := range []struct{ path, kind, apiVersion string }{
		{"/api/v1/pods?fieldSelector=status.phase%3DRunning", "Pod", "v1"},
		{"/apis/apps/v1/deployments", "Deployment", "apps/v1"},
		{"/apis/apps/v1/statefulsets", "StatefulSet", "apps/v1"},
		{"/apis/apps/v1/daemonsets", "DaemonSet", "apps/v1"},
		{"/apis/batch/v1/cronjobs", "CronJob", "batch/v1"},
	} {
		var l list[json.RawMessage]
		if err := c.get(ctx, src.path, &l); err != nil {
			if src.kind == "Pod" {
				return nil, nil, err
			}
			continue // controller APIs may be forbidden; pods alone still evaluate
		}
		for _, raw := range l.Items {
			var obj map[string]any
			if json.Unmarshal(raw, &obj) != nil {
				continue
			}
			// List items carry no kind/apiVersion; rules match on them.
			obj["kind"], obj["apiVersion"] = src.kind, src.apiVersion
			var p pod
			_ = json.Unmarshal(raw, &p)
			if skipNamespaces[p.Metadata.Namespace] {
				continue
			}
			kind, name := src.kind, p.Metadata.Name
			if src.kind == "Pod" {
				kind, name = owner(p)
			}
			owners[src.kind+"/"+p.Metadata.Namespace+"/"+p.Metadata.Name] = kind + "/" + name
			b, _ := json.Marshal(obj)
			objs = append(objs, b)
		}
	}
	return objs, owners, nil
}
