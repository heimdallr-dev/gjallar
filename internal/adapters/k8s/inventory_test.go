package k8s

import (
	"encoding/json"
	"testing"
	"time"
)

const podsJSON = `[
 {"metadata":{"name":"web-7d9f8c6b5-abcde","namespace":"shop","labels":{"app":"web"},
   "ownerReferences":[{"kind":"ReplicaSet","name":"web-7d9f8c6b5"}]},
  "spec":{"containers":[{"name":"app","image":"harbor.local/shop/web:1.0",
     "securityContext":{"runAsNonRoot":true,"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true},
     "resources":{"limits":{"cpu":"1","memory":"512Mi"}}}]},
  "status":{"phase":"Running","containerStatuses":[{"name":"app",
     "imageID":"harbor.local/shop/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}},
 {"metadata":{"name":"web-7d9f8c6b5-fghij","namespace":"shop","labels":{"app":"web"},
   "ownerReferences":[{"kind":"ReplicaSet","name":"web-7d9f8c6b5"}]},
  "spec":{"containers":[{"name":"app","image":"harbor.local/shop/web:1.0"}]},
  "status":{"phase":"Running","containerStatuses":[{"name":"app","imageID":"docker-pullable://harbor.local/shop/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}},
 {"metadata":{"name":"node-exporter-x1","namespace":"monitoring","labels":{"app":"ne"},
   "ownerReferences":[{"kind":"DaemonSet","name":"node-exporter"}]},
  "spec":{"hostNetwork":true,"volumes":[{"hostPath":{}}],"containers":[{"name":"ne","image":"prom/node-exporter",
     "securityContext":{"privileged":true}}]},
  "status":{"phase":"Running","containerStatuses":[{"name":"ne","imageID":"sha256:bbbb"}]}}
]`

const svcJSON = `[{"metadata":{"name":"web","namespace":"shop"},"spec":{"type":"ClusterIP","selector":{"app":"web"}}}]`
const ingJSON = `[{"metadata":{"name":"web","namespace":"shop"},"spec":{"rules":[{"http":{"paths":[{"backend":{"service":{"name":"web"}}}]}}]}}]`

func TestBuildWorkloads(t *testing.T) {
	var pods []pod
	var svcs []service
	var ings []ingress
	for _, x := range []struct {
		s string
		v any
	}{{podsJSON, &pods}, {svcJSON, &svcs}, {ingJSON, &ings}} {
		if err := json.Unmarshal([]byte(x.s), x.v); err != nil {
			t.Fatal(err)
		}
	}
	ws := BuildWorkloads("homelab", pods, svcs, ings, nil, time.Now())
	if len(ws) != 2 {
		t.Fatalf("replicas should collapse into one workload, got %d", len(ws))
	}
	web := ws[0]
	if web.ID() != "homelab/shop/Deployment/web" || !web.Exposed {
		t.Errorf("web: id=%s exposed=%v", web.ID(), web.Exposed)
	}
	c := web.Containers[0]
	if c.Image.Digest == "" || !c.RunAsNonRoot || c.AllowPrivilegeEscalation || !c.HasLimits || !c.ReadOnlyRootFS {
		t.Errorf("web container facts wrong: %+v", c)
	}
	ne := ws[1]
	if ne.Kind != "DaemonSet" || !ne.HostNetwork || !ne.HostPath || !ne.Containers[0].Privileged || ne.Exposed {
		t.Errorf("node-exporter facts wrong: %+v", ne)
	}
	if ne.Containers[0].Image.Digest != "" {
		t.Errorf("bare config digest must be ignored, got %s", ne.Containers[0].Image.Digest)
	}
	if got := BuildWorkloads("c", pods, svcs, ings, map[string]bool{"shop": true}, time.Now()); len(got) != 1 {
		t.Errorf("namespace skip failed: %d", len(got))
	}
}
