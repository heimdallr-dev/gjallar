package main

import (
	"testing"

	"github.com/heimdallr-dev/gjallar/internal/adapters/rego"
	"github.com/heimdallr-dev/gjallar/internal/domain"
)

func TestAttachPosture(t *testing.T) {
	ws := []domain.Workload{{Cluster: "c", Namespace: "shop", Kind: "Deployment", Name: "web"}, {Cluster: "c", Namespace: "shop", Kind: "Deployment", Name: "api"}}
	owners := map[string]string{
		"Pod/shop/web-6d4f9-abcde": "Deployment/web", "Pod/shop/web-6d4f9-fghij": "Deployment/web",
		"Deployment/shop/web": "Deployment/web",
	}
	rs := []rego.Result{
		{Kind: "Pod", Namespace: "shop", Name: "web-6d4f9-abcde", ControlID: "C-0057", Message: "privileged"},
		{Kind: "Pod", Namespace: "shop", Name: "web-6d4f9-fghij", ControlID: "C-0057", Message: "privileged"}, // replica: same finding
		{Kind: "Deployment", Namespace: "shop", Name: "web", ControlID: "C-0044", Message: "host port"},
		{Kind: "Pod", Namespace: "other", Name: "unknown", ControlID: "C-0001", Message: "x"},
	}
	attachPosture(ws, rs, owners)
	if got := ws[0].ExternalPosture; len(got) != 2 || got[0].CheckID != "C-0057" || got[0].WorkloadID != "c/shop/Deployment/web" || got[1].CheckID != "C-0044" {
		t.Fatalf("web posture: %+v", got)
	}
	if len(ws[1].ExternalPosture) != 0 {
		t.Fatalf("api posture: %+v", ws[1].ExternalPosture)
	}
}
