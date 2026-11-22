package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/heimdallr-dev/gjallar/internal/adapters/memory"
	"github.com/heimdallr-dev/gjallar/internal/app"
	"github.com/heimdallr-dev/gjallar/internal/domain"
)

type gen struct{ d domain.Digest }

func (g gen) Generate(context.Context, domain.ImageRef) (domain.SBOM, error) {
	return domain.SBOM{Digest: g.d, Raw: []byte(`{"artifacts":[]}`)}, nil
}

type attestor struct {
	calls []string
	err   error
}

func (a *attestor) Attest(_ context.Context, ref domain.ImageRef, typ string, _ []byte) error {
	a.calls = append(a.calls, ref.Repository+"@"+string(ref.Digest)+" "+typ)
	return a.err
}

func TestSBOMWorkerAttestsOwnRegistriesOnly(t *testing.T) {
	ctx := context.Background()
	d := domain.Digest("sha256:" + strings.Repeat("d", 64))
	bus := memory.NewBus()
	var evs []domain.SBOMGenerated
	bus.Subscribe(domain.SubjSBOMDone, func(_ context.Context, b []byte) error {
		var ev domain.SBOMGenerated
		_ = json.Unmarshal(b, &ev)
		evs = append(evs, ev)
		return nil
	})
	at := &attestor{}
	w := app.SBOMWorker{Gen: gen{d}, Store: memory.NewStore(), Bus: bus, Attest: at, AttestRepos: []string{"harbor.local/"}}
	_ = w.Handle(ctx, domain.ScanJob{Image: domain.ImageRef{Repository: "harbor.local/apps/web", Tag: "1"}, Digest: d})
	_ = w.Handle(ctx, domain.ScanJob{Image: domain.ImageRef{Repository: "docker.io/library/nginx", Tag: "1"}, Digest: d})
	if len(at.calls) != 1 || at.calls[0] != "harbor.local/apps/web@"+string(d)+" "+app.PredicateSyft {
		t.Fatalf("attest calls: %v", at.calls)
	}
	if len(evs) != 2 || !evs[0].Attested || evs[1].Attested {
		t.Fatalf("events: %+v", evs)
	}
	at.err = errors.New("denied")
	_ = w.Handle(ctx, domain.ScanJob{Image: domain.ImageRef{Repository: "harbor.local/apps/web", Tag: "1"}, Digest: d})
	if last := evs[len(evs)-1]; last.Error != "" || last.AttestError != "denied" || last.Packages != 0 && last.Digest == "" {
		t.Fatalf("signing failure must not fail the scan: %+v", last)
	}
}

func TestMergeFindingsPrimaryWins(t *testing.T) {
	g := []domain.Finding{{VulnID: "CVE-1", Package: "openssl", EPSS: 0.9}}
	o := []domain.Finding{{VulnID: "CVE-1", Package: "openssl", Source: "osv"}, {VulnID: "CVE-2", Package: "openssl", Source: "osv"}}
	m := app.MergeFindings(g, o)
	if len(m) != 2 || m[0].EPSS != 0.9 || m[0].Source != "" || m[1].VulnID != "CVE-2" || m[1].Source != "osv" {
		t.Fatalf("merge: %+v", m)
	}
}

func TestAcceptRiskQueuesSignedVEX(t *testing.T) {
	ctx := context.Background()
	repo, bus := memory.NewRepo(), memory.NewBus()
	var jobs []domain.VEXJob
	bus.Subscribe(domain.SubjJobVEX, func(_ context.Context, b []byte) error {
		var j domain.VEXJob
		_ = json.Unmarshal(b, &j)
		jobs = append(jobs, j)
		return nil
	})
	d := domain.Digest("sha256:" + strings.Repeat("e", 64))
	img := domain.ImageRef{Repository: "harbor.local/apps/web", Tag: "1", Digest: d}
	_, _ = repo.EnsureImage(ctx, img)
	f := domain.Finding{ID: domain.FindingID(d, "CVE-9", "openssl", "1"), Digest: d, VulnID: "CVE-9", Package: "openssl", Version: "1", State: domain.StateOpen}
	_ = repo.SaveFindings(ctx, d, "db", []domain.Finding{f})
	hub := app.NewHub(repo, bus, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := hub.AcceptRisk(ctx, f.ID, "not reachable in this service", "ana", nil); err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].Image.Digest != d || !strings.Contains(string(jobs[0].Document), "CVE-9") || !strings.Contains(string(jobs[0].Document), "not_affected") {
		t.Fatalf("vex jobs: %+v", jobs)
	}
	at := &attestor{}
	w := app.VEXWorker{Attest: at, AttestRepos: []string{"harbor.local/"}}
	_ = w.Handle(ctx, jobs[0])
	_ = w.Handle(ctx, domain.VEXJob{Image: domain.ImageRef{Repository: "docker.io/library/nginx", Digest: d}})
	if len(at.calls) != 1 || !strings.HasSuffix(at.calls[0], " openvex") {
		t.Fatalf("attest calls: %v", at.calls)
	}
}
