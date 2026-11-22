package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/heimdallr-dev/gjallar/internal/adapters/memory"
	"github.com/heimdallr-dev/gjallar/internal/app"
	"github.com/heimdallr-dev/gjallar/internal/domain"
)

type ledger map[string]bool

func (l ledger) MarkNew(_ context.Context, k string) (bool, error) {
	if l[k] {
		return false, nil
	}
	l[k] = true
	return true, nil
}

func (l ledger) Forget(_ context.Context, k string) error { delete(l, k); return nil }

type sent map[string][]string

func (s sent) Send(_ context.Context, t app.NotifyTarget, as []app.Alert) error {
	for _, a := range as {
		s[t.Name] = append(s[t.Name], a.Finding.VulnID)
	}
	return nil
}

func TestNotifier(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewRepo()
	d := domain.Digest("sha256:" + strings.Repeat("b", 64))
	img := domain.ImageRef{Repository: "harbor.local/shop/web", Tag: "1", Digest: d}
	_ = repo.UpsertWorkload(ctx, domain.Workload{Cluster: "c", Namespace: "shop", Kind: "Deployment", Name: "web", Containers: []domain.Container{{Name: "web", Image: img}}})
	_, _ = repo.EnsureImage(ctx, img)
	mk := func(id string, band domain.RiskBand, kev bool) domain.Finding {
		return domain.Finding{ID: domain.FindingID(d, id, "p", "1"), Digest: d, VulnID: id, Package: "p", Version: "1", KEV: kev, State: domain.StateOpen, Risk: domain.RiskScore{Value: 50, Band: band}}
	}
	fs := []domain.Finding{mk("CVE-URGENT", domain.BandUrgent, false), mk("CVE-KEV-MEDIUM", domain.BandMedium, true), mk("CVE-LOW", "low", false)}
	_ = repo.SaveFindings(ctx, d, "db", fs)

	out := sent{}
	n := &app.Notifier{Repo: repo, Ledger: ledger{}, Sender: out, Targets: []app.NotifyTarget{
		{Name: "shop-team", Namespaces: []string{"shop"}, KEV: true},
		{Name: "other-team", Namespaces: []string{"payments"}},
		{Name: "secops", MinBand: "medium"},
	}}
	ev := domain.FindingsScored{Digest: d, Repository: img.Repository, Findings: fs}
	if err := n.HandleScored(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(out["shop-team"], ","); got != "CVE-URGENT,CVE-KEV-MEDIUM" {
		t.Errorf("shop-team got %q", got)
	}
	if len(out["other-team"]) != 0 {
		t.Errorf("other namespace must not be notified: %v", out["other-team"])
	}
	if got := strings.Join(out["secops"], ","); got != "CVE-URGENT,CVE-KEV-MEDIUM" {
		t.Errorf("secops (min medium) got %q", got)
	}
	before := len(out["shop-team"])
	if err := n.HandleScored(ctx, ev); err != nil || len(out["shop-team"]) != before {
		t.Errorf("re-scoring must not notify again: %v %v", out["shop-team"], err)
	}
}

type flaky struct {
	fails int
	got   []string
}

func (f *flaky) Send(_ context.Context, _ app.NotifyTarget, as []app.Alert) error {
	if f.fails > 0 {
		f.fails--
		return errors.New("webhook 502")
	}
	for _, a := range as {
		f.got = append(f.got, a.Finding.VulnID)
	}
	return nil
}

func TestNotifierRetriesAfterFailedSend(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewRepo()
	d := domain.Digest("sha256:" + strings.Repeat("c", 64))
	f := domain.Finding{ID: domain.FindingID(d, "CVE-X", "p", "1"), Digest: d, VulnID: "CVE-X", Package: "p", Version: "1",
		State: domain.StateOpen, Risk: domain.RiskScore{Value: 90, Band: domain.BandUrgent}}
	_ = repo.SaveFindings(ctx, d, "db", []domain.Finding{f})
	s := &flaky{fails: 1}
	n := &app.Notifier{Repo: repo, Ledger: ledger{}, Sender: s, Targets: []app.NotifyTarget{{Name: "t"}}}
	ev := domain.FindingsScored{Digest: d, Findings: []domain.Finding{f}}
	if err := n.HandleScored(ctx, ev); err == nil {
		t.Fatal("failed send must return an error so the bus redelivers")
	}
	if err := n.HandleScored(ctx, ev); err != nil || len(s.got) != 1 {
		t.Fatalf("redelivery must send: %v %v", err, s.got)
	}
}
