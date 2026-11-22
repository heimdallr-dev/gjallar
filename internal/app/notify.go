package app

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/heimdallr-dev/gjallar/internal/domain"
)

// NotifyTarget is one webhook (a team's Slack or Teams channel) and what it wants.
type NotifyTarget struct {
	Name       string   `json:"name"`
	URL        string   `json:"url"`
	Format     string   `json:"format"`     // slack | teams | json
	Namespaces []string `json:"namespaces"` // empty = all namespaces
	MinBand    string   `json:"min_band"`   // urgent (default) | high | medium | low
	KEV        bool     `json:"kev"`        // also notify any known-exploited finding, whatever its band
}

// Alert is one finding worth telling a team about.
type Alert struct {
	Finding    domain.Finding
	Repository string
	Workloads  []string
}

// AlertSender delivers a batch of alerts to one target (webhook adapter).
type AlertSender interface {
	Send(ctx context.Context, t NotifyTarget, alerts []Alert) error
}

// AlertLedger remembers what was sent. MarkNew is atomic across replicas:
// it returns true only for the first caller with that key.
type AlertLedger interface {
	MarkNew(ctx context.Context, key string) (bool, error)
	// Forget undoes MarkNew after a failed send, so a retry sends again.
	Forget(ctx context.Context, key string) error
}

// Notifier turns scored findings into team notifications: a finding is sent
// once per target, the first time it is open and urgent (or KEV, if asked).
type Notifier struct {
	Repo    Repository
	Ledger  AlertLedger
	Sender  AlertSender
	Targets []NotifyTarget
}

var bandRank = map[domain.RiskBand]int{"low": 0, "medium": 1, "high": 2, "urgent": 3}

// HandleScored is the consumer for gjallar.results.scored.
func (n *Notifier) HandleScored(ctx context.Context, ev domain.FindingsScored) error {
	if len(n.Targets) == 0 {
		return nil
	}
	views, err := n.Repo.ListFindings(ctx, FindingFilter{Digest: ev.Digest, State: string(domain.StateOpen), Limit: 100000})
	if err != nil {
		return err
	}
	where := make(map[string][]string, len(views))
	for _, v := range views {
		where[v.ID] = v.Workloads
	}
	var errs []error
	for _, t := range n.Targets {
		min := bandRank[domain.RiskBand(strings.ToLower(t.MinBand))]
		if t.MinBand == "" {
			min = bandRank["urgent"]
		}
		var batch []Alert
		for _, f := range ev.Findings {
			if f.State != domain.StateOpen {
				continue
			}
			if bandRank[f.Risk.Band] < min && !(t.KEV && f.KEV) {
				continue
			}
			wl := inNamespaces(where[f.ID], t.Namespaces)
			if len(t.Namespaces) > 0 && len(wl) == 0 {
				continue
			}
			first, err := n.Ledger.MarkNew(ctx, t.Name+"."+f.ID)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if first {
				batch = append(batch, Alert{Finding: f, Repository: ev.Repository, Workloads: wl})
			}
		}
		if len(batch) == 0 {
			continue
		}
		sort.Slice(batch, func(i, j int) bool { return batch[i].Finding.Risk.Value > batch[j].Finding.Risk.Value })
		if err := n.Sender.Send(ctx, t, batch); err != nil {
			// Unmark and fail: the bus redelivers the event with backoff, and the retry sends again.
			for _, a := range batch {
				_ = n.Ledger.Forget(ctx, t.Name+"."+a.Finding.ID)
			}
			errs = append(errs, fmt.Errorf("notify %s: %w", t.Name, err))
		}
	}
	return errors.Join(errs...)
}

// inNamespaces keeps workloads ("ns/name") in the allowed namespaces; all if none given.
func inNamespaces(workloads, namespaces []string) []string {
	if len(namespaces) == 0 {
		return workloads
	}
	var out []string
	for _, w := range workloads {
		ns, _, _ := strings.Cut(w, "/")
		for _, n := range namespaces {
			if ns == n {
				out = append(out, w)
				break
			}
		}
	}
	return out
}
