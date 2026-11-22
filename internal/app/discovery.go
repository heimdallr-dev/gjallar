package app

import (
	"context"
	"errors"
	"log/slog"

	"github.com/heimdallr-dev/gjallar/internal/domain"
)

// RegistryCatalog lists the images (with digests) a registry holds.
type RegistryCatalog interface {
	Images(ctx context.Context) ([]domain.ImageRef, error)
}

// RegistryDiscovery scans images in a registry before they reach a cluster.
type RegistryDiscovery struct {
	Catalog RegistryCatalog
	Hub     *Hub
	Log     *slog.Logger
}

// Run lists the registry once and queues new digests. It returns how many
// were queued; known digests are skipped by the hub's claim.
func (d *RegistryDiscovery) Run(ctx context.Context) (int, error) {
	refs, err := d.Catalog.Images(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	var errs []error
	for _, ref := range refs {
		queued, err := d.Hub.DiscoverImage(ctx, ref)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if queued {
			n++
			if d.Log != nil {
				d.Log.Info("queued sbom from registry", "image", ref.String())
			}
		}
	}
	return n, errors.Join(errs...)
}
