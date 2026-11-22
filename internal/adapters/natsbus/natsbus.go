// Package natsbus adapts NATS JetStream to Gjallar's EventBus and SBOMStore
// ports, and provides durable consumers for driving adapters (hub, workers).
package natsbus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/heimdallr-dev/gjallar/internal/app"
	"github.com/heimdallr-dev/gjallar/internal/domain"
	"github.com/heimdallr-dev/gjallar/internal/platform/telemetry"
)

const (
	// StreamJobs is a work queue: each job is delivered to exactly one worker.
	StreamJobs = "GJALLAR_JOBS"
	// StreamEvents keeps inventory and results for 7 days so the hub and the
	// analytics writer can each consume them independently.
	StreamEvents = "GJALLAR_EVENTS"
	// BucketSBOMs holds raw Syft JSON keyed by digest.
	BucketSBOMs = "gjallar-sboms"
)

// Bus wraps a JetStream connection.
type Bus struct {
	NC  *nats.Conn
	JS  jetstream.JetStream
	Log *slog.Logger
	obj jetstream.ObjectStore
}

// Connect dials NATS and makes sure streams and buckets exist. It retries
// for up to five minutes (a cold cluster spends ~2 min pulling the NATS image
// and provisioning its volume), so pods that start first don't crash-loop.
func Connect(ctx context.Context, url, name string, log *slog.Logger, opts ...nats.Option) (*Bus, error) {
	deadline := time.Now().Add(5 * time.Minute)
	for {
		b, err := connect(ctx, url, name, log, opts...)
		if err == nil || time.Now().After(deadline) {
			return b, err
		}
		log.Warn("nats not ready, retrying", "err", err)
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(2 * time.Second):
		}
	}
}

func connect(ctx context.Context, url, name string, log *slog.Logger, opts ...nats.Option) (*Bus, error) {
	opts = append([]nats.Option{nats.Name(name), nats.MaxReconnects(-1), nats.ReconnectWait(2 * time.Second)}, opts...)
	if tok := os.Getenv("GJALLAR_NATS_TOKEN"); tok != "" {
		opts = append(opts, nats.Token(tok))
	}
	nc, err := nats.Connect(url, opts...)
	if err != nil {
		return nil, fmt.Errorf("nats connect %s: %w", url, err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, err
	}
	b := &Bus{NC: nc, JS: js, Log: log}
	if err := b.ensure(ctx); err != nil {
		nc.Close()
		return nil, err
	}
	return b, nil
}

func (b *Bus) ensure(ctx context.Context) error {
	if _, err := b.JS.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name: StreamJobs, Subjects: []string{"gjallar.jobs.>"}, Retention: jetstream.WorkQueuePolicy,
		Storage: jetstream.FileStorage, MaxAge: 72 * time.Hour, Duplicates: 10 * time.Minute,
	}); err != nil {
		return fmt.Errorf("stream %s: %w", StreamJobs, err)
	}
	if _, err := b.JS.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name: StreamEvents, Subjects: []string{"gjallar.inventory.>", "gjallar.results.>", "gjallar.events.>"},
		Retention: jetstream.LimitsPolicy, Storage: jetstream.FileStorage, MaxAge: 7 * 24 * time.Hour,
		MaxBytes: 2 << 30,
	}); err != nil {
		return fmt.Errorf("stream %s: %w", StreamEvents, err)
	}
	// Worker consumers must exist before any worker has run: KEDA reads their
	// lag to scale a worker up from zero. Workers apply their own settings
	// (AckWait, MaxDeliver...) when they start, so only create missing ones.
	for role, subj := range map[string]string{"sbom": domain.SubjJobSBOM, "vuln": domain.SubjJobVuln, "license": domain.SubjJobLicense, "patch": domain.SubjJobPatch, "vex": domain.SubjJobVEX} {
		if _, err := b.JS.Consumer(ctx, StreamJobs, "worker-"+role); errors.Is(err, jetstream.ErrConsumerNotFound) {
			if _, err := b.JS.CreateConsumer(ctx, StreamJobs, jetstream.ConsumerConfig{
				Durable: "worker-" + role, FilterSubject: subj, AckPolicy: jetstream.AckExplicitPolicy,
			}); err != nil && !errors.Is(err, jetstream.ErrConsumerExists) {
				return fmt.Errorf("consumer worker-%s: %w", role, err)
			}
		} else if err != nil {
			return fmt.Errorf("consumer worker-%s: %w", role, err)
		}
	}
	obj, err := b.JS.CreateOrUpdateObjectStore(ctx, jetstream.ObjectStoreConfig{
		Bucket: BucketSBOMs, Description: "Raw Syft SBOMs by image digest", Storage: jetstream.FileStorage, Compression: true,
	})
	if err != nil {
		return fmt.Errorf("object store: %w", err)
	}
	b.obj = obj
	return nil
}

// Close drains the connection.
func (b *Bus) Close() { _ = b.NC.Drain() }

// Publish implements app.EventBus. Rematch jobs get a dedupe ID so a burst
// of DB-update triggers (CronJob + a manual click) queues each image once.
// Discovery needs no dedupe here: Postgres claims SBOM work atomically.
func (b *Bus) Publish(ctx context.Context, subject string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	msg := &nats.Msg{Subject: subject, Data: data, Header: nats.Header{}}
	telemetry.Inject(ctx, msg.Header)
	var opts []jetstream.PublishOpt
	if job, ok := v.(domain.ScanJob); ok && job.Reason == "rematch" {
		bucket := time.Now().UTC().Truncate(5 * time.Minute).Format(time.RFC3339)
		opts = append(opts, jetstream.WithMsgID(subject+"|"+string(job.Digest)+"|rematch|"+bucket))
	}
	_, err = b.JS.PublishMsg(ctx, msg, opts...)
	return err
}

// Put implements app.SBOMStore.
func (b *Bus) Put(ctx context.Context, d domain.Digest, raw []byte) error {
	_, err := b.obj.Put(ctx, jetstream.ObjectMeta{Name: key(d)}, bytes.NewReader(raw))
	return err
}

// Get implements app.SBOMStore.
func (b *Bus) Get(ctx context.Context, d domain.Digest) ([]byte, error) {
	r, err := b.obj.Get(ctx, key(d))
	if errors.Is(err, jetstream.ErrObjectNotFound) {
		return nil, app.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func key(d domain.Digest) string { return strings.ReplaceAll(string(d), ":", "_") }

// Handler processes one message payload.
type Handler func(ctx context.Context, data []byte) error

// ConsumeOpts tunes a durable consumer.
type ConsumeOpts struct {
	Stream     string
	Durable    string
	Subjects   []string
	AckWait    time.Duration // how long a handler may run before redelivery
	MaxDeliver int
	Parallel   int // concurrent handlers
}

// Consume runs a durable pull consumer until ctx is done. Successful
// handlers ack; failures nak with backoff; after MaxDeliver the message is
// terminated and logged so one poison message cannot block a queue.
func (b *Bus) Consume(ctx context.Context, o ConsumeOpts, h Handler) error {
	if o.AckWait == 0 {
		o.AckWait = 5 * time.Minute
	}
	if o.MaxDeliver == 0 {
		o.MaxDeliver = 5
	}
	if o.Parallel <= 0 {
		o.Parallel = 1
	}
	// No consumer BackOff: JetStream uses BackOff[n] instead of AckWait as the
	// redelivery timeout, so a 10 s first step re-sent every job longer than 10 s
	// (Syft, Grype's first DB download, Copa) to run again in parallel. Retry
	// delays come from NakWithDelay in handle(); AckWait + InProgress cover long runs.
	cfg := jetstream.ConsumerConfig{
		Durable: o.Durable, AckPolicy: jetstream.AckExplicitPolicy, AckWait: o.AckWait,
		MaxDeliver: o.MaxDeliver, MaxAckPending: o.Parallel * 2,
	}
	if len(o.Subjects) == 1 {
		cfg.FilterSubject = o.Subjects[0]
	} else {
		cfg.FilterSubjects = o.Subjects
	}
	cons, err := b.JS.CreateOrUpdateConsumer(ctx, o.Stream, cfg)
	if err != nil {
		return fmt.Errorf("consumer %s: %w", o.Durable, err)
	}
	sem := make(chan struct{}, o.Parallel)
	cc, err := cons.Consume(func(m jetstream.Msg) {
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			b.handle(ctx, o, m, h)
		}()
	}, jetstream.PullMaxMessages(o.Parallel))
	if err != nil {
		return err
	}
	<-ctx.Done()
	cc.Stop()
	return nil
}

func (b *Bus) handle(ctx context.Context, o ConsumeOpts, m jetstream.Msg, h Handler) {
	hctx := telemetry.Extract(ctx, m.Headers())
	hctx, span := telemetry.Start(hctx, "consume "+m.Subject(), "consumer", o.Durable)
	// Long-running engines (Syft on a 2 GB image) keep the message alive.
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(o.AckWait / 2)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				_ = m.InProgress()
			case <-stop:
				return
			}
		}
	}()
	err := h(hctx, m.Data())
	close(stop)
	span.End(err)
	meta, _ := m.Metadata()
	switch {
	case err == nil:
		_ = m.Ack()
		telemetry.Jobs.Inc(o.Durable, "ok")
	case meta != nil && int(meta.NumDelivered) >= o.MaxDeliver:
		b.Log.Error("giving up on message", "subject", m.Subject(), "deliveries", meta.NumDelivered, "err", err)
		_ = m.Term()
		telemetry.Jobs.Inc(o.Durable, "dead")
	default:
		b.Log.Warn("handler failed, will retry", "subject", m.Subject(), "err", err)
		delay := 10 * time.Second
		if meta != nil {
			delay = time.Duration(meta.NumDelivered*meta.NumDelivered) * 10 * time.Second
		}
		_ = m.NakWithDelay(delay)
		telemetry.Jobs.Inc(o.Durable, "retry")
	}
}

// JSON adapts a typed handler to a raw Handler.
func JSON[T any](fn func(context.Context, T) error) Handler {
	return func(ctx context.Context, data []byte) error {
		var v T
		if err := json.Unmarshal(data, &v); err != nil {
			return fmt.Errorf("decode: %w", err) // will be retried then termed
		}
		return fn(ctx, v)
	}
}
