package elasticlog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"git.informatik.uni-hamburg.de/iss/bp-itsec-ss23/ssh-honeypot/internal/lineread"
	"github.com/elastic/go-elasticsearch/v8/esutil"
)

const (
	flushInterval = 10 * time.Second
	maxBufferSize = 1 << 20 // 1 MiB
)

type BulkWriter struct {
	bi esutil.BulkIndexer

	tick *time.Ticker

	mu sync.Mutex

	buf bytes.Buffer
}

func NewBulkWriter(bi esutil.BulkIndexer) *BulkWriter {
	return &BulkWriter{
		bi: bi,
	}
}

// Sync periodically pushes buffered log messages to ElasticSearch.
// Sync blocks until ctx is done.
func (w *BulkWriter) Sync(ctx context.Context) {
	w.tick = time.NewTicker(flushInterval)
	defer w.tick.Stop()

	for {
		select {
		case <-w.tick.C:
			w.flush()
		case <-ctx.Done():
			w.flush()
			return
		}
	}
}

func (w *BulkWriter) Close() error {
	return w.bi.Close(context.Background())
}

func (w *BulkWriter) maybeFlush() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.buf.Len() > maxBufferSize {
		w.flushLocked()

		w.tick.Reset(flushInterval)
	}
}

func (w *BulkWriter) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.flushLocked()
}

func (w *BulkWriter) flushLocked() {
	if w.buf.Len() == 0 {
		return // buffer empty, nothing to flush
	}

	_ = lineread.Reader(&w.buf, func(line []byte) error {
		sum := sha256.Sum256(line)
		hash := hex.EncodeToString(sum[:])

		return w.bi.Add(context.Background(), esutil.BulkIndexerItem{
			Action:     "index",
			DocumentID: hash,
			Body:       bytes.NewReader(line),
		})
	})

	w.buf.Reset()
}

type Handler struct {
	bw   *BulkWriter
	base slog.Handler
}

var _ slog.Handler = (*Handler)(nil)

func NewHandler(bw *BulkWriter) *Handler {
	tee := io.MultiWriter(os.Stderr, &bw.buf)

	return &Handler{
		bw:   bw,
		base: slog.NewJSONHandler(tee, nil),
	}
}

func (h *Handler) Enabled(ctx context.Context, lvl slog.Level) bool {
	return h.base.Enabled(ctx, lvl)
}

func (h *Handler) Handle(ctx context.Context, rec slog.Record) error {
	err := h.base.Handle(ctx, rec)

	h.bw.maybeFlush()

	return err
}

func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &Handler{
		bw:   h.bw,
		base: h.base.WithAttrs(attrs),
	}
}

func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{
		bw:   h.bw,
		base: h.base.WithGroup(name),
	}
}
