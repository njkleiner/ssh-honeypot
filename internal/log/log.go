package log

import (
	"context"
	"log/slog"
	"runtime"
	"time"
)

type ContextKey struct{}

func Logger(ctx context.Context) *slog.Logger {
	if log, ok := ctx.Value(ContextKey{}).(*slog.Logger); ok {
		return log
	}

	return slog.Default()
}

func handle(ctx context.Context, lvl slog.Level, msg string, args ...any) {
	log := Logger(ctx)

	if !log.Enabled(ctx, lvl) {
		return
	}

	var pc [1]uintptr

	// skip [runtime.Callers, this function, this function's caller]
	runtime.Callers(3, pc[:])

	rec := slog.NewRecord(time.Now(), lvl, msg, pc[0])
	rec.Add(args...)

	_ = log.Handler().Handle(ctx, rec)
}

func Debug(ctx context.Context, msg string, args ...any) {
	handle(ctx, slog.LevelDebug, msg, args...)
}

func Info(ctx context.Context, msg string, args ...any) {
	handle(ctx, slog.LevelInfo, msg, args...)
}

func Warn(ctx context.Context, msg string, args ...any) {
	handle(ctx, slog.LevelWarn, msg, args...)
}

func Error(ctx context.Context, msg string, args ...any) {
	handle(ctx, slog.LevelError, msg, args...)
}
