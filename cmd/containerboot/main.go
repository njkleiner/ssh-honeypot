package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"time"

	"git.informatik.uni-hamburg.de/iss/bp-itsec-ss23/ssh-honeypot/internal/control"
	"git.informatik.uni-hamburg.de/iss/bp-itsec-ss23/ssh-honeypot/internal/watch"
	"github.com/fsnotify/fsnotify"
	"golang.org/x/sync/errgroup"
)

var defaultWatchPaths = []string{
	"/home", "/root",
	"/var", "/etc",
	"/tmp",
}

func main() {
	if err := run(); err != nil && err != context.Canceled {
		fmt.Fprintln(os.Stderr, err)

		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	eg, ctx := errgroup.WithContext(ctx)

	srv := control.NewServer()

	eg.Go(func() error {
		return srv.ListenAndServe(ctx)
	})

	eg.Go(func() error {
		w, err := watch.NewWatcher()

		if err != nil {
			return err
		}

		defer w.Close()

		for _, path := range defaultWatchPaths {
			_ = w.Watch(path)
		}

		done := make(chan error, 1)

		go func() {
			done <- w.Listen(ctx)
		}()

		for evt := range w.Events() {
			var kind control.EventKind

			switch {
			case evt.Has(fsnotify.Create):
				kind = control.EventFileAdded
			case evt.Has(fsnotify.Write):
				kind = control.EventFileModified
			case evt.Has(fsnotify.Rename):
				kind = control.EventFileMoved
			case evt.Has(fsnotify.Remove):
				kind = control.EventFileRemoved
			case evt.Has(fsnotify.Chmod):
				kind = control.EventFileMode
			}

			srv.Submit(control.Event{
				Kind: kind,
				Time: time.Now().UTC(),

				File: &control.FileEvent{
					Name: filepath.Base(evt.Name),
					Path: evt.Name,
				},
			})
		}

		return <-done
	})

	eg.Go(func() error {
		return exec.Command("/usr/sbin/sshd", "-D").Run()
	})

	if err := eg.Wait(); err != nil {
		return err
	}

	return nil
}
