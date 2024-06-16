package watch

import (
	"context"
	"io/fs"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
)

type Watcher struct {
	watch *fsnotify.Watcher

	events chan fsnotify.Event

	seen map[string]struct{}
}

func NewWatcher() (*Watcher, error) {
	w, err := fsnotify.NewWatcher()

	if err != nil {
		return nil, err
	}

	return &Watcher{
		watch: w,

		seen:   make(map[string]struct{}),
		events: make(chan fsnotify.Event),
	}, nil
}

func (w *Watcher) Listen(ctx context.Context) error {
	defer close(w.events)

	for {
		select {
		case evt := <-w.watch.Events:
			w.handle(evt)
		case <-w.watch.Errors:
			// ignore errors
		case <-ctx.Done():
			return nil
		}
	}
}

func (w *Watcher) Close() error {
	if err := w.watch.Close(); err != nil {
		return err
	}

	return nil
}

func (w *Watcher) Events() <-chan fsnotify.Event {
	return w.events
}

func (w *Watcher) Watch(dir string) error {
	return w.add(dir)
}

func (w *Watcher) handle(evt fsnotify.Event) {
	if evt.Has(fsnotify.Create) {
		_ = w.add(evt.Name) // watch new directories on a best effort basis; ignore errors
	}

	w.events <- evt
}

// add watches the entire file system tree rooted at dir,
// including (recursively) all subtrees of dir.
//
// add does nothing if dir is not actually a directory.
func (w *Watcher) add(dir string) error {
	return filepath.WalkDir(dir, func(path string, ent fs.DirEntry, err error) error {
		if err != nil {
			return filepath.SkipDir
		}

		if !ent.IsDir() {
			return nil
		}

		path = filepath.Clean(path)

		if _, ok := w.seen[path]; ok {
			return nil
		}

		if err := w.watch.Add(path); err != nil {
			return filepath.SkipDir
		}

		w.seen[path] = struct{}{}

		return nil
	})
}
