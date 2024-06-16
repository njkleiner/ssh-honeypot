package control

import (
	"time"
)

type EventKind string

const (
	EventFileAdded    = EventKind("file.create")
	EventFileMoved    = EventKind("file.rename")
	EventFileModified = EventKind("file.write")
	EventFileRemoved  = EventKind("file.remove")
	EventFileMode     = EventKind("file.mode")
)

type FileEvent struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type Event struct {
	Kind EventKind `json:"kind"`
	Time time.Time `json:"time"`

	File *FileEvent `json:"file,omitempty"`
}

type AuthInfo struct {
	User     string `json:"user"`
	Password string `json:"password"`
}
