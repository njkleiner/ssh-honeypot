package fakeshell

import (
	"bytes"
	"io"
	"sync"
)

// unreader implements [io.Reader] with an optional "head" buffer.
type unreader struct {
	// mu protects access to from, head.
	mu sync.Mutex

	// from is the original source reader that will be used when head is empty.
	from io.Reader

	// head is an optional buffer, that, when non-empty, will first be drained
	// before from will be used to read data again.
	head bytes.Buffer
}

var _ io.Reader = (*unreader)(nil)

func (u *unreader) Read(buf []byte) (int, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if n, _ := u.head.Read(buf); n > 0 {
		return n, nil
	}

	return u.from.Read(buf)
}

func (u *unreader) lock() {
	u.mu.Lock()
}

func (u *unreader) unlock() {
	u.mu.Unlock()
}

func (u *unreader) unread(buf []byte) {
	u.head.Write(buf)
}
