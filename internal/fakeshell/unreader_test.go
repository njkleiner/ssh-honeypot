package fakeshell

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestUnreader(t *testing.T) {
	u := &unreader{from: strings.NewReader("Hello World")}

	var into bytes.Buffer

	if n, err := io.CopyN(&into, u, 5); err != nil || n != 5 {
		// should read from u.from because u.head is empty.
		t.Errorf("cannot read first 4 bytes: err=%v; n=%d", err, n)
	}

	if got, want := into.String(), "Hello"; got != want {
		t.Errorf("invalid result from first read: got=%q; want=%q", got, want)
	}

	into.Reset()

	u.unread([]byte("Goodbye "))

	if n, err := io.CopyN(&into, u, 7); err != nil || n != 7 {
		// should read from u.head since it is non-empty.
		t.Errorf("cannot read next 7 bytes: err=%v; n=%d", err, n)
	}

	if got, want := into.String(), "Goodbye"; got != want {
		t.Errorf("invalid result from second read: got=%q; want=%q", got, want)
	}

	into.Reset()

	// Note that we now deliberately attempt to read more bytes than
	// there are available in the buffer and reader in total to test
	// that [io.EOF] is returned correctly in this case.

	if n, err := io.CopyN(&into, u, 8); err != io.EOF || n != 7 {
		// should read the remaining byte (" ") from the buffer,
		// as well as all the remaining bytes from the reader.
		t.Errorf("cannot read next 7 (out of 8) bytes: err=%v; n=%d", err, n)
	}

	if got, want := into.String(), "  World"; got != want {
		// Note that there are two trailing spaces, one from the buffer
		// and one from the remaining reader bytes (" World").
		t.Errorf("invalid result from third read: got=%q; want=%q", got, want)
	}

	into.Reset()

	// Note that the buffer and reader are now both empty.
	// Any subsequent read calls should return [io.EOF].

	if n, err := io.CopyN(&into, u, 1); err != io.EOF || n != 0 {
		t.Errorf("cannot read next 0 bytes: err=%v; n=%d", err, n)
	}

	u.unread([]byte("Go"))

	// Since the buffer is now non-empty again, we expect the following behavior:
	// reading should succeed (from the buffer), but any attempt to read further,
	// i.e. past the buffer, should return [io.EOF] since reader is empty now.

	if n, err := io.CopyN(&into, u, 3); err != io.EOF || n != 2 {
		t.Errorf("cannot read next 2 (out of 3) bytes: err=%v; n=%d", err, n)
	}

	if got, want := into.String(), "Go"; got != want {
		t.Errorf("invalid result from fourth read: got=%q; want=%q", got, want)
	}
}
