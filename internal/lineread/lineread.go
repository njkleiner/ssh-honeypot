package lineread

import (
	"bufio"
	"io"
)

// Reader reads from r line by line and calls fn for each line.
func Reader(r io.Reader, fn func(line []byte) error) error {
	bs := bufio.NewScanner(r)

	for bs.Scan() {
		if err := fn(bs.Bytes()); err != nil {
			return err
		}
	}

	return bs.Err()
}
