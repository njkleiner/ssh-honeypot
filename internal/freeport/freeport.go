package freeport

import (
	"net"
)

func Random() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")

	if err != nil {
		return 0, err
	}

	ln, err := net.ListenTCP("tcp", addr)

	if err != nil {
		return 0, err
	}

	defer ln.Close()

	return ln.Addr().(*net.TCPAddr).Port, nil
}
