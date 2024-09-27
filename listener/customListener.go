package tlsExtension

import (
	"net"
)

type CustomListener struct {
}

// Accept implements the Accept method in the [Listener] interface; it
// waits for the next call and returns a generic [Conn].
func (l *CustomListener) Accept() (net.Conn, error) {
	return nil, nil
}

// Close stops listening on the TCP address.
// Already Accepted connections are not closed.
func (l *CustomListener) Close() error {
	return nil
}

// Addr returns the listener's network address, a [*TCPAddr].
// The Addr returned is shared by all invocations of Addr, so
// do not modify it.
func (l *CustomListener) Addr() Addr { return nil }
