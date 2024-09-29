package tlsExtension

// #cgo LDFLAGS: -lssl -lcrypto
// #include "tls_extension/server.c"
import "C"

import (
	"fmt"
	"net"
	"strconv"
	"time"
	"unsafe"
)

type CustomServerListener struct {
	tlsListener *C.tls_server_connection
}

func Listen(addr string, certFile string, keyFile string) (net.Listener, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("error while creating listener: %v", err)
	}

	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("bad format of IP address: %v", err)
	}

	return &CustomServerListener{tlsListener: C.start_tls_server(C.CString(certFile), C.CString(certFile), C.int(p))}, nil
}

// Accept implements the Accept method in the [Listener] interface; it
// waits for the next call and returns a generic [Conn].
func (l *CustomServerListener) Accept() (net.Conn, error) {
	conn := C.tls_server_accept(l.tlsListener)

	if conn == nil {
		return nil, fmt.Errorf("could not accept connection")
	}

	return &CustomTLSConn{tlsConn: conn}, nil
}

// Close stops listening on the TCP address.
// Already Accepted connections are not closed.
func (l *CustomServerListener) Close() error {
	ret := C.tls_server_close(l.tlsListener)
	if ret != 0 {
		return fmt.Errorf("could not close the TLS connection")
	}
	return nil
}

// Addr returns the listener's network address, a [*TCPAddr].
// The Addr returned is shared by all invocations of Addr, so
// do not modify it.
func (l *CustomServerListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 4433}
}

type CustomTLSConn struct {
	tlsConn *C.tls_connection
}

func (c *CustomTLSConn) Read(b []byte) (int, error) {
	n := int(C.tls_read(c.tlsConn, unsafe.Pointer(&b[0]), C.int(len(b))))
	if n < 0 {
		return 0, fmt.Errorf("could not read from TLS")
	}

	return n, nil
}

func (c *CustomTLSConn) Write(b []byte) (int, error) {
	n := int(C.tls_write(c.tlsConn, unsafe.Pointer(&b[0]), C.int(len(b))))
	if n < 0 {
		return 0, fmt.Errorf("could not write to TLS")
	}
	return n, nil
}

func (c *CustomTLSConn) Close() error {
	C.tls_close(c.tlsConn)
	return nil
}

func (c *CustomTLSConn) LocalAddr() net.Addr {
	return &net.TCPAddr{}
}

func (c *CustomTLSConn) RemoteAddr() net.Addr {
	// Return remote address
	return &net.TCPAddr{}
}

func (c *CustomTLSConn) SetDeadline(t time.Time) error {
	// Set deadlines (e.g., using syscall or C functions)
	return nil
}

func (c *CustomTLSConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *CustomTLSConn) SetWriteDeadline(t time.Time) error {
	return nil
}
