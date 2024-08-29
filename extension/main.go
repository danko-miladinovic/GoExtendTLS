package main

import (
	"fmt"
	"log"
	"net"
	"time"

	tlstools "gitlab.com/go-extension/tls"
	"golang.org/x/crypto/cryptobyte"
)

// Define a constant for your custom extension type
const (
	extensionHelloWorldType uint16 = 12345 // Choose a unique extension type
	fileLocation            string = "C:\\Users\\danko\\Desktop\\Cocos\\GoExtendTLS"
)

// CustomHelloWorldExtension is a custom TLS extension with "Hello World!" value
type CustomHelloWorldExtension struct {
	Value string
}

// Implement the ExtensionId method
func (e *CustomHelloWorldExtension) ExtensionId() uint16 {
	return extensionHelloWorldType
}

// Implement the NegotiatedVersion method (required by the interface, but not used in this example)
func (e *CustomHelloWorldExtension) NegotiatedVersion(vers uint16) {}

// Implement the Negotiate method (only for servers, we'll return true to always include the extension)
func (e *CustomHelloWorldExtension) Negotiate(messageType uint8) bool {
	return true
}

// Implement the Len method to return the length of the extension data
func (e *CustomHelloWorldExtension) Len(messageType uint8) int {
	return len(e.Value)
}

// Implement the Marshal method to serialize the extension data
func (e *CustomHelloWorldExtension) Marshal(messageType uint8, b *cryptobyte.Builder) {
	b.AddBytes([]byte(e.Value))
}

// Implement the Unmarshal method to deserialize the extension data
func (e *CustomHelloWorldExtension) Unmarshal(messageType uint8, b cryptobyte.String) bool {
	var data []byte
	if !b.ReadBytes(&data, len("Hello World!")) {
		return false
	}
	e.Value = string(data)
	return true
}

// Implement the Clone method to return a shallow copy of the extension
func (e *CustomHelloWorldExtension) Clone() tlstools.Extension {
	return &CustomHelloWorldExtension{Value: e.Value}
}

func main() {
	go startServer()

	// Give the server a moment to start
	// In a real-world application, you'd want a more robust way to handle this
	// such as checking the server's readiness.
	select {
	case <-time.After(1 * time.Second):
	}

	startClient()
}

func startServer() {
	cert_path := fileLocation + "//cert.pem"
	key_path := fileLocation + "//key.pem"
	cert, err := tlstools.LoadX509KeyPair(cert_path, key_path)
	if err != nil {
		log.Fatalf("Server: loadkeys: %s", err)
	}

	// Server TLS configuration
	config := &tlstools.Config{
		MinVersion: tlstools.VersionTLS12,
		CipherSuites: []uint16{
			tlstools.TLS_AES_128_GCM_SHA256,
			tlstools.TLS_AES_128_CCM_SHA256,
			tlstools.TLS_AES_128_CCM_8_SHA256,
		},
		Certificates: []tlstools.Certificate{cert},
		Extensions: []tlstools.Extension{
			&CustomHelloWorldExtension{},
		},
	}

	ln, err := tlstools.Listen("tcp", ":8443", config)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	defer ln.Close()

	fmt.Println("Server listening on :8443")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	tlsConn, ok := conn.(*tlstools.Conn)
	if !ok {
		log.Println("Failed to convert connection to TLS")
		return
	}

	err := tlsConn.Handshake()
	if err != nil {
		log.Printf("TLS handshake failed: %v", err)
		return
	}
	fmt.Printf("handleConnection done!\n")
	// After the handshake, you can retrieve the custom extension value
	// state := tlsConn.ConnectionState()
	// for _, ext := range state.Extensions {
	// 	if hwExt, ok := ext.(*CustomHelloWorldExtension); ok {
	// 		fmt.Printf("Server received custom extension: %s\n", hwExt.Value)
	// 	}
	// }
}

func startClient() {
	// Create a TLS configuration and add the custom extension
	config := &tlstools.Config{
		InsecureSkipVerify: true,
		CipherSuites: []uint16{
			tlstools.TLS_AES_128_GCM_SHA256,
			tlstools.TLS_AES_128_CCM_SHA256,
			tlstools.TLS_AES_128_CCM_8_SHA256,
		},
		MinVersion: tlstools.VersionTLS12,
		Extensions: []tlstools.Extension{
			&CustomHelloWorldExtension{Value: "Hello World!"},
		},
	}

	// Create a custom dialer to apply the TLS config
	dialer := &tlstools.Dialer{
		Config: config,
	}

	// Connect to the server using the custom extension
	conn, err := dialer.Dial("tcp", "localhost:8443")
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Perform a handshake to ensure the custom extension is sent
	tlsConn := conn.(*tlstools.Conn)
	err = tlsConn.Handshake()
	if err != nil {
		log.Fatalf("TLS handshake failed: %v", err)
	}

	fmt.Println("Client connected with custom TLS extension")
}
