package main

import (
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

const (
	HelloWorldExtensionType uint16 = 0x1337 // custom extension type
	fileLocation            string = "C:\\Users\\danko\\Desktop\\Cocos\\GoExtendTLS"
)

type HelloWorldExtension struct {
	*utls.GenericExtension
	Message string
}

// // Len returns the length of the extension data
// func (e *HelloWorldExtension) Len() int {
// 	fmt.Printf("Len(): %d\n", 4+len(e.Message))
// 	return 4 + len(e.Message) // 2 bytes for the extension type, 2 bytes for the length, plus the message length
// }

// // Read reads the extension data into the provided byte slice
// func (e *HelloWorldExtension) Read(b []byte) (n int, err error) {
// 	if len(b) < e.Len() {
// 		return 0, io.ErrShortBuffer
// 	}

// 	// Write the extension type
// 	b[0] = byte(HelloWorldExtensionType >> 8)
// 	b[1] = byte(HelloWorldExtensionType & 0xff)

// 	// Write the length of the extension data
// 	b[2] = byte(len(e.Message) >> 8)
// 	b[3] = byte(len(e.Message) & 0xff)

// 	// Write the actual message
// 	copy(b[4:], e.Message)

// 	fmt.Printf("Read(): len(b): %d e.Len(): %d\n", len(b), e.Len())

// 	return e.Len(), io.EOF
// }

func loadRootCAs() *x509.CertPool {
	roots := x509.NewCertPool()
	// Typically you load from a file, e.g., roots.AppendCertsFromPEM(certFile)
	return roots
}

func startTLSServer() {
	cert_path := fileLocation + "//cert.pem"
	key_path := fileLocation + "//key.pem"
	cert, err := utls.LoadX509KeyPair(cert_path, key_path)
	if err != nil {
		log.Fatalf("Server: loadkeys: %s", err)
	}

	// TLS configuration
	config := &utls.Config{
		InsecureSkipVerify: true,
		RootCAs:            loadRootCAs(),
		Certificates:       []utls.Certificate{cert},
	}

	// Listen for incoming connections
	ln, err := utls.Listen("tcp", ":8443", config)
	if err != nil {
		log.Fatalf("Server: listen: %s", err)
	}
	defer ln.Close()
	fmt.Println("Server: listening on :8443")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatalf("Server: accept: %s", err)
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	fmt.Println("Server: new connection accepted")

	cert_path := fileLocation + "//cert.pem"
	key_path := fileLocation + "//key.pem"
	cert, err := utls.LoadX509KeyPair(cert_path, key_path)
	if err != nil {
		log.Fatalf("Server: loadkeys: %s", err)
	}

	// TLS configuration
	config := &utls.Config{
		InsecureSkipVerify: true,
		RootCAs:            loadRootCAs(),
		Certificates:       []utls.Certificate{cert},
		ServerName:         "localhost",
	}

	// Create uTLS connection to read the custom extension
	// Conn := utls.UClient(conn, config, utls.HelloCustom)
	uConn := utls.Server(conn, config)

	// Complete the handshake to receive the ClientHello with extensions
	if err := uConn.Handshake(); err != nil {
		log.Fatalf("Server: handshake failed: %s", err)
	}

	// Look for the Hello World extension in the received ClientHello
	// for _, ext := range uConn.Extensions {
	// 	if ext, ok := ext.(*utls.GenericExtension); ok && ext.Id == HelloWorldExtensionType {
	// 		// Parse the "Hello World!" message
	// 		if len(ext.Data) > 2 {
	// 			messageLength := int(ext.Data[0])<<8 | int(ext.Data[1])
	// 			message := string(ext.Data[2 : 2+messageLength])
	// 			fmt.Printf("Server: received message: %s\n", message)
	// 		}
	// 	}
	// }
}

func startTLSClient() {
	cert_path := fileLocation + "//cert.pem"
	key_path := fileLocation + "//key.pem"
	cert, err := utls.LoadX509KeyPair(cert_path, key_path)
	if err != nil {
		log.Fatalf("Server: loadkeys: %s", err)
	}

	// TLS configuration
	config := &utls.Config{
		InsecureSkipVerify: true,
		Certificates:       []utls.Certificate{cert},
	}

	// Connect to the server
	conn, err := net.Dial("tcp", "localhost:8443")
	if err != nil {
		log.Fatalf("Client: dial: %s", err)
	}
	defer conn.Close()

	// Create a new uTLS client connection
	uConn := utls.UClient(conn, config, utls.HelloCustom)

	message := "Hello World!"
	// Create the custom Hello World extension and initialize the GenericExtension
	helloWorldExt := &HelloWorldExtension{
		GenericExtension: &utls.GenericExtension{
			Id:   HelloWorldExtensionType,
			Data: []byte(message),
		},
		Message: message,
	}

	// Set custom extensions
	spec := &utls.ClientHelloSpec{
		Extensions: []utls.TLSExtension{
			helloWorldExt,
		},
		// TLSVersMin: utls.VersionTLS12,
		// TLSVersMax: utls.VersionTLS13,
	}

	if err := uConn.ApplyPreset(spec); err != nil {
		log.Fatalf("Client: ApplyPreset: %s", err)
	}

	// Complete the handshake
	if err := uConn.Handshake(); err != nil {
		log.Fatalf("Client: handshake: %s", err)
	}

	fmt.Println("Client: TLS handshake completed")
}

func main() {
	// Start the server in a goroutine
	go startTLSServer()

	// Give the server some time to start
	time.Sleep(2 * time.Second)

	// Start the client
	startTLSClient()
}
