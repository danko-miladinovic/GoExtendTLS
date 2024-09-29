package main

import (
	"context"
	"log"

	"github.com/danko-miladinovic/GoExtendTLS/hello"
	tlsExtension "github.com/danko-miladinovic/GoExtendTLS/listener"
	"google.golang.org/grpc"
)

type HelloWorld struct {
	hello.UnimplementedHelloWorldServer
}

func (h *HelloWorld) Hello(ctx context.Context, r *hello.HelloRequest) (*hello.HelloResponse, error) {
	ret := hello.HelloResponse{
		Message: "Hello World! " + r.Name,
	}
	return &ret, nil
}

func main() {
	listener, err := tlsExtension.Listen("127.0.0.1:7022", "/home/cocosai/danko/test/grpc_test/GoExtendTLS/server-cert.pem", "/home/cocosai/danko/test/grpc_test/GoExtendTLS/server-key.pem")
	if err != nil {
		log.Fatalf("cannot create listener: %v", err)
	}

	server := grpc.NewServer()
	service := &HelloWorld{}

	hello.RegisterHelloWorldServer(server, service)

	err = server.Serve(listener)
	if err != nil {
		log.Fatalf("could not server: %v", err)
	}
}
