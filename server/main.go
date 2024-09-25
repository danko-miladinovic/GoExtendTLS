package main

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/danko-miladinovic/GoExtendTLS/hello"
	"google.golang.org/grpc"
)

type HelloWorld struct {
	hello.UnimplementedHelloWorldServer
}

func (h *HelloWorld) Hello(ctx context.Context, r *hello.HelloRequest) (*hello.HelloResponse, error) {
	ret := hello.HelloResponse{
		Message: "Hello World!" + r.Name,
	}
	return &ret, nil
}

func main() {
	listener, err := net.Listen("tcp", "127.0.0.1:8089")
	if err != nil {
		log.Fatalf("cannot create listener: %v", err)
	}

	server := grpc.NewServer()
	service := &HelloWorld{}

	hello.RegisterHelloWorldServer(server, service)

	fmt.Print("AAAAAAAAAAAA\n")
	err = server.Serve(listener)
	if err != nil {
		log.Fatalf("could not server: %v", err)
	}
}
