package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/danko-miladinovic/GoExtendTLS/hello"
	tlsExtension "github.com/danko-miladinovic/GoExtendTLS/listener"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	// conn, err := grpc.NewClient("127.0.0.1:7022", grpc.WithTransportCredentials(insecure.NewCredentials()))
	conn, err := grpc.NewClient("127.0.0.1:7022",
		grpc.WithContextDialer(tlsExtension.CustomDialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("cannot dial server")
	}
	defer conn.Close()

	c := hello.NewHelloWorldClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	r, err := c.Hello(ctx, &hello.HelloRequest{Name: "Bob"})
	if err != nil {
		log.Fatalf("error calling function Hello: %v", err)
	}

	fmt.Printf("Response is: %s\n", r.Message)
}
