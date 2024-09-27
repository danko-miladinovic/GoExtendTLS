package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/danko-miladinovic/GoExtendTLS/hello"
	"google.golang.org/grpc"
)

func main() {
	conn, err := grpc.NewClient("127.0.0.1:7022")
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
