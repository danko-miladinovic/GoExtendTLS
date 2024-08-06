package main

import "fmt"

const (
	AttestedTLSExtensionType uint16 = 0x1337
)

type AttestedTLSExtension struct {
	Message string
}

func (a *AttestedTLSExtension) Len() int {
	return 2 + len(a.Message)
}

func (a *AttestedTLSExtension) Write(b []byte) (n int, err error) {

}

func main() {
	fmt.Println("Hello, world.")
}
