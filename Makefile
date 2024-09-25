grpc:
	protoc --go_out=hello --go_opt=paths=source_relative --go-grpc_out=hello --go-grpc_opt=paths=source_relative hello.proto